//! The parts of `@node-saml/node-saml` 5 the service uses, ported line by line: `getAuthorizeUrlAsync` (a deflated,
//! redirect-signed AuthnRequest), `validatePostResponseAsync` (signature, decryption, `InResponseTo`, subject
//! confirmation, conditions and audience checks, profile extraction) and `generateServiceProviderMetadata` (signed
//! SP metadata). Its errors are plain errors with Node-SAML's messages.

use std::io::Write;
use std::sync::{Arc, LazyLock};

use better_iam_core::js;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value};

use crate::dsig::{self, Action, Selector, SignOptions, SignReference};
use crate::keys::{Hash, SamlError, SamlResult, base64_decode, base64_encode, rsa_sign};
use crate::xml::{Document, NodeId};
use crate::xml2js::to_xml2js;
use crate::xmlenc;

const PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const METADATA_NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
/// `DEFAULT_IDENTIFIER_FORMAT`.
const DEFAULT_IDENTIFIER_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

fn plain(message: impl Into<String>) -> SamlError {
    SamlError::plain(message)
}

/// `CacheProvider`: where request IDs live between the AuthnRequest and the response.
#[async_trait::async_trait]
pub trait CacheProvider: Send + Sync {
    /// `saveAsync(key, value)`.
    async fn save(&self, key: &str, value: &str) -> SamlResult<()>;
    /// `getAsync(key)`.
    async fn get(&self, key: &str) -> SamlResult<Option<String>>;
    /// `removeAsync(key)` (`key` null for a response without `InResponseTo`).
    async fn remove(&self, key: Option<&str>) -> SamlResult<Option<String>>;
}

/// `ValidateInResponseTo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidateInResponseTo {
    Never,
    IfPresent,
    Always,
}

/// The `SamlConfig` the service builds for a connection (everything else at Node-SAML's defaults).
#[derive(Clone)]
pub struct SamlOptions {
    pub entry_point: String,
    pub issuer: String,
    pub idp_issuer: String,
    pub callback_url: String,
    pub audience: String,
    pub idp_cert: Vec<String>,
    pub private_key: String,
    pub public_cert: String,
    pub decryption_pvk: Option<String>,
    pub validate_in_response_to: ValidateInResponseTo,
    pub request_id_expiration_period_ms: f64,
    pub max_assertion_age_ms: f64,
    pub accepted_clock_skew_ms: f64,
    pub cache_provider: Arc<dyn CacheProvider>,
    pub generate_unique_id: Arc<dyn Fn() -> String + Send + Sync>,
}

/// The validated assertion (`profile.getAssertionXml()`), as a document.
#[derive(Debug, Clone)]
pub struct AssertionXml {
    pub document: Document,
    pub root: NodeId,
}

impl AssertionXml {
    /// The assertion XML text (`getAssertionXml()`).
    pub fn xml(&self) -> String {
        self.document.serialize(self.root)
    }
}

/// The Node-SAML `Profile`: its members in insertion order (None is `undefined`) and the assertion.
#[derive(Debug, Clone)]
pub struct Profile {
    pub members: IndexMap<String, Option<Value>>,
    pub assertion: AssertionXml,
}

impl Profile {
    /// `profile[name]`.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.members.get(name).and_then(Option::as_ref)
    }

    /// `profile[name]` when it is a string.
    pub fn text(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(Value::as_str)
    }

    /// The profile as a JSON object (`undefined` members left out).
    pub fn to_json(&self) -> Map<String, Value> {
        self.members
            .iter()
            .filter_map(|(key, value)| value.clone().map(|value| (key.clone(), value)))
            .collect()
    }
}

/// The current time (`new Date().getTime()`): the process wall clock.
fn now_ms() -> f64 {
    js::now_ms()
}

/// `new Date().toISOString()`.
pub fn generate_instant() -> String {
    js::iso_string(now_ms()).unwrap_or_default()
}

/// JavaScript truthiness of a member read from xml2js output.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(number)) => number
            .as_f64()
            .is_some_and(|value| value != 0.0 && !value.is_nan()),
        Some(Value::String(text)) => !text.is_empty(),
        Some(_) => true,
    }
}

/// `base[key]` with JavaScript semantics over xml2js output: a TypeError for `undefined`/`null`.
fn get<'a>(base: Option<&'a Value>, key: &str) -> SamlResult<Option<&'a Value>> {
    match base {
        None => Err(plain(format!(
            "Cannot read properties of undefined (reading '{key}')"
        ))),
        Some(Value::Null) => Err(plain(format!(
            "Cannot read properties of null (reading '{key}')"
        ))),
        Some(Value::Object(map)) => Ok(map.get(key)),
        Some(Value::Array(items)) => {
            Ok(key.parse::<usize>().ok().and_then(|index| items.get(index)))
        }
        Some(_) => Ok(None),
    }
}

/// `String(value)` of an optional member.
fn js_string(value: Option<&Value>) -> String {
    match value {
        None => "undefined".to_owned(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Null) => "null".to_owned(),
        Some(other) => other.to_string(),
    }
}

/// `dateStringToTimestamp(dateString, label)`.
fn date_string_to_timestamp(value: Option<&Value>, label: &str) -> SamlResult<f64> {
    let text = js_string(value);
    let parsed = match value {
        Some(Value::String(text)) => better_iam_auth::js_date::parse(text),
        _ => f64::NAN,
    };
    if parsed.is_nan() {
        return Err(plain(format!(
            "Error parsing {label}: '{text}' is not a valid date"
        )));
    }
    Ok(parsed)
}

/// `PEM_FORMAT_REGEX` of Node-SAML's crypto helpers.
static PEM_FORMAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)^(-----BEGIN [A-Z ]{1,48}-----(\r\n|\r|\n).*(\r\n|\r|\n)-----END [A-Z ]{1,48}-----(\r\n|\r|\n)?)$").unwrap()
});
static BASE64_FORMAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)^(?:[A-Za-z0-9+/]{4}\n?)*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$").unwrap()
});

/// `normalizePemFile`.
fn normalize_pem_file(pem: &str) -> String {
    let normalized = pem.trim().replace("\r\n", "\n").replace('\r', "\n");
    let mut lines = Vec::new();
    for line in normalized.split('\n') {
        let chars: Vec<char> = line.chars().collect();
        for chunk in chars.chunks(64) {
            lines.push(chunk.iter().collect::<String>());
        }
    }
    format!("{}\n", lines.join("\n"))
}

/// `keyInfoToPem(keyInfo, pemLabel, optionName)`.
pub fn key_info_to_pem(key_info: &str, label: &str, option: &str) -> SamlResult<String> {
    if key_info.is_empty() {
        return Err(plain(format!("{option} is not provided")));
    }
    if PEM_FORMAT.is_match(key_info) {
        return Ok(normalize_pem_file(key_info));
    }
    if !BASE64_FORMAT.is_match(key_info) {
        return Err(plain(format!(
            "{option} is not in PEM format or in base64 format"
        )));
    }
    Ok(normalize_pem_file(&format!(
        "-----BEGIN {label}-----\n{key_info}\n-----END {label}-----"
    )))
}

/// `stripPemHeaderAndFooter`.
fn strip_pem_header_and_footer(certificate: &str) -> String {
    static HEADER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"-----BEGIN [A-Z ]{1,48}-----\n?").unwrap());
    static FOOTER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"-----END [A-Z ]{1,48}-----\n?").unwrap());
    let normalized = certificate.replace("\r\n", "\n").replace('\r', "\n");
    let without_header = HEADER.replace(&normalized, "").into_owned();
    FOOTER.replace(&without_header, "").into_owned()
}

/// `querystring.escape`: everything but `A-Z a-z 0-9 - _ . ! ~ * ' ( )` percent-encoded.
fn querystring_escape(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// xmlbuilder's text escaping.
fn escape_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\r', "&#xD;")
}

/// xmlbuilder's attribute escaping.
fn escape_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
        .replace('\t', "&#x9;")
        .replace('\n', "&#xA;")
        .replace('\r', "&#xD;")
}

/// A node for the xmlbuilder-style writer.
enum XmlNode {
    Element {
        name: String,
        attrs: Vec<(String, String)>,
        children: Vec<XmlNode>,
    },
    Text(String),
}

fn el(name: &str, attrs: &[(&str, &str)], children: Vec<XmlNode>) -> XmlNode {
    XmlNode::Element {
        name: name.to_owned(),
        attrs: attrs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        children,
    }
}

/// `xmlbuilder.create(obj).end(options)`: compact, or pretty with two-space indents.
fn build_xml(root: &XmlNode, pretty: bool) -> String {
    fn write(node: &XmlNode, pretty: bool, level: usize, out: &mut String) {
        let indent = if pretty {
            "  ".repeat(level)
        } else {
            String::new()
        };
        let newline = if pretty { "\n" } else { "" };
        match node {
            XmlNode::Text(text) => {
                out.push_str(&indent);
                out.push_str(&escape_text(text));
                out.push_str(newline);
            }
            XmlNode::Element {
                name,
                attrs,
                children,
            } => {
                out.push_str(&indent);
                out.push('<');
                out.push_str(name);
                for (attr, value) in attrs {
                    out.push_str(&format!(" {attr}=\"{}\"", escape_attr(value)));
                }
                match children.as_slice() {
                    [] => {
                        out.push_str("/>");
                        out.push_str(newline);
                    }
                    [XmlNode::Text(text)] => {
                        out.push('>');
                        out.push_str(&escape_text(text));
                        out.push_str(&format!("</{name}>"));
                        out.push_str(newline);
                    }
                    children => {
                        out.push('>');
                        out.push_str(newline);
                        for child in children {
                            write(child, pretty, level + 1, out);
                        }
                        out.push_str(&indent);
                        out.push_str(&format!("</{name}>"));
                        out.push_str(newline);
                    }
                }
            }
        }
    }
    let mut out = String::from("<?xml version=\"1.0\"?>");
    if pretty {
        out.push('\n');
    }
    write(root, pretty, 0, &mut out);
    if pretty && out.ends_with('\n') {
        out.pop();
    }
    out
}

/// `new SAML(options)`.
pub struct Saml {
    options: SamlOptions,
}

impl Saml {
    pub fn new(options: SamlOptions) -> Self {
        Saml { options }
    }

    fn must_validate_in_response_to(&self, has_in_response_to: bool) -> bool {
        self.options.validate_in_response_to == ValidateInResponseTo::Always
            || (self.options.validate_in_response_to == ValidateInResponseTo::IfPresent
                && has_in_response_to)
    }

    /// `generateAuthorizeRequestAsync(false, false)`.
    async fn generate_authorize_request(&self) -> SamlResult<String> {
        if self.options.entry_point.is_empty() {
            return Err(plain("entryPoint is required"));
        }
        let id = (self.options.generate_unique_id)();
        let instant = generate_instant();
        if self.must_validate_in_response_to(true) {
            self.options.cache_provider.save(&id, &instant).await?;
        }
        let request = el(
            "samlp:AuthnRequest",
            &[
                ("xmlns:samlp", PROTOCOL_NS),
                ("ID", &id),
                ("Version", "2.0"),
                ("IssueInstant", &instant),
                (
                    "ProtocolBinding",
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                ),
                ("Destination", &self.options.entry_point),
                ("AssertionConsumerServiceURL", &self.options.callback_url),
            ],
            vec![
                el(
                    "saml:Issuer",
                    &[("xmlns:saml", ASSERTION_NS)],
                    vec![XmlNode::Text(self.options.issuer.clone())],
                ),
                el(
                    "samlp:NameIDPolicy",
                    &[
                        ("xmlns:samlp", PROTOCOL_NS),
                        ("AllowCreate", "true"),
                        ("Format", DEFAULT_IDENTIFIER_FORMAT),
                    ],
                    Vec::new(),
                ),
                el(
                    "samlp:RequestedAuthnContext",
                    &[("xmlns:samlp", PROTOCOL_NS), ("Comparison", "exact")],
                    vec![el(
                        "saml:AuthnContextClassRef",
                        &[("xmlns:saml", ASSERTION_NS)],
                        vec![XmlNode::Text(
                            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
                                .to_owned(),
                        )],
                    )],
                ),
            ],
        );
        Ok(build_xml(&request, false))
    }

    /// `getAuthorizeUrlAsync(relayState, undefined, {})`: the entry point with the deflated request, the relay state,
    /// and the redirect-binding signature (`SigAlg`, `Signature`).
    pub async fn get_authorize_url(&self, relay_state: &str) -> SamlResult<String> {
        let request = self.generate_authorize_request().await?;
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(request.as_bytes())
            .map_err(|error| plain(error.to_string()))?;
        let deflated = encoder.finish().map_err(|error| plain(error.to_string()))?;
        let mut target =
            url::Url::parse(&self.options.entry_point).map_err(|_| plain("Invalid URL"))?;
        let mut message: Vec<(String, String)> =
            vec![("SAMLRequest".into(), base64_encode(&deflated))];
        if !relay_state.is_empty() {
            message.push(("RelayState".into(), relay_state.to_owned()));
        }
        // signRequest: SigAlg, then the signature over `querystring.stringify` of the signed members.
        let sig_alg = dsig::RSA_SHA256.to_owned();
        message.push(("SigAlg".into(), sig_alg));
        let signed: Vec<String> = message
            .iter()
            .map(|(key, value)| {
                format!("{}={}", querystring_escape(key), querystring_escape(value))
            })
            .collect();
        let private_key = key_info_to_pem(&self.options.private_key, "PRIVATE KEY", "privateKey")?;
        let signature = rsa_sign(&private_key, Hash::Sha256, signed.join("&").as_bytes())?;
        message.push(("Signature".into(), signature));
        let mut pairs: Vec<(String, String)> = target
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        for (key, value) in message {
            // URLSearchParams.set: replace the first pair with the name, drop the others, or append.
            match pairs.iter().position(|(existing, _)| *existing == key) {
                Some(position) => {
                    pairs[position].1 = value;
                    let mut index = 0;
                    pairs.retain(|(existing, _)| {
                        let keep = *existing != key || index == position;
                        index += 1;
                        keep
                    });
                }
                None => pairs.push((key, value)),
            }
        }
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs.iter())
            .finish();
        target.set_query(if query.is_empty() { None } else { Some(&query) });
        Ok(target.to_string())
    }

    /// `generateServiceProviderMetadata(decryptionCert, publicCert)`: signed SP metadata.
    pub fn generate_service_provider_metadata(
        &self,
        decryption_cert: Option<&str>,
        public_cert: &str,
    ) -> SamlResult<String> {
        let decryption_cert = match &self.options.decryption_pvk {
            Some(_) => match decryption_cert.filter(|cert| !cert.is_empty()) {
                Some(cert) => Some(cert),
                None => {
                    return Err(plain(
                        "Missing decryptionCert while generating metadata for decrypting service provider",
                    ));
                }
            },
            None => None,
        };
        if public_cert.is_empty() {
            return Err(plain(
                "Missing publicCert while generating metadata for signing service provider messages",
            ));
        }
        let key_info = |cert: &str| {
            el(
                "ds:KeyInfo",
                &[],
                vec![el(
                    "ds:X509Data",
                    &[],
                    vec![el(
                        "ds:X509Certificate",
                        &[],
                        vec![XmlNode::Text(strip_pem_header_and_footer(cert))],
                    )],
                )],
            )
        };
        let mut descriptor_children = vec![el(
            "KeyDescriptor",
            &[("use", "signing")],
            vec![key_info(public_cert)],
        )];
        if let Some(cert) = decryption_cert {
            let mut children = vec![key_info(cert)];
            for algorithm in [
                "http://www.w3.org/2009/xmlenc11#aes256-gcm",
                "http://www.w3.org/2009/xmlenc11#aes128-gcm",
                "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
                "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
            ] {
                children.push(el(
                    "EncryptionMethod",
                    &[("Algorithm", algorithm)],
                    Vec::new(),
                ));
            }
            descriptor_children.push(el("KeyDescriptor", &[("use", "encryption")], children));
        }
        descriptor_children.push(el(
            "NameIDFormat",
            &[],
            vec![XmlNode::Text(DEFAULT_IDENTIFIER_FORMAT.to_owned())],
        ));
        descriptor_children.push(el(
            "AssertionConsumerService",
            &[
                ("index", "1"),
                ("isDefault", "true"),
                ("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
                ("Location", &self.options.callback_url),
            ],
            Vec::new(),
        ));
        let id = (self.options.generate_unique_id)();
        let metadata = el(
            "EntityDescriptor",
            &[
                ("xmlns", METADATA_NS),
                ("xmlns:ds", crate::c14n::DSIG_NS),
                ("entityID", &self.options.issuer),
                ("ID", &id),
            ],
            vec![el(
                "SPSSODescriptor",
                &[
                    ("protocolSupportEnumeration", PROTOCOL_NS),
                    ("AuthnRequestsSigned", "true"),
                    ("WantAssertionsSigned", "true"),
                ],
                descriptor_children,
            )],
        );
        let xml = build_xml(&metadata, true);
        dsig::compute_signature(
            &xml,
            &SignOptions {
                private_key: self.options.private_key.clone(),
                public_cert: None,
                signature_algorithm: dsig::RSA_SHA256.to_owned(),
                canonicalization_algorithm: dsig::EXC_C14N.to_owned(),
                references: vec![SignReference {
                    selector: Selector::qualified(METADATA_NS, "EntityDescriptor"),
                    transforms: vec![
                        dsig::ENVELOPED_SIGNATURE.to_owned(),
                        dsig::EXC_C14N.to_owned(),
                    ],
                    digest_algorithm: dsig::SHA256.to_owned(),
                }],
                location: Selector::qualified(METADATA_NS, "EntityDescriptor"),
                action: Action::Prepend,
            },
        )
    }

    /// `getKeyInfosAsPem()`.
    fn key_infos_as_pem(&self) -> SamlResult<Vec<String>> {
        self.options
            .idp_cert
            .iter()
            .enumerate()
            .map(|(index, cert)| key_info_to_pem(cert, "CERTIFICATE", &format!("idpCert[{index}]")))
            .collect()
    }

    /// `validateInResponseTo(inResponseTo)`.
    async fn validate_in_response_to(&self, in_response_to: Option<&str>) -> SamlResult<()> {
        if self.must_validate_in_response_to(in_response_to.is_some_and(|value| !value.is_empty()))
        {
            match in_response_to.filter(|value| !value.is_empty()) {
                Some(value) => {
                    if self
                        .options
                        .cache_provider
                        .get(value)
                        .await?
                        .is_none_or(|value| value.is_empty())
                    {
                        return Err(plain("InResponseTo is not valid"));
                    }
                }
                None => return Err(plain("InResponseTo is missing from response")),
            }
        }
        Ok(())
    }

    /// `getSignedAssertion(signedXml)`: the assertion inside verified XML (decrypting an encrypted one).
    fn get_signed_assertion(&self, signed_xml: &str) -> SamlResult<Option<AssertionXml>> {
        let document = parse_dom(signed_xml)?;
        let root = document.document_element().expect("parsed");
        match document.local_name(root) {
            Some("Response") => {
                let assertions = document.find_children(root, None, "Assertion");
                if assertions.len() == 1 {
                    let (document, root) = document.clone_subtree(assertions[0]);
                    return Ok(Some(AssertionXml { document, root }));
                }
                let encrypted = document.find_children(root, None, "EncryptedAssertion");
                if encrypted.len() == 1 {
                    let key = self
                        .options
                        .decryption_pvk
                        .clone()
                        .filter(|key| !key.is_empty())
                        .ok_or_else(|| plain("No decryption key for encrypted SAML response"))?;
                    let decrypted = xmlenc::decrypt(&document, encrypted[0], &key)?;
                    let decrypted = parse_dom(&decrypted)?;
                    let root = decrypted.document_element().expect("parsed");
                    if decrypted.local_name(root) != Some("Assertion") {
                        return Err(plain("Invalid EncryptedAssertion content"));
                    }
                    return Ok(Some(AssertionXml {
                        document: decrypted,
                        root,
                    }));
                }
                Ok(None)
            }
            Some("Assertion") => {
                let (document, root) = document.clone_subtree(root);
                Ok(Some(AssertionXml { document, root }))
            }
            _ => Ok(None),
        }
    }

    /// `validatePostResponseAsync({ SAMLResponse })`: the profile (None with `loggedOut` for a logout response).
    pub async fn validate_post_response(
        &self,
        saml_response: &str,
    ) -> SamlResult<(Option<Profile>, bool)> {
        let mut in_response_to: Option<String> = None;
        let result = self
            .validate_post_response_inner(saml_response, &mut in_response_to)
            .await;
        if result.is_err()
            && self.must_validate_in_response_to(
                in_response_to
                    .as_deref()
                    .is_some_and(|value| !value.is_empty()),
            )
        {
            self.options
                .cache_provider
                .remove(in_response_to.as_deref())
                .await?;
        }
        result
    }

    async fn validate_post_response_inner(
        &self,
        saml_response: &str,
        in_response_to: &mut Option<String>,
    ) -> SamlResult<(Option<Profile>, bool)> {
        let xml = String::from_utf8_lossy(&base64_decode(saml_response)).into_owned();
        let document = parse_dom(&xml)?;
        let root = document.document_element().expect("parsed");
        *in_response_to = if document.local_name(root) == Some("Response") {
            document.attr(root, "InResponseTo").map(str::to_owned)
        } else {
            None
        };
        self.validate_in_response_to(in_response_to.as_deref())
            .await?;
        let pems = self.key_infos_as_pem()?;
        let response_verified = dsig::get_verified_xml(&xml, &document, root, &pems)?;
        let valid_signature = response_verified.is_some();
        if !valid_signature {
            return Err(plain("Invalid document signature"));
        }
        let is_response = document.local_name(root) == Some("Response");
        let assertions = if is_response {
            document.find_children(root, None, "Assertion")
        } else {
            Vec::new()
        };
        let encrypted = if is_response {
            document.find_children(root, None, "EncryptedAssertion")
        } else {
            Vec::new()
        };
        if assertions.len() + encrypted.len() > 1 {
            return Err(plain("Invalid signature: multiple assertions"));
        }
        let mut assertion_verified = None;
        let mut decrypted_verified = None;
        if assertions.len() == 1 {
            assertion_verified = dsig::get_verified_xml(&xml, &document, assertions[0], &pems)?;
            if assertion_verified.is_none() {
                return Err(plain("Invalid signature"));
            }
        }
        if encrypted.len() == 1 {
            let key = self
                .options
                .decryption_pvk
                .clone()
                .filter(|key| !key.is_empty())
                .ok_or_else(|| plain("No decryption key for encrypted SAML response"))?;
            let decrypted_xml = xmlenc::decrypt(&document, encrypted[0], &key)?;
            let decrypted = parse_dom(&decrypted_xml)?;
            let decrypted_root = decrypted.document_element().expect("parsed");
            if decrypted.local_name(decrypted_root) != Some("Assertion") {
                return Err(plain("Invalid EncryptedAssertion content"));
            }
            decrypted_verified =
                dsig::get_verified_xml(&decrypted_xml, &decrypted, decrypted_root, &pems)?;
            if decrypted_verified.is_none() {
                return Err(plain("Invalid signature from encrypted assertion"));
            }
        }
        let verified = response_verified
            .filter(|xml| !xml.is_empty())
            .or(assertion_verified.filter(|xml| !xml.is_empty()))
            .or(decrypted_verified.filter(|xml| !xml.is_empty()));
        if let Some(verified) = verified
            && assertions.len() + encrypted.len() == 1
        {
            let Some(signed) = self.get_signed_assertion(&verified)? else {
                return Err(plain("Cannot obtain assertion from signed data"));
            };
            return self
                .process_validly_signed_assertion(signed, in_response_to.as_deref())
                .await;
        }
        self.unsigned_outcome(&document, root, valid_signature)
    }

    /// The xml2js fallback for responses without an assertion: provider status errors, a logout response, or
    /// `Missing SAML assertion`.
    fn unsigned_outcome(
        &self,
        document: &Document,
        root: NodeId,
        valid_signature: bool,
    ) -> SamlResult<(Option<Profile>, bool)> {
        let parsed = to_xml2js(document, root).map_err(plain)?;
        let response = parsed.get("Response");
        if truthy(response) {
            let response = response.expect("truthy");
            let has_assertion = response
                .as_object()
                .is_some_and(|map| map.contains_key("Assertion"));
            if !has_assertion {
                let status = get(Some(response), "Status")?;
                if truthy(status) {
                    let status0 = get(status, "0")?;
                    let status_code = get(status0, "StatusCode")?;
                    let code_value = |code: Option<&Value>| -> SamlResult<Option<String>> {
                        let first = get(code, "0")?;
                        let attributes = get(first, "$")?;
                        Ok(match attributes {
                            None => None,
                            some => get(some, "Value")?
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                        })
                    };
                    if truthy(status_code)
                        && code_value(status_code)?.as_deref()
                            == Some("urn:oasis:names:tc:SAML:2.0:status:Responder")
                    {
                        let nested = get(get(status_code, "0")?, "StatusCode")?;
                        if truthy(nested)
                            && code_value(nested)?.as_deref()
                                == Some("urn:oasis:names:tc:SAML:2.0:status:NoPassive")
                        {
                            if !valid_signature {
                                return Err(plain("Invalid signature: NoPassive"));
                            }
                            return Ok((None, false));
                        }
                    }
                    if truthy(status_code)
                        && let Some(value) =
                            code_value(status_code)?.filter(|value| !value.is_empty())
                    {
                        let message_type = value.rsplit(':').next().unwrap_or_default().to_owned();
                        if message_type != "Success" {
                            let mut message = "unspecified".to_owned();
                            let status_message = get(status0, "StatusMessage")?;
                            if truthy(status_message) {
                                if let Some(text) = get(get(status_message, "0")?, "_")?
                                    .and_then(Value::as_str)
                                    .filter(|text| !text.is_empty())
                                {
                                    message = text.to_owned();
                                }
                            } else if truthy(get(get(status_code, "0")?, "StatusCode")?)
                                && let Some(nested) =
                                    code_value(get(get(status_code, "0")?, "StatusCode")?)?
                            {
                                message = nested.rsplit(':').next().unwrap_or_default().to_owned();
                            }
                            return Err(plain(format!(
                                "SAML provider returned {message_type} error: {message}"
                            )));
                        }
                    }
                }
            }
            return Err(plain("Missing SAML assertion"));
        }
        if !valid_signature {
            return Err(plain("Invalid signature: No response found"));
        }
        if truthy(parsed.get("LogoutResponse")) {
            return Ok((None, true));
        }
        Err(plain("Unknown SAML response message"))
    }

    /// `calcMaxAgeAssertionTime(maxAssertionAgeMs, notOnOrAfter, issueInstant)`.
    fn calc_max_age_assertion_time(
        &self,
        not_on_or_after: Option<&Value>,
        issue_instant: Option<&Value>,
    ) -> SamlResult<f64> {
        let not_on_or_after = date_string_to_timestamp(not_on_or_after, "NotOnOrAfter")?;
        let issue_instant = date_string_to_timestamp(issue_instant, "IssueInstant")?;
        if self.options.max_assertion_age_ms == 0.0 {
            return Ok(not_on_or_after);
        }
        let max_time = issue_instant + self.options.max_assertion_age_ms;
        Ok(if max_time < not_on_or_after {
            max_time
        } else {
            not_on_or_after
        })
    }

    /// `checkTimestampsValidityError(nowMs, notBefore, notOnOrAfter, maxTimeLimitMs)`: the error message, if any.
    fn check_timestamps(
        &self,
        now: f64,
        not_before: Option<&Value>,
        not_on_or_after: Option<&Value>,
        max_time_limit: Option<f64>,
    ) -> SamlResult<Option<String>> {
        let skew = self.options.accepted_clock_skew_ms;
        if skew == -1.0 {
            return Ok(None);
        }
        if truthy(not_before) {
            let not_before = date_string_to_timestamp(not_before, "NotBefore")?;
            if now + skew < not_before {
                return Ok(Some("SAML assertion not yet valid".into()));
            }
        }
        if truthy(not_on_or_after) {
            let not_on_or_after = date_string_to_timestamp(not_on_or_after, "NotOnOrAfter")?;
            if now - skew >= not_on_or_after {
                return Ok(Some(
                    "SAML assertion expired: clocks skewed too much".into(),
                ));
            }
        }
        if let Some(max) = max_time_limit.filter(|max| *max != 0.0 && !max.is_nan())
            && now - skew >= max
        {
            return Ok(Some("SAML assertion expired: assertion too old".into()));
        }
        Ok(None)
    }

    /// `processValidlySignedAssertionAsync(xml, samlResponseXml, inResponseTo)`.
    async fn process_validly_signed_assertion(
        &self,
        signed: AssertionXml,
        in_response_to: Option<&str>,
    ) -> SamlResult<(Option<Profile>, bool)> {
        let now = now_ms();
        let cache = &self.options.cache_provider;
        let mut profile: IndexMap<String, Option<Value>> = IndexMap::new();
        let parsed = to_xml2js(&signed.document, signed.root).map_err(plain)?;
        let assertion = parsed.get("Assertion");
        'in_response_to: {
            let issuer = get(assertion, "Issuer")?;
            if truthy(issuer) {
                let text = get(get(issuer, "0")?, "_")?;
                if truthy(text) {
                    profile.insert("issuer".into(), text.cloned());
                }
            }
            if let Some(value) = in_response_to {
                profile.insert("inResponseTo".into(), Some(Value::String(value.to_owned())));
            }
            let authn_statement = get(assertion, "AuthnStatement")?;
            if truthy(authn_statement) {
                let attributes = get(get(authn_statement, "0")?, "$")?;
                if truthy(attributes) {
                    let session_index = get(attributes, "SessionIndex")?;
                    if truthy(session_index) {
                        profile.insert("sessionIndex".into(), session_index.cloned());
                    }
                }
            }
            let subject = get(assertion, "Subject")?;
            let mut subject_confirmation: Option<&Value> = None;
            let mut confirm_data: Option<&Value> = None;
            let mut subject_confirmations: Option<&Value> = None;
            if truthy(subject) {
                let subject0 = get(subject, "0")?;
                let name_id = get(subject0, "NameID")?;
                if truthy(name_id) {
                    let first = get(name_id, "0")?;
                    let text = get(first, "_")?;
                    if truthy(text) {
                        profile.insert("nameID".into(), text.cloned());
                        let attributes = get(first, "$")?;
                        if truthy(attributes) && truthy(get(attributes, "Format")?) {
                            profile
                                .insert("nameIDFormat".into(), get(attributes, "Format")?.cloned());
                            profile.insert(
                                "nameQualifier".into(),
                                get(attributes, "NameQualifier")?.cloned(),
                            );
                            profile.insert(
                                "spNameQualifier".into(),
                                get(attributes, "SPNameQualifier")?.cloned(),
                            );
                        }
                    }
                }
                subject_confirmations = get(subject0, "SubjectConfirmation")?;
                if let Some(Value::Array(items)) = subject_confirmations {
                    for item in items {
                        let data = get(Some(item), "SubjectConfirmationData")?;
                        let data = match data {
                            None | Some(Value::Null) => None,
                            some => get(some, "0")?,
                        };
                        let attributes = match data {
                            None => None,
                            some => get(some, "$")?,
                        };
                        if truthy(attributes) {
                            let max_time = self.calc_max_age_assertion_time(
                                get(attributes, "NotOnOrAfter")?,
                                get(get(assertion, "$")?, "IssueInstant")?,
                            )?;
                            let error = self.check_timestamps(
                                now,
                                get(attributes, "NotBefore")?,
                                get(attributes, "NotOnOrAfter")?,
                                Some(max_time),
                            )?;
                            if error.is_none() {
                                subject_confirmation = Some(item);
                                break;
                            }
                        }
                    }
                }
                if let Some(confirmation) = subject_confirmation {
                    confirm_data = get(get(Some(confirmation), "SubjectConfirmationData")?, "0")?;
                }
            }
            // A SubjectConfirmation InResponseTo must match the Response's.
            if self
                .must_validate_in_response_to(in_response_to.is_some_and(|value| !value.is_empty()))
            {
                if subject_confirmation.is_some() {
                    let attributes = match confirm_data {
                        None => None,
                        some => get(some, "$")?,
                    };
                    if truthy(attributes) {
                        let subject_in_response_to = get(attributes, "InResponseTo")?;
                        let subject_text = js_string(subject_in_response_to);
                        if in_response_to.is_some_and(|value| !value.is_empty())
                            && truthy(subject_in_response_to)
                            && Some(subject_text.as_str()) != in_response_to
                        {
                            cache.remove(in_response_to).await?;
                            return Err(plain("InResponseTo does not match subjectInResponseTo"));
                        } else if truthy(subject_in_response_to) {
                            let mut found = false;
                            if let Some(result) = cache
                                .get(&subject_text)
                                .await?
                                .filter(|value| !value.is_empty())
                            {
                                let created_at = better_iam_auth::js_date::parse(&result);
                                if now < created_at + self.options.request_id_expiration_period_ms {
                                    found = true;
                                }
                            }
                            cache.remove(in_response_to).await?;
                            if !found {
                                return Err(plain("SubjectInResponseTo is not valid"));
                            }
                            break 'in_response_to;
                        }
                    }
                } else if subject_confirmations.is_some_and(|value| !value.is_null()) {
                    return Err(plain(
                        "No valid subject confirmation found among those available in the SAML assertion",
                    ));
                } else {
                    cache.remove(in_response_to).await?;
                    break 'in_response_to;
                }
            }
        }
        let conditions_list = get(assertion, "Conditions")?;
        let conditions = if truthy(conditions_list) {
            get(conditions_list, "0")?
        } else {
            Some(&Value::Null)
        };
        if truthy(conditions_list)
            && conditions_list
                .and_then(Value::as_array)
                .is_some_and(|items| items.len() > 1)
        {
            return Err(plain(
                "Unable to process multiple conditions in SAML assertion",
            ));
        }
        if truthy(conditions) {
            let attributes = get(conditions, "$")?;
            if truthy(attributes) {
                let max_time = self.calc_max_age_assertion_time(
                    get(attributes, "NotOnOrAfter")?,
                    get(get(assertion, "$")?, "IssueInstant")?,
                )?;
                if let Some(error) = self.check_timestamps(
                    now,
                    get(attributes, "NotBefore")?,
                    get(attributes, "NotOnOrAfter")?,
                    Some(max_time),
                )? {
                    return Err(plain(error));
                }
            }
        }
        if let Some(error) = self.check_audience(get(conditions, "AudienceRestriction")?)? {
            return Err(plain(error));
        }
        let attribute_statement = get(assertion, "AttributeStatement")?;
        if truthy(attribute_statement) {
            let mut attributes: Vec<&Value> = Vec::new();
            if let Some(Value::Array(statements)) = attribute_statement {
                for statement in statements {
                    if let Some(Value::Array(items)) = get(Some(statement), "Attribute")? {
                        attributes.extend(items.iter());
                    }
                }
            }
            if !attributes.is_empty() {
                let mut profile_attributes: IndexMap<String, Option<Value>> = IndexMap::new();
                for attribute in attributes {
                    let Some(values) = attribute
                        .as_object()
                        .and_then(|map| map.get("AttributeValue"))
                    else {
                        continue;
                    };
                    let name = js_string(get(get(Some(attribute), "$")?, "Name")?);
                    let value = match values {
                        Value::Array(items) if items.len() == 1 => attribute_value(&items[0]),
                        Value::Array(items) => Some(Value::Array(
                            items
                                .iter()
                                .map(|item| attribute_value(item).unwrap_or(Value::Null))
                                .collect(),
                        )),
                        other => attribute_value(other),
                    };
                    profile_attributes.insert(name.clone(), value.clone());
                    if profile.contains_key(&name) {
                        continue;
                    }
                    profile.insert(name, value);
                }
                let object: Map<String, Value> = profile_attributes
                    .into_iter()
                    .map(|(key, value)| (key, value.unwrap_or(Value::Null)))
                    .collect();
                profile.insert("attributes".into(), Some(Value::Object(object)));
            }
        }
        let member = |profile: &IndexMap<String, Option<Value>>, key: &str| {
            profile.get(key).cloned().flatten()
        };
        if !truthy(member(&profile, "mail").as_ref()) {
            let oid = member(&profile, "urn:oid:0.9.2342.19200300.100.1.3");
            if truthy(oid.as_ref()) {
                profile.insert("mail".into(), oid);
            }
        }
        if !truthy(member(&profile, "email").as_ref()) {
            let mail = member(&profile, "mail");
            if truthy(mail.as_ref()) {
                profile.insert("email".into(), mail);
            }
        }
        Ok((
            Some(Profile {
                members: profile,
                assertion: signed,
            }),
            false,
        ))
    }

    /// `checkAudienceValidityError(expectedAudience, audienceRestrictions)`: the error message, if any.
    fn check_audience(&self, restrictions: Option<&Value>) -> SamlResult<Option<String>> {
        let items = match restrictions {
            Some(Value::Array(items)) if !items.is_empty() => items,
            _ => return Ok(Some("SAML assertion has no AudienceRestriction".into())),
        };
        let expected = &self.options.audience;
        for restriction in items {
            let audience = get(Some(restriction), "Audience")?;
            let first = match audience {
                Some(Value::Array(list)) => list.first(),
                _ => None,
            };
            if !truthy(audience) || first.is_none() || !truthy(get(first, "_")?) {
                return Ok(Some(
                    "SAML assertion AudienceRestriction has no Audience value".into(),
                ));
            }
            let list = audience
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let texts: Vec<Option<String>> = list
                .iter()
                .map(|item| {
                    item.as_object()
                        .and_then(|map| map.get("_"))
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .collect();
            if texts
                .iter()
                .all(|text| text.as_deref() != Some(expected.as_str()))
            {
                let received: Vec<String> =
                    texts.into_iter().map(Option::unwrap_or_default).collect();
                return Ok(Some(format!(
                    "SAML assertion audience mismatch. Expected: {expected} Received: {}",
                    received.join(", ")
                )));
            }
        }
        Ok(None)
    }
}

/// `attrValueMapper(value)`: the object itself when it has child elements, otherwise its text.
fn attribute_value(value: &Value) -> Option<Value> {
    match value {
        Value::Object(map) => {
            if map.keys().any(|key| key != "_" && key != "$") {
                Some(value.clone())
            } else {
                map.get("_").cloned()
            }
        }
        Value::String(text) if !text.is_empty() => Some(value.clone()),
        _ => None,
    }
}

/// `parseDomFromString(xml)`: errors (not warnings) reject.
pub fn parse_dom(xml: &str) -> SamlResult<Document> {
    Document::parse(xml).map_err(|error| plain(error.0))
}
