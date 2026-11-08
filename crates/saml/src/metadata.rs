//! Port of `packages/saml/src/metadata.ts`: IdP metadata import and the certificate details administrators need to
//! watch rollover (`X509Certificate`'s `fingerprint256`, `subject`, `validFrom` and `validTo`, as Node formats them).

use std::sync::LazyLock;

use better_iam_core::{IamError, js};
use der::asn1::ObjectIdentifier;
use der::{Decode, Tag, Tagged};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::time::Time;

use crate::c14n::DSIG_NS;
use crate::keys::base64_decode;
use crate::xml::{Document, is_js_space};

const METADATA_NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
const REDIRECT_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

/// What a service provider needs from an identity provider's SAML metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdpMetadata {
    pub entity_id: String,
    /// The HTTP-Redirect single sign-on endpoint.
    pub entry_point: String,
    /// PEM signing certificates, in document order (several during certificate rollover).
    pub certificates: Vec<String>,
    /// The HTTP-Redirect single logout endpoint, when published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub single_logout_url: Option<String>,
}

/// Details administrators need to watch certificate rollover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pub fingerprint256: String,
    pub subject: String,
    pub not_before: String,
    pub not_after: String,
    pub expired: bool,
}

fn invalid_certificate() -> IamError {
    IamError::new(
        "INVALID_INPUT",
        "IdP certificates must be X.509 certificates.",
    )
}

static BASE64_BODY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/]+=*$").unwrap());

/// The DER of a PEM certificate (`new X509Certificate(pem)`), when it parses.
fn certificate_der(pem: &str) -> Option<(Vec<u8>, Certificate)> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64_decode(&body);
    let certificate = Certificate::from_der(&der).ok()?;
    Some((der, certificate))
}

/// Normalizes a PEM or bare base64 DER certificate to PEM, rejecting anything that is not a parseable X.509
/// certificate.
pub fn normalize_certificate(value: &str) -> Result<String, IamError> {
    let without_armor = value
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "");
    let body: String = without_armor.chars().filter(|c| !is_js_space(*c)).collect();
    if body.is_empty() || js::utf16_len(&body) > 16_384 || !BASE64_BODY.is_match(&body) {
        return Err(invalid_certificate());
    }
    let chars: Vec<char> = body.chars().collect();
    let lines: Vec<String> = chars
        .chunks(64)
        .map(|chunk| chunk.iter().collect())
        .collect();
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        lines.join("\n")
    );
    if certificate_der(&pem).is_none() {
        return Err(invalid_certificate());
    }
    Ok(pem)
}

/// OpenSSL's short names of the attribute types (`XN_FLAG_FN_SN`).
fn short_name(oid: &ObjectIdentifier) -> String {
    let dotted = oid.to_string();
    let name = match dotted.as_str() {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "street",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "title",
        "2.5.4.13" => "description",
        "2.5.4.15" => "businessCategory",
        "2.5.4.16" => "postalAddress",
        "2.5.4.17" => "postalCode",
        "2.5.4.18" => "postOfficeBox",
        "2.5.4.41" => "name",
        "2.5.4.42" => "GN",
        "2.5.4.43" => "initials",
        "2.5.4.44" => "generationQualifier",
        "2.5.4.46" => "dnQualifier",
        "2.5.4.65" => "pseudonym",
        "2.5.4.97" => "organizationIdentifier",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "0.9.2342.19200300.100.1.1" => "UID",
        "0.9.2342.19200300.100.1.25" => "DC",
        "1.3.6.1.4.1.311.60.2.1.1" => "jurisdictionL",
        "1.3.6.1.4.1.311.60.2.1.2" => "jurisdictionST",
        "1.3.6.1.4.1.311.60.2.1.3" => "jurisdictionC",
        _ => return dotted,
    };
    name.to_owned()
}

/// The text of a directory string (UTF-8, Printable, IA5, Visible, Teletex or BMP string).
fn directory_string(tag: Tag, bytes: &[u8]) -> String {
    match tag {
        Tag::BmpString => {
            let units: Vec<u16> = bytes
                .chunks(2)
                .map(|pair| u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        Tag::TeletexString => bytes.iter().map(|byte| *byte as char).collect(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// `ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_ESC_CTRL`.
fn escape_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::new();
    for (index, &c) in chars.iter().enumerate() {
        let first = index == 0;
        let last = index == chars.len() - 1;
        if matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';')
            || (first && (c == '#' || c == ' '))
            || (last && c == ' ')
        {
            out.push('\\');
            out.push(c);
        } else if (c as u32) < 0x20 || c as u32 == 0x7f {
            out.push_str(&format!("\\{:02X}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// `X509Certificate.subject`: one `type=value` line per RDN, multi-valued RDNs joined with ` + `.
fn subject(certificate: &Certificate) -> String {
    certificate
        .tbs_certificate
        .subject
        .0
        .iter()
        .map(|rdn| {
            rdn.0
                .iter()
                .map(|attribute| {
                    let value = attribute.value.value();
                    format!(
                        "{}={}",
                        short_name(&attribute.oid),
                        escape_value(&directory_string(attribute.value.tag(), value))
                    )
                })
                .collect::<Vec<_>>()
                .join(" + ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn time_ms(time: &Time) -> f64 {
    time.to_unix_duration().as_millis() as f64
}

/// The details of a PEM certificate: SHA-256 fingerprint (`AB:CD:...`), subject, validity and whether it expired.
pub fn certificate_info(pem: &str) -> Result<CertificateInfo, IamError> {
    let (der, certificate) = certificate_der(pem).ok_or_else(invalid_certificate)?;
    let fingerprint = Sha256::digest(&der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let validity = &certificate.tbs_certificate.validity;
    let not_before = time_ms(&validity.not_before);
    let not_after = time_ms(&validity.not_after);
    Ok(CertificateInfo {
        fingerprint256: fingerprint,
        subject: subject(&certificate),
        not_before: js::iso_string(not_before).unwrap_or_default(),
        not_after: js::iso_string(not_after).unwrap_or_default(),
        expired: not_after <= js::now_ms(),
    })
}

static UNSAFE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<!DOCTYPE|<!ENTITY").unwrap());

/// Reads entity ID, redirect-binding SSO/SLO endpoints, and signing certificates from IdP metadata. The document must
/// describe exactly one identity provider; DTDs and entities are refused. Metadata signatures are not checked: import
/// metadata only from a source you trust (an administrator upload or an HTTPS URL of the IdP).
pub fn parse_idp_metadata(xml: &str) -> Result<IdpMetadata, IamError> {
    if js::utf16_len(xml) > 512 * 1024 || UNSAFE.is_match(xml) {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Unsafe or oversized SAML metadata.",
        ));
    }
    let one_idp = || {
        IamError::new(
            "INVALID_INPUT",
            "Metadata must describe exactly one identity provider.",
        )
    };
    let document = Document::parse(xml).map_err(|_| one_idp())?;
    let descriptors =
        document.find_descendants(Document::ROOT, Some(METADATA_NS), "IDPSSODescriptor");
    if descriptors.len() != 1 {
        return Err(one_idp());
    }
    let idp = descriptors[0];
    let entity_id = document
        .parent(idp)
        .filter(|entity| document.is(*entity, Some(METADATA_NS), "EntityDescriptor"))
        .and_then(|entity| document.attr(entity, "entityID"))
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| IamError::new("INVALID_INPUT", "The identity provider has no entityID."))?;
    let endpoint = |name: &str| -> Option<String> {
        document
            .find_descendants(idp, Some(METADATA_NS), name)
            .into_iter()
            .find(|service| document.attr(*service, "Binding") == Some(REDIRECT_BINDING))
            .and_then(|service| document.attr(service, "Location").map(str::to_owned))
    };
    let entry_point = endpoint("SingleSignOnService")
        .filter(|location| !location.is_empty())
        .ok_or_else(|| {
            IamError::new(
                "INVALID_INPUT",
                "The identity provider has no HTTP-Redirect sign-on endpoint.",
            )
        })?;
    let mut certificates: Vec<String> = Vec::new();
    for key in document.find_descendants(idp, Some(METADATA_NS), "KeyDescriptor") {
        if let Some(usage) = document.attr(key, "use")
            && !usage.is_empty()
            && usage != "signing"
        {
            continue;
        }
        for cert in document.find_descendants(key, Some(DSIG_NS), "X509Certificate") {
            let pem = normalize_certificate(&document.text_content(cert))?;
            if !certificates.contains(&pem) {
                certificates.push(pem);
            }
        }
    }
    if certificates.is_empty() {
        return Err(IamError::new(
            "INVALID_INPUT",
            "The identity provider publishes no signing certificate.",
        ));
    }
    let single_logout_url = endpoint("SingleLogoutService").filter(|location| !location.is_empty());
    Ok(IdpMetadata {
        entity_id,
        entry_point,
        certificates,
        single_logout_url,
    })
}
