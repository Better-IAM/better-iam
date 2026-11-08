//! XML signatures as the TypeScript implementation checks and makes them: Node-SAML's `getVerifiedXml` over
//! `xml-crypto` 6's `SignedXml` (`loadSignature`, `checkSignature`, `validateReference`, the enveloped-signature
//! transform), and `computeSignature` for signed metadata. Only the canonical bytes of the one reference a signature
//! covers are trusted afterwards (the returned "signed reference"), which is what defeats signature wrapping:
//! callers read identities from those bytes, never from the document they were handed.

use crate::c14n::{self, C14nOptions, DSIG_NS, NsDecl, find_ancestor_ns};
use crate::keys::{
    Hash, SamlError, SamlResult, base64_decode, base64_encode, pem_blocks, rsa_sign, rsa_verify,
};
use crate::xml::{Document, Kind, NodeId};

pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const EXC_C14N_WITH_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
pub const C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
pub const C14N_WITH_COMMENTS: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
pub const ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
pub const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
pub const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

/// The ID attributes `xml-crypto` looks references up by, in order.
const ID_ATTRIBUTES: [&str; 3] = ["Id", "ID", "id"];

fn plain(message: impl Into<String>) -> SamlError {
    SamlError::plain(message)
}

fn digest_hash(algorithm: &str) -> SamlResult<Hash> {
    match algorithm {
        SHA1 => Ok(Hash::Sha1),
        SHA256 => Ok(Hash::Sha256),
        SHA512 => Ok(Hash::Sha512),
        other => Err(plain(format!("hash algorithm '{other}' is not supported"))),
    }
}

fn signature_hash(algorithm: Option<&str>) -> SamlResult<Hash> {
    match algorithm {
        None => Err(plain("signatureAlgorithm is required")),
        Some(RSA_SHA1) => Ok(Hash::Sha1),
        Some(RSA_SHA256) => Ok(Hash::Sha256),
        Some(RSA_SHA512) => Ok(Hash::Sha512),
        Some(other) => Err(plain(format!(
            "signature algorithm '{other}' is not supported"
        ))),
    }
}

fn is_canonicalization(algorithm: &str) -> bool {
    matches!(
        algorithm,
        EXC_C14N | EXC_C14N_WITH_COMMENTS | C14N | C14N_WITH_COMMENTS | ENVELOPED_SIGNATURE
    )
}

/// `findAttr(element, localName)`: the first attribute with that local name, in any namespace.
fn find_attr<'a>(document: &'a Document, id: NodeId, local: &str) -> Option<&'a str> {
    document
        .element(id)?
        .attrs
        .iter()
        .find(|attr| attr.local == local)
        .map(|attr| attr.value.as_str())
}

/// The first `text()` node child of the first `SignatureValue` below `node`, when it is a text node
/// (`xpath.select1(".//*[local-name(.)='SignatureValue']/text()")` checked with `isTextNode`).
fn signature_value_text(document: &Document, node: NodeId) -> Option<String> {
    for value in document.find_descendants(node, None, "SignatureValue") {
        for child in document.children(value) {
            match document.kind(*child) {
                Kind::Text(text) => return Some(text.clone()),
                Kind::CData(_) => return None,
                _ => {}
            }
        }
    }
    None
}

/// The first element (document element included) with any attribute of local name `attr` whose value is `value`
/// (`//*[@*[local-name(.)='attr']='value']`).
fn elements_with_id(document: &Document, attr: &str, value: &str) -> Vec<NodeId> {
    document
        .descendants(Document::ROOT)
        .into_iter()
        .filter(|node| {
            document.element(*node).is_some_and(|element| {
                element
                    .attrs
                    .iter()
                    .any(|item| item.local == attr && item.value == value)
            })
        })
        .collect()
}

/// A `<Reference>` of a signature.
#[derive(Debug, Clone, Default)]
struct Reference {
    /// The ID attribute the referenced element was found by (`ref.xpath`).
    id_attribute: Option<String>,
    transforms: Vec<String>,
    digest_algorithm: String,
    uri: String,
    digest_value: String,
    inclusive_prefixes: Vec<String>,
}

/// The enveloped-signature transform. With a signature node, removes every descendant signature whose
/// `SignatureValue` equals its own; without one, the first child signature.
fn enveloped(clone: &mut Document, node: NodeId, expected: Option<Option<String>>) {
    match expected {
        None => {
            if let Some(signature) = clone
                .find_children(node, Some(DSIG_NS), "Signature")
                .first()
                .copied()
            {
                clone.detach(signature);
            }
        }
        Some(Some(expected)) => {
            for signature in clone.find_descendants(node, Some(DSIG_NS), "Signature") {
                if signature_value_text(clone, signature).as_deref() == Some(expected.as_str()) {
                    clone.detach(signature);
                }
            }
        }
        Some(None) => {}
    }
}

/// `getCanonXml(transforms, node, options)`: the transforms run on a clone of `node` until the first
/// canonicalization turns it into text; later transforms are skipped. `signature_value` is the `SignatureValue` of
/// `options.signatureNode` (None when there is no signature node, as while signing).
fn canon_xml(
    transforms: &[String],
    document: &Document,
    node: NodeId,
    options: &C14nOptions,
    signature_value: Option<Option<String>>,
) -> SamlResult<String> {
    let (mut clone, root) = document.clone_subtree(node);
    for transform in transforms {
        let c14n_error = |error: c14n::C14nError| plain(error.0);
        match transform.as_str() {
            EXC_C14N => {
                return c14n::exclusive(&mut clone, root, options, false).map_err(c14n_error);
            }
            EXC_C14N_WITH_COMMENTS => {
                return c14n::exclusive(&mut clone, root, options, true).map_err(c14n_error);
            }
            C14N => return c14n::inclusive(&clone, root, options, false).map_err(c14n_error),
            C14N_WITH_COMMENTS => {
                return c14n::inclusive(&clone, root, options, true).map_err(c14n_error);
            }
            ENVELOPED_SIGNATURE => enveloped(&mut clone, root, signature_value.clone()),
            other => {
                return Err(plain(format!(
                    "canonicalization algorithm '{other}' is not supported"
                )));
            }
        }
    }
    Ok(clone.serialize(root))
}

/// The state `new SignedXml()` builds while loading and checking one signature.
struct SignedXml<'a> {
    /// The document the signature node belongs to, and the node.
    document: &'a Document,
    signature: NodeId,
    canonicalization: Option<String>,
    signature_algorithm: Option<String>,
    references: Vec<Reference>,
    signature_value: String,
    public_cert: String,
    signed_references: Vec<String>,
}

impl<'a> SignedXml<'a> {
    /// `sig.loadSignature(signatureNode)`.
    fn load(
        document: &'a Document,
        signature: NodeId,
        public_cert: &str,
    ) -> SamlResult<SignedXml<'a>> {
        let mut sig = SignedXml {
            document,
            signature,
            canonicalization: None,
            signature_algorithm: None,
            references: Vec::new(),
            signature_value: String::new(),
            public_cert: public_cert.to_owned(),
            signed_references: Vec::new(),
        };
        let first_algorithm = |local: &str| -> Option<Option<String>> {
            document
                .find_descendants(signature, None, local)
                .into_iter()
                .find(|node| {
                    document
                        .element(*node)
                        .is_some_and(|element| element.attrs.iter().any(|a| a.name == "Algorithm"))
                })
                .map(|node| document.attr(node, "Algorithm").map(str::to_owned))
        };
        match first_algorithm("CanonicalizationMethod") {
            Some(algorithm) => sig.canonicalization = algorithm,
            None => {
                return Err(plain(
                    "could not find CanonicalizationMethod/@Algorithm element",
                ));
            }
        }
        if let Some(algorithm) = first_algorithm("SignatureMethod") {
            sig.signature_algorithm = algorithm;
        }
        let signed_info = document.find_children(signature, None, "SignedInfo");
        if signed_info.is_empty() {
            return Err(plain("no signed info node found"));
        }
        if signed_info.len() > 1 {
            return Err(plain(
                "could not load signature that contains multiple SignedInfo nodes",
            ));
        }
        let for_signed_info = match sig.canonicalization.as_deref() {
            None | Some(C14N) | Some(C14N_WITH_COMMENTS) => EXC_C14N.to_owned(),
            Some(other) => other.to_owned(),
        };
        let canon = sig.canon_xml(
            &[for_signed_info],
            document,
            signed_info[0],
            &C14nOptions::default(),
        )?;
        sig.load_references(&canon)?;
        if let Some(value) = signature_value_text(document, signature) {
            sig.signature_value = value.replace("\r\n", "").replace('\n', "");
        }
        Ok(sig)
    }

    /// `getCanonXml` with this signature as `options.signatureNode`.
    fn canon_xml(
        &self,
        transforms: &[String],
        document: &Document,
        node: NodeId,
        options: &C14nOptions,
    ) -> SamlResult<String> {
        canon_xml(
            transforms,
            document,
            node,
            options,
            Some(signature_value_text(self.document, self.signature)),
        )
    }

    /// The references of a canonical SignedInfo (`findChildren(signedInfo, 'Reference')` + `loadReference`).
    fn load_references(&mut self, canonical_signed_info: &str) -> SamlResult<()> {
        let parsed = Document::parse(canonical_signed_info).map_err(|error| plain(error.0))?;
        let root = parsed
            .document_element()
            .ok_or_else(|| plain("could not find any Reference elements"))?;
        self.references.clear();
        let references = parsed.find_children(root, None, "Reference");
        if references.is_empty() {
            return Err(plain("could not find any Reference elements"));
        }
        for reference in references {
            self.load_reference(&parsed, reference)?;
        }
        Ok(())
    }

    /// `loadReference(refNode)`.
    fn load_reference(&mut self, document: &Document, reference: NodeId) -> SamlResult<()> {
        let describe = || document.serialize(reference);
        let methods = document.find_children(reference, None, "DigestMethod");
        let Some(method) = methods.first() else {
            return Err(plain(format!(
                "could not find DigestMethod in reference {}",
                describe()
            )));
        };
        let Some(digest_algorithm) = find_attr(document, *method, "Algorithm") else {
            return Err(plain(format!(
                "could not find Algorithm attribute in node {}",
                document.serialize(*method)
            )));
        };
        let values = document.find_children(reference, None, "DigestValue");
        if values.is_empty() {
            return Err(plain(format!(
                "could not find DigestValue node in reference {}",
                describe()
            )));
        }
        if values.len() > 1 {
            return Err(plain(format!(
                "could not load reference for a node that contains multiple DigestValue nodes: {}",
                describe()
            )));
        }
        let digest_value = document.text_content(values[0]);
        if digest_value.is_empty() {
            return Err(plain(format!(
                "could not find the value of DigestValue in {}",
                describe()
            )));
        }
        let mut transforms = Vec::new();
        let mut inclusive_prefixes = Vec::new();
        if let Some(list) = document
            .find_children(reference, None, "Transforms")
            .first()
        {
            let all = document.find_children(*list, None, "Transform");
            for transform in &all {
                if let Some(algorithm) = find_attr(document, *transform, "Algorithm") {
                    transforms.push(algorithm.to_owned());
                }
            }
            let Some(last) = all.last() else {
                return Err(plain(
                    "Cannot read properties of undefined (reading 'documentElement')",
                ));
            };
            for namespaces in document.find_children(*last, None, "InclusiveNamespaces") {
                inclusive_prefixes.extend(
                    document
                        .attr(namespaces, "PrefixList")
                        .unwrap_or_default()
                        .split(' ')
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned),
                );
            }
        }
        if transforms
            .last()
            .is_none_or(|last| last == ENVELOPED_SIGNATURE)
        {
            transforms.push(C14N.to_owned());
        }
        let uri = document
            .attr(reference, "URI")
            .filter(|uri| !uri.is_empty())
            .unwrap_or_default()
            .to_owned();
        self.references.push(Reference {
            id_attribute: None,
            transforms,
            digest_algorithm: digest_algorithm.to_owned(),
            uri,
            digest_value,
            inclusive_prefixes,
        });
        Ok(())
    }

    /// `validateReference(ref, doc)`.
    fn validate_reference(&mut self, index: usize, document: &Document) -> SamlResult<bool> {
        let reference = self.references[index].clone();
        let uri = reference
            .uri
            .strip_prefix('#')
            .unwrap_or(&reference.uri)
            .to_owned();
        let mut element = None;
        let mut id_attribute = None;
        if uri.is_empty() {
            element = document.document_element();
        } else if uri.contains('\'') {
            return Err(plain("Cannot validate a uri with quotes inside it"));
        } else {
            let mut count = 0;
            for attr in ID_ATTRIBUTES {
                let found = elements_with_id(document, attr, &uri);
                if !found.is_empty() {
                    count += found.len();
                    if count > 1 {
                        return Err(plain(
                            "Cannot validate a document which contains multiple elements with the same value for the \
                             ID / Id / Id attributes, in order to prevent signature wrapping attack.",
                        ));
                    }
                    element = Some(found[0]);
                    id_attribute = Some(attr.to_owned());
                }
            }
        }
        self.references[index].id_attribute = id_attribute.clone();
        let Some(element) = element else {
            return Ok(false);
        };
        let ancestors: Vec<NsDecl> = match &id_attribute {
            Some(attr) => find_ancestor_ns(
                document,
                elements_with_id(document, attr, &uri).first().copied(),
            ),
            None => Vec::new(),
        };
        let options = C14nOptions {
            inclusive_prefixes: reference.inclusive_prefixes.clone(),
            ancestor_namespaces: ancestors,
        };
        let canonical = self.canon_xml(&reference.transforms, document, element, &options)?;
        let digest =
            base64_encode(&digest_hash(&reference.digest_algorithm)?.digest(canonical.as_bytes()));
        if base64_decode(&digest) != base64_decode(&reference.digest_value) {
            return Ok(false);
        }
        self.signed_references.push(canonical);
        Ok(true)
    }

    /// `checkSignature(xml)`: Ok(false) when a reference does not validate, an error when the signature value does
    /// not verify or the signature is unusable.
    fn check(&mut self, xml: &str) -> SamlResult<bool> {
        let document = Document::parse(xml).map_err(|error| plain(error.0))?;
        self.references.clear();
        let canonicalization = self.canonicalization.clone().ok_or_else(|| {
            plain("Missing canonicalizationAlgorithm when trying to get signed info for XML")
        })?;
        let signed_info = self
            .document
            .find_children(self.signature, None, "SignedInfo");
        if signed_info.is_empty() {
            return Err(plain("could not find SignedInfo element in the message"));
        }
        if signed_info.len() > 1 {
            return Err(plain(
                "could not get canonicalized signed info for a signature that contains multiple SignedInfo nodes",
            ));
        }
        let first_signed_info = document
            .find_descendants(Document::ROOT, None, "SignedInfo")
            .first()
            .copied();
        let options = C14nOptions {
            inclusive_prefixes: Vec::new(),
            ancestor_namespaces: find_ancestor_ns(&document, first_signed_info),
        };
        let canonical =
            self.canon_xml(&[canonicalization], self.document, signed_info[0], &options)?;
        if canonical.is_empty() {
            return Err(plain("Canonical signed info cannot be empty"));
        }
        self.load_references(&canonical)?;
        for index in 0..self.references.len() {
            if !self.validate_reference(index, &document)? {
                self.signed_references.clear();
                return Ok(false);
            }
        }
        let hash = signature_hash(self.signature_algorithm.as_deref())?;
        if rsa_verify(
            &self.public_cert,
            hash,
            canonical.as_bytes(),
            &self.signature_value,
        )? {
            Ok(true)
        } else {
            self.signed_references.clear();
            Err(plain(format!(
                "invalid signature: the signature value {} is incorrect",
                self.signature_value
            )))
        }
    }
}

/// `normalizeNewlines(xml)`: `\r\n?` → `\n`.
fn normalize_newlines(xml: &str) -> String {
    xml.replace("\r\n", "\n").replace('\r', "\n")
}

/// Node-SAML's `getVerifiedXml(fullXml, currentNode, pemFiles)`: the canonical bytes of `current` as covered by its
/// one enveloped signature, verified with one of the certificates; None when it carries no signature or none
/// verifies. Structural problems (several signatures, too many transforms, a reference that does not point at the
/// signed element exactly once) are errors.
pub fn get_verified_xml(
    full_xml: &str,
    document: &Document,
    current: NodeId,
    pems: &[String],
) -> SamlResult<Option<String>> {
    let full_xml = normalize_newlines(full_xml);
    let signatures = document.find_children(current, Some(DSIG_NS), "Signature");
    if signatures.is_empty() {
        return Ok(None);
    }
    if signatures.len() > 1 {
        return Err(plain("Too many signatures found for this element"));
    }
    let signature = signatures[0];
    if document
        .find_descendants(signature, Some(DSIG_NS), "Transform")
        .len()
        > 2
    {
        return Err(plain("Invalid signature, too many transforms"));
    }
    for pem in pems {
        let mut sig = SignedXml::load(document, signature, pem)?;
        if sig.references.len() != 1 {
            return Ok(None);
        }
        if document.parent(signature).is_none() {
            return Ok(None);
        }
        let uri = sig.references[0].uri.clone();
        let reference_id = uri.strip_prefix('#').unwrap_or(&uri).to_owned();
        if reference_id.is_empty() {
            return Err(plain("signature reference uri not found"));
        }
        if reference_id.contains('\'') || reference_id.contains('"') {
            return Err(plain(
                "ref URI included quote character ' or \". Not a valid ID, and not allowed",
            ));
        }
        let referenced: Vec<NodeId> = document
            .descendants(Document::ROOT)
            .into_iter()
            .filter(|node| {
                document.element(*node).is_some_and(|element| {
                    element
                        .attrs
                        .iter()
                        .any(|attr| attr.name == "ID" && attr.value == reference_id)
                })
            })
            .collect();
        if referenced.len() != 1 {
            return Err(plain(
                "Invalid signature: ID cannot refer to more than one element",
            ));
        }
        if Some(referenced[0]) != document.parent(signature) {
            return Err(plain(
                "Invalid signature: Referenced node does not refer to it's parent element",
            ));
        }
        match sig.check(&full_xml) {
            Ok(true) => {
                if sig.signed_references.len() != 1 {
                    // Thrown inside the try that tries the next certificate.
                    continue;
                }
                return Ok(sig.signed_references.pop());
            }
            Ok(false) | Err(_) => continue,
        }
    }
    Ok(None)
}

// --- signing ----------------------------------------------------------------------------------------------------

/// The elements an XPath of the signing code selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// `//*[local-name()='local' (and namespace-uri()='namespace')]`.
    Descendants {
        namespace: Option<String>,
        local: String,
    },
    /// `{parent}/*[local-name()='local' (and namespace-uri()='namespace')]`.
    Children {
        parent: Box<Selector>,
        namespace: Option<String>,
        local: String,
    },
}

impl Selector {
    /// `//*[local-name()='local']`.
    pub fn local(local: &str) -> Selector {
        Selector::Descendants {
            namespace: None,
            local: local.to_owned(),
        }
    }

    /// `//*[local-name()='local' and namespace-uri()='namespace']`.
    pub fn qualified(namespace: &str, local: &str) -> Selector {
        Selector::Descendants {
            namespace: Some(namespace.to_owned()),
            local: local.to_owned(),
        }
    }

    /// `{self}/*[local-name()='local']`.
    pub fn child(self, local: &str) -> Selector {
        Selector::Children {
            parent: Box::new(self),
            namespace: None,
            local: local.to_owned(),
        }
    }

    /// The selected elements in document order.
    pub fn select(&self, document: &Document) -> Vec<NodeId> {
        match self {
            Selector::Descendants { namespace, local } => {
                document.find_descendants(Document::ROOT, namespace.as_deref(), local)
            }
            Selector::Children {
                parent,
                namespace,
                local,
            } => {
                let mut out = Vec::new();
                for node in parent.select(document) {
                    out.extend(document.find_children(node, namespace.as_deref(), local));
                }
                out.sort_unstable();
                out.dedup();
                let order = document.descendants(Document::ROOT);
                out.sort_by_key(|node| order.iter().position(|item| item == node));
                out
            }
        }
    }
}

/// Where `computeSignature` puts the signature relative to the located element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Append,
    Prepend,
    Before,
    After,
}

/// A reference to sign.
#[derive(Debug, Clone)]
pub struct SignReference {
    pub selector: Selector,
    pub transforms: Vec<String>,
    pub digest_algorithm: String,
}

/// `new SignedXml({ privateKey, publicCert, signatureAlgorithm, canonicalizationAlgorithm })` with references and a
/// location, for `computeSignature`.
#[derive(Debug, Clone)]
pub struct SignOptions {
    pub private_key: String,
    /// Adds `<KeyInfo><X509Data>` with the certificates of this PEM.
    pub public_cert: Option<String>,
    pub signature_algorithm: String,
    pub canonicalization_algorithm: String,
    pub references: Vec<SignReference>,
    pub location: Selector,
    pub action: Action,
}

/// `ensureHasId(node)`: the node's `Id`/`ID`/`id` (any namespace), or a new `Id="_{n}"`.
fn ensure_has_id(document: &mut Document, node: NodeId, counter: &mut usize) -> String {
    for attr in ID_ATTRIBUTES {
        if let Some(value) = find_attr(document, node, attr) {
            return value.to_owned();
        }
    }
    let id = format!("_{counter}");
    *counter += 1;
    document.set_attribute(node, "Id", &id);
    id
}

/// `computeSignature(xml, { location })` + `getSignedXml()`.
pub fn compute_signature(xml: &str, options: &SignOptions) -> SamlResult<String> {
    let mut document = Document::parse(xml).map_err(|error| plain(error.0))?;
    if !is_canonicalization(&options.canonicalization_algorithm) {
        return Err(plain(format!(
            "canonicalization algorithm '{}' is not supported",
            options.canonicalization_algorithm
        )));
    }
    let hash = signature_hash(Some(&options.signature_algorithm))?;
    let mut counter = 0;
    let mut references = String::new();
    for reference in &options.references {
        let nodes = reference.selector.select(&document);
        if nodes.is_empty() {
            return Err(plain(format!(
                "the following xpath cannot be signed because it was not found: {:?}",
                reference.selector
            )));
        }
        for node in nodes {
            let id = ensure_has_id(&mut document, node, &mut counter);
            references.push_str(&format!("<Reference URI=\"#{id}\"><Transforms>"));
            for transform in &reference.transforms {
                if !is_canonicalization(transform) {
                    return Err(plain(format!(
                        "canonicalization algorithm '{transform}' is not supported"
                    )));
                }
                references.push_str(&format!("<Transform Algorithm=\"{transform}\" />"));
            }
            let ancestors = find_ancestor_ns(
                &document,
                reference.selector.select(&document).first().copied(),
            );
            let options = C14nOptions {
                inclusive_prefixes: Vec::new(),
                ancestor_namespaces: ancestors,
            };
            let canonical = canon_xml(&reference.transforms, &document, node, &options, None)?;
            let digest = digest_hash(&reference.digest_algorithm)?;
            references.push_str(&format!(
                "</Transforms><DigestMethod Algorithm=\"{}\" /><DigestValue>{}</DigestValue></Reference>",
                reference.digest_algorithm,
                base64_encode(&digest.digest(canonical.as_bytes()))
            ));
        }
    }
    let signed_info = format!(
        "<SignedInfo><CanonicalizationMethod Algorithm=\"{}\" /><SignatureMethod Algorithm=\"{}\" />{references}</SignedInfo>",
        options.canonicalization_algorithm, options.signature_algorithm
    );
    let key_info = match &options.public_cert {
        Some(cert) => {
            let certificates: String = pem_blocks(cert)
                .into_iter()
                .filter(|block| block.label == "CERTIFICATE")
                .map(|block| {
                    format!(
                        "<X509Certificate>{}</X509Certificate>",
                        base64_encode(&block.der)
                    )
                })
                .collect();
            format!("<KeyInfo><X509Data>{certificates}</X509Data></KeyInfo>")
        }
        None => String::new(),
    };
    let wrapper = Document::parse(&format!(
        "<Dummy ><Signature xmlns=\"{DSIG_NS}\">{signed_info}{key_info}</Signature></Dummy>"
    ))
    .map_err(|error| plain(error.0))?;
    let wrapper_root = wrapper.document_element().expect("parsed");
    let signature = document.import(&wrapper, wrapper.child_elements(wrapper_root)[0]);
    let Some(target) = options.location.select(&document).first().copied() else {
        return Err(plain(format!(
            "the following xpath cannot be used because it was not found: {:?}",
            options.location
        )));
    };
    match options.action {
        Action::Append => document.append_child(target, signature),
        Action::Prepend => {
            let first = document.children(target).first().copied();
            document.insert_before(target, signature, first);
        }
        Action::Before | Action::After => {
            let Some(parent) = document
                .parent(target)
                .filter(|parent| *parent != Document::ROOT)
            else {
                return Err(plain(
                    "`location.reference` refers to the root node (by default), so we can't insert `before`",
                ));
            };
            let reference = if options.action == Action::Before {
                Some(target)
            } else {
                document.next_sibling(target)
            };
            document.insert_before(parent, signature, reference);
        }
    }
    let signed_info_node = document.find_children(signature, None, "SignedInfo")[0];
    let first_signed_info = document
        .find_descendants(Document::ROOT, None, "SignedInfo")
        .first()
        .copied();
    let c14n_options = C14nOptions {
        inclusive_prefixes: Vec::new(),
        ancestor_namespaces: find_ancestor_ns(&document, first_signed_info),
    };
    let canonical = canon_xml(
        std::slice::from_ref(&options.canonicalization_algorithm),
        &document,
        signed_info_node,
        &c14n_options,
        Some(None),
    )?;
    let value = rsa_sign(&options.private_key, hash, canonical.as_bytes())?;
    let value_wrapper = Document::parse(&format!(
        "<Signature xmlns=\"{DSIG_NS}\"><SignatureValue>{value}</SignatureValue></Signature>"
    ))
    .map_err(|error| plain(error.0))?;
    let value_root = value_wrapper.document_element().expect("parsed");
    let value_node = document.import(&value_wrapper, value_wrapper.child_elements(value_root)[0]);
    let after = document.next_sibling(signed_info_node);
    document.insert_before(signature, value_node, after);
    Ok(document.serialize(Document::ROOT))
}
