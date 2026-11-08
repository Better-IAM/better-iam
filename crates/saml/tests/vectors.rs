//! Differential checks against the TypeScript implementation's libraries. `tests/fixtures/xmldsig-vectors.json` was
//! written by `xml-crypto` 6, `xml-encryption` 3 and Node-SAML 5 (`getVerifiedXml`): signed responses (including
//! signature-wrapping and comment-injection attempts) with the outcome Node-SAML reached for the Response and for its
//! first assertion, canonicalizations of tricky documents, and encrypted assertions. The Rust implementation must
//! reach the same outcome, byte for byte.

use std::path::Path;

use better_iam_saml::c14n::{self, C14nOptions};
use better_iam_saml::dsig::get_verified_xml;
use better_iam_saml::xml::Document;
use better_iam_saml::xmlenc;
use serde_json::Value;

const ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

fn vectors() -> Value {
    serde_json::from_str(&fixture("xmldsig-vectors.json")).unwrap()
}

fn outcome(xml: &str, pick_assertion: bool, pems: &[String]) -> Value {
    let document = Document::parse(xml).unwrap();
    let node = if pick_assertion {
        document
            .find_descendants(Document::ROOT, Some(ASSERTION_NS), "Assertion")
            .first()
            .copied()
    } else {
        document.document_element()
    };
    let Some(node) = node else {
        return serde_json::json!({ "missing": true });
    };
    match get_verified_xml(xml, &document, node, pems) {
        Ok(Some(canonical)) => serde_json::json!({ "ok": canonical }),
        Ok(None) => serde_json::json!({ "null": true }),
        Err(error) => serde_json::json!({ "error": error.message() }),
    }
}

#[test]
fn signatures_verify_exactly_as_node_saml_verifies_them() {
    let pems = vec![fixture("attacker.cert.pem"), fixture("idp.cert.pem")];
    let vectors = vectors();
    for vector in vectors["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let xml = vector["xml"].as_str().unwrap();
        assert_eq!(
            outcome(xml, false, &pems),
            vector["response"],
            "{name}: response"
        );
        assert_eq!(
            outcome(xml, true, &pems),
            vector["assertion"],
            "{name}: assertion"
        );
    }
}

#[test]
fn canonicalization_matches_xml_crypto() {
    let vectors = vectors();
    for vector in vectors["c14n"].as_array().unwrap() {
        let xml = vector["xml"].as_str().unwrap();
        let index = vector["index"].as_u64().unwrap() as usize;
        let document = Document::parse(xml).unwrap();
        let element = document
            .self_and_descendants(Document::ROOT)
            .into_iter()
            .filter(|node| document.element(*node).is_some())
            .nth(index)
            .unwrap();
        let (mut clone, root) = document.clone_subtree(element);
        let output = match vector["algorithm"].as_str().unwrap() {
            "exc" => c14n::exclusive(&mut clone, root, &C14nOptions::default(), false).unwrap(),
            _ => c14n::inclusive(&clone, root, &C14nOptions::default(), false).unwrap(),
        };
        assert_eq!(
            output,
            vector["output"].as_str().unwrap(),
            "{xml} #{index} {}",
            vector["algorithm"]
        );
    }
}

#[test]
fn decrypts_what_xml_encryption_encrypts() {
    let key = fixture("sp.key.pem");
    let vectors = vectors();
    for vector in vectors["encrypted"].as_array().unwrap() {
        let document = Document::parse(vector["xml"].as_str().unwrap()).unwrap();
        let root = document.document_element().unwrap();
        let decrypted = xmlenc::decrypt(&document, root, &key)
            .unwrap_or_else(|error| panic!("{}: {error}", vector["encryptionAlgorithm"]));
        assert_eq!(
            decrypted,
            vector["plaintext"].as_str().unwrap(),
            "{}",
            vector["encryptionAlgorithm"]
        );
    }
}
