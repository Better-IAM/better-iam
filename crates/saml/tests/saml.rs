//! Port of tests/saml.test.ts: SAML SP security and shared replay state.

mod saml_support;

use std::sync::{Arc, Mutex};

use better_iam_core::{Filter, FindOptions, IamStore};
use better_iam_saml::xml::{Document, Kind};
use better_iam_saml::{
    CallbackInput, SamlConfigOptions, SamlConnection, SamlService, create_saml_cache,
    create_saml_service, validate_saml_envelope,
};
use saml_support::*;
use serde_json::{Map, Value, json};

struct Changes<'a> {
    issuer: Option<&'a str>,
    audience: Option<&'a str>,
    destination: Option<&'a str>,
    expires: Option<String>,
}

const NONE: Changes<'static> = Changes {
    issuer: None,
    audience: None,
    destination: None,
    expires: None,
};

fn make_response(idp: &KeyPair, request_id: &str, changes: &Changes<'_>) -> String {
    let now = iso(now());
    let expires = changes
        .expires
        .clone()
        .unwrap_or_else(|| iso(saml_support::now() + 120_000.0));
    let assertion = format!(
        "<saml:Assertion xmlns:saml=\"{ASSERTION_NS}\" ID=\"_{}\" Version=\"2.0\" IssueInstant=\"{now}\"><saml:Issuer>{}</saml:Issuer><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">stable-user-subject</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData InResponseTo=\"{request_id}\" Recipient=\"https://iam.test/saml/callback\" NotOnOrAfter=\"{expires}\"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"{}\" NotOnOrAfter=\"{expires}\"><saml:AudienceRestriction><saml:Audience>{}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant=\"{now}\" SessionIndex=\"session\"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name=\"email\"><saml:AttributeValue>same@example.test</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>",
        uuid(),
        changes.issuer.unwrap_or("https://idp.test"),
        iso(saml_support::now() - 1000.0),
        changes.audience.unwrap_or("https://iam.test/sp"),
    );
    let signed = sign(&assertion, "Assertion", idp);
    let response = format!(
        "<samlp:Response xmlns:samlp=\"{PROTOCOL_NS}\" xmlns:saml=\"{ASSERTION_NS}\" ID=\"_{}\" Version=\"2.0\" IssueInstant=\"{now}\" Destination=\"{}\" InResponseTo=\"{request_id}\"><saml:Issuer>https://idp.test</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>{signed}</samlp:Response>",
        uuid(),
        changes
            .destination
            .unwrap_or("https://iam.test/saml/callback"),
    );
    sign(&response, "Response", idp)
}

struct Fixture {
    store: Arc<dyn IamStore>,
    service: SamlService,
    completed: Arc<Mutex<Vec<Value>>>,
    idp: KeyPair,
}

fn connection(idp: &KeyPair) -> SamlConnection {
    SamlConnection {
        id: "enterprise".into(),
        tenant_id: "a".into(),
        entry_point: "https://idp.test/login".into(),
        idp_issuer: "https://idp.test".into(),
        idp_certificates: vec![idp.cert.clone()],
        entity_id: "https://iam.test/sp".into(),
        callback_url: "https://iam.test/saml/callback".into(),
        private_key: idp.private.clone(),
        public_certificate: idp.cert.clone(),
        ..SamlConnection::default()
    }
}

fn options(store: &Arc<dyn IamStore>, completed: &Arc<Mutex<Vec<Value>>>) -> SamlConfigOptions {
    let completed = completed.clone();
    SamlConfigOptions::new(
        store.clone(),
        Arc::new(move |input: Value| {
            completed.lock().unwrap().push(input);
            Box::pin(async { Ok(json!({ "authenticated": true })) })
        }),
    )
}

async fn fixture() -> Fixture {
    let idp = keys("idp");
    let store = store_with_tenants(&["a"]).await;
    let completed = Arc::new(Mutex::new(Vec::new()));
    let mut item = connection(&idp);
    item.map_attributes = Some(Arc::new(|profile| {
        profile.text("email").map(|email| {
            let mut attributes = Map::new();
            attributes.insert("mail".into(), Value::String(email.to_owned()));
            attributes
        })
    }));
    let mut config = options(&store, &completed);
    config.connections = vec![item];
    let service = create_saml_service(config).unwrap();
    Fixture {
        store,
        service,
        completed,
        idp,
    }
}

struct State {
    relay_state: String,
    binding: String,
    request_id: String,
}

async fn begin(service: &SamlService) -> State {
    let result = service.begin("enterprise", None, None).await.unwrap();
    State {
        request_id: request_id(&result.url),
        relay_state: result.relay_state,
        binding: result.binding,
    }
}

async fn count(store: &Arc<dyn IamStore>, collection: &str) -> usize {
    store
        .find(collection, &Filter::new(), &FindOptions::default())
        .await
        .unwrap()
        .len()
}

#[test]
fn validates_real_signed_responses_and_rejects_concurrent_replay() {
    run(|| async {
        let f = fixture().await;
        let state = begin(&f.service).await;
        let input = CallbackInput {
            relay_state: state.relay_state.clone(),
            binding: state.binding.clone(),
            saml_response: b64(&make_response(&f.idp, &state.request_id, &NONE)),
        };
        let (first, second) = tokio::join!(
            f.service.callback("enterprise", &input),
            f.service.callback("enterprise", &input)
        );
        assert_eq!(
            [first.is_ok(), second.is_ok()]
                .iter()
                .filter(|ok| **ok)
                .count(),
            1
        );
        assert_eq!(
            *f.completed.lock().unwrap(),
            vec![json!({
                "tenantId": "a",
                "providerId": "enterprise",
                "issuer": "https://idp.test",
                "subject": "stable-user-subject",
                "email": "same@example.test",
                "emailVerified": false,
                "attributes": { "mail": "same@example.test" },
            })]
        );
        assert_eq!(count(&f.store, "samlRequests").await, 0);
        assert_eq!(count(&f.store, "samlRelays").await, 0);
    });
}

#[test]
fn requires_browser_binding_and_rejects_forged_or_modified_assertions() {
    run(|| async {
        let f = fixture().await;
        let state = begin(&f.service).await;
        let xml = make_response(&f.idp, &state.request_id, &NONE);
        let input = CallbackInput {
            relay_state: state.relay_state.clone(),
            binding: state.binding.clone(),
            saml_response: b64(&xml),
        };
        let forged = CallbackInput {
            binding: "forged".into(),
            ..input.clone()
        };
        assert!(f.service.callback("enterprise", &forged).await.is_err());
        let modified = CallbackInput {
            saml_response: b64(&xml.replace("same@example.test", "attacker@example.test")),
            ..input.clone()
        };
        assert!(f.service.callback("enterprise", &modified).await.is_err());
        assert!(f.completed.lock().unwrap().is_empty());
        assert_eq!(
            f.service.callback("enterprise", &input).await.unwrap(),
            json!({ "authenticated": true })
        );
    });
}

#[test]
fn rejects_wrong_destination_issuer_audience_and_expired_assertion() {
    run(|| async {
        let f = fixture().await;
        let expired = iso(now() - 300_000.0);
        for change in [
            Changes {
                destination: Some("https://evil.test/callback"),
                ..NONE
            },
            Changes {
                issuer: Some("https://evil.test"),
                ..NONE
            },
            Changes {
                audience: Some("https://another-sp.test"),
                ..NONE
            },
            Changes {
                expires: Some(expired.clone()),
                ..NONE
            },
        ] {
            let state = begin(&f.service).await;
            let input = CallbackInput {
                relay_state: state.relay_state,
                binding: state.binding,
                saml_response: b64(&make_response(&f.idp, &state.request_id, &change)),
            };
            assert!(f.service.callback("enterprise", &input).await.is_err());
        }
        assert!(f.completed.lock().unwrap().is_empty());
    });
}

#[test]
fn does_not_accept_unsolicited_saml_and_scopes_cache_to_the_connection() {
    run(|| async {
        let f = fixture().await;
        let input = CallbackInput {
            relay_state: "unsolicited".into(),
            binding: "unsolicited".into(),
            saml_response: b64(&make_response(&f.idp, "_unsolicited", &NONE)),
        };
        assert!(f.service.callback("enterprise", &input).await.is_err());
        let a = create_saml_cache(f.store.clone(), "a", "connection-one", None);
        let b = create_saml_cache(f.store.clone(), "a", "connection-two", None);
        a.save_async("_request", "now").await.unwrap();
        assert_eq!(b.get_async("_request").await.unwrap(), None);
        assert_eq!(a.get_async("_request").await.unwrap(), Some("now".into()));
        a.remove_async(Some("_request")).await.unwrap();
        assert_eq!(a.get_async("_request").await.unwrap(), None);
    });
}

#[test]
fn decrypts_and_verifies_encrypted_signed_assertions_and_supports_certificate_rollover() {
    run(|| async {
        let f = fixture().await;
        let old = keys("old");
        let mut item = connection(&f.idp);
        item.idp_certificates = vec![old.cert.clone(), f.idp.cert.clone()];
        item.decryption_private_key = Some(f.idp.private.clone());
        item.decryption_certificate = Some(f.idp.cert.clone());
        item.require_encrypted_assertions = true;
        let mut config = options(&f.store, &f.completed);
        config.connections = vec![item];
        let service = create_saml_service(config).unwrap();
        let state = begin(&service).await;
        let mut document =
            Document::parse(&make_response(&f.idp, &state.request_id, &NONE)).unwrap();
        let root = document.document_element().unwrap();
        let assertion =
            document.find_descendants(Document::ROOT, Some(ASSERTION_NS), "Assertion")[0];
        let encrypted = encrypt(&document.serialize(assertion), &f.idp.cert);
        let wrapper = Document::parse(&format!(
            "<saml:EncryptedAssertion xmlns:saml=\"{ASSERTION_NS}\">{encrypted}</saml:EncryptedAssertion>"
        ))
        .unwrap();
        let imported = document.import(&wrapper, wrapper.document_element().unwrap());
        document.replace_child(root, imported, assertion);
        for child in document.children(root).to_vec() {
            if matches!(document.kind(child), Kind::Element(element) if element.local == "Signature")
            {
                document.detach(child);
            }
        }
        let xml = sign(&document.serialize(root), "Response", &f.idp);
        let input = CallbackInput {
            relay_state: state.relay_state,
            binding: state.binding,
            saml_response: b64(&xml),
        };
        assert_eq!(
            service.callback("enterprise", &input).await.unwrap(),
            json!({ "authenticated": true })
        );
        assert_eq!(f.completed.lock().unwrap().len(), 1);
    });
}

#[test]
fn generates_signed_metadata_with_rollover_support_and_rejects_xml_entities() {
    run(|| async {
        let f = fixture().await;
        let metadata = f.service.metadata("enterprise").unwrap();
        assert!(metadata.contains("Signature"));
        assert!(metadata.contains("https://iam.test/saml/callback"));
        assert!(metadata.contains("WantAssertionsSigned=\"true\""));
        assert!(
            validate_saml_envelope(
                "<!DOCTYPE a [<!ENTITY x SYSTEM \"file:///secrets\">]><a/>",
                "https://iam.test/saml/callback",
                Some("_request"),
                false,
            )
            .is_err()
        );
        let error = validate_saml_envelope(
            &make_response(&f.idp, "_request", &NONE),
            "https://iam.test/saml/callback",
            Some("_request"),
            true,
        )
        .unwrap_err();
        assert!(error.message().contains("encrypted"), "{error}");
    });
}
