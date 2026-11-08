//! Signature wrapping (XSW) and comment injection against the whole service: identities come only from the canonical
//! bytes a verified signature covers, so moved, duplicated or unsigned assertions are refused and comments can never
//! truncate a NameID.

mod saml_support;

use std::sync::{Arc, Mutex};

use better_iam_core::IamStore;
use better_iam_saml::{
    CallbackInput, SamlConfigOptions, SamlConnection, SamlService, create_saml_service,
};
use saml_support::*;
use serde_json::{Value, json};

const CALLBACK: &str = "https://iam.test/saml/callback";

fn assertion(id: &str, request_id: &str, name_id: &str) -> String {
    let now = iso(saml_support::now());
    let expires = iso(saml_support::now() + 120_000.0);
    format!(
        "<saml:Assertion xmlns:saml=\"{ASSERTION_NS}\" ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{now}\"><saml:Issuer>https://idp.test</saml:Issuer><saml:Subject><saml:NameID>{name_id}</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData InResponseTo=\"{request_id}\" Recipient=\"{CALLBACK}\" NotOnOrAfter=\"{expires}\"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"{}\" NotOnOrAfter=\"{expires}\"><saml:AudienceRestriction><saml:Audience>https://iam.test/sp</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>",
        iso(saml_support::now() - 1000.0)
    )
}

fn response(request_id: &str, inner: &str) -> String {
    format!(
        "<samlp:Response xmlns:samlp=\"{PROTOCOL_NS}\" xmlns:saml=\"{ASSERTION_NS}\" ID=\"_{}\" Version=\"2.0\" IssueInstant=\"{}\" Destination=\"{CALLBACK}\" InResponseTo=\"{request_id}\"><saml:Issuer>https://idp.test</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>{inner}</samlp:Response>",
        uuid(),
        iso(saml_support::now())
    )
}

struct Fixture {
    service: SamlService,
    completed: Arc<Mutex<Vec<Value>>>,
    idp: KeyPair,
    attacker: KeyPair,
    #[allow(dead_code)]
    store: Arc<dyn IamStore>,
}

async fn fixture() -> Fixture {
    let (idp, attacker, sp) = (keys("idp"), keys("attacker"), keys("sp"));
    let store = store_with_tenants(&["a"]).await;
    let completed = Arc::new(Mutex::new(Vec::new()));
    let recorded = completed.clone();
    let mut config = SamlConfigOptions::new(
        store.clone(),
        Arc::new(move |input: Value| {
            recorded.lock().unwrap().push(input);
            Box::pin(async { Ok(json!({ "ok": true })) })
        }),
    );
    config.connections = vec![SamlConnection {
        id: "enterprise".into(),
        tenant_id: "a".into(),
        entry_point: "https://idp.test/login".into(),
        idp_issuer: "https://idp.test".into(),
        idp_certificates: vec![idp.cert.clone()],
        entity_id: "https://iam.test/sp".into(),
        callback_url: CALLBACK.into(),
        private_key: sp.private,
        public_certificate: sp.cert,
        ..SamlConnection::default()
    }];
    let service = create_saml_service(config).unwrap();
    Fixture {
        service,
        completed,
        idp,
        attacker,
        store,
    }
}

impl Fixture {
    /// Starts a sign-in, builds the response for its request ID, and posts it.
    async fn attempt(
        &self,
        build: impl FnOnce(&str) -> String,
    ) -> Result<Value, better_iam_saml::SamlError> {
        let state = self.service.begin("enterprise", None, None).await.unwrap();
        let xml = build(&request_id(&state.url));
        self.service
            .callback(
                "enterprise",
                &CallbackInput {
                    saml_response: b64(&xml),
                    relay_state: state.relay_state,
                    binding: state.binding,
                },
            )
            .await
    }

    fn subjects(&self) -> Vec<Value> {
        self.completed
            .lock()
            .unwrap()
            .iter()
            .map(|input| input["subject"].clone())
            .collect()
    }
}

#[test]
fn comments_never_truncate_a_name_id() {
    run(|| async {
        let f = fixture().await;
        // The IdP signed "user@evil.test<!---->.attacker.test": the signed bytes say user@evil.test.attacker.test.
        f.attempt(|request| {
            let signed = sign(
                &assertion("_a1", request, "user@evil.test<!---->.attacker.test"),
                "Assertion",
                &f.idp,
            );
            sign(&response(request, &signed), "Response", &f.idp)
        })
        .await
        .unwrap();
        // A comment added after signing is outside the signed bytes and changes nothing.
        f.attempt(|request| {
            let signed = sign(
                &assertion("_a2", request, "user@example.test"),
                "Assertion",
                &f.idp,
            );
            sign(&response(request, &signed), "Response", &f.idp)
                .replace("user@example.test", "user@example.test<!---->")
        })
        .await
        .unwrap();
        assert_eq!(
            f.subjects(),
            vec![
                json!("user@evil.test.attacker.test"),
                json!("user@example.test")
            ]
        );
    });
}

#[test]
fn refuses_wrapped_duplicated_and_resigned_assertions() {
    run(|| async {
        let f = fixture().await;
        // XSW: the signed assertion moved into Extensions, an unsigned one in its place.
        let wrapped = f
            .attempt(|request| {
                let signed = sign(
                    &assertion("_a1", request, "user@example.test"),
                    "Assertion",
                    &f.idp,
                );
                let document = sign(&response(request, &signed), "Response", &f.idp);
                document.replace(
                    &signed,
                    &format!(
                        "<samlp:Extensions>{signed}</samlp:Extensions>{}",
                        assertion("_evil", request, "admin@victim.test")
                    ),
                )
            })
            .await
            .unwrap_err();
        assert!(wrapped.as_iam().is_none(), "{wrapped:?}");
        // XSW: an evil assertion hidden inside the Response signature, which the enveloped transform leaves out.
        let hidden = f
            .attempt(|request| {
                let signed = sign(
                    &assertion("_a1", request, "user@example.test"),
                    "Assertion",
                    &f.idp,
                );
                sign(&response(request, &signed), "Response", &f.idp).replacen(
                    "</Signature>",
                    &format!(
                        "<Object>{}</Object></Signature>",
                        assertion("_evil", request, "admin@victim.test")
                    ),
                    1,
                )
            })
            .await;
        assert!(
            hidden.is_err()
                || f.subjects()
                    .iter()
                    .all(|subject| subject != "admin@victim.test")
        );
        // Two assertions with the same ID.
        let duplicated = f
            .attempt(|request| {
                let signed = sign(
                    &assertion("_a1", request, "user@example.test"),
                    "Assertion",
                    &f.idp,
                );
                let evil = signed.replace("user@example.test", "admin@victim.test");
                sign(
                    &response(request, &format!("{signed}{evil}")),
                    "Response",
                    &f.idp,
                )
            })
            .await;
        assert!(duplicated.is_err());
        // The Response re-signed by the attacker around an assertion it signed itself.
        let resigned = f
            .attempt(|request| {
                let evil = sign(
                    &assertion("_a1", request, "admin@victim.test"),
                    "Assertion",
                    &f.attacker,
                );
                sign(&response(request, &evil), "Response", &f.attacker)
            })
            .await
            .unwrap_err();
        assert_eq!(resigned.message(), "Invalid document signature");
        // A genuinely signed Response around an assertion the attacker signed.
        let mixed = f
            .attempt(|request| {
                let evil = sign(
                    &assertion("_a1", request, "admin@victim.test"),
                    "Assertion",
                    &f.attacker,
                );
                sign(&response(request, &evil), "Response", &f.idp)
            })
            .await
            .unwrap_err();
        assert_eq!(mixed.message(), "Invalid signature");
        // An unsigned Response around a signed assertion.
        let unsigned = f
            .attempt(|request| {
                response(
                    request,
                    &sign(
                        &assertion("_a1", request, "user@example.test"),
                        "Assertion",
                        &f.idp,
                    ),
                )
            })
            .await
            .unwrap_err();
        assert_eq!(unsigned.message(), "Invalid document signature");
        assert!(
            f.subjects()
                .iter()
                .all(|subject| subject != "admin@victim.test")
        );
    });
}
