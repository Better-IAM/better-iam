//! Port of tests/security-saml.test.ts. SAML responses: an IdP-initiated assertion is accepted only while it is fresh
//! (not forever once its single-use record lapses), and `requireEncryptedAssertions` is judged where assertions are
//! actually read.
//!
//! The first test moves the process wall clock (`Date.now()`, which the TypeScript test fakes with
//! `vi.setSystemTime`); the tests of this file hold a lock so they never run at the same time.

mod saml_support;

use std::sync::{Arc, Mutex};

use better_iam_core::{CredentialInput, IamError, IamStore, js};
use better_iam_saml::{
    CallbackInput, SamlConfigOptions, SamlService, SamlServiceProvider, create_saml_service,
};
use saml_support::*;
use serde_json::{Value, json};

static SERIAL: Mutex<()> = Mutex::new(());

fn bare(pem: &str) -> String {
    pem.replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

fn metadata(cert: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"https://idp.test\"><md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.test/login\"/></md:IDPSSODescriptor></md:EntityDescriptor>",
        bare(cert)
    )
}

struct ResponseOptions<'a> {
    request_id: Option<&'a str>,
    acs: &'a str,
    audience: &'a str,
    issued_ago_ms: f64,
    condition_times: bool,
    inject_encrypted: bool,
}

fn response(idp: &KeyPair, options: &ResponseOptions<'_>) -> String {
    let answers = options
        .request_id
        .map(|id| format!(" InResponseTo=\"{id}\""))
        .unwrap_or_default();
    let issued = now() - options.issued_ago_ms;
    let instant = iso(issued);
    let expires = iso(issued + 120_000.0);
    let conditions = if options.condition_times {
        format!(
            "<saml:Conditions NotBefore=\"{}\" NotOnOrAfter=\"{expires}\">",
            iso(issued - 1000.0)
        )
    } else {
        "<saml:Conditions>".to_owned()
    };
    let (acs, audience) = (options.acs, options.audience);
    let assertion = format!(
        "<saml:Assertion xmlns:saml=\"{ASSERTION_NS}\" ID=\"_{}\" Version=\"2.0\" IssueInstant=\"{instant}\"><saml:Issuer>https://idp.test</saml:Issuer><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">employee-42</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData{answers} Recipient=\"{acs}\" NotOnOrAfter=\"{expires}\"/></saml:SubjectConfirmation></saml:Subject>{conditions}<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant=\"{instant}\" SessionIndex=\"s\"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>",
        uuid()
    );
    let document = format!(
        "<samlp:Response xmlns:samlp=\"{PROTOCOL_NS}\" xmlns:saml=\"{ASSERTION_NS}\" ID=\"_{}\" Version=\"2.0\" IssueInstant=\"{instant}\" Destination=\"{acs}\"{answers}><saml:Issuer>https://idp.test</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>{}</samlp:Response>",
        uuid(),
        sign(&assertion, "Assertion", idp)
    );
    let mut signed = sign(&document, "Response", idp);
    if options.inject_encrypted {
        // The Response signature is the first </Signature>; the enveloped transform excludes its contents.
        signed = signed.replacen(
            "</Signature>",
            &format!("<Object><saml:EncryptedAssertion xmlns:saml=\"{ASSERTION_NS}\"/></Object></Signature>"),
            1,
        );
    }
    b64(&signed)
}

struct Fixture {
    completed: Arc<Mutex<Vec<Value>>>,
    service: SamlService,
    idp: KeyPair,
    #[allow(dead_code)]
    store: Arc<dyn IamStore>,
}

async fn fixture() -> Fixture {
    let (idp, sp) = (keys("idp"), keys("sp"));
    let store = store_with_tenants(&["a"]).await;
    let completed = Arc::new(Mutex::new(Vec::new()));
    let recorded = completed.clone();
    let mut config = SamlConfigOptions::new(
        store.clone(),
        Arc::new(move |input: Value| {
            let subject = input["subject"].clone();
            recorded.lock().unwrap().push(input);
            Box::pin(async move { Ok(json!({ "signedIn": subject })) })
        }),
    );
    config.service_provider = Some(SamlServiceProvider {
        base_url: "https://iam.test".into(),
        private_key: sp.private.clone(),
        public_certificate: sp.cert.clone(),
        decryption_private_key: Some(sp.private.clone()),
        decryption_certificate: Some(sp.cert.clone()),
    });
    config.authenticate = Some(Arc::new(|_| Box::pin(async { Ok(principal()) })));
    config.authorize = Some(Arc::new(|credential: CredentialInput, _, _| {
        Box::pin(async move {
            if credential.token.as_deref() != Some("admin") {
                return Err(IamError::with_status("ACCESS_DENIED", "no", 403));
            }
            Ok(())
        })
    }));
    let service = create_saml_service(config).unwrap();
    Fixture {
        completed,
        service,
        idp,
        store,
    }
}

fn admin() -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some("admin".into()),
    }
}

/// Puts the process wall clock back to real time when dropped.
struct RealTime;

impl Drop for RealTime {
    fn drop(&mut self) {
        js::set_wall_clock(None);
    }
}

#[test]
fn accepts_an_idp_initiated_assertion_without_conditions_times_only_while_it_is_fresh_and_once() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    run(|| async {
        let _real_time = RealTime;
        let f = fixture().await;
        let connection = f
            .service
            .create_connection(
                &admin(),
                &json!({
                    "tenantId": "a",
                    "id": "portal",
                    "name": "Portal",
                    "metadataXml": metadata(&f.idp.cert),
                    "allowIdpInitiated": true,
                }),
            )
            .await
            .unwrap();
        let (acs, audience) = (
            connection["acsUrl"].as_str().unwrap(),
            connection["entityId"].as_str().unwrap(),
        );
        let post = |saml_response: String| {
            let service = f.service.clone();
            async move {
                service
                    .handler(&post_form(
                        "https://iam.test/saml/portal/acs",
                        &[("SAMLResponse", &saml_response)],
                        None,
                    ))
                    .await
                    .unwrap()
                    .status()
            }
        };
        let timeless = |issued_ago_ms: f64| ResponseOptions {
            request_id: None,
            acs,
            audience,
            issued_ago_ms,
            condition_times: false,
            inject_encrypted: false,
        };
        // A day-old one is refused outright.
        assert_eq!(post(response(&f.idp, &timeless(86_400_000.0))).await, 401);
        // A fresh one works once; replaying it fails now, after the single-use record lapses, and a month later.
        let fresh = response(&f.idp, &timeless(0.0));
        assert_eq!(post(fresh.clone()).await, 200);
        assert_eq!(post(fresh.clone()).await, 401);
        let later = js::system_now_ms() + 11.0 * 60_000.0;
        js::set_wall_clock(Some(Arc::new(move || later)));
        assert_eq!(post(fresh.clone()).await, 401);
        let much_later = later + 30.0 * 86_400_000.0;
        js::set_wall_clock(Some(Arc::new(move || much_later)));
        assert_eq!(post(fresh).await, 401);
        assert_eq!(f.completed.lock().unwrap().len(), 1);
    });
}

#[test]
fn is_not_fooled_by_an_empty_encrypted_assertion_hidden_in_the_signature_when_encryption_is_required()
 {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    run(|| async {
        let f = fixture().await;
        let connection = f
            .service
            .create_connection(
                &admin(),
                &json!({
                    "tenantId": "a",
                    "id": "enc",
                    "name": "Enc",
                    "metadataXml": metadata(&f.idp.cert),
                    "requireEncryptedAssertions": true,
                }),
            )
            .await
            .unwrap();
        for inject_encrypted in [false, true] {
            let state = f.service.begin("enc", None, None).await.unwrap();
            let saml_response = response(
                &f.idp,
                &ResponseOptions {
                    request_id: Some(&request_id(&state.url)),
                    acs: connection["acsUrl"].as_str().unwrap(),
                    audience: connection["entityId"].as_str().unwrap(),
                    issued_ago_ms: 0.0,
                    condition_times: true,
                    inject_encrypted,
                },
            );
            let error = f
                .service
                .callback(
                    "enc",
                    &CallbackInput {
                        saml_response,
                        relay_state: state.relay_state,
                        binding: state.binding,
                    },
                )
                .await
                .unwrap_err();
            assert!(
                error.message().contains("encrypted assertion is required"),
                "{error}"
            );
        }
        assert!(f.completed.lock().unwrap().is_empty());
    });
}
