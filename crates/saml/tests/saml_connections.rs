//! Port of tests/saml-connections.test.ts: tenant-managed SAML connections.

mod saml_support;

use std::sync::{Arc, Mutex};

use better_iam_core::{CredentialInput, Filter, FindOptions, IamError, IamStore};
use better_iam_saml::{
    CallbackInput, SamlConfigOptions, SamlConnection, SamlService, SamlServiceProvider,
    create_saml_service, parse_idp_metadata,
};
use regex::Regex;
use saml_support::*;
use serde_json::{Value, json};

fn bare(pem: &str) -> String {
    pem.replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

fn metadata(certificates: &[&str], extra: &str) -> String {
    let keys: String = certificates
        .iter()
        .map(|cert| {
            format!(
                "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>",
                bare(cert)
            )
        })
        .collect();
    format!(
        "<?xml version=\"1.0\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"https://idp.test\"><md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">{keys}{extra}<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.test/logout\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://idp.test/post\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.test/login\"/></md:IDPSSODescriptor></md:EntityDescriptor>"
    )
}

/// A signed IdP response for a managed connection's ACS URL and SP entity ID.
fn response(request_id: Option<&str>, acs: &str, audience: &str, key: &KeyPair) -> String {
    let answers = request_id
        .map(|id| format!(" InResponseTo=\"{id}\""))
        .unwrap_or_default();
    let now = iso(saml_support::now());
    let expires = iso(saml_support::now() + 120_000.0);
    let assertion = format!(
        "<saml:Assertion xmlns:saml=\"{ASSERTION_NS}\" ID=\"_{}\" Version=\"2.0\" IssueInstant=\"{now}\"><saml:Issuer>https://idp.test</saml:Issuer><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">employee-42</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData{answers} Recipient=\"{acs}\" NotOnOrAfter=\"{expires}\"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"{}\" NotOnOrAfter=\"{expires}\"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant=\"{now}\" SessionIndex=\"session\"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name=\"email\"><saml:AttributeValue>ada@acme.test</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"dept\"><saml:AttributeValue>finance</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>",
        uuid(),
        iso(saml_support::now() - 1000.0)
    );
    let document = format!(
        "<samlp:Response xmlns:samlp=\"{PROTOCOL_NS}\" xmlns:saml=\"{ASSERTION_NS}\" ID=\"_{}\" Version=\"2.0\" IssueInstant=\"{now}\" Destination=\"{acs}\"{answers}><saml:Issuer>https://idp.test</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>{}</samlp:Response>",
        uuid(),
        sign(&assertion, "Assertion", key)
    );
    b64(&sign(&document, "Response", key))
}

struct Fixture {
    store: Arc<dyn IamStore>,
    completed: Arc<Mutex<Vec<Value>>>,
    denied: Arc<Mutex<Vec<String>>>,
    service: SamlService,
    idp: KeyPair,
    next: KeyPair,
    sp: KeyPair,
}

fn admin() -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some("admin".into()),
    }
}

fn sp_provider(sp: &KeyPair) -> SamlServiceProvider {
    SamlServiceProvider {
        base_url: "https://iam.test".into(),
        private_key: sp.private.clone(),
        public_certificate: sp.cert.clone(),
        ..SamlServiceProvider::default()
    }
}

fn completing(store: &Arc<dyn IamStore>, completed: &Arc<Mutex<Vec<Value>>>) -> SamlConfigOptions {
    let completed = completed.clone();
    SamlConfigOptions::new(
        store.clone(),
        Arc::new(move |input: Value| {
            let subject = input["subject"].clone();
            completed.lock().unwrap().push(input);
            Box::pin(async move { Ok(json!({ "signedIn": subject })) })
        }),
    )
}

async fn fixture() -> Fixture {
    let (idp, next, sp) = (keys("idp"), keys("next"), keys("sp"));
    let store = store_with_tenants(&["a", "b"]).await;
    let completed = Arc::new(Mutex::new(Vec::new()));
    let denied = Arc::new(Mutex::new(Vec::new()));
    let mut config = completing(&store, &completed);
    config.connections = vec![SamlConnection {
        id: "static".into(),
        tenant_id: "a".into(),
        entry_point: "https://idp.test/login".into(),
        idp_issuer: "https://idp.test".into(),
        idp_certificates: vec![idp.cert.clone()],
        entity_id: "https://iam.test/static".into(),
        callback_url: "https://iam.test/static/callback".into(),
        private_key: sp.private.clone(),
        public_certificate: sp.cert.clone(),
        ..SamlConnection::default()
    }];
    config.service_provider = Some(sp_provider(&sp));
    config.authenticate = Some(Arc::new(|_| Box::pin(async { Ok(principal()) })));
    let refused = denied.clone();
    config.authorize = Some(Arc::new(
        move |credential: CredentialInput, action: String, _| {
            let refused = refused.clone();
            Box::pin(async move {
                if credential.token.as_deref() != Some("admin") {
                    refused.lock().unwrap().push(action);
                    return Err(IamError::with_status("ACCESS_DENIED", "Forbidden", 403));
                }
                Ok(())
            })
        },
    ));
    let service = create_saml_service(config).unwrap();
    Fixture {
        store,
        completed,
        denied,
        service,
        idp,
        next,
        sp,
    }
}

async fn actions(store: &Arc<dyn IamStore>) -> Vec<String> {
    store
        .find(
            "audit",
            &Filter::new().eq("tenantId", "a"),
            &FindOptions::default(),
        )
        .await
        .unwrap()
        .iter()
        .map(|event| event["action"].as_str().unwrap().to_owned())
        .collect()
}

fn base(idp: &KeyPair) -> Value {
    json!({
        "tenantId": "a",
        "name": "Acme",
        "entryPoint": "https://idp.test/login",
        "idpIssuer": "https://idp.test",
        "idpCertificates": [idp.cert],
    })
}

fn with(mut value: Value, changes: Value) -> Value {
    for (key, change) in changes.as_object().unwrap() {
        value[key] = change.clone();
    }
    value
}

#[test]
fn parses_idp_metadata_redirect_endpoints_and_signing_certificates_only() {
    let (idp, next, sp) = (keys("idp"), keys("next"), keys("sp"));
    let parsed = parse_idp_metadata(&metadata(
        &[&idp.cert, &next.cert],
        &format!(
            "<md:KeyDescriptor use=\"encryption\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>",
            bare(&sp.cert)
        ),
    ))
    .unwrap();
    assert_eq!(parsed.entity_id, "https://idp.test");
    assert_eq!(parsed.entry_point, "https://idp.test/login");
    assert_eq!(
        parsed.single_logout_url.as_deref(),
        Some("https://idp.test/logout")
    );
    assert_eq!(parsed.certificates.len(), 2);
    assert!(parsed.certificates[0].contains("-----BEGIN CERTIFICATE-----"));
    assert!(
        parse_idp_metadata("<!DOCTYPE x [<!ENTITY a \"b\">]><x/>")
            .unwrap_err()
            .message
            .contains("Unsafe")
    );
    let soap = metadata(&[&idp.cert], "").replace(
        "HTTP-Redirect\" Location=\"https://idp.test/login",
        "SOAP\" Location=\"https://idp.test/login",
    );
    assert!(
        parse_idp_metadata(&soap)
            .unwrap_err()
            .message
            .contains("HTTP-Redirect")
    );
    let not_a_cert = metadata(&[&idp.cert], "").replace(&bare(&idp.cert), "bm90IGEgY2VydA==");
    assert!(
        parse_idp_metadata(&not_a_cert)
            .unwrap_err()
            .message
            .contains("X.509")
    );
}

#[test]
fn creates_a_connection_from_metadata_and_signs_members_in_through_its_acs_url() {
    run(|| async {
        let f = fixture().await;
        let created = f
            .service
            .create_connection(
                &admin(),
                &json!({
                    "tenantId": "a",
                    "id": "acme",
                    "name": "Acme Okta",
                    "metadataXml": metadata(&[&f.idp.cert], ""),
                    "trustedEmailDomains": ["ACME.test"],
                    "attributeMapping": { "department": "dept" },
                }),
            )
            .await
            .unwrap();
        assert_matches(
            &created,
            json!({
                "id": "acme",
                "tenantId": "a",
                "name": "Acme Okta",
                "enabled": true,
                "entryPoint": "https://idp.test/login",
                "idpIssuer": "https://idp.test",
                "trustedEmailDomains": ["acme.test"],
                "entityId": "https://iam.test/saml/acme/metadata",
                "acsUrl": "https://iam.test/saml/acme/acs",
                "loginUrl": "https://iam.test/saml/acme/login",
            }),
        );
        assert_eq!(created["certificates"][0]["expired"], json!(false));
        assert!(
            Regex::new("^[0-9A-F:]+$").unwrap().is_match(
                created["certificates"][0]["fingerprint256"]
                    .as_str()
                    .unwrap()
            )
        );
        assert_eq!(created["certificates"][0]["subject"], json!("CN=idp.test"));

        // SP metadata is served for the managed connection.
        let served = f
            .service
            .handler(&get("https://iam.test/saml/acme/metadata"))
            .await
            .unwrap();
        assert_eq!(served.status(), 200);
        assert!(String::from_utf8_lossy(served.body()).contains("https://iam.test/saml/acme/acs"));
        assert!(
            f.service
                .get_metadata("acme")
                .await
                .unwrap()
                .contains("WantAssertionsSigned=\"true\"")
        );

        // Browser flow: login redirect sets the binding cookie, the IdP posts back to the ACS URL.
        let login = f
            .service
            .handler(&get("https://iam.test/saml/acme/login"))
            .await
            .unwrap();
        assert_eq!(login.status(), 302);
        let location = header(&login, "location").unwrap();
        let parsed = url::Url::parse(&location).unwrap();
        assert_eq!(
            format!("{}{}", parsed.origin().ascii_serialization(), parsed.path()),
            "https://idp.test/login"
        );
        let request = authn_request(&location);
        assert!(request.contains("AssertionConsumerServiceURL=\"https://iam.test/saml/acme/acs\""));
        let cookie = header(&login, "set-cookie")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let relay = parsed
            .query_pairs()
            .find(|(key, _)| key == "RelayState")
            .unwrap()
            .1
            .into_owned();
        let saml_response = response(
            Some(&request_id(&location)),
            created["acsUrl"].as_str().unwrap(),
            created["entityId"].as_str().unwrap(),
            &f.idp,
        );
        let posted = f
            .service
            .handler(&post_form(
                "https://iam.test/saml/acme/acs",
                &[("SAMLResponse", &saml_response), ("RelayState", &relay)],
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(posted.status(), 200);
        assert_eq!(json_body(&posted), json!({ "signedIn": "employee-42" }));
        let completed = f.completed.lock().unwrap().clone();
        assert_eq!(completed.len(), 1);
        assert_matches(
            &completed[0],
            json!({
                "tenantId": "a",
                "issuer": "https://idp.test",
                "subject": "employee-42",
                "email": "ada@acme.test",
                "emailVerified": true,
                "attributes": { "department": "finance" },
            }),
        );
        // Links are keyed by a random provider key of this very connection, never by its reusable ID.
        assert!(
            Regex::new("^saml:acme:[A-Za-z0-9_-]{16}$")
                .unwrap()
                .is_match(completed[0]["providerId"].as_str().unwrap())
        );
        assert!(
            actions(&f.store)
                .await
                .contains(&"iam:saml:CreateConnection".to_owned())
        );
    });
}

#[test]
fn rolls_over_certificates_disables_and_deletes_connections_within_the_tenant() {
    run(|| async {
        let f = fixture().await;
        f.service
            .create_connection(&admin(), &with(base(&f.idp), json!({ "id": "acme" })))
            .await
            .unwrap();
        let acs = "https://iam.test/saml/acme/acs";
        let audience = "https://iam.test/saml/acme/metadata";
        let attempt = |key: KeyPair| {
            let service = f.service.clone();
            async move {
                let state = service.begin("acme", None, None).await.unwrap();
                let input = CallbackInput {
                    saml_response: response(Some(&request_id(&state.url)), acs, audience, &key),
                    relay_state: state.relay_state,
                    binding: state.binding,
                };
                service.callback("acme", &input).await
            }
        };
        // An assertion signed by the next IdP key fails until the rollover lists it.
        assert!(attempt(f.next.clone()).await.is_err());
        let rolled = f
            .service
            .update_connection(
                &admin(),
                &json!({ "tenantId": "a", "connectionId": "acme", "idpCertificates": [f.idp.cert, f.next.cert] }),
            )
            .await
            .unwrap();
        assert_eq!(rolled["certificates"].as_array().unwrap().len(), 2);
        assert_eq!(
            attempt(f.next.clone()).await.unwrap(),
            json!({ "signedIn": "employee-42" })
        );

        // Disabled connections stop new sign-ins; listing still shows them.
        f.service
            .update_connection(
                &admin(),
                &json!({ "tenantId": "a", "connectionId": "acme", "enabled": false }),
            )
            .await
            .unwrap();
        assert_eq!(
            f.service
                .begin("acme", None, None)
                .await
                .unwrap_err()
                .as_iam()
                .unwrap()
                .status,
            404
        );
        assert_eq!(
            f.service
                .handler(&get("https://iam.test/saml/acme/login"))
                .await
                .unwrap()
                .status(),
            404
        );
        let listed = f.service.list_connections(&admin(), "a").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_matches(&listed[0], json!({ "id": "acme", "enabled": false }));

        // Other tenants and callers without permission see nothing.
        assert_eq!(
            f.service
                .get_connection(&admin(), "b", "acme")
                .await
                .unwrap_err()
                .as_iam()
                .unwrap()
                .status,
            404
        );
        let member = CredentialInput {
            headers: None,
            token: Some("member".into()),
        };
        let refused = f
            .service
            .update_connection(
                &member,
                &json!({ "tenantId": "a", "connectionId": "acme", "name": "Mine" }),
            )
            .await
            .unwrap_err();
        assert_eq!(refused.as_iam().unwrap().status, 403);
        assert!(
            f.denied
                .lock()
                .unwrap()
                .contains(&"iam:saml:connections:update".to_owned())
        );

        f.service
            .delete_connection(&admin(), "a", "acme")
            .await
            .unwrap();
        assert!(
            f.service
                .list_connections(&admin(), "a")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            f.service
                .get_metadata("acme")
                .await
                .unwrap_err()
                .as_iam()
                .unwrap()
                .status,
            404
        );
        let actions = actions(&f.store).await;
        for action in [
            "iam:saml:CreateConnection",
            "iam:saml:UpdateConnection",
            "iam:saml:DeleteConnection",
        ] {
            assert!(actions.contains(&action.to_owned()), "{action}");
        }
    });
}

#[test]
fn accepts_idp_initiated_sign_in_only_when_enabled_once_per_assertion() {
    run(|| async {
        let f = fixture().await;
        let created = f
            .service
            .create_connection(
                &admin(),
                &json!({
                    "tenantId": "a",
                    "id": "portal",
                    "name": "Portal",
                    "metadataXml": metadata(&[&f.idp.cert], ""),
                    "allowIdpInitiated": true,
                }),
            )
            .await
            .unwrap();
        assert_eq!(created["allowIdpInitiated"], json!(true));
        let (acs, entity) = (
            created["acsUrl"].as_str().unwrap(),
            created["entityId"].as_str().unwrap(),
        );
        let post = |saml_response: String, relay_state: Option<&'static str>| {
            let service = f.service.clone();
            async move {
                let mut form = vec![("SAMLResponse", saml_response.as_str())];
                if let Some(relay) = relay_state {
                    form.push(("RelayState", relay));
                }
                service
                    .handler(&post_form("https://iam.test/saml/portal/acs", &form, None))
                    .await
                    .unwrap()
            }
        };
        let unsolicited = response(None, acs, entity, &f.idp);
        let accepted = post(unsolicited.clone(), Some("https://app.example/dashboard")).await;
        assert_eq!(accepted.status(), 200);
        assert_eq!(json_body(&accepted), json!({ "signedIn": "employee-42" }));
        // The same assertion cannot be replayed, and responses to requests still need their browser binding.
        assert_eq!(post(unsolicited, None).await.status(), 401);
        assert_eq!(
            post(response(Some("_forged"), acs, entity, &f.idp), Some("x"))
                .await
                .status(),
            401
        );
        // Other audiences and signers are refused like SP-initiated responses.
        assert_eq!(
            post(response(None, acs, "https://elsewhere.test", &f.idp), None)
                .await
                .status(),
            401
        );
        assert_eq!(
            post(response(None, acs, entity, &f.next), None)
                .await
                .status(),
            401
        );
        assert_eq!(f.completed.lock().unwrap().len(), 1);

        // Turning it off refuses unsolicited responses again.
        f.service
            .update_connection(
                &admin(),
                &json!({ "tenantId": "a", "connectionId": "portal", "allowIdpInitiated": false }),
            )
            .await
            .unwrap();
        assert_eq!(
            post(response(None, acs, entity, &f.idp), None)
                .await
                .status(),
            401
        );
        let refused = f
            .service
            .idp_initiated("portal", &response(None, acs, entity, &f.idp))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), Some("SAML_INVALID"));
        assert_eq!(f.completed.lock().unwrap().len(), 1);
    });
}

#[test]
fn validates_connection_input() {
    run(|| async {
        let f = fixture().await;
        let base = base(&f.idp);
        f.service
            .create_connection(&admin(), &with(base.clone(), json!({ "id": "taken" })))
            .await
            .unwrap();
        let mut without_name = with(base.clone(), json!({ "name": "" }));
        without_name.as_object_mut().unwrap().remove("metadataXml");
        for (input, code) in [
            (with(base.clone(), json!({ "id": "taken" })), "CONFLICT"),
            (with(base.clone(), json!({ "id": "static" })), "CONFLICT"),
            (
                with(base.clone(), json!({ "id": "Not Valid" })),
                "INVALID_INPUT",
            ),
            (
                with(
                    base.clone(),
                    json!({ "entryPoint": "http://idp.test/login" }),
                ),
                "INVALID_INPUT",
            ),
            (
                with(base.clone(), json!({ "idpCertificates": [] })),
                "INVALID_INPUT",
            ),
            (
                with(
                    base.clone(),
                    json!({ "idpCertificates": ["not a certificate"] }),
                ),
                "INVALID_INPUT",
            ),
            (
                with(
                    base.clone(),
                    json!({ "trustedEmailDomains": ["*.acme.test"] }),
                ),
                "INVALID_INPUT",
            ),
            (
                with(
                    base.clone(),
                    json!({ "attributeMapping": { "bad name": "x" } }),
                ),
                "INVALID_INPUT",
            ),
            (
                with(base.clone(), json!({ "requireEncryptedAssertions": true })),
                "INVALID_INPUT",
            ),
            (without_name, "INVALID_INPUT"),
            (
                with(base.clone(), json!({ "metadataXml": "<!DOCTYPE x><x/>" })),
                "INVALID_INPUT",
            ),
        ] {
            let error = f
                .service
                .create_connection(&admin(), &input)
                .await
                .unwrap_err();
            assert_eq!(error.code(), Some(code), "{input}");
        }
        // Configured connections keep their fixed URLs and are not managed through the API.
        assert_eq!(
            f.service
                .get_connection(&admin(), "a", "static")
                .await
                .unwrap_err()
                .as_iam()
                .unwrap()
                .status,
            404
        );
        assert!(
            f.service
                .metadata("static")
                .unwrap()
                .contains("https://iam.test/static/callback")
        );
        let mut options = completing(&f.store, &f.completed);
        options.service_provider = Some(SamlServiceProvider {
            base_url: "http://iam.test".into(),
            private_key: "x".into(),
            public_certificate: "y".into(),
            ..SamlServiceProvider::default()
        });
        assert!(
            create_saml_service(options)
                .err()
                .unwrap()
                .message()
                .contains("HTTPS")
        );
    });
}

#[test]
fn passes_trust_scim_provisioned_to_the_host_gated_as_a_trust_change_and_shows_the_provider_key() {
    run(|| async {
        let f = fixture().await;
        let trust_changes = Arc::new(Mutex::new(Vec::<String>::new()));
        let mut config = completing(&f.store, &f.completed);
        config.service_provider = Some(sp_provider(&f.sp));
        config.authenticate = Some(Arc::new(|_| Box::pin(async { Ok(principal()) })));
        config.authorize = Some(Arc::new(|_, _, _| Box::pin(async { Ok(()) })));
        let recorded = trust_changes.clone();
        config.assert_trust_change = Some(Arc::new(move |_, _, provider_id: String| {
            recorded.lock().unwrap().push(provider_id);
            Box::pin(async { Ok(()) })
        }));
        let trusting = create_saml_service(config).unwrap();
        let created = trusting
            .create_connection(
                &admin(),
                &json!({
                    "tenantId": "a",
                    "id": "okta",
                    "name": "Okta",
                    "metadataXml": metadata(&[&f.idp.cert], ""),
                    "trustedEmailDomains": ["acme.test"],
                }),
            )
            .await
            .unwrap();
        assert_eq!(created["trustScimProvisioned"], json!(false));
        let provider_id = created["providerId"].as_str().unwrap().to_owned();
        assert!(provider_id.starts_with("saml:okta:"));
        assert_eq!(*trust_changes.lock().unwrap(), vec![provider_id.clone()]);
        // Trusting SCIM-provisioned accounts widens what the connection can sign in to; narrowing does not.
        let update = |value: Value| {
            let trusting = trusting.clone();
            async move {
                let mut input = json!({ "tenantId": "a", "connectionId": "okta" });
                input["trustScimProvisioned"] = value;
                trusting.update_connection(&admin(), &input).await
            }
        };
        let scim = update(json!(["scim-1", "scim-1"])).await.unwrap();
        assert_eq!(scim["trustScimProvisioned"], json!(["scim-1"]));
        assert_eq!(trust_changes.lock().unwrap().len(), 2);
        update(json!(true)).await.unwrap();
        assert_eq!(trust_changes.lock().unwrap().len(), 3);
        update(json!(["scim-1"])).await.unwrap();
        assert_eq!(trust_changes.lock().unwrap().len(), 3);
        assert_eq!(
            update(json!("yes")).await.unwrap_err().code(),
            Some("INVALID_INPUT")
        );

        let login = trusting
            .handler(&get("https://iam.test/saml/okta/login"))
            .await
            .unwrap();
        let location = header(&login, "location").unwrap();
        let relay = url::Url::parse(&location)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "RelayState")
            .unwrap()
            .1
            .into_owned();
        let saml_response = response(
            Some(&request_id(&location)),
            created["acsUrl"].as_str().unwrap(),
            created["entityId"].as_str().unwrap(),
            &f.idp,
        );
        let cookie = header(&login, "set-cookie")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        trusting
            .handler(&post_form(
                "https://iam.test/saml/okta/acs",
                &[("SAMLResponse", &saml_response), ("RelayState", &relay)],
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_matches(
            f.completed.lock().unwrap().last().unwrap(),
            json!({ "providerId": provider_id, "emailVerified": true, "trustScimProvisioned": ["scim-1"] }),
        );
        let mut options = completing(&f.store, &f.completed);
        options.connections = vec![SamlConnection {
            id: "bad".into(),
            tenant_id: "a".into(),
            entry_point: "https://idp.test/login".into(),
            idp_issuer: "https://idp.test".into(),
            idp_certificates: vec![f.idp.cert.clone()],
            entity_id: "https://iam.test/bad".into(),
            callback_url: "https://iam.test/bad/callback".into(),
            private_key: f.sp.private.clone(),
            public_certificate: f.sp.cert.clone(),
            trust_scim_provisioned: Some(json!([42])),
            ..SamlConnection::default()
        }];
        assert!(
            create_saml_service(options)
                .err()
                .unwrap()
                .message()
                .contains("trustScimProvisioned")
        );
    });
}

#[test]
fn asks_the_host_to_redirect_after_sign_in_after_sign_in_return_to_mfa_fragment_error_page() {
    run(|| async {
        let f = fixture().await;
        let outcome: Arc<Mutex<Result<Value, IamError>>> = Arc::new(Mutex::new(Ok(json!({
            "token": "session-token",
            "session": { "expiresAt": saml_support::now() + 60_000.0 },
        }))));
        let mut config = SamlConfigOptions::new(f.store.clone(), {
            let completed = f.completed.clone();
            let outcome = outcome.clone();
            Arc::new(move |input: Value| {
                completed.lock().unwrap().push(input);
                let result = outcome.lock().unwrap().clone();
                Box::pin(async move { result })
            })
        });
        config.service_provider = Some(sp_provider(&f.sp));
        config.authenticate = Some(Arc::new(|_| {
            Box::pin(async { Err(IamError::with_status("UNAUTHENTICATED", "No", 401)) })
        }));
        config.authorize = Some(Arc::new(|_, _, _| Box::pin(async { Ok(()) })));
        config.trusted_origins = Some(vec!["https://app.example.test".into()]);
        config.after_sign_in = Some("https://app.example.test/home".into());
        config.mfa_url = Some("/mfa".into());
        config.error_url = Some("/login?sso=1".into());
        let redirecting = create_saml_service(config).unwrap();
        let created = f
            .service
            .create_connection(
                &admin(),
                &json!({ "tenantId": "a", "id": "acme", "name": "Acme", "metadataXml": metadata(&[&f.idp.cert], "") }),
            )
            .await
            .unwrap();
        let sign_in = |query: &'static str| {
            let redirecting = redirecting.clone();
            let (acs, entity, idp) = (
                created["acsUrl"].as_str().unwrap().to_owned(),
                created["entityId"].as_str().unwrap().to_owned(),
                f.idp.clone(),
            );
            async move {
                let login = redirecting
                    .handler(&get(&format!("https://iam.test/saml/acme/login{query}")))
                    .await
                    .unwrap();
                assert_eq!(login.status(), 302);
                let location = header(&login, "location").unwrap();
                let relay = url::Url::parse(&location)
                    .unwrap()
                    .query_pairs()
                    .find(|(key, _)| key == "RelayState")
                    .unwrap()
                    .1
                    .into_owned();
                let saml_response = response(Some(&request_id(&location)), &acs, &entity, &idp);
                let cookie = header(&login, "set-cookie")
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .to_owned();
                redirecting
                    .handler(&post_form(
                        "https://iam.test/saml/acme/acs",
                        &[("SAMLResponse", &saml_response), ("RelayState", &relay)],
                        Some(&cookie),
                    ))
                    .await
                    .unwrap()
            }
        };
        // A session: the JSON stays (the host turns it into a 303 with the cookie), the hint names the page.
        let plain = sign_in("").await;
        assert_eq!(plain.status(), 200);
        assert_eq!(
            header(&plain, "x-better-iam-redirect").as_deref(),
            Some("https://app.example.test/home")
        );
        assert_matches(&json_body(&plain), json!({ "token": "session-token" }));
        let back = sign_in("?returnTo=%2Finvoices%3Fpage%3D2").await;
        assert_eq!(
            header(&back, "x-better-iam-redirect").as_deref(),
            Some("/invoices?page=2")
        );

        // MFA: the challenge goes in the fragment, to the MFA page, with returnTo.
        *outcome.lock().unwrap() = Ok(
            json!({ "mfaRequired": true, "challenge": "challenge-1", "enrollmentRequired": false }),
        );
        let mfa = sign_in("?returnTo=/reports").await;
        let target = header(&mfa, "x-better-iam-redirect").unwrap();
        assert!(target.starts_with("/mfa#"), "{target}");
        let fragment: serde_json::Map<String, Value> =
            url::form_urlencoded::parse(target.split('#').nth(1).unwrap().as_bytes())
                .map(|(key, value)| (key.into_owned(), Value::String(value.into_owned())))
                .collect();
        assert_eq!(
            Value::Object(fragment),
            json!({
                "tenantId": "a",
                "mfaRequired": "true",
                "challenge": "challenge-1",
                "enrollmentRequired": "false",
                "returnTo": "/reports",
            })
        );

        // Failures go to the error page with the host's code; the JSON body stays generic.
        *outcome.lock().unwrap() = Err(IamError::with_status(
            "ACCOUNT_LINK_REQUIRED",
            "Link first",
            409,
        ));
        let failed = sign_in("").await;
        assert_eq!(failed.status(), 401);
        assert_eq!(
            header(&failed, "x-better-iam-redirect").as_deref(),
            Some("/login?sso=1&error=ACCOUNT_LINK_REQUIRED")
        );
        assert_eq!(json_body(&failed), json!({ "error": "SAML_INVALID" }));

        // returnTo must be a path on this site.
        for bad in [
            "https://evil.test/",
            "//evil.test",
            "/\\evil.test",
            "relative",
        ] {
            let encoded: String = url::form_urlencoded::byte_serialize(bad.as_bytes()).collect();
            let answer = redirecting
                .handler(&get(&format!(
                    "https://iam.test/saml/acme/login?returnTo={encoded}"
                )))
                .await
                .unwrap();
            assert_eq!(answer.status(), 400, "{bad}");
        }
        // Without afterSignIn nothing changes: no hint.
        let login = f
            .service
            .handler(&get("https://iam.test/saml/acme/login?returnTo=/x"))
            .await
            .unwrap();
        assert_eq!(login.status(), 302);

        let options = || {
            let mut options = completing(&f.store, &f.completed);
            options.service_provider = Some(sp_provider(&f.sp));
            options
        };
        let message = |options: SamlConfigOptions| {
            create_saml_service(options)
                .err()
                .map(|error| error.message().to_owned())
        };
        let mut evil = options();
        evil.after_sign_in = Some("https://evil.test/".into());
        assert!(message(evil).unwrap().contains("afterSignIn"));
        let mut scheme_relative = options();
        scheme_relative.after_sign_in = Some("//evil.test/".into());
        assert!(message(scheme_relative).unwrap().contains("afterSignIn"));
        let mut mfa_only = options();
        mfa_only.mfa_url = Some("/mfa".into());
        assert!(message(mfa_only).unwrap().contains("need afterSignIn"));
        let mut own = options();
        own.after_sign_in = Some("https://iam.test/welcome".into());
        assert!(create_saml_service(own).is_ok());
    });
}
