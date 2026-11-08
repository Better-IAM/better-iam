//! Port of the SAML tests of tests/security-federation.test.ts ("federated account links"): accounts linked through
//! one sign-in provider must stay out of reach of every other trust anchor: a SAML connection given another
//! provider's ID, a connection deleted and recreated under the same ID, or an administrator who swaps a connection's
//! IdP certificates to sign assertions for the owner. The service runs on `iam.protocol_host()`.

mod organization_fixture;
mod saml_support;

use better_iam_core::{CredentialInput, Filter};
use better_iam_saml::{
    SamlConfigOptions, SamlError, SamlService, SamlServiceProvider, create_saml_service,
};
use organization_fixture::{Org, bearer, body, ok, organization, run};
use saml_support::{ASSERTION_NS, KeyPair, PROTOCOL_NS, b64, iso, keys, now, sign, uuid};
use serde_json::{Value, json};

struct Claims<'a> {
    issuer: &'a str,
    name_id: &'a str,
    email: Option<&'a str>,
}

/// A signed, unsolicited (IdP-initiated) response.
fn unsolicited(connection: &Value, key: &KeyPair, claims: &Claims<'_>) -> String {
    let (acs, entity) = (
        connection["acsUrl"].as_str().unwrap(),
        connection["entityId"].as_str().unwrap(),
    );
    let now = iso(saml_support::now());
    let expires = iso(saml_support::now() + 120_000.0);
    let email = claims
        .email
        .map(|email| {
            format!(
                "<saml:AttributeStatement><saml:Attribute Name=\"email\"><saml:AttributeValue>{email}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>"
            )
        })
        .unwrap_or_default();
    let assertion = format!(
        "<saml:Assertion xmlns:saml=\"{ASSERTION_NS}\" ID=\"_{}\" Version=\"2.0\" IssueInstant=\"{now}\"><saml:Issuer>{}</saml:Issuer><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">{}</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"{acs}\" NotOnOrAfter=\"{expires}\"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"{}\" NotOnOrAfter=\"{expires}\"><saml:AudienceRestriction><saml:Audience>{entity}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant=\"{now}\" SessionIndex=\"session\"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>{email}</saml:Assertion>",
        uuid(),
        claims.issuer,
        claims.name_id,
        iso(saml_support::now() - 1000.0)
    );
    let document = format!(
        "<samlp:Response xmlns:samlp=\"{PROTOCOL_NS}\" xmlns:saml=\"{ASSERTION_NS}\" ID=\"_{}\" Version=\"2.0\" IssueInstant=\"{now}\" Destination=\"{acs}\"><saml:Issuer>{}</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>{}</samlp:Response>",
        uuid(),
        claims.issuer,
        sign(&assertion, "Assertion", key)
    );
    b64(&sign(&document, "Response", key))
}

struct Setup {
    f: Org,
    service: SamlService,
    idp: KeyPair,
    attacker: KeyPair,
}

async fn setup() -> Setup {
    let f = organization(|_| {}).await;
    let sp = keys("sp");
    let mut options = SamlConfigOptions::from_protocol_host(&f.iam).unwrap();
    options.service_provider = Some(SamlServiceProvider {
        base_url: "https://iam.test".into(),
        private_key: sp.private,
        public_certificate: sp.cert,
        ..SamlServiceProvider::default()
    });
    let service = create_saml_service(options).unwrap();
    Setup {
        f,
        service,
        idp: keys("idp"),
        attacker: keys("attacker"),
    }
}

impl Setup {
    /// A fresh (recently authenticated) owner session.
    async fn owner_sign_in(&self) -> CredentialInput {
        self.f.session(&self.f.owner_id, false).await
    }

    async fn signed_in_as(&self, result: Result<Value, SamlError>) -> String {
        let result = result.unwrap();
        self.f
            .iam
            .authenticate(&bearer(result["token"].as_str().unwrap()))
            .await
            .unwrap()
            .identity
            .id
    }
}

fn connection_input(id: &str, tenant_id: &str, certificate: &str, issuer: &str) -> Value {
    json!({
        "tenantId": tenant_id,
        "id": id,
        "name": "Acme IdP",
        "entryPoint": "https://idp.test/login",
        "idpIssuer": issuer,
        "idpCertificates": [certificate],
        "trustedEmailDomains": ["acme.test"],
        "allowIdpInitiated": true,
    })
}

fn code(result: Result<Value, SamlError>) -> Option<String> {
    result
        .err()
        .and_then(|error| error.code().map(str::to_owned))
}

#[test]
fn never_lets_a_saml_connection_reach_accounts_linked_through_another_provider_with_the_same_id() {
    run(|| async {
        let s = setup().await;
        // The owner signs in with GitHub through a deployment OAuth connection named "github".
        s.f.insert(
            "externalIdentities",
            json!({
                "id": uuid(),
                "tenantId": s.f.tenant_id,
                "uniqueKey": better_iam_core::js::stringify(&json!(["github", "https://github.com", "1234"])),
                "identityId": s.f.owner_id,
                "providerId": "github",
                "issuer": "https://github.com",
                "subject": "1234",
            }),
        )
        .await;
        let owner = s.owner_sign_in().await;
        let connection = s
            .service
            .create_connection(
                &owner,
                &connection_input(
                    "github",
                    &s.f.tenant_id,
                    &s.attacker.cert,
                    "https://github.com",
                ),
            )
            .await
            .unwrap();
        let claims = Claims {
            issuer: "https://github.com",
            name_id: "1234",
            email: Some("owner@acme.test"),
        };
        let result = s
            .service
            .idp_initiated("github", &unsolicited(&connection, &s.attacker, &claims))
            .await;
        assert_eq!(code(result), Some("ACCOUNT_LINK_REQUIRED".into()));
    });
}

#[test]
fn unlinks_accounts_when_a_connection_is_deleted_so_a_recreated_one_with_the_same_id_starts_over() {
    run(|| async {
        let s = setup().await;
        let owner = s.owner_sign_in().await;
        let first = s
            .service
            .create_connection(
                &owner,
                &connection_input("acme", &s.f.tenant_id, &s.idp.cert, "https://idp.test"),
            )
            .await
            .unwrap();
        let claims = Claims {
            issuer: "https://idp.test",
            name_id: "employee-7",
            email: Some("emp7@acme.test"),
        };
        let employee = s
            .signed_in_as(
                s.service
                    .idp_initiated("acme", &unsolicited(&first, &s.idp, &claims))
                    .await,
            )
            .await;
        let again = s
            .signed_in_as(
                s.service
                    .idp_initiated("acme", &unsolicited(&first, &s.idp, &claims))
                    .await,
            )
            .await;
        assert_eq!(again, employee);
        s.service
            .delete_connection(&owner, &s.f.tenant_id, "acme")
            .await
            .unwrap();
        assert!(
            s.f.find(
                "externalIdentities",
                Filter::new().eq("tenantId", s.f.tenant_id.clone())
            )
            .await
            .is_empty()
        );
        let second = s
            .service
            .create_connection(
                &owner,
                &connection_input("acme", &s.f.tenant_id, &s.attacker.cert, "https://idp.test"),
            )
            .await
            .unwrap();
        let result = s
            .service
            .idp_initiated("acme", &unsolicited(&second, &s.attacker, &claims))
            .await;
        assert_eq!(code(result), Some("ACCOUNT_LINK_REQUIRED".into()));
    });
}

#[test]
fn lets_only_an_owner_recently_signed_in_change_what_a_connection_an_owner_signs_in_through_trusts()
{
    run(|| async {
        let s = setup().await;
        let owner = s.owner_sign_in().await;
        let tenant_id = s.f.tenant_id.clone();
        let connection = s
            .service
            .create_connection(
                &owner,
                &connection_input("acme", &tenant_id, &s.idp.cert, "https://idp.test"),
            )
            .await
            .unwrap();
        let record =
            s.f.iam
                .store
                .get("samlConnections", "acme")
                .await
                .unwrap()
                .unwrap();
        let provider_key = record["providerKey"].as_str().unwrap().to_owned();
        s.f.insert(
            "externalIdentities",
            json!({
                "id": uuid(),
                "tenantId": tenant_id,
                "uniqueKey": better_iam_core::js::stringify(&json!([provider_key, "https://idp.test", "owner-at-idp"])),
                "identityId": s.f.owner_id,
                "providerId": provider_key,
                "issuer": "https://idp.test",
                "subject": "owner-at-idp",
            }),
        )
        .await;
        // A delegated administrator of SAML connections.
        let dana = s.f.member("dana").await;
        let role = ok(s
            .f
            .iam
            .api
            .roles
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "SSO admin",
                    "permissions": [
                        "iam:saml:connections:read",
                        "iam:saml:connections:update",
                        "iam:saml:connections:create",
                    ],
                })),
            )
            .await);
        ok(s.f
            .iam
            .api
            .bindings
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "roleId": role["id"],
                    "subjectType": "identity",
                    "subjectId": dana,
                })),
            )
            .await);
        let dana_session = s.f.sign_in(&dana).await;
        let update = |credential: CredentialInput, change: Value| {
            let service = s.service.clone();
            let tenant_id = tenant_id.clone();
            async move {
                let mut input = json!({ "tenantId": tenant_id, "connectionId": "acme" });
                for (key, value) in change.as_object().unwrap() {
                    input[key] = value.clone();
                }
                service.update_connection(&credential, &input).await
            }
        };
        let swap = json!({ "idpCertificates": [s.idp.cert, s.attacker.cert] });
        assert_eq!(
            code(update(dana_session.clone(), swap.clone()).await),
            Some("ACCESS_DENIED".into())
        );
        for change in [
            json!({ "idpIssuer": "https://evil.test" }),
            json!({ "trustedEmailDomains": ["acme.test", "evil.test"] }),
        ] {
            assert_eq!(
                code(update(dana_session.clone(), change).await),
                Some("ACCESS_DENIED".into())
            );
        }
        // Nothing that widens trust went through; the owner cannot be signed in with the attacker's key.
        let claims = Claims {
            issuer: "https://idp.test",
            name_id: "owner-at-idp",
            email: None,
        };
        assert!(
            s.service
                .idp_initiated("acme", &unsolicited(&connection, &s.attacker, &claims))
                .await
                .is_err()
        );
        // Renaming changes no trust, so the delegated administrator may.
        let renamed = update(dana_session.clone(), json!({ "name": "Acme SSO" }))
            .await
            .unwrap();
        assert_eq!(renamed["name"], json!("Acme SSO"));
        // The owner may, but only with a recent sign-in.
        s.f.advance(10.0 * 60_000.0);
        assert_eq!(
            code(update(owner.clone(), swap.clone()).await),
            Some("RECENT_AUTH_REQUIRED".into())
        );
        let fresh = s.owner_sign_in().await;
        let updated = update(fresh, swap).await.unwrap();
        assert!(updated["certificates"].is_array());
        let _ = now();
    });
}
