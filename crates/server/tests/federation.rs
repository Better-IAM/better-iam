//! Port of the federation tests that exercise `federation.ts` directly: tests/federated-attributes.test.ts (mapped
//! attributes), tests/security-federation.test.ts (root enrollment, live grants, trust changes),
//! tests/federation-import-gaps.test.ts (first SSO sign-in of SCIM-provisioned people), plus account linking and the
//! conformance entry of `protocolHost`. SCIM connections and users, roles and bindings, which the TypeScript suites
//! create through the SCIM service and other API groups, are written to the store directly. `syncRoleMappings`,
//! `identityStatusChanged` and `groupDeleted` call into teams.ts and licenses.ts, which other units port.

mod org_fixture;

use better_iam_auth::service::base::CreateIdentityInput;
use better_iam_core::{AttributeType, Filter, IamStoreExt, Identity, PermissionsConfig};
use org_fixture::{DAY, Org, code, run};
use serde_json::{Value, json};

fn login(org: &Org, extra: Value) -> Value {
    let mut input = json!({
        "tenantId": org.tenant_id,
        "providerId": "corp-sso",
        "issuer": "https://idp.example.test",
        "subject": "u-123",
        "email": "alice@acme.test",
        "emailVerified": true,
        "name": "Alice",
    });
    for (key, value) in extra.as_object().unwrap() {
        if value.is_null() {
            input.as_object_mut().unwrap().remove(key);
        } else {
            input[key] = value.clone();
        }
    }
    input
}

async fn identity_of(org: &Org, result: &Value) -> Value {
    let id = result["session"]["identityId"].as_str().expect("a session");
    Value::Object(org.get("identities", id).await.unwrap())
}

#[test]
fn stores_mapped_attributes_on_every_federated_sign_in() {
    run(|| async {
        let org = Org::new(|options| {
            let mut attributes = indexmap::IndexMap::new();
            attributes.insert("department".to_owned(), AttributeType::String);
            attributes.insert("level".to_owned(), AttributeType::Number);
            options.permissions = Some(PermissionsConfig {
                identity_attributes: Some(attributes),
                ..PermissionsConfig::default()
            });
        })
        .await;
        let host = org.iam.protocol_host();
        let first = host
            .complete_authentication(&login(
                &org,
                json!({ "attributes": { "department": "finance", "level": 2 } }),
            ))
            .await
            .unwrap();
        assert!(first["token"].is_string());
        assert_eq!(first["session"]["method"], json!("federated"));
        assert!(first["session"].get("tokenHash").is_none());
        let stored = identity_of(&org, &first).await;
        assert_eq!(
            stored["attributes"],
            json!({ "department": "finance", "level": 2 })
        );
        assert_eq!(stored["emailVerified"], json!(true));
        assert_eq!(stored["name"], json!("Alice"));
        // The next sign-in replaces the attributes; a sign-in without a mapping leaves them alone.
        host.complete_authentication(&login(
            &org,
            json!({ "attributes": { "department": "ops" } }),
        ))
        .await
        .unwrap();
        assert_eq!(
            identity_of(&org, &first).await["attributes"],
            json!({ "department": "ops" })
        );
        let again = host
            .complete_authentication(&login(&org, json!({})))
            .await
            .unwrap();
        assert_eq!(
            again["session"]["identityId"],
            first["session"]["identityId"]
        );
        assert_eq!(
            identity_of(&org, &first).await["attributes"],
            json!({ "department": "ops" })
        );
        // Undeclared or mistyped attributes are rejected and the sign-in fails closed.
        assert_eq!(
            code(
                host.complete_authentication(&login(
                    &org,
                    json!({ "attributes": { "badge": "gold" } })
                ))
                .await
            ),
            "INVALID_INPUT"
        );
        assert_eq!(
            code(
                host.complete_authentication(&login(
                    &org,
                    json!({ "attributes": { "level": "high" } })
                ))
                .await
            ),
            "INVALID_INPUT"
        );
        assert_eq!(
            identity_of(&org, &first).await["attributes"],
            json!({ "department": "ops" })
        );
        // One link records the provider, issuer and subject.
        let links = org
            .find(
                "externalIdentities",
                Filter::new().eq("tenantId", org.tenant_id.clone()),
            )
            .await;
        assert_eq!(links.len(), 1);
        assert_eq!(
            links[0]["uniqueKey"],
            json!(r#"["corp-sso","https://idp.example.test","u-123"]"#)
        );
        assert_eq!(links[0]["subject"], json!("u-123"));
        // The validator protocols use for SCIM payloads.
        assert_eq!(
            host.validate_identity_attributes(Some(&json!({ "level": 3 })))
                .unwrap(),
            *json!({ "level": 3 }).as_object().unwrap()
        );
        assert_eq!(
            code(host.validate_identity_attributes(Some(&json!({ "nope": 1 })))),
            "INVALID_INPUT"
        );
    });
}

#[test]
fn enrollment_needs_a_verified_email_and_never_creates_platform_accounts() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let host = org.iam.protocol_host();
        assert_eq!(
            code(
                host.complete_authentication(&json!({
                    "tenantId": org.root_tenant_id,
                    "providerId": "google",
                    "issuer": "https://accounts.google.com",
                    "subject": "stranger-1",
                    "email": "stranger@gmail.example",
                    "emailVerified": true,
                }))
                .await
            ),
            "FORBIDDEN"
        );
        // Organizations still enroll verified addresses as documented.
        let joined = host
            .complete_authentication(&json!({
                "tenantId": org.tenant_id,
                "providerId": "google",
                "issuer": "https://accounts.google.com",
                "subject": "new-member-1",
                "email": "New.Member@acme.test",
                "emailVerified": true,
            }))
            .await
            .unwrap();
        let identity = identity_of(&org, &joined).await;
        assert_eq!(identity["email"], json!("new.member@acme.test"));
        assert_eq!(identity["name"], json!("New.Member@acme.test"));
        let error = host
            .complete_authentication(&login(&org, json!({ "emailVerified": false })))
            .await
            .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "VERIFIED_EMAIL_REQUIRED",
                "Federation enrollment needs a verified email"
            )
        );
        assert_eq!(
            code(
                host.complete_authentication(&login(&org, json!({ "email": null })))
                    .await
            ),
            "VERIFIED_EMAIL_REQUIRED"
        );
        // An existing account is linked only after its owner proves control of it.
        org.member("alice").await;
        assert_eq!(
            code(host.complete_authentication(&login(&org, json!({}))).await),
            "ACCOUNT_LINK_REQUIRED"
        );
        // An inactive organization signs nobody in.
        org.patch("tenants", &org.tenant_id, json!({ "status": "suspended" }))
            .await;
        assert!(
            host.complete_authentication(&login(
                &org,
                json!({ "subject": "x", "email": "x@acme.test" })
            ))
            .await
            .is_err()
        );
    });
}

#[test]
fn links_an_existing_account_with_a_verified_linking_proof() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let host = org.iam.protocol_host();
        let alice = org.member("alice").await;
        let session = org.sign_in("alice").await;
        let principal = org
            .iam
            .ctx
            .principals()
            .unwrap()
            .authenticate(&session)
            .await
            .unwrap();
        let proof = json!({
            "linkingSessionId": principal.session.id,
            "linkingIdentityId": alice.id,
        });
        let linked = host
            .complete_authentication(&login(&org, proof.clone()))
            .await
            .unwrap();
        assert_eq!(linked["session"]["identityId"], json!(alice.id));
        let audit = org
            .find(
                "audit",
                Filter::new().eq("action", "identity:link-provider"),
            )
            .await;
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0]["actorId"], json!(alice.id));
        assert_eq!(audit[0]["resourceId"], json!(alice.id));
        // Signing in again uses the link.
        let again = host
            .complete_authentication(&login(&org, json!({})))
            .await
            .unwrap();
        assert_eq!(again["session"]["identityId"], json!(alice.id));
        // The same external account cannot be linked to someone else.
        let bob = org.member("bob").await;
        let bob_principal = org
            .iam
            .ctx
            .principals()
            .unwrap()
            .authenticate(&org.sign_in("bob").await)
            .await
            .unwrap();
        let error = host
            .complete_authentication(&login(
                &org,
                json!({ "linkingSessionId": bob_principal.session.id, "linkingIdentityId": bob.id }),
            ))
            .await
            .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.status),
            ("ACCOUNT_LINK_CONFLICT", 409)
        );
        // A proof naming another identity, or an unknown session, is refused.
        for proof in [
            json!({ "linkingSessionId": bob_principal.session.id, "linkingIdentityId": alice.id }),
            json!({ "linkingSessionId": "missing", "linkingIdentityId": alice.id }),
        ] {
            let error = host
                .complete_authentication(&login(&org, proof))
                .await
                .unwrap_err();
            assert_eq!(
                (error.code.as_str(), error.message.as_str(), error.status),
                (
                    "INVALID_LINK",
                    "Invalid verified account-linking proof",
                    403
                )
            );
        }
        // The proof must be a recent sign-in.
        org.advance(DAY);
        assert_eq!(
            code(
                host.complete_authentication(&login(
                    &org,
                    json!({ "subject": "u-456", "linkingSessionId": principal.session.id, "linkingIdentityId": alice.id }),
                ))
                .await
            ),
            "RECENT_AUTH_REQUIRED"
        );
    });
}

/// A SCIM connection of the organization and a person it provisioned (as the SCIM service stores them).
async fn scim_person(org: &Org, connection_id: &str, name: &str, verified: bool) -> Identity {
    let auth = org.iam.auth.clone();
    let tenant_id = org.tenant_id.clone();
    let email = format!("{name}@acme.test");
    let identity = org
        .iam
        .store
        .transaction(|tx| async move {
            auth.create_identity(
                &tx,
                CreateIdentityInput {
                    tenant_id,
                    email,
                    name: name.to_owned(),
                    password: None,
                    owner: None,
                    root_admin: None,
                    email_verified: Some(verified),
                },
            )
            .await
        })
        .await
        .unwrap();
    org.insert(
        "scimUsers",
        json!({
            "id": better_iam_server::utils::id(),
            "tenantId": org.tenant_id,
            "connectionId": connection_id,
            "identityId": identity.id,
            "userName": format!("{name}@acme.test"),
        }),
    )
    .await;
    identity
}

#[test]
fn links_the_first_sso_sign_in_to_a_trusted_scim_account() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let host = org.iam.protocol_host();
        let connection = "scim-connection-1";
        org.insert(
            "scimConnections",
            json!({ "id": connection, "tenantId": org.tenant_id, "name": "Okta", "revoked": false }),
        )
        .await;
        let ada = scim_person(&org, connection, "ada", false).await;
        let federated = |extra: Value| {
            let mut input = json!({
                "tenantId": org.tenant_id,
                "providerId": "acme-okta",
                "issuer": "https://acme.okta.example",
                "emailVerified": true,
            });
            for (key, value) in extra.as_object().unwrap() {
                input[key] = value.clone();
            }
            async move { host.complete_authentication(&input).await }
        };
        // Without trust, or with an unverified email, or trusting another SCIM connection: no link.
        assert_eq!(
            code(federated(json!({ "subject": "okta-ada", "email": "ada@acme.test" })).await),
            "ACCOUNT_LINK_REQUIRED"
        );
        assert_eq!(
            code(
                federated(json!({
                    "subject": "okta-ada", "email": "ada@acme.test", "emailVerified": false,
                    "trustScimProvisioned": true,
                }))
                .await
            ),
            "VERIFIED_EMAIL_REQUIRED"
        );
        assert_eq!(
            code(
                federated(json!({
                    "subject": "okta-ada", "email": "ada@acme.test",
                    "trustScimProvisioned": ["another-connection"],
                }))
                .await
            ),
            "ACCOUNT_LINK_REQUIRED"
        );
        // A federated-only tenant: the trusted connection signs Ada in to the provisioned account and links it.
        org.patch(
            "tenants",
            &org.tenant_id,
            json!({ "authPolicy": { "allowedMethods": ["federated"] } }),
        )
        .await;
        let first = federated(json!({
            "subject": "okta-ada", "email": "ADA@acme.test", "trustScimProvisioned": [connection],
        }))
        .await
        .unwrap();
        assert!(first["token"].is_string());
        assert_eq!(first["session"]["identityId"], json!(ada.id));
        let linked = org.get("identities", &ada.id).await.unwrap();
        assert_eq!(linked["emailVerified"], json!(true));
        let links = org
            .find(
                "externalIdentities",
                Filter::new().eq("identityId", ada.id.clone()),
            )
            .await;
        assert_eq!(links.len(), 1);
        assert_eq!(links[0]["providerId"], json!("acme-okta"));
        assert_eq!(links[0]["subject"], json!("okta-ada"));
        let audit = org
            .find(
                "audit",
                Filter::new().eq("action", "identity:link-provider"),
            )
            .await;
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0]["resourceId"], json!(ada.id));
        assert_eq!(audit[0]["actorId"], json!(ada.id));
        assert_eq!(
            audit[0]["metadata"],
            json!({ "providerId": "acme-okta", "via": "scim" })
        );
        // Later sign-ins use the link, whatever the connection's setting.
        let again = federated(json!({ "subject": "okta-ada", "email": "ada@acme.test" }))
            .await
            .unwrap();
        assert_eq!(again["session"]["identityId"], json!(ada.id));
        // Another account at the same IdP claiming the address does not take the linked account over.
        assert_eq!(
            code(
                federated(json!({
                    "subject": "okta-mallory", "email": "ada@acme.test", "trustScimProvisioned": true,
                }))
                .await
            ),
            "ACCOUNT_LINK_REQUIRED"
        );
    });
}

#[test]
fn never_links_accounts_scim_did_not_provision() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let host = org.iam.protocol_host();
        let connection = "scim-connection-2";
        org.insert(
            "scimConnections",
            json!({ "id": connection, "tenantId": org.tenant_id, "name": "Okta", "revoked": false }),
        )
        .await;
        org.member("bob").await;
        let federated = |subject: &str, email: &str| {
            let input = json!({
                "tenantId": org.tenant_id,
                "providerId": "acme-okta",
                "issuer": "https://acme.okta.example",
                "subject": subject,
                "email": email,
                "emailVerified": true,
                "trustScimProvisioned": true,
            });
            async move { host.complete_authentication(&input).await }
        };
        assert_eq!(
            code(federated("okta-bob", "bob@acme.test").await),
            "ACCOUNT_LINK_REQUIRED"
        );
        // The owner's account is never a target, even if an IdP vouches for its address.
        assert_eq!(
            code(federated("okta-owner", "owner@acme.test").await),
            "ACCOUNT_LINK_REQUIRED"
        );
        // Nor an account of a revoked SCIM connection.
        scim_person(&org, connection, "cyd", false).await;
        org.patch("scimConnections", connection, json!({ "revoked": true }))
            .await;
        assert_eq!(
            code(federated("okta-cyd", "cyd@acme.test").await),
            "ACCOUNT_LINK_REQUIRED"
        );
    });
}

#[test]
fn lists_only_roles_in_force_as_live_grants() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let alice = org.member("alice").await;
        let in_force = org
            .grant(
                &alice.id,
                json!([{ "effect": "allow", "actions": ["documents:read"], "resources": ["*"] }]),
            )
            .await;
        let group = org.group("Engineering").await;
        org.add_member(&group, &alice.id).await;
        for extra in [
            json!({ "eligible": true }),
            json!({ "startsAt": org.now() + DAY }),
        ] {
            let role_id = better_iam_server::utils::id();
            org.insert(
                "roles",
                json!({
                    "id": role_id, "tenantId": org.tenant_id, "name": format!("Role {role_id}"), "policyIds": [],
                    "document": { "version": 1, "statements": [] }, "protected": false,
                    "authorityId": org.authority_id,
                }),
            )
            .await;
            let mut binding = json!({
                "id": better_iam_server::utils::id(), "tenantId": org.tenant_id, "subjectType": "identity",
                "subjectId": alice.id, "roleId": role_id, "authorityId": org.authority_id,
            });
            for (key, value) in extra.as_object().unwrap() {
                binding[key] = value.clone();
            }
            org.insert("bindings", binding).await;
        }
        let grants = org
            .iam
            .protocol_host()
            .live_grants(&alice.id, &org.tenant_id)
            .await
            .unwrap();
        assert_eq!(
            grants,
            json!({ "groupIds": [group], "roleIds": [in_force] })
        );
        let called = org
            .iam
            .federation
            .call(
                "protocolHost.liveGrants",
                vec![json!(alice.id), json!(org.tenant_id)],
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(called, grants);
    });
}

#[test]
fn lets_only_an_owner_recently_signed_in_change_what_an_owner_connection_trusts() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let host = org.iam.protocol_host();
        org.insert(
            "externalIdentities",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": org.tenant_id,
                "uniqueKey": r#"["saml:acme","https://idp.test","owner-at-idp"]"#,
                "identityId": org.owner_id,
                "providerId": "saml:acme",
                "issuer": "https://idp.test",
                "subject": "owner-at-idp",
            }),
        )
        .await;
        let target = json!({ "tenantId": org.tenant_id, "providerId": "saml:acme" });
        // A delegated administrator may not.
        let dana = org.member("dana").await;
        org.grant(
            &dana.id,
            json!([{ "effect": "allow", "actions": ["iam:*"], "resources": ["*"] }]),
        )
        .await;
        let dana_session = org.sign_in("dana").await;
        let error = host
            .assert_trust_change(&dana_session, &target)
            .await
            .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "ACCESS_DENIED",
                "An owner signs in through this connection; only an owner can change what it trusts"
            )
        );
        // Connections nobody privileged signs in through are open to delegated administrators.
        host.assert_trust_change(
            &dana_session,
            &json!({ "tenantId": org.tenant_id, "providerId": "other" }),
        )
        .await
        .unwrap();
        // The owner may, but only with a recent sign-in.
        let owner = org.owner_sign_in().await;
        host.assert_trust_change(&owner, &target).await.unwrap();
        org.advance(10.0 * 60_000.0);
        assert_eq!(
            code(host.assert_trust_change(&owner, &target).await),
            "RECENT_AUTH_REQUIRED"
        );
        let fresh = org.owner_sign_in().await;
        let called = org
            .iam
            .federation
            .call(
                "protocolHost.assertTrustChange",
                vec![json!({ "token": fresh.token }), target.clone()],
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(called, better_iam_server::port::undefined());
        // A root administrator linked through a connection: only a root administrator may change it.
        org.patch("identities", &org.owner_id, json!({ "owner": null }))
            .await;
        org.insert(
            "externalIdentities",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": org.tenant_id,
                "uniqueKey": r#"["saml:root","https://idp.test","root-at-idp"]"#,
                "identityId": org.root_id,
                "providerId": "saml:root",
                "issuer": "https://idp.test",
                "subject": "root-at-idp",
            }),
        )
        .await;
        let dana_session = org.sign_in("dana").await;
        let error = host
            .assert_trust_change(
                &dana_session,
                &json!({ "tenantId": org.tenant_id, "providerId": "saml:root" }),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.message,
            "A root administrator signs in through this connection; only a root administrator can change what it trusts"
        );
    });
}

#[test]
fn answers_protocol_host_calls() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let federation = &org.iam.federation;
        let session = org.sign_in_owner_principal().await;
        let validated = federation
            .call(
                "protocolHost.validateSession",
                vec![json!(session.session.id)],
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(validated["identity"]["id"], json!(org.owner_id));
        assert_eq!(
            code(
                federation
                    .call("protocolHost.validateSession", vec![json!("missing")])
                    .await
                    .unwrap()
            ),
            "UNAUTHENTICATED"
        );
        // A protocol's audit event joins the chain.
        let event = json!({
            "id": better_iam_server::utils::id(),
            "tenantId": org.tenant_id,
            "actorId": "scim",
            "action": "scim:user:create",
            "resourceId": org.owner_id,
            "timestamp": org.now(),
            "outcome": "allow",
        });
        let tx = json!({ "$tx": true });
        org.iam
            .store
            .transaction(|_| async {
                federation
                    .call("protocolHost.recordAudit", vec![tx.clone(), event.clone()])
                    .await
                    .unwrap()
            })
            .await
            .unwrap();
        let recorded = org
            .find("audit", Filter::new().eq("action", "scim:user:create"))
            .await;
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0]["hash"].is_string());
        // Members the host does not have.
        assert!(
            federation
                .call("protocolHost.nothing", vec![])
                .await
                .is_none()
        );
        assert!(federation.call("authenticate", vec![]).await.is_none());
    });
}

trait OwnerPrincipal {
    async fn sign_in_owner_principal(&self) -> better_iam_core::AuthenticatedPrincipal;
}

impl OwnerPrincipal for Org {
    async fn sign_in_owner_principal(&self) -> better_iam_core::AuthenticatedPrincipal {
        let credential = self.owner_sign_in().await;
        self.iam
            .ctx
            .principals()
            .unwrap()
            .authenticate(&credential)
            .await
            .unwrap()
    }
}
