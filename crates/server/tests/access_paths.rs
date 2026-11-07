//! Self-service access paths: ported from tests/access-paths.test.ts. Tenants, members and sessions come from the
//! organization fixture; the access package is written the way `packages.create` writes it (the packages API group
//! belongs to another port unit).

mod organization_fixture;

use better_iam_core::{CredentialInput, PermissionsConfig};
use better_iam_server::options::{AuthorizationRequest, ResourceTarget};
use organization_fixture::{Org, body, code, fails, ok, organization, run};
use serde_json::{Value, json};

fn doc() -> Value {
    json!({ "type": "document", "id": "d1" })
}

struct Scenario {
    f: Org,
    tenant_id: String,
    owner: CredentialInput,
    alice_token: CredentialInput,
    bob_token: CredentialInput,
    eligible: Value,
    pkg: Value,
    agreement: Value,
    writer: Value,
}

async fn scenario() -> Scenario {
    let f = organization(|options| {
        options.permissions = Some(PermissionsConfig {
            actions: Some(vec![
                "documents:read".into(),
                "documents:write".into(),
                "documents:delete".into(),
                "documents:share".into(),
            ]),
            ..PermissionsConfig::default()
        });
    })
    .await;
    let tenant_id = f.tenant_id.clone();
    let owner = f.owner_credential.clone();
    let alice = f.member("alice").await;
    f.member("bob").await;
    let api = &f.iam.api;
    let role = |name: &'static str, statements: Value| {
        let (owner, tenant_id) = (owner.clone(), tenant_id.clone());
        async move {
            ok(api
                .roles
                .create(
                    &owner,
                    body(json!({
                        "tenantId": tenant_id,
                        "name": name,
                        "document": { "version": 1, "statements": statements },
                    })),
                )
                .await)
        }
    };
    let bind = |role_id: Value, subject_id: String, extra: Value| {
        let (owner, tenant_id) = (owner.clone(), tenant_id.clone());
        async move {
            let mut input = json!({
                "tenantId": tenant_id,
                "roleId": role_id,
                "subjectType": "identity",
                "subjectId": subject_id,
            });
            for (key, value) in extra.as_object().unwrap() {
                input[key] = value.clone();
            }
            ok(api.bindings.create(&owner, body(input)).await)
        }
    };
    let member = ok(api
        .roles
        .create(
            &owner,
            body(json!({
                "tenantId": tenant_id,
                "name": "Member",
                "permissions": ["iam:packages:request", "iam:bindings:activate"],
            })),
        )
        .await);
    bind(member["id"].clone(), alice.clone(), json!({})).await;
    // Reading needs MFA.
    let reader = role(
        "MFA reader",
        json!([{
            "effect": "allow",
            "actions": ["documents:read"],
            "resources": ["*"],
            "conditions": { "Bool": { "principal.mfa": true } },
        }]),
    )
    .await;
    bind(reader["id"].clone(), alice.clone(), json!({})).await;
    // Writing through a just-in-time binding.
    let writer = role(
        "Writer",
        json!([{ "effect": "allow", "actions": ["documents:write"], "resources": ["*"] }]),
    )
    .await;
    let eligible = bind(
        writer["id"].clone(),
        alice.clone(),
        json!({ "eligible": true, "requireJustification": true }),
    )
    .await;
    // Deleting through a requestable package (as packages.create writes it).
    let deleter = role(
        "Deleter",
        json!([{ "effect": "allow", "actions": ["documents:delete"], "resources": ["*"] }]),
    )
    .await;
    let now = f.now();
    let pkg = Value::Object(
        f.insert(
            "accessPackages",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": tenant_id,
                "uniqueKey": "name:cleanup crew",
                "name": "Cleanup crew",
                "roleIds": [deleter["id"]],
                "groupIds": [],
                "createdAt": now,
                "updatedAt": now,
                "requestable": true,
            }),
        )
        .await,
    );
    // Sharing once the acceptable-use policy is accepted.
    let sharer = role(
        "Sharer",
        json!([
            { "effect": "allow", "actions": ["documents:share"], "resources": ["*"] },
            {
                "effect": "deny",
                "actions": ["documents:share"],
                "resources": ["*"],
                "conditions": { "NumericGreaterThan": { "principal.pendingAgreements": 0 } },
            },
        ]),
    )
    .await;
    bind(sharer["id"].clone(), alice.clone(), json!({})).await;
    let agreement = ok(api
        .agreements
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Acceptable use", "content": "Be nice." })),
        )
        .await);
    let alice_token = f.sign_in(&alice).await;
    let bob_id = f
        .find(
            "identities",
            better_iam_core::Filter::new().eq("email", "bob@acme.test"),
        )
        .await[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let bob_token = f.sign_in(&bob_id).await;
    Scenario {
        f,
        tenant_id,
        owner,
        alice_token,
        bob_token,
        eligible,
        pkg,
        agreement,
        writer,
    }
}

async fn find(s: &Scenario, action: &str, credential: &CredentialInput) -> Value {
    ok(s.f
        .iam
        .api
        .access_paths
        .find(
            credential,
            body(json!({ "tenantId": s.tenant_id, "action": action, "resource": doc() })),
        )
        .await)
}

#[test]
fn finds_the_step_up_agreement_activation_and_package_that_would_each_grant_access() {
    run(|| async {
        let s = scenario().await;
        let alice = s.alice_token.clone();

        let read = find(&s, "documents:read", &alice).await;
        assert_eq!(read["allowed"], json!(false));
        assert!(read["reason"].is_string());
        assert_eq!(read["paths"], json!([{ "kind": "mfa" }]));
        assert_eq!(read.as_object().unwrap().len(), 3);

        assert_eq!(
            find(&s, "documents:share", &alice).await["paths"],
            json!([{
                "kind": "accept-agreements",
                "agreements": [{ "id": s.agreement["id"], "name": "Acceptable use", "version": 1 }],
            }])
        );
        assert_eq!(
            find(&s, "documents:write", &alice).await["paths"],
            json!([{
                "kind": "activate",
                "bindingId": s.eligible["id"],
                "role": { "id": s.writer["id"], "name": "Writer" },
                "requireApproval": false,
                "requireJustification": true,
                "requireMfa": false,
            }])
        );
        assert_eq!(
            find(&s, "documents:delete", &alice).await["paths"],
            json!([{
                "kind": "request-package",
                "package": { "id": s.pkg["id"], "name": "Cleanup crew" },
                "requireJustification": false,
            }])
        );
        // Someone with none of these options gets no paths.
        let bob = find(&s, "documents:delete", &s.bob_token).await;
        assert_eq!(bob["allowed"], json!(false));
        assert_eq!(bob["paths"], json!([]));

        // Nothing was saved by the simulations.
        let api = &s.f.iam.api;
        assert_eq!(
            ok(api
                .bindings
                .list_activations(&s.owner, body(json!({ "tenantId": s.tenant_id })))
                .await),
            json!([])
        );
        let status = ok(api
            .agreements
            .status(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "agreementId": s.agreement["id"] })),
            )
            .await);
        assert_eq!(status["accepted"], json!([]));
        let bindings = ok(api
            .bindings
            .list(&s.owner, body(json!({ "tenantId": s.tenant_id })))
            .await);
        assert!(!bindings.as_array().unwrap().iter().any(|binding| {
            binding["uniqueKey"]
                .as_str()
                .is_some_and(|key| key.starts_with("simulation:"))
        }));
        let decision =
            s.f.iam
                .authorize(&AuthorizationRequest {
                    credential: alice.clone(),
                    tenant_id: s.tenant_id.clone(),
                    action: "documents:delete".into(),
                    resource: ResourceTarget {
                        kind: "document".into(),
                        id: "d1".into(),
                    },
                })
                .await
                .unwrap();
        assert!(!decision.allowed);

        // Taking a path works: accepting the agreement allows sharing, and then no paths are needed.
        ok(api
            .agreements
            .accept(
                &alice,
                body(json!({
                    "tenantId": s.tenant_id,
                    "agreementId": s.agreement["id"],
                    "version": 1,
                })),
            )
            .await);
        let share = find(&s, "documents:share", &alice).await;
        assert_eq!(share["allowed"], json!(true));
        assert!(share["reason"].is_string());
        assert_eq!(share["paths"], json!([]));
    });
}

#[test]
fn only_serves_ordinary_sessions_of_the_tenant_and_known_actions() {
    run(|| async {
        let s = scenario().await;
        let api = &s.f.iam.api;
        let error = fails(
            api.access_paths
                .find(
                    &s.f.root_credential,
                    body(json!({
                        "tenantId": s.tenant_id,
                        "action": "documents:read",
                        "resource": doc(),
                    })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            api.access_paths
                .find(
                    &s.alice_token,
                    body(json!({
                        "tenantId": s.tenant_id,
                        "action": "documents:fly",
                        "resource": doc(),
                    })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_ACTION");
    });
}
