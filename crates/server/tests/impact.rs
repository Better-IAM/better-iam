//! Change impact preview: ported from tests/impact.test.ts. Tenants, members and sessions come from the organization
//! fixture; roles, policies, groups and bindings are created through their API groups.
//!
//! The preview evaluates access invariants before and after the change (`invariants.ts evaluateInvariants`) and checks
//! the change's own permission with `api/packages.ts allow`; both belong to other port units. Until those land the
//! suites are ignored.

mod organization_fixture;

use better_iam_core::CredentialInput;
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
    alice: String,
    bob: String,
    carol: String,
    dave: String,
    reader: Value,
    writer: Value,
    writing: Value,
}

async fn scenario() -> Scenario {
    let f = organization(|_| {}).await;
    let tenant_id = f.tenant_id.clone();
    let owner = f.owner_credential.clone();
    let alice = f.member("alice").await;
    let bob = f.member("bob").await;
    let carol = f.member("carol").await;
    let dave = f.member("dave").await;
    let api = &f.iam.api;
    let reader = ok(api
        .roles
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Reader", "permissions": ["documents:read"] })),
        )
        .await);
    let senior = ok(api
        .roles
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Senior", "inherits": [reader["id"]] })),
        )
        .await);
    let writing = ok(api
        .policies
        .create(
            &owner,
            body(json!({
                "tenantId": tenant_id,
                "name": "Writing",
                "document": {
                    "version": 1,
                    "statements": [{ "effect": "allow", "actions": ["documents:write"], "resources": ["*"] }],
                },
            })),
        )
        .await);
    let writer = ok(api
        .roles
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Writer", "policyIds": [writing["id"]] })),
        )
        .await);
    let team = ok(api
        .groups
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Team" })),
        )
        .await);
    // The membership as `groups.addMembers` stores it (its license and team hooks belong to other port units).
    let group_id = team["id"].as_str().unwrap();
    f.insert(
        "groupMembers",
        json!({
            "id": better_iam_server::utils::id(),
            "tenantId": tenant_id,
            "uniqueKey": format!("{group_id}:{bob}"),
            "groupId": group_id,
            "identityId": bob,
        }),
    )
    .await;
    for (role_id, subject_type, subject_id) in [
        (&reader["id"], "identity", json!(alice)),
        (&reader["id"], "group", team["id"].clone()),
        (&senior["id"], "identity", json!(carol)),
        (&writer["id"], "identity", json!(dave)),
    ] {
        ok(api
            .bindings
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "roleId": role_id,
                    "subjectType": subject_type,
                    "subjectId": subject_id,
                })),
            )
            .await);
    }
    Scenario {
        f,
        tenant_id,
        owner,
        alice,
        bob,
        carol,
        dave,
        reader,
        writer,
        writing,
    }
}

async fn preview(
    s: &Scenario,
    credential: &CredentialInput,
    input: Value,
) -> Result<Value, String> {
    let mut input = input;
    input["tenantId"] = json!(s.tenant_id);
    match s.f.iam.api.impact.preview(credential, body(input)).await {
        Ok(reply) => Ok(reply.into_value().expect("JSON")),
        Err(error) => Err(error.code),
    }
}

#[test]
#[ignore = "needs invariants.ts evaluateInvariants and api/packages.ts allow (other port units)"]
fn shows_who_gains_access_from_a_role_change_through_groups_and_inheritance_without_saving_it() {
    run(|| async {
        let s = scenario().await;
        let preview = preview(
            &s,
            &s.owner,
            json!({
                "change": { "role": { "roleId": s.reader["id"], "permissions": ["documents:read", "documents:write"] } },
                "resources": [doc()],
            }),
        )
        .await
        .unwrap();
        let names: Vec<&Value> = preview["roles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|role| &role["name"])
            .collect();
        assert_eq!(names, vec![&json!("Reader"), &json!("Senior")]);
        assert_eq!(preview["evaluated"], json!(3));
        assert_eq!(preview["truncated"], json!(false));
        assert_eq!(preview["gainedTotal"], json!(3));
        assert_eq!(preview["lostTotal"], json!(0));
        let mut ids: Vec<String> = preview["identities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["identity"]["id"].as_str().unwrap().to_owned())
            .collect();
        ids.sort();
        let mut expected = vec![s.alice.clone(), s.bob.clone(), s.carol.clone()];
        expected.sort();
        assert_eq!(ids, expected);
        assert_eq!(
            preview["identities"][0]["changes"],
            json!([{ "resource": "document/d1", "gained": ["documents:write"], "lost": [] }])
        );
        // Nothing was saved.
        let role = ok(s
            .f
            .iam
            .api
            .roles
            .get(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "roleId": s.reader["id"] })),
            )
            .await);
        assert!(!role.to_string().contains("documents:write"));
        let alice = s.f.sign_in(&s.alice).await;
        let check =
            s.f.iam
                .authorize(&AuthorizationRequest {
                    credential: alice,
                    tenant_id: s.tenant_id.clone(),
                    action: "documents:write".into(),
                    resource: ResourceTarget {
                        kind: "document".into(),
                        id: "d1".into(),
                    },
                })
                .await
                .unwrap();
        assert!(!check.allowed);
    });
}

#[test]
#[ignore = "needs invariants.ts evaluateInvariants and api/packages.ts allow (other port units)"]
fn previews_policy_edits_and_role_deletion_with_the_real_validation() {
    run(|| async {
        let s = scenario().await;
        let policy = preview(
            &s,
            &s.owner,
            json!({
                "change": {
                    "policy": {
                        "policyId": s.writing["id"],
                        "document": {
                            "version": 1,
                            "statements": [{ "effect": "allow", "actions": ["documents:read"], "resources": ["*"] }],
                        },
                    },
                },
                "resources": [doc()],
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            policy["identities"],
            json!([{
                "identity": { "id": s.dave, "name": "dave@acme.test" },
                "changes": [
                    { "resource": "document/d1", "gained": ["documents:read"], "lost": ["documents:write"] },
                ],
            }])
        );
        let current = ok(s
            .f
            .iam
            .api
            .policies
            .get(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "policyId": s.writing["id"] })),
            )
            .await);
        assert_eq!(current["version"], json!(1));

        let removal = preview(
            &s,
            &s.owner,
            json!({
                "change": { "deleteRole": s.writer["id"] },
                "resources": [doc()],
                "actions": ["documents:write"],
            }),
        )
        .await
        .unwrap();
        assert_eq!(removal["lostTotal"], json!(1));
        assert_eq!(
            removal["identities"][0]["changes"][0]["lost"],
            json!(["documents:write"])
        );
        // Deleting a role others inherit is refused exactly as roles.delete would refuse it.
        assert_eq!(
            preview(
                &s,
                &s.owner,
                json!({ "change": { "deleteRole": s.reader["id"] }, "resources": [doc()] }),
            )
            .await
            .unwrap_err(),
            "RESOURCE_IN_USE"
        );
        let bindings = ok(s
            .f
            .iam
            .api
            .bindings
            .list(&s.owner, body(json!({ "tenantId": s.tenant_id })))
            .await);
        assert!(
            bindings
                .as_array()
                .unwrap()
                .iter()
                .any(|binding| binding["roleId"] == s.writer["id"])
        );
    });
}

#[test]
#[ignore = "needs invariants.ts evaluateInvariants and api/packages.ts allow (other port units)"]
fn validates_input_and_requires_simulate_permission() {
    run(|| async {
        let s = scenario().await;
        let api = &s.f.iam.api;
        let invalid = [
            json!({
                "change": { "deleteRole": s.writer["id"], "role": { "roleId": s.reader["id"] } },
                "resources": [doc()],
            }),
            json!({ "change": { "deleteRole": s.writer["id"] }, "resources": [] }),
        ];
        for input in invalid {
            assert_eq!(
                preview(&s, &s.owner, input).await.unwrap_err(),
                "INVALID_INPUT"
            );
        }
        assert_eq!(
            preview(
                &s,
                &s.owner,
                json!({
                    "change": { "deleteRole": s.writer["id"] },
                    "resources": [doc()],
                    "actions": ["documents:fly"],
                }),
            )
            .await
            .unwrap_err(),
            "INVALID_ACTION"
        );
        let alice = s.f.sign_in(&s.alice).await;
        assert_eq!(
            preview(
                &s,
                &alice,
                json!({ "change": { "deleteRole": s.writer["id"] }, "resources": [doc()] }),
            )
            .await
            .unwrap_err(),
            "ACCESS_DENIED"
        );
        // Simulating is not enough: the preview also needs the permission the real change needs.
        let simulator = ok(api
            .roles
            .create(
                &s.owner,
                body(json!({
                    "tenantId": s.tenant_id,
                    "name": "Simulator",
                    "permissions": ["iam:policies:simulate"],
                })),
            )
            .await);
        ok(api
            .bindings
            .create(
                &s.owner,
                body(json!({
                    "tenantId": s.tenant_id,
                    "roleId": simulator["id"],
                    "subjectType": "identity",
                    "subjectId": s.bob,
                })),
            )
            .await);
        let bob = s.f.sign_in(&s.bob).await;
        for change in [
            json!({ "deleteRole": s.writer["id"] }),
            json!({ "role": { "roleId": s.reader["id"], "permissions": ["documents:write"] } }),
        ] {
            let error = fails(
                api.impact
                    .preview(
                        &bob,
                        body(json!({ "tenantId": s.tenant_id, "change": change, "resources": [doc()] })),
                    )
                    .await,
            );
            assert_eq!(code(&error), "ACCESS_DENIED");
        }
    });
}
