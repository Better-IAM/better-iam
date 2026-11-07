//! Access requests: the port of the `access requests` suite of tests/access.test.ts.
//!
//! Roles, bindings and grant authorities are written to the store directly (see `governance`); the purge worker step
//! of the TypeScript test (`purgeDeleted`) is replaced by removing the expired binding, as the sweep would.

mod governance;

use better_iam_core::CredentialInput;
use better_iam_server::options::{AuthorizationRequest, ResourceTarget};
use governance::{Fixture, FixtureOptions, body, err, num, ok, organization, run};
use serde_json::{Value, json};

/// A member holding a role with `permissions` (bound by the owner); its identity ID and credential.
async fn member(f: &Fixture, name: &str, permissions: &[&str]) -> (String, CredentialInput) {
    let identity = f.member(name).await;
    if !permissions.is_empty() {
        let role = f.role(&format!("{name} base"), permissions).await;
        f.bind(&role, "identity", &identity).await;
    }
    (identity, f.sign_in(name).await)
}

#[test]
fn members_request_roles_that_a_reviewer_approves_under_their_own_authority_as_temporary_bindings()
{
    run(|| async {
        let f = organization(FixtureOptions {
            access_request_lifetime_ms: Some(60.0 * 60_000.0),
            ..FixtureOptions::default()
        })
        .await;
        let api = &f.iam.api.access_requests;
        let tenant_id = f.tenant_id.clone();
        let (alice, alice_credential) = member(&f, "alice", &["iam:access-requests:create"]).await;
        let (reviewer, reviewer_credential) = member(
            &f,
            "reviewer",
            &[
                "iam:access-requests:read",
                "iam:access-requests:review",
                "iam:bindings:create",
                "iam:roles:read",
            ],
        )
        .await;
        let admin = f
            .role("Document admin", &["documents:read", "documents:write"])
            .await;
        let owner_role = f
            .find("roles", &[("tenantId", json!(tenant_id))])
            .await
            .into_iter()
            .find(|role| role["protected"] == json!(true))
            .unwrap();
        let refused = err(api
            .create(
                &alice_credential,
                body(json!({ "tenantId": tenant_id, "roleIds": [owner_role["id"]] })),
            )
            .await);
        assert_eq!(refused.code, "PROTECTED_RESOURCE");
        let refused = err(api
            .create(
                &alice_credential,
                body(json!({ "tenantId": tenant_id, "roleIds": [] })),
            )
            .await);
        assert_eq!(
            (refused.code.as_str(), refused.message.as_str()),
            ("INVALID_INPUT", "Request 1-20 roles")
        );
        let refused = err(api
            .create(
                &alice_credential,
                body(json!({ "tenantId": tenant_id, "roleIds": [admin], "durationSeconds": 10 })),
            )
            .await);
        assert_eq!(
            (refused.code.as_str(), refused.message.as_str()),
            ("INVALID_INPUT", "Invalid durationSeconds")
        );
        let refused = err(api
            .create(
                &reviewer_credential,
                body(json!({ "tenantId": tenant_id, "roleIds": [admin] })),
            )
            .await);
        assert_eq!(refused.code, "ACCESS_DENIED");
        let request = ok(api
            .create(
                &alice_credential,
                body(json!({
                    "tenantId": tenant_id,
                    "roleIds": [admin, admin],
                    "justification": "Incident 42",
                    "durationSeconds": 2 * 3600,
                })),
            )
            .await);
        assert_eq!(request["status"], json!("pending"));
        assert_eq!(request["requesterId"], json!(alice));
        assert_eq!(request["roleIds"], json!([admin]));
        assert_eq!(request["durationSeconds"], json!(7200));
        assert_eq!(request["justification"], json!("Incident 42"));
        assert_eq!(request["createdAt"], num(f.now()));
        assert_eq!(request["expiresAt"], num(f.now() + 3_600_000.0));
        let request_id = request["id"].as_str().unwrap().to_owned();
        let refused = err(api
            .create(
                &alice_credential,
                body(json!({ "tenantId": tenant_id, "roleIds": [admin] })),
            )
            .await);
        assert_eq!(refused.code, "CONFLICT");
        let mine = ok(api
            .list_mine(&alice_credential, body(json!({ "tenantId": tenant_id })))
            .await);
        assert_eq!(
            mine.as_array()
                .unwrap()
                .iter()
                .map(|item| item["id"].clone())
                .collect::<Vec<_>>(),
            vec![json!(request_id)]
        );
        let refused = err(api
            .list(&alice_credential, body(json!({ "tenantId": tenant_id })))
            .await);
        assert_eq!(refused.code, "ACCESS_DENIED");
        let pending = ok(api
            .list(
                &reviewer_credential,
                body(json!({ "tenantId": tenant_id, "status": "pending" })),
            )
            .await);
        assert_eq!(
            pending
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["id"].clone())
                .collect::<Vec<_>>(),
            vec![json!(request_id)]
        );
        let refused = err(api
            .list(
                &reviewer_credential,
                body(json!({ "tenantId": tenant_id, "status": "open" })),
            )
            .await);
        assert_eq!(
            (refused.code.as_str(), refused.message.as_str()),
            ("INVALID_INPUT", "Invalid status")
        );
        assert_eq!(
            ok(api
                .list(
                    &reviewer_credential,
                    body(json!({ "tenantId": tenant_id, "requesterId": reviewer })),
                )
                .await),
            json!([])
        );
        let check = || {
            let credential = alice_credential.clone();
            let tenant_id = tenant_id.clone();
            let iam = &f.iam;
            async move {
                iam.authorize(&AuthorizationRequest {
                    credential,
                    tenant_id,
                    action: "documents:write".into(),
                    resource: ResourceTarget {
                        kind: "document".into(),
                        id: "runbook".into(),
                    },
                })
                .await
                .unwrap()
                .allowed
            }
        };
        assert!(!check().await);
        // A requester cannot approve their own request even with review permission, and a reviewer needs a grant
        // authority.
        let refused = err(api
            .approve(
                &alice_credential,
                body(json!({ "tenantId": tenant_id, "requestId": request_id })),
            )
            .await);
        assert_eq!(refused.code, "ACCESS_DENIED");
        let refused = err(api
            .approve(
                &reviewer_credential,
                body(json!({ "tenantId": tenant_id, "requestId": request_id })),
            )
            .await);
        assert_eq!(refused.code, "GRANT_AUTHORITY_REQUIRED");
        // `authorities.create` as the owner.
        let reviewer_authority = better_iam_server::utils::id();
        f.insert(
            "grantAuthorities",
            json!({
                "id": reviewer_authority,
                "tenantId": tenant_id,
                "identityId": reviewer,
                "ceiling": {
                    "version": 1,
                    "statements": [{ "effect": "allow", "actions": ["documents:*"], "resources": ["*"] }],
                },
                "parentAuthorityId": f.owner_authority,
                "revoked": false,
            }),
        )
        .await;
        let approved = ok(api
            .approve(
                &reviewer_credential,
                body(json!({
                    "tenantId": tenant_id,
                    "requestId": request_id,
                    "note": "Approved for the incident",
                })),
            )
            .await);
        assert_eq!(approved["status"], json!("approved"));
        assert_eq!(approved["reviewerId"], json!(reviewer));
        assert_eq!(approved["note"], json!("Approved for the incident"));
        assert_eq!(approved["grantExpiresAt"], num(f.now() + 7_200_000.0));
        assert_eq!(approved["reviewedAt"], num(f.now()));
        assert_eq!(approved["bindingIds"].as_array().unwrap().len(), 1);
        assert!(check().await);
        let binding = f
            .find(
                "bindings",
                &[
                    ("tenantId", json!(tenant_id)),
                    ("subjectId", json!(alice)),
                    ("roleId", json!(admin)),
                ],
            )
            .await
            .remove(0);
        assert_eq!(binding["expiresAt"], num(f.now() + 7_200_000.0));
        assert_eq!(binding["accessRequestId"], json!(request_id));
        assert_eq!(binding["authorityId"], json!(reviewer_authority));
        assert_eq!(
            binding["uniqueKey"],
            json!(format!("identity:{alice}:{admin}:{reviewer_authority}"))
        );
        f.advance(7_201_000.0);
        assert!(!check().await);
        let refused = err(api
            .approve(
                &reviewer_credential,
                body(json!({ "tenantId": tenant_id, "requestId": request_id })),
            )
            .await);
        assert_eq!(
            (refused.code.as_str(), refused.message.as_str()),
            ("INVALID_TRANSITION", "Request is approved")
        );
        // Denial, cancellation, expiry, and the audit trail.
        let second = ok(api
            .create(
                &alice_credential,
                body(json!({ "tenantId": tenant_id, "roleIds": [admin] })),
            )
            .await);
        let denied = ok(api
            .deny(
                &reviewer_credential,
                body(
                    json!({ "tenantId": tenant_id, "requestId": second["id"], "note": "Not now" }),
                ),
            )
            .await);
        assert_eq!(denied["status"], json!("denied"));
        assert_eq!(denied["note"], json!("Not now"));
        f.advance(1000.0);
        let third = ok(api
            .create(
                &alice_credential,
                body(json!({ "tenantId": tenant_id, "roleIds": [admin] })),
            )
            .await);
        let refused = err(api
            .cancel(
                &reviewer_credential,
                body(json!({ "tenantId": tenant_id, "requestId": third["id"] })),
            )
            .await);
        assert_eq!(refused.code, "ACCESS_DENIED");
        let cancelled = ok(api
            .cancel(
                &alice_credential,
                body(json!({ "tenantId": tenant_id, "requestId": third["id"] })),
            )
            .await);
        assert_eq!(cancelled["status"], json!("cancelled"));
        assert_eq!(cancelled["reviewedAt"], num(f.now()));
        f.advance(1000.0);
        let fourth = ok(api
            .create(
                &alice_credential,
                body(json!({ "tenantId": tenant_id, "roleIds": [admin] })),
            )
            .await);
        f.advance(61.0 * 60_000.0);
        assert_eq!(
            ok(api
                .get(
                    &reviewer_credential,
                    body(json!({ "tenantId": tenant_id, "requestId": fourth["id"] })),
                )
                .await)["status"],
            json!("expired")
        );
        let refused = err(api
            .deny(
                &reviewer_credential,
                body(json!({ "tenantId": tenant_id, "requestId": fourth["id"] })),
            )
            .await);
        assert_eq!(
            (refused.code.as_str(), refused.message.as_str()),
            ("INVALID_TRANSITION", "Request is expired")
        );
        // Reading marks nothing: the stored request stays pending until the purge worker sweeps it.
        let stored = f
            .find("accessRequests", &[("id", fourth["id"].clone())])
            .await;
        assert_eq!(stored[0]["status"], json!("pending"));
        let statuses: Vec<Value> = ok(api
            .list_mine(&alice_credential, body(json!({ "tenantId": tenant_id })))
            .await)
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["status"].clone())
        .collect();
        assert_eq!(
            statuses,
            vec![
                json!("expired"),
                json!("cancelled"),
                json!("denied"),
                json!("approved")
            ]
        );
        let expired = ok(api
            .list_mine(
                &alice_credential,
                body(json!({ "tenantId": tenant_id, "status": "expired" })),
            )
            .await);
        // The status filter reads stored statuses: the unswept request is still stored as pending.
        assert_eq!(expired, json!([]));
        let mut trail: Vec<String> = Vec::new();
        for action in ["access-request:approve", "access-request:deny"] {
            for event in f
                .find(
                    "audit",
                    &[("tenantId", json!(tenant_id)), ("action", json!(action))],
                )
                .await
            {
                if action == "access-request:approve" {
                    assert_eq!(event["metadata"]["requesterId"], json!(alice));
                    assert_eq!(event["metadata"]["roleIds"], json!([admin]));
                    assert_eq!(event["actorId"], json!(reviewer));
                }
                trail.push(event["action"].as_str().unwrap().to_owned());
            }
        }
        assert_eq!(trail, vec!["access-request:approve", "access-request:deny"]);
        // Approval reuses an existing standing binding instead of duplicating it, and an approver override shortens
        // the grant. (The purge worker swept the expired grant first.)
        f.remove("bindings", binding["id"].as_str().unwrap()).await;
        let standing = better_iam_server::utils::id();
        f.insert(
            "bindings",
            json!({
                "id": standing,
                "tenantId": tenant_id,
                "uniqueKey": format!("identity:{alice}:{admin}:{reviewer_authority}"),
                "subjectType": "identity",
                "subjectId": alice,
                "roleId": admin,
                "authorityId": reviewer_authority,
            }),
        )
        .await;
        let fifth = ok(api
            .create(
                &alice_credential,
                body(
                    json!({ "tenantId": tenant_id, "roleIds": [admin], "durationSeconds": 86400 }),
                ),
            )
            .await);
        let shortened = ok(api
            .approve(
                &reviewer_credential,
                body(json!({ "tenantId": tenant_id, "requestId": fifth["id"], "durationSeconds": 600 })),
            )
            .await);
        assert_eq!(shortened["grantExpiresAt"], num(f.now() + 600_000.0));
        assert_eq!(shortened["bindingIds"], json!([standing]));
        let bindings = f
            .find(
                "bindings",
                &[
                    ("tenantId", json!(tenant_id)),
                    ("roleId", json!(admin)),
                    ("subjectId", json!(alice)),
                ],
            )
            .await;
        assert_eq!(
            bindings
                .iter()
                .map(|item| item["expiresAt"].clone())
                .collect::<Vec<_>>(),
            vec![num(f.now() + 600_000.0)]
        );
        assert_eq!(bindings[0]["accessRequestId"], fifth["id"]);
    });
}

#[test]
fn requests_come_from_ordinary_sessions_of_an_active_tenant_and_are_bounded() {
    run(|| async {
        let f = organization(FixtureOptions::default()).await;
        let api = &f.iam.api.access_requests;
        let tenant_id = f.tenant_id.clone();
        let (_, alice_credential) = member(&f, "alice", &["iam:access-requests:create"]).await;
        let mut roles = Vec::new();
        for index in 0..21 {
            roles.push(f.role(&format!("Role {index}"), &["documents:read"]).await);
        }
        let refused = err(api
            .create(
                &alice_credential,
                body(json!({ "tenantId": tenant_id, "roleIds": roles })),
            )
            .await);
        assert_eq!(refused.message, "Request 1-20 roles");
        let refused = err(api
            .create(
                &alice_credential,
                body(json!({ "tenantId": tenant_id, "roleIds": "all" })),
            )
            .await);
        assert_eq!(refused.message, "Invalid roleIds");
        let refused = err(api
            .create(
                &alice_credential,
                body(json!({ "tenantId": tenant_id, "roleIds": ["missing"] })),
            )
            .await);
        assert_eq!(refused.status, 404);
        let refused = err(api
            .create(
                &alice_credential,
                body(json!({ "tenantId": tenant_id, "roleIds": [roles[0]], "justification": "" })),
            )
            .await);
        assert_eq!(refused.message, "Invalid justification");
        // Twenty open requests at most.
        for role in roles.iter().take(20) {
            ok(api
                .create(
                    &alice_credential,
                    body(json!({ "tenantId": tenant_id, "roleIds": [role] })),
                )
                .await);
        }
        let refused = err(api
            .create(
                &alice_credential,
                body(json!({ "tenantId": tenant_id, "roleIds": [roles[20]] })),
            )
            .await);
        assert_eq!(
            (refused.code.as_str(), refused.status),
            ("TOO_MANY_REQUESTS", 429)
        );
        // A suspended tenant takes no requests.
        f.patch("tenants", &tenant_id, json!({ "status": "suspended" }))
            .await;
        let refused = value_of(
            api.create(
                &alice_credential,
                body(json!({ "tenantId": tenant_id, "roleIds": [roles[20]] })),
            )
            .await,
        );
        assert!(refused.is_err());
        let refused = err(api
            .get(
                &f.owner,
                body(json!({ "tenantId": tenant_id, "requestId": 5 })),
            )
            .await);
        assert_ne!(refused.status, 200);
    });
}

fn value_of<O: serde::Serialize>(
    result: Result<better_iam_server::api::Reply<O>, better_iam_core::IamError>,
) -> Result<Value, better_iam_core::IamError> {
    governance::value(result)
}
