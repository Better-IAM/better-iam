//! The `policies` API group: tests/policy-tools.test.ts (versions and document tests), the policy case of
//! tests/server-security.test.ts (creator ceilings), and the rules of api/policies.ts (optimistic concurrency, the
//! Owner policy, attachments, simulations and access reviews).

mod grants;

use better_iam_core::{Filter, IamStoreExt};
use grants::{
    bind, body, can, code, find, fixture, full, identity, insert_all, refused, run, value,
};
use serde_json::json;

#[test]
fn restores_earlier_policy_versions_and_evaluates_candidate_documents() {
    run(|| async {
        let f = fixture().await;
        let api = &f.iam.api;
        let owner = &f.credential;
        let read_only = json!({
            "version": 1,
            "statements": [{ "effect": "allow", "actions": ["documents:read"], "resources": ["*"] }],
        });
        let read_write = json!({
            "version": 1,
            "statements": [{ "effect": "allow", "actions": ["documents:read", "documents:write"], "resources": ["document/*"] }],
        });
        let policy = value(
            api.policies
                .create(
                    owner,
                    body(json!({ "tenantId": "a", "name": "Documents", "document": read_only })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(policy["version"], json!(1));
        assert_eq!(policy["authorityId"], json!("user-authority"));
        let policy_id = policy["id"].as_str().unwrap().to_owned();
        let updated = value(
            api.policies
                .update(
                    owner,
                    body(json!({ "tenantId": "a", "policyId": policy_id, "version": 1, "document": read_write })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(updated["version"], json!(2));
        assert_eq!(
            code(value(
                api.policies
                    .restore_version(
                        owner,
                        body(json!({ "tenantId": "a", "policyId": policy_id, "version": 2 }))
                    )
                    .await
            )),
            "INVALID_INPUT"
        );
        assert_eq!(
            code(value(
                api.policies
                    .restore_version(
                        owner,
                        body(json!({ "tenantId": "a", "policyId": policy_id, "version": 9 }))
                    )
                    .await
            )),
            "INVALID_INPUT"
        );
        let restored = value(
            api.policies
                .restore_version(
                    owner,
                    body(json!({ "tenantId": "a", "policyId": policy_id, "version": 1 })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(restored["version"], json!(3));
        assert_eq!(restored["document"], read_only);
        let versions = value(
            api.policies
                .list_versions(
                    owner,
                    body(json!({ "tenantId": "a", "policyId": policy_id })),
                )
                .await,
        )
        .unwrap();
        let versions = versions.as_array().unwrap();
        assert_eq!(
            versions
                .iter()
                .map(|item| item["version"].clone())
                .collect::<Vec<_>>(),
            vec![json!(1), json!(2), json!(3)]
        );
        assert_eq!(versions[1]["document"], read_write);
        // Archived versions carry the policy's ID; the listing leaves their unique keys out.
        assert_eq!(versions[0]["policyId"], json!(policy_id));
        assert!(versions[0].get("uniqueKey").is_none());
        let archived = find(
            &f.iam,
            "policyVersions",
            Filter::new().eq("policyId", policy_id.clone()),
        )
        .await;
        let mut keys: Vec<String> = archived
            .iter()
            .map(|record| record["uniqueKey"].as_str().unwrap().to_owned())
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![format!("{policy_id}:1"), format!("{policy_id}:2")]
        );

        // Candidate documents evaluate against caller-supplied context without being stored.
        let conditional = json!({
            "version": 1,
            "statements": [{
                "effect": "allow",
                "actions": ["documents:write"],
                "resources": ["document/${principal.id}-*"],
                "conditions": { "Bool": { "principal.mfa": true } },
            }],
        });
        let allowed = value(
            api.policies
                .test(
                    owner,
                    body(json!({
                        "tenantId": "a",
                        "document": conditional,
                        "action": "documents:write",
                        "resource": "document/alice-notes",
                        "context": { "principal.id": "alice", "principal.mfa": true },
                    })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(allowed["allowed"], json!(true));
        assert_eq!(allowed["matched"].as_array().unwrap().len(), 1);
        let denied = value(
            api.policies
                .test(
                    owner,
                    body(json!({
                        "tenantId": "a",
                        "document": conditional,
                        "action": "documents:write",
                        "resource": "document/alice-notes",
                        "context": { "principal.id": "alice", "principal.mfa": false },
                    })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(denied["allowed"], json!(false));
        assert_eq!(
            code(value(
                api.policies
                    .test(
                        owner,
                        body(json!({
                            "tenantId": "a",
                            "document": { "version": 1, "statements": [{ "effect": "allow", "actions": ["documents:burn"], "resources": ["*"] }] },
                            "action": "documents:burn",
                            "resource": "document/x",
                        }))
                    )
                    .await
            )),
            "INVALID_ACTION"
        );
        // The server's keys default to a synthetic session in the tenant.
        let tenant_scoped = value(
            api.policies
                .test(
                    owner,
                    body(json!({
                        "tenantId": "a",
                        "document": {
                            "version": 1,
                            "statements": [{
                                "effect": "allow",
                                "actions": ["documents:read"],
                                "resources": ["*"],
                                "conditions": { "StringEquals": { "principal.tenantId": "a", "principal.riskLevel": "none" } },
                            }],
                        },
                        "action": "documents:read",
                        "resource": "document/x",
                    })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(tenant_scoped["allowed"], json!(true));
        let crowded: serde_json::Map<String, serde_json::Value> = (0..201)
            .map(|index| (format!("app.key{index}"), json!(index)))
            .collect();
        let error = value(
            api.policies
                .test(
                    owner,
                    body(json!({
                        "tenantId": "a",
                        "document": read_only,
                        "action": "documents:read",
                        "resource": "document/x",
                        "context": crowded,
                    })),
                )
                .await,
        )
        .err()
        .unwrap();
        assert_eq!(error.message, "context may hold at most 200 keys");
        let listed = value(
            api.policies
                .list(owner, body(json!({ "tenantId": "a" })))
                .await,
        )
        .unwrap();
        assert_eq!(
            listed
                .as_array()
                .unwrap()
                .iter()
                .filter(|item| item["name"] == json!("Documents"))
                .count(),
            1
        );
    });
}

#[test]
fn retains_policy_creator_ceilings_when_a_higher_authority_later_attaches_the_policy() {
    run(|| async {
        let f = fixture().await;
        let api = &f.iam.api;
        let mut authority = grants::get(&f.iam, "grantAuthorities", "user-authority")
            .await
            .unwrap();
        authority.insert(
            "ceiling".into(),
            json!({ "version": 1, "statements": [{ "effect": "allow", "actions": ["iam:*", "documents:read"], "resources": ["*"] }] }),
        );
        f.iam
            .store
            .transaction(|tx| async move { tx.put("grantAuthorities", &authority).await })
            .await
            .unwrap();
        let policy = value(
            api.policies
                .create(
                    &f.credential,
                    body(
                        json!({ "tenantId": "a", "name": "Delegated policy", "document": full() }),
                    ),
                )
                .await,
        )
        .unwrap();
        let role = value(
            api.roles
                .create(
                    &f.root,
                    body(json!({ "tenantId": "a", "name": "Root attachment", "policyIds": [policy["id"]] })),
                )
                .await,
        )
        .unwrap();
        bind(
            &f.iam,
            role["id"].as_str().unwrap(),
            &f.other.id,
            role["authorityId"].as_str().unwrap(),
        )
        .await;
        let login = grants::session(&f.iam, &f.other, false).await;
        assert!(can(&f.iam, &login, "documents:read", "a-doc").await);
        assert!(!can(&f.iam, &login, "documents:write", "a-doc").await);
        value(
            api.policies
                .update(
                    &f.credential,
                    body(json!({ "tenantId": "a", "policyId": policy["id"], "version": 1, "document": full() })),
                )
                .await,
        )
        .unwrap();
        assert!(!can(&f.iam, &login, "documents:write", "a-doc").await);
        value(
            api.authorities
                .revoke(
                    &f.root,
                    body(json!({ "tenantId": "a", "authorityId": "user-authority" })),
                )
                .await,
        )
        .unwrap();
        assert!(!can(&f.iam, &login, "documents:read", "a-doc").await);
    });
}

#[test]
fn guards_versions_the_owner_policy_and_attached_policies() {
    run(|| async {
        let f = fixture().await;
        let api = &f.iam.api;
        let user = &f.credential;
        let read = json!({ "version": 1, "statements": [{ "effect": "allow", "actions": ["documents:read"], "resources": ["*"] }] });
        let policy = value(
            api.policies
                .create(
                    user,
                    body(json!({ "tenantId": "a", "name": "Readers", "description": "Read access", "document": read })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(policy["description"], json!("Read access"));
        let policy_id = policy["id"].clone();
        assert_eq!(
            refused(value(
                api.policies
                    .update(
                        user,
                        body(json!({ "tenantId": "a", "policyId": policy_id, "version": 7, "name": "Stale" }))
                    )
                    .await
            )),
            ("VERSION_CONFLICT".to_owned(), 409)
        );
        let error = value(
            api.policies
                .update(
                    user,
                    body(json!({ "tenantId": "a", "policyId": policy_id, "version": 1 })),
                )
                .await,
        )
        .err()
        .unwrap();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            ("INVALID_INPUT", "Nothing to update")
        );
        let renamed = value(
            api.policies
                .update(
                    user,
                    body(json!({ "tenantId": "a", "policyId": policy_id, "version": 1, "name": "Renamed" })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(renamed["name"], json!("Renamed"));
        assert_eq!(renamed["document"], read);
        assert_eq!(renamed["version"], json!(2));
        assert_eq!(
            code(value(
                api.policies
                    .create(user, body(json!({ "tenantId": "a", "name": "Broken" })))
                    .await
            )),
            "INVALID_POLICY"
        );
        // A role that attaches the policy keeps it.
        value(
            api.roles
                .create(
                    user,
                    body(json!({ "tenantId": "a", "name": "Holder", "policyIds": [policy_id] })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(
            refused(value(
                api.policies
                    .delete(
                        user,
                        body(json!({ "tenantId": "a", "policyId": policy_id }))
                    )
                    .await
            )),
            ("RESOURCE_IN_USE".to_owned(), 409)
        );
        // The Owner policy is protected, even from root.
        insert_all(
            &f.iam,
            vec![(
                "policies",
                json!({ "id": "owner-policy", "tenantId": "a", "name": "Owner", "uniqueKey": "system:owner", "document": full(), "version": 1 }),
            )],
        )
        .await;
        for result in [
            value(
                api.policies
                    .update(
                        &f.root,
                        body(json!({ "tenantId": "a", "policyId": "owner-policy", "version": 1, "name": "Mine" })),
                    )
                    .await,
            ),
            value(
                api.policies
                    .delete(&f.root, body(json!({ "tenantId": "a", "policyId": "owner-policy" })))
                    .await,
            ),
            value(
                api.policies
                    .restore_version(
                        &f.root,
                        body(json!({ "tenantId": "a", "policyId": "owner-policy", "version": 1 })),
                    )
                    .await,
            ),
        ] {
            let error = result.err().unwrap();
            assert_eq!(
                (error.code.as_str(), error.message.as_str()),
                ("PROTECTED_RESOURCE", "Owner policy is protected")
            );
        }
        // An unattached policy is deleted; reads answer the stored record.
        let spare = value(
            api.policies
                .create(
                    user,
                    body(json!({ "tenantId": "a", "name": "Spare", "document": read })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(
            value(
                api.policies
                    .get(
                        user,
                        body(json!({ "tenantId": "a", "policyId": spare["id"] }))
                    )
                    .await
            )
            .unwrap(),
            spare
        );
        assert_eq!(
            value(
                api.policies
                    .delete(
                        user,
                        body(json!({ "tenantId": "a", "policyId": spare["id"] }))
                    )
                    .await
            )
            .unwrap(),
            json!({ "deleted": true })
        );
        assert_eq!(
            code(value(
                api.policies
                    .get(
                        user,
                        body(json!({ "tenantId": "a", "policyId": spare["id"] }))
                    )
                    .await
            )),
            "NOT_FOUND"
        );
    });
}

#[test]
fn simulates_decisions_and_reviews_who_can_act() {
    run(|| async {
        let f = fixture().await;
        let api = &f.iam.api;
        let user = &f.credential;
        let reader = value(
            api.roles
                .create(user, body(json!({ "tenantId": "a", "name": "Reader", "permissions": ["documents:read"] })))
                .await,
        )
        .unwrap();
        let alice = identity(&f.iam, "a", "alice@example.com", "Alice").await;
        bind(
            &f.iam,
            reader["id"].as_str().unwrap(),
            &alice.id,
            "user-authority",
        )
        .await;
        let simulated = value(
            api.policies
                .simulate(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "identityId": alice.id,
                        "action": "documents:read",
                        "resource": { "type": "document", "id": "a-doc" },
                    })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(simulated["allowed"], json!(true));
        let refused_write = value(
            api.policies
                .simulate(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "identityId": alice.id,
                        "action": "documents:write",
                        "resource": { "type": "document", "id": "a-doc" },
                    })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(refused_write["allowed"], json!(false));
        let unknown = value(
            api.policies
                .simulate(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "identityId": alice.id,
                        "action": "documents:burn",
                        "resource": { "type": "document", "id": "a-doc" },
                    })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(unknown["reason"], json!("UNKNOWN_ACTION"));
        assert_eq!(
            code(value(
                api.policies
                    .simulate(
                        user,
                        body(json!({ "tenantId": "a", "identityId": alice.id, "action": 5, "resource": { "type": "document", "id": "x" } })),
                    )
                    .await
            )),
            "INVALID_INPUT"
        );

        let review = value(
            api.policies
                .who_can(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "action": "documents:read",
                        "resource": { "type": "document", "id": "a-doc" },
                    })),
                )
                .await,
        )
        .unwrap();
        let mut found: Vec<String> = review["identities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["identityId"].as_str().unwrap().to_owned())
            .collect();
        found.sort();
        let mut expected = vec![alice.id.clone(), f.user.id.clone()];
        expected.sort();
        assert_eq!(found, expected);
        assert_eq!(review["total"], json!(2));
        let first = &review["identities"][0];
        assert!(first["reason"].is_string() && first["kind"] == json!("user"));
        let paged = value(
            api.policies
                .who_can(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "action": "documents:read",
                        "resource": { "type": "document", "id": "a-doc" },
                        "limit": 1,
                        "offset": 1,
                    })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(paged["identities"].as_array().unwrap().len(), 1);
        assert_eq!(paged["total"], json!(2));
        let services = value(
            api.policies
                .who_can(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "action": "documents:read",
                        "resource": { "type": "document", "id": "a-doc" },
                        "kind": "service",
                    })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(services, json!({ "identities": [], "total": 0 }));
        let error = value(
            api.policies
                .who_can(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "action": "documents:read",
                        "resource": { "type": "document", "id": "a-doc" },
                        "kind": "robot",
                    })),
                )
                .await,
        )
        .err()
        .unwrap();
        assert_eq!(error.message, "kind must be user or service");
        let error = value(
            api.policies
                .who_can(
                    user,
                    body(json!({ "tenantId": "a", "action": "documents:burn", "resource": { "type": "document", "id": "x" } })),
                )
                .await,
        )
        .err()
        .unwrap();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            ("INVALID_ACTION", "Unknown action documents:burn")
        );

        // Every catalog action, sorted, when no actions are given.
        let actions = value(
            api.policies
                .effective_actions(
                    user,
                    body(json!({ "tenantId": "a", "identityId": alice.id, "resource": { "type": "document", "id": "a-doc" } })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(actions["allowed"], json!(["documents:read"]));
        let results = actions["results"].as_array().unwrap();
        let names: Vec<String> = results
            .iter()
            .map(|item| item["action"].as_str().unwrap().to_owned())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        assert!(names.contains(&"documents:write".to_owned()) && names.len() > 2);
        assert_eq!(
            code(value(
                api.policies
                    .effective_actions(
                        user,
                        body(json!({
                            "tenantId": "a",
                            "identityId": alice.id,
                            "resource": { "type": "document", "id": "a-doc" },
                            "actions": ["documents:burn"],
                        })),
                    )
                    .await
            )),
            "INVALID_ACTION"
        );
    });
}
