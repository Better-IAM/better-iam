//! Feature flags: ported from tests/feature-flags.test.ts. Tenants, members and grants come from the organization
//! fixture (written as `tenants.create`, `identities.create`, `roles.create` and `bindings.create` write them).

mod organization_fixture;

use better_iam_core::{CredentialInput, Filter};
use better_iam_server::features::rollout_bucket;
use better_iam_server::options::{AuthorizationRequest, ResourceTarget};
use organization_fixture::{Org, assert_matches, body, code, fails, ok, organization, run};
use serde_json::{Value, json};

/// A project under Acme whose owner is active.
async fn project(f: &Org, name: &str) -> (String, CredentialInput) {
    let (tenant_id, _, credential) = f
        .activate(
            &f.tenant_id,
            name,
            "project",
            &format!("{}@acme.test", name.to_lowercase()),
        )
        .await;
    (tenant_id, credential)
}

async fn evaluate_one(f: &Org, tenant_id: &str, key: &str) -> Value {
    let evaluations = f
        .iam
        .features
        .evaluate(tenant_id, Some(&json!({ "keys": [key] })))
        .await
        .unwrap();
    evaluations[0].to_json()
}

async fn is_enabled(f: &Org, tenant_id: &str, key: &str) -> bool {
    f.iam.features.is_enabled(tenant_id, key).await.unwrap()
}

#[test]
fn platform_flags_resolve_defaults_overrides_targets_locks_and_the_kill_switch() {
    run(|| async {
        let f = organization(|_| {}).await;
        let features = &f.iam.api.features;
        let root_id = f.root_tenant.clone();
        let flag = ok(features
            .create(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id,
                    "key": "new-billing",
                    "description": "The new billing pages",
                    "tenantOverridable": true,
                })),
            )
            .await);
        assert_matches(
            &flag,
            json!({
                "key": "new-billing",
                "scope": "platform",
                "defaultValue": false,
                "tenantOverridable": true,
                "killSwitch": false,
                "internal": false,
            }),
        );
        assert!(!is_enabled(&f, &f.tenant_id, "new-billing").await);
        assert_matches(
            &evaluate_one(&f, &f.tenant_id, "new-billing").await,
            json!({ "reason": "DEFAULT", "overridable": true, "locked": false }),
        );

        // The organization turns it on for itself.
        let chosen = ok(features
            .set_override(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "key": "new-billing", "value": true })),
            )
            .await);
        assert_matches(
            &chosen,
            json!({ "value": true, "reason": "OVERRIDE", "decidedBy": f.tenant_id }),
        );
        assert_eq!(
            ok(features
                .evaluate(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id }))
                )
                .await),
            json!({ "tenantId": f.tenant_id, "flags": { "new-billing": true } })
        );

        // An unlocked platform target on the same tenant does not beat the tenant's own choice...
        ok(features
            .set_target(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id, "key": "new-billing", "targetTenantId": f.tenant_id, "value": false,
                })),
            )
            .await);
        assert!(is_enabled(&f, &f.tenant_id, "new-billing").await);
        // ...a locked one does, and refuses new overrides until it is lifted.
        ok(features
            .set_target(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id, "key": "new-billing", "targetTenantId": f.tenant_id, "value": false,
                    "locked": true, "note": "Invoice migration pending",
                })),
            )
            .await);
        assert_matches(
            &evaluate_one(&f, &f.tenant_id, "new-billing").await,
            json!({ "value": false, "reason": "TARGET", "locked": true, "overridable": false }),
        );
        let refused = fails(
            features
                .set_override(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "key": "new-billing", "value": true })),
                )
                .await,
        );
        assert_eq!(code(&refused), "FEATURE_LOCKED");
        let listed = ok(features
            .list(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id })),
            )
            .await);
        let flags = listed["flags"].as_array().unwrap();
        assert_eq!(flags.len(), 1);
        assert_matches(
            &flags[0],
            json!({
                "key": "new-billing",
                "scope": "platform",
                "definedBy": root_id,
                "override": { "value": true },
                "target": { "value": false, "locked": true },
            }),
        );
        // Tenants see neither the platform's settings nor its note.
        assert!(flags[0].get("definition").is_none());
        assert!(!listed.to_string().contains("Invoice migration"));

        ok(features
            .set_target(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id, "key": "new-billing", "targetTenantId": f.tenant_id, "value": null,
                })),
            )
            .await);
        assert!(is_enabled(&f, &f.tenant_id, "new-billing").await);

        // The kill switch wins over everything, and lifting it restores the previous state.
        ok(features
            .update(
                &f.root_credential,
                body(json!({ "tenantId": root_id, "key": "new-billing", "killSwitch": true })),
            )
            .await);
        assert_matches(
            &evaluate_one(&f, &f.tenant_id, "new-billing").await,
            json!({ "value": false, "reason": "KILL_SWITCH" }),
        );
        ok(features
            .update(
                &f.root_credential,
                body(json!({ "tenantId": root_id, "key": "new-billing", "killSwitch": false })),
            )
            .await);
        assert!(is_enabled(&f, &f.tenant_id, "new-billing").await);

        // Flags that do not allow overrides refuse them; withdrawing a choice is always allowed.
        ok(features
            .update(
                &f.root_credential,
                body(json!({ "tenantId": root_id, "key": "new-billing", "tenantOverridable": false })),
            )
            .await);
        assert!(!is_enabled(&f, &f.tenant_id, "new-billing").await);
        let refused = fails(
            features
                .set_override(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "key": "new-billing", "value": true })),
                )
                .await,
        );
        assert_eq!(code(&refused), "FEATURE_LOCKED");
        ok(features
            .set_override(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "key": "new-billing", "value": null })),
            )
            .await);

        // Unknown keys are off.
        assert!(!is_enabled(&f, &f.tenant_id, "nothing-here").await);
        assert_eq!(
            ok(features
                .evaluate(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "keys": ["nothing-here"] })),
                )
                .await),
            json!({ "tenantId": f.tenant_id, "flags": { "nothing-here": false } })
        );
    });
}

#[test]
fn validates_keys_and_settings() {
    run(|| async {
        let f = organization(|_| {}).await;
        let features = &f.iam.api.features;
        let root_id = f.root_tenant.clone();
        for key in [
            "Bad".to_owned(),
            "1st".to_owned(),
            "a--b".to_owned(),
            "trailing-".to_owned(),
            "x".repeat(65),
            "__proto__".to_owned(),
        ] {
            let error = fails(
                features
                    .create(
                        &f.root_credential,
                        body(json!({ "tenantId": root_id, "key": key })),
                    )
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT", "{key}");
        }
        for input in [
            json!({ "tenantId": root_id, "key": "on-with-rollout", "defaultValue": true, "rolloutPercentage": 10 }),
            json!({ "tenantId": root_id, "key": "hidden", "internal": true, "tenantOverridable": true }),
            json!({ "tenantId": root_id, "key": "extra", "colour": "blue" }),
        ] {
            let error = fails(features.create(&f.root_credential, body(input)).await);
            assert_eq!(code(&error), "INVALID_INPUT");
        }
        let error = fails(
            features
                .create(
                    &f.root_credential,
                    body(json!({ "tenantId": root_id, "key": "extra", "colour": "blue" })),
                )
                .await,
        );
        assert_eq!(error.message, "Unknown flag field colour");
        ok(features
            .create(
                &f.root_credential,
                body(json!({ "tenantId": root_id, "key": "reports.v2" })),
            )
            .await);
        let error = fails(
            features
                .create(
                    &f.root_credential,
                    body(json!({ "tenantId": root_id, "key": "reports.v2" })),
                )
                .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        let error = fails(
            features
                .update(
                    &f.root_credential,
                    body(json!({ "tenantId": root_id, "key": "missing" })),
                )
                .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
        // A target must sit below the defining tenant.
        let error = fails(
            features
                .set_target(
                    &f.root_credential,
                    body(json!({
                        "tenantId": root_id, "key": "reports.v2", "targetTenantId": root_id, "value": true,
                    })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
    });
}

#[test]
fn tenant_flags_reach_the_subtree_and_ancestors_own_their_keys() {
    run(|| async {
        let f = organization(|_| {}).await;
        let features = &f.iam.api.features;
        let root_id = f.root_tenant.clone();
        let (apollo, apollo_credential) = project(&f, "Apollo").await;
        let flag = ok(features
            .create(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "key": "beta-reports", "tenantOverridable": true })),
            )
            .await);
        assert_matches(&flag, json!({ "scope": "tenant", "tenantId": f.tenant_id }));
        ok(features
            .set_target(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id, "key": "beta-reports", "targetTenantId": apollo, "value": true,
                })),
            )
            .await);
        assert!(is_enabled(&f, &apollo, "beta-reports").await);
        assert!(!is_enabled(&f, &f.tenant_id, "beta-reports").await);
        // The flag never reaches the platform tenant.
        assert!(!is_enabled(&f, &root_id, "beta-reports").await);
        // An organization cannot target outside its subtree or itself.
        for target in [root_id.clone(), f.tenant_id.clone()] {
            let error = fails(
                features
                    .set_target(
                        &f.owner_credential,
                        body(json!({
                            "tenantId": f.tenant_id, "key": "beta-reports", "targetTenantId": target, "value": true,
                        })),
                    )
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT");
        }

        // The project sees the organization's flag and its target, and may override it.
        let listed = ok(features
            .list(&apollo_credential, body(json!({ "tenantId": apollo })))
            .await);
        assert_matches(
            &listed["flags"][0],
            json!({
                "key": "beta-reports",
                "scope": "tenant",
                "definedBy": f.tenant_id,
                "target": { "value": true, "locked": false },
                "evaluation": { "value": true, "reason": "TARGET", "decidedBy": apollo },
            }),
        );
        let opted = ok(features
            .set_override(
                &apollo_credential,
                body(json!({ "tenantId": apollo, "key": "beta-reports", "value": false })),
            )
            .await);
        assert_matches(&opted, json!({ "value": false, "reason": "OVERRIDE" }));
        // The defining tenant changes its own flag through update, not an override.
        let error = fails(
            features
                .set_override(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "key": "beta-reports", "value": true })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let targets = ok(features
            .list_targets(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "key": "beta-reports" })),
            )
            .await);
        let summary: Vec<Value> = targets
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                json!([
                    entry["source"],
                    entry["tenantName"],
                    entry["value"],
                    entry["active"]
                ])
            })
            .collect();
        assert!(summary.contains(&json!(["target", "Apollo", true, true])));
        assert!(summary.contains(&json!(["override", "Apollo", false, true])));

        // Keys an ancestor defines cannot be defined again below it...
        ok(features
            .create(
                &f.root_credential,
                body(json!({ "tenantId": root_id, "key": "sso" })),
            )
            .await);
        let error = fails(
            features
                .create(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "key": "sso" })),
                )
                .await,
        );
        assert_eq!(
            (code(&error), error.message.as_str()),
            ("CONFLICT", "A platform flag already uses this key")
        );
        let error = fails(
            features
                .create(
                    &apollo_credential,
                    body(json!({ "tenantId": apollo, "key": "beta-reports" })),
                )
                .await,
        );
        assert_eq!(
            (code(&error), error.message.as_str()),
            (
                "CONFLICT",
                "An enclosing tenant already defines a flag with this key"
            )
        );
        // ...and a platform flag created later shadows a tenant's flag of the same key: tenants cannot switch a
        // platform-gated feature on for themselves.
        ok(features
            .create(
                &f.owner_credential,
                body(
                    json!({ "tenantId": f.tenant_id, "key": "audit-export", "defaultValue": true }),
                ),
            )
            .await);
        assert!(is_enabled(&f, &f.tenant_id, "audit-export").await);
        ok(features
            .create(
                &f.root_credential,
                body(json!({ "tenantId": root_id, "key": "audit-export" })),
            )
            .await);
        assert!(!is_enabled(&f, &f.tenant_id, "audit-export").await);
        let shadowed = ok(features
            .list(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id })),
            )
            .await);
        let keys: Vec<&Value> = shadowed["shadowed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| &entry["key"])
            .collect();
        assert_eq!(keys, vec![&json!("audit-export")]);
        let entry = shadowed["flags"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["key"] == "audit-export")
            .unwrap();
        assert_matches(entry, json!({ "scope": "platform", "definedBy": root_id }));
    });
}

#[test]
fn an_organization_overrides_a_platform_flag_for_its_projects() {
    run(|| async {
        let f = organization(|_| {}).await;
        let features = &f.iam.api.features;
        let root_id = f.root_tenant.clone();
        let (apollo, apollo_credential) = project(&f, "Apollo").await;
        ok(features
            .create(
                &f.root_credential,
                body(
                    json!({ "tenantId": root_id, "key": "new-editor", "tenantOverridable": true }),
                ),
            )
            .await);
        ok(features
            .set_override(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "key": "new-editor", "value": true })),
            )
            .await);
        assert_matches(
            &evaluate_one(&f, &apollo, "new-editor").await,
            json!({ "value": true, "reason": "OVERRIDE", "decidedBy": f.tenant_id }),
        );
        // A platform target on the project is closer than the organization's choice.
        ok(features
            .set_target(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id, "key": "new-editor", "targetTenantId": apollo, "value": false,
                })),
            )
            .await);
        assert!(!is_enabled(&f, &apollo, "new-editor").await);
        // A lock on the organization silences overrides in its whole subtree but not the platform's own closer
        // target.
        ok(features
            .set_target(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id, "key": "new-editor", "targetTenantId": f.tenant_id, "value": true,
                    "locked": true,
                })),
            )
            .await);
        let error = fails(
            features
                .set_override(
                    &apollo_credential,
                    body(json!({ "tenantId": apollo, "key": "new-editor", "value": true })),
                )
                .await,
        );
        assert_eq!(code(&error), "FEATURE_LOCKED");
        assert!(!is_enabled(&f, &apollo, "new-editor").await);
        ok(features
            .set_target(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id, "key": "new-editor", "targetTenantId": apollo, "value": null,
                })),
            )
            .await);
        assert_matches(
            &evaluate_one(&f, &apollo, "new-editor").await,
            json!({ "value": true, "reason": "TARGET", "decidedBy": f.tenant_id, "locked": true }),
        );
    });
}

#[test]
fn rollouts_bucket_whole_organizations_stably() {
    run(|| async {
        let f = organization(|_| {}).await;
        let features = &f.iam.api.features;
        let root_id = f.root_tenant.clone();
        let (apollo, _) = project(&f, "Apollo").await;
        ok(features
            .create(
                &f.root_credential,
                body(json!({ "tenantId": root_id, "key": "fast-search", "rolloutPercentage": 0 })),
            )
            .await);
        let bucket = rollout_bucket("fast-search", &f.tenant_id);
        assert!((0.0..100.0).contains(&bucket));
        assert_eq!(rollout_bucket("fast-search", &f.tenant_id), bucket);
        let mut previous = false;
        for percentage in [0, 10, 25, 50, 75, 100] {
            ok(features
                .update(
                    &f.root_credential,
                    body(json!({ "tenantId": root_id, "key": "fast-search", "rolloutPercentage": percentage })),
                )
                .await);
            let organization = evaluate_one(&f, &f.tenant_id, "fast-search").await;
            let child = evaluate_one(&f, &apollo, "fast-search").await;
            assert_matches(
                &organization,
                json!({ "reason": "ROLLOUT", "value": bucket < percentage as f64 }),
            );
            // A project lands on the same side as its organization.
            assert_eq!(child["value"], organization["value"]);
            if previous {
                assert_eq!(organization["value"], json!(true));
            }
            previous = organization["value"] == json!(true);
        }
        assert!(previous);
        // Clearing the rollout falls back to the default.
        ok(features
            .update(
                &f.root_credential,
                body(
                    json!({ "tenantId": root_id, "key": "fast-search", "rolloutPercentage": null }),
                ),
            )
            .await);
        assert_matches(
            &evaluate_one(&f, &f.tenant_id, "fast-search").await,
            json!({ "value": false, "reason": "DEFAULT" }),
        );
        // The stored flag lost the member, as TypeScript's `delete` leaves it.
        let stored = f
            .find("featureFlags", Filter::new().eq("uniqueKey", "fast-search"))
            .await;
        assert!(stored[0].get("rolloutPercentage").is_none());
    });
}

#[test]
fn policies_see_the_flags_that_are_on_as_tenant_features() {
    run(|| async {
        let f = organization(|options| {
            // An application claiming the flag must not satisfy the condition.
            options.resolve_context = Some(std::sync::Arc::new(|_| {
                Box::pin(async {
                    let mut context = serde_json::Map::new();
                    context.insert("tenant.features".into(), json!(["exports"]));
                    Ok(context)
                })
            }));
        })
        .await;
        let features = &f.iam.api.features;
        let root_id = f.root_tenant.clone();
        let alice = f.member("alice").await;
        f.grant(
            &alice,
            json!([{
                "effect": "allow",
                "actions": ["documents:read"],
                "resources": ["*"],
                "conditions": { "ArrayContains": { "tenant.features": "exports" } },
            }]),
        )
        .await;
        let alice_credential = f.sign_in(&alice).await;
        let can_read = || async {
            f.iam
                .authorize(&AuthorizationRequest {
                    credential: alice_credential.clone(),
                    tenant_id: f.tenant_id.clone(),
                    action: "documents:read".into(),
                    resource: ResourceTarget {
                        kind: "document".into(),
                        id: "d1".into(),
                    },
                })
                .await
                .unwrap()
                .allowed
        };
        assert!(!can_read().await);
        ok(features
            .create(
                &f.root_credential,
                body(json!({ "tenantId": root_id, "key": "exports" })),
            )
            .await);
        assert!(!can_read().await);
        ok(features
            .set_target(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id, "key": "exports", "targetTenantId": f.tenant_id, "value": true,
                })),
            )
            .await);
        assert!(can_read().await);
        ok(features
            .update(
                &f.root_credential,
                body(json!({ "tenantId": root_id, "key": "exports", "killSwitch": true })),
            )
            .await);
        assert!(!can_read().await);
    });
}

#[test]
fn members_evaluate_their_tenant_and_internal_flags_stay_hidden() {
    run(|| async {
        let f = organization(|_| {}).await;
        let features = &f.iam.api.features;
        let root_id = f.root_tenant.clone();
        let alice_id = f.member("alice").await;
        let alice = f.sign_in(&alice_id).await;
        ok(features
            .create(
                &f.root_credential,
                body(json!({ "tenantId": root_id, "key": "public-beta", "defaultValue": true })),
            )
            .await);
        ok(features
            .create(
                &f.root_credential,
                body(json!({ "tenantId": root_id, "key": "ops-hold", "internal": true, "defaultValue": true })),
            )
            .await);
        assert_eq!(
            ok(features
                .evaluate(&alice, body(json!({ "tenantId": f.tenant_id })))
                .await),
            json!({ "tenantId": f.tenant_id, "flags": { "public-beta": true } })
        );
        assert_eq!(
            ok(features
                .evaluate(
                    &alice,
                    body(json!({ "tenantId": f.tenant_id, "keys": ["ops-hold"] })),
                )
                .await),
            json!({ "tenantId": f.tenant_id, "flags": { "ops-hold": false } })
        );
        // Trusted server code sees internal flags.
        let values = f.iam.features.values(&f.tenant_id).await.unwrap();
        assert_eq!(
            values.into_iter().collect::<Vec<_>>(),
            vec![
                ("ops-hold".to_owned(), true),
                ("public-beta".to_owned(), true)
            ]
        );
        let error = fails(
            features
                .evaluate(&alice, body(json!({ "tenantId": root_id })))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            features
                .list(&alice, body(json!({ "tenantId": f.tenant_id })))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            features
                .create(
                    &alice,
                    body(json!({ "tenantId": f.tenant_id, "key": "mine" })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // Owners do not see the platform's internal flags; root administrators do.
        let owner_view = ok(features
            .list(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id })),
            )
            .await);
        let keys: Vec<&Value> = owner_view["flags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|flag| &flag["key"])
            .collect();
        assert_eq!(keys, vec![&json!("public-beta")]);
        let root_view = ok(features
            .list(&f.root_credential, body(json!({ "tenantId": f.tenant_id })))
            .await);
        let pairs: Vec<Value> = root_view["flags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|flag| json!([flag["key"], flag["definition"]["internal"]]))
            .collect();
        assert_eq!(
            pairs,
            vec![json!(["ops-hold", true]), json!(["public-beta", false])]
        );
        let error = fails(
            features
                .set_override(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "key": "ops-hold", "value": false })),
                )
                .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");

        // Over HTTP with a bearer token.
        let token = alice.token.clone().unwrap();
        let (status, response) = f
            .post(
                "features/evaluate",
                &token,
                json!({ "tenantId": f.tenant_id }),
            )
            .await;
        assert_eq!(status, 200, "{response}");
        assert_eq!(
            response["data"],
            json!({ "tenantId": f.tenant_id, "flags": { "public-beta": true } })
        );
        // The conformance server's `call` answers the same evaluator.
        let called = f
            .iam
            .features
            .call("values", vec![json!(f.tenant_id)])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(called, json!({ "ops-hold": true, "public-beta": true }));
    });
}

#[test]
fn targets_lapse_deletes_clean_up_and_changes_are_audited() {
    run(|| async {
        let f = organization(|_| {}).await;
        let features = &f.iam.api.features;
        let root_id = f.root_tenant.clone();
        ok(features
            .create(
                &f.root_credential,
                body(json!({ "tenantId": root_id, "key": "trial-seats" })),
            )
            .await);
        let expires_at = f.now() + 3_600_000.0;
        ok(features
            .set_target(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id, "key": "trial-seats", "targetTenantId": f.tenant_id, "value": true,
                    "expiresAt": expires_at,
                })),
            )
            .await);
        assert_matches(
            &evaluate_one(&f, &f.tenant_id, "trial-seats").await,
            json!({ "value": true, "reason": "TARGET", "expiresAt": expires_at }),
        );
        let error = fails(
            features
                .set_target(
                    &f.root_credential,
                    body(json!({
                        "tenantId": root_id, "key": "trial-seats", "targetTenantId": f.tenant_id, "value": true,
                        "expiresAt": f.now() - 1.0,
                    })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        f.advance(2.0 * 3_600_000.0);
        assert!(!is_enabled(&f, &f.tenant_id, "trial-seats").await);
        let root_credential = f.session(&f.root_id, true).await;
        let lapsed = ok(features
            .list_targets(
                &root_credential,
                body(json!({ "tenantId": root_id, "key": "trial-seats" })),
            )
            .await);
        assert_matches(&lapsed[0], json!({ "tenantName": "Acme", "active": false }));

        let removed = ok(features
            .delete(
                &root_credential,
                body(json!({ "tenantId": root_id, "key": "trial-seats" })),
            )
            .await);
        assert_eq!(removed, json!({ "success": true, "removedTargets": 1 }));
        assert_matches(
            &evaluate_one(&f, &f.tenant_id, "trial-seats").await,
            json!({ "value": false, "reason": "UNKNOWN" }),
        );
        let trail = ok(f
            .iam
            .api
            .audit
            .list(
                &root_credential,
                body(json!({ "tenantId": root_id, "action": "feature:*" })),
            )
            .await);
        let events = trail.as_array().unwrap();
        let mut actions: Vec<&str> = events
            .iter()
            .map(|event| event["action"].as_str().unwrap())
            .collect();
        actions.sort();
        assert_eq!(
            actions,
            vec!["feature:create", "feature:delete", "feature:target"]
        );
        let target = events
            .iter()
            .find(|event| event["action"] == "feature:target")
            .unwrap();
        assert_matches(
            &target["metadata"],
            json!({ "key": "trial-seats", "targetTenantId": f.tenant_id, "value": true }),
        );
    });
}
