//! Tests of `api/package-automation.ts`, the reconciler of automatic (birthright) access packages.
//!
//! The TypeScript suites drive it through the packages API (tests/security-packages.test.ts, tests/org-birthright.test.ts).
//! The first group of cases calls the reconciler, the rule view, and `afterIdentityChange` directly on records written
//! the way `packages.create` stores them, covering the paths that do not create or remove assignments: suspensions
//! (an invalid rule, an inactive owner), issues recorded once per transition and forgotten when their package is gone,
//! skipped tenants, and the administrator's view of a rule. The ported TypeScript scenarios that grant and revoke
//! through the packages API wait for that unit (`api/packages.ts`: allow, assignPackage, authorizePackage,
//! refreshAssignment, retimeAssignment, revokeAssignment, ruleEnvironment, and the packages routes).

mod organization_fixture;

use std::collections::HashMap;

use better_iam_core::{AttributeType, CredentialInput, Filter, PermissionsConfig, Record};
use better_iam_server::api::package_automation::{
    after_identity_change, auto_assign_view, reconcile_package_rules,
};
use better_iam_server::models::AccessPackage;
use better_iam_server::options::{AuthorizationRequest, ResourceTarget};
use better_iam_server::package_rules::RuleEnvironment;
use indexmap::{IndexMap, IndexSet};
use organization_fixture::{Org, body, ok, organization, run};
use serde_json::{Map, Value, json};

const DAY: f64 = 86_400_000.0;

fn people() -> Value {
    json!({ "StringEquals": { "principal.kind": "user" } })
}

/// `toMatchObject` with arrays compared element by element (same length).
fn matches_list(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::Array(actual), Value::Array(expected)) => {
            actual.len() == expected.len()
                && actual
                    .iter()
                    .zip(expected)
                    .all(|(actual, expected)| matches_list(actual, expected))
        }
        (Value::Object(actual), Value::Object(expected)) => expected.iter().all(|(key, value)| {
            actual
                .get(key)
                .is_some_and(|member| matches_list(member, value))
        }),
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
        (actual, expected) => actual == expected,
    }
}

#[track_caller]
fn assert_list(actual: &Value, expected: Value) {
    assert!(
        matches_list(actual, &expected),
        "\n  actual:   {actual}\n  expected: {expected}"
    );
}

/// The organization's grant authority (the one its owner holds).
async fn owner_authority(f: &Org) -> String {
    f.find(
        "grantAuthorities",
        Filter::new().eq("tenantId", f.tenant_id.clone()),
    )
    .await
    .into_iter()
    .next()
    .expect("authority")["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// An access package with a rule, as `packages.create` stores it (owner and authority of the caller, revision 1).
async fn rule_package(f: &Org, name: &str, owner_id: &str, rule: Value) -> AccessPackage {
    let authority = owner_authority(f).await;
    let mut auto_assign = rule.as_object().unwrap().clone();
    auto_assign.insert("ownerId".into(), json!(owner_id));
    auto_assign.insert("authorityId".into(), json!(authority));
    auto_assign.insert("revision".into(), json!(1));
    auto_assign.insert("updatedAt".into(), json!(f.now()));
    let record = f
        .insert(
            "accessPackages",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": f.tenant_id,
                "name": name,
                "roleIds": [],
                "groupIds": [],
                "autoAssign": auto_assign,
                "createdAt": f.now(),
                "updatedAt": f.now(),
            }),
        )
        .await;
    better_iam_server::port::decode(record).unwrap()
}

async fn audit_events(f: &Org, action: &str) -> Vec<Record> {
    f.find(
        "audit",
        Filter::new()
            .eq("tenantId", f.tenant_id.clone())
            .eq("action", action),
    )
    .await
}

async fn issues(f: &Org) -> Vec<Record> {
    f.find(
        "packageRuleIssues",
        Filter::new().eq("tenantId", f.tenant_id.clone()),
    )
    .await
}

async fn reconcile(f: &Org, options: Value) -> Value {
    serde_json::to_value(
        reconcile_package_rules(&f.iam.ctx, &options)
            .await
            .expect("reconcile"),
    )
    .unwrap()
}

fn environment(f: &Org) -> RuleEnvironment {
    RuleEnvironment {
        identity_attributes: f.iam.ctx.catalog.identity_attributes.clone(),
        groups: None,
        packaged_groups: None,
        org: Some(json!({})),
        extra: Map::new(),
    }
}

async fn set_status(f: &Org, identity_id: &str, status: &str) {
    let mut record = f
        .iam
        .store
        .get("identities", identity_id)
        .await
        .unwrap()
        .unwrap();
    record.insert("status".into(), json!(status));
    f.put("identities", record).await;
}

#[test]
fn after_identity_change_answers_the_result_and_needs_no_rule() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let result = json!({ "id": alice, "name": "alice" });
        let answered = after_identity_change(
            &f.iam.ctx,
            &f.tenant_id,
            std::slice::from_ref(&alice),
            &result,
        )
        .await
        .unwrap();
        assert_eq!(answered, result);
        // Nothing to do without identities either.
        assert_eq!(
            after_identity_change(&f.iam.ctx, &f.tenant_id, &[], &json!(null))
                .await
                .unwrap(),
            json!(null)
        );
        // An identity-change run over a tenant without rule packages stops before reading anything.
        let run = reconcile(
            &f,
            json!({ "tenantId": f.tenant_id, "identityIds": [alice], "trigger": "identity-change" }),
        )
        .await;
        assert_eq!(
            run,
            json!({
                "trigger": "identity-change",
                "assigned": 0.0, "refreshed": 0.0, "restored": 0.0, "ending": 0.0, "revoked": 0.0, "stale": 0.0,
                "failed": [], "suspended": [], "braked": [],
                "skipped": { "inactiveTenants": 0, "failedTenants": [] },
                "truncated": false,
            })
        );
    });
}

#[test]
fn suspends_a_rule_that_no_longer_validates_and_records_the_issue_once() {
    run(|| async {
        let f = organization(|_| {}).await;
        f.member("alice").await;
        let pkg = rule_package(
            &f,
            "Wiki",
            &f.owner_id,
            json!({ "include": [{ "StringEquals": { "principal.kind": "user" }, "ArrayContains": { "identity.groups": ["g-gone"] } }] }),
        )
        .await;
        let run = reconcile(
            &f,
            json!({ "tenantId": f.tenant_id, "trigger": "schedule" }),
        )
        .await;
        let detail = "autoAssign.include[0]: unknown group g-gone";
        assert_eq!(
            run["suspended"],
            json!([{ "tenantId": f.tenant_id, "packageId": pkg.id, "reason": "invalid-rule", "detail": detail }])
        );
        assert_eq!(run["assigned"], json!(0.0));
        let stored = issues(&f).await;
        assert_eq!(stored.len(), 1);
        assert_list(
            &Value::Object(stored[0].clone()),
            json!({
                "uniqueKey": format!("{}:suspended", pkg.id),
                "packageId": pkg.id,
                "kind": "suspended",
                "code": "invalid-rule",
                "message": detail,
                "revision": 1,
            }),
        );
        let events = audit_events(&f, "package:auto-suspended").await;
        assert_eq!(events.len(), 1);
        assert_list(
            &Value::Object(events[0].clone()),
            json!({
                "actorId": "deployment-operator",
                "resourceId": pkg.id,
                "outcome": "deny",
                "metadata": {
                    "trigger": "schedule",
                    "packageId": pkg.id,
                    "packageName": "Wiki",
                    "reason": "invalid-rule",
                    "detail": detail,
                },
            }),
        );
        // A persistent problem is neither re-audited nor re-written.
        let again = reconcile(
            &f,
            json!({ "tenantId": f.tenant_id, "trigger": "manual", "requestedBy": f.owner_id }),
        )
        .await;
        assert_eq!(again["suspended"].as_array().unwrap().len(), 1);
        assert_eq!(audit_events(&f, "package:auto-suspended").await.len(), 1);
        assert_eq!(issues(&f).await.len(), 1);

        // The administrator's view says the same.
        let view = auto_assign_view(
            &f.iam.ctx,
            &f.iam.store,
            &pkg,
            &RuleEnvironment {
                groups: Some(IndexSet::new()),
                ..environment(&f)
            },
        )
        .await
        .unwrap();
        assert_eq!(view.status, "suspended");
        assert_eq!(view.suspended_reason.as_deref(), Some("invalid-rule"));
        assert_eq!(view.suspended_detail.as_deref(), Some(detail));
        assert_eq!(view.issue_count, 1.0);
        assert_list(
            &json!(view.issues),
            json!([{ "kind": "suspended", "code": "invalid-rule", "message": detail }]),
        );
    });
}

#[test]
fn freezes_additions_while_the_rule_owner_is_inactive() {
    run(|| async {
        let f = organization(|_| {}).await;
        let mallory = f.member("mallory").await;
        f.member("alice").await;
        let pkg = rule_package(&f, "Everyone", &mallory, json!({ "include": [people()] })).await;
        set_status(&f, &mallory, "disabled").await;
        let run = reconcile(
            &f,
            json!({ "tenantId": f.tenant_id, "packageId": pkg.id, "trigger": "manual" }),
        )
        .await;
        assert_eq!(
            run["suspended"],
            json!([{
                "tenantId": f.tenant_id,
                "packageId": pkg.id,
                "reason": "owner-inactive",
                "detail": "The rule owner mallory is disabled",
            }])
        );
        assert_eq!(run["assigned"], json!(0.0));
        assert!(
            f.find(
                "packageAssignments",
                Filter::new().eq("packageId", pkg.id.clone())
            )
            .await
            .is_empty()
        );
        let stored = issues(&f).await;
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0]["code"], json!("owner-inactive"));

        let view = auto_assign_view(&f.iam.ctx, &f.iam.store, &pkg, &environment(&f))
            .await
            .unwrap();
        assert_eq!(view.status, "suspended");
        assert_eq!(view.suspended_reason.as_deref(), Some("owner-inactive"));
        assert_eq!(
            view.suspended_detail.as_deref(),
            Some("The rule owner mallory is not active")
        );
        assert_eq!(view.owner_name, "mallory");

        // A deleted owner reads as deleted; a rule matching nobody needs no owner at all.
        set_status(&f, &mallory, "deleted").await;
        let deleted = reconcile(
            &f,
            json!({ "tenantId": f.tenant_id, "trigger": "schedule" }),
        )
        .await;
        assert_eq!(
            deleted["suspended"][0]["detail"],
            json!("The rule owner mallory is deleted")
        );
        let nobody = rule_package(
            &f,
            "Nobody",
            &mallory,
            json!({ "include": [{ "StringEquals": { "principal.kind": "service" } }] }),
        )
        .await;
        let quiet = reconcile(
            &f,
            json!({ "tenantId": f.tenant_id, "packageId": nobody.id, "trigger": "schedule" }),
        )
        .await;
        assert_eq!(quiet["suspended"], json!([]));
    });
}

#[test]
fn shows_an_active_rule_with_its_warnings_owner_and_latest_issues() {
    run(|| async {
        let f = organization(|options| {
            options.permissions = Some(PermissionsConfig {
                actions: Some(vec!["documents:read".into(), "documents:write".into()]),
                identity_attributes: Some(IndexMap::from([(
                    "department".to_owned(),
                    AttributeType::String,
                )])),
                ..PermissionsConfig::default()
            });
        })
        .await;
        let alice = f.member("alice").await;
        let pkg = rule_package(
            &f,
            "Finance",
            &f.owner_id,
            json!({
                "include": [{ "StringEquals": { "principal.kind": "user", "principal.department": "finance" } }],
                "graceMs": 7.0 * DAY,
            }),
        )
        .await;
        for (index, (identity_id, since)) in [(alice.as_str(), 2.0), ("i-gone", 1.0)]
            .into_iter()
            .enumerate()
        {
            f.insert(
                "packageRuleIssues",
                json!({
                    "id": format!("issue-{index}"),
                    "tenantId": f.tenant_id,
                    "uniqueKey": format!("{}:identity:{identity_id}", pkg.id),
                    "packageId": pkg.id,
                    "kind": "failed",
                    "identityId": identity_id,
                    "code": "SOD_CONFLICT",
                    "message": "Separation of duties",
                    "revision": 1,
                    "since": f.now() + since,
                }),
            )
            .await;
        }
        let view = auto_assign_view(&f.iam.ctx, &f.iam.store, &pkg, &environment(&f))
            .await
            .unwrap();
        assert_eq!(view.status, "active");
        assert_eq!(view.suspended_reason, None);
        assert_eq!(view.owner_name, "Acme owner");
        assert_eq!(view.grace_ms, Some(7.0 * DAY));
        assert_eq!(view.revision, 1.0);
        assert_eq!(
            view.warnings,
            [
                "include[0] tests principal.department, which anyone holding iam:identities:update can set, so they choose who receives this package under its owner\u{2019}s authority"
            ]
        );
        assert_eq!(view.issue_count, 2.0);
        assert_list(
            &json!(view.issues),
            json!([
                { "kind": "failed", "identityId": alice, "identityName": "alice", "code": "SOD_CONFLICT" },
                { "kind": "failed", "identityId": "i-gone", "identityName": "i-gone" },
            ]),
        );

        // A revoked authority suspends the rule.
        let authority_id = owner_authority(&f).await;
        let mut authority = f
            .iam
            .store
            .get("grantAuthorities", &authority_id)
            .await
            .unwrap()
            .unwrap();
        authority.insert("revoked".into(), json!(true));
        f.put("grantAuthorities", authority).await;
        let revoked = auto_assign_view(&f.iam.ctx, &f.iam.store, &pkg, &environment(&f))
            .await
            .unwrap();
        assert_eq!(
            revoked.suspended_reason.as_deref(),
            Some("authority-revoked")
        );
        assert_eq!(
            revoked.suspended_detail.as_deref(),
            Some("The rule owner\u{2019}s grant authority is revoked or no longer theirs")
        );
    });
}

#[test]
fn forgets_issues_whose_package_or_identity_is_gone_and_skips_inactive_tenants() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let pkg = rule_package(
            &f,
            "Services",
            &f.owner_id,
            json!({ "include": [{ "StringEquals": { "principal.kind": "service" } }] }),
        )
        .await;
        let issue = |id: &str, package_id: &str, identity_id: &str| {
            json!({
                "id": id,
                "tenantId": f.tenant_id,
                "uniqueKey": format!("{package_id}:identity:{identity_id}"),
                "packageId": package_id,
                "kind": "failed",
                "identityId": identity_id,
                "code": "ERROR",
                "message": "failed",
                "revision": 1,
                "since": f.now(),
            })
        };
        // A package that is gone, an identity that is gone, and a pair that needs nothing any more.
        f.insert("packageRuleIssues", issue("i1", "p-gone", &alice))
            .await;
        f.insert("packageRuleIssues", issue("i2", &pkg.id, "i-gone"))
            .await;
        f.insert("packageRuleIssues", issue("i3", &pkg.id, &alice))
            .await;
        let run = reconcile(&f, json!({ "trigger": "schedule" })).await;
        assert_eq!(
            run["skipped"],
            json!({ "inactiveTenants": 0, "failedTenants": [] })
        );
        assert!(issues(&f).await.is_empty());

        // A named tenant that is not active is skipped.
        let mut tenant = f
            .iam
            .store
            .get("tenants", &f.tenant_id)
            .await
            .unwrap()
            .unwrap();
        tenant.insert("status".into(), json!("suspended"));
        f.put("tenants", tenant).await;
        let skipped = reconcile(
            &f,
            json!({ "tenantId": f.tenant_id, "trigger": "schedule" }),
        )
        .await;
        assert_eq!(skipped["skipped"]["inactiveTenants"], json!(1));
        // An unknown tenant is refused.
        let missing = reconcile_package_rules(
            &f.iam.ctx,
            &json!({ "tenantId": "t-unknown", "trigger": "schedule" }),
        )
        .await
        .unwrap_err();
        assert_eq!(missing.code, "NOT_FOUND");
    });
}

// --- Ported TypeScript scenarios that need the packages API (another unit) ---------------------------------------

struct Setup {
    f: Org,
    owner: CredentialInput,
    writer: Value,
    reader: Value,
    finance: Value,
    lounge: Value,
    alice: String,
    mallory: String,
}

/// tests/security-packages.test.ts `setup`: Acme with Writer and Reader roles, a Finance group that carries Reader,
/// an empty Lounge group, and Mallory, a package manager.
async fn setup(identity_attributes: Option<IndexMap<String, AttributeType>>) -> Setup {
    let f = organization(move |options| {
        options.permissions = Some(PermissionsConfig {
            actions: Some(vec!["documents:read".into(), "documents:write".into()]),
            identity_attributes,
            ..PermissionsConfig::default()
        });
    })
    .await;
    let owner = f.owner_credential.clone();
    let tenant_id = f.tenant_id.clone();
    let writer = ok(f
        .iam
        .api
        .roles
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Writer", "permissions": ["documents:write"] })),
        )
        .await);
    let reader = ok(f
        .iam
        .api
        .roles
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Reader", "permissions": ["documents:read"] })),
        )
        .await);
    let finance = ok(f
        .iam
        .api
        .groups
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Finance" })),
        )
        .await);
    ok(f.iam
        .api
        .bindings
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "roleId": reader["id"], "subjectType": "group", "subjectId": finance["id"] })),
        )
        .await);
    let lounge = ok(f
        .iam
        .api
        .groups
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Lounge" })),
        )
        .await);
    let alice = f.member("alice").await;
    let mallory = f.member("mallory").await;
    let manager = ok(f
        .iam
        .api
        .roles
        .create(
            &owner,
            body(json!({
                "tenantId": tenant_id,
                "name": "Package manager",
                "permissions": ["iam:packages:update", "iam:packages:assign", "iam:packages:read", "iam:groups:update"],
            })),
        )
        .await);
    ok(f.iam
        .api
        .bindings
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "roleId": manager["id"], "subjectType": "identity", "subjectId": mallory })),
        )
        .await);
    Setup {
        f,
        owner,
        writer,
        reader,
        finance,
        lounge,
        alice,
        mallory,
    }
}

impl Setup {
    fn tenant(&self) -> &str {
        &self.f.tenant_id
    }

    async fn can(&self, identity_id: &str, action: &str) -> bool {
        self.f
            .iam
            .authorize(&AuthorizationRequest {
                credential: self.f.sign_in(identity_id).await,
                tenant_id: self.f.tenant_id.clone(),
                action: action.into(),
                resource: ResourceTarget {
                    kind: "documents".into(),
                    id: "a".into(),
                },
            })
            .await
            .expect("authorize")
            .allowed
    }

    async fn create_package(&self, mut input: Value) -> Value {
        input["tenantId"] = json!(self.tenant());
        ok(self
            .f
            .iam
            .api
            .packages
            .create(&self.owner, body(input))
            .await)
    }

    async fn holders(&self, package_id: &Value, source: Option<&str>) -> Vec<String> {
        let mut input = json!({ "tenantId": self.tenant(), "packageId": package_id });
        if let Some(source) = source {
            input["source"] = json!(source);
        }
        let listed = ok(self
            .f
            .iam
            .api
            .packages
            .list_assignments(&self.owner, body(input))
            .await);
        listed
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|assignment| {
                assignment["identityId"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect()
    }

    async fn reconcile(&self, package_id: &Value) -> Value {
        ok(self
            .f
            .iam
            .api
            .packages
            .reconcile(
                &self.owner,
                body(json!({ "tenantId": self.tenant(), "packageId": package_id })),
            )
            .await)
    }

    async fn membership(&self, group_id: &Value, identity_id: &str) -> Option<Record> {
        self.f
            .find(
                "groupMembers",
                Filter::new()
                    .eq("tenantId", self.f.tenant_id.clone())
                    .eq("groupId", group_id.clone())
                    .eq("identityId", identity_id.to_owned()),
            )
            .await
            .into_iter()
            .next()
    }

    async fn add_member(&self, group_id: &Value, identity_id: &str) {
        ok(self
            .f
            .iam
            .api
            .groups
            .add_member(
                &self.owner,
                body(json!({ "tenantId": self.tenant(), "groupId": group_id, "identityId": identity_id })),
            )
            .await);
    }
}

fn with_people(conditions: Value) -> Value {
    let mut clause = people();
    for (key, value) in conditions.as_object().unwrap() {
        if key == "StringEquals" {
            for (attribute, expected) in value.as_object().unwrap() {
                clause["StringEquals"][attribute] = expected.clone();
            }
        } else {
            clause[key] = value.clone();
        }
    }
    clause
}

#[test]
#[ignore = "needs api/packages.ts (packages routes, assignPackage, allow, authorizePackage, ruleEnvironment) from the packages unit"]
fn records_the_grant_an_invariant_forbids_as_a_failed_issue_and_still_grants_everyone_else() {
    run(|| async {
        let s = setup(Some(IndexMap::from([(
            "contractor".to_owned(),
            AttributeType::Boolean,
        )])))
        .await;
        ok(s.f
            .iam
            .api
            .identities
            .update(
                &s.owner,
                body(json!({ "tenantId": s.tenant(), "identityId": s.alice, "attributes": { "contractor": true } })),
            )
            .await);
        ok(s.f
            .iam
            .api
            .invariants
            .create(
                &s.owner,
                body(json!({
                    "tenantId": s.tenant(),
                    "name": "Contractors never write",
                    "subject": { "attribute": { "name": "contractor", "value": true } },
                    "action": "documents:write",
                    "resource": { "type": "documents", "id": "a" },
                    "expect": "deny",
                    "mode": "enforce",
                })),
            )
            .await);
        let pkg = s
            .create_package(json!({
                "name": "Writers",
                "roleIds": [s.writer["id"]],
                "autoAssign": { "include": [people()] },
            }))
            .await;
        assert_list(
            &pkg["reconcile"]["failed"],
            json!([{ "identityId": s.alice, "code": "INVARIANT_VIOLATION" }]),
        );
        let holders = s.holders(&pkg["id"], None).await;
        assert!(holders.contains(&s.mallory));
        assert!(!holders.contains(&s.alice));
        assert!(!s.can(&s.alice, "documents:write").await);
        assert!(s.can(&s.mallory, "documents:write").await);
        let view = ok(s
            .f
            .iam
            .api
            .packages
            .get(
                &s.owner,
                body(json!({ "tenantId": s.tenant(), "packageId": pkg["id"] })),
            )
            .await);
        assert_list(
            &view["autoAssign"]["issues"],
            json!([{ "identityId": s.alice, "code": "INVARIANT_VIOLATION" }]),
        );
        let checked = ok(s
            .f
            .iam
            .api
            .invariants
            .run(&s.owner, body(json!({ "tenantId": s.tenant() })))
            .await);
        assert!(!checked.to_string().contains(&s.alice));
    });
}

#[test]
#[ignore = "needs api/packages.ts (packages routes, previewAutoAssign, ruleEnvironment) from the packages unit"]
fn flags_attributes_manager_id_and_groups_without_bindings_in_include_and_exclude_clauses() {
    run(|| async {
        let s = setup(Some(IndexMap::from([
            ("department".to_owned(), AttributeType::String),
            ("contractor".to_owned(), AttributeType::Boolean),
        ])))
        .await;
        let pkg = s
            .create_package(json!({
                "name": "Finance birthright",
                "roleIds": [s.writer["id"]],
                "autoAssign": {
                    "include": [
                        with_people(json!({ "StringEquals": { "principal.department": "finance" } })),
                        with_people(json!({ "StringEquals": { "identity.managerId": s.mallory } })),
                        with_people(json!({ "ArrayContains": { "identity.groups": [s.lounge["id"], s.finance["id"]] } })),
                    ],
                    "exclude": [{ "Bool": { "principal.contractor": true } }],
                },
            }))
            .await;
        let warnings: Vec<String> = pkg["autoAssign"]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|warning| warning.as_str().unwrap().to_owned())
            .collect();
        let has = |prefix: &str, needle: &str| {
            warnings
                .iter()
                .any(|warning| warning.starts_with(prefix) && warning.contains(needle))
        };
        assert!(has(
            "include[0] tests principal.department, ",
            "iam:identities:update"
        ));
        assert!(has(
            "include[1] tests identity.managerId, ",
            "iam:identities:update"
        ));
        assert!(has(
            "include[2] tests identity.groups for ",
            ", a group without role bindings"
        ));
        assert!(has(
            "exclude[0] tests principal.contractor, ",
            "lift the exclusion"
        ));
        let finance = s.finance["id"].as_str().unwrap();
        let lounge = s.lounge["id"].as_str().unwrap();
        assert!(!warnings.iter().any(|warning| warning.contains(finance)));
        assert!(warnings.iter().any(|warning| warning.contains(lounge)));
        let preview = ok(s
            .f
            .iam
            .api
            .packages
            .preview_auto_assign(
                &s.owner,
                body(json!({ "tenantId": s.tenant(), "packageId": pkg["id"] })),
            )
            .await);
        assert_eq!(preview["warnings"], pkg["autoAssign"]["warnings"]);
    });
}

#[test]
#[ignore = "needs api/packages.ts (packages routes, ruleEnvironment) from the packages unit"]
fn does_not_flag_rules_on_fixed_facts() {
    run(|| async {
        let s = setup(None).await;
        let pkg = s
            .create_package(json!({
                "name": "Everyone",
                "roleIds": [s.reader["id"]],
                "autoAssign": { "include": [with_people(json!({ "ArrayContains": { "identity.groups": [s.finance["id"]] } }))] },
            }))
            .await;
        assert_eq!(pkg["autoAssign"]["warnings"], json!([]));
    });
}

#[test]
#[ignore = "needs api/packages.ts (packages routes, assignPackage, revokeAssignment) from the packages unit"]
fn ignores_a_team_backing_group_joined_only_through_a_package_granted_source_group() {
    run(|| async {
        let s = setup(None).await;
        let contractors = ok(s
            .f
            .iam
            .api
            .groups
            .create(
                &s.owner,
                body(json!({ "tenantId": s.tenant(), "name": "Contractors" })),
            )
            .await);
        let vendors = ok(s
            .f
            .iam
            .api
            .teams
            .create(
                &s.owner,
                body(json!({ "tenantId": s.tenant(), "name": "Vendors", "syncGroupIds": [contractors["id"]] })),
            )
            .await);
        let kit = s
            .create_package(json!({ "name": "Contractor kit", "groupIds": [contractors["id"]] }))
            .await;
        let chained = s
            .create_package(json!({
                "name": "Vendor tools",
                "roleIds": [s.writer["id"]],
                "autoAssign": { "include": [with_people(json!({ "ArrayContains": { "identity.groups": [vendors["groupId"]] } }))] },
            }))
            .await;
        // Alice reaches the Vendors team (and its backing group) only through the Contractor kit package.
        ok(s.f
            .iam
            .api
            .packages
            .assign(
                &s.owner,
                body(json!({ "tenantId": s.tenant(), "packageId": kit["id"], "identityId": s.alice })),
            )
            .await);
        assert!(s.membership(&vendors["groupId"], &s.alice).await.is_some());
        s.reconcile(&chained["id"]).await;
        assert!(
            s.holders(&chained["id"], Some("automatic"))
                .await
                .is_empty()
        );
        // A direct membership of the source group counts.
        let bob = s.f.member("bob").await;
        s.add_member(&contractors["id"], &bob).await;
        s.reconcile(&chained["id"]).await;
        assert_eq!(s.holders(&chained["id"], Some("automatic")).await, [bob]);
    });
}

#[test]
#[ignore = "needs api/packages.ts (packages routes, assignPackage, revokeAssignment) from the packages unit"]
fn a_package_cannot_keep_itself_alive_through_a_team_synced_from_its_own_group() {
    run(|| async {
        let s = setup(None).await;
        let seed = ok(s
            .f
            .iam
            .api
            .groups
            .create(
                &s.owner,
                body(json!({ "tenantId": s.tenant(), "name": "Seed" })),
            )
            .await);
        let granted = ok(s
            .f
            .iam
            .api
            .groups
            .create(
                &s.owner,
                body(json!({ "tenantId": s.tenant(), "name": "Granted" })),
            )
            .await);
        let echo = ok(s
            .f
            .iam
            .api
            .teams
            .create(
                &s.owner,
                body(json!({ "tenantId": s.tenant(), "name": "Echo", "syncGroupIds": [granted["id"]] })),
            )
            .await);
        let pkg = s
            .create_package(json!({
                "name": "Loop",
                "groupIds": [granted["id"]],
                "autoAssign": {
                    "include": [
                        with_people(json!({ "ArrayContains": { "identity.groups": [seed["id"]] } })),
                        with_people(json!({ "ArrayContains": { "identity.groups": [echo["groupId"]] } })),
                    ],
                },
            }))
            .await;
        s.add_member(&seed["id"], &s.alice).await;
        s.reconcile(&pkg["id"]).await;
        assert_eq!(
            s.holders(&pkg["id"], None).await,
            std::slice::from_ref(&s.alice)
        );
        assert!(s.membership(&echo["groupId"], &s.alice).await.is_some());
        ok(s.f
            .iam
            .api
            .groups
            .remove_member(
                &s.owner,
                body(
                    json!({ "tenantId": s.tenant(), "groupId": seed["id"], "identityId": s.alice }),
                ),
            )
            .await);
        s.reconcile(&pkg["id"]).await;
        assert!(s.holders(&pkg["id"], None).await.is_empty());
        assert!(s.membership(&echo["groupId"], &s.alice).await.is_none());
    });
}

/// tests/org-birthright.test.ts `scenario`: four people, a Wiki group, Engineering with Platform below it, and the
/// Platform team with Site Reliability below it.
struct Org2 {
    s: Setup,
    people: HashMap<&'static str, String>,
    wiki: Value,
    engineering: Value,
    platform_department: Value,
    platform: Value,
    sre: Value,
}

async fn org_scenario() -> Org2 {
    let s = setup(None).await;
    let mut people = HashMap::new();
    people.insert("alice", s.alice.clone());
    for name in ["bob", "carol", "dave"] {
        people.insert(name, s.f.member(name).await);
    }
    let tenant = s.tenant().to_owned();
    let wiki = ok(s
        .f
        .iam
        .api
        .groups
        .create(
            &s.owner,
            body(json!({ "tenantId": tenant, "name": "Wiki editors" })),
        )
        .await);
    let engineering = ok(s
        .f
        .iam
        .api
        .departments
        .create(
            &s.owner,
            body(json!({ "tenantId": tenant, "name": "Engineering" })),
        )
        .await);
    let platform_department = ok(s
        .f
        .iam
        .api
        .departments
        .create(
            &s.owner,
            body(json!({ "tenantId": tenant, "name": "Platform", "parentId": engineering["id"] })),
        )
        .await);
    let platform = ok(s
        .f
        .iam
        .api
        .teams
        .create(
            &s.owner,
            body(json!({ "tenantId": tenant, "name": "Platform" })),
        )
        .await);
    let sre = ok(s
        .f
        .iam
        .api
        .teams
        .create(
            &s.owner,
            body(json!({ "tenantId": tenant, "name": "Site Reliability", "slug": "sre", "parentId": platform["id"] })),
        )
        .await);
    Org2 {
        s,
        people,
        wiki,
        engineering,
        platform_department,
        platform,
        sre,
    }
}

impl Org2 {
    fn id(&self, name: &str) -> String {
        self.people[name].clone()
    }

    async fn holders(&self, package_id: &Value) -> Vec<String> {
        let mut holders = self.s.holders(package_id, Some("automatic")).await;
        holders.sort();
        holders
    }
}

#[test]
#[ignore = "needs api/packages.ts (packages routes, assignPackage, revokeAssignment) from the packages unit"]
fn grants_a_package_to_a_department_and_the_departments_below_it_as_people_join_and_leave() {
    run(|| async {
        let o = org_scenario().await;
        let s = &o.s;
        let pkg = s
            .create_package(json!({
                "name": "Engineering basics",
                "groupIds": [o.wiki["id"]],
                "autoAssign": { "include": [with_people(json!({ "ArrayContains": { "identity.departments": [o.engineering["id"]] } }))] },
            }))
            .await;
        assert!(o.holders(&pkg["id"]).await.is_empty());
        let preview = ok(s
            .f
            .iam
            .api
            .packages
            .preview_auto_assign(&s.owner, body(json!({ "tenantId": s.tenant() })))
            .await);
        let keys: Vec<&str> = preview["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key["key"].as_str().unwrap())
            .collect();
        assert!(keys.contains(&"identity.teams") && keys.contains(&"identity.departments"));

        // Placing people re-evaluates the rule at once: a sub-department counts for Engineering.
        ok(s.f
            .iam
            .api
            .departments
            .assign(
                &s.owner,
                body(json!({ "tenantId": s.tenant(), "departmentId": o.platform_department["id"], "identityIds": [o.id("carol"), o.id("dave")] })),
            )
            .await);
        let mut expected = vec![o.id("carol"), o.id("dave")];
        expected.sort();
        assert_eq!(o.holders(&pkg["id"]).await, expected);

        // Leavers lose it, and so does everyone when their department moves out from under Engineering.
        ok(s.f
            .iam
            .api
            .departments
            .unassign(
                &s.owner,
                body(json!({ "tenantId": s.tenant(), "identityId": o.id("carol") })),
            )
            .await);
        assert_eq!(o.holders(&pkg["id"]).await, [o.id("dave")]);
        ok(s.f
            .iam
            .api
            .departments
            .update(
                &s.owner,
                body(json!({ "tenantId": s.tenant(), "departmentId": o.platform_department["id"], "parentId": null })),
            )
            .await);
        assert!(o.holders(&pkg["id"]).await.is_empty());

        // A department a rule names stays until the rule stops naming it.
        let refused = organization_fixture::fails(
            s.f.iam
                .api
                .departments
                .delete(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant(), "departmentId": o.engineering["id"] })),
                )
                .await,
        );
        assert_eq!(refused.code, "RESOURCE_IN_USE");
        assert!(refused.message.contains("Engineering basics"));
    });
}

#[test]
#[ignore = "needs api/packages.ts (packages routes, assignPackage, revokeAssignment) from the packages unit"]
fn matches_members_of_a_team_and_of_the_teams_below_it_but_not_memberships_a_package_created() {
    run(|| async {
        let o = org_scenario().await;
        let s = &o.s;
        let pkg = s
            .create_package(json!({
                "name": "Platform tools",
                "groupIds": [o.wiki["id"]],
                "autoAssign": { "include": [with_people(json!({ "ArrayContains": { "identity.teams": [o.platform["id"]] } }))] },
            }))
            .await;
        let team_member = |method: &'static str| {
            let input = json!({ "tenantId": s.tenant(), "teamId": o.sre["id"], "identityId": o.id("alice") });
            async move {
                if method == "add" {
                    ok(s.f.iam.api.teams.add_member(&s.owner, body(input)).await)
                } else {
                    ok(s.f.iam.api.teams.remove_member(&s.owner, body(input)).await)
                }
            }
        };
        team_member("add").await;
        assert_eq!(o.holders(&pkg["id"]).await, [o.id("alice")]);
        team_member("remove").await;
        assert!(o.holders(&pkg["id"]).await.is_empty());

        // A team synced from a group: a membership of the source group counts only when no package created it.
        let contractors = ok(s
            .f
            .iam
            .api
            .groups
            .create(
                &s.owner,
                body(json!({ "tenantId": s.tenant(), "name": "Contractors" })),
            )
            .await);
        let kit = s
            .create_package(json!({ "name": "Contractor kit", "groupIds": [contractors["id"]] }))
            .await;
        let vendors = ok(s
            .f
            .iam
            .api
            .teams
            .create(
                &s.owner,
                body(json!({ "tenantId": s.tenant(), "name": "Vendors", "parentId": o.platform["id"], "syncGroupIds": [contractors["id"]] })),
            )
            .await);
        ok(s.f
            .iam
            .api
            .packages
            .assign(
                &s.owner,
                body(json!({ "tenantId": s.tenant(), "packageId": kit["id"], "identityId": o.id("bob") })),
            )
            .await);
        s.add_member(&contractors["id"], &o.id("carol")).await;
        s.reconcile(&pkg["id"]).await;
        assert_eq!(o.holders(&pkg["id"]).await, [o.id("carol")]);

        // Teams no rule names can go; the one the rule names stays until the rule stops naming it.
        for team in [&vendors, &o.sre] {
            let deleted = ok(s
                .f
                .iam
                .api
                .teams
                .delete(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant(), "teamId": team["id"] })),
                )
                .await);
            assert_eq!(deleted["deleted"], json!(true));
        }
        let refused = organization_fixture::fails(
            s.f.iam
                .api
                .teams
                .delete(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant(), "teamId": o.platform["id"] })),
                )
                .await,
        );
        assert_eq!(refused.code, "RESOURCE_IN_USE");
    });
}

#[test]
#[ignore = "needs api/packages.ts (packages.create, ruleEnvironment) from the packages unit"]
fn validates_the_teams_and_departments_a_rule_names() {
    run(|| async {
        let o = org_scenario().await;
        let s = &o.s;
        let create = |conditions: Value| {
            let input = json!({
                "tenantId": s.tenant(),
                "name": "Checked",
                "groupIds": [o.wiki["id"]],
                "autoAssign": { "include": [with_people(conditions)] },
            });
            async move { s.f.iam.api.packages.create(&s.owner, body(input)).await }
        };
        let error = organization_fixture::fails(
            create(json!({ "ArrayContains": { "identity.teams": ["no-such-team"] } })).await,
        );
        assert_eq!(error.code, "INVALID_INPUT");
        assert!(error.message.contains("unknown team"));
        let error = organization_fixture::fails(
            create(json!({ "ArrayContains": { "identity.departments": [o.platform["id"]] } }))
                .await,
        );
        assert_eq!(error.code, "INVALID_INPUT");
        assert!(error.message.contains("unknown department"));
        let error = organization_fixture::fails(
            create(json!({ "StringEquals": { "identity.teams": o.platform["id"] } })).await,
        );
        assert_eq!(error.code, "INVALID_INPUT");
        let created = ok(create(json!({ "Exists": { "identity.departments": true } })).await);
        assert_eq!(created["name"], json!("Checked"));
    });
}
