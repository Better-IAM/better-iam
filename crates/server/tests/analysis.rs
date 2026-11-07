//! Access analysis: ported from tests/analysis.test.ts and the `analysis.lintPolicy` suite of
//! tests/policy-lint.test.ts. Tenants, owners, members and sessions come from the organization fixture (the TypeScript
//! suite's own fixture signs the owner in through `tenants.acceptInvitation`, which is the same state); policies,
//! roles, identities, groups and bindings are created through their API groups.
//!
//! Every findings scan checks separation-of-duties rules (`sod.ts sodViolations`), and creating or updating identities
//! runs `api/package-automation.ts afterIdentityChange`; both belong to other port units, so the suites that scan are
//! ignored until they land. Account status and trusts are written the way `identities.setStatus` and `trust.create`
//! store them. `analysis.lintPolicy` does not scan and runs now.

mod organization_fixture;

use better_iam_core::{
    AttributeType, CredentialInput, Filter, IamStoreExt, PermissionsConfig, PermissionsMode,
    ResourceTypeDefinition,
};
use better_iam_server::http::AuthArgs;
use better_iam_server::options::{AuthorizationRequest, ResourceTarget};
use indexmap::IndexMap;
use organization_fixture::{Org, assert_matches, bearer, body, code, fails, ok, organization, run};
use serde_json::{Map, Value, json};

const DAY: f64 = 86_400_000.0;

/// The organization fixture with the sessions of the TypeScript analysis fixture (30 days).
async fn fixture() -> Org {
    organization(|options| {
        if let Some(authentication) = options.authentication.as_mut() {
            authentication.session_lifetime_ms = Some(30.0 * DAY);
            authentication.session_idle_timeout_ms = Some(30.0 * DAY);
        }
    })
    .await
}

/// `{kind}:{subject.name ?? subject.id}` for every finding, sorted.
fn kinds(findings: &Value) -> Vec<String> {
    let mut out: Vec<String> = findings
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| {
            let subject = &finding["subject"];
            let name = subject
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| subject["id"].as_str())
                .unwrap();
            format!("{}:{name}", finding["kind"].as_str().unwrap())
        })
        .collect();
    out.sort();
    out
}

fn of_kind(report: &Value, kind: &str) -> Vec<Value> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["kind"] == json!(kind))
        .cloned()
        .collect()
}

async fn findings(
    f: &Org,
    credential: &CredentialInput,
    input: Value,
) -> Result<Value, (String, u16)> {
    let mut input = input;
    input["tenantId"] = json!(f.tenant_id);
    f.iam
        .api
        .analysis
        .findings(credential, body(input))
        .await
        .map(|reply| reply.into_value().unwrap())
        .map_err(|error| (error.code, error.status))
}

/// `auth.signIn` with a password.
async fn password_sign_in(f: &Org, email: &str, password: &str) -> CredentialInput {
    let session = f
        .iam
        .api
        .auth
        .call(
            "signIn",
            AuthArgs::Public(
                json!({ "tenantId": f.tenant_id, "email": email, "password": password }),
            ),
        )
        .await
        .expect("sign in");
    bearer(session["token"].as_str().expect("no MFA"))
}

async fn create(f: &Org, credential: &CredentialInput, group: &str, input: Value) -> Value {
    let mut input = input;
    input["tenantId"] = json!(f.tenant_id);
    let api = &f.iam.api;
    match group {
        "policies" => ok(api.policies.create(credential, body(input)).await),
        "roles" => ok(api.roles.create(credential, body(input)).await),
        "identities" => ok(api.identities.create(credential, body(input)).await),
        "serviceAccounts" => ok(api.service_accounts.create(credential, body(input)).await),
        "groups" => ok(api.groups.create(credential, body(input)).await),
        "bindings" => ok(api.bindings.create(credential, body(input)).await),
        "credentials" => ok(api.credentials.create(credential, body(input)).await),
        other => panic!("no create for {other}"),
    }
}

fn identity_of(created: &Value) -> Value {
    created
        .get("identity")
        .cloned()
        .unwrap_or_else(|| created.clone())
}

#[test]
#[ignore = "needs sod.ts sodViolations and api/package-automation.ts afterIdentityChange (other port units)"]
fn reports_risky_and_stale_configuration_ordered_by_severity() {
    run(|| async {
        let f = fixture().await;
        let owner = f.owner_credential.clone();
        let tenant_id = f.tenant_id.clone();
        let api = &f.iam.api;
        let admin = create(
            &f,
            &owner,
            "policies",
            json!({
                "name": "Everything",
                "document": { "version": 1, "statements": [{ "effect": "allow", "actions": ["*"], "resources": ["*"] }] },
            }),
        )
        .await;
        let broad = create(
            &f,
            &owner,
            "policies",
            json!({
                "name": "Documents",
                "document": { "version": 1, "statements": [{ "effect": "allow", "actions": ["documents:*"], "resources": ["*"] }] },
            }),
        )
        .await;
        create(
            &f,
            &owner,
            "policies",
            json!({
                "name": "Scoped admin",
                "document": {
                    "version": 1,
                    "statements": [{
                        "effect": "allow",
                        "actions": ["*"],
                        "resources": ["*"],
                        "conditions": { "Bool": { "principal.mfa": true } },
                    }],
                },
            }),
        )
        .await;
        let admins = create(
            &f,
            &owner,
            "roles",
            json!({ "name": "Admins", "policyIds": [admin["id"]] }),
        )
        .await;
        let editors = create(
            &f,
            &owner,
            "roles",
            json!({ "name": "Editors", "policyIds": [broad["id"]] }),
        )
        .await;
        create(
            &f,
            &owner,
            "roles",
            json!({ "name": "Unused", "permissions": ["documents:read"] }),
        )
        .await;
        let alice = identity_of(
            &create(
                &f,
                &owner,
                "identities",
                json!({ "email": "alice@acme.test", "name": "Alice", "password": "a strong alice password" }),
            )
            .await,
        );
        let bot = identity_of(
            &create(
                &f,
                &owner,
                "serviceAccounts",
                json!({ "name": "deploy-bot" }),
            )
            .await,
        );
        for subject in [&alice, &bot] {
            create(
                &f,
                &owner,
                "bindings",
                json!({ "roleId": admins["id"], "subjectType": "identity", "subjectId": subject["id"] }),
            )
            .await;
        }
        let ghosts = create(&f, &owner, "groups", json!({ "name": "Ghosts" })).await;
        create(
            &f,
            &owner,
            "bindings",
            json!({ "roleId": editors["id"], "subjectType": "group", "subjectId": ghosts["id"] }),
        )
        .await;
        // Alice signs in once so she is not yet dormant.
        password_sign_in(&f, "alice@acme.test", "a strong alice password").await;

        let report = findings(&f, &owner, json!({})).await.unwrap();
        // Alice's direct, permanent Admins binding is standing administrator access. Everything's only lint warning
        // (unrestricted-admin) already has its own finding, so no separate policy-lint finding is reported.
        let mut expected = vec![
            "admin-without-mfa:alice@acme.test",
            "admin-without-mfa:owner@acme.test",
            "broad-action-wildcard:Documents",
            "empty-group-with-access:Ghosts",
            "service-account-admin:deploy-bot",
            "standing-privileged-access:alice@acme.test",
            "unattached-policy:Scoped admin",
            "unrestricted-admin-policy:Everything",
            "unused-role:Unused",
        ];
        expected.sort();
        assert_eq!(kinds(&report["findings"]), expected);
        let rank = |severity: &Value| {
            ["high", "medium", "low"]
                .iter()
                .position(|name| severity == &json!(name))
                .unwrap()
        };
        let severities: Vec<usize> = report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|finding| rank(&finding["severity"]))
            .collect();
        let mut ordered = severities.clone();
        ordered.sort();
        assert_eq!(severities, ordered);
        assert_eq!(
            report["summary"],
            json!({ "high": 3, "medium": 3, "low": 3, "suppressed": 0 })
        );

        // Findings are stable across runs, so they can be suppressed with a reason.
        let again = findings(&f, &owner, json!({})).await.unwrap();
        let ids = |report: &Value| -> Vec<Value> {
            report["findings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|finding| finding["id"].clone())
                .collect()
        };
        assert_eq!(ids(&again), ids(&report));
        let unused = of_kind(&report, "unused-role")[0].clone();
        ok(api
            .analysis
            .suppress(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "findingId": unused["id"],
                    "reason": "Kept for the upcoming audit team",
                })),
            )
            .await);
        let suppressed = findings(&f, &owner, json!({})).await.unwrap();
        assert!(!ids(&suppressed).contains(&unused["id"]));
        assert_eq!(suppressed["summary"]["suppressed"], json!(1));
        let all = findings(&f, &owner, json!({ "includeSuppressed": true }))
            .await
            .unwrap();
        let entry = all["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["id"] == unused["id"])
            .unwrap()
            .clone();
        assert_matches(
            &entry["suppressed"],
            json!({ "reason": "Kept for the upcoming audit team" }),
        );
        ok(api
            .analysis
            .unsuppress(
                &owner,
                body(json!({ "tenantId": tenant_id, "findingId": unused["id"] })),
            )
            .await);
        assert!(ids(&findings(&f, &owner, json!({})).await.unwrap()).contains(&unused["id"]));
        let error = fails(
            api.analysis
                .suppress(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "findingId": "not-a-finding", "reason": "x" })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
    });
}

#[test]
#[ignore = "needs sod.ts sodViolations and api/package-automation.ts afterIdentityChange (other port units)"]
fn reports_dormant_members_who_still_hold_access() {
    run(|| async {
        let f = fixture().await;
        let owner = f.owner_credential.clone();
        let readers = create(
            &f,
            &owner,
            "roles",
            json!({ "name": "Readers", "permissions": ["documents:read"] }),
        )
        .await;
        let bob = identity_of(
            &create(
                &f,
                &owner,
                "identities",
                json!({ "email": "bob@acme.test", "name": "Bob", "password": "a strong bob password" }),
            )
            .await,
        );
        create(
            &f,
            &owner,
            "bindings",
            json!({ "roleId": readers["id"], "subjectType": "identity", "subjectId": bob["id"] }),
        )
        .await;
        let robot =
            identity_of(&create(&f, &owner, "serviceAccounts", json!({ "name": "nightly" })).await);
        create(
            &f,
            &owner,
            "credentials",
            json!({ "identityId": robot["id"], "name": "backup" }),
        )
        .await;
        let fresh = findings(&f, &owner, json!({})).await.unwrap();
        assert!(of_kind(&fresh, "dormant-access").is_empty());
        assert!(of_kind(&fresh, "stale-api-key").is_empty());
        f.advance(10.0 * DAY);
        // The owner keeps their session alive; Bob never signed in.
        let later = findings(&f, &owner, json!({ "dormantDays": 7 }))
            .await
            .unwrap();
        let dormant = of_kind(&later, "dormant-access");
        let mut names: Vec<&str> = dormant
            .iter()
            .map(|finding| finding["subject"]["name"].as_str().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, vec!["bob@acme.test", "owner@acme.test"]);
        assert!(
            dormant
                .iter()
                .find(|finding| finding["subject"]["name"] == json!("bob@acme.test"))
                .unwrap()["title"]
                .as_str()
                .unwrap()
                .contains("never signed in")
        );
        let stale = of_kind(&later, "stale-api-key");
        assert_eq!(stale.len(), 1);
        assert_matches(
            &stale[0],
            json!({
                "severity": "medium",
                "title": "API key backup has never been used",
                "subject": { "type": "credential", "name": "backup" },
            }),
        );
        assert_eq!(
            findings(&f, &owner, json!({ "dormantDays": 0 }))
                .await
                .unwrap_err()
                .0,
            "INVALID_INPUT"
        );

        // Members without iam:analysis:read cannot run the analysis.
        let login = password_sign_in(&f, "bob@acme.test", "a strong bob password").await;
        assert_eq!(findings(&f, &login, json!({})).await.unwrap_err().1, 403);
    });
}

async fn bind(f: &Org, role_id: &Value, subject_id: &Value, extra: Value) -> Value {
    let mut input =
        json!({ "roleId": role_id, "subjectType": "identity", "subjectId": subject_id });
    for (key, value) in extra.as_object().unwrap() {
        input[key] = value.clone();
    }
    create(f, &f.owner_credential, "bindings", input).await
}

#[test]
#[ignore = "needs sod.ts sodViolations and api/package-automation.ts afterIdentityChange (other port units)"]
fn reports_standing_administrator_bindings_not_eligible_temporary_service_or_group_ones() {
    run(|| async {
        let f = organization(|_| {}).await;
        let owner = f.owner_credential.clone();
        let admins = create(
            &f,
            &owner,
            "roles",
            json!({
                "name": "Admins",
                "document": { "version": 1, "statements": [{ "effect": "allow", "actions": ["*"], "resources": ["*"] }] },
            }),
        )
        .await;
        let readers = create(
            &f,
            &owner,
            "roles",
            json!({ "name": "Readers", "permissions": ["documents:read"] }),
        )
        .await;
        let alice = json!(f.member("alice").await);
        let bob = json!(f.member("bob").await);
        let carol = json!(f.member("carol").await);
        let dave = json!(f.member("dave").await);
        let bot = identity_of(
            &create(
                &f,
                &owner,
                "serviceAccounts",
                json!({ "name": "deploy-bot" }),
            )
            .await,
        );
        let team = create(&f, &owner, "groups", json!({ "name": "Team" })).await;
        let standing = bind(&f, &admins["id"], &alice, json!({})).await;
        bind(&f, &admins["id"], &bob, json!({ "eligible": true })).await;
        bind(
            &f,
            &admins["id"],
            &carol,
            json!({ "expiresAt": f.now() + DAY }),
        )
        .await;
        bind(&f, &readers["id"], &dave, json!({})).await;
        bind(&f, &admins["id"], &bot["id"], json!({})).await;
        bind(
            &f,
            &admins["id"],
            &team["id"],
            json!({ "subjectType": "group" }),
        )
        .await;

        let found = of_kind(
            &findings(&f, &owner, json!({})).await.unwrap(),
            "standing-privileged-access",
        );
        // The owner's protected Owner binding is not reported either.
        assert_eq!(found.len(), 1);
        assert_matches(
            &found[0],
            json!({
                "severity": "medium",
                "title": "alice@acme.test holds Admins as standing administrator access",
                "subject": { "type": "identity", "id": alice, "name": "alice@acme.test" },
            }),
        );
        assert_eq!(
            found[0]["subject"].as_object().unwrap().len(),
            3,
            "subject is exactly type, id and name"
        );
        assert!(found[0]["detail"].as_str().unwrap().contains("eligible"));
        ok(f.iam
            .api
            .bindings
            .update(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "bindingId": standing["id"], "eligible": true })),
            )
            .await);
        assert!(
            of_kind(
                &findings(&f, &owner, json!({})).await.unwrap(),
                "standing-privileged-access"
            )
            .is_empty()
        );
    });
}

#[test]
#[ignore = "needs sod.ts sodViolations (another port unit)"]
fn reports_eligible_bindings_nobody_has_activated_once_they_outlive_the_dormant_window() {
    run(|| async {
        let f = organization(|_| {}).await;
        let owner = f.owner_credential.clone();
        let api = &f.iam.api;
        let auditors = create(
            &f,
            &owner,
            "roles",
            json!({ "name": "Auditors", "permissions": ["iam:audit:read"] }),
        )
        .await;
        let elevators = create(
            &f,
            &owner,
            "roles",
            json!({ "name": "Elevators", "permissions": ["iam:bindings:activate"] }),
        )
        .await;
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        let carol = f.member("carol").await;
        let team = create(&f, &owner, "groups", json!({ "name": "Team" })).await;
        for person in [&bob, &carol] {
            bind(&f, &elevators["id"], &json!(person), json!({})).await;
        }
        let eligible = |subject: Value, extra: Value| {
            let f = &f;
            let auditors = auditors.clone();
            async move {
                let mut extra = extra;
                extra["eligible"] = json!(true);
                bind(f, &auditors["id"], &subject, extra).await
            }
        };
        eligible(json!(alice), json!({})).await;
        let used = eligible(json!(bob), json!({})).await;
        let requested = eligible(json!(carol), json!({ "requireApproval": true })).await;
        eligible(team["id"].clone(), json!({ "subjectType": "group" })).await;
        let bob_session = f.sign_in(&bob).await;
        ok(api
            .bindings
            .activate(
                &bob_session,
                body(json!({ "tenantId": f.tenant_id, "bindingId": used["id"] })),
            )
            .await);
        // Carol only asks; a request that is never approved is not an activation.
        let carol_session = f.sign_in(&carol).await;
        ok(api
            .bindings
            .activate(
                &carol_session,
                body(json!({ "tenantId": f.tenant_id, "bindingId": requested["id"] })),
            )
            .await);
        let unused = |credential: CredentialInput| {
            let f = &f;
            async move {
                of_kind(
                    &findings(f, &credential, json!({ "dormantDays": 7 }))
                        .await
                        .unwrap(),
                    "unused-eligible-binding",
                )
            }
        };

        // Bindings as young as their subjects are not reported yet.
        assert!(unused(owner.clone()).await.is_empty());
        f.advance(10.0 * DAY);
        let later = unused(f.sign_in(&f.owner_id).await).await;
        let mut subjects: Vec<String> = later
            .iter()
            .map(|finding| {
                format!(
                    "{}:{}",
                    finding["subject"]["type"].as_str().unwrap(),
                    finding["subject"]["name"].as_str().unwrap()
                )
            })
            .collect();
        subjects.sort();
        assert_eq!(
            subjects,
            vec![
                "group:Team",
                "identity:alice@acme.test",
                "identity:carol@acme.test"
            ]
        );
        let alice_finding = later
            .iter()
            .find(|finding| finding["subject"]["id"] == json!(alice))
            .unwrap();
        assert_matches(
            alice_finding,
            json!({
                "severity": "low",
                "title": "Eligible Auditors binding for alice@acme.test has no recorded activation",
            }),
        );
        assert!(
            alice_finding["detail"]
                .as_str()
                .unwrap()
                .contains("no activation")
        );
        // Carol's request dates the binding from the audit trail.
        let carol_detail = later
            .iter()
            .find(|finding| finding["subject"]["id"] == json!(carol))
            .unwrap()["detail"]
            .as_str()
            .unwrap()
            .to_owned();
        let at = carol_detail.find("existed for at least ").expect("dated");
        let rest = &carol_detail[at + "existed for at least ".len()..];
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        assert!(!digits.is_empty() && rest[digits.len()..].starts_with(" days"));
        let ids: std::collections::HashSet<&str> = later
            .iter()
            .map(|finding| finding["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), 3);
    });
}

#[test]
#[ignore = "needs sod.ts sodViolations (another port unit)"]
fn counts_only_activations_the_bindings_api_recorded_not_audit_events_a_member_can_provoke() {
    run(|| async {
        let f = organization(|_| {}).await;
        let owner = f.owner_credential.clone();
        let auditors = create(
            &f,
            &owner,
            "roles",
            json!({ "name": "Auditors", "permissions": ["iam:audit:read"] }),
        )
        .await;
        let alice = f.member("alice").await;
        let binding = bind(
            &f,
            &auditors["id"],
            &json!(alice),
            json!({ "eligible": true }),
        )
        .await;
        f.advance(10.0 * DAY);
        let unused = || {
            let f = &f;
            async move {
                let owner = f.sign_in(&f.owner_id).await;
                of_kind(
                    &findings(f, &owner, json!({ "dormantDays": 7 }))
                        .await
                        .unwrap(),
                    "unused-eligible-binding",
                )
                .iter()
                .map(|finding| finding["subject"]["id"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
            }
        };
        assert_eq!(unused().await, vec![alice.clone()]);

        // Alice holds no permissions, yet authorize() audits each denial under the action and resource ID she names.
        let token = f.sign_in(&alice).await;
        let forged = [
            "binding:activate",
            "binding:activation-approved",
            "binding:break-glass",
        ];
        for action in forged {
            let decision = f
                .iam
                .authorize(&AuthorizationRequest {
                    credential: token.clone(),
                    tenant_id: f.tenant_id.clone(),
                    action: action.into(),
                    resource: ResourceTarget {
                        kind: "anything".into(),
                        id: binding["id"].as_str().unwrap().to_owned(),
                    },
                })
                .await
                .unwrap();
            assert!(!decision.allowed);
        }
        let audited = f
            .find(
                "audit",
                Filter::new()
                    .eq("tenantId", f.tenant_id.clone())
                    .eq("resourceId", binding["id"].as_str().unwrap().to_owned()),
            )
            .await;
        let mut actions: Vec<&str> = audited
            .iter()
            .map(|event| event["action"].as_str().unwrap())
            .collect();
        actions.sort();
        let mut expected = forged.to_vec();
        expected.sort();
        assert_eq!(actions, expected);
        // None of those denials is an activation, so the dormant grant stays reported.
        assert_eq!(unused().await, vec![alice.clone()]);
    });
}

/// Replaces an identity's `managerId` directly (links the API refuses can arrive through direct writes or imports).
async fn link(f: &Org, identity_id: &str, manager_id: &str) {
    set_member(f, identity_id, "managerId", json!(manager_id)).await;
}

/// Writes one member of a stored identity.
async fn set_member(f: &Org, identity_id: &str, key: &str, value: Value) {
    let identity_id = identity_id.to_owned();
    let key = key.to_owned();
    f.store()
        .transaction(|tx| async move {
            let mut record = tx.get("identities", &identity_id).await?.expect("identity");
            record.insert(key, value);
            tx.put("identities", &record).await
        })
        .await
        .unwrap();
}

#[test]
#[ignore = "needs sod.ts sodViolations and api/package-automation.ts afterIdentityChange (other port units)"]
fn reports_manager_links_to_missing_or_inactive_people_and_manager_loops() {
    run(|| async {
        let f = organization(|_| {}).await;
        let owner = f.owner_credential.clone();
        let mut people: IndexMap<&str, String> = IndexMap::new();
        for name in [
            "alice", "bob", "carol", "dave", "erin", "frank", "gina", "hank",
        ] {
            people.insert(name, f.member(name).await);
        }
        let manage = |name: &'static str, manager: &'static str| {
            let (f, people, owner) = (&f, &people, owner.clone());
            async move {
                ok(f.iam
                    .api
                    .identities
                    .update(
                        &owner,
                        body(json!({
                            "tenantId": f.tenant_id,
                            "identityId": people[name],
                            "managerId": people[manager],
                        })),
                    )
                    .await);
            }
        };
        manage("alice", "bob").await;
        // Bob's status as `identities.setStatus` stores it (its guest and threat hooks belong to other port units).
        set_member(&f, &people["bob"], "status", json!("disabled")).await;
        link(&f, &people["carol"], "no-such-identity").await;
        manage("gina", "dave").await;
        manage("dave", "erin").await;
        link(&f, &people["erin"], &people["dave"]).await;
        link(&f, &people["frank"], &people["frank"]).await;
        manage("hank", "gina").await;

        let report = findings(&f, &owner, json!({})).await.unwrap();
        let orphaned = of_kind(&report, "orphaned-manager");
        let mut titles: Vec<&str> = orphaned
            .iter()
            .map(|finding| finding["title"].as_str().unwrap())
            .collect();
        titles.sort();
        assert_eq!(
            titles,
            vec![
                "alice@acme.test's manager bob@acme.test is disabled",
                "carol@acme.test's manager no longer exists",
            ]
        );
        assert!(
            orphaned
                .iter()
                .all(|finding| finding["severity"] == json!("low"))
        );
        // Gina and Hank report into the loop without being part of it.
        let cycles = of_kind(&report, "manager-cycle");
        let mut names: Vec<&str> = cycles
            .iter()
            .map(|finding| finding["subject"]["name"].as_str().unwrap())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec!["dave@acme.test", "erin@acme.test", "frank@acme.test"]
        );
        assert!(
            cycles
                .iter()
                .all(|finding| finding["severity"] == json!("medium"))
        );
        let by_subject = |id: &str| {
            cycles
                .iter()
                .find(|finding| finding["subject"]["id"] == json!(id))
                .unwrap()
                .clone()
        };
        assert!(
            by_subject(&people["dave"])["detail"]
                .as_str()
                .unwrap()
                .contains("dave@acme.test → erin@acme.test → dave@acme.test")
        );
        assert_eq!(
            by_subject(&people["frank"])["title"],
            json!("frank@acme.test's manager chain loops back to them")
        );
    });
}

#[test]
#[ignore = "needs sod.ts sodViolations (another port unit)"]
fn finds_a_manager_loop_at_the_end_of_a_very_deep_reporting_chain_in_linear_time() {
    run(|| async {
        let f = organization(|_| {}).await;
        let tenant_id = f.tenant_id.clone();
        // 10,000 people in one reporting chain whose last 30 form a loop, written directly (the API refuses loops).
        let size = 10_000usize;
        let loop_size = 30usize;
        let created_at = f.now();
        f.store()
            .transaction(|tx| async move {
                for index in 0..size {
                    let manager = if index + 1 < size {
                        index + 1
                    } else {
                        size - loop_size
                    };
                    let record: Map<String, Value> = json!({
                        "id": format!("person-{index}"),
                        "tenantId": tenant_id,
                        "kind": "user",
                        "name": format!("person-{index}"),
                        "status": "active",
                        "emailVerified": false,
                        "rootAdmin": false,
                        "owner": false,
                        "createdAt": created_at,
                        "managerId": format!("person-{manager}"),
                    })
                    .as_object()
                    .unwrap()
                    .clone();
                    tx.insert("identities", &record).await?;
                }
                Ok(())
            })
            .await
            .unwrap();
        let started = std::time::Instant::now();
        let cycles = of_kind(
            &findings(&f, &f.owner_credential, json!({})).await.unwrap(),
            "manager-cycle",
        );
        // Debug builds are slower than the TypeScript bound; the check is that the work stays linear.
        assert!(started.elapsed().as_secs_f64() < 60.0);
        // Only the loop's members are reported; the 9,970 people reporting into it are not part of it.
        let mut ids: Vec<String> = cycles
            .iter()
            .map(|finding| finding["subject"]["id"].as_str().unwrap().to_owned())
            .collect();
        ids.sort();
        let mut expected: Vec<String> = (0..loop_size)
            .map(|index| format!("person-{}", size - loop_size + index))
            .collect();
        expected.sort();
        assert_eq!(ids, expected);
        // A long loop is shortened in the detail, starting and ending with the reported person.
        let detail = cycles
            .iter()
            .find(|finding| finding["subject"]["id"] == json!("person-9985"))
            .unwrap()["detail"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            detail.starts_with(
                "person-9985 → person-9986 → person-9987 → person-9988 → person-9989 → person-9990 → person-9991 → person-9992 → person-9993 → … 21 more → person-9985. "
            ),
            "{detail}"
        );
    });
}

#[test]
#[ignore = "needs sod.ts sodViolations (another port unit)"]
fn reports_stored_policies_and_inline_role_documents_with_lint_warnings() {
    run(|| async {
        let f = organization(|_| {}).await;
        let owner = f.owner_credential.clone();
        create(
            &f,
            &owner,
            "policies",
            json!({
                "name": "Office network",
                "document": {
                    "version": 1,
                    "statements": [
                        {
                            "effect": "allow",
                            "actions": ["documents:read"],
                            "resources": ["documents/*"],
                            "conditions": { "IpAddress": { "request.ip": "10.0.0.0/8" } },
                        },
                        {
                            "effect": "allow",
                            "actions": ["documents:write"],
                            "resources": ["documents/*"],
                            "conditions": { "StringEquals": { "principal.groups": "writers" } },
                        },
                    ],
                },
            }),
        )
        .await;
        // Informational notes alone (a service-wide wildcard) do not make a finding.
        create(
            &f,
            &owner,
            "policies",
            json!({
                "name": "Clean",
                "document": {
                    "version": 1,
                    "statements": [{ "effect": "allow", "actions": ["documents:*"], "resources": ["documents/*"] }],
                },
            }),
        )
        .await;
        create(
            &f,
            &owner,
            "roles",
            json!({
                "name": "Inline",
                "document": {
                    "version": 1,
                    "statements": [{
                        "effect": "deny",
                        "actions": ["documents:write"],
                        "resources": ["documents/*"],
                        "conditions": { "StringEquals": { "resource.type": "secret" } },
                    }],
                },
            }),
        )
        .await;
        create(
            &f,
            &owner,
            "roles",
            json!({ "name": "Plain", "permissions": ["documents:read"] }),
        )
        .await;

        let lint = of_kind(
            &findings(&f, &owner, json!({})).await.unwrap(),
            "policy-lint",
        );
        let mut subjects: Vec<String> = lint
            .iter()
            .map(|finding| {
                format!(
                    "{}:{}",
                    finding["subject"]["type"].as_str().unwrap(),
                    finding["subject"]["name"].as_str().unwrap()
                )
            })
            .collect();
        subjects.sort();
        assert_eq!(subjects, vec!["policy:Office network", "role:Inline"]);
        let policy = lint
            .iter()
            .find(|finding| finding["subject"]["type"] == json!("policy"))
            .unwrap();
        assert_matches(
            policy,
            json!({ "severity": "low", "title": "Policy Office network has 2 lint warnings" }),
        );
        assert!(
            policy["detail"]
                .as_str()
                .unwrap()
                .contains("unknown-context-key, array-key-string-operator")
        );
        let role = lint
            .iter()
            .find(|finding| finding["subject"]["type"] == json!("role"))
            .unwrap();
        assert_eq!(
            role["title"],
            json!("Role Inline's inline document has 2 lint warnings")
        );
        assert!(
            role["detail"]
                .as_str()
                .unwrap()
                .contains("optional-key-deny, unknown-context-key")
        );
    });
}

#[test]
#[ignore = "needs sod.ts sodViolations (another port unit)"]
fn reads_stored_trust_flags_as_roles_assume_enforces_them_fail_closed() {
    run(|| async {
        let f = organization(|_| {}).await;
        let role = create(
            &f,
            &f.owner_credential,
            "roles",
            json!({ "name": "Reader", "permissions": ["documents:read"] }),
        )
        .await;
        // A cross-tenant identity trust whose stored flags are then replaced (a null value removes one). The trust API
        // group belongs to another port unit, so the trust is written as `trust.create` stores it.
        let trust_with = |flags: Value| {
            let (f, role) = (&f, role.clone());
            async move {
                // As `trust.create` stores a cross-tenant identity trust with its defaults.
                let now = f.now();
                let trust = f
                    .insert(
                        "trusts",
                        json!({
                            "id": better_iam_server::utils::id(),
                            "tenantId": f.tenant_id,
                            "kind": "identity",
                            "sourceTenantId": f.root_tenant,
                            "sourceIdentityId": f.root_id,
                            "roleId": role["id"],
                            "requireMfa": true,
                            "ceiling": better_iam_server::utils::all_value(),
                            "revoked": false,
                            "passSourceAttributes": false,
                            "allowedTagKeys": [],
                            "sourceIdentityMode": "forbidden",
                            "createdAt": now,
                            "createdBy": f.root_id,
                            "updatedAt": now,
                        }),
                    )
                    .await;
                let trust_id = trust["id"].as_str().unwrap().to_owned();
                let id = trust_id.clone();
                f.store()
                    .transaction(|tx| async move {
                        let mut next = tx.get("trusts", &id).await?.expect("trust");
                        for (key, value) in flags.as_object().unwrap() {
                            if value.is_null() {
                                next.shift_remove(key);
                            } else {
                                next.insert(key.clone(), value.clone());
                            }
                        }
                        tx.put("trusts", &next).await
                    })
                    .await
                    .unwrap();
                trust_id
            }
        };
        let open = trust_with(json!({ "requireMfa": false, "passSourceAttributes": true })).await;
        let legacy = trust_with(json!({ "requireMfa": null, "passSourceAttributes": null })).await;
        let malformed =
            trust_with(json!({ "requireMfa": "no", "passSourceAttributes": "false" })).await;
        let falsy = trust_with(json!({ "requireMfa": 0, "passSourceAttributes": 1 })).await;
        let report = findings(&f, &f.owner_credential, json!({})).await.unwrap();
        let subjects = |kind: &str| {
            let mut ids: Vec<String> = of_kind(&report, kind)
                .iter()
                .map(|finding| finding["subject"]["id"].as_str().unwrap().to_owned())
                .collect();
            ids.sort();
            ids
        };
        // Only the boolean false waives MFA; a missing or malformed flag requires it, so no finding.
        assert_eq!(subjects("trust-without-mfa"), vec![open.clone()]);
        // Legacy trusts (no field) pass attributes; a malformed value passes nothing, so no finding.
        let mut passing = vec![open.clone(), legacy.clone()];
        passing.sort();
        assert_eq!(subjects("trust-passes-foreign-attributes"), passing);
        assert!(!subjects("trust-passes-foreign-attributes").contains(&malformed));
        assert!(!subjects("trust-without-mfa").contains(&falsy));
    });
}

// --- tests/policy-lint.test.ts: analysis.lintPolicy ---------------------------------------------------------------

fn doc(statements: Vec<Value>) -> Value {
    json!({ "version": 1, "statements": statements })
}

fn allow(extra: Value) -> Value {
    let mut statement =
        json!({ "effect": "allow", "actions": ["documents:read"], "resources": ["documents/*"] });
    for (key, value) in extra.as_object().unwrap() {
        statement[key] = value.clone();
    }
    statement
}

fn deny(extra: Value) -> Value {
    let mut statement = allow(extra.clone());
    statement["effect"] = json!("deny");
    for (key, value) in extra.as_object().unwrap() {
        statement[key] = value.clone();
    }
    statement
}

async fn lint(f: &Org, credential: &CredentialInput, input: Value) -> Result<Value, (String, u16)> {
    let mut input = input;
    input["tenantId"] = json!(f.tenant_id);
    f.iam
        .api
        .analysis
        .lint_policy(credential, body(input))
        .await
        .map(|reply| reply.into_value().unwrap())
        .map_err(|error| (error.code, error.status))
}

#[test]
fn lints_candidate_documents_and_stored_policies_with_the_tenant_catalog() {
    run(|| async {
        let f = organization(|options| {
            let mut attributes = IndexMap::new();
            attributes.insert("department".to_owned(), AttributeType::String);
            options.permissions = Some(PermissionsConfig {
                actions: Some(vec!["documents:read".into(), "documents:write".into()]),
                identity_attributes: Some(attributes),
                ..PermissionsConfig::default()
            });
        })
        .await;
        let owner = f.owner_credential.clone();
        let network = doc(vec![allow(
            json!({ "conditions": { "IpAddress": { "request.ip": "10.0.0.0/8" } } }),
        )]);

        let candidate = lint(&f, &owner, json!({ "document": network }))
            .await
            .unwrap();
        assert_eq!(candidate["valid"], json!(true));
        assert_eq!(candidate["warnings"].as_array().unwrap().len(), 1);
        assert_matches(
            &candidate["warnings"][0],
            json!({ "code": "unknown-context-key", "statement": 0 }),
        );
        // Keys the application supplies are declared per call; identity attributes come from configuration.
        assert_eq!(
            lint(
                &f,
                &owner,
                json!({ "document": network, "contextKeys": ["request.ip"] })
            )
            .await
            .unwrap(),
            json!({ "valid": true, "warnings": [] })
        );
        assert_eq!(
            lint(
                &f,
                &owner,
                json!({
                    "document": doc(vec![allow(json!({
                        "conditions": { "StringEquals": { "principal.department": "x" } },
                    }))]),
                })
            )
            .await
            .unwrap(),
            json!({ "valid": true, "warnings": [] })
        );

        let stored = create(
            &f,
            &owner,
            "policies",
            json!({ "name": "Office network", "document": network }),
        )
        .await;
        assert_eq!(
            lint(&f, &owner, json!({ "policyId": stored["id"] }))
                .await
                .unwrap(),
            candidate
        );
        assert_eq!(
            lint(&f, &owner, json!({ "policyId": "no-such-policy" }))
                .await
                .unwrap_err()
                .0,
            "NOT_FOUND"
        );

        // Structural and catalog validation turn into an invalid result without warnings. Catalog validation runs
        // first, so a document naming unknown actions is rejected before any pattern matching.
        let invalid = lint(&f, &owner, json!({ "document": { "version": 1 } }))
            .await
            .unwrap();
        assert_matches(
            &invalid,
            json!({ "valid": false, "error": { "code": "INVALID_POLICY" }, "warnings": [] }),
        );
        assert_eq!(
            lint(
                &f,
                &owner,
                json!({
                    "document": doc(vec![allow(json!({
                        "actions": ["documents:delete"],
                        "conditions": { "IpAddress": { "request.ip": "10.0.0.0/8" } },
                    }))]),
                })
            )
            .await
            .unwrap(),
            json!({
                "valid": false,
                "error": { "code": "INVALID_ACTION", "message": "Unknown action documents:delete" },
                "warnings": [],
            })
        );
        let mut statements: Vec<Value> = (0..29)
            .map(|_| allow(json!({ "actions": vec!["x"; 128], "resources": vec!["x"; 128] })))
            .collect();
        statements.push(deny(json!({ "actions": ["*"], "resources": ["*"] })));
        assert_eq!(
            lint(&f, &owner, json!({ "document": doc(statements) }))
                .await
                .unwrap(),
            json!({
                "valid": false,
                "error": { "code": "INVALID_ACTION", "message": "Unknown action x" },
                "warnings": [],
            })
        );

        // Exactly one of document and policyId.
        assert_eq!(
            lint(&f, &owner, json!({})).await.unwrap_err().0,
            "INVALID_INPUT"
        );
        assert_eq!(
            lint(
                &f,
                &owner,
                json!({ "document": network, "policyId": stored["id"] })
            )
            .await
            .unwrap_err()
            .0,
            "INVALID_INPUT"
        );

        // Members without iam:policies:read cannot lint.
        let bob = f.member("bob").await;
        let bob = f.sign_in(&bob).await;
        assert_eq!(
            lint(&f, &bob, json!({ "document": network }))
                .await
                .unwrap_err(),
            ("ACCESS_DENIED".to_owned(), 403)
        );
        assert_eq!(
            lint(&f, &bob, json!({ "policyId": stored["id"] }))
                .await
                .unwrap_err()
                .1,
            403
        );
    });
}

fn hostile_document() -> Value {
    let mut statements: Vec<Value> = (0..29)
        .map(|_| allow(json!({ "actions": vec!["?"; 128], "resources": vec!["documents/x"; 128] })))
        .collect();
    statements
        .extend((0..58).map(|_| deny(json!({ "actions": vec!["??"; 128], "resources": ["*"] }))));
    statements.push(deny(json!({ "actions": ["*"], "resources": ["*"] })));
    doc(statements)
}

#[test]
fn lints_stored_policies_full_of_wildcard_patterns_quickly() {
    run(|| async {
        let f = organization(|_| {}).await;
        let owner = f.owner_credential.clone();
        // Wildcard actions pass catalog validation, so only the linter's own bounds keep this cheap.
        let hostile = create(
            &f,
            &owner,
            "policies",
            json!({ "name": "Hostile", "document": hostile_document() }),
        )
        .await;
        let started = std::time::Instant::now();
        let linted = lint(&f, &owner, json!({ "policyId": hostile["id"] }))
            .await
            .unwrap();
        let shadowed = linted["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|warning| warning["code"] == json!("shadowed-allow"))
            .count();
        assert_eq!(shadowed, 29);
        // Debug builds are slower than the TypeScript bound (3 s); the check is that the linter stays bounded.
        assert!(started.elapsed().as_secs_f64() < 30.0);
    });
}

#[test]
#[ignore = "needs sod.ts sodViolations (another port unit)"]
fn lints_stored_policies_full_of_wildcard_patterns_quickly_in_findings_too() {
    run(|| async {
        let f = organization(|_| {}).await;
        let owner = f.owner_credential.clone();
        let hostile = create(
            &f,
            &owner,
            "policies",
            json!({ "name": "Hostile", "document": hostile_document() }),
        )
        .await;
        let started = std::time::Instant::now();
        let report = findings(&f, &owner, json!({})).await.unwrap();
        assert!(
            report["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| {
                    finding["kind"] == json!("policy-lint")
                        && finding["subject"]["id"] == hostile["id"]
                })
        );
        assert!(started.elapsed().as_secs_f64() < 30.0);
    });
}

#[test]
fn checks_resource_attributes_against_platform_and_tenant_resource_types_without_a_resolver() {
    run(|| async {
        let f = organization(|options| {
            options.resolve_resource = None;
            let mut folder_attributes = IndexMap::new();
            folder_attributes.insert("classification".to_owned(), AttributeType::String);
            let mut resource_types = IndexMap::new();
            resource_types.insert(
                "folder".to_owned(),
                ResourceTypeDefinition {
                    managed: Some(true),
                    actions: Some(vec!["folders:read".into()]),
                    attributes: Some(folder_attributes),
                    ..ResourceTypeDefinition::default()
                },
            );
            options.permissions = Some(PermissionsConfig {
                mode: Some(PermissionsMode::TenantDefined),
                actions: Some(vec!["documents:read".into(), "documents:write".into()]),
                resource_types: Some(resource_types),
                ..PermissionsConfig::default()
            });
        })
        .await;
        let owner = f.owner_credential.clone();
        ok(f.iam
            .api
            .resource_types
            .register(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "ticket",
                    "actions": ["read"],
                    "attributes": { "priority": "number" },
                })),
            )
            .await);
        let result = lint(
            &f,
            &owner,
            json!({
                "document": doc(vec![allow(json!({
                    "actions": ["folders:read", "ticket:read"],
                    "resources": ["folder/*", "ticket/*"],
                    "conditions": {
                        "StringEquals": { "resource.classification": "secret", "resource.size": "large" },
                        "NumericGreaterThan": { "resource.priority": 2 },
                        "Exists": { "resource.parentId": true },
                    },
                }))]),
            }),
        )
        .await
        .unwrap();
        assert_eq!(result["valid"], json!(true));
        let warnings = result["warnings"].as_array().unwrap();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0]["code"], json!("unknown-context-key"));
        assert!(
            warnings[0]["message"]
                .as_str()
                .unwrap()
                .contains("resource.size")
        );
    });
}
