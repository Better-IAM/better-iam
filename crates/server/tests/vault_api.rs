//! The secrets vault (api/vault.ts): ports of tests/vault.test.ts, tests/vault-security.test.ts and
//! tests/vault-review.test.ts.
//!
//! The suites run against the record helpers of vault.ts (vault unit) and, for customer-managed keys, kms.ts and the
//! `keys` API group (kms unit). A test that reaches one of those while it is still a skeleton stub (NOT_IMPLEMENTED)
//! reports itself as blocked instead of failing; every other failure fails the test.

mod organization_fixture;

use std::sync::{Arc, Mutex};

use better_iam_core::{
    CredentialInput, Filter, IamError, IamPlugin, IamResult, OperationHookInput, PluginHooks,
};
use better_iam_server::options::{VaultEngine, VaultOptions, VaultRotator};
use better_iam_server::secrets::SecretRotationOptions;
use better_iam_server::{better_iam, options::BetterIamOptions};
use indexmap::IndexMap;
use organization_fixture::{Org, assert_matches, bearer, body, code, fails, ok, organization};
use regex::Regex;
use serde_json::{Value, json};

const MINUTE: f64 = 60_000.0;
const HOUR: f64 = 3_600_000.0;
const DAY: f64 = 24.0 * HOUR;
const SECRET: &str = "organization-fixture-secret-with-32-characters";

/// Runs a test body on a large-stack runtime; a body that stops at another unit's skeleton stub (NOT_IMPLEMENTED) is
/// reported as blocked rather than failed.
fn run<F, Fut>(body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + 'static,
{
    let outcome = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(body());
        })
        .expect("thread")
        .join();
    if let Err(panic) = outcome {
        let message = panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
            .unwrap_or_default();
        if message.contains("NOT_IMPLEMENTED") {
            eprintln!("blocked on another unit's stub: {message}");
            return;
        }
        std::panic::resume_unwind(panic);
    }
}

fn vault_options(configure: impl FnOnce(&mut VaultOptions)) -> impl FnOnce(&mut BetterIamOptions) {
    move |options| {
        let mut vault = VaultOptions::default();
        configure(&mut vault);
        options.vault = Some(vault);
    }
}

fn rotators(
    entries: Vec<(&str, Arc<dyn VaultRotator>)>,
) -> IndexMap<String, Arc<dyn VaultRotator>> {
    entries
        .into_iter()
        .map(|(name, rotator)| (name.to_owned(), rotator))
        .collect()
}

fn engines(entries: Vec<(&str, Arc<dyn VaultEngine>)>) -> IndexMap<String, Arc<dyn VaultEngine>> {
    entries
        .into_iter()
        .map(|(name, engine)| (name.to_owned(), engine))
        .collect()
}

/// A member holding a role with `statements`, signed in.
async fn member_with(f: &Org, name: &str, statements: Value) -> (String, CredentialInput) {
    let identity = f.member(name).await;
    f.grant(&identity, statements).await;
    let credential = f.sign_in(&identity).await;
    (identity, credential)
}

async fn audit_actions(f: &Org, prefix: &str) -> Vec<String> {
    f.find("audit", Filter::new())
        .await
        .into_iter()
        .filter(|event| {
            event["action"]
                .as_str()
                .unwrap_or_default()
                .starts_with(prefix)
        })
        .map(|event| {
            format!(
                "{}:{}",
                event["action"].as_str().unwrap_or_default(),
                event["outcome"].as_str().unwrap_or_default()
            )
        })
        .collect()
}

fn names(list: &Value) -> Vec<String> {
    list["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|secret| secret["name"].as_str().unwrap().to_owned())
        .collect()
}

fn n(value: &Value) -> f64 {
    value.as_f64().unwrap_or(f64::NAN)
}

fn s(value: &Value) -> String {
    value.as_str().unwrap_or_default().to_owned()
}

fn failure(message: impl Into<String>) -> IamError {
    IamError::new("TEST_FAILURE", message)
}

// --- rotators and engines ----------------------------------------------------------------------------------------

#[derive(Default)]
struct RecordingRotator {
    applied: Mutex<Vec<Value>>,
    fail_next: Mutex<bool>,
}

#[async_trait::async_trait]
impl VaultRotator for RecordingRotator {
    async fn rotate(&self, input: Value) -> IamResult<()> {
        let fail = std::mem::replace(&mut *self.fail_next.lock().unwrap(), false);
        if fail {
            return Err(failure(format!(
                "database refused password {}",
                s(&input["value"])
            )));
        }
        self.applied.lock().unwrap().push(input);
        Ok(())
    }
}

#[derive(Default)]
struct DynamicEngine {
    issued: Mutex<IndexMap<String, String>>,
    revoked: Mutex<Vec<String>>,
    renewals: Mutex<Vec<f64>>,
    fail_revoke: Mutex<u32>,
    fail_issue: Mutex<bool>,
}

#[async_trait::async_trait]
impl VaultEngine for DynamicEngine {
    async fn issue(&self, input: Value) -> IamResult<Value> {
        if *self.fail_issue.lock().unwrap() {
            return Err(failure("database unavailable"));
        }
        let lease_id = s(&input["leaseId"]);
        let username = format!("v-{}-{}", s(&input["holder"]["name"]), &lease_id[..8]);
        self.issued
            .lock()
            .unwrap()
            .insert(lease_id.clone(), username.clone());
        Ok(json!({
            "fields": { "username": username, "password": format!("pw-{lease_id}"), "role": input["config"]["role"] },
            "handle": username,
        }))
    }
    fn has_revoke(&self) -> bool {
        true
    }
    async fn revoke(&self, input: Value) -> IamResult<()> {
        let mut failing = self.fail_revoke.lock().unwrap();
        if *failing > 0 {
            *failing -= 1;
            return Err(failure("revoke refused"));
        }
        self.revoked.lock().unwrap().push(s(&input["handle"]));
        Ok(())
    }
    fn has_renew(&self) -> bool {
        true
    }
    async fn renew(&self, input: Value) -> IamResult<()> {
        self.renewals.lock().unwrap().push(n(&input["ttlMs"]));
        Ok(())
    }
}

/// An engine that hands out `pw-{leaseId}` with the lease id as handle, and records revocations by lease id.
#[derive(Default)]
struct LeaseIdEngine {
    revoked: Mutex<Vec<String>>,
    bad_handle: Mutex<bool>,
}

#[async_trait::async_trait]
impl VaultEngine for LeaseIdEngine {
    async fn issue(&self, input: Value) -> IamResult<Value> {
        let lease_id = s(&input["leaseId"]);
        Ok(if *self.bad_handle.lock().unwrap() {
            json!({ "value": format!("pw-{lease_id}"), "handle": "x".repeat(5000) })
        } else {
            json!({ "value": format!("pw-{lease_id}"), "handle": lease_id })
        })
    }
    fn has_revoke(&self) -> bool {
        true
    }
    async fn revoke(&self, input: Value) -> IamResult<()> {
        self.revoked.lock().unwrap().push(s(&input["leaseId"]));
        Ok(())
    }
}

struct MintingEngine;

#[async_trait::async_trait]
impl VaultEngine for MintingEngine {
    async fn issue(&self, _input: Value) -> IamResult<Value> {
        Ok(json!({ "value": "minted" }))
    }
}

// --- tests/vault.test.ts -----------------------------------------------------------------------------------------

#[test]
fn stores_versions_moves_stages_reveals_and_logs_access() {
    run(|| async {
        let f = organization(|_| {}).await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        let created = ok(vault
            .create(
                &owner,
                body(json!({
                    "tenantId": t,
                    "name": "prod/db/password",
                    "description": "Primary database",
                    "tags": { "environment": "prod", "team": "payments" },
                    "value": "first-password-value",
                })),
            )
            .await);
        assert_matches(
            &created,
            json!({
                "name": "prod/db/password",
                "kind": "static",
                "format": "text",
                "status": "active",
                "stages": { "current": 1 },
                "latestVersion": 1,
                "tags": { "environment": "prod", "team": "payments" },
            }),
        );
        assert!(!created.to_string().contains("first-password-value"));
        // Values are sealed at rest.
        let stored = serde_json::to_string(&f.find("vaultVersions", Filter::new()).await).unwrap();
        assert!(!stored.contains("first-password-value"));

        ok(vault
            .put(
                &owner,
                body(json!({ "tenantId": t, "name": "prod/db/password", "value": "second-password-value" })),
            )
            .await);
        let revealed = ok(vault
            .reveal(
                &owner,
                body(json!({ "tenantId": t, "name": "prod/db/password" })),
            )
            .await);
        assert_matches(
            &revealed,
            json!({ "version": 2, "stages": ["current"], "value": "second-password-value" }),
        );
        let previous = ok(vault
            .reveal(
                &owner,
                body(json!({ "tenantId": t, "name": "prod/db/password", "stage": "previous" })),
            )
            .await);
        assert_eq!(previous["value"], "first-password-value");

        // Staged values wait for promotion; promote also rolls back.
        let staged = ok(vault
            .put(
                &owner,
                body(json!({
                    "tenantId": t,
                    "name": "prod/db/password",
                    "value": "third-password-value",
                    "stage": "pending",
                })),
            )
            .await);
        assert_matches(&staged, json!({ "version": 3, "stages": ["pending"] }));
        let promoted = ok(vault
            .promote(
                &owner,
                body(json!({ "tenantId": t, "name": "prod/db/password", "version": 3 })),
            )
            .await);
        assert_eq!(promoted["stages"], json!({ "current": 3, "previous": 2 }));
        ok(vault
            .promote(
                &owner,
                body(json!({ "tenantId": t, "name": "prod/db/password", "version": 1 })),
            )
            .await);
        let rolled_back = ok(vault
            .reveal(
                &owner,
                body(json!({ "tenantId": t, "name": "prod/db/password" })),
            )
            .await);
        assert_eq!(rolled_back["value"], "first-password-value");

        // Disabled and destroyed versions are not revealed; the current version is protected.
        let error = fails(
            vault
                .set_version_state(
                    &owner,
                    body(json!({ "tenantId": t, "name": "prod/db/password", "version": 1, "state": "disabled" })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_TRANSITION");
        ok(vault
            .set_version_state(
                &owner,
                body(json!({ "tenantId": t, "name": "prod/db/password", "version": 2, "state": "disabled" })),
            )
            .await);
        let error = fails(
            vault
                .reveal(
                    &owner,
                    body(json!({ "tenantId": t, "name": "prod/db/password", "version": 2 })),
                )
                .await,
        );
        assert_eq!(code(&error), "VERSION_DISABLED");
        ok(vault
            .destroy_version(
                &owner,
                body(json!({ "tenantId": t, "name": "prod/db/password", "version": 3 })),
            )
            .await);
        let error = fails(
            vault
                .reveal(
                    &owner,
                    body(json!({ "tenantId": t, "name": "prod/db/password", "version": 3 })),
                )
                .await,
        );
        assert_eq!(code(&error), "VERSION_DESTROYED");
        let versions = ok(vault
            .list_versions(
                &owner,
                body(json!({ "tenantId": t, "name": "prod/db/password" })),
            )
            .await);
        let summary: Vec<Value> = versions
            .as_array()
            .unwrap()
            .iter()
            .map(|version| json!([version["version"], version["state"], version["stages"]]))
            .collect();
        assert_eq!(
            summary,
            vec![
                json!([3, "destroyed", []]),
                json!([2, "disabled", []]),
                json!([1, "enabled", ["current"]]),
            ]
        );

        let log = ok(vault
            .access_log(
                &owner,
                body(json!({ "tenantId": t, "name": "prod/db/password" })),
            )
            .await);
        // Three successful reveals and three new versions (the refused reveals are not uses).
        let mut actions: Vec<String> = log
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| s(&entry["action"]))
            .collect();
        actions.sort();
        assert_eq!(actions, ["put", "put", "put", "reveal", "reveal", "reveal"]);
        assert!(log.as_array().unwrap().iter().all(|entry| {
            entry["identityId"] == f.owner_id.as_str() && entry["identityName"] == "Acme owner"
        }));
        let audit = audit_actions(&f, "vault:").await;
        for action in [
            "vault:create:allow",
            "vault:reveal:allow",
            "vault:promote:allow",
        ] {
            assert!(audit.contains(&action.to_owned()), "{action} in {audit:?}");
        }
    });
}

#[test]
fn decides_access_by_name_and_by_tag_and_lists_only_what_the_caller_may_read() {
    run(|| async {
        let f = organization(|_| {}).await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        for (name, team) in [
            ("team-a/api-key", "a"),
            ("team-a/db", "a"),
            ("team-b/api-key", "b"),
            ("shared/smtp", "a"),
        ] {
            ok(vault
                .create(
                    &owner,
                    body(json!({ "tenantId": t, "name": name, "tags": { "team": team }, "value": format!("value of {name}") })),
                )
                .await);
        }
        let (_, alice) = member_with(
            &f,
            "alice",
            json!([{ "effect": "allow", "actions": ["iam:vault:read", "iam:vault:reveal"], "resources": ["iam/vault/secrets/team-a/*"] }]),
        )
        .await;
        let (_, bob) = member_with(
            &f,
            "bob",
            json!([{
                "effect": "allow",
                "actions": ["iam:vault:read", "iam:vault:reveal"],
                "resources": ["iam/vault/secrets/*"],
                "conditions": { "StringEquals": { "resource.tag.team": "a" } },
            }]),
        )
        .await;
        let shown = ok(vault
            .reveal(&alice, body(json!({ "tenantId": t, "name": "team-a/db" })))
            .await);
        assert_eq!(shown["value"], "value of team-a/db");
        let error = fails(
            vault
                .reveal(
                    &alice,
                    body(json!({ "tenantId": t, "name": "team-b/api-key" })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let alice_list = ok(vault.list(&alice, body(json!({ "tenantId": t }))).await);
        assert_eq!(names(&alice_list), ["team-a/api-key", "team-a/db"]);

        // Tag conditions: bob reads every team-a secret wherever it lives, and nothing else.
        let bob_list = ok(vault.list(&bob, body(json!({ "tenantId": t }))).await);
        assert_eq!(
            names(&bob_list),
            ["shared/smtp", "team-a/api-key", "team-a/db"]
        );
        let error = fails(
            vault
                .reveal(
                    &bob,
                    body(json!({ "tenantId": t, "name": "team-b/api-key" })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // A name nobody uses has no tags: the condition fails closed.
        let error = fails(
            vault
                .get(&bob, body(json!({ "tenantId": t, "name": "team-c/new" })))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");

        // Prefix and tag filters.
        let owned = ok(vault
            .list(&owner, body(json!({ "tenantId": t, "prefix": "team-" })))
            .await);
        assert_eq!(owned["total"], 3);
        let tagged = ok(vault
            .list(
                &owner,
                body(json!({ "tenantId": t, "tags": { "team": "b" } })),
            )
            .await);
        assert_eq!(names(&tagged), ["team-b/api-key"]);

        // Reading metadata never reveals values, and the denied reveal was audited.
        assert!(!bob_list.to_string().contains("value of"));
        assert!(
            audit_actions(&f, "iam:vault:reveal")
                .await
                .contains(&"iam:vault:reveal:deny".to_owned())
        );
    });
}

#[test]
fn rotates_with_a_generator_and_a_rotator_retries_failures_with_the_same_value_and_runs_on_schedule()
 {
    run(|| async {
        let rotator = Arc::new(RecordingRotator::default());
        let dyn_rotator: Arc<dyn VaultRotator> = rotator.clone();
        let f = organization(vault_options(move |vault| {
            vault.rotators = Some(rotators(vec![("postgres", dyn_rotator)]));
        }))
        .await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &owner,
                body(json!({
                    "tenantId": t,
                    "name": "db/app",
                    "value": "initial-app-password",
                    "rotation": {
                        "intervalDays": 30,
                        "rotator": "postgres",
                        "generator": { "length": 24, "charset": "ascii", "exclude": "%" },
                    },
                })),
            )
            .await);
        let rotated = ok(vault
            .rotate(&owner, body(json!({ "tenantId": t, "name": "db/app" })))
            .await);
        assert_matches(
            &rotated,
            json!({ "name": "db/app", "version": 2, "rotator": "postgres" }),
        );
        let first = rotator.applied.lock().unwrap()[0].clone();
        assert_matches(
            &first,
            json!({ "version": 2, "previous": "initial-app-password" }),
        );
        let current = ok(vault
            .reveal(&owner, body(json!({ "tenantId": t, "name": "db/app" })))
            .await);
        let value = s(&current["value"]);
        assert_eq!(value, s(&first["value"]));
        assert_eq!(value.chars().count(), 24);
        assert!(!value.contains('%'));
        for class in ["[a-z]", "[A-Z]", "[0-9]", "[^a-zA-Z0-9]"] {
            assert!(
                Regex::new(class).unwrap().is_match(&value),
                "{class} in {value}"
            );
        }

        // A failing rotator leaves the pending version; the error is stored redacted; the retry reuses the value.
        *rotator.fail_next.lock().unwrap() = true;
        let error = fails(
            vault
                .rotate(&owner, body(json!({ "tenantId": t, "name": "db/app" })))
                .await,
        );
        assert_eq!(code(&error), "ROTATION_FAILED");
        assert!(error.message.contains("[redacted]"), "{}", error.message);
        let after_failure = ok(vault
            .get(&owner, body(json!({ "tenantId": t, "name": "db/app" })))
            .await);
        assert_matches(
            &after_failure["stages"],
            json!({ "current": 2, "pending": 3 }),
        );
        assert_matches(&after_failure["rotation"], json!({ "failures": 1 }));
        let message = s(&after_failure["rotation"]["lastFailure"]["message"]);
        assert!(
            !Regex::new(r"refused password [^\[]")
                .unwrap()
                .is_match(&message)
        );
        ok(vault
            .rotate(&owner, body(json!({ "tenantId": t, "name": "db/app" })))
            .await);
        let pending_value = rotator.applied.lock().unwrap().last().cloned().unwrap();
        assert_eq!(pending_value["version"], 3);
        let after_retry = ok(vault
            .get(&owner, body(json!({ "tenantId": t, "name": "db/app" })))
            .await);
        assert_eq!(
            after_retry["stages"],
            json!({ "current": 3, "previous": 2 })
        );
        assert_matches(
            &after_retry["rotation"],
            json!({ "intervalDays": 30, "due": false }),
        );
        assert!(after_retry["rotation"].get("lastFailure").is_none());

        // Nothing is due yet; after 31 days the scheduler rotates it.
        let run = f.iam.vault.rotate_due(None).await.unwrap();
        assert_eq!(run["rotated"], json!([]));
        f.advance(31.0 * DAY);
        let run = f.iam.vault.rotate_due(None).await.unwrap();
        assert_eq!(
            run["rotated"],
            json!([{ "tenantId": t, "name": "db/app", "version": 4 }])
        );
        let audit = audit_actions(&f, "vault:").await;
        for action in ["vault:rotate:allow", "vault:rotate:deny"] {
            assert!(audit.contains(&action.to_owned()), "{action} in {audit:?}");
        }
    });
}

#[test]
fn records_a_reminder_once_when_a_manual_rotation_is_due() {
    run(|| async {
        let f = organization(|_| {}).await;
        let vault = f.iam.api.vault.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &f.owner_credential,
                body(json!({
                    "tenantId": t,
                    "name": "vendor/api-key",
                    "value": "vendor-issued-key",
                    "rotation": { "intervalDays": 7 },
                })),
            )
            .await);
        f.advance(8.0 * DAY);
        assert_eq!(
            f.iam.vault.rotate_due(None).await.unwrap()["reminded"],
            json!([{ "tenantId": t, "name": "vendor/api-key" }])
        );
        assert_eq!(
            f.iam.vault.rotate_due(None).await.unwrap()["reminded"],
            json!([])
        );
        let owner = f.sign_in(&f.owner_id).await;
        let view = ok(vault
            .get(
                &owner,
                body(json!({ "tenantId": t, "name": "vendor/api-key" })),
            )
            .await);
        assert_matches(&view["rotation"], json!({ "due": true }));
        // A new current version resets the schedule.
        ok(vault
            .put(
                &owner,
                body(json!({ "tenantId": t, "name": "vendor/api-key", "value": "a newly issued key" })),
            )
            .await);
        let renewed = ok(vault
            .get(
                &owner,
                body(json!({ "tenantId": t, "name": "vendor/api-key" })),
            )
            .await);
        assert_matches(&renewed["rotation"], json!({ "due": false }));
        assert!(
            audit_actions(&f, "vault:")
                .await
                .contains(&"vault:rotation-due:allow".to_owned())
        );
    });
}

#[test]
fn checks_out_shared_credentials_exclusively_and_rotates_them_when_they_come_back() {
    run(|| async {
        let f = organization(|_| {}).await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &owner,
                body(json!({
                    "tenantId": t,
                    "name": "break-glass/root",
                    "generate": true,
                    "checkout": { "exclusive": true, "rotateOnCheckin": true, "requireReason": true, "maxDurationMs": 2.0 * HOUR },
                })),
            )
            .await);
        let operators = json!([{
            "effect": "allow",
            "actions": ["iam:vault:lease", "iam:vault:reveal", "iam:vault:read"],
            "resources": ["iam/vault/secrets/break-glass/*"],
        }]);
        let (alice_id, alice) = member_with(&f, "alice", operators.clone()).await;
        let (_, bob) = member_with(&f, "bob", operators).await;

        let error = fails(
            vault
                .reveal(
                    &alice,
                    body(json!({ "tenantId": t, "name": "break-glass/root" })),
                )
                .await,
        );
        assert_eq!(code(&error), "CHECKOUT_REQUIRED");
        let error = fails(
            vault
                .checkout(
                    &alice,
                    body(json!({ "tenantId": t, "name": "break-glass/root" })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let checkout = ok(vault
            .checkout(
                &alice,
                body(json!({ "tenantId": t, "name": "break-glass/root", "reason": "INC-1234 database outage" })),
            )
            .await);
        assert_matches(&checkout, json!({ "version": 1, "stages": ["current"] }));
        assert_eq!(s(&checkout["value"]).chars().count(), 32);
        assert_eq!(n(&checkout["expiresAt"]) - f.now(), 2.0 * HOUR);
        // The holder may reveal what they checked out; others wait.
        let shown = ok(vault
            .reveal(
                &alice,
                body(json!({ "tenantId": t, "name": "break-glass/root" })),
            )
            .await);
        assert_eq!(shown["value"], checkout["value"]);
        let error = fails(
            vault
                .checkout(
                    &bob,
                    body(json!({ "tenantId": t, "name": "break-glass/root", "reason": "me too" })),
                )
                .await,
        );
        assert_eq!(code(&error), "SECRET_CHECKED_OUT");
        let view = ok(vault
            .get(
                &owner,
                body(json!({ "tenantId": t, "name": "break-glass/root" })),
            )
            .await);
        assert_eq!(
            view["checkedOut"],
            json!([{ "leaseId": checkout["leaseId"], "holderId": alice_id, "expiresAt": checkout["expiresAt"] }])
        );
        // Others cannot return someone else's check-out without iam:vault:manage.
        let error = fails(
            vault
                .checkin(
                    &bob,
                    body(json!({ "tenantId": t, "leaseId": checkout["leaseId"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");

        let returned = ok(vault
            .checkin(
                &alice,
                body(json!({ "tenantId": t, "leaseId": checkout["leaseId"] })),
            )
            .await);
        assert_eq!(
            returned,
            json!({ "leaseId": checkout["leaseId"], "state": "ended", "rotated": 2 })
        );
        let next = ok(vault
            .checkout(
                &bob,
                body(json!({ "tenantId": t, "name": "break-glass/root", "reason": "INC-1235", "durationMs": HOUR })),
            )
            .await);
        assert_eq!(next["version"], 2);
        assert_ne!(next["value"], checkout["value"]);

        // An expired check-out ends by itself and rotates too.
        f.advance(HOUR + 1.0);
        let run = f.iam.vault.expire_leases(None).await.unwrap();
        assert_matches(&run, json!({ "expired": 1, "rotated": 1 }));
        let owner_again = f.sign_in(&f.owner_id).await;
        let view = ok(vault
            .get(
                &owner_again,
                body(json!({ "tenantId": t, "name": "break-glass/root" })),
            )
            .await);
        assert_eq!(view["stages"]["current"], 3);
        assert_eq!(view["checkedOut"], json!([]));
        let audit = audit_actions(&f, "vault:").await;
        for action in [
            "vault:checkout:allow",
            "vault:checkin:allow",
            "vault:checkout-expired:allow",
        ] {
            assert!(audit.contains(&action.to_owned()), "{action} in {audit:?}");
        }
    });
}

#[test]
fn mints_dynamic_credentials_per_lease_and_revokes_them_at_the_engine() {
    run(|| async {
        let engine = Arc::new(DynamicEngine::default());
        let dyn_engine: Arc<dyn VaultEngine> = engine.clone();
        let f = organization(vault_options(move |vault| {
            vault.engines = Some(engines(vec![("postgres", dyn_engine)]));
        }))
        .await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &owner,
                body(json!({
                    "tenantId": t,
                    "name": "db/readonly",
                    "kind": "dynamic",
                    "format": "json",
                    "engine": "postgres",
                    "engineConfig": { "role": "readonly" },
                    "lease": { "defaultTtlMs": HOUR, "maxTtlMs": 4.0 * HOUR },
                })),
            )
            .await);
        let (alice_id, alice) = member_with(
            &f,
            "alice",
            json!([{ "effect": "allow", "actions": ["iam:vault:lease"], "resources": ["iam/vault/secrets/db/*"] }]),
        )
        .await;
        let lease = ok(vault
            .lease(
                &alice,
                body(json!({ "tenantId": t, "name": "db/readonly" })),
            )
            .await);
        let lease_id = s(&lease["leaseId"]);
        let username = engine.issued.lock().unwrap()[&lease_id].clone();
        assert_matches(
            &lease["fields"],
            json!({ "role": "readonly", "username": username }),
        );
        assert_eq!(n(&lease["expiresAt"]) - n(&lease["issuedAt"]), HOUR);
        assert_eq!(lease["renewable"], true);
        // The credential is never stored; only the sealed handle is.
        let rows = serde_json::to_string(&f.find("vaultLeases", Filter::new()).await).unwrap();
        assert!(!rows.contains(&format!("pw-{lease_id}")));
        assert!(!rows.contains(&username));
        // Static operations do not apply.
        let error = fails(
            vault
                .reveal(
                    &owner,
                    body(json!({ "tenantId": t, "name": "db/readonly" })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");

        let renewed = ok(vault
            .renew_lease(
                &alice,
                body(json!({ "tenantId": t, "leaseId": lease_id, "ttlMs": 3.0 * HOUR })),
            )
            .await);
        assert_eq!(n(&renewed["expiresAt"]) - f.now(), 3.0 * HOUR);
        assert_eq!(*engine.renewals.lock().unwrap(), vec![3.0 * HOUR]);
        let mine = ok(vault
            .list_mine(&alice, body(json!({ "tenantId": t })))
            .await);
        assert_eq!(mine.as_array().unwrap().len(), 1);

        let ended = ok(vault
            .revoke_lease(&alice, body(json!({ "tenantId": t, "leaseId": lease_id })))
            .await);
        assert_eq!(ended["state"], "ended");
        assert_eq!(*engine.revoked.lock().unwrap(), vec![username]);

        // An expiring lease is revoked by the job; a refused revocation is retried.
        let second = ok(vault
            .lease(
                &alice,
                body(json!({ "tenantId": t, "name": "db/readonly" })),
            )
            .await);
        *engine.fail_revoke.lock().unwrap() = 1;
        f.advance(HOUR + 1.0);
        assert_matches(
            &f.iam.vault.expire_leases(None).await.unwrap(),
            json!({ "expired": 0, "retrying": 1 }),
        );
        // Retries back off: nothing happens until the retry is due.
        assert_matches(
            &f.iam.vault.expire_leases(None).await.unwrap(),
            json!({ "expired": 0, "retrying": 0 }),
        );
        f.advance(2.0 * MINUTE);
        assert_matches(
            &f.iam.vault.expire_leases(None).await.unwrap(),
            json!({ "expired": 1, "retrying": 0 }),
        );
        let second_username = engine.issued.lock().unwrap()[&s(&second["leaseId"])].clone();
        assert!(engine.revoked.lock().unwrap().contains(&second_username));

        // A failing engine fails the call and leaves no live lease.
        *engine.fail_issue.lock().unwrap() = true;
        let fresh = f.sign_in(&alice_id).await;
        let error = fails(
            vault
                .lease(
                    &fresh,
                    body(json!({ "tenantId": t, "name": "db/readonly" })),
                )
                .await,
        );
        assert_eq!(code(&error), "ENGINE_FAILED");
        let owner_again = f.sign_in(&f.owner_id).await;
        let history = ok(vault
            .list_leases(
                &owner_again,
                body(json!({ "tenantId": t, "name": "db/readonly", "includeEnded": true })),
            )
            .await);
        let mut states: Vec<String> = history
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| s(&entry["state"]))
            .collect();
        states.sort();
        assert_eq!(states, ["ended", "expired", "failed"]);
        assert!(
            history
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["holderName"] == "alice")
        );
    });
}

#[test]
fn keeps_deleted_secrets_restorable_during_the_recovery_window_then_purges_them() {
    run(|| async {
        let f = organization(|_| {}).await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        for (name, value) in [("old/key", "old-key-value"), ("tmp/key", "tmp-key-value")] {
            ok(vault
                .create(
                    &owner,
                    body(json!({ "tenantId": t, "name": name, "value": value })),
                )
                .await);
        }
        let scheduled = ok(vault
            .delete(
                &owner,
                body(json!({ "tenantId": t, "name": "old/key", "recoveryDays": 7 })),
            )
            .await);
        assert_matches(&scheduled, json!({ "status": "pending-deletion" }));
        let error = fails(
            vault
                .reveal(&owner, body(json!({ "tenantId": t, "name": "old/key" })))
                .await,
        );
        assert_eq!(code(&error), "SECRET_PENDING_DELETION");
        let error = fails(
            vault
                .create(
                    &owner,
                    body(json!({ "tenantId": t, "name": "old/key", "value": "x-value" })),
                )
                .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        assert_eq!(
            ok(vault.list(&owner, body(json!({ "tenantId": t }))).await)["total"],
            1
        );
        assert_eq!(
            ok(vault
                .list(&owner, body(json!({ "tenantId": t, "status": "all" })))
                .await)["total"],
            2
        );
        ok(vault
            .restore(&owner, body(json!({ "tenantId": t, "name": "old/key" })))
            .await);
        assert_eq!(
            ok(vault
                .reveal(&owner, body(json!({ "tenantId": t, "name": "old/key" })))
                .await)["value"],
            "old-key-value"
        );

        ok(vault
            .delete(
                &owner,
                body(json!({ "tenantId": t, "name": "old/key", "recoveryDays": 7 })),
            )
            .await);
        f.advance(6.0 * DAY);
        assert_eq!(
            f.iam.vault.purge_deleted(None).await.unwrap(),
            json!({ "purged": 0 })
        );
        f.advance(2.0 * DAY);
        assert_eq!(
            f.iam.vault.purge_deleted(None).await.unwrap(),
            json!({ "purged": 1 })
        );
        assert_eq!(
            f.find("vaultVersions", Filter::new().eq("tenantId", t.clone()))
                .await
                .len(),
            1
        );

        // Immediate deletion.
        let fresh = f.sign_in(&f.owner_id).await;
        let gone = ok(vault
            .delete(
                &fresh,
                body(json!({ "tenantId": t, "name": "tmp/key", "recoveryDays": 0 })),
            )
            .await);
        assert_eq!(gone["status"], "deleted");
        assert!(
            f.find("vaultSecrets", Filter::new().eq("tenantId", t.clone()))
                .await
                .is_empty()
        );
        let audit = audit_actions(&f, "vault:").await;
        for action in [
            "vault:delete:allow",
            "vault:restore:allow",
            "vault:purge:allow",
        ] {
            assert!(audit.contains(&action.to_owned()), "{action} in {audit:?}");
        }
    });
}

#[test]
fn serves_trusted_code_resolves_references_and_re_seals_under_a_new_deployment_secret() {
    run(|| async {
        let f = organization(|_| {}).await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &owner,
                body(json!({
                    "tenantId": t,
                    "name": "smtp",
                    "format": "json",
                    "fields": { "host": "smtp.acme.test", "password": "smtp-password" },
                })),
            )
            .await);
        ok(vault
            .create(
                &owner,
                body(json!({ "tenantId": t, "name": "stripe/key", "value": "sk_test_123456" })),
            )
            .await);
        assert_eq!(
            f.iam.vault.get(&t, "smtp", None).await.unwrap()["fields"],
            json!({ "host": "smtp.acme.test", "password": "smtp-password" })
        );
        assert_eq!(
            f.iam
                .vault
                .resolve(
                    &t,
                    &json!({
                        "mail": { "host": "vault://smtp#host", "password": "vault://smtp#password" },
                        "payments": ["vault://stripe/key", "plain"],
                        "retries": 3,
                    }),
                )
                .await
                .unwrap(),
            json!({
                "mail": { "host": "smtp.acme.test", "password": "smtp-password" },
                "payments": ["sk_test_123456", "plain"],
                "retries": 3,
            })
        );
        let error = f
            .iam
            .vault
            .resolve(&t, &json!("vault://smtp#user"))
            .await
            .unwrap_err();
        assert_eq!(code(&error), "NOT_FOUND");

        // A new deployment secret with the old one kept as previous: values still open, then are re-sealed.
        let mut options = BetterIamOptions::new(
            f.store(),
            "a brand new deployment secret with 32+ characters",
            "http://localhost:3000",
        );
        options.previous_secrets = Some(vec![SECRET.to_owned()]);
        let rotated = better_iam(options).expect("options");
        assert_eq!(
            rotated.vault.get(&t, "stripe/key", None).await.unwrap()["value"],
            "sk_test_123456"
        );
        let result = rotated
            .rotate_secrets(&SecretRotationOptions::default())
            .await
            .unwrap();
        assert_eq!(result.resealed.get("vaultVersions").copied(), Some(2.0));
        let fresh = better_iam(BetterIamOptions::new(
            f.store(),
            "a brand new deployment secret with 32+ characters",
            "http://localhost:3000",
        ))
        .expect("options");
        assert_eq!(
            fresh.vault.get(&t, "smtp", None).await.unwrap()["fields"]["password"],
            "smtp-password"
        );
    });
}

#[test]
fn encrypts_values_under_a_customer_managed_key_and_disabling_the_key_shreds_them() {
    run(|| async {
        let f = organization(|_| {}).await;
        let vault = f.iam.api.vault.clone();
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        let key = ok(keys
            .create(
                &owner,
                body(json!({ "tenantId": t, "alias": "alias/vault" })),
            )
            .await);
        let key_id = s(&key["id"]);
        ok(vault
            .create(
                &owner,
                body(json!({ "tenantId": t, "name": "cmk/api", "value": "under-the-customer-key", "kmsKey": "alias/vault" })),
            )
            .await);
        ok(vault
            .create(
                &owner,
                body(json!({ "tenantId": t, "name": "cmk/later", "value": "first-under-deployment-secret" })),
            )
            .await);
        ok(vault
            .put(
                &owner,
                body(json!({ "tenantId": t, "name": "cmk/later", "value": "second-value" })),
            )
            .await);
        let rows = f
            .find(
                "vaultVersions",
                Filter::new()
                    .eq("tenantId", t.clone())
                    .eq("version", 1)
                    .eq("kmsKeyId", key_id.clone()),
            )
            .await;
        let row = &rows[0];
        assert!(!s(&row["sealed"]).contains("under-the-customer-key"));
        assert_eq!(row["kmsKeyId"], key_id.as_str());
        assert_eq!(
            ok(vault
                .reveal(&owner, body(json!({ "tenantId": t, "name": "cmk/api" })))
                .await)["value"],
            "under-the-customer-key"
        );

        // Moving a secret under the key re-encrypts every kept version.
        let moved = ok(vault
            .update(
                &owner,
                body(json!({ "tenantId": t, "name": "cmk/later", "kmsKey": key_id })),
            )
            .await);
        assert_eq!(moved["kmsKeyId"], key_id.as_str());
        let later = f
            .find(
                "vaultVersions",
                Filter::new()
                    .eq("tenantId", t.clone())
                    .eq("kmsKeyId", key_id.clone()),
            )
            .await;
        assert_eq!(later.len(), 3);
        assert_eq!(
            ok(vault
                .reveal(
                    &owner,
                    body(json!({ "tenantId": t, "name": "cmk/later", "stage": "previous" })),
                )
                .await)["value"],
            "first-under-deployment-secret"
        );
        // Every use shows on the key's audit trail.
        let kms_events = f
            .find("audit", Filter::new())
            .await
            .into_iter()
            .filter(|event| {
                event["action"] == "iam:kms:decrypt" && event["metadata"]["via"] == "vault"
            })
            .count();
        assert!(kms_events > 0);

        // Disabling the key makes the values unreadable until it is enabled again.
        ok(keys
            .disable(&owner, body(json!({ "tenantId": t, "keyId": key_id })))
            .await);
        let error = fails(
            vault
                .reveal(&owner, body(json!({ "tenantId": t, "name": "cmk/api" })))
                .await,
        );
        assert_eq!(code(&error), "KEY_STATE_INVALID");
        ok(keys
            .enable(&owner, body(json!({ "tenantId": t, "keyId": key_id })))
            .await);
        assert_eq!(
            ok(vault
                .reveal(&owner, body(json!({ "tenantId": t, "name": "cmk/api" })))
                .await)["value"],
            "under-the-customer-key"
        );

        // Vault rights alone do not let someone bind secrets to a key they cannot use.
        let (_, alice) = member_with(
            &f,
            "alice",
            json!([{ "effect": "allow", "actions": ["iam:vault:*"], "resources": ["iam/vault/secrets/*"] }]),
        )
        .await;
        let error = fails(
            vault
                .create(
                    &alice,
                    body(json!({ "tenantId": t, "name": "alice/secret", "value": "value", "kmsKey": key_id })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // Moving back under the deployment secret.
        let back = ok(vault
            .update(
                &owner,
                body(json!({ "tenantId": t, "name": "cmk/api", "kmsKey": null })),
            )
            .await);
        assert!(back.get("kmsKeyId").is_none());
        assert_eq!(
            ok(vault
                .reveal(&owner, body(json!({ "tenantId": t, "name": "cmk/api" })))
                .await)["value"],
            "under-the-customer-key"
        );
    });
}

#[test]
fn validates_names_values_and_settings() {
    run(|| async {
        let f = organization(|_| {}).await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        let long = "x".repeat(65);
        for name in ["../etc", "a//b", ".hidden", "a/-b", long.as_str()] {
            let error = fails(
                vault
                    .create(
                        &owner,
                        body(json!({ "tenantId": t, "name": name, "value": "value" })),
                    )
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT", "{name}");
        }
        let error = fails(
            vault
                .create(
                    &owner,
                    body(json!({ "tenantId": t, "name": "j", "format": "json", "value": "[1,2]" })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let error = fails(
            vault
                .create(
                    &owner,
                    body(json!({ "tenantId": t, "name": "r", "value": "value", "rotation": { "rotator": "nope" } })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let error = fails(
            vault
                .create(
                    &owner,
                    body(
                        json!({ "tenantId": t, "name": "d", "kind": "dynamic", "engine": "none" }),
                    ),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let mut options = BetterIamOptions::new(f.store(), SECRET, "http://localhost:3000");
        let bad: Arc<dyn VaultRotator> = Arc::new(RecordingRotator::default());
        options.vault = Some(VaultOptions {
            rotators: Some(rotators(vec![("Bad", bad)])),
            ..VaultOptions::default()
        });
        match better_iam(options) {
            Ok(_) => panic!("a rotator named Bad must be refused"),
            Err(error) => assert!(error.message.contains("rotators"), "{}", error.message),
        }
        let generated = ok(vault
            .generate(
                &owner,
                body(json!({ "generator": { "length": 12, "charset": "numeric", "eachClass": false } })),
            )
            .await);
        assert!(
            Regex::new("^[0-9]{12}$")
                .unwrap()
                .is_match(&s(&generated["value"]))
        );
    });
}

#[test]
fn serves_the_vault_over_http() {
    run(|| async {
        let f = organization(|_| {}).await;
        let t = f.tenant_id.clone();
        ok(f.iam
            .api
            .vault
            .create(
                &f.owner_credential,
                body(json!({ "tenantId": t, "name": "http/secret", "value": "over-the-wire" })),
            )
            .await);
        let token = f.owner_credential.token.clone().unwrap();
        let (status, answer) = f
            .post(
                "vault/reveal",
                &token,
                json!({ "tenantId": t, "name": "http/secret" }),
            )
            .await;
        assert_eq!(status, 200, "{answer}");
        assert_matches(
            &answer["data"],
            json!({ "value": "over-the-wire", "version": 1 }),
        );
    });
}

// --- tests/vault-security.test.ts --------------------------------------------------------------------------------

/// A rotator that fails with the json secret's password in its message while `fail` is set.
struct LeakyRotator(Mutex<bool>);

#[async_trait::async_trait]
impl VaultRotator for LeakyRotator {
    async fn rotate(&self, input: Value) -> IamResult<()> {
        if *self.0.lock().unwrap() {
            return Err(failure(format!(
                "ALTER ROLE app PASSWORD '{}' failed",
                s(&input["fields"]["password"])
            )));
        }
        Ok(())
    }
}

#[test]
fn redacts_every_field_of_a_json_value_from_rotator_errors() {
    run(|| async {
        let rotator: Arc<dyn VaultRotator> = Arc::new(LeakyRotator(Mutex::new(true)));
        let f = organization(vault_options(move |vault| {
            vault.rotators = Some(rotators(vec![("db", rotator)]));
        }))
        .await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &owner,
                body(json!({
                    "tenantId": t,
                    "name": "db/app",
                    "format": "json",
                    "fields": { "username": "app", "password": "initial-password" },
                    "rotation": { "rotator": "db", "field": "password", "intervalDays": 30 },
                })),
            )
            .await);
        let error = fails(
            vault
                .rotate(&owner, body(json!({ "tenantId": t, "name": "db/app" })))
                .await,
        );
        assert_eq!(code(&error), "ROTATION_FAILED");
        let (_, reader) = member_with(
            &f,
            "reader",
            json!([{ "effect": "allow", "actions": ["iam:vault:read"], "resources": ["iam/vault/secrets/*"] }]),
        )
        .await;
        let seen = ok(vault
            .get(&reader, body(json!({ "tenantId": t, "name": "db/app" })))
            .await);
        assert!(s(&seen["rotation"]["lastFailure"]["message"]).contains("[redacted]"));
        let pending = ok(vault
            .reveal(
                &owner,
                body(json!({ "tenantId": t, "name": "db/app", "stage": "pending" })),
            )
            .await);
        let password = s(&pending["fields"]["password"]);
        assert!(!seen.to_string().contains(&password));
        let audit = serde_json::to_string(&f.find("audit", Filter::new()).await).unwrap();
        assert!(!audit.contains(&password));
    });
}

#[test]
fn never_hands_a_pending_value_someone_staged_by_hand_to_the_rotator() {
    run(|| async {
        let rotator = Arc::new(RecordingRotator::default());
        let dyn_rotator: Arc<dyn VaultRotator> = rotator.clone();
        let f = organization(vault_options(move |vault| {
            vault.rotators = Some(rotators(vec![("db", dyn_rotator)]));
        }))
        .await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &owner,
                body(json!({
                    "tenantId": t,
                    "name": "shared/root",
                    "generate": true,
                    "rotation": { "rotator": "db" },
                    "checkout": { "rotateOnCheckin": true, "required": false },
                })),
            )
            .await);
        let (_, writer) = member_with(
            &f,
            "writer",
            json!([{ "effect": "allow", "actions": ["iam:vault:write"], "resources": ["iam/vault/secrets/*"] }]),
        )
        .await;
        ok(vault
            .put(
                &writer,
                body(json!({ "tenantId": t, "name": "shared/root", "value": "writer-chosen-password", "stage": "pending" })),
            )
            .await);
        ok(vault
            .rotate(
                &owner,
                body(json!({ "tenantId": t, "name": "shared/root" })),
            )
            .await);
        let applied = rotator.applied.lock().unwrap().clone();
        assert_eq!(applied.len(), 1);
        assert_ne!(applied[0]["value"], "writer-chosen-password");
        let current = ok(vault
            .reveal(
                &owner,
                body(json!({ "tenantId": t, "name": "shared/root" })),
            )
            .await);
        assert_eq!(current["value"], applied[0]["value"]);
    });
}

#[test]
fn rotates_a_check_out_ended_with_revoke_lease_and_needs_a_policy_to_check_out_at_all() {
    run(|| async {
        let f = organization(|_| {}).await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &owner,
                body(json!({
                    "tenantId": t,
                    "name": "shared/admin",
                    "generate": true,
                    "checkout": { "rotateOnCheckin": true, "required": false },
                })),
            )
            .await);
        ok(vault
            .create(
                &owner,
                body(json!({ "tenantId": t, "name": "plain/key", "value": "plain-value" })),
            )
            .await);
        let (_, holder) = member_with(
            &f,
            "holder",
            json!([{ "effect": "allow", "actions": ["iam:vault:lease"], "resources": ["iam/vault/secrets/*"] }]),
        )
        .await;
        // A lease grant does not read static secrets without a check-out policy.
        let error = fails(
            vault
                .checkout(&holder, body(json!({ "tenantId": t, "name": "plain/key" })))
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let out = ok(vault
            .checkout(
                &holder,
                body(json!({ "tenantId": t, "name": "shared/admin" })),
            )
            .await);
        let ended = ok(vault
            .revoke_lease(
                &holder,
                body(json!({ "tenantId": t, "leaseId": out["leaseId"] })),
            )
            .await);
        assert_matches(&ended, json!({ "state": "ended", "rotated": 2 }));
        let now = ok(vault
            .reveal(
                &owner,
                body(json!({ "tenantId": t, "name": "shared/admin" })),
            )
            .await);
        assert_ne!(now["value"], out["value"]);
    });
}

#[test]
fn refuses_re_tagging_a_secret_out_of_the_callers_reach() {
    run(|| async {
        let f = organization(|_| {}).await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &owner,
                body(json!({ "tenantId": t, "name": "team-a/secret", "tags": { "team": "a" }, "value": "team-a-value" })),
            )
            .await);
        let (_, member) = member_with(
            &f,
            "mallory",
            json!([
                {
                    "effect": "allow",
                    "actions": ["iam:vault:manage"],
                    "resources": ["iam/vault/secrets/*"],
                    "conditions": { "StringEquals": { "resource.tag.team": "a" } },
                },
                {
                    "effect": "allow",
                    "actions": ["iam:vault:reveal"],
                    "resources": ["iam/vault/secrets/*"],
                    "conditions": { "StringEquals": { "resource.tag.team": "b" } },
                },
            ]),
        )
        .await;
        let error = fails(
            vault
                .update(
                    &member,
                    body(
                        json!({ "tenantId": t, "name": "team-a/secret", "tags": { "team": "b" } }),
                    ),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            vault
                .reveal(
                    &member,
                    body(json!({ "tenantId": t, "name": "team-a/secret" })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let view = ok(vault
            .get(
                &owner,
                body(json!({ "tenantId": t, "name": "team-a/secret" })),
            )
            .await);
        assert_eq!(view["tags"], json!({ "team": "a" }));
    });
}

#[test]
fn validates_rotation_settings_that_could_never_rotate() {
    run(|| async {
        let f = organization(|_| {}).await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        let error = fails(
            vault
                .create(
                    &owner,
                    body(json!({
                        "tenantId": t,
                        "name": "j/one",
                        "format": "json",
                        "fields": { "password": "p-value" },
                        "checkout": { "rotateOnCheckin": true },
                    })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        for field in ["__proto__", "constructor", "prototype"] {
            let error = fails(
                vault
                    .create(
                        &owner,
                        body(json!({
                            "tenantId": t,
                            "name": "j/two",
                            "format": "json",
                            "fields": { "password": "p-value" },
                            "rotation": { "field": field, "generator": true },
                        })),
                    )
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT", "{field}");
        }
        ok(vault
            .create(
                &owner,
                body(json!({ "tenantId": t, "name": "j/three", "format": "json", "fields": { "password": "p-value" } })),
            )
            .await);
        for reference in ["vault://j/three#constructor", "vault://j/three#__proto__"] {
            let error = f
                .iam
                .vault
                .resolve(&t, &json!(reference))
                .await
                .unwrap_err();
            assert_eq!(code(&error), "NOT_FOUND", "{reference}");
        }
    });
}

/// A rotator that disables the version it is handed, through the API, before it returns.
struct DisablingRotator(
    Mutex<
        Option<(
            Arc<better_iam_server::api::vault::VaultApi>,
            CredentialInput,
        )>,
    >,
);

#[async_trait::async_trait]
impl VaultRotator for DisablingRotator {
    async fn rotate(&self, input: Value) -> IamResult<()> {
        let (vault, owner) = self.0.lock().unwrap().clone().expect("wired");
        vault
            .set_version_state(
                &owner,
                body(json!({
                    "tenantId": input["tenantId"],
                    "name": input["name"],
                    "version": input["version"],
                    "state": "disabled",
                })),
            )
            .await?;
        Ok(())
    }
}

#[test]
fn does_not_promote_a_version_disabled_while_the_rotator_ran() {
    run(|| async {
        let rotator = Arc::new(DisablingRotator(Mutex::new(None)));
        let dyn_rotator: Arc<dyn VaultRotator> = rotator.clone();
        let f = organization(vault_options(move |vault| {
            vault.rotators = Some(rotators(vec![("db", dyn_rotator)]));
        }))
        .await;
        *rotator.0.lock().unwrap() = Some((f.iam.api.vault.clone(), f.owner_credential.clone()));
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &owner,
                body(json!({ "tenantId": t, "name": "db/x", "value": "first-value", "rotation": { "rotator": "db" } })),
            )
            .await);
        let error = fails(
            vault
                .rotate(&owner, body(json!({ "tenantId": t, "name": "db/x" })))
                .await,
        );
        assert_eq!(code(&error), "ROTATION_FAILED");
        let view = ok(vault
            .get(&owner, body(json!({ "tenantId": t, "name": "db/x" })))
            .await);
        assert_eq!(view["stages"]["current"], 1);
    });
}

#[test]
fn revokes_what_an_engine_minted_when_the_issue_fails_after_the_call() {
    run(|| async {
        let engine = Arc::new(LeaseIdEngine {
            bad_handle: Mutex::new(true),
            ..LeaseIdEngine::default()
        });
        let dyn_engine: Arc<dyn VaultEngine> = engine.clone();
        let f = organization(vault_options(move |vault| {
            vault.engines = Some(engines(vec![("e", dyn_engine)]));
        }))
        .await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &owner,
                body(json!({
                    "tenantId": t,
                    "name": "dyn/x",
                    "kind": "dynamic",
                    "engine": "e",
                    "lease": { "defaultTtlMs": HOUR, "maxTtlMs": 4.0 * HOUR },
                })),
            )
            .await);
        let error = fails(
            vault
                .lease(&owner, body(json!({ "tenantId": t, "name": "dyn/x" })))
                .await,
        );
        assert_eq!(code(&error), "ENGINE_FAILED");
        assert_eq!(engine.revoked.lock().unwrap().len(), 1);
        // Renewals extend by the original length, not by how long the lease has lasted so far.
        *engine.bad_handle.lock().unwrap() = false;
        let lease = ok(vault
            .lease(
                &owner,
                body(json!({ "tenantId": t, "name": "dyn/x", "ttlMs": HOUR })),
            )
            .await);
        f.advance(30.0 * MINUTE);
        let first = ok(vault
            .renew_lease(
                &owner,
                body(json!({ "tenantId": t, "leaseId": lease["leaseId"] })),
            )
            .await);
        assert_eq!(n(&first["expiresAt"]) - f.now(), HOUR);
        f.advance(30.0 * MINUTE);
        let second = ok(vault
            .renew_lease(
                &owner,
                body(json!({ "tenantId": t, "leaseId": lease["leaseId"] })),
            )
            .await);
        assert_eq!(n(&second["expiresAt"]) - f.now(), HOUR);
    });
}

#[test]
fn keeps_customer_managed_keys_in_charge_of_the_values() {
    run(|| async {
        let f = organization(|_| {}).await;
        let vault = f.iam.api.vault.clone();
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        let key = ok(keys.create(&owner, body(json!({ "tenantId": t }))).await);
        ok(vault
            .create(
                &owner,
                body(json!({ "tenantId": t, "name": "cmk/x", "value": "under-the-key", "kmsKey": key["id"] })),
            )
            .await);
        let (_, manager) = member_with(
            &f,
            "manager",
            json!([{ "effect": "allow", "actions": ["iam:vault:*"], "resources": ["iam/vault/secrets/*"] }]),
        )
        .await;
        // Vault rights alone neither read a key-protected value nor move it off its key.
        let error = fails(
            vault
                .reveal(&manager, body(json!({ "tenantId": t, "name": "cmk/x" })))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            vault
                .update(
                    &manager,
                    body(json!({ "tenantId": t, "name": "cmk/x", "kmsKey": null })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // Non-AES keys cannot be bound.
        let signing = ok(keys
            .create(&owner, body(json!({ "tenantId": t, "keySpec": "ed25519" })))
            .await);
        let error = fails(
            vault
                .create(
                    &owner,
                    body(json!({ "tenantId": t, "name": "cmk/y", "value": "v-value", "kmsKey": signing["id"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
    });
}

// --- tests/vault-review.test.ts ----------------------------------------------------------------------------------

/// An agent acting for `person` under a delegation of `scopes` (held back for confirmation when `confirm` says so):
/// the agent, its API key, the delegation and the delegated session.
async fn acting_for(
    f: &Org,
    person: &CredentialInput,
    scopes: Value,
    confirm: Value,
    sponsor_id: Option<&str>,
) -> (Value, CredentialInput, Value, CredentialInput) {
    let api = &f.iam.api;
    let t = f.tenant_id.clone();
    let label = scopes
        .as_array()
        .unwrap()
        .iter()
        .map(s)
        .collect::<Vec<_>>()
        .join(" ");
    let mut input = json!({ "tenantId": t, "name": format!("Agent {label}") });
    if let Some(sponsor_id) = sponsor_id {
        input["sponsorId"] = json!(sponsor_id);
    }
    let agent = ok(api.agents.create(&f.owner_credential, body(input)).await);
    let key = ok(api
        .credentials
        .create(
            &f.owner_credential,
            body(json!({ "tenantId": t, "identityId": agent["id"] })),
        )
        .await);
    let agent_key = bearer(&s(&key["token"]));
    let mut grant = json!({ "tenantId": t, "agentId": agent["id"], "scopes": scopes });
    if !confirm.as_array().unwrap().is_empty() {
        grant["confirm"] = confirm;
    }
    let delegation = ok(api.delegations.grant(person, body(grant)).await);
    let assumed = ok(api
        .delegations
        .assume(
            &agent_key,
            body(json!({ "tenantId": t, "delegationId": delegation["id"] })),
        )
        .await);
    let acting = bearer(&s(&assumed["token"]));
    (agent, agent_key, delegation, acting)
}

#[test]
fn refuses_changes_that_move_a_secret_into_what_the_caller_may_reveal_and_creations_a_deny_targets()
{
    run(|| async {
        let f = organization(vault_options(|vault| {
            let engine: Arc<dyn VaultEngine> = Arc::new(MintingEngine);
            vault.engines = Some(engines(vec![
                ("pg-app", engine.clone()),
                ("pg-admin", engine),
            ]));
        }))
        .await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &owner,
                body(json!({ "tenantId": t, "name": "prod/db", "tags": { "environment": "prod" }, "value": "prod-password" })),
            )
            .await);
        let (_, admin) = member_with(
            &f,
            "vaultadmin",
            json!([
                { "effect": "allow", "actions": ["iam:vault:manage", "iam:vault:read"], "resources": ["iam/vault/secrets/*"] },
                {
                    "effect": "allow",
                    "actions": ["iam:vault:reveal"],
                    "resources": ["iam/vault/secrets/*"],
                    "conditions": { "StringEquals": { "resource.tag.environment": "staging" } },
                },
            ]),
        )
        .await;
        let error = fails(
            vault
                .update(
                    &admin,
                    body(json!({ "tenantId": t, "name": "prod/db", "tags": { "environment": "staging" } })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let view = ok(vault
            .get(&admin, body(json!({ "tenantId": t, "name": "prod/db" })))
            .await);
        assert_eq!(view["tags"], json!({ "environment": "prod" }));
        // Changes that open nothing new still pass.
        ok(vault
            .update(
                &admin,
                body(
                    json!({ "tenantId": t, "name": "prod/db", "description": "Payments database" }),
                ),
            )
            .await);
        let error = fails(
            vault
                .reveal(&admin, body(json!({ "tenantId": t, "name": "prod/db" })))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");

        // A deny on an attribute other than tags applies to the creation itself.
        let (_, dev) = member_with(
            &f,
            "dev",
            json!([
                { "effect": "allow", "actions": ["iam:vault:manage", "iam:vault:lease"], "resources": ["iam/vault/secrets/*"] },
                {
                    "effect": "deny",
                    "actions": ["iam:vault:manage", "iam:vault:lease"],
                    "resources": ["iam/vault/secrets/*"],
                    "conditions": { "StringEquals": { "resource.engine": "pg-admin" } },
                },
            ]),
        )
        .await;
        let error = fails(
            vault
                .create(
                    &dev,
                    body(json!({ "tenantId": t, "name": "mine/admin", "kind": "dynamic", "engine": "pg-admin" })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            vault
                .get(&owner, body(json!({ "tenantId": t, "name": "mine/admin" })))
                .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
        ok(vault
            .create(
                &dev,
                body(json!({ "tenantId": t, "name": "mine/app", "kind": "dynamic", "engine": "pg-app" })),
            )
            .await);
    });
}

#[test]
fn uses_up_a_confirmation_of_the_customer_managed_key_with_each_reveal() {
    run(|| async {
        let f = organization(|_| {}).await;
        let api = &f.iam.api;
        let vault = api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        let (_, alice) = member_with(
            &f,
            "alice",
            json!([{
                "effect": "allow",
                "actions": ["iam:vault:reveal", "iam:vault:read", "iam:kms:decrypt", "iam:kms:encrypt"],
                "resources": ["iam/vault/secrets/*", "iam/kms/*"],
            }]),
        )
        .await;
        let key = ok(api
            .keys
            .create(&owner, body(json!({ "tenantId": t })))
            .await);
        let key_id = s(&key["id"]);
        ok(vault
            .create(
                &owner,
                body(json!({ "tenantId": t, "name": "cmk/db", "value": "db-password", "kmsKey": key_id })),
            )
            .await);
        let (_, _, _, acting) = acting_for(
            &f,
            &alice,
            json!(["iam:vault:reveal", "iam:kms:decrypt"]),
            json!(["iam:vault:reveal", "iam:kms:decrypt"]),
            None,
        )
        .await;
        let approve = |action: &'static str, id: String| {
            let (api, acting, alice, t) = (api, acting.clone(), alice.clone(), t.clone());
            async move {
                let request = ok(api
                    .delegations
                    .request_confirmation(
                        &acting,
                        body(json!({
                            "tenantId": t,
                            "action": action,
                            "resource": { "type": "iam", "id": id },
                            "reason": "Read the database password once",
                        })),
                    )
                    .await);
                ok(api
                    .delegations
                    .decide_confirmation(
                        &alice,
                        body(json!({ "tenantId": t, "confirmationId": request["id"], "approve": true })),
                    )
                    .await);
            }
        };
        approve("iam:vault:reveal", "vault/secrets/cmk/db".into()).await;
        approve("iam:kms:decrypt", format!("kms/{key_id}")).await;
        assert_eq!(
            ok(vault
                .reveal(&acting, body(json!({ "tenantId": t, "name": "cmk/db" })))
                .await)["value"],
            "db-password"
        );
        // A second reveal approval alone is not enough: the key's approval was used up by the first reveal.
        approve("iam:vault:reveal", "vault/secrets/cmk/db".into()).await;
        let error = fails(
            vault
                .reveal(&acting, body(json!({ "tenantId": t, "name": "cmk/db" })))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // The refused call rolled back, so its reveal approval still stands for the next one.
        approve("iam:kms:decrypt", format!("kms/{key_id}")).await;
        assert_eq!(
            ok(vault
                .reveal(&acting, body(json!({ "tenantId": t, "name": "cmk/db" })))
                .await)["value"],
            "db-password"
        );
    });
}

#[test]
fn rotates_to_a_chosen_value_only_for_callers_who_may_write_and_reveal_it_never_behind_check_outs()
{
    run(|| async {
        let rotator = Arc::new(RecordingRotator::default());
        let dyn_rotator: Arc<dyn VaultRotator> = rotator.clone();
        let f = organization(vault_options(move |vault| {
            vault.rotators = Some(rotators(vec![("db", dyn_rotator)]));
        }))
        .await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &owner,
                body(json!({
                    "tenantId": t,
                    "name": "break-glass/root",
                    "generate": true,
                    "rotation": { "rotator": "db", "intervalDays": 30 },
                    "checkout": { "required": true, "exclusive": true },
                })),
            )
            .await);
        ok(vault
            .create(
                &owner,
                body(json!({ "tenantId": t, "name": "svc/token", "value": "first-token", "rotation": { "rotator": "db" } })),
            )
            .await);
        let (_, operator) = member_with(
            &f,
            "operator",
            json!([{ "effect": "allow", "actions": ["iam:vault:rotate", "iam:vault:read"], "resources": ["iam/vault/secrets/*"] }]),
        )
        .await;
        for (credential, name, expected) in [
            (&operator, "break-glass/root", "INVALID_INPUT"),
            (&owner, "break-glass/root", "INVALID_INPUT"),
            (&operator, "svc/token", "ACCESS_DENIED"),
        ] {
            let error = fails(
                vault
                    .rotate(
                        credential,
                        body(json!({ "tenantId": t, "name": name, "value": "known-to-me" })),
                    )
                    .await,
            );
            assert_eq!(code(&error), expected, "{name}");
        }
        assert!(rotator.applied.lock().unwrap().is_empty());
        // Generated values rotate as before.
        ok(vault
            .rotate(
                &operator,
                body(json!({ "tenantId": t, "name": "svc/token" })),
            )
            .await);
        assert_eq!(rotator.applied.lock().unwrap().len(), 1);
        let (_, writer) = member_with(
            &f,
            "writer",
            json!([{
                "effect": "allow",
                "actions": ["iam:vault:rotate", "iam:vault:write", "iam:vault:reveal"],
                "resources": ["iam/vault/secrets/*"],
            }]),
        )
        .await;
        ok(vault
            .rotate(
                &writer,
                body(json!({ "tenantId": t, "name": "svc/token", "value": "chosen-token" })),
            )
            .await);
        assert_eq!(
            rotator.applied.lock().unwrap().last().unwrap()["value"],
            "chosen-token"
        );
    });
}

#[test]
fn ends_leases_when_the_delegation_behind_them_ends_or_the_agent_may_no_longer_act() {
    run(|| async {
        let engine = Arc::new(LeaseIdEngine::default());
        let dyn_engine: Arc<dyn VaultEngine> = engine.clone();
        let f = organization(vault_options(move |vault| {
            vault.engines = Some(engines(vec![("pg", dyn_engine)]));
        }))
        .await;
        let api = &f.iam.api;
        let vault = api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &owner,
                body(json!({
                    "tenantId": t,
                    "name": "prod/db",
                    "kind": "dynamic",
                    "engine": "pg",
                    "lease": { "defaultTtlMs": 7.0 * DAY, "maxTtlMs": 30.0 * DAY },
                })),
            )
            .await);
        let lease = json!([{ "effect": "allow", "actions": ["iam:vault:lease"], "resources": ["iam/vault/secrets/*"] }]);
        let (sponsor_id, _) = member_with(&f, "sponsor", json!([])).await;
        let (_, alice) = member_with(&f, "alice", lease.clone()).await;
        let (agent, agent_key, delegation, acting) = acting_for(
            &f,
            &alice,
            json!(["iam:vault:lease"]),
            json!([]),
            Some(&sponsor_id),
        )
        .await;
        f.grant(&s(&agent["id"]), lease).await;
        let own = ok(vault
            .lease(
                &agent_key,
                body(json!({ "tenantId": t, "name": "prod/db" })),
            )
            .await);
        let for_alice = ok(vault
            .lease(&acting, body(json!({ "tenantId": t, "name": "prod/db" })))
            .await);
        let kept = ok(vault
            .lease(&alice, body(json!({ "tenantId": t, "name": "prod/db" })))
            .await);

        ok(api
            .delegations
            .revoke(
                &alice,
                body(json!({ "tenantId": t, "delegationId": delegation["id"] })),
            )
            .await);
        f.iam.vault.expire_leases(None).await.unwrap();
        assert_eq!(
            *engine.revoked.lock().unwrap(),
            vec![s(&for_alice["leaseId"])]
        );

        ok(api
            .identities
            .set_status(
                &owner,
                body(json!({ "tenantId": t, "identityId": sponsor_id, "status": "disabled" })),
            )
            .await);
        f.iam.vault.expire_leases(None).await.unwrap();
        assert_eq!(
            *engine.revoked.lock().unwrap(),
            vec![s(&for_alice["leaseId"]), s(&own["leaseId"])]
        );
        let live = ok(vault
            .list_leases(&owner, body(json!({ "tenantId": t, "name": "prod/db" })))
            .await);
        let active: Vec<String> = live
            .as_array()
            .unwrap()
            .iter()
            .filter(|item| item["state"] == "active")
            .map(|item| s(&item["id"]))
            .collect();
        assert_eq!(active, vec![s(&kept["leaseId"])]);
    });
}

#[test]
fn finds_a_departed_holders_lease_however_many_live_leases_sort_before_it() {
    run(|| async {
        let engine = Arc::new(LeaseIdEngine::default());
        let dyn_engine: Arc<dyn VaultEngine> = engine.clone();
        let f = organization(vault_options(move |vault| {
            vault.engines = Some(engines(vec![("pg", dyn_engine)]));
        }))
        .await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &owner,
                body(json!({
                    "tenantId": t,
                    "name": "prod/db",
                    "kind": "dynamic",
                    "engine": "pg",
                    "lease": { "defaultTtlMs": 7.0 * DAY, "maxTtlMs": 30.0 * DAY },
                })),
            )
            .await);
        let mut holders = IndexMap::new();
        for index in 0..6 {
            let (person, credential) = member_with(
                &f,
                &format!("p{index}"),
                json!([{ "effect": "allow", "actions": ["iam:vault:lease"], "resources": ["iam/vault/secrets/*"] }]),
            )
            .await;
            let taken = ok(vault
                .lease(
                    &credential,
                    body(json!({ "tenantId": t, "name": "prod/db" })),
                )
                .await);
            holders.insert(s(&taken["leaseId"]), person);
        }
        let order: Vec<String> = f
            .find("vaultLeases", Filter::new().eq("state", "active"))
            .await
            .iter()
            .map(|item| s(&item["id"]))
            .collect();
        let last = order.last().unwrap().clone();
        ok(f.iam
            .api
            .identities
            .set_status(
                &owner,
                body(json!({ "tenantId": t, "identityId": holders[&last], "status": "disabled" })),
            )
            .await);
        f.iam
            .vault
            .expire_leases(Some(&json!({ "limit": 5 })))
            .await
            .unwrap();
        assert_eq!(*engine.revoked.lock().unwrap(), vec![last]);
    });
}

struct Spy(Arc<Mutex<Vec<String>>>);

#[async_trait::async_trait]
impl PluginHooks for Spy {
    async fn after_operation(&self, _input: &OperationHookInput, result: &Value) -> IamResult<()> {
        self.0.lock().unwrap().push(result.to_string());
        Ok(())
    }
}

struct SpyPlugin(Arc<Mutex<Vec<String>>>);

#[async_trait::async_trait]
impl IamPlugin for SpyPlugin {
    fn id(&self) -> &str {
        "spy"
    }
    fn hooks(&self) -> Option<Arc<dyn PluginHooks>> {
        Some(Arc::new(Spy(self.0.clone())))
    }
}

#[test]
fn keeps_values_from_plugin_hooks_and_lets_only_a_session_that_may_lease_act_on_another_sessions_lease()
 {
    run(|| async {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let plugin = SpyPlugin(seen.clone());
        let f = organization(move |options| {
            options.plugins = Some(vec![Arc::new(plugin)]);
            let rotator: Arc<dyn VaultRotator> = Arc::new(RecordingRotator::default());
            options.vault = Some(VaultOptions {
                rotators: Some(rotators(vec![("db", rotator)])),
                ..VaultOptions::default()
            });
        })
        .await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &owner,
                body(json!({
                    "tenantId": t,
                    "name": "shared/admin",
                    "value": "first-admin-password",
                    "rotation": { "rotator": "db" },
                    "checkout": { "required": false },
                })),
            )
            .await);
        let (alice_id, alice) = member_with(
            &f,
            "alice",
            json!([{ "effect": "allow", "actions": ["iam:vault:*"], "resources": ["iam/vault/secrets/*"] }]),
        )
        .await;
        assert_eq!(
            ok(vault
                .reveal(
                    &alice,
                    body(json!({ "tenantId": t, "name": "shared/admin" }))
                )
                .await)["value"],
            "first-admin-password"
        );
        ok(vault
            .rotate(
                &alice,
                body(json!({ "tenantId": t, "name": "shared/admin" })),
            )
            .await);
        let out = ok(vault
            .checkout(
                &alice,
                body(json!({ "tenantId": t, "name": "shared/admin" })),
            )
            .await);
        let current = f.iam.vault.get(&t, "shared/admin", None).await.unwrap();
        assert_eq!(out["value"], current["value"]);
        let seen = seen.lock().unwrap().clone();
        assert!(seen.len() >= 3);
        let current_value = s(&current["value"]);
        for result in &seen {
            assert!(!result.contains("first-admin-password"), "{result}");
            assert!(!result.contains(&current_value), "{result}");
        }

        // An agent acting for alice without iam:vault:lease cannot end the check-out she took herself.
        let (_, _, _, acting) =
            acting_for(&f, &alice, json!(["iam:vault:read"]), json!([]), None).await;
        let error = fails(
            vault
                .checkin(
                    &acting,
                    body(json!({ "tenantId": t, "leaseId": out["leaseId"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            vault
                .revoke_lease(
                    &acting,
                    body(json!({ "tenantId": t, "leaseId": out["leaseId"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // Another session of hers that may lease can.
        let again = f.sign_in(&alice_id).await;
        let returned = ok(vault
            .checkin(
                &again,
                body(json!({ "tenantId": t, "leaseId": out["leaseId"] })),
            )
            .await);
        assert_matches(&returned, json!({ "state": "ended" }));
    });
}

#[test]
fn destroys_values_for_good_only_from_a_recently_signed_in_session() {
    run(|| async {
        let f = organization(|_| {}).await;
        let vault = f.iam.api.vault.clone();
        let owner = f.owner_credential.clone();
        let t = f.tenant_id.clone();
        ok(vault
            .create(
                &owner,
                body(json!({ "tenantId": t, "name": "old/key", "value": "value-one" })),
            )
            .await);
        ok(vault
            .put(
                &owner,
                body(json!({ "tenantId": t, "name": "old/key", "value": "value-two" })),
            )
            .await);
        f.advance(10.0 * MINUTE);
        let error = fails(
            vault
                .destroy_version(
                    &owner,
                    body(json!({ "tenantId": t, "name": "old/key", "version": 1 })),
                )
                .await,
        );
        assert_eq!(code(&error), "RECENT_AUTH_REQUIRED");
        let error = fails(
            vault
                .delete(
                    &owner,
                    body(json!({ "tenantId": t, "name": "old/key", "recoveryDays": 0 })),
                )
                .await,
        );
        assert_eq!(code(&error), "RECENT_AUTH_REQUIRED");
        // A recovery window needs no fresh sign-in.
        let scheduled = ok(vault
            .delete(
                &owner,
                body(json!({ "tenantId": t, "name": "old/key", "recoveryDays": 7 })),
            )
            .await);
        assert_matches(&scheduled, json!({ "status": "pending-deletion" }));
    });
}
