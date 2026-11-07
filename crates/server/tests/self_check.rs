//! `iam.selfCheck()` (self-check.ts). Ported from tests/self-check.test.ts (the doctor CLI case belongs to the CLI
//! port, the libSQL case runs on SQLite here). The backlog checks read `retention.countDue` (retention.ts, another
//! unit): steps past it end the test early with a note until that unit lands. The sealed-value, backlog and archive
//! findings are also judged with stand-ins for `countDue` and the dry-run secret rotation.

mod common;
mod tenants_support;

use std::sync::Arc;

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_core::IamStore;
use better_iam_server::better_iam;
use better_iam_server::metrics::MetricsOptions;
use better_iam_server::observe::ObservabilityOptions;
use better_iam_server::options::{BetterIamOptions, Toggle};
use serde_json::{Map, Value, json};
use tenants_support::*;

const MINUTE: f64 = 60_000.0;

/// `{ [check]: severity }` of a result.
fn checks(result: &Value) -> Map<String, Value> {
    result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| {
            (
                finding["check"].as_str().unwrap().to_owned(),
                finding["severity"].clone(),
            )
        })
        .collect()
}

fn expect(pairs: &[(&str, &str)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(check, severity)| ((*check).to_owned(), json!(severity)))
        .collect()
}

async fn seed(store: &Arc<dyn IamStore>, collection: &str, records: Vec<Value>) {
    use better_iam_core::IamStoreExt;
    let collection = collection.to_owned();
    store
        .transaction(|tx| async move {
            for record in records {
                let mut record = record.as_object().unwrap().clone();
                record
                    .entry("tenantId")
                    .or_insert_with(|| Value::String("t".into()));
                tx.insert(&collection, &record).await?;
            }
            Ok(())
        })
        .await
        .unwrap();
}

#[test]
fn reports_a_database_without_the_iam_schema() {
    run(|| async {
        let inbox = Inbox::default();
        let iam = better_iam(options(false, &inbox)).expect("valid options");
        let result = iam.self_check(None).await.unwrap();
        assert_eq!(result["ok"], false);
        assert_eq!(
            checks(&result),
            expect(&[
                ("schema-behind", "error"),
                ("in-memory-database", "warning"),
                ("no-email-transport", "warning"),
            ])
        );
        assert_eq!(result["storage"]["adapter"], "sqlite");
        assert_eq!(result["storage"]["schemaVersion"], Value::Null);
        let schema = result["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["check"] == "schema-behind")
            .unwrap();
        assert_eq!(schema["message"], "The database has no IAM schema");
        assert_eq!(
            schema["fix"],
            "Run `better-iam migrate` (or `iam.initialize()`) before serving traffic"
        );
        iam.initialize().await.unwrap();
        let initialized = or_skip!(iam.self_check(None).await).unwrap();
        assert_eq!(
            checks(&initialized),
            expect(&[
                ("not-bootstrapped", "error"),
                ("in-memory-database", "warning"),
                ("no-email-transport", "warning"),
            ])
        );
    });
}

#[test]
fn validates_its_options() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        let cases = [
            (
                json!({ "cap": 0 }),
                "cap must be an integer between 1 and 100000",
            ),
            (
                json!({ "cap": 1.5 }),
                "cap must be an integer between 1 and 100000",
            ),
            (
                json!({ "deliveryRetentionMs": -1 }),
                "deliveryRetentionMs must be an integer between 0 and 315360000000",
            ),
            (
                json!({ "graceMs": 2.0 * DAY }),
                "graceMs must be an integer between 0 and 86400000",
            ),
        ];
        for (options, message) in cases {
            let error = failure(f.iam.self_check(Some(&options)).await);
            assert_eq!(
                (error.code.as_str(), error.message.as_str()),
                ("INVALID_INPUT", message)
            );
        }
    });
}

#[test]
fn passes_a_healthy_deployment_and_notices_jobs_that_are_not_running() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        let healthy = or_skip!(f.iam.self_check(None).await).unwrap();
        assert_eq!(healthy["ok"], true);
        assert_eq!(
            checks(&healthy),
            expect(&[("in-memory-database", "warning")])
        );
        let wall = better_iam_server::utils::date_now();
        // Due for three days: a sweep that runs at least daily would have removed them.
        seed(
            &f.iam.store,
            "oauthArtifacts",
            (0..6)
                .map(|index| json!({ "id": format!("a{index}"), "expiresAt": wall - 3.0 * DAY }))
                .collect(),
        )
        .await;
        // Due for a day only: an on-schedule sweep may not have run yet, so this is no backlog.
        seed(
            &f.iam.store,
            "oauthLoginStates",
            vec![json!({ "id": "recent", "expiresAt": wall - DAY })],
        )
        .await;
        seed(
            &f.iam.store,
            "authChallenges",
            vec![json!({ "id": "c", "expiresAt": NOW - 2.0 * DAY })],
        )
        .await;
        seed(
            &f.iam.store,
            "outbox",
            vec![
                json!({ "id": "waiting", "kind": "email", "createdAt": NOW - 20.0 * MINUTE, "attempts": 0 }),
                json!({ "id": "dead", "kind": "email", "createdAt": NOW - 2.0 * DAY, "attempts": 25, "failedAt": NOW - MINUTE }),
            ],
        )
        .await;
        seed(
            &f.iam.store,
            "auditHooks",
            vec![json!({ "id": "hook", "delivered": false, "event": { "timestamp": NOW - 20.0 * MINUTE } })],
        )
        .await;
        let behind = f.iam.self_check(Some(&json!({ "cap": 5 }))).await.unwrap();
        assert_eq!(behind["ok"], true);
        assert_eq!(
            checks(&behind),
            expect(&[
                ("in-memory-database", "warning"),
                ("sweep-backlog", "warning"),
                ("purge-not-running", "warning"),
                ("outbox-stalled", "warning"),
                ("outbox-abandoned", "warning"),
                ("audit-hooks-stalled", "warning"),
            ])
        );
        let backlog = behind["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["check"] == "sweep-backlog")
            .unwrap()
            .clone();
        assert_eq!(backlog["count"], 5);
        let message = backlog["message"].as_str().unwrap();
        assert!(message.contains("5+"), "{message}");
        assert!(message.contains("oauthArtifacts"), "{message}");
        assert!(!message.contains("oauthLoginStates"), "{message}");
        // Running the jobs clears their findings.
        or_skip!(f.iam.sweep_expired(None).await).unwrap();
        f.iam.purge_deleted(None).await.unwrap();
        {
            use better_iam_core::IamStoreExt;
            f.iam
                .store
                .transaction(|tx| async move {
                    tx.delete("outbox", "waiting").await?;
                    tx.delete("auditHooks", "hook").await
                })
                .await
                .unwrap();
        }
        assert_eq!(
            checks(&f.iam.self_check(Some(&json!({ "cap": 5 }))).await.unwrap()),
            expect(&[
                ("in-memory-database", "warning"),
                ("outbox-abandoned", "warning"),
            ])
        );
    });
}

#[test]
fn judges_the_sweep_backlog_with_the_retention_the_sweep_uses() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        seed(
            &f.iam.store,
            "outbox",
            (0..3)
                .map(|index| {
                    json!({
                        "id": format!("sent{index}"), "kind": "email", "createdAt": NOW - 41.0 * DAY,
                        "attempts": 1, "deliveredAt": NOW - 40.0 * DAY,
                    })
                })
                .collect(),
        )
        .await;
        let result = or_skip!(f.iam.self_check(None).await).unwrap();
        assert_eq!(checks(&result)["sweep-backlog"], "warning");
        // A sweep keeping deliveries for 90 days deletes none of them, so nothing is overdue.
        let ninety = json!({ "deliveryRetentionMs": 90.0 * DAY });
        let swept = f.iam.sweep_expired(Some(&ninety)).await.unwrap();
        assert_eq!(swept["deleted"], json!({}));
        assert!(
            checks(&f.iam.self_check(Some(&ninety)).await.unwrap())
                .get("sweep-backlog")
                .is_none()
        );
    });
}

#[test]
fn accepts_random_secrets() {
    run(|| async {
        let inbox = Inbox::default();
        let mut options: BetterIamOptions = options(true, &inbox);
        // 32 hex digits with only ten distinct characters: random, not a placeholder.
        options.secret = "3d5f6a92a99f9dffd33aacb3d2563256".into();
        let iam = better_iam(options).expect("valid options");
        iam.initialize().await.unwrap();
        iam.bootstrap(
            &json!({ "email": "root@example.test", "name": "Root", "password": ROOT_PASSWORD }),
        )
        .await
        .unwrap();
        let result = or_skip!(iam.self_check(None).await).unwrap();
        assert_eq!(
            checks(&result),
            expect(&[("in-memory-database", "warning")])
        );
    });
}

#[test]
fn flags_settings_that_can_lose_data_or_be_guessed() {
    run(|| async {
        let folder = tempfile::tempdir().unwrap();
        let mut adapter =
            SqliteAdapterOptions::new(folder.path().join("risky.db").to_string_lossy());
        adapter.journal_mode = Some("delete".into());
        adapter.durability = Some("normal".into());
        let store: Arc<dyn IamStore> = sqlite_adapter(adapter).expect("sqlite");
        let inbox = Inbox::default();
        let mut options = options(true, &inbox);
        options.database = Some(store);
        options.secret = "change-me-change-me-change-me-change-me".into();
        options.observability = Some(ObservabilityOptions {
            on_span: None,
            metrics: Some(Toggle::Options(MetricsOptions {
                bearer_token: Some("short-token".into()),
                ..MetricsOptions::default()
            })),
        });
        let iam = better_iam(options).expect("valid options");
        iam.initialize().await.unwrap();
        iam.bootstrap(
            &json!({ "email": "root@example.test", "name": "Root", "password": ROOT_PASSWORD }),
        )
        .await
        .unwrap();
        let result = or_skip!(iam.self_check(None).await).unwrap();
        assert_eq!(result["ok"], false);
        assert_eq!(
            checks(&result),
            expect(&[
                ("sqlite-durability", "error"),
                ("weak-secret", "warning"),
                ("weak-metrics-token", "warning"),
            ])
        );
    });
}

/// A self-check over a migrated store holding a root tenant, with stand-ins for `retention.countDue` and the dry-run
/// secret rotation, so every finding of the sealed-values and backlog sections can be judged here.
async fn judged(
    configure: impl FnOnce(&mut BetterIamOptions),
    due: Value,
    sealed: Value,
    options: Value,
) -> (Value, Vec<Value>) {
    use better_iam_core::IamStoreExt;
    let inbox = Inbox::default();
    let mut settings = tenants_support::options(true, &inbox);
    configure(&mut settings);
    let ctx = common::context(settings, NOW);
    ctx.store.migrate().await.unwrap();
    ctx.store
        .transaction(|tx| async move {
            let mut root = Map::new();
            root.insert("id".into(), json!("root"));
            root.insert("tenantId".into(), json!("root"));
            root.insert("name".into(), json!("Platform"));
            root.insert("type".into(), json!("root"));
            root.insert("parentId".into(), Value::Null);
            root.insert("status".into(), json!("active"));
            root.insert("createdAt".into(), json!(NOW));
            tx.insert("tenants", &root).await
        })
        .await
        .unwrap();
    let calls: Arc<std::sync::Mutex<Vec<Value>>> = Arc::default();
    let seen = calls.clone();
    let count_due: better_iam_server::port::Callback = Arc::new(move |args: Vec<Value>| {
        seen.lock().unwrap().extend(args);
        let due = due.clone();
        Box::pin(async move { Ok(due) })
    });
    let sample_secrets: better_iam_server::port::Callback = Arc::new(move |args: Vec<Value>| {
        assert_eq!(args.len(), 1);
        let sealed = sealed.clone();
        Box::pin(async move { Ok(sealed) })
    });
    let check =
        better_iam_server::self_check::create_self_check(&ctx, count_due, sample_secrets).unwrap();
    let result = check.run(Some(&options)).await.unwrap();
    let calls = calls.lock().unwrap().clone();
    (result, calls)
}

fn finding<'a>(result: &'a Value, check: &str) -> &'a Value {
    result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["check"] == check)
        .unwrap_or_else(|| panic!("no {check} finding"))
}

#[test]
fn judges_sealed_values_and_the_sweep_backlog() {
    run(|| async {
        let clean = json!({ "resealed": {}, "unreadable": {}, "current": 3, "complete": true, "done": true });
        // Values no secret opens, values still sealed with a previous secret, and a backlog past the cap.
        let (result, calls) = judged(
            |_| {},
            json!({ "oauthArtifacts": 7, "sessions": 0, "outbox": 1 }),
            json!({
                "resealed": { "webhooks": 2 },
                "unreadable": { "authMfa": 1, "outbox": 2 },
                "current": 0, "complete": false, "done": false,
            }),
            json!({ "cap": 5, "graceMs": 1000 }),
        )
        .await;
        same(
            &Value::Array(calls),
            &json!([{ "cap": 5, "graceMs": 1000, "overdueMs": 2.0 * DAY }]),
        );
        assert_eq!(result["ok"], false);
        same(
            finding(&result, "unreadable-secrets"),
            &json!({
                "check": "unreadable-secrets",
                "severity": "error",
                "message": "3 stored secret value(s) open with no configured secret (authMfa: 1, outbox: 2); the deployment secret was probably changed without previousSecrets",
                "fix": "Put the old secret in `previousSecrets`, run `better-iam rotate-secrets`, then remove it",
                "count": 3,
            }),
        );
        same(
            finding(&result, "secret-rotation-pending"),
            &json!({
                "check": "secret-rotation-pending",
                "severity": "warning",
                "message": "2 stored secret value(s) are still sealed with a previous secret",
                "fix": "Run `better-iam rotate-secrets` (or `iam.rotateSecrets()`) until it reports `done: true`, then remove `previousSecrets` a day later",
                "count": 2,
            }),
        );
        same(
            finding(&result, "sweep-backlog"),
            &json!({
                "check": "sweep-backlog",
                "severity": "warning",
                "message": "5+ record(s) have been due for the retention sweep for more than two days (oauthArtifacts: 7, outbox: 1)",
                "fix": "Schedule `better-iam sweep` (or `iam.sweepExpired()`) hourly or daily, with a `limit` that keeps up",
                "count": 5,
            }),
        );
        // previousSecrets set and nothing needs it: confirmed by a complete sample, or not yet.
        let previous = |options: &mut BetterIamOptions| {
            options.previous_secrets =
                Some(vec!["the-previous-secret-of-at-least-32-chars".into()]);
        };
        let (result, _) = judged(previous, json!({}), clean.clone(), json!({ "cap": 7 })).await;
        assert_eq!(result["ok"], true);
        assert_eq!(
            checks(&result),
            expect(&[
                ("in-memory-database", "warning"),
                ("previous-secrets-configured", "info"),
            ])
        );
        let mut partial = clean.clone();
        partial["complete"] = json!(false);
        let (result, _) = judged(previous, json!({}), partial, json!({ "cap": 7 })).await;
        assert_eq!(
            finding(&result, "secret-rotation-unverified")["message"],
            "previousSecrets is set; no value in a sample of 7 per collection needs it, but not every record was examined"
        );
        // Without previousSecrets a clean sample says nothing.
        let (result, calls) = judged(
            |_| {},
            json!({ "authChallenges": 0 }),
            clean.clone(),
            json!({}),
        )
        .await;
        same(
            &Value::Array(calls),
            &json!([{ "cap": 1000, "overdueMs": 2.0 * DAY }]),
        );
        assert_eq!(
            checks(&result),
            expect(&[("in-memory-database", "warning")])
        );
    });
}

#[test]
fn judges_secrets_tokens_and_durability_settings() {
    run(|| async {
        let clean = json!({ "resealed": {}, "unreadable": {}, "current": 0, "complete": true, "done": true });
        let folder = tempfile::tempdir().unwrap();
        let path = folder
            .path()
            .join("risky.db")
            .to_string_lossy()
            .into_owned();
        let (result, _) = judged(
            |options| {
                let mut adapter = SqliteAdapterOptions::new(path);
                adapter.journal_mode = Some("delete".into());
                adapter.durability = Some("normal".into());
                options.database = Some(sqlite_adapter(adapter).expect("sqlite"));
                options.secret = "Change_Me-change-me-change-me-change-me".into();
                options.observability = Some(ObservabilityOptions {
                    on_span: None,
                    metrics: Some(Toggle::Options(MetricsOptions {
                        bearer_token: Some("short-token".into()),
                        ..MetricsOptions::default()
                    })),
                });
                options.authentication = None;
            },
            json!({}),
            clean.clone(),
            json!({}),
        )
        .await;
        assert_eq!(result["ok"], false);
        assert_eq!(
            checks(&result),
            expect(&[
                ("sqlite-durability", "error"),
                ("weak-secret", "warning"),
                ("weak-metrics-token", "warning"),
                ("no-email-transport", "warning"),
            ])
        );
        assert_eq!(
            finding(&result, "sqlite-durability")["message"],
            "SQLite runs a rollback journal with synchronous=normal, which a power failure can corrupt"
        );
        // Random secrets pass however few distinct characters hex has; little variety or a placeholder does not.
        for (secret, weak) in [
            ("3d5f6a92a99f9dffd33aacb3d2563256", false),
            ("aaaaaaaabbbbbbbbccccccccdddddddd", true),
            ("secret-but-long-enough-and-varied-0123456789", true),
            ("a-very-long-PLACEHOLDER-value-0123456789", true),
        ] {
            let (result, _) = judged(
                |options| options.secret = secret.into(),
                json!({}),
                clean.clone(),
                json!({}),
            )
            .await;
            assert_eq!(
                checks(&result).contains_key("weak-secret"),
                weak,
                "{secret}"
            );
        }
    });
}

#[test]
fn notices_an_audit_archive_that_falls_behind() {
    run(|| async {
        use better_iam_core::IamStoreExt;
        let clean = json!({ "resealed": {}, "unreadable": {}, "current": 0, "complete": true, "done": true });
        let inbox = Inbox::default();
        let mut settings = tenants_support::options(true, &inbox);
        settings.audit_archive = Some(better_iam_server::options::AuditArchiveOptions {
            write: Some(Arc::new(|_| Box::pin(async { Ok(()) }))),
            ..Default::default()
        });
        let ctx = common::context(settings, NOW);
        ctx.store.migrate().await.unwrap();
        // Two tenants with chains: one archived through its last event, one with a two-day-old event not archived.
        ctx.store
            .transaction(|tx| async move {
                for (tenant, sequence) in [("a", 2.0), ("b", 1.0)] {
                    let mut head = Map::new();
                    head.insert("id".into(), json!(tenant));
                    head.insert("tenantId".into(), json!(tenant));
                    head.insert("sequence".into(), json!(sequence));
                    head.insert("hash".into(), json!("h"));
                    tx.insert("auditChains", &head).await?;
                    let mut event = Map::new();
                    event.insert("id".into(), json!(format!("{tenant}-event")));
                    event.insert("tenantId".into(), json!(tenant));
                    event.insert("sequence".into(), json!(sequence));
                    event.insert("timestamp".into(), json!(NOW - 2.0 * DAY));
                    tx.insert("audit", &event).await?;
                }
                let mut cursor = Map::new();
                cursor.insert("id".into(), json!("a"));
                cursor.insert("tenantId".into(), json!("a"));
                cursor.insert("sequence".into(), json!(2));
                tx.insert("auditArchiveCursors", &cursor).await
            })
            .await
            .unwrap();
        let count_due: better_iam_server::port::Callback =
            Arc::new(|_| Box::pin(async { Ok(json!({})) }));
        let sample_secrets: better_iam_server::port::Callback = Arc::new(move |_| {
            let sealed = clean.clone();
            Box::pin(async move { Ok(sealed) })
        });
        let check =
            better_iam_server::self_check::create_self_check(&ctx, count_due, sample_secrets)
                .unwrap();
        let result = check.run(None).await.unwrap();
        same(
            finding(&result, "audit-archive-behind"),
            &json!({
                "check": "audit-archive-behind",
                "severity": "warning",
                "message": "1 tenant(s) have audit events older than a day that are not archived",
                "fix": "Schedule `better-iam audit-archive` (or `iam.archiveAudit()`) at least hourly, and check the sink for failures",
                "count": 1,
            }),
        );
        // No root tenant was bootstrapped in this store.
        assert_eq!(finding(&result, "not-bootstrapped")["severity"], "error");
    });
}
