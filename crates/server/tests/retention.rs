//! The retention sweep (`iam.sweepExpired`) and its read-only backlog count (`countDue`). Ported from
//! tests/retention.test.ts; the CLI case belongs to the CLI port.

mod organization_fixture;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::SignInResult;
use better_iam_core::{
    Filter, FindOptions, IamStore, IamStoreExt, Record, StoreCall, StoreMethod, instrument_store,
};
use better_iam_server::options::{BetterIamOptions, EventOptions};
use better_iam_server::self_check::DueOptions;
use better_iam_server::{BetterIam, better_iam};
use organization_fixture::{bearer, body, organization, run};
use serde_json::{Value, json};

const DAY: f64 = 86_400_000.0;
const NOW: f64 = 1_900_000_000_000.0;
const SECRET: &str = "retention-test-secret-with-at-least-32-characters";

fn record(id: &str, fields: Value) -> Record {
    let mut record = Record::new();
    record.insert("id".into(), json!(id));
    record.insert("tenantId".into(), json!("t"));
    for (key, value) in fields.as_object().unwrap() {
        record.insert(key.clone(), value.clone());
    }
    record
}

async fn seed(store: &Arc<dyn IamStore>, rows: Vec<(&str, Record)>) {
    let rows: Vec<(String, Record)> = rows
        .into_iter()
        .map(|(collection, record)| (collection.to_owned(), record))
        .collect();
    store
        .transaction(|tx| async move {
            for (collection, record) in &rows {
                tx.insert(collection, record).await?;
            }
            Ok(())
        })
        .await
        .unwrap();
}

async fn ids(store: &Arc<dyn IamStore>, collection: &str) -> Vec<String> {
    let mut ids: Vec<String> = store
        .find(collection, &Filter::new(), &FindOptions::default())
        .await
        .unwrap()
        .iter()
        .map(|record| record["id"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}

async fn sweep(iam: &BetterIam, options: Value) -> Value {
    iam.sweep_expired(Some(&options)).await.unwrap()
}

/// A deployment of its own on an in-memory store (optionally instrumented).
async fn standalone(
    calls: Option<Arc<Mutex<Vec<StoreCall>>>>,
    configure: impl FnOnce(&mut BetterIamOptions),
) -> (BetterIam, Arc<dyn IamStore>) {
    let database: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    let store = match calls {
        Some(calls) => instrument_store(
            database.clone(),
            Arc::new(move |call: &StoreCall| calls.lock().unwrap().push(call.clone())),
            None,
        ),
        None => database.clone(),
    };
    let mut options = BetterIamOptions::new(store, SECRET, "http://localhost:3000");
    configure(&mut options);
    let iam = better_iam(options).expect("valid options");
    iam.initialize().await.expect("initialize");
    (iam, database)
}

fn session_token(result: SignInResult) -> String {
    match result {
        SignInResult::Session(session) => session.token,
        SignInResult::MfaRequired(_) => panic!("unexpected MFA"),
    }
}

#[test]
fn deletes_expired_sessions_and_keeps_live_sessions_and_renewable_api_keys() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let _ = alice;
        // An API key that expires in a minute (a session of kind `api-key`).
        let account = better_iam_server::utils::id();
        f.insert(
            "identities",
            json!({
                "id": account,
                "tenantId": f.tenant_id,
                "kind": "service",
                "name": "ci",
                "status": "active",
                "emailVerified": false,
                "rootAdmin": false,
                "owner": false,
                "createdAt": f.now(),
            }),
        )
        .await;
        let created = f
            .iam
            .api
            .credentials
            .create(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "identityId": account, "name": "short", "expiresInSeconds": 60 })),
            )
            .await;
        let key_listed = created.is_ok();
        if !key_listed {
            f.insert(
                "sessions",
                json!({
                    "id": better_iam_server::utils::id(),
                    "tenantId": f.tenant_id,
                    "identityId": account,
                    "kind": "api-key",
                    "name": "short",
                    "tokenHash": "short-key",
                    "createdAt": f.now(),
                    "lastSeenAt": f.now(),
                    "authenticatedAt": f.now(),
                    "expiresAt": f.now() + 60_000.0,
                    "mfa": false,
                }),
            )
            .await;
        }
        let password = json!({ "tenantId": f.tenant_id, "email": "alice@acme.test", "password": "a strong alice password" });
        let stale = session_token(f.iam.auth.sign_in(&password).await.unwrap());
        let before = f
            .find("sessions", Filter::new().eq("kind", "user"))
            .await
            .len();
        assert!(before >= 3);

        f.advance(8.0 * DAY);
        let fresh = session_token(f.iam.auth.sign_in(&password).await.unwrap());
        let result = f.iam.sweep_expired(None).await.unwrap();
        assert_eq!(result["truncated"], json!(false));
        assert_eq!(result["deleted"]["sessions"].as_f64(), Some(before as f64));
        let remaining = f.find("sessions", Filter::new()).await;
        let mut kinds: Vec<&str> = remaining
            .iter()
            .map(|session| session["kind"].as_str().unwrap())
            .collect();
        kinds.sort();
        assert_eq!(kinds, ["api-key", "user"]);
        f.iam.auth.get_session(&bearer(&fresh)).await.unwrap();
        assert_eq!(
            f.iam
                .auth
                .get_session(&bearer(&stale))
                .await
                .unwrap_err()
                .code,
            "UNAUTHENTICATED"
        );
        // The expired key is still listed, so an administrator can see it and renew it.
        if key_listed {
            let owner = f.sign_in(&f.owner_id).await;
            let keys = f
                .iam
                .api
                .credentials
                .list(&owner, body(json!({ "tenantId": f.tenant_id })))
                .await
                .unwrap()
                .into_value()
                .unwrap();
            assert_eq!(keys[0]["name"], json!("short"));
            assert_eq!(keys[0]["expired"], json!(true));
        }

        // Nothing else expired: a second run deletes nothing.
        assert_eq!(
            f.iam.sweep_expired(None).await.unwrap(),
            json!({ "deleted": {}, "total": 0, "truncated": false })
        );
    });
}

#[test]
fn honors_the_grace_period_and_the_delivery_retention() {
    run(|| async {
        let f = organization(|_| {}).await;
        let now = f.now();
        let store = f.store();
        // A delivered message (the owner invitation of the TypeScript fixture), an abandoned one and a pending one.
        seed(
            &store,
            vec![
                (
                    "outbox",
                    record(
                        "invitation",
                        json!({ "kind": "email", "createdAt": now, "attempts": 1, "deliveredAt": now }),
                    ),
                ),
                (
                    "outbox",
                    record(
                        "failed",
                        json!({ "kind": "email", "createdAt": now, "attempts": 25, "failedAt": now }),
                    ),
                ),
                (
                    "outbox",
                    record(
                        "pending",
                        json!({ "kind": "email", "createdAt": now - 60.0 * DAY, "attempts": 3 }),
                    ),
                ),
                (
                    "sessions",
                    record(
                        "just-expired",
                        json!({
                            "identityId": "x",
                            "kind": "user",
                            "tokenHash": "h1",
                            "createdAt": now - DAY,
                            "lastSeenAt": now - DAY,
                            "authenticatedAt": now - DAY,
                            "expiresAt": now - 60_000.0,
                            "mfa": false,
                        }),
                    ),
                ),
            ],
        )
        .await;
        let delivered = f
            .find("outbox", Filter::new())
            .await
            .into_iter()
            .filter(|message| message.get("deliveredAt").is_some_and(Value::is_number))
            .count();
        assert!(delivered > 0);

        assert_eq!(sweep(&f.iam, json!({})).await["deleted"], json!({}));
        assert_eq!(
            sweep(&f.iam, json!({ "graceMs": 0 })).await["deleted"],
            json!({ "sessions": 1 })
        );

        f.advance(29.0 * DAY);
        assert!(
            sweep(&f.iam, json!({})).await["deleted"]
                .get("outbox")
                .is_none()
        );
        f.advance(2.0 * DAY);
        let result = sweep(&f.iam, json!({})).await;
        assert_eq!(
            result["deleted"]["outbox"].as_f64(),
            Some((delivered + 1) as f64)
        );
        assert_eq!(ids(&store, "outbox").await, ["pending"]);
        // A shorter retention applies at once; pending messages are never swept.
        seed(
            &store,
            vec![(
                "outbox",
                record(
                    "sent",
                    json!({ "kind": "sms", "createdAt": f.now(), "attempts": 1, "deliveredAt": f.now() }),
                ),
            )],
        )
        .await;
        assert_eq!(
            sweep(&f.iam, json!({ "deliveryRetentionMs": 0 })).await["deleted"],
            json!({ "outbox": 1 })
        );
        assert_eq!(ids(&store, "outbox").await, ["pending"]);
    });
}

#[test]
fn sweeps_protocol_artifacts_devices_relationship_tuples_and_dispatched_audit_hooks() {
    run(|| async {
        let (iam, database) = standalone(None, |_| {}).await;
        let past = NOW - 10.0 * 60_000.0;
        let future = NOW + 60_000.0;
        let mut rows: Vec<(&str, Record)> = Vec::new();
        for collection in [
            "oauthArtifacts",
            "oauthLoginStates",
            "samlRequests",
            "samlRelays",
            "samlAssertions",
            "authDevices",
            "relationships",
        ] {
            rows.push((collection, record("old", json!({ "expiresAt": past }))));
            rows.push((collection, record("live", json!({ "expiresAt": future }))));
        }
        rows.extend([
            ("relationships", record("forever", json!({}))),
            (
                "sessions",
                record(
                    "role-old",
                    json!({ "kind": "role", "tokenHash": "r", "expiresAt": past }),
                ),
            ),
            (
                "sessions",
                record(
                    "key-old",
                    json!({ "kind": "api-key", "tokenHash": "k", "expiresAt": past }),
                ),
            ),
            (
                "sessions",
                record(
                    "future-kind",
                    json!({ "kind": "federated", "tokenHash": "f", "expiresAt": past }),
                ),
            ),
            // Grants outlive their expiry by 31 days so back-channel logout can still find the client.
            (
                "oauthArtifacts",
                record(
                    "grant-recent",
                    json!({ "model": "Grant", "expiresAt": NOW - 30.0 * DAY }),
                ),
            ),
            (
                "oauthArtifacts",
                record(
                    "grant-old",
                    json!({ "model": "Grant", "expiresAt": NOW - 32.0 * DAY }),
                ),
            ),
            (
                "ssfDeliveries",
                record(
                    "failed-old",
                    json!({ "status": "failed", "createdAt": NOW - 41.0 * DAY, "failedAt": NOW - 40.0 * DAY }),
                ),
            ),
            // Queued long ago, abandoned yesterday: kept for the retention from when it failed.
            (
                "ssfDeliveries",
                record(
                    "failed-new",
                    json!({ "status": "failed", "createdAt": NOW - 60.0 * DAY, "failedAt": NOW - DAY }),
                ),
            ),
            (
                "ssfDeliveries",
                record(
                    "failed-legacy",
                    json!({ "status": "failed", "createdAt": NOW - 40.0 * DAY }),
                ),
            ),
            (
                "ssfDeliveries",
                record(
                    "pending-old",
                    json!({ "status": "pending", "createdAt": NOW - 40.0 * DAY }),
                ),
            ),
            (
                "auditHooks",
                record("done", json!({ "delivered": true, "deliveredAt": past })),
            ),
            ("auditHooks", record("done-legacy", json!({ "delivered": true }))),
            ("auditHooks", record("waiting", json!({ "delivered": false }))),
            // Collections the sweep leaves alone even past expiry: history, or renewable.
            (
                "ownerInvitations",
                record("invite", json!({ "expiresAt": past, "consumed": false })),
            ),
            ("scimConnections", record("scim", json!({ "expiresAt": past }))),
            (
                "accessRequests",
                record(
                    "request",
                    json!({ "expiresAt": past, "status": "pending" }),
                ),
            ),
        ]);
        seed(&database, rows).await;
        let result = sweep(&iam, json!({ "now": NOW })).await;
        assert_eq!(
            result,
            json!({
                "deleted": {
                    "sessions": 1,
                    "authDevices": 1,
                    "relationships": 1,
                    "oauthArtifacts": 2,
                    "oauthLoginStates": 1,
                    "samlRequests": 1,
                    "samlRelays": 1,
                    "samlAssertions": 1,
                    "ssfDeliveries": 2,
                    "auditHooks": 2,
                },
                "total": 13,
                "truncated": false,
            })
        );
        // The collections appear in the order the sweep reaches them.
        let order: Vec<&String> = result["deleted"].as_object().unwrap().keys().collect();
        assert_eq!(
            order,
            [
                "sessions",
                "authDevices",
                "relationships",
                "oauthArtifacts",
                "oauthLoginStates",
                "samlRequests",
                "samlRelays",
                "samlAssertions",
                "ssfDeliveries",
                "auditHooks"
            ]
        );
        assert_eq!(ids(&database, "sessions").await, ["future-kind", "key-old"]);
        assert_eq!(ids(&database, "relationships").await, ["forever", "live"]);
        assert_eq!(
            ids(&database, "oauthArtifacts").await,
            ["grant-recent", "live"]
        );
        assert_eq!(
            ids(&database, "ssfDeliveries").await,
            ["failed-new", "pending-old"]
        );
        assert_eq!(ids(&database, "auditHooks").await, ["waiting"]);
        for collection in ["ownerInvitations", "scimConnections", "accessRequests"] {
            assert_eq!(ids(&database, collection).await.len(), 1);
        }
    });
}

#[test]
fn sweeps_expired_session_tokens_and_redeemed_web_identity_tokens_keeping_expired_api_keys() {
    run(|| async {
        let (iam, database) = standalone(None, |_| {}).await;
        let past = NOW - 10.0 * 60_000.0;
        let future = NOW + 60_000.0;
        seed(
            &database,
            vec![
                (
                    "sessions",
                    record(
                        "sts-old",
                        json!({ "kind": "session-token", "tokenHash": "s1", "expiresAt": past }),
                    ),
                ),
                (
                    "sessions",
                    record(
                        "sts-live",
                        json!({ "kind": "session-token", "tokenHash": "s2", "expiresAt": future }),
                    ),
                ),
                (
                    "sessions",
                    record(
                        "key-old",
                        json!({ "kind": "api-key", "tokenHash": "k", "expiresAt": past }),
                    ),
                ),
                (
                    "webIdentityReplays",
                    record(
                        "replay-old",
                        json!({ "providerId": "p", "expiresAt": past }),
                    ),
                ),
                (
                    "webIdentityReplays",
                    record(
                        "replay-live",
                        json!({ "providerId": "p", "expiresAt": future }),
                    ),
                ),
            ],
        )
        .await;
        assert_eq!(
            sweep(&iam, json!({ "now": NOW })).await,
            json!({ "deleted": { "sessions": 1, "webIdentityReplays": 1 }, "total": 2, "truncated": false })
        );
        assert_eq!(ids(&database, "sessions").await, ["key-old", "sts-live"]);
        assert_eq!(ids(&database, "webIdentityReplays").await, ["replay-live"]);
        // Within the grace period nothing is due yet.
        seed(
            &database,
            vec![(
                "webIdentityReplays",
                record(
                    "replay-recent",
                    json!({ "providerId": "p", "expiresAt": NOW - 1000.0 }),
                ),
            )],
        )
        .await;
        assert_eq!(
            sweep(&iam, json!({ "now": NOW })).await["deleted"],
            json!({})
        );
    });
}

#[test]
fn works_in_short_batches_stops_at_the_limit_and_continues_on_the_next_run() {
    run(|| async {
        let calls: Arc<Mutex<Vec<StoreCall>>> = Arc::default();
        let (iam, database) = standalone(Some(calls.clone()), |_| {}).await;
        seed(
            &database,
            (0..23)
                .map(|index| {
                    (
                        "oauthArtifacts",
                        record(
                            &format!("a{index:02}"),
                            json!({ "expiresAt": NOW - (index as f64 + 1.0) * DAY }),
                        ),
                    )
                })
                .collect(),
        )
        .await;
        calls.lock().unwrap().clear();
        let first = sweep(&iam, json!({ "now": NOW, "batchSize": 5, "limit": 12 })).await;
        assert_eq!(
            first,
            json!({ "deleted": { "oauthArtifacts": 12 }, "total": 12, "truncated": true })
        );
        // Oldest first, and never more than one batch per read.
        let expected: Vec<String> = (0..11).map(|index| format!("a{index:02}")).collect();
        assert_eq!(ids(&database, "oauthArtifacts").await, expected);
        let calls_seen = calls.lock().unwrap().clone();
        assert!(
            calls_seen
                .iter()
                .filter(|call| call.method == StoreMethod::FindOrdered)
                .all(|call| call
                    .page
                    .as_ref()
                    .and_then(|page| page.limit)
                    .is_some_and(|limit| limit <= 5))
        );
        let deletes: Vec<&StoreCall> = calls_seen
            .iter()
            .filter(|call| call.method == StoreMethod::Delete)
            .collect();
        assert_eq!(deletes.len(), 12);
        assert!(deletes.iter().all(|call| call.in_transaction));
        let second = sweep(&iam, json!({ "now": NOW, "batchSize": 5 })).await;
        assert_eq!(
            second,
            json!({ "deleted": { "oauthArtifacts": 11 }, "total": 11, "truncated": false })
        );
    });
}

#[test]
fn steps_over_records_it_keeps_instead_of_reading_them_again() {
    run(|| async {
        let calls: Arc<Mutex<Vec<StoreCall>>> = Arc::default();
        let (iam, database) = standalone(Some(calls.clone()), |_| {}).await;
        // Expired API keys interleaved with expired user sessions, several sharing one expiry.
        seed(
            &database,
            (0..24)
                .map(|index| {
                    (
                        "sessions",
                        record(
                            &format!("s{index:02}"),
                            json!({
                                "kind": if index % 2 == 1 { "api-key" } else { "user" },
                                "tokenHash": format!("h{index}"),
                                "expiresAt": NOW - DAY - ((index / 6) as f64) * 60_000.0,
                            }),
                        ),
                    )
                })
                .collect(),
        )
        .await;
        calls.lock().unwrap().clear();
        let result = sweep(&iam, json!({ "now": NOW, "batchSize": 5 })).await;
        assert_eq!(
            result,
            json!({ "deleted": { "sessions": 12 }, "total": 12, "truncated": false })
        );
        let kinds: Vec<Value> = database
            .find("sessions", &Filter::new(), &FindOptions::default())
            .await
            .unwrap()
            .iter()
            .map(|session| session["kind"].clone())
            .collect();
        assert_eq!(kinds, vec![json!("api-key"); 12]);
        let calls_seen = calls.lock().unwrap().clone();
        let session_reads: Vec<&StoreCall> = calls_seen
            .iter()
            .filter(|call| call.method == StoreMethod::FindOrdered && call.collection == "sessions")
            .collect();
        // 24 due records in batches of 5: four full reads and one short one, never a re-read.
        assert_eq!(
            session_reads.iter().map(|call| call.records).sum::<u64>(),
            24
        );
        assert_eq!(session_reads.len(), 5);
    });
}

#[test]
fn stamps_dispatched_audit_hooks_and_tolerates_rows_removed_by_an_overlapping_dispatcher() {
    run(|| async {
        let remove_first = Arc::new(AtomicBool::new(true));
        let holder: Arc<Mutex<Option<Arc<dyn IamStore>>>> = Arc::default();
        let (flag, slot) = (remove_first.clone(), holder.clone());
        let (iam, database) = standalone(None, move |options| {
            *slot.lock().unwrap() = options.database.clone();
            let slot = slot.clone();
            options.events = Some(EventOptions {
                // Meanwhile another dispatcher delivered the first row and a sweep deleted it.
                on_event: Some(Arc::new(move |event: Record| {
                    let flag = flag.clone();
                    let store = slot.lock().unwrap().clone();
                    Box::pin(async move {
                        if !flag.swap(false, Ordering::SeqCst) {
                            return Ok(());
                        }
                        let id = event["id"].as_str().unwrap_or_default().to_owned();
                        if let Some(store) = store {
                            store
                                .transaction(|tx| async move { tx.delete("auditHooks", &id).await })
                                .await?;
                        }
                        Ok(())
                    })
                })),
                ..EventOptions::default()
            });
        })
        .await;
        let _ = holder;
        iam.bootstrap(&json!({
            "email": "root@example.test",
            "name": "Root",
            "password": "a strong root test password",
        }))
        .await
        .unwrap();
        let pending = database
            .find(
                "auditHooks",
                &Filter::new().eq("delivered", false),
                &FindOptions::default(),
            )
            .await
            .unwrap()
            .len();
        assert!(pending > 1);
        assert_eq!(
            iam.dispatch_audit_hooks().await.unwrap()["dispatched"].as_f64(),
            Some(pending as f64)
        );
        let rows = database
            .find("auditHooks", &Filter::new(), &FindOptions::default())
            .await
            .unwrap();
        assert_eq!(rows.len(), pending - 1);
        assert!(rows.iter().all(|row| row["delivered"] == json!(true)
            && row.get("deliveredAt").is_some_and(Value::is_number)));
        let later = better_iam_server::utils::date_now() + 3_600_000.0;
        assert_eq!(
            sweep(&iam, json!({ "now": later })).await["deleted"]["auditHooks"].as_f64(),
            Some((pending - 1) as f64)
        );
    });
}

#[test]
fn validates_its_options() {
    run(|| async {
        let (iam, _) = standalone(None, |_| {}).await;
        let cases = [
            (
                json!({ "batchSize": 0 }),
                "batchSize must be an integer between 1 and 5000",
            ),
            (
                json!({ "batchSize": 5001 }),
                "batchSize must be an integer between 1 and 5000",
            ),
            (
                json!({ "limit": 0 }),
                "limit must be an integer between 1 and 1000000",
            ),
            (
                json!({ "limit": 1.5 }),
                "limit must be an integer between 1 and 1000000",
            ),
            (
                json!({ "limit": "5" }),
                "limit must be an integer between 1 and 1000000",
            ),
            (
                json!({ "graceMs": -1 }),
                "graceMs must be an integer between 0 and 86400000",
            ),
            (
                json!({ "graceMs": 2.0 * DAY }),
                "graceMs must be an integer between 0 and 86400000",
            ),
            (
                json!({ "deliveryRetentionMs": 3651.0 * DAY }),
                "deliveryRetentionMs must be an integer between 0 and 315360000000",
            ),
            (
                json!({ "now": null }),
                "now must be a finite number of milliseconds",
            ),
            (
                json!({ "now": "soon" }),
                "now must be a finite number of milliseconds",
            ),
        ];
        for (options, message) in cases {
            let error = iam.sweep_expired(Some(&options)).await.unwrap_err();
            assert_eq!(error.code, "INVALID_INPUT", "{options}");
            assert_eq!(error.message, message, "{options}");
        }
        // Null members fall back to their defaults (`value ?? fallback`).
        assert_eq!(
            iam.sweep_expired(Some(&json!({ "batchSize": null, "limit": null })))
                .await
                .unwrap(),
            json!({ "deleted": {}, "total": 0, "truncated": false })
        );
    });
}

#[test]
fn counts_overdue_records_up_to_a_cap() {
    run(|| async {
        let (iam, database) = standalone(None, |_| {}).await;
        let now = better_iam_server::utils::date_now();
        let mut rows: Vec<(&str, Record)> = (0..7)
            .map(|index| {
                (
                    "oauthArtifacts",
                    record(
                        &format!("o{index}"),
                        json!({ "expiresAt": now - 2.0 * DAY - index as f64 }),
                    ),
                )
            })
            .collect();
        rows.push((
            "oauthArtifacts",
            record("recent", json!({ "expiresAt": now - 60.0 * 60_000.0 })),
        ));
        rows.push((
            "oauthArtifacts",
            record(
                "grant",
                json!({ "model": "Grant", "expiresAt": now - 2.0 * DAY }),
            ),
        ));
        rows.push(("auditHooks", record("legacy", json!({ "delivered": true }))));
        seed(&database, rows).await;
        let options = |cap: f64| DueOptions {
            overdue_ms: DAY,
            cap,
            delivery_retention_ms: None,
            grace_ms: None,
            extra: serde_json::Map::new(),
        };
        let counts = iam.retention.count_due(&options(100.0)).await.unwrap();
        assert_eq!(counts.get("oauthArtifacts"), Some(&7.0));
        assert_eq!(counts.get("auditHooks"), Some(&1.0));
        assert_eq!(counts.get("sessions"), Some(&0.0));
        let capped = iam.retention.count_due(&options(3.0)).await.unwrap();
        assert_eq!(capped.get("oauthArtifacts"), Some(&3.0));
        // Reads only: everything is still there.
        assert_eq!(ids(&database, "oauthArtifacts").await.len(), 9);
        let error = iam
            .retention
            .count_due(&DueOptions {
                grace_ms: Some(-1.0),
                ..options(10.0)
            })
            .await
            .unwrap_err();
        assert_eq!(
            error.message,
            "graceMs must be an integer between 0 and 86400000"
        );
    });
}
