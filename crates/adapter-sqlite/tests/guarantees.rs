//! Port of `tests/adapters.test.ts` ("SQLite adapter guarantees").

use std::sync::{Arc, Mutex};
use std::time::Duration;

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_core::{Filter, FindOptions, IamError, IamStore, IamStoreExt, Record, js, record};
use serde_json::json;

struct Fixture {
    _directory: tempfile::TempDir,
    path: String,
    store: Arc<dyn IamStore>,
}

async fn fixture() -> Fixture {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory
        .path()
        .join("iam.sqlite")
        .to_string_lossy()
        .into_owned();
    let store = sqlite_adapter(SqliteAdapterOptions::new(path.clone())).expect("store");
    store.migrate().await.expect("migrate");
    Fixture {
        _directory: directory,
        path,
        store,
    }
}

fn r(value: serde_json::Value) -> Record {
    record(value)
}

async fn all(store: &Arc<dyn IamStore>, collection: &str) -> Vec<Record> {
    store
        .find(collection, &Filter::new(), &FindOptions::default())
        .await
        .expect("find")
}

#[tokio::test(flavor = "multi_thread")]
async fn migrates_idempotently_rejects_writes_without_a_transaction_and_enforces_tenant_scoped_keys()
 {
    let Fixture { store, .. } = fixture().await;
    store.migrate().await.expect("migrate again");
    let error = store
        .insert("users", &r(json!({ "id": "one", "tenantId": "a" })))
        .await
        .unwrap_err();
    assert_eq!(error.code, "TRANSACTION_REQUIRED");
    store
        .transaction(|tx| async move {
            tx.insert(
                "users",
                &r(json!({ "id": "one", "tenantId": "a", "uniqueKey": "same@example.com" })),
            )
            .await?;
            tx.insert(
                "users",
                &r(json!({ "id": "two", "tenantId": "b", "uniqueKey": "same@example.com" })),
            )
            .await?;
            tx.insert("users", &r(json!({ "id": "three", "tenantId": "a" })))
                .await?;
            tx.insert("users", &r(json!({ "id": "four", "tenantId": "a" })))
                .await
        })
        .await
        .expect("seed");
    let error = store
        .transaction(|tx| async move {
            tx.insert(
                "users",
                &r(json!({ "id": "five", "tenantId": "a", "uniqueKey": "same@example.com" })),
            )
            .await
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, "CONFLICT");
    let error = store
        .transaction(|tx| async move {
            tx.insert("users", &r(json!({ "id": "one", "tenantId": "b" })))
                .await
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, "CONFLICT");
    assert_eq!(
        store
            .find(
                "users",
                &Filter::new().eq("tenantId", "b"),
                &FindOptions::default()
            )
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rolls_back_across_awaits_and_nested_transactions_and_rejects_escaped_handles() {
    let Fixture { store, .. } = fixture().await;
    let leaked: Arc<Mutex<Option<Arc<dyn IamStore>>>> = Arc::new(Mutex::new(None));
    let slot = leaked.clone();
    let root = store.clone();
    let error = store
        .transaction(move |tx| async move {
            *slot.lock().unwrap() = Some(tx.clone());
            tx.insert("items", &r(json!({ "id": "first", "tenantId": "a" })))
                .await?;
            tokio::time::sleep(Duration::from_millis(2)).await;
            root.transaction(|nested| async move {
                nested
                    .insert("items", &r(json!({ "id": "second", "tenantId": "a" })))
                    .await
            })
            .await?;
            Err::<(), _>(IamError::new("ROLLBACK_ME", "rollback-me"))
        })
        .await
        .unwrap_err();
    assert_eq!(error.message, "rollback-me");
    assert!(all(&store, "items").await.is_empty());
    let handle = leaked.lock().unwrap().clone().unwrap();
    assert_eq!(
        handle.get("items", "first").await.unwrap_err().code,
        "TRANSACTION_CLOSED"
    );
    let error = store
        .transaction(|tx| async move {
            tx.insert("items", &r(json!({ "id": "first", "tenantId": "a" })))
                .await?;
            // Caller cannot commit a failed nested operation.
            let _ = tx
                .transaction(|_| async move { Err::<(), _>(IamError::new("NESTED", "nested")) })
                .await;
            Ok(())
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, "TRANSACTION_ABORTED");
    assert!(all(&store, "items").await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn does_not_resurrect_missing_records_or_change_record_tenant_ownership() {
    let Fixture { store, .. } = fixture().await;
    let error = store
        .transaction(|tx| async move {
            tx.put("items", &r(json!({ "id": "missing", "tenantId": "a" })))
                .await
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, "NOT_FOUND");
    store
        .transaction(|tx| async move {
            tx.insert(
                "items",
                &r(json!({ "id": "one", "tenantId": "a", "value": 1 })),
            )
            .await
        })
        .await
        .unwrap();
    let error = store
        .transaction(|tx| async move {
            tx.put(
                "items",
                &r(json!({ "id": "one", "tenantId": "b", "value": 2 })),
            )
            .await
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, "CONFLICT");
    store
        .transaction(|tx| async move {
            tx.put(
                "items",
                &r(json!({ "id": "one", "tenantId": "a", "value": 3 })),
            )
            .await
        })
        .await
        .unwrap();
    assert_eq!(
        store.get("items", "one").await.unwrap().unwrap()["value"],
        json!(3)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn uses_strict_json_filters_deterministic_pagination_and_detached_data() {
    let Fixture { store, .. } = fixture().await;
    store
        .transaction(|tx| async move {
            tx.insert("items", &r(json!({ "id": "a", "tenantId": "t", "value": 1, "nested": { "a": true, "b": null }, "tags": ["x", "y"] })))
                .await?;
            tx.insert("items", &r(json!({ "id": "b", "tenantId": "t", "value": "1" }))).await?;
            tx.insert("items", &r(json!({ "id": "c", "tenantId": "t", "value": null }))).await
        })
        .await
        .unwrap();
    let find = |filter: Filter, options: FindOptions| {
        let store = store.clone();
        async move { store.find("items", &filter, &options).await }
    };
    assert_eq!(
        find(Filter::new().eq("value", 1), FindOptions::default())
            .await
            .unwrap()
            .len(),
        1
    );
    let nested = Filter::new()
        .eq("nested", json!({ "b": null, "a": true }))
        .eq("tags", json!(["x", "y"]));
    assert_eq!(find(nested, FindOptions::default()).await.unwrap().len(), 1);
    assert_eq!(
        find(
            Filter::new().eq("nested", json!({ "a": true })),
            FindOptions::default()
        )
        .await
        .unwrap()
        .len(),
        0
    );
    let paged = find(
        Filter::new().eq("tenantId", "t"),
        FindOptions {
            offset: Some(1),
            limit: Some(1),
            after: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        paged
            .iter()
            .map(|record| record["id"].clone())
            .collect::<Vec<_>>(),
        vec![json!("b")]
    );
    assert!(
        find(Filter::new(), FindOptions::limit(0))
            .await
            .unwrap()
            .is_empty()
    );
    let error = find(
        Filter::new(),
        FindOptions {
            offset: Some(-1),
            ..FindOptions::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, "INVALID_FILTER");
}

#[tokio::test(flavor = "multi_thread")]
async fn serializes_concurrent_read_modify_write_across_two_database_connections() {
    let Fixture { store, path, .. } = fixture().await;
    let second = sqlite_adapter(SqliteAdapterOptions::new(path)).unwrap();
    second.migrate().await.unwrap();
    store
        .transaction(|tx| async move {
            tx.insert(
                "counter",
                &r(json!({ "id": "counter", "tenantId": "a", "value": 0 })),
            )
            .await
        })
        .await
        .unwrap();
    let runs = (0..20).map(|index| {
        let db = if index % 2 == 1 {
            store.clone()
        } else {
            second.clone()
        };
        async move {
            db.transaction(|tx| async move {
                let mut current = tx.get("counter", "counter").await?.unwrap();
                tokio::time::sleep(Duration::from_millis(1)).await;
                let value = js::as_number(&current["value"]).unwrap_or(0.0);
                current.insert("value".into(), json!(value + 1.0));
                tx.put("counter", &current).await
            })
            .await
        }
    });
    for outcome in futures::future::join_all(runs).await {
        outcome.unwrap();
    }
    assert_eq!(
        js::as_number(&store.get("counter", "counter").await.unwrap().unwrap()["value"]),
        Some(20.0)
    );
    second.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn atomically_consumes_single_use_records_under_concurrency() {
    let Fixture { store, path, .. } = fixture().await;
    let second = sqlite_adapter(SqliteAdapterOptions::new(path)).unwrap();
    store
        .transaction(|tx| async move {
            tx.insert("tokens", &r(json!({ "id": "one", "tenantId": "a" })))
                .await
        })
        .await
        .unwrap();
    let consume = |db: Arc<dyn IamStore>| async move {
        db.transaction(|tx| async move {
            let record = tx.get("tokens", "one").await?;
            tokio::time::sleep(Duration::from_millis(1)).await;
            if record.is_none() {
                return Ok(false);
            }
            tx.delete("tokens", "one").await?;
            Ok(true)
        })
        .await
    };
    let outcomes = futures::future::join_all([
        consume(store.clone()),
        consume(second.clone()),
        consume(store.clone()),
    ])
    .await;
    assert_eq!(
        outcomes
            .into_iter()
            .filter(|outcome| *outcome.as_ref().unwrap())
            .count(),
        1
    );
    second.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn does_not_expose_dirty_reads_through_the_root_adapter() {
    let Fixture { store, .. } = fixture().await;
    let (notify, inserted) = tokio::sync::oneshot::channel::<()>();
    let transaction = store.transaction(move |tx| async move {
        tx.insert("items", &r(json!({ "id": "uncommitted", "tenantId": "a" })))
            .await?;
        let _ = notify.send(());
        tokio::time::sleep(Duration::from_millis(10)).await;
        Err::<(), _>(IamError::new("ROLLBACK", "rollback"))
    });
    let read = async {
        inserted.await.unwrap();
        store.get("items", "uncommitted").await
    };
    let (outcome, read) = tokio::join!(transaction, read);
    assert_eq!(outcome.unwrap_err().message, "rollback");
    assert!(read.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn closes_idempotently_and_rejects_operations_after_closure() {
    let Fixture { store, .. } = fixture().await;
    store.close().await.unwrap();
    store.close().await.unwrap();
    assert_eq!(
        store.get("items", "one").await.unwrap_err().code,
        "STORE_CLOSED"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_oversized_multibyte_natural_keys_consistently_with_postgresql_index_limits() {
    let Fixture { store, .. } = fixture().await;
    let error = store
        .transaction(|tx| async move {
            tx.insert(
                "items",
                &r(json!({ "id": "unicode", "tenantId": "a", "uniqueKey": "界".repeat(171) })),
            )
            .await
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, "INVALID_RECORD");
    store
        .transaction(|tx| async move {
            tx.insert(
                "items",
                &r(json!({ "id": "unicode", "tenantId": "a", "uniqueKey": "界".repeat(170) })),
            )
            .await
        })
        .await
        .unwrap();
    assert!(store.get("items", "unicode").await.unwrap().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn validates_options_like_the_typescript_adapter() {
    let invalid = |options: SqliteAdapterOptions| {
        sqlite_adapter(options)
            .err()
            .map(|error| (error.code, error.message))
    };
    assert_eq!(
        invalid(SqliteAdapterOptions::new("file:iam.db")),
        Some((
            "INVALID_CONFIG".into(),
            "SQLite requires a filename or :memory:; URI filenames are unsupported".into()
        ))
    );
    assert_eq!(
        invalid(SqliteAdapterOptions {
            busy_timeout_ms: Some(60_001),
            ..SqliteAdapterOptions::new(":memory:")
        }),
        Some((
            "INVALID_CONFIG".into(),
            "busyTimeoutMs must be between 0 and 60000".into()
        ))
    );
    assert_eq!(
        invalid(SqliteAdapterOptions {
            journal_mode: Some("memory".into()),
            ..SqliteAdapterOptions::new(":memory:")
        }),
        Some((
            "INVALID_CONFIG".into(),
            "journalMode must be wal or delete".into()
        ))
    );
    assert_eq!(
        invalid(SqliteAdapterOptions {
            durability: Some("off".into()),
            ..SqliteAdapterOptions::new(":memory:")
        }),
        Some((
            "INVALID_CONFIG".into(),
            "durability must be full or normal".into()
        ))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn describes_the_database() {
    let Fixture { store, .. } = fixture().await;
    store
        .transaction(|tx| async move {
            tx.insert("items", &r(json!({ "id": "one", "tenantId": "a" })))
                .await
        })
        .await
        .unwrap();
    let description = store.describe().await.unwrap();
    assert_eq!(description.adapter, "sqlite");
    assert_eq!(description.schema_version, Some(1.0));
    assert_eq!(description.migrations.len(), 6);
    assert_eq!(description.collections.len(), 1);
    assert_eq!(description.settings["journalMode"], json!("wal"));
    assert_eq!(description.settings["synchronous"], json!("full"));
    assert_eq!(description.settings["inMemory"], json!(false));
    let fresh = sqlite_adapter(SqliteAdapterOptions::new(":memory:")).unwrap();
    let empty = fresh.describe().await.unwrap();
    assert_eq!(empty.schema_version, None);
    assert!(empty.migrations.is_empty() && empty.collections.is_empty());
}
