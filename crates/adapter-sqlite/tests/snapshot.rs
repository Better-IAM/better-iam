//! `spec/vectors/snapshot.json` against SQLite `:memory:`, the store the TypeScript generator used.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_core::{
    Filter, FindOptions, IamStore, IamStoreExt, SnapshotOptions, export_store, import_store, js,
    record, record_id,
};
use serde_json::{Map, Value, json};

const NOW: f64 = 1_767_225_600_000.0;

fn store() -> Arc<dyn IamStore> {
    sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("store")
}

fn error(error: &better_iam_core::IamError) -> Value {
    json!({ "$error": { "name": "IamError", "code": error.code, "status": error.status, "message": error.message } })
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_vectors_on_sqlite() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/snapshot.json");
    let file: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("vectors")).expect("json");
    let mut failures = Vec::new();
    let cases = file["cases"].as_array().expect("cases");
    for case in cases {
        let (name, input) = (case["name"].as_str().unwrap_or_default(), &case["input"]);
        let store = store();
        store.migrate().await.expect("migrate");
        let actual = if name.starts_with("export") {
            let records = input["records"].clone();
            store
                .transaction(move |tx| async move {
                    for (collection, list) in records.as_object().into_iter().flatten() {
                        for item in list.as_array().into_iter().flatten() {
                            tx.insert(collection, &record(item.clone())).await?;
                        }
                    }
                    Ok(())
                })
                .await
                .expect("seed");
            let options = input.get("options").cloned().unwrap_or(json!({}));
            let options = SnapshotOptions {
                collections: options
                    .get("collections")
                    .and_then(Value::as_array)
                    .map(|names| {
                        names
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    }),
                page_size: options.get("pageSize").and_then(Value::as_i64),
                now: Some(NOW),
            };
            let lines = Arc::new(Mutex::new(Vec::<String>::new()));
            let sink = lines.clone();
            match export_store(
                store.as_ref(),
                move |line| {
                    sink.lock().expect("lines").push(line);
                    Ok(())
                },
                &options,
            )
            .await
            {
                Ok(summary) => {
                    json!({ "lines": *lines.lock().expect("lines"), "summary": summary.to_value() })
                }
                Err(failure) => error(&failure),
            }
        } else {
            if let Some(existing) = input.get("existing") {
                let existing = record(existing.clone());
                store
                    .transaction(move |tx| async move { tx.insert("tenants", &existing).await })
                    .await
                    .expect("existing");
            }
            let lines: Vec<String> = input["lines"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            match import_store(store.as_ref(), lines).await {
                Ok(summary) => {
                    let mut stored = Map::new();
                    for collection in store.collections().await.expect("collections") {
                        let ids = store
                            .find(&collection, &Filter::new(), &FindOptions::default())
                            .await
                            .expect("find");
                        stored.insert(
                            collection,
                            ids.iter()
                                .map(|item| Value::String(record_id(item).to_owned()))
                                .collect(),
                        );
                    }
                    json!({ "summary": summary.to_value(), "stored": stored })
                }
                Err(failure) => error(&failure),
            }
        };
        if !js::deep_equal(&actual, &case["output"]) {
            failures.push(format!(
                "{name}: expected {}, received {}",
                case["output"], actual
            ));
        }
        store.close().await.expect("close");
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    println!("snapshot vectors on SQLite: {} passed", cases.len());
}
