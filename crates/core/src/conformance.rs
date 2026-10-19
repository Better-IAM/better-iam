//! The behavioral contract every [`IamStore`] adapter must satisfy (`@better-iam/core/conformance`), ported case for
//! case. Give every case a freshly created and migrated store, then close it afterwards (a case may close the store
//! itself; `close()` must be idempotent).
//!
//! ```ignore
//! for case in adapter_conformance_cases() {
//!     let store = my_adapter(options)?;
//!     store.migrate().await?;
//!     let outcome = (case.run)(store.clone()).await;
//!     store.close().await?;
//!     outcome?;
//! }
//! ```
//!
//! Inputs JavaScript can build but a `serde_json::Value` cannot hold are left out, each noted where its case
//! stands: unpaired UTF-16 surrogates, `undefined` array items, sparse arrays and arrays with extra properties,
//! `NaN`/`Infinity`, `Date`/`Map`/function/symbol values, circular references, fractional pagination numbers and
//! non-string cursors (the Rust types refuse them at compile time).

use std::sync::{Arc, Mutex};

use futures::future::{BoxFuture, join_all};
use serde_json::{Map, Value, json};

use crate::js;
use crate::storage::{Filter, compare_ids, find_ordered};
use crate::{
    Direction, FindOptions, IamError, IamResult, IamStore, IamStoreExt, OrderOptions, Record,
};

/// A conformance failure (`ConformanceFailure`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConformanceFailure(pub String);

impl From<IamError> for ConformanceFailure {
    fn from(error: IamError) -> Self {
        ConformanceFailure(format!("{}: {}", error.code, error.message))
    }
}

type Outcome = Result<(), ConformanceFailure>;

/// One case (`ConformanceCase`).
#[derive(Clone)]
pub struct ConformanceCase {
    pub name: &'static str,
    pub run: fn(Arc<dyn IamStore>) -> BoxFuture<'static, Outcome>,
}

fn check(condition: bool, message: &str) -> Outcome {
    if condition {
        Ok(())
    } else {
        Err(ConformanceFailure(message.to_owned()))
    }
}

/// `canonical`: sorted-key JSON; None is `undefined`.
fn canonical(value: Option<&Value>) -> String {
    match value {
        None => "undefined".into(),
        Some(Value::Array(items)) => format!(
            "[{}]",
            items
                .iter()
                .map(|item| canonical(Some(item)))
                .collect::<Vec<_>>()
                .join(",")
        ),
        Some(Value::Object(map)) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|left, right| js::cmp_utf16(left, right));
            format!(
                "{{{}}}",
                keys.iter()
                    .map(|key| format!("{}:{}", js::quote(key), canonical(map.get(*key))))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        Some(other) => js::stringify(other),
    }
}

fn same(actual: Option<&Value>, expected: Option<&Value>, message: &str) -> Outcome {
    let (left, right) = (canonical(actual), canonical(expected));
    check(
        left == right,
        &format!("{message}: expected {right}, received {left}"),
    )
}

fn same_ids(records: &[Record], expected: &[&str], message: &str) -> Outcome {
    let actual = Value::Array(
        records
            .iter()
            .map(|record| Value::String(crate::record_id(record).to_owned()))
            .collect(),
    );
    let expected = Value::Array(
        expected
            .iter()
            .map(|id| Value::String((*id).to_owned()))
            .collect(),
    );
    same(Some(&actual), Some(&expected), message)
}

fn same_id_strings(records: &[Record], expected: &[String], message: &str) -> Outcome {
    let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
    same_ids(records, &expected, message)
}

async fn rejects<T>(
    operation: impl std::future::Future<Output = IamResult<T>>,
    code: &str,
    message: &str,
) -> Result<IamError, ConformanceFailure> {
    match operation.await {
        Ok(_) => Err(ConformanceFailure(format!(
            "{message}: expected {code}, but the operation succeeded"
        ))),
        Err(error) if error.code == code => Ok(error),
        Err(error) => Err(ConformanceFailure(format!(
            "{message}: expected {code}, received {}",
            error.code
        ))),
    }
}

fn record(value: Value) -> Record {
    crate::record(value)
}

async fn seed(
    store: &Arc<dyn IamStore>,
    collection: &'static str,
    records: Vec<Record>,
) -> Outcome {
    store
        .transaction(move |tx| async move {
            for record in &records {
                tx.insert(collection, record).await?;
            }
            Ok(())
        })
        .await?;
    Ok(())
}

fn filter(value: Value) -> Filter {
    match value {
        Value::Object(map) => Filter::from(map),
        _ => Filter::new(),
    }
}

async fn find(
    store: &Arc<dyn IamStore>,
    collection: &str,
    filter: &Filter,
    options: FindOptions,
) -> Result<Vec<Record>, ConformanceFailure> {
    Ok(store.find(collection, filter, &options).await?)
}

fn page(offset: i64, limit: i64) -> FindOptions {
    FindOptions {
        offset: Some(offset),
        limit: Some(limit),
        after: None,
    }
}

fn num(value: f64) -> Value {
    js::number(value).unwrap_or(Value::Null)
}

macro_rules! case {
    ($name:literal, $body:ident) => {
        ConformanceCase {
            name: $name,
            run: |store| Box::pin($body(store)),
        }
    };
}

async fn round_trips(store: Arc<dyn IamStore>) -> Outcome {
    let original = record(json!({
        "id": "r1",
        "tenantId": "t1",
        "name": "Ada",
        "nested": { "list": [1, "two", true, null, { "deep": "é 😀 中文" }] },
        "sum": num(0.1 + 0.2),
        "large": num(2f64.powi(53) + 2.0),
        "small": num(5e-324),
        "exponent": num(1e21),
    }));
    seed(&store, "items", vec![original.clone()]).await?;
    let read = store.get("items", "r1").await?;
    let expected = js::parse(&js::stringify_object(&original))
        .map_err(|error| ConformanceFailure(error.to_string()))?;
    same(
        read.clone().map(Value::Object).as_ref(),
        Some(&expected),
        "get returns the stored record",
    )?;
    check(read.is_some(), "inserted records can be read")?;
    let mut read = read.unwrap_or_default();
    read.insert("name".into(), json!("changed"));
    let again = store.get("items", "r1").await?;
    check(
        again.and_then(|record| record.get("name").cloned()) == Some(json!("Ada")),
        "records are detached copies",
    )?;
    check(
        store.get("items", "missing").await?.is_none(),
        "missing ids read as undefined",
    )?;
    check(
        store.get("other", "r1").await?.is_none(),
        "collections are separate",
    )
}

async fn uniqueness(store: Arc<dyn IamStore>) -> Outcome {
    seed(
        &store,
        "users",
        vec![
            record(json!({ "id": "one", "tenantId": "a", "uniqueKey": "same@example.com" })),
            record(json!({ "id": "two", "tenantId": "b", "uniqueKey": "same@example.com" })),
            record(json!({ "id": "three", "tenantId": "a" })),
        ],
    )
    .await?;
    seed(
        &store,
        "groups",
        vec![record(json!({ "id": "one", "tenantId": "a" }))],
    )
    .await?;
    rejects(
        store.transaction(|tx| async move {
            tx.insert("users", &record(json!({ "id": "one", "tenantId": "c" })))
                .await
        }),
        "CONFLICT",
        "ids are unique per collection across tenants",
    )
    .await?;
    rejects(
        store.transaction(|tx| async move {
            tx.insert(
                "users",
                &record(json!({ "id": "four", "tenantId": "a", "uniqueKey": "same@example.com" })),
            )
            .await
        }),
        "CONFLICT",
        "natural keys are unique within a tenant",
    )
    .await?;
    rejects(
        store.transaction(|tx| async move {
            tx.put(
                "users",
                &record(json!({ "id": "three", "tenantId": "a", "uniqueKey": "same@example.com" })),
            )
            .await
        }),
        "CONFLICT",
        "put cannot take another record’s natural key",
    )
    .await?;
    rejects(
        store.transaction(|tx| async move {
            tx.insert("users", &record(json!({ "id": "five", "tenantId": "a" })))
                .await?;
            // A caught storage failure still dooms the transaction.
            let _ = tx
                .insert("users", &record(json!({ "id": "one", "tenantId": "a" })))
                .await;
            Ok(())
        }),
        "TRANSACTION_ABORTED",
        "a failed statement aborts the enclosing transaction",
    )
    .await?;
    check(
        store.get("users", "five").await?.is_none(),
        "aborted writes are rolled back",
    )
}

async fn replaces_on_put(store: Arc<dyn IamStore>) -> Outcome {
    seed(&store, "items", vec![record(json!({ "id": "x", "tenantId": "t1", "uniqueKey": "key-x", "label": "first", "extra": true }))])
        .await?;
    rejects(
        store.transaction(|tx| async move {
            tx.put(
                "items",
                &record(json!({ "id": "missing", "tenantId": "t1" })),
            )
            .await
        }),
        "NOT_FOUND",
        "put does not insert",
    )
    .await?;
    rejects(
        store.transaction(|tx| async move {
            tx.put("items", &record(json!({ "id": "x", "tenantId": "t2" })))
                .await
        }),
        "CONFLICT",
        "tenant ownership is immutable",
    )
    .await?;
    store
        .transaction(|tx| async move {
            tx.put(
                "items",
                &record(json!({ "id": "x", "tenantId": "t1", "label": "second" })),
            )
            .await
        })
        .await?;
    same(
        store.get("items", "x").await?.map(Value::Object).as_ref(),
        Some(&json!({ "id": "x", "tenantId": "t1", "label": "second" })),
        "put replaces the record",
    )?;
    check(
        find(
            &store,
            "items",
            &filter(json!({ "extra": true })),
            FindOptions::default(),
        )
        .await?
        .is_empty(),
        "removed fields stop matching",
    )?;
    seed(
        &store,
        "items",
        vec![record(
            json!({ "id": "y", "tenantId": "t1", "uniqueKey": "key-x" }),
        )],
    )
    .await?;
    let found = find(
        &store,
        "items",
        &filter(json!({ "uniqueKey": "key-x" })),
        FindOptions::default(),
    )
    .await?;
    check(
        found.first().map(crate::record_id) == Some("y"),
        "freed keys can be reused",
    )
}

async fn deletes(store: Arc<dyn IamStore>) -> Outcome {
    seed(
        &store,
        "items",
        vec![record(
            json!({ "id": "x", "tenantId": "t1", "tokenHash": "abc" }),
        )],
    )
    .await?;
    store
        .transaction(|tx| async move {
            tx.delete("items", "x").await?;
            tx.delete("items", "never-existed").await
        })
        .await?;
    check(
        store.get("items", "x").await?.is_none(),
        "deleted records are gone",
    )?;
    check(
        find(
            &store,
            "items",
            &filter(json!({ "tokenHash": "abc" })),
            FindOptions::default(),
        )
        .await?
        .is_empty(),
        "deleted records stop matching",
    )
}

async fn requires_transactions(store: Arc<dyn IamStore>) -> Outcome {
    rejects(
        store.insert("items", &record(json!({ "id": "x", "tenantId": "t" }))),
        "TRANSACTION_REQUIRED",
        "insert",
    )
    .await?;
    seed(
        &store,
        "items",
        vec![record(json!({ "id": "y", "tenantId": "t" }))],
    )
    .await?;
    rejects(
        store.put(
            "items",
            &record(json!({ "id": "y", "tenantId": "t", "v": 1 })),
        ),
        "TRANSACTION_REQUIRED",
        "put",
    )
    .await?;
    rejects(store.delete("items", "y"), "TRANSACTION_REQUIRED", "delete").await?;
    let read = store.get("items", "y").await?;
    check(
        read.and_then(|record| record.get("v").cloned()).is_none(),
        "rejected writes change nothing",
    )
}

async fn rolls_back_and_joins(store: Arc<dyn IamStore>) -> Outcome {
    let failure = IamError::new("APPLICATION_FAILURE", "application failure");
    let thrown = failure.clone();
    let result = store
        .transaction(move |tx| async move {
            tx.insert("items", &record(json!({ "id": "a", "tenantId": "t" })))
                .await?;
            Err::<(), _>(thrown)
        })
        .await;
    check(
        result.err() == Some(failure),
        "the callback’s error propagates unchanged",
    )?;
    check(
        store.get("items", "a").await?.is_none(),
        "a throwing callback rolls back",
    )?;
    let root = store.clone();
    let nested: Result<(), ConformanceFailure> = store
        .transaction(move |tx| async move {
            tx.insert("items", &record(json!({ "id": "b", "tenantId": "t" })))
                .await?;
            let seen = root
                .transaction(|inner| async move {
                    let seen = inner.get("items", "b").await?.is_some();
                    inner
                        .insert("items", &record(json!({ "id": "c", "tenantId": "t" })))
                        .await?;
                    Ok(seen)
                })
                .await?;
            tx.transaction(|inner| async move {
                inner
                    .insert("items", &record(json!({ "id": "d", "tenantId": "t" })))
                    .await
            })
            .await?;
            Ok(check(seen, "nested transactions see outer writes"))
        })
        .await?;
    nested?;
    same_ids(
        &find(&store, "items", &Filter::new(), FindOptions::default()).await?,
        &["b", "c", "d"],
        "nested writes commit with the outer transaction",
    )?;
    rejects(
        store.transaction(|tx| async move {
            tx.insert("items", &record(json!({ "id": "e", "tenantId": "t" })))
                .await?;
            // The outer transaction must still roll back.
            let _ = tx
                .transaction(
                    |_| async move { Err::<(), _>(IamError::new("INNER", "inner failure")) },
                )
                .await;
            Ok(())
        }),
        "TRANSACTION_ABORTED",
        "a failed nested transaction aborts the outer one",
    )
    .await?;
    check(
        store.get("items", "e").await?.is_none(),
        "nested failures roll back outer writes",
    )
}

async fn rejects_leaked_handles(store: Arc<dyn IamStore>) -> Outcome {
    let leaked: Arc<Mutex<Option<Arc<dyn IamStore>>>> = Arc::new(Mutex::new(None));
    let slot = leaked.clone();
    store
        .transaction(move |tx| async move {
            *slot.lock().map_err(|_| IamError::new("POISONED", "lock"))? = Some(tx.clone());
            tx.insert("items", &record(json!({ "id": "a", "tenantId": "t" })))
                .await
        })
        .await?;
    let handle = leaked
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
        .ok_or_else(|| ConformanceFailure("no handle".into()))?;
    rejects(
        handle.get("items", "a"),
        "TRANSACTION_CLOSED",
        "reads through a leaked handle",
    )
    .await?;
    rejects(
        handle.insert("items", &record(json!({ "id": "b", "tenantId": "t" }))),
        "TRANSACTION_CLOSED",
        "writes through a leaked handle",
    )
    .await?;
    Ok(())
}

async fn serializes_concurrent_transactions(store: Arc<dyn IamStore>) -> Outcome {
    seed(
        &store,
        "counters",
        vec![record(json!({ "id": "c", "tenantId": "t", "value": 0 }))],
    )
    .await?;
    let runs = (0..8u64).map(|index| {
        let store = store.clone();
        async move {
            store
                .transaction(move |tx| async move {
                    let mut current = tx.get("counters", "c").await?.unwrap_or_default();
                    tokio::time::sleep(std::time::Duration::from_millis(index % 3)).await;
                    let value = current.get("value").and_then(js::as_number).unwrap_or(0.0);
                    current.insert("value".into(), num(value + 1.0));
                    tx.put("counters", &current).await
                })
                .await
        }
    });
    for outcome in join_all(runs).await {
        outcome?;
    }
    let value = store
        .get("counters", "c")
        .await?
        .and_then(|record| record.get("value").and_then(js::as_number));
    check(value == Some(8.0), "no update is lost")
}

async fn typed_equality(store: Arc<dyn IamStore>) -> Outcome {
    let values: Vec<(&str, Value)> = vec![
        ("a", json!(1)),
        ("b", json!("1")),
        ("c", json!(true)),
        ("d", json!("true")),
        ("e", Value::Null),
        ("g", json!({ "x": 1, "y": [1, 2] })),
        ("h", json!([1, 2])),
        ("i", json!([2, 1])),
        ("j", json!({ "x": 1 })),
        ("k", json!(0)),
        ("l", json!("Abc")),
        ("m", json!("abc")),
        ("n", json!("e\u{0301}")),
        ("o", json!("\u{e9}")),
        ("p", json!(1.5)),
        ("q", json!("")),
        ("r", json!(" abc")),
        ("s", json!([])),
        ("t", json!({})),
        ("u", json!(false)),
        ("w", json!([null, 1])),
    ];
    let mut records: Vec<Record> = values
        .iter()
        .map(|(id, v)| record(json!({ "id": id, "tenantId": "t", "v": v })))
        .collect();
    records.push(record(json!({ "id": "f", "tenantId": "t" })));
    seed(&store, "values", records).await?;
    let expectations: Vec<(Option<Value>, &[&str])> = vec![
        (Some(json!(1)), &["a"]),
        (Some(json!("1")), &["b"]),
        (Some(json!(true)), &["c"]),
        (Some(json!(false)), &["u"]),
        (Some(json!("true")), &["d"]),
        (Some(Value::Null), &["e"]),
        (None, &["f"]),
        (Some(json!({ "y": [1, 2], "x": 1 })), &["g"]),
        (Some(json!([1, 2])), &["h"]),
        (Some(json!([2, 1])), &["i"]),
        (Some(json!({ "x": 1 })), &["j"]),
        (Some(json!([null, 1])), &["w"]),
        (Some(json!(0)), &["k"]),
        (Some(num(-0.0)), &["k"]),
        (Some(json!("abc")), &["m"]),
        (Some(json!("Abc")), &["l"]),
        (Some(json!("\u{e9}")), &["o"]),
        (Some(json!("e\u{0301}")), &["n"]),
        (Some(json!(1.5)), &["p"]),
        (Some(json!("")), &["q"]),
        (Some(json!([])), &["s"]),
        (Some(json!({})), &["t"]),
    ];
    for (value, expected) in expectations {
        let mut by_value = Filter::new();
        by_value.set("v", value.clone());
        same_ids(
            &find(&store, "values", &by_value, FindOptions::default()).await?,
            expected,
            &format!("filter v = {}", canonical(value.as_ref())),
        )?;
    }
    same_ids(
        &find(
            &store,
            "values",
            &filter(json!({ "missing": "x" })),
            FindOptions::default(),
        )
        .await?,
        &[],
        "filters on absent fields",
    )?;
    same_ids(
        &find(
            &store,
            "values",
            &filter(json!({ "v": 1, "tenantId": "t" })),
            FindOptions::default(),
        )
        .await?,
        &["a"],
        "conditions combine with AND",
    )?;
    same_ids(
        &find(
            &store,
            "values",
            &filter(json!({ "v": 1, "tenantId": "other" })),
            FindOptions::default(),
        )
        .await?,
        &[],
        "tenant narrows results",
    )?;
    // Sparse arrays and arrays with extra properties have no serde_json form; their cases are left out.
    let absent_key = Filter::new().eq("v", false).absent("absent\u{0}key");
    same_ids(
        &find(&store, "values", &absent_key, FindOptions::default()).await?,
        &["u"],
        "absence of a key no database can name",
    )?;
    let mut wide = Filter::new().eq("v", 1.5);
    for index in 0..40 {
        wide.set(format!("missing{index}"), None);
    }
    same_ids(
        &find(&store, "values", &wide, FindOptions::default()).await?,
        &["p"],
        "forty conditions",
    )?;
    wide.set("missing39", Some(json!("present")));
    same_ids(
        &find(&store, "values", &wide, FindOptions::default()).await?,
        &[],
        "forty conditions, one failing",
    )
}

async fn column_filters(store: Arc<dyn IamStore>) -> Outcome {
    seed(
        &store,
        "keys",
        vec![
            record(json!({ "id": "a", "tenantId": "t1", "uniqueKey": "k1" })),
            record(json!({ "id": "b", "tenantId": "t2", "uniqueKey": "k1" })),
            record(json!({ "id": "c", "tenantId": "t1" })),
        ],
    )
    .await?;
    let none = FindOptions::default;
    same_ids(
        &find(&store, "keys", &filter(json!({ "id": "a" })), none()).await?,
        &["a"],
        "id filter",
    )?;
    same_ids(
        &find(&store, "keys", &filter(json!({ "id": 5 })), none()).await?,
        &[],
        "non-string id filter",
    )?;
    same_ids(
        &find(&store, "keys", &filter(json!({ "tenantId": "t1" })), none()).await?,
        &["a", "c"],
        "tenant filter",
    )?;
    same_ids(
        &find(&store, "keys", &Filter::new().absent("tenantId"), none()).await?,
        &[],
        "absent tenant filter",
    )?;
    same_ids(
        &find(
            &store,
            "keys",
            &filter(json!({ "uniqueKey": "k1" })),
            none(),
        )
        .await?,
        &["a", "b"],
        "natural key across tenants",
    )?;
    same_ids(
        &find(&store, "keys", &Filter::new().absent("uniqueKey"), none()).await?,
        &["c"],
        "records without a natural key",
    )?;
    same_ids(
        &find(
            &store,
            "keys",
            &filter(json!({ "uniqueKey": null })),
            none(),
        )
        .await?,
        &[],
        "natural keys are never null",
    )?;
    same_ids(
        &find(
            &store,
            "keys",
            &filter(json!({ "tenantId": "t1", "uniqueKey": "k1", "id": "a" })),
            none(),
        )
        .await?,
        &["a"],
        "combined columns",
    )
}

async fn unsafe_field_names(store: Arc<dyn IamStore>) -> Outcome {
    let names = [
        "dotted.key",
        "with space",
        "quote\"key",
        "apostrophe'key",
        "$dollar",
        "123start",
        "unicod\u{e9}",
        "",
    ];
    let records = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let mut map = Map::new();
            map.insert("id".into(), json!(format!("n{index}")));
            map.insert("tenantId".into(), json!("t"));
            map.insert((*name).into(), json!("match"));
            map
        })
        .collect();
    seed(&store, "names", records).await?;
    for (index, name) in names.iter().enumerate() {
        let by_name = Filter::new().eq(*name, "match");
        same_ids(
            &find(&store, "names", &by_name, FindOptions::default()).await?,
            &[&format!("n{index}")],
            &format!("field {}", js::quote(name)),
        )?;
    }
    Ok(())
}

async fn unusual_strings(store: Arc<dyn IamStore>) -> Outcome {
    // Unpaired surrogates (records b and c, the '\ud83d' list member, the aliasing checks) have no Rust form.
    let escape_key = crate::storage::JSONB_ESCAPE_KEY;
    let mut odd_key = Map::new();
    odd_key.insert("id".into(), json!("d"));
    odd_key.insert("tenantId".into(), json!("t"));
    odd_key.insert("kind".into(), json!("odd"));
    odd_key.insert("k\u{0}".into(), json!(1));
    odd_key.insert("v".into(), json!("plain"));
    let mut escaped = Map::new();
    escaped.insert("list".into(), json!(["\u{0}"]));
    escaped.insert(escape_key.into(), json!("x"));
    let mut marker = Map::new();
    marker.insert(escape_key.into(), json!("deadbeef"));
    let records = vec![
        record(json!({ "id": "a", "tenantId": "t", "kind": "odd", "v": "a\u{0}b" })),
        odd_key,
        record(
            json!({ "id": "e", "tenantId": "t", "kind": "odd", "v": Value::Object(escaped.clone()) }),
        ),
        record(
            json!({ "id": "f", "tenantId": "t", "kind": "odd", "v": Value::Object(marker.clone()) }),
        ),
        record(json!({ "id": "g", "tenantId": "t", "kind": "plain", "v": "\u{fffd}" })),
        record(json!({ "id": "h", "tenantId": "t", "kind": "plain", "v": "😀" })),
    ];
    seed(&store, "strings", records.clone()).await?;
    for item in &records {
        let id = crate::record_id(item);
        same(
            store.get("strings", id).await?.map(Value::Object).as_ref(),
            Some(&Value::Object(item.clone())),
            &format!("round trip of {id}"),
        )?;
    }
    let by_value: Vec<(Value, &[&str])> = vec![
        (json!("a\u{0}b"), &["a"]),
        (json!("plain"), &["d"]),
        (Value::Object(escaped), &["e"]),
        (Value::Object(marker), &["f"]),
        (json!("\u{fffd}"), &["g"]),
        (json!("😀"), &["h"]),
        (json!("a"), &[]),
    ];
    for (value, expected) in by_value {
        let message = format!("filter v = {}", canonical(Some(&value)));
        same_ids(
            &find(
                &store,
                "strings",
                &Filter::new().eq("v", value),
                FindOptions::default(),
            )
            .await?,
            expected,
            &message,
        )?;
    }
    same_ids(
        &find(
            &store,
            "strings",
            &filter(json!({ "kind": "odd" })),
            FindOptions::default(),
        )
        .await?,
        &["a", "d", "e", "f"],
        "sibling fields",
    )?;
    same_ids(
        &find(
            &store,
            "strings",
            &Filter::new().eq("k\u{0}", 1),
            FindOptions::default(),
        )
        .await?,
        &["d"],
        "a key with U+0000",
    )?;
    same_ids(
        &find(
            &store,
            "strings",
            &filter(json!({ "kind": "odd" })),
            page(2, 5),
        )
        .await?,
        &["e", "f"],
        "paged",
    )?;
    rejects(
        store.transaction(|tx| async move {
            tx.insert(
                "strings",
                &record(json!({ "id": "x\u{0}", "tenantId": "t" })),
            )
            .await
        }),
        "INVALID_RECORD",
        "an id with U+0000",
    )
    .await?;
    Ok(())
}

const ORDER: [&str; 14] = [
    "b", "B", "a", "A", "0", "~", "_", "\u{e9}", "z", "\u{ffff}", "😀", "\u{e000}", "aa", "a-",
];

fn sorted_ids(ids: &[&str]) -> Vec<String> {
    let mut sorted: Vec<String> = ids.iter().map(|id| (*id).to_owned()).collect();
    sorted.sort_by(|left, right| compare_ids(left, right));
    sorted
}

fn window(items: &[String], offset: usize, limit: Option<usize>) -> Vec<String> {
    items
        .iter()
        .skip(offset)
        .take(limit.unwrap_or(usize::MAX))
        .cloned()
        .collect()
}

async fn id_order(store: Arc<dyn IamStore>) -> Outcome {
    let records = ORDER
        .iter()
        .enumerate()
        .map(|(index, id)| {
            record(json!({ "id": id, "tenantId": "t", "kind": "x", "odd key": index % 2 }))
        })
        .collect();
    seed(&store, "ordered", records).await?;
    let expected = sorted_ids(&ORDER);
    let x = filter(json!({ "kind": "x" }));
    same_id_strings(
        &find(&store, "ordered", &Filter::new(), FindOptions::default()).await?,
        &expected,
        "unfiltered order",
    )?;
    same_id_strings(
        &find(&store, "ordered", &x, FindOptions::default()).await?,
        &expected,
        "filtered order",
    )?;
    for (offset, limit) in [(0usize, 3usize), (3, 3), (12, 5), (14, 2), (20, 1)] {
        let part = window(&expected, offset, Some(limit));
        same_id_strings(
            &find(
                &store,
                "ordered",
                &Filter::new(),
                page(offset as i64, limit as i64),
            )
            .await?,
            &part,
            &format!("page {offset}+{limit}"),
        )?;
        same_id_strings(
            &find(&store, "ordered", &x, page(offset as i64, limit as i64)).await?,
            &part,
            &format!("filtered page {offset}+{limit}"),
        )?;
    }
    same_ids(
        &find(&store, "ordered", &Filter::new(), FindOptions::limit(0)).await?,
        &[],
        "limit 0",
    )?;
    same_id_strings(
        &find(
            &store,
            "ordered",
            &x,
            FindOptions {
                offset: Some(5),
                ..FindOptions::default()
            },
        )
        .await?,
        &window(&expected, 5, None),
        "offset without limit",
    )?;
    let odd: Vec<String> = expected
        .iter()
        .filter(|id| {
            ORDER
                .iter()
                .position(|item| item == id)
                .is_some_and(|index| index % 2 == 1)
        })
        .cloned()
        .collect();
    same_id_strings(
        &find(
            &store,
            "ordered",
            &filter(json!({ "odd key": 1 })),
            page(1, 3),
        )
        .await?,
        &window(&odd, 1, Some(3)),
        "in-memory filter page",
    )?;
    rejects(
        store.find(
            "ordered",
            &Filter::new(),
            &FindOptions {
                offset: Some(-1),
                ..FindOptions::default()
            },
        ),
        "INVALID_FILTER",
        "negative offset",
    )
    .await?;
    // A fractional limit has no `i64` form; the Rust type refuses it at compile time.
    Ok(())
}

async fn cursor_pages(store: Arc<dyn IamStore>) -> Outcome {
    let mut order: Vec<&str> = ORDER.to_vec();
    order.push("u1");
    let records: Vec<Record> = order
        .iter()
        .enumerate()
        .map(|(index, id)| {
            record(json!({
                "id": id,
                "tenantId": if *id == "u1" { "u" } else { "t" },
                "kind": if index % 3 == 0 { "x" } else { "y" },
                "odd key": index % 2,
            }))
        })
        .collect();
    seed(&store, "cursor", records.clone()).await?;
    let by_id = |id: &str| {
        records
            .iter()
            .find(|record| crate::record_id(record) == id)
            .cloned()
            .unwrap_or_default()
    };
    let expected = sorted_ids(&order);
    let after = |cursor: &str, keep: &dyn Fn(&str) -> bool| -> Vec<String> {
        expected
            .iter()
            .filter(|id| compare_ids(id, cursor) == std::cmp::Ordering::Greater && keep(id))
            .cloned()
            .collect()
    };
    let all = |_: &str| true;
    for size in [1usize, 4] {
        let mut walked: Vec<Record> = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..=order.len() {
            let options = FindOptions {
                limit: Some(size as i64),
                after: cursor.clone(),
                offset: None,
            };
            let part = find(&store, "cursor", &Filter::new(), options).await?;
            let length = part.len();
            cursor = part
                .last()
                .map(|record| crate::record_id(record).to_owned());
            walked.extend(part);
            if length < size {
                break;
            }
        }
        same_id_strings(&walked, &expected, &format!("walk in pages of {size}"))?;
    }
    let cursor = |after: &str| FindOptions {
        after: Some(after.to_owned()),
        ..FindOptions::default()
    };
    same_id_strings(
        &find(&store, "cursor", &Filter::new(), cursor("a")).await?,
        &after("a", &all),
        "cursor between ids",
    )?;
    same_id_strings(
        &find(&store, "cursor", &Filter::new(), cursor("")).await?,
        &expected,
        "empty cursor",
    )?;
    same_ids(
        &find(&store, "cursor", &Filter::new(), cursor("\u{10FFFF}")).await?,
        &[],
        "past the last id",
    )?;
    // A cursor with an unpaired surrogate has no Rust form.
    let kind = |value: &'static str| move |id: &str| by_id(id).get("kind") == Some(&json!(value));
    same_id_strings(
        &find(
            &store,
            "cursor",
            &filter(json!({ "kind": "x" })),
            FindOptions {
                after: Some("B".into()),
                limit: Some(2),
                offset: None,
            },
        )
        .await?,
        &window(&after("B", &kind("x")), 0, Some(2)),
        "filtered cursor page",
    )?;
    same_id_strings(
        &find(
            &store,
            "cursor",
            &Filter::new(),
            FindOptions {
                after: Some("a".into()),
                offset: Some(1),
                limit: Some(1),
            },
        )
        .await?,
        &window(&after("a", &all), 1, Some(1)),
        "cursor with offset",
    )?;
    same_id_strings(
        &find(
            &store,
            "cursor",
            &filter(json!({ "kind": "y" })),
            FindOptions {
                after: Some("B".into()),
                offset: Some(1),
                limit: Some(2),
            },
        )
        .await?,
        &window(&after("B", &kind("y")), 1, Some(2)),
        "filtered cursor with offset",
    )?;
    same_id_strings(
        &find(
            &store,
            "cursor",
            &filter(json!({ "tenantId": "t" })),
            cursor("_"),
        )
        .await?,
        &after("_", &|id: &str| {
            by_id(id).get("tenantId") == Some(&json!("t"))
        }),
        "tenant cursor",
    )?;
    same_id_strings(
        &find(
            &store,
            "cursor",
            &filter(json!({ "odd key": 1 })),
            FindOptions {
                after: Some("B".into()),
                offset: Some(1),
                limit: Some(2),
            },
        )
        .await?,
        &window(
            &after("B", &|id: &str| by_id(id).get("odd key") == Some(&json!(1))),
            1,
            Some(2),
        ),
        "in-memory filter with cursor and offset",
    )?;
    // A non-string cursor has no `FindOptions` form; the Rust type refuses it at compile time.
    Ok(())
}

fn conformance_numbers() -> Vec<f64> {
    vec![
        0.0,
        1.0,
        -1.0,
        0.1 + 0.2,
        2f64.powi(53) - 1.0,
        2f64.powi(53) + 2.0,
        2f64.powi(60),
        -(2f64.powi(60)),
        4_611_686_018_427_389_000.0,
        9_223_372_036_854_775_000.0,
        2f64.powi(64),
        1e16,
        1e17,
        1e21,
        1e-7,
        1e-300,
        5e-324,
        1.712_580_832_755_795_2e177,
        -7.491_602_062_452_078e303,
        2.209_340_230_334_720_7e-113,
        f64::MAX,
    ]
}

async fn number_lookups(store: Arc<dyn IamStore>) -> Outcome {
    let numbers = conformance_numbers();
    let records = numbers
        .iter()
        .enumerate()
        .flat_map(|(index, n)| {
            [
                record(json!({ "id": format!("n{index}"), "tenantId": "t", "n": num(*n) })),
                record(json!({ "id": format!("n{index}-copy"), "tenantId": "t", "n": num(*n) })),
            ]
        })
        .collect();
    seed(&store, "numbers", records).await?;
    for (index, n) in numbers.iter().enumerate() {
        let label = js::number_to_string(*n);
        let by_number = Filter::new().eq("n", num(*n));
        let (first, copy) = (format!("n{index}"), format!("n{index}-copy"));
        same_ids(
            &find(&store, "numbers", &by_number, FindOptions::default()).await?,
            &[&first, &copy],
            &format!("n = {label}"),
        )?;
        same_ids(
            &find(&store, "numbers", &by_number, page(1, 1)).await?,
            &[&copy],
            &format!("paged n = {label}"),
        )?;
        let read = store
            .get("numbers", &first)
            .await?
            .and_then(|record| record.get("n").cloned());
        same(
            read.as_ref(),
            Some(&num(*n)),
            &format!("round trip of {label}"),
        )?;
    }
    Ok(())
}

async fn selective_pages(store: Arc<dyn IamStore>) -> Outcome {
    let records: Vec<Record> = (0..300)
        .map(|index| {
            record(json!({
                "id": format!("r{index:03}"),
                "tenantId": if index % 2 == 1 { "odd" } else { "even" },
                "third": index % 3 == 0,
                "group": format!("g{}", index % 7),
                "in memory": index % 5,
            }))
        })
        .collect();
    seed(&store, "rows", records.clone()).await?;
    same(
        Some(&json!(
            find(&store, "rows", &Filter::new(), FindOptions::default())
                .await?
                .len()
        )),
        Some(&json!(300)),
        "no silent truncation",
    )?;
    let selective: Vec<String> = records
        .iter()
        .filter(|record| {
            record.get("third") == Some(&json!(true))
                && record.get("tenantId") == Some(&json!("even"))
        })
        .map(|record| crate::record_id(record).to_owned())
        .collect();
    let both = filter(json!({ "third": true, "tenantId": "even" }));
    same_id_strings(
        &find(&store, "rows", &both, FindOptions::default()).await?,
        &selective,
        "filtered",
    )?;
    for (offset, limit) in [(0usize, 7usize), (7, 7), (45, 10), (49, 3)] {
        same_id_strings(
            &find(&store, "rows", &both, page(offset as i64, limit as i64)).await?,
            &window(&selective, offset, Some(limit)),
            &format!("page {offset}+{limit}"),
        )?;
    }
    let mixed: Vec<String> = records
        .iter()
        .filter(|record| {
            record.get("group") == Some(&json!("g3")) && record.get("in memory") == Some(&json!(2))
        })
        .map(|record| crate::record_id(record).to_owned())
        .collect();
    same_id_strings(
        &find(
            &store,
            "rows",
            &filter(json!({ "group": "g3", "in memory": 2 })),
            page(1, 4),
        )
        .await?,
        &window(&mixed, 1, Some(4)),
        "page of a partly in-memory filter",
    )
}

async fn uncommitted_reads(store: Arc<dyn IamStore>) -> Outcome {
    seed(
        &store,
        "drafts",
        vec![record(
            json!({ "id": "a", "tenantId": "t", "state": "old", "kind": "x" }),
        )],
    )
    .await?;
    let root = store.clone();
    let outcome: Arc<Mutex<Outcome>> = Arc::new(Mutex::new(Ok(())));
    let report = outcome.clone();
    rejects(
        store.transaction(move |tx| async move {
            let checks = async {
                tx.insert(
                    "drafts",
                    &record(json!({ "id": "b", "tenantId": "t", "state": "new", "kind": "x" })),
                )
                .await?;
                tx.put(
                    "drafts",
                    &record(json!({ "id": "a", "tenantId": "t", "state": "new", "kind": "x" })),
                )
                .await?;
                let new = filter(json!({ "state": "new" }));
                same_ids(
                    &tx.find("drafts", &new, &FindOptions::default()).await?,
                    &["a", "b"],
                    "exact filter",
                )?;
                same_ids(
                    &tx.find("drafts", &new, &FindOptions::limit(1)).await?,
                    &["a"],
                    "exact page",
                )?;
                same_ids(
                    &tx.find(
                        "drafts",
                        &filter(json!({ "state": "old" })),
                        &FindOptions::default(),
                    )
                    .await?,
                    &[],
                    "replaced value",
                )?;
                let joined = Filter::new().eq("kind", "x").absent("x y");
                same_ids(
                    &root
                        .find("drafts", &joined, &FindOptions::default())
                        .await?,
                    &["a", "b"],
                    "joined read",
                )?;
                tx.delete("drafts", "a").await?;
                same_ids(
                    &tx.find(
                        "drafts",
                        &filter(json!({ "kind": "x" })),
                        &FindOptions::default(),
                    )
                    .await?,
                    &["b"],
                    "deleted inside",
                )?;
                Ok::<(), ConformanceFailure>(())
            };
            let result = checks.await;
            if let Ok(mut slot) = report.lock() {
                *slot = result;
            }
            Err::<(), _>(IamError::new("ROLLBACK", "discard"))
        }),
        "ROLLBACK",
        "the draft transaction",
    )
    .await?;
    outcome
        .lock()
        .map_err(|_| ConformanceFailure("poisoned".into()))?
        .clone()?;
    same_ids(
        &find(
            &store,
            "drafts",
            &filter(json!({ "state": "old" })),
            FindOptions::default(),
        )
        .await?,
        &["a"],
        "rolled back",
    )
}

async fn numeric_order(store: Arc<dyn IamStore>) -> Outcome {
    let stamps: Vec<Option<Value>> = vec![
        Some(json!(5)),
        Some(json!(3)),
        Some(json!(5)),
        Some(json!(-1)),
        Some(num(2f64.powi(60))),
        Some(json!(0.5)),
        Some(json!(7)),
        Some(json!("6")),
        Some(Value::Null),
        None,
        Some(json!(5)),
        Some(num(1e21)),
        Some(json!(3)),
    ];
    let records: Vec<Record> = (0..300usize)
        .map(|index| {
            let mut item = record(json!({
                "id": format!("e{:03}", (index * 37) % 300),
                "tenantId": if index % 3 == 0 { "other" } else { "t" },
                "kind": if index % 4 == 0 { "x" } else { "y" },
            }));
            if let Some(stamp) = &stamps[index % stamps.len()] {
                item.insert("timestamp".into(), stamp.clone());
            }
            item
        })
        .collect();
    seed(&store, "events", records.clone()).await?;
    let reference = |keep: &dyn Fn(&Record) -> bool, desc: bool| -> Vec<String> {
        let mut kept: Vec<&Record> = records
            .iter()
            .filter(|record| {
                record.get("timestamp").and_then(js::as_number).is_some() && keep(record)
            })
            .collect();
        kept.sort_by(|a, b| {
            let (left, right) = (
                a["timestamp"].as_f64().unwrap_or(0.0),
                b["timestamp"].as_f64().unwrap_or(0.0),
            );
            let mut ordering = left
                .partial_cmp(&right)
                .unwrap_or(std::cmp::Ordering::Equal);
            if desc {
                ordering = ordering.reverse();
            }
            ordering.then_with(|| compare_ids(crate::record_id(a), crate::record_id(b)))
        });
        kept.iter()
            .map(|record| crate::record_id(record).to_owned())
            .collect()
    };
    let tenant = |record: &Record| record.get("tenantId") == Some(&json!("t"));
    let in_tenant = filter(json!({ "tenantId": "t" }));
    let ordered = |direction: Direction, offset: Option<i64>, limit: Option<i64>| OrderOptions {
        field: "timestamp".into(),
        direction,
        offset,
        limit,
        ..OrderOptions::default()
    };
    for direction in [Direction::Asc, Direction::Desc] {
        let all = reference(&tenant, direction == Direction::Desc);
        let label = direction.as_str();
        same_id_strings(
            &find_ordered(
                store.as_ref(),
                "events",
                &in_tenant,
                &ordered(direction, None, None),
                None,
            )
            .await?,
            &all,
            &format!("{label} order"),
        )?;
        for (offset, limit) in [(0usize, 10usize), (15, 20), (all.len() - 3, 10)] {
            same_id_strings(
                &find_ordered(
                    store.as_ref(),
                    "events",
                    &in_tenant,
                    &ordered(direction, Some(offset as i64), Some(limit as i64)),
                    None,
                )
                .await?,
                &window(&all, offset, Some(limit)),
                &format!("{label} page {offset}+{limit}"),
            )?;
        }
    }
    let bounded = reference(
        &|record: &Record| {
            let value = record["timestamp"].as_f64().unwrap_or(f64::NAN);
            tenant(record) && (0.5..=5.0).contains(&value)
        },
        false,
    );
    let range = OrderOptions {
        field: "timestamp".into(),
        from: Some(0.5),
        to: Some(5.0),
        ..OrderOptions::default()
    };
    same_id_strings(
        &find_ordered(store.as_ref(), "events", &in_tenant, &range, None).await?,
        &bounded,
        "bounded range",
    )?;
    let big = 2f64.powi(60);
    let exact = OrderOptions {
        field: "timestamp".into(),
        from: Some(big),
        to: Some(big),
        ..OrderOptions::default()
    };
    same_id_strings(
        &find_ordered(store.as_ref(), "events", &in_tenant, &exact, None).await?,
        &reference(
            &|record: &Record| tenant(record) && record["timestamp"].as_f64() == Some(big),
            false,
        ),
        "a bound above 2^53",
    )?;
    let xs = reference(
        &|record: &Record| tenant(record) && record.get("kind") == Some(&json!("x")),
        true,
    );
    same_id_strings(
        &find_ordered(
            store.as_ref(),
            "events",
            &filter(json!({ "tenantId": "t", "kind": "x" })),
            &ordered(Direction::Desc, Some(2), Some(7)),
            None,
        )
        .await?,
        &window(&xs, 2, Some(7)),
        "filtered page",
    )?;
    let only_x = |record: &Record| record.get("kind") == Some(&json!("x"));
    same_id_strings(
        &find_ordered(
            store.as_ref(),
            "events",
            &in_tenant,
            &ordered(Direction::Desc, Some(3), Some(5)),
            Some(&only_x),
        )
        .await?,
        &window(&xs, 3, Some(5)),
        "in-memory predicate page",
    )?;
    rejects(
        find_ordered(
            store.as_ref(),
            "events",
            &Filter::new(),
            &OrderOptions::by("not a field"),
            None,
        ),
        "INVALID_FILTER",
        "an order field that is not an identifier",
    )
    .await?;
    rejects(
        find_ordered(
            store.as_ref(),
            "events",
            &Filter::new(),
            &OrderOptions {
                from: Some(f64::NAN),
                ..OrderOptions::by("timestamp")
            },
            None,
        ),
        "INVALID_FILTER",
        "a NaN bound",
    )
    .await?;
    let outcome: Arc<Mutex<Outcome>> = Arc::new(Mutex::new(Ok(())));
    let report = outcome.clone();
    rejects(
        store.transaction(move |tx| async move {
            let checks = async {
                tx.insert(
                    "events",
                    &record(json!({ "id": "z-new", "tenantId": "t", "timestamp": num(1e22) })),
                )
                .await?;
                let latest = OrderOptions {
                    field: "timestamp".into(),
                    direction: Direction::Desc,
                    limit: Some(1),
                    ..OrderOptions::default()
                };
                same_ids(
                    &find_ordered(
                        tx.as_ref(),
                        "events",
                        &filter(json!({ "tenantId": "t" })),
                        &latest,
                        None,
                    )
                    .await?,
                    &["z-new"],
                    "uncommitted write in order",
                )?;
                Ok::<(), ConformanceFailure>(())
            };
            let result = checks.await;
            if let Ok(mut slot) = report.lock() {
                *slot = result;
            }
            Err::<(), _>(IamError::new("ROLLBACK", "discard"))
        }),
        "ROLLBACK",
        "the ordered draft",
    )
    .await?;
    outcome
        .lock()
        .map_err(|_| ConformanceFailure("poisoned".into()))?
        .clone()
}

async fn validates_records(store: Arc<dyn IamStore>) -> Outcome {
    // A Date, NaN, Infinity, a Map, a function, a symbol key, a circular reference and an undefined array item have
    // no serde_json form; the remaining cases follow.
    let mut proto = Map::new();
    proto.insert("id".into(), json!("x"));
    proto.insert("tenantId".into(), json!("t"));
    proto.insert("__proto__".into(), json!(1));
    let invalid: Vec<(&str, Record)> = vec![
        ("a __proto__ key", proto),
        ("an empty id", record(json!({ "id": "", "tenantId": "t" }))),
        (
            "an oversized id",
            record(json!({ "id": "\u{e9}".repeat(257), "tenantId": "t" })),
        ),
        (
            "a control character in tenantId",
            record(json!({ "id": "x", "tenantId": "t\n" })),
        ),
        (
            "a null natural key",
            record(json!({ "id": "x", "tenantId": "t", "uniqueKey": null })),
        ),
        (
            "an oversized record",
            record(json!({ "id": "x", "tenantId": "t", "v": "a".repeat(1_048_577) })),
        ),
    ];
    for (label, item) in invalid {
        rejects(
            store.transaction(move |tx| async move { tx.insert("invalid", &item).await }),
            "INVALID_RECORD",
            label,
        )
        .await?;
    }
    check(
        find(&store, "invalid", &Filter::new(), FindOptions::default())
            .await?
            .is_empty(),
        "no invalid record was written",
    )
}

async fn consistent_lookups(store: Arc<dyn IamStore>) -> Outcome {
    seed(
        &store,
        "sessions",
        vec![
            record(json!({ "id": "s1", "tenantId": "t1", "tokenHash": "h1", "identityId": "i1" })),
            record(json!({ "id": "s2", "tenantId": "t2", "tokenHash": "h2", "identityId": "i1" })),
            record(json!({ "id": "s3", "tenantId": "t1", "tokenHash": "h3", "identityId": "i2" })),
        ],
    )
    .await?;
    let none = FindOptions::default;
    same_ids(
        &find(
            &store,
            "sessions",
            &filter(json!({ "tokenHash": "h2" })),
            none(),
        )
        .await?,
        &["s2"],
        "lookup across tenants",
    )?;
    same_ids(
        &find(
            &store,
            "sessions",
            &filter(json!({ "identityId": "i1" })),
            none(),
        )
        .await?,
        &["s1", "s2"],
        "secondary lookup",
    )?;
    same_ids(
        &find(
            &store,
            "sessions",
            &filter(json!({ "identityId": "i1", "tenantId": "t1" })),
            none(),
        )
        .await?,
        &["s1"],
        "tenant-scoped lookup",
    )?;
    store
        .transaction(|tx| async move {
            tx.put(
                "sessions",
                &record(
                    json!({ "id": "s2", "tenantId": "t2", "tokenHash": "h4", "identityId": "i1" }),
                ),
            )
            .await
        })
        .await?;
    same_ids(
        &find(
            &store,
            "sessions",
            &filter(json!({ "tokenHash": "h2" })),
            none(),
        )
        .await?,
        &[],
        "old value no longer matches",
    )?;
    same_ids(
        &find(
            &store,
            "sessions",
            &filter(json!({ "tokenHash": "h4" })),
            none(),
        )
        .await?,
        &["s2"],
        "new value matches",
    )?;
    store
        .transaction(|tx| async move { tx.delete("sessions", "s1").await })
        .await?;
    same_ids(
        &find(
            &store,
            "sessions",
            &filter(json!({ "identityId": "i1" })),
            none(),
        )
        .await?,
        &["s2"],
        "deleted records disappear",
    )?;
    same_ids(
        &find(
            &store,
            "sessions",
            &filter(json!({ "tokenHash": 1 })),
            none(),
        )
        .await?,
        &[],
        "typed lookups never coerce",
    )
}

async fn idempotent_migrations(store: Arc<dyn IamStore>) -> Outcome {
    seed(
        &store,
        "items",
        vec![record(
            json!({ "id": "kept", "tenantId": "t", "tokenHash": "h" }),
        )],
    )
    .await?;
    store.migrate().await?;
    store.migrate().await?;
    same_ids(
        &find(
            &store,
            "items",
            &filter(json!({ "tokenHash": "h" })),
            FindOptions::default(),
        )
        .await?,
        &["kept"],
        "data survives migration",
    )
}

async fn no_leaks(store: Arc<dyn IamStore>) -> Outcome {
    seed(&store, "items", vec![record(json!({ "id": "x", "tenantId": "t", "uniqueKey": "key-do-not-leak", "secret": "do-not-leak" }))]).await?;
    let conflicts = vec![
        rejects(
            store.transaction(|tx| async move { tx.insert("items", &record(json!({ "id": "x", "tenantId": "t", "secret": "do-not-leak" }))).await }),
            "CONFLICT",
            "duplicate id",
        )
        .await?,
        rejects(
            store.transaction(|tx| async move {
                tx.insert("items", &record(json!({ "id": "y", "tenantId": "t", "uniqueKey": "key-do-not-leak", "secret": "do-not-leak" })))
                    .await
            }),
            "CONFLICT",
            "duplicate natural key",
        )
        .await?,
    ];
    let pattern =
        regex::Regex::new("(?i)insert|select|iam_records|do-not-leak").expect("valid pattern");
    for error in conflicts {
        let exposed = [
            error.message.clone(),
            error.to_string(),
            format!("{error:?}"),
            serde_json::to_string(&error).unwrap_or_default(),
            error.code.clone(),
        ]
        .join("\n");
        check(
            !pattern.is_match(&exposed),
            "errors carry no SQL, table names, or record data",
        )?;
    }
    Ok(())
}

async fn closes(store: Arc<dyn IamStore>) -> Outcome {
    store.close().await?;
    store.close().await?;
    rejects(store.get("items", "x"), "STORE_CLOSED", "reads after close").await?;
    rejects(
        store.transaction(|_| async move { Ok(()) }),
        "STORE_CLOSED",
        "transactions after close",
    )
    .await?;
    Ok(())
}

fn cases() -> Vec<ConformanceCase> {
    vec![
        case!(
            "round-trips JSON records and returns detached copies",
            round_trips
        ),
        case!(
            "enforces identifier and tenant-scoped natural-key uniqueness",
            uniqueness
        ),
        case!(
            "replaces whole records on put without upserting or moving tenants",
            replaces_on_put
        ),
        case!("deletes records and ignores missing ids", deletes),
        case!(
            "requires a transaction for every write",
            requires_transactions
        ),
        case!(
            "rolls back failed transactions and joins nested ones",
            rolls_back_and_joins
        ),
        case!(
            "rejects transaction handles after completion",
            rejects_leaked_handles
        ),
        case!(
            "serializes concurrent read-modify-write transactions",
            serializes_concurrent_transactions
        ),
        case!(
            "matches filters with strict, typed JSON equality",
            typed_equality
        ),
        case!(
            "filters by id, tenant, and natural-key columns",
            column_filters
        ),
        case!(
            "filters on field names that cannot appear in SQL",
            unsafe_field_names
        ),
        case!(
            "stores and finds strings with U+0000, unpaired surrogates, and reserved keys",
            unusual_strings
        ),
        case!(
            "orders by id in code-point order and paginates deterministically",
            id_order
        ),
        case!("pages with an id cursor in code-point order", cursor_pages),
        case!(
            "finds numbers by value across the whole double range",
            number_lookups
        ),
        case!(
            "pages selectively filtered results across many rows",
            selective_pages
        ),
        case!(
            "finds uncommitted writes inside the writing transaction",
            uncommitted_reads
        ),
        case!(
            "orders, bounds, and pages by a numeric field",
            numeric_order
        ),
        case!("validates records before writing", validates_records),
        case!(
            "keeps lookups consistent through updates and deletes",
            consistent_lookups
        ),
        case!(
            "migrates idempotently without touching data",
            idempotent_migrations
        ),
        case!(
            "reports storage conflicts without leaking SQL or record data",
            no_leaks
        ),
        case!("closes idempotently and rejects later use", closes),
    ]
}

/// A fresh copy of every conformance case, in a stable order (`adapterConformanceCases`).
pub fn adapter_conformance_cases() -> Vec<ConformanceCase> {
    cases()
}

/// The result of [`run_adapter_conformance`].
#[derive(Debug, Default)]
pub struct ConformanceReport {
    pub passed: Vec<&'static str>,
    pub failed: Vec<(&'static str, ConformanceFailure)>,
}

/// Runs every case against fresh stores and collects failures instead of stopping at the first
/// (`runAdapterConformance`).
pub async fn run_adapter_conformance<F, Fut>(mut create_store: F) -> ConformanceReport
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = IamResult<Arc<dyn IamStore>>>,
{
    let mut report = ConformanceReport::default();
    for case in adapter_conformance_cases() {
        let store = match create_store().await {
            Ok(store) => store,
            Err(error) => {
                report.failed.push((case.name, error.into()));
                continue;
            }
        };
        let outcome = match store.migrate().await {
            Ok(()) => (case.run)(store.clone()).await,
            Err(error) => Err(error.into()),
        };
        let closed = store.close().await;
        match outcome.and(closed.map_err(ConformanceFailure::from)) {
            Ok(()) => report.passed.push(case.name),
            Err(error) => report.failed.push((case.name, error)),
        }
    }
    report
}
