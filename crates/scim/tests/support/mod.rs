//! Shared helpers of the SCIM suites: a runtime with large stacks, an in-memory SQLite store, administrator
//! callbacks, and fetch-style requests.

#![allow(dead_code)]

use std::future::Future;
use std::sync::Arc;

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_core::{
    CredentialInput, Filter, FindOptions, IamError, IamStore, IamStoreExt, Record, js as core_js,
};
use better_iam_scim::{HttpRequest, HttpResponse, authenticate_fn, authorize_fn};
use bytes::Bytes;
use serde_json::{Value, json};

/// Runs a test body on a runtime with large worker stacks (debug-build futures are big).
pub fn run<F, Fut>(body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(body());
        })
        .expect("thread")
        .join()
        .expect("test body");
}

pub type Store = Arc<dyn IamStore>;

pub async fn memory_store() -> Store {
    let store = sqlite_adapter(SqliteAdapterOptions {
        filename: ":memory:".into(),
        busy_timeout_ms: None,
        journal_mode: None,
        durability: None,
    })
    .expect("store");
    store.migrate().await.expect("migrate");
    store
}

pub fn now() -> f64 {
    core_js::now_ms()
}

/// Inserts tenants (`root` parents of the others when `root` is listed).
pub async fn tenants(store: &Store, ids: &[&str]) {
    let ids: Vec<String> = ids.iter().map(|id| (*id).to_owned()).collect();
    let has_root = ids.iter().any(|id| id == "root");
    store
        .transaction(move |tx| async move {
            for id in &ids {
                let parent = if id == "root" || !has_root {
                    Value::Null
                } else {
                    json!("root")
                };
                tx.insert(
                    "tenants",
                    &record(json!({
                        "id": id,
                        "tenantId": id,
                        "name": id,
                        "type": if id == "root" { "root" } else { "organization" },
                        "parentId": parent,
                        "status": "active",
                        "createdAt": now(),
                    })),
                )
                .await?;
            }
            Ok(())
        })
        .await
        .expect("tenants");
}

pub fn record(value: Value) -> Record {
    value.as_object().cloned().expect("an object")
}

pub fn token(value: &str) -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some(value.to_owned()),
    }
}

/// The callbacks of the TypeScript fixtures: the `admin` token is an administrator, anything else is forbidden.
pub fn admin_callbacks() -> (
    better_iam_scim::AuthorizeFn,
    better_iam_scim::AuthenticateFn,
) {
    let authorize = authorize_fn(
        |credential: CredentialInput, _action, _resource| async move {
            if credential.token.as_deref() != Some("admin") {
                return Err(IamError::with_status("FORBIDDEN", "Forbidden", 403));
            }
            Ok(())
        },
    );
    let authenticate = authenticate_fn(|credential: CredentialInput| async move {
        if credential.token.as_deref() != Some("admin") {
            return Err(IamError::with_status("FORBIDDEN", "Forbidden", 403));
        }
        Ok("administrator".to_owned())
    });
    (authorize, authenticate)
}

/// A fetch-style request.
pub fn request(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<String>,
) -> HttpRequest {
    let mut builder = http::Request::builder().method(method).uri(url);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder
        .body(body.map(Bytes::from).unwrap_or_default())
        .expect("request")
}

/// A response's status, headers and JSON body.
pub struct Answer {
    pub status: u16,
    pub headers: http::HeaderMap,
    pub body: Value,
}

impl Answer {
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }
}

pub fn answer(response: HttpResponse) -> Answer {
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let text = String::from_utf8_lossy(response.body()).into_owned();
    let body = if text.is_empty() {
        Value::Null
    } else {
        core_js::parse(&text).expect("JSON body")
    };
    Answer {
        status,
        headers,
        body,
    }
}

pub async fn find(store: &Store, collection: &str, filter: Filter) -> Vec<Record> {
    store
        .find(collection, &filter, &FindOptions::default())
        .await
        .expect("find")
}

pub async fn get(store: &Store, collection: &str, id: &str) -> Option<Record> {
    store.get(collection, id).await.expect("get")
}

/// Writes inside a transaction.
pub async fn put(store: &Store, collection: &'static str, value: Record) {
    store
        .transaction(move |tx| async move { tx.put(collection, &value).await.map(|_| ()) })
        .await
        .expect("put");
}

pub async fn insert(store: &Store, collection: &'static str, value: Record) {
    store
        .transaction(move |tx| async move { tx.insert(collection, &value).await.map(|_| ()) })
        .await
        .expect("insert");
}

pub async fn delete(store: &Store, collection: &'static str, id: &str) {
    let id = id.to_owned();
    store
        .transaction(move |tx| async move { tx.delete(collection, &id).await })
        .await
        .expect("delete");
}

/// `encodeURIComponent`.
pub fn encode(value: &str) -> String {
    better_iam_scim::js::encode_uri_component(value)
}

/// Whether `actual` contains every member of `expected` with the same value (`toMatchObject`), recursively.
pub fn matches(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::Object(actual), Value::Object(expected)) => expected
            .iter()
            .all(|(key, value)| actual.get(key).is_some_and(|member| matches(member, value))),
        (Value::Array(actual), Value::Array(expected)) => {
            actual.len() == expected.len()
                && actual
                    .iter()
                    .zip(expected)
                    .all(|(actual, expected)| matches(actual, expected))
        }
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
        (actual, expected) => actual == expected,
    }
}

#[track_caller]
pub fn assert_matches(actual: &Value, expected: Value) {
    assert!(
        matches(actual, &expected),
        "expected {actual} to match {expected}"
    );
}
