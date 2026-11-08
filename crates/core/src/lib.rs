//! Core of Better IAM for Rust, the counterpart of `@better-iam/core`: shared types, the storage contract
//! ([`IamStore`]) and the record-store building blocks every adapter shares, policy validation and evaluation,
//! query planning and filter compilers, the audit hash chain, store snapshots, security classification, Shared
//! Signals claims, and delegation token claims.
//!
//! Module and function names mirror the TypeScript sources (`policy.ts` → [`policy`], `evaluatePolicy` →
//! [`policy::evaluate_policy`]) so a change in one implementation is easy to find in the other. Records are JSON
//! objects ([`Record`]) stored exactly as the TypeScript adapters store them, so TypeScript and Rust servers can share
//! one database.
#![forbid(unsafe_code)]

pub mod audit;
pub mod boxing;
pub mod classification;
#[cfg(feature = "conformance")]
pub mod conformance;
pub mod delegation_tokens;
pub mod filter_compilers;
pub mod instrument;
pub mod jcs;
pub mod js;
pub mod models;
pub mod plan;
pub mod policy;
pub mod shared_signals;
pub mod snapshot;
pub mod sql;
pub mod storage;
pub mod task_scope;

use std::any::Any;
use std::future::Future;
use std::sync::Arc;

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub use audit::*;
pub use boxing::boxed;
pub use classification::*;
pub use delegation_tokens::*;
pub use filter_compilers::*;
pub use instrument::*;
pub use jcs::*;
pub use models::*;
pub use plan::*;
pub use policy::*;
pub use shared_signals::*;
pub use snapshot::*;
pub use sql::*;
pub use storage::*;

/// Every failure Better IAM reports: a stable machine-readable `code`, a human-readable `message`, and the HTTP
/// `status` the server answers with (400 unless stated).
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
#[error("{message}")]
pub struct IamError {
    pub code: String,
    pub message: String,
    pub status: u16,
    /// Members some TypeScript errors carry beside code, message and status (`retryAfterMs` on rate-limit refusals,
    /// `WrongRegionError`'s `region` and `location`), which the HTTP error envelope reports. Not part of equality
    /// and not serialized with the error.
    #[serde(skip)]
    pub details: Option<Box<IamErrorDetails>>,
}

/// The extra members of an [`IamError`] (see [`IamError::details`]).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IamErrorDetails {
    /// `retryAfterMs`: when a rate-limited caller may try again (the `Retry-After` header, in seconds).
    pub retry_after_ms: Option<f64>,
    /// `WRONG_REGION`: the region that serves the organization.
    pub region: Option<String>,
    /// `WRONG_REGION`: the organization's sign-in address in that region.
    pub location: Option<String>,
    /// The name of the JavaScript exception this error stands for when TypeScript throws something that is not an
    /// `IamError` (`Error`, `TypeError`, ...). Such an error is `INTERNAL_ERROR` 500 and keeps the exception's own
    /// message for the code that reads `error.message` (an archive failure report, for one), while the HTTP answer
    /// still says "Internal server error".
    pub thrown: Option<String>,
}

impl PartialEq for IamError {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.message == other.message && self.status == other.status
    }
}

impl Eq for IamError {}

impl IamError {
    /// `new IamError(code, message)`: status 400.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::with_status(code, message, 400)
    }

    /// `new IamError(code, message, status)`.
    pub fn with_status(code: impl Into<String>, message: impl Into<String>, status: u16) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            status,
            details: None,
        }
    }

    /// The error with extra members (`Object.assign(error, { retryAfterMs })`, `WrongRegionError`).
    pub fn with_details(mut self, details: IamErrorDetails) -> Self {
        self.details = Some(Box::new(details));
        self
    }

    /// The error a port answers for behavior it does not implement yet (HTTP 501).
    pub fn not_implemented(what: impl Into<String>) -> Self {
        Self::with_status("NOT_IMPLEMENTED", what, 501)
    }
}

/// `Result` with [`IamError`].
pub type IamResult<T> = Result<T, IamError>;

/// JSON data (`Json` in TypeScript).
pub type Json = Value;

/// A stored record: a JSON object with string `id` and `tenantId` members and an optional `uniqueKey`
/// (`StoredRecord`). Records are plain JSON so unknown members written by other implementations survive.
pub type Record = Map<String, Value>;

/// Pagination of [`IamStore::find`] (`FindOptions`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    /// Keyset pagination: only records whose id sorts after this id (code-point order). Unlike a growing `offset`,
    /// each page costs the same however deep it is. `offset` applies after it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

impl FindOptions {
    pub fn limit(limit: i64) -> Self {
        Self {
            limit: Some(limit),
            ..Self::default()
        }
    }
}

/// Sort direction of [`OrderOptions`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    #[default]
    Asc,
    Desc,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Asc => "asc",
            Direction::Desc => "desc",
        }
    }
}

/// Orders `find_ordered` results by a numeric top-level field (ties by id, ascending), keeping only records whose
/// field is a number within `[from, to]` (`OrderOptions`). Use it for time and sequence ordered data.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderOptions {
    pub field: String,
    #[serde(default)]
    pub direction: Direction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
}

impl OrderOptions {
    pub fn by(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            ..Self::default()
        }
    }
}

/// One applied migration in a [`StoreDescription`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationRecord {
    pub name: String,
    pub applied_at: f64,
}

/// Record count of one collection in a [`StoreDescription`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CollectionCount {
    pub name: String,
    pub records: f64,
}

/// What [`IamStore::describe`] reports about a database (`StoreDescription`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreDescription {
    pub adapter: String,
    pub schema_version: Option<f64>,
    pub migrations: Vec<MigrationRecord>,
    pub collections: Vec<CollectionCount>,
    /// Adapter settings worth checking in production (journal mode, durability, size, server version): strings,
    /// numbers, booleans or null.
    pub settings: Map<String, Value>,
}

/// The value a transaction callback produces, type-erased for the object-safe [`IamStore::transaction_dyn`].
pub type TransactionValue = Box<dyn Any + Send>;

/// A transaction callback for [`IamStore::transaction_dyn`]: it receives the transaction handle.
pub type TransactionFn<'a> =
    Box<dyn FnOnce(Arc<dyn IamStore>) -> BoxFuture<'a, IamResult<TransactionValue>> + Send + 'a>;

/// The storage contract (`IamStore`). Filters are strict equality against JSON fields. All writes require
/// [`IamStoreExt::transaction`].
///
/// The TypeScript contract's optional members (`findOrdered`, `collections`, `describe`) are trait methods with a
/// `has_*` probe: a store without one keeps the default, which refuses with `UNSUPPORTED`.
#[async_trait::async_trait]
pub trait IamStore: Send + Sync {
    async fn get(&self, collection: &str, id: &str) -> IamResult<Option<Record>>;

    async fn find(
        &self,
        collection: &str,
        filter: &Filter,
        options: &FindOptions,
    ) -> IamResult<Vec<Record>>;

    /// Whether the store implements [`IamStore::find_ordered`] (`store.findOrdered !== undefined`).
    fn has_find_ordered(&self) -> bool {
        false
    }

    /// Optional: `find` ordered and bounded by a numeric field, paged by the database. Call it through
    /// [`storage::find_ordered`], which falls back to `find` for stores without it.
    async fn find_ordered(
        &self,
        _collection: &str,
        _filter: &Filter,
        _order: &OrderOptions,
    ) -> IamResult<Vec<Record>> {
        Err(IamError::with_status(
            "UNSUPPORTED",
            "This store cannot run ordered queries",
            501,
        ))
    }

    /// Whether the store implements [`IamStore::collections`].
    fn has_collections(&self) -> bool {
        false
    }

    /// Optional: every collection holding at least one record, sorted (snapshots, diagnostics).
    async fn collections(&self) -> IamResult<Vec<String>> {
        Err(IamError::with_status(
            "UNSUPPORTED",
            "This adapter cannot list its collections",
            501,
        ))
    }

    /// Whether the store implements [`IamStore::describe`].
    fn has_describe(&self) -> bool {
        false
    }

    /// Optional: adapter, applied migrations, record counts, and storage settings (`better-iam doctor`).
    async fn describe(&self) -> IamResult<StoreDescription> {
        Err(IamError::with_status(
            "UNSUPPORTED",
            "This adapter cannot describe its database",
            501,
        ))
    }

    async fn insert(&self, collection: &str, record: &Record) -> IamResult<Record>;

    async fn put(&self, collection: &str, record: &Record) -> IamResult<Record>;

    async fn delete(&self, collection: &str, id: &str) -> IamResult<()>;

    /// Serializable read/modify/write; nested transactions join the outer transaction. Object-safe form of
    /// [`IamStoreExt::transaction`], which callers use.
    async fn transaction_dyn(&self, run: TransactionFn<'_>) -> IamResult<TransactionValue>;

    async fn migrate(&self) -> IamResult<()>;

    async fn close(&self) -> IamResult<()>;
}

/// Typed helpers over [`IamStore`].
pub trait IamStoreExt: IamStore {
    /// Serializable read/modify/write (`store.transaction(fn)`); nested transactions join the outer transaction.
    /// The callback receives the transaction handle; errors it returns roll the transaction back and propagate
    /// unchanged.
    fn transaction<'a, T, F, Fut>(
        &'a self,
        run: F,
    ) -> impl Future<Output = IamResult<T>> + Send + 'a
    where
        T: Send + 'static,
        F: FnOnce(Arc<dyn IamStore>) -> Fut + Send + 'a,
        Fut: Future<Output = IamResult<T>> + Send + 'a,
    {
        async move {
            // The callback's future is created in this closure, not inside the boxed future's poll, so it never
            // occupies an unoptimized build's stack frame on the way to the heap.
            let erased: TransactionFn<'a> = Box::new(move |tx| {
                let work = run(tx);
                Box::pin(async move { work.await.map(|value| Box::new(value) as TransactionValue) })
            });
            let value = self.transaction_dyn(erased).await?;
            match value.downcast::<T>() {
                Ok(value) => Ok(*value),
                Err(_) => Err(IamError::with_status(
                    "INTERNAL_ERROR",
                    "Transaction result type mismatch",
                    500,
                )),
            }
        }
    }

    /// `store.get(collection, id)` deserialized into a typed record.
    fn get_as<'a, T>(
        &'a self,
        collection: &'a str,
        id: &'a str,
    ) -> impl Future<Output = IamResult<Option<T>>> + Send + 'a
    where
        T: serde::de::DeserializeOwned + Send + 'a,
    {
        async move {
            match self.get(collection, id).await? {
                None => Ok(None),
                Some(record) => serde_json::from_value(Value::Object(record))
                    .map(Some)
                    .map_err(|_| {
                        IamError::with_status(
                            "STORAGE_CORRUPT",
                            "Record does not match its type",
                            500,
                        )
                    }),
            }
        }
    }
}

impl<S: IamStore + ?Sized> IamStoreExt for S {}

/// Walks a tenant and its ancestors: true only when every one exists and is active. Cycles read as inactive
/// (`tenantTreeActive`).
pub async fn tenant_tree_active(store: &dyn IamStore, tenant_id: &str) -> IamResult<bool> {
    let mut visited = std::collections::HashSet::new();
    let mut current = Some(tenant_id.to_owned());
    while let Some(id) = current.filter(|id| !id.is_empty()) {
        if !visited.insert(id.clone()) {
            return Ok(false);
        }
        let Some(tenant) = store.get("tenants", &id).await? else {
            return Ok(false);
        };
        if tenant.get("status").and_then(Value::as_str) != Some("active") {
            return Ok(false);
        }
        current = tenant
            .get("parentId")
            .and_then(Value::as_str)
            .map(str::to_owned);
    }
    Ok(true)
}

/// Builds a [`Record`] from a JSON object value; any other value gives an empty record.
pub fn record(value: Value) -> Record {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// The string member `id` of a record ("" when absent).
pub fn record_id(record: &Record) -> &str {
    record.get("id").and_then(Value::as_str).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_default_to_400() {
        let error = IamError::new("X", "y");
        assert_eq!(error.status, 400);
        assert_eq!(error.to_string(), "y");
    }
}
