//! Storage call instrumentation (`instrument.ts`): wraps a store so every data call is reported, for slow-query
//! logging, capacity planning, and tests that bound how much work an operation does. The wrapper adds no behavior.

use std::sync::Arc;
use std::time::Instant;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::storage::Filter;
use crate::{
    FindOptions, IamResult, IamStore, OrderOptions, Record, StoreDescription, TransactionFn,
    TransactionValue,
};

/// The storage method a [`StoreCall`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StoreMethod {
    Get,
    Find,
    FindOrdered,
    Insert,
    Put,
    Delete,
    Collections,
    Describe,
}

impl StoreMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            StoreMethod::Get => "get",
            StoreMethod::Find => "find",
            StoreMethod::FindOrdered => "findOrdered",
            StoreMethod::Insert => "insert",
            StoreMethod::Put => "put",
            StoreMethod::Delete => "delete",
            StoreMethod::Collections => "collections",
            StoreMethod::Describe => "describe",
        }
    }
}

/// Pagination of a reported `find` (`StoreCall.page`): a keyset cursor is reported as `keyset: true`, not its id.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreCallPage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyset: Option<bool>,
}

/// One storage call observed by [`instrument_store`] (`StoreCall`). Never carries record data or filter values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreCall {
    pub method: StoreMethod,
    /// The collection, or `*` for whole-store calls.
    pub collection: String,
    /// Filter keys of a `find`, sorted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_keys: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<StoreCallPage>,
    /// Records returned or written; collections listed or described for whole-store calls.
    pub records: u64,
    pub duration_ms: f64,
    /// The call was made through the handle a transaction callback received.
    pub in_transaction: bool,
    /// The call failed; `records` is 0.
    pub failed: bool,
}

/// Receives each [`StoreCall`]; a panic in it is caught and ignored.
pub type StoreCallListener = Arc<dyn Fn(&StoreCall) + Send + Sync>;
/// The clock in milliseconds (`performance.now()` by default).
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

struct Instrumented {
    target: Arc<dyn IamStore>,
    on_call: StoreCallListener,
    now: Clock,
    in_transaction: bool,
}

impl Instrumented {
    fn report(&self, call: StoreCall) {
        let listener = self.on_call.clone();
        // Observability must never change the outcome of a storage call.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| listener(&call)));
    }

    async fn timed<T>(
        &self,
        method: StoreMethod,
        collection: &str,
        filter_keys: Option<Vec<String>>,
        page: Option<StoreCallPage>,
        run: impl std::future::Future<Output = IamResult<T>>,
        count: impl Fn(&T) -> u64,
    ) -> IamResult<T> {
        let started = (self.now)();
        let result = run.await;
        let (records, failed) = match &result {
            Ok(value) => (count(value), false),
            Err(_) => (0, true),
        };
        self.report(StoreCall {
            method,
            collection: collection.to_owned(),
            filter_keys,
            page,
            records,
            duration_ms: (self.now)() - started,
            in_transaction: self.in_transaction,
            failed,
        });
        result
    }
}

fn sorted_keys(filter: &Filter) -> Vec<String> {
    let mut keys: Vec<String> = filter.keys().into_iter().map(str::to_owned).collect();
    keys.sort_by(|left, right| crate::js::cmp_utf16(left, right));
    keys
}

#[async_trait::async_trait]
impl IamStore for Instrumented {
    async fn get(&self, collection: &str, id: &str) -> IamResult<Option<Record>> {
        self.timed(
            StoreMethod::Get,
            collection,
            None,
            None,
            self.target.get(collection, id),
            |value| u64::from(value.is_some()),
        )
        .await
    }

    async fn find(
        &self,
        collection: &str,
        filter: &Filter,
        options: &FindOptions,
    ) -> IamResult<Vec<Record>> {
        let page = (options.limit.is_some() || options.offset.is_some() || options.after.is_some())
            .then(|| StoreCallPage {
                offset: options.offset,
                limit: options.limit,
                keyset: options.after.as_ref().map(|_| true),
            });
        self.timed(
            StoreMethod::Find,
            collection,
            Some(sorted_keys(filter)),
            page,
            self.target.find(collection, filter, options),
            |records| records.len() as u64,
        )
        .await
    }

    fn has_find_ordered(&self) -> bool {
        self.target.has_find_ordered()
    }

    async fn find_ordered(
        &self,
        collection: &str,
        filter: &Filter,
        order: &OrderOptions,
    ) -> IamResult<Vec<Record>> {
        self.timed(
            StoreMethod::FindOrdered,
            collection,
            Some(sorted_keys(filter)),
            Some(StoreCallPage {
                offset: order.offset,
                limit: order.limit,
                keyset: None,
            }),
            self.target.find_ordered(collection, filter, order),
            |records| records.len() as u64,
        )
        .await
    }

    fn has_collections(&self) -> bool {
        self.target.has_collections()
    }

    async fn collections(&self) -> IamResult<Vec<String>> {
        self.timed(
            StoreMethod::Collections,
            "*",
            None,
            None,
            self.target.collections(),
            |names| names.len() as u64,
        )
        .await
    }

    fn has_describe(&self) -> bool {
        self.target.has_describe()
    }

    async fn describe(&self) -> IamResult<StoreDescription> {
        self.timed(
            StoreMethod::Describe,
            "*",
            None,
            None,
            self.target.describe(),
            |description| description.collections.len() as u64,
        )
        .await
    }

    async fn insert(&self, collection: &str, record: &Record) -> IamResult<Record> {
        self.timed(
            StoreMethod::Insert,
            collection,
            None,
            None,
            self.target.insert(collection, record),
            |_| 1,
        )
        .await
    }

    async fn put(&self, collection: &str, record: &Record) -> IamResult<Record> {
        self.timed(
            StoreMethod::Put,
            collection,
            None,
            None,
            self.target.put(collection, record),
            |_| 1,
        )
        .await
    }

    async fn delete(&self, collection: &str, id: &str) -> IamResult<()> {
        self.timed(
            StoreMethod::Delete,
            collection,
            None,
            None,
            self.target.delete(collection, id),
            |_| 1,
        )
        .await
    }

    async fn transaction_dyn(&self, run: TransactionFn<'_>) -> IamResult<TransactionValue> {
        let (on_call, now) = (self.on_call.clone(), self.now.clone());
        self.target
            .transaction_dyn(Box::new(move |tx| {
                let wrapped: Arc<dyn IamStore> = Arc::new(Instrumented {
                    target: tx,
                    on_call,
                    now,
                    in_transaction: true,
                });
                run(wrapped)
            }))
            .await
    }

    async fn migrate(&self) -> IamResult<()> {
        self.target.migrate().await
    }

    async fn close(&self) -> IamResult<()> {
        self.target.close().await
    }
}

/// Wraps a store so every data call is reported to `on_call` (`instrumentStore`): reads, writes, `collections`, and
/// `describe`; `transaction`, `migrate`, and `close` pass straight through. `now` defaults to a monotonic clock in
/// milliseconds.
pub fn instrument_store(
    store: Arc<dyn IamStore>,
    on_call: StoreCallListener,
    now: Option<Clock>,
) -> Arc<dyn IamStore> {
    let now = now.unwrap_or_else(|| {
        let origin = Instant::now();
        Arc::new(move || origin.elapsed().as_secs_f64() * 1000.0)
    });
    Arc::new(Instrumented {
        target: store,
        on_call,
        now,
        in_transaction: false,
    })
}

/// Totals of one group of calls in [`summarize_store_calls`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreCallTotals {
    pub calls: u64,
    pub records: u64,
    pub duration_ms: f64,
}

/// Totals of a list of calls, grouped by method and collection (`find:sessions`) (`summarizeStoreCalls`).
pub fn summarize_store_calls(calls: &[StoreCall]) -> IndexMap<String, StoreCallTotals> {
    let mut summary: IndexMap<String, StoreCallTotals> = IndexMap::new();
    for call in calls {
        let entry = summary
            .entry(format!("{}:{}", call.method.as_str(), call.collection))
            .or_default();
        entry.calls += 1;
        entry.records += call.records;
        entry.duration_ms += call.duration_ms;
    }
    summary
}
