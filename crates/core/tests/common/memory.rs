//! An in-memory `IamStore` built on the shared record-store logic, for core tests (snapshots, audit chains, and the
//! conformance suite run against the generic `record_store` code without SQL).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use better_iam_core::storage::{
    DriverError, DriverOperation, OperationValue, RecordAccess, RecordDriver, StorageRow,
    record_store, storage_error,
};
use better_iam_core::task_scope;
use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, IamStore, OrderOptions, Record, TransactionFn,
    TransactionValue,
};

type Rows = BTreeMap<(String, String), StorageRow>;

struct Context {
    active: AtomicBool,
    rollback_only: AtomicBool,
    rows: Arc<Mutex<Rows>>,
}

struct Shared {
    rows: Arc<Mutex<Rows>>,
    lock: tokio::sync::Mutex<()>,
    scope: usize,
    closed: AtomicBool,
}

#[derive(Clone)]
pub struct MemoryStore {
    shared: Arc<Shared>,
    context: Option<Arc<Context>>,
}

struct Driver {
    rows: Arc<Mutex<Rows>>,
}

fn lock(rows: &Mutex<Rows>) -> std::sync::MutexGuard<'_, Rows> {
    rows.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[async_trait::async_trait]
impl RecordDriver for Driver {
    async fn select(
        &self,
        collection: &str,
        id: Option<&str>,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StorageRow>, DriverError> {
        Ok(lock(&self.rows)
            .values()
            .filter(|row| row.collection == collection)
            .filter(|row| id.is_none_or(|id| row.id == id))
            .filter(|row| tenant_id.is_none_or(|tenant| row.tenant_id == tenant))
            .cloned()
            .collect())
    }

    async fn insert(&self, row: &StorageRow) -> Result<(), DriverError> {
        let mut rows = lock(&self.rows);
        let key = (row.collection.clone(), row.id.clone());
        if rows.contains_key(&key) {
            return Err(DriverError::database(
                "SQLITE_CONSTRAINT_PRIMARYKEY",
                "duplicate",
            ));
        }
        if row.unique_key.is_some()
            && rows.values().any(|other| {
                other.collection == row.collection
                    && other.tenant_id == row.tenant_id
                    && other.unique_key == row.unique_key
            })
        {
            return Err(DriverError::database(
                "SQLITE_CONSTRAINT_UNIQUE",
                "duplicate",
            ));
        }
        rows.insert(key, row.clone());
        Ok(())
    }

    async fn update(&self, row: &StorageRow) -> Result<bool, DriverError> {
        let mut rows = lock(&self.rows);
        let key = (row.collection.clone(), row.id.clone());
        if row.unique_key.is_some()
            && rows.values().any(|other| {
                other.collection == row.collection
                    && other.id != row.id
                    && other.tenant_id == row.tenant_id
                    && other.unique_key == row.unique_key
            })
        {
            return Err(DriverError::database(
                "SQLITE_CONSTRAINT_UNIQUE",
                "duplicate",
            ));
        }
        match rows.get_mut(&key) {
            Some(existing) if existing.tenant_id == row.tenant_id => {
                *existing = row.clone();
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn delete(&self, collection: &str, id: &str) -> Result<(), DriverError> {
        lock(&self.rows).remove(&(collection.to_owned(), id.to_owned()));
        Ok(())
    }

    fn has_collections(&self) -> bool {
        true
    }

    async fn collections(&self) -> Result<Vec<String>, DriverError> {
        let mut names: Vec<String> = lock(&self.rows)
            .values()
            .map(|row| row.collection.clone())
            .collect();
        names.dedup();
        names.sort();
        names.dedup();
        Ok(names)
    }
}

impl MemoryStore {
    pub fn open() -> Arc<dyn IamStore> {
        Arc::new(MemoryStore {
            shared: Arc::new(Shared {
                rows: Arc::new(Mutex::new(BTreeMap::new())),
                lock: tokio::sync::Mutex::new(()),
                scope: task_scope::new_key(),
                closed: AtomicBool::new(false),
            }),
            context: None,
        })
    }

    fn active(&self) -> IamResult<Option<Arc<Context>>> {
        if self.shared.closed.load(Ordering::SeqCst) && self.context.is_none() {
            return Err(IamError::with_status(
                "STORE_CLOSED",
                "Database adapter is closed",
                500,
            ));
        }
        let context = self
            .context
            .clone()
            .or_else(|| task_scope::current::<Context>(self.shared.scope));
        if let Some(context) = &context
            && !context.active.load(Ordering::SeqCst)
        {
            return Err(IamError::with_status(
                "TRANSACTION_CLOSED",
                "Transaction has already completed",
                500,
            ));
        }
        Ok(context)
    }
}

#[async_trait::async_trait]
impl RecordAccess for MemoryStore {
    async fn read(&self, operation: DriverOperation) -> IamResult<OperationValue> {
        if let Some(context) = self.active()? {
            let result = operation(Arc::new(Driver {
                rows: context.rows.clone(),
            }))
            .await;
            return result.map_err(|error| {
                context.rollback_only.store(true, Ordering::SeqCst);
                storage_error(error)
            });
        }
        let _guard = self.shared.lock.lock().await;
        self.active()?;
        operation(Arc::new(Driver {
            rows: self.shared.rows.clone(),
        }))
        .await
        .map_err(storage_error)
    }

    async fn write(&self, operation: DriverOperation) -> IamResult<OperationValue> {
        if self.active()?.is_none() {
            return Err(IamError::with_status(
                "TRANSACTION_REQUIRED",
                "Database writes require transaction()",
                500,
            ));
        }
        self.read(operation).await
    }
}

#[async_trait::async_trait]
impl IamStore for MemoryStore {
    async fn get(&self, collection: &str, id: &str) -> IamResult<Option<Record>> {
        record_store::get(self, collection, id).await
    }
    async fn find(
        &self,
        collection: &str,
        filter: &Filter,
        options: &FindOptions,
    ) -> IamResult<Vec<Record>> {
        record_store::find(self, collection, filter, options).await
    }
    fn has_find_ordered(&self) -> bool {
        true
    }
    async fn find_ordered(
        &self,
        collection: &str,
        filter: &Filter,
        order: &OrderOptions,
    ) -> IamResult<Vec<Record>> {
        record_store::find_ordered(self, collection, filter, order).await
    }
    fn has_collections(&self) -> bool {
        true
    }
    async fn collections(&self) -> IamResult<Vec<String>> {
        record_store::collections(self).await
    }
    async fn insert(&self, collection: &str, record: &Record) -> IamResult<Record> {
        record_store::insert(self, collection, record).await
    }
    async fn put(&self, collection: &str, record: &Record) -> IamResult<Record> {
        record_store::put(self, collection, record).await
    }
    async fn delete(&self, collection: &str, id: &str) -> IamResult<()> {
        record_store::delete(self, collection, id).await
    }
    async fn transaction_dyn(&self, run: TransactionFn<'_>) -> IamResult<TransactionValue> {
        if let Some(current) = self.active()? {
            let handle: Arc<dyn IamStore> = Arc::new(MemoryStore {
                shared: self.shared.clone(),
                context: Some(current.clone()),
            });
            return run(handle)
                .await
                .inspect_err(|_| current.rollback_only.store(true, Ordering::SeqCst));
        }
        let _guard = self.shared.lock.lock().await;
        self.active()?;
        let snapshot = lock(&self.shared.rows).clone();
        let context = Arc::new(Context {
            active: AtomicBool::new(true),
            rollback_only: AtomicBool::new(false),
            rows: Arc::new(Mutex::new(snapshot)),
        });
        let handle: Arc<dyn IamStore> = Arc::new(MemoryStore {
            shared: self.shared.clone(),
            context: Some(context.clone()),
        });
        let result = task_scope::run(self.shared.scope, context.clone(), run(handle)).await;
        context.active.store(false, Ordering::SeqCst);
        let value = result?;
        if context.rollback_only.load(Ordering::SeqCst) {
            return Err(IamError::with_status(
                "TRANSACTION_ABORTED",
                "A nested database operation failed; transaction rolled back",
                409,
            ));
        }
        let committed = lock(&context.rows).clone();
        *lock(&self.shared.rows) = committed;
        Ok(value)
    }
    async fn migrate(&self) -> IamResult<()> {
        self.active()?;
        Ok(())
    }
    async fn close(&self) -> IamResult<()> {
        if self.shared.closed.load(Ordering::SeqCst) {
            return Ok(());
        }
        if self.active()?.is_some() {
            return Err(IamError::with_status(
                "TRANSACTION_ACTIVE",
                "Cannot close an adapter inside a transaction",
                500,
            ));
        }
        self.shared.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}
