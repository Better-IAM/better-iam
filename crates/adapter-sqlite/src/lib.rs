//! SQLite storage for Better IAM (`@better-iam/adapter-sqlite`): the same schema, migrations, SQL and record
//! encoding as the TypeScript adapter, so TypeScript and Rust servers can share one database file.
//!
//! SQLite serializes operations per canonical filename in this process. SQLite's own `BEGIN IMMEDIATE` lock
//! coordinates other processes with a bounded wait. Use PostgreSQL when sustained concurrent writes or large datasets
//! are expected.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use better_iam_core::sql::{
    COLLECTIONS_SQL, MigrationOptions, SqlDialect, SqlExecutor, SqlRow, SqlValue, apply_migrations,
    describe_records, sqlite_select,
};
use better_iam_core::storage::{
    DriverError, DriverOperation, OperationValue, QueryCapabilities, RecordAccess, RecordDriver,
    RecordQuery, StorageRow, record_store, storage_error,
};
use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, IamStore, OrderOptions, Record, StoreDescription,
    TransactionFn, TransactionValue, task_scope,
};
use rusqlite::types::{Value as SqliteValue, ValueRef};
use rusqlite::{Connection, params_from_iter};
use serde_json::{Map, Value};

/// `SqliteAdapterOptions`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SqliteAdapterOptions {
    /// A file path or `:memory:`; URI filenames (`file:`) are refused.
    pub filename: String,
    /// How long an operation waits for another connection's lock (default 5000, 0 to 60000).
    pub busy_timeout_ms: Option<i64>,
    /// Journal of a database file: `wal` (default) or `delete` (for file systems without shared-memory support).
    /// Ignored for `:memory:`.
    pub journal_mode: Option<String>,
    /// `full` (default) flushes every commit to disk; `normal` in WAL mode can lose the last commits on power loss.
    pub durability: Option<String>,
}

impl SqliteAdapterOptions {
    pub fn new(filename: impl Into<String>) -> Self {
        Self {
            filename: filename.into(),
            ..Self::default()
        }
    }
}

// --- per-file locks ------------------------------------------------------------------------------

/// One entry of the locks the current call chain holds.
struct Held {
    mutex: usize,
    active: AtomicBool,
}

/// The per-file locks the current async call chain holds, so re-entry fails instead of waiting on itself.
#[derive(Default)]
struct HeldChain(Vec<Arc<Held>>);

fn held_key() -> usize {
    static KEY: OnceLock<usize> = OnceLock::new();
    *KEY.get_or_init(task_scope::new_key)
}

struct FileMutex {
    id: usize,
    lock: tokio::sync::Mutex<()>,
}

impl FileMutex {
    fn new() -> Arc<Self> {
        static NEXT: AtomicUsize = AtomicUsize::new(1);
        Arc::new(Self {
            id: NEXT.fetch_add(1, Ordering::Relaxed),
            lock: tokio::sync::Mutex::new(()),
        })
    }

    async fn run<T, F>(&self, operation: F) -> IamResult<T>
    where
        F: std::future::Future<Output = IamResult<T>>,
    {
        // Another adapter instance on the same file, called inside this instance's transaction (for example copying
        // a database onto itself), would otherwise wait for a lock its caller holds.
        let chain = task_scope::current::<HeldChain>(held_key());
        if chain.as_ref().is_some_and(|chain| {
            chain
                .0
                .iter()
                .any(|entry| entry.mutex == self.id && entry.active.load(Ordering::SeqCst))
        }) {
            return Err(IamError::with_status(
                "DATABASE_IN_USE",
                "This call chain already holds this database through another adapter instance",
                409,
            ));
        }
        let _guard = self.lock.lock().await;
        let entry = Arc::new(Held {
            mutex: self.id,
            active: AtomicBool::new(true),
        });
        let mut entries = chain.map(|chain| chain.0.clone()).unwrap_or_default();
        entries.push(entry.clone());
        let result = task_scope::run(held_key(), Arc::new(HeldChain(entries)), operation).await;
        entry.active.store(false, Ordering::SeqCst);
        result
    }
}

/// The canonical spelling of a database path: absolute, symlinks and Windows short names resolved, lower case on
/// Windows, so every spelling of a file shares one lock.
fn canonical_path(filename: &str) -> String {
    let absolute =
        std::path::absolute(Path::new(filename)).unwrap_or_else(|_| PathBuf::from(filename));
    let resolved = std::fs::canonicalize(&absolute).ok().or_else(|| {
        let parent = absolute.parent()?;
        let name = absolute.file_name()?;
        std::fs::canonicalize(parent)
            .ok()
            .map(|parent| parent.join(name))
    });
    let text = resolved.unwrap_or(absolute).to_string_lossy().into_owned();
    if cfg!(windows) {
        text.to_lowercase()
    } else {
        text
    }
}

fn mutex_for(filename: &str) -> Arc<FileMutex> {
    if filename == ":memory:" {
        return FileMutex::new();
    }
    static MUTEXES: OnceLock<Mutex<HashMap<String, Arc<FileMutex>>>> = OnceLock::new();
    let mut mutexes = MUTEXES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    mutexes
        .entry(canonical_path(filename))
        .or_insert_with(FileMutex::new)
        .clone()
}

// --- errors --------------------------------------------------------------------------------------

/// The result code name better-sqlite3 reports in `error.code`.
fn code_name(extended: i32) -> String {
    let name = match extended {
        261 => "SQLITE_BUSY_RECOVERY",
        517 => "SQLITE_BUSY_SNAPSHOT",
        773 => "SQLITE_BUSY_TIMEOUT",
        262 => "SQLITE_LOCKED_SHAREDCACHE",
        518 => "SQLITE_LOCKED_VTAB",
        275 => "SQLITE_CONSTRAINT_CHECK",
        531 => "SQLITE_CONSTRAINT_COMMITHOOK",
        787 => "SQLITE_CONSTRAINT_FOREIGNKEY",
        1043 => "SQLITE_CONSTRAINT_FUNCTION",
        1299 => "SQLITE_CONSTRAINT_NOTNULL",
        1555 => "SQLITE_CONSTRAINT_PRIMARYKEY",
        1811 => "SQLITE_CONSTRAINT_TRIGGER",
        2067 => "SQLITE_CONSTRAINT_UNIQUE",
        2323 => "SQLITE_CONSTRAINT_VTAB",
        2579 => "SQLITE_CONSTRAINT_ROWID",
        2835 => "SQLITE_CONSTRAINT_PINNED",
        3091 => "SQLITE_CONSTRAINT_DATATYPE",
        264 => "SQLITE_READONLY_RECOVERY",
        520 => "SQLITE_READONLY_CANTLOCK",
        776 => "SQLITE_READONLY_ROLLBACK",
        1032 => "SQLITE_READONLY_DBMOVED",
        270 => "SQLITE_CANTOPEN_NOTEMPDIR",
        526 => "SQLITE_CANTOPEN_ISDIR",
        782 => "SQLITE_CANTOPEN_FULLPATH",
        267 => "SQLITE_CORRUPT_VTAB",
        257 => "SQLITE_ERROR_MISSING_COLLSEQ",
        513 => "SQLITE_ERROR_RETRY",
        769 => "SQLITE_ERROR_SNAPSHOT",
        516 => "SQLITE_ABORT_ROLLBACK",
        code => match code & 0xff {
            1 => "SQLITE_ERROR",
            2 => "SQLITE_INTERNAL",
            3 => "SQLITE_PERM",
            4 => "SQLITE_ABORT",
            5 => "SQLITE_BUSY",
            6 => "SQLITE_LOCKED",
            7 => "SQLITE_NOMEM",
            8 => "SQLITE_READONLY",
            9 => "SQLITE_INTERRUPT",
            10 => "SQLITE_IOERR",
            11 => "SQLITE_CORRUPT",
            12 => "SQLITE_NOTFOUND",
            13 => "SQLITE_FULL",
            14 => "SQLITE_CANTOPEN",
            15 => "SQLITE_PROTOCOL",
            16 => "SQLITE_EMPTY",
            17 => "SQLITE_SCHEMA",
            18 => "SQLITE_TOOBIG",
            19 => "SQLITE_CONSTRAINT",
            20 => "SQLITE_MISMATCH",
            21 => "SQLITE_MISUSE",
            22 => "SQLITE_NOLFS",
            23 => "SQLITE_AUTH",
            24 => "SQLITE_FORMAT",
            25 => "SQLITE_RANGE",
            26 => "SQLITE_NOTADB",
            _ => "SQLITE_ERROR",
        },
    };
    name.to_owned()
}

fn sqlite_error(error: rusqlite::Error) -> DriverError {
    match error {
        rusqlite::Error::SqliteFailure(failure, message) => DriverError::database(
            code_name(failure.extended_code),
            message.unwrap_or_else(|| failure.to_string()),
        ),
        other => DriverError::database("SQLITE_ERROR", other.to_string()),
    }
}

// --- the connection ------------------------------------------------------------------------------

type SharedConnection = Arc<Mutex<Option<Connection>>>;

fn closed_error() -> IamError {
    IamError::with_status("STORE_CLOSED", "Database adapter is closed", 500)
}

/// Runs a statement batch on the connection, off the async threads.
async fn blocking<T, F>(connection: &SharedConnection, run: F) -> Result<T, DriverError>
where
    T: Send + 'static,
    F: FnOnce(&Connection) -> Result<T, DriverError> + Send + 'static,
{
    let connection = connection.clone();
    tokio::task::spawn_blocking(move || {
        let guard = connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(connection) = guard.as_ref() else {
            return Err(DriverError::Iam(closed_error()));
        };
        run(connection)
    })
    .await
    .map_err(|error| DriverError::database("SQLITE_ERROR", error.to_string()))?
}

fn parameters(values: &[SqlValue]) -> Vec<SqliteValue> {
    values
        .iter()
        .map(|value| match value {
            SqlValue::Null => SqliteValue::Null,
            SqlValue::Integer(value) => SqliteValue::Integer(*value),
            SqlValue::Real(value) => SqliteValue::Real(*value),
            SqlValue::Text(value) => SqliteValue::Text(value.clone()),
        })
        .collect()
}

fn json_of(value: ValueRef<'_>) -> Value {
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(value) => {
            better_iam_core::js::number(value as f64).unwrap_or(Value::Null)
        }
        ValueRef::Real(value) => better_iam_core::js::number(value).unwrap_or(Value::Null),
        ValueRef::Text(text) => Value::String(String::from_utf8_lossy(text).into_owned()),
        ValueRef::Blob(bytes) => {
            Value::Array(bytes.iter().map(|byte| Value::from(*byte)).collect())
        }
    }
}

fn rows_of(
    connection: &Connection,
    text: &str,
    values: &[SqlValue],
) -> Result<Vec<SqlRow>, DriverError> {
    let mut statement = connection.prepare_cached(text).map_err(sqlite_error)?;
    let names: Vec<String> = statement
        .column_names()
        .into_iter()
        .map(str::to_owned)
        .collect();
    let mut rows = statement
        .query(params_from_iter(parameters(values)))
        .map_err(sqlite_error)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let mut map = Map::new();
        for (index, name) in names.iter().enumerate() {
            map.insert(
                name.clone(),
                json_of(row.get_ref(index).map_err(sqlite_error)?),
            );
        }
        out.push(map);
    }
    Ok(out)
}

fn storage_rows(
    connection: &Connection,
    text: &str,
    values: &[SqlValue],
) -> Result<Vec<StorageRow>, DriverError> {
    let mut statement = connection.prepare_cached(text).map_err(sqlite_error)?;
    let rows = statement
        .query_map(params_from_iter(parameters(values)), |row| {
            Ok(StorageRow {
                collection: row.get("collection")?,
                id: row.get("id")?,
                tenant_id: row.get("tenant_id")?,
                unique_key: row.get("unique_key")?,
                data: row.get("data")?,
            })
        })
        .map_err(sqlite_error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
}

fn execute(connection: &Connection, text: &str, values: &[SqlValue]) -> Result<usize, DriverError> {
    let mut statement = connection.prepare_cached(text).map_err(sqlite_error)?;
    statement
        .execute(params_from_iter(parameters(values)))
        .map_err(sqlite_error)
}

/// The record driver of one connection (`driverFor`).
struct Driver {
    connection: SharedConnection,
}

#[async_trait::async_trait]
impl RecordDriver for Driver {
    async fn select(
        &self,
        collection: &str,
        id: Option<&str>,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StorageRow>, DriverError> {
        let mut text = "SELECT collection, id, tenant_id, unique_key, data FROM iam_records WHERE collection = ?".to_owned();
        let mut values = vec![SqlValue::from(collection)];
        if let Some(id) = id {
            text.push_str(" AND id = ?");
            values.push(SqlValue::from(id));
        }
        if let Some(tenant_id) = tenant_id {
            text.push_str(" AND tenant_id = ?");
            values.push(SqlValue::from(tenant_id));
        }
        text.push_str(" ORDER BY id ASC");
        blocking(&self.connection, move |connection| {
            storage_rows(connection, &text, &values)
        })
        .await
    }

    async fn insert(&self, row: &StorageRow) -> Result<(), DriverError> {
        let values = vec![
            SqlValue::from(row.collection.as_str()),
            SqlValue::from(row.id.as_str()),
            SqlValue::from(row.tenant_id.as_str()),
            row.unique_key
                .clone()
                .map(SqlValue::Text)
                .unwrap_or(SqlValue::Null),
            SqlValue::from(row.data.as_str()),
        ];
        blocking(&self.connection, move |connection| {
            execute(
                connection,
                "INSERT INTO iam_records (collection, id, tenant_id, unique_key, data) VALUES (?, ?, ?, ?, ?)",
                &values,
            )
            .map(|_| ())
        })
        .await
    }

    async fn update(&self, row: &StorageRow) -> Result<bool, DriverError> {
        let values = vec![
            SqlValue::from(row.data.as_str()),
            row.unique_key
                .clone()
                .map(SqlValue::Text)
                .unwrap_or(SqlValue::Null),
            SqlValue::from(row.collection.as_str()),
            SqlValue::from(row.id.as_str()),
            SqlValue::from(row.tenant_id.as_str()),
        ];
        blocking(&self.connection, move |connection| {
            execute(
                connection,
                "UPDATE iam_records SET data = ?, unique_key = ? WHERE collection = ? AND id = ? AND tenant_id = ?",
                &values,
            )
            .map(|changed| changed == 1)
        })
        .await
    }

    async fn delete(&self, collection: &str, id: &str) -> Result<(), DriverError> {
        let values = vec![SqlValue::from(collection), SqlValue::from(id)];
        blocking(&self.connection, move |connection| {
            execute(
                connection,
                "DELETE FROM iam_records WHERE collection = ? AND id = ?",
                &values,
            )
            .map(|_| ())
        })
        .await
    }

    fn has_query(&self) -> bool {
        true
    }

    fn query_capabilities(&self) -> QueryCapabilities {
        QueryCapabilities {
            json: false,
            order: true,
        }
    }

    async fn query(&self, query: &RecordQuery) -> Result<Vec<StorageRow>, DriverError> {
        let statement = sqlite_select(query)?;
        blocking(&self.connection, move |connection| {
            storage_rows(connection, &statement.text, &statement.values)
        })
        .await
    }

    fn has_collections(&self) -> bool {
        true
    }

    async fn collections(&self) -> Result<Vec<String>, DriverError> {
        let rows = blocking(&self.connection, |connection| {
            rows_of(connection, COLLECTIONS_SQL, &[])
        })
        .await?;
        Ok(rows
            .iter()
            .map(|row| match row.get("collection") {
                Some(Value::String(name)) => name.clone(),
                Some(other) => other.to_string(),
                None => String::new(),
            })
            .collect())
    }
}

/// The connection as a [`SqlExecutor`] (`executor`).
struct Executor {
    connection: SharedConnection,
}

#[async_trait::async_trait]
impl SqlExecutor for Executor {
    async fn execute(&self, text: &str, values: &[SqlValue]) -> Result<Vec<SqlRow>, DriverError> {
        let (text, values) = (text.to_owned(), values.to_vec());
        blocking(&self.connection, move |connection| {
            rows_of(connection, &text, &values)
        })
        .await
    }
}

// --- the store -----------------------------------------------------------------------------------

struct TransactionContext {
    active: AtomicBool,
    rollback_only: AtomicBool,
}

struct Shared {
    connection: SharedConnection,
    mutex: Arc<FileMutex>,
    /// The `AsyncLocalStorage` of this adapter instance.
    scope: usize,
    in_memory: bool,
}

/// A SQLite store (`SqliteStore`): the root store, or a transaction handle when `context` is set.
pub struct SqliteStore {
    shared: Arc<Shared>,
    context: Option<Arc<TransactionContext>>,
    closed: AtomicBool,
}

const SYNCHRONOUS_MODES: [&str; 4] = ["off", "normal", "full", "extra"];

impl SqliteStore {
    fn handle(&self, context: Arc<TransactionContext>) -> Arc<dyn IamStore> {
        Arc::new(SqliteStore {
            shared: self.shared.clone(),
            context: Some(context),
            closed: AtomicBool::new(false),
        })
    }

    fn active(&self) -> IamResult<Option<Arc<TransactionContext>>> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(closed_error());
        }
        let context = self
            .context
            .clone()
            .or_else(|| task_scope::current::<TransactionContext>(self.shared.scope));
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

    fn driver(&self) -> Arc<dyn RecordDriver> {
        Arc::new(Driver {
            connection: self.shared.connection.clone(),
        })
    }

    async fn statement(&self, text: &'static str) -> IamResult<()> {
        blocking(&self.shared.connection, move |connection| {
            connection.execute_batch(text).map_err(sqlite_error)
        })
        .await
        .map_err(storage_error)
    }

    async fn describe_now(&self) -> IamResult<StoreDescription> {
        let executor = Executor {
            connection: self.shared.connection.clone(),
        };
        let pragma = |name: &'static str| {
            let executor = &executor;
            async move {
                let rows = executor.execute(&format!("PRAGMA {name}"), &[]).await?;
                Ok::<Option<Value>, DriverError>(
                    rows.first().and_then(|row| row.values().next().cloned()),
                )
            }
        };
        let number = |value: Option<Value>| {
            value
                .as_ref()
                .map(better_iam_core::js::to_number)
                .unwrap_or(f64::NAN)
        };
        let run = async {
            let page_size = number(pragma("page_size").await?);
            let journal_mode = match pragma("journal_mode").await? {
                Some(Value::String(mode)) => mode,
                Some(other) => other.to_string(),
                None => "undefined".to_owned(),
            };
            let synchronous = number(pragma("synchronous").await?);
            let synchronous = if synchronous.fract() == 0.0 && (0.0..4.0).contains(&synchronous) {
                Value::String(SYNCHRONOUS_MODES[synchronous as usize].to_owned())
            } else {
                Value::Null
            };
            let size = number(pragma("page_count").await?) * page_size;
            let free = number(pragma("freelist_count").await?) * page_size;
            let mut settings = Map::new();
            settings.insert("journalMode".into(), Value::String(journal_mode));
            settings.insert("synchronous".into(), synchronous);
            settings.insert(
                "sizeBytes".into(),
                better_iam_core::js::number(size).unwrap_or(Value::Null),
            );
            settings.insert(
                "freeBytes".into(),
                better_iam_core::js::number(free).unwrap_or(Value::Null),
            );
            settings.insert("inMemory".into(), Value::Bool(self.shared.in_memory));
            describe_records(&executor, "sqlite", settings).await
        };
        run.await.map_err(storage_error)
    }
}

#[async_trait::async_trait]
impl RecordAccess for SqliteStore {
    async fn read(&self, operation: DriverOperation) -> IamResult<OperationValue> {
        if let Some(context) = self.active()? {
            return operation(self.driver()).await.map_err(|error| {
                context.rollback_only.store(true, Ordering::SeqCst);
                storage_error(error)
            });
        }
        self.shared
            .mutex
            .run(async {
                self.active()?;
                operation(self.driver()).await.map_err(storage_error)
            })
            .await
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
impl IamStore for SqliteStore {
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

    fn has_describe(&self) -> bool {
        true
    }

    async fn describe(&self) -> IamResult<StoreDescription> {
        if self.active()?.is_some() {
            return self.describe_now().await;
        }
        self.shared
            .mutex
            .run(async {
                self.active()?;
                self.describe_now().await
            })
            .await
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
            return run(self.handle(current.clone())).await.inspect_err(|_| {
                current.rollback_only.store(true, Ordering::SeqCst);
            });
        }
        self.shared
            .mutex
            .run(async {
                self.active()?;
                // Acquire the SQLite writer lock before any reads, and keep one connection across awaited
                // application code. A deferred transaction is not sufficient.
                self.statement("BEGIN IMMEDIATE").await?;
                let context = Arc::new(TransactionContext {
                    active: AtomicBool::new(true),
                    rollback_only: AtomicBool::new(false),
                });
                let handle = self.handle(context.clone());
                let outcome =
                    task_scope::run(self.shared.scope, context.clone(), run(handle)).await;
                let outcome = match outcome {
                    Ok(value) if context.rollback_only.load(Ordering::SeqCst) => {
                        drop(value);
                        Err(IamError::with_status(
                            "TRANSACTION_ABORTED",
                            "A nested database operation failed; transaction rolled back",
                            409,
                        ))
                    }
                    Ok(value) => self.statement("COMMIT").await.map(|()| value),
                    Err(error) => Err(error),
                };
                if outcome.is_err() {
                    // Preserve the original failure.
                    let _ = self.statement("ROLLBACK").await;
                }
                context.active.store(false, Ordering::SeqCst);
                outcome
            })
            .await
    }

    async fn migrate(&self) -> IamResult<()> {
        let connection = self.shared.connection.clone();
        better_iam_core::IamStoreExt::transaction(self, move |_store| async move {
            let executor = Executor { connection };
            apply_migrations(&executor, SqlDialect::Sqlite, MigrationOptions::default())
                .await
                .map(|_| ())
                .map_err(storage_error)
        })
        .await
    }

    async fn close(&self) -> IamResult<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Ok(());
        }
        if self.active()?.is_some() {
            return Err(IamError::with_status(
                "TRANSACTION_ACTIVE",
                "Cannot close an adapter inside a transaction",
                500,
            ));
        }
        self.shared
            .mutex
            .run(async {
                if !self.closed.swap(true, Ordering::SeqCst) {
                    let connection = self.shared.connection.clone();
                    let taken = tokio::task::spawn_blocking(move || {
                        connection
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .take()
                    })
                    .await
                    .ok()
                    .flatten();
                    if let Some(connection) = taken {
                        let _ = connection.close();
                    }
                }
                Ok(())
            })
            .await
    }
}

fn invalid_config(message: &str) -> IamError {
    IamError::new("INVALID_CONFIG", message)
}

/// Opens a SQLite store (`sqliteAdapter`). SQLite serializes operations per canonical filename in this process;
/// SQLite's own `BEGIN IMMEDIATE` lock coordinates other processes with a bounded wait.
pub fn sqlite_adapter(options: SqliteAdapterOptions) -> IamResult<Arc<dyn IamStore>> {
    sqlite_store(options).map(|store| store as Arc<dyn IamStore>)
}

/// [`sqlite_adapter`] returning the concrete store.
pub fn sqlite_store(options: SqliteAdapterOptions) -> IamResult<Arc<SqliteStore>> {
    if options.filename.is_empty() || options.filename.starts_with("file:") {
        return Err(invalid_config(
            "SQLite requires a filename or :memory:; URI filenames are unsupported",
        ));
    }
    let timeout = options.busy_timeout_ms.unwrap_or(5000);
    if !(0..=60_000).contains(&timeout) {
        return Err(invalid_config("busyTimeoutMs must be between 0 and 60000"));
    }
    if options
        .journal_mode
        .as_deref()
        .is_some_and(|mode| mode != "wal" && mode != "delete")
    {
        return Err(invalid_config("journalMode must be wal or delete"));
    }
    if options
        .durability
        .as_deref()
        .is_some_and(|mode| mode != "full" && mode != "normal")
    {
        return Err(invalid_config("durability must be full or normal"));
    }
    let mutex = mutex_for(&options.filename);
    let in_memory = options.filename == ":memory:";
    let open = || -> Result<Connection, rusqlite::Error> {
        let connection = Connection::open(&options.filename)?;
        connection.busy_timeout(Duration::from_millis(timeout as u64))?;
        connection.set_prepared_statement_cache_capacity(256);
        connection.execute_batch("PRAGMA foreign_keys = ON")?;
        if !in_memory {
            let mode = if options.journal_mode.as_deref() == Some("delete") {
                "DELETE"
            } else {
                "WAL"
            };
            connection.query_row(&format!("PRAGMA journal_mode = {mode}"), [], |_| Ok(()))?;
        }
        let synchronous = if options.durability.as_deref() == Some("normal") {
            "NORMAL"
        } else {
            "FULL"
        };
        connection.execute_batch(&format!("PRAGMA synchronous = {synchronous}"))?;
        Ok(connection)
    };
    let connection = open().map_err(|error| storage_error(sqlite_error(error)))?;
    Ok(Arc::new(SqliteStore {
        shared: Arc::new(Shared {
            connection: Arc::new(Mutex::new(Some(connection))),
            mutex,
            scope: task_scope::new_key(),
            in_memory,
        }),
        context: None,
        closed: AtomicBool::new(false),
    }))
}
