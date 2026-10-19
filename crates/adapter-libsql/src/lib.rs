//! libSQL persistence for Better IAM (`@better-iam/adapter-libsql`): local files and remote Turso or sqld databases
//! through one adapter, with the same schema, migrations, SQL and record encoding as the TypeScript adapter.
//! Transactions serialize per database in this process and take the writer lock (`BEGIN IMMEDIATE`) before any read;
//! remote servers queue write transactions themselves.
//!
//! Local databases (`:memory:`, `file:` URLs and plain paths) are SQLite files and run on the bundled SQLite of
//! `rusqlite`; remote databases (`libsql:`, `https:`, `http:`, `wss:`, `ws:`) run over Hrana with the `libsql`
//! crate. The libSQL C core is not linked: it defines the same C symbols as bundled SQLite, so a program could not
//! use this adapter and the SQLite adapter together. Embedded replicas (`sync_url`) and encrypted local files
//! (`encryption_key`) need that core and are refused with `NOT_IMPLEMENTED`.
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
    TransactionFn, TransactionValue, js, task_scope,
};
use rusqlite::types::{Value as SqliteValue, ValueRef};
use serde_json::{Map, Value};

/// `LibsqlAdapterOptions`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LibsqlAdapterOptions {
    /// `:memory:`, `file:./iam.db`, a plain path, or a remote `libsql:`, `https:`, `wss:` URL (Turso, sqld).
    pub url: String,
    /// Bearer token for remote databases.
    pub auth_token: Option<String>,
    /// Encryption key for local encrypted files (not implemented in the Rust adapter).
    pub encryption_key: Option<String>,
    /// Embedded replica: a local file kept in sync with this remote URL (not implemented in the Rust adapter).
    pub sync_url: Option<String>,
    /// Sync interval in seconds for embedded replicas.
    pub sync_interval: Option<f64>,
    /// How long local file operations wait for another connection's lock (default 5000, 0-60000).
    pub busy_timeout_ms: Option<i64>,
}

impl LibsqlAdapterOptions {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Self::default()
        }
    }
}

// --- per-database locks --------------------------------------------------------------------------

struct Held {
    mutex: usize,
    active: AtomicBool,
}

#[derive(Default)]
struct HeldChain(Vec<Arc<Held>>);

fn held_key() -> usize {
    static KEY: OnceLock<usize> = OnceLock::new();
    *KEY.get_or_init(task_scope::new_key)
}

struct DatabaseMutex {
    id: usize,
    lock: tokio::sync::Mutex<()>,
}

impl DatabaseMutex {
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
        // Another adapter instance on the same database, called inside this instance's transaction, would otherwise
        // wait for a lock its caller holds.
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

fn memory(url: &str) -> bool {
    url == ":memory:" || url.starts_with("file::memory:")
}

/// `/^[a-z][a-z0-9+.-]+:/i`: a URL scheme of two or more characters (a single letter is a Windows drive).
fn has_scheme(url: &str) -> bool {
    let bytes = url.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    let end = bytes
        .iter()
        .position(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-')));
    matches!(end, Some(end) if end >= 2 && bytes[end] == b':')
}

/// The file path of a local URL (`file:x.db`, `file:///C:/x.db`, a plain path), query string removed.
fn local_path(url: &str) -> PathBuf {
    let path = url.split('?').next().unwrap_or_default();
    if let Some(rest) = path.strip_prefix("file://") {
        // `file:///C:/x.db` and `file:///srv/x.db` are URLs: the path follows the (empty) host.
        let rest = rest.strip_prefix("localhost").unwrap_or(rest);
        let windows_drive =
            rest.len() > 2 && rest.as_bytes()[0] == b'/' && rest.as_bytes()[2] == b':';
        return PathBuf::from(if windows_drive { &rest[1..] } else { rest });
    }
    PathBuf::from(path.strip_prefix("file:").unwrap_or(path))
}

fn canonical_path(path: &Path) -> String {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
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

fn mutex_for(url: &str) -> Arc<DatabaseMutex> {
    if memory(url) {
        return DatabaseMutex::new();
    }
    let canonical = if url.starts_with("file:") || !has_scheme(url) {
        format!("file:{}", canonical_path(&local_path(url)))
    } else {
        url.to_owned()
    };
    static MUTEXES: OnceLock<Mutex<HashMap<String, Arc<DatabaseMutex>>>> = OnceLock::new();
    let mut mutexes = MUTEXES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    mutexes
        .entry(canonical)
        .or_insert_with(DatabaseMutex::new)
        .clone()
}

// --- errors --------------------------------------------------------------------------------------

/// SQLite result code names, as the libSQL client reports them in `extendedCode`.
fn code_name(extended: i32) -> &'static str {
    match extended {
        261 => "SQLITE_BUSY_RECOVERY",
        517 => "SQLITE_BUSY_SNAPSHOT",
        773 => "SQLITE_BUSY_TIMEOUT",
        262 => "SQLITE_LOCKED_SHAREDCACHE",
        1555 => "SQLITE_CONSTRAINT_PRIMARYKEY",
        2067 => "SQLITE_CONSTRAINT_UNIQUE",
        1299 => "SQLITE_CONSTRAINT_NOTNULL",
        275 => "SQLITE_CONSTRAINT_CHECK",
        787 => "SQLITE_CONSTRAINT_FOREIGNKEY",
        code => match code & 0xff {
            5 => "SQLITE_BUSY",
            6 => "SQLITE_LOCKED",
            8 => "SQLITE_READONLY",
            10 => "SQLITE_IOERR",
            11 => "SQLITE_CORRUPT",
            13 => "SQLITE_FULL",
            14 => "SQLITE_CANTOPEN",
            19 => "SQLITE_CONSTRAINT",
            26 => "SQLITE_NOTADB",
            _ => "SQLITE_ERROR",
        },
    }
}

/// The code a remote error names in its message (Hrana errors carry the SQLite code as text).
fn code_in_message(message: &str) -> Option<&'static str> {
    const KNOWN: [&str; 8] = [
        "SQLITE_CONSTRAINT_PRIMARYKEY",
        "SQLITE_CONSTRAINT_UNIQUE",
        "SQLITE_BUSY_SNAPSHOT",
        "SQLITE_BUSY",
        "SQLITE_LOCKED",
        "SQLITE_CONSTRAINT",
        "SQLITE_READONLY",
        "SQLITE_ERROR",
    ];
    KNOWN.into_iter().find(|code| message.contains(code))
}

/// `mapError`: the extended code when there is one.
fn local_error(error: rusqlite::Error) -> DriverError {
    match error {
        rusqlite::Error::SqliteFailure(failure, message) => DriverError::database(
            code_name(failure.extended_code),
            message.unwrap_or_else(|| failure.to_string()),
        ),
        other => DriverError::database("SQLITE_ERROR", other.to_string()),
    }
}

fn remote_error(error: libsql::Error) -> DriverError {
    match &error {
        libsql::Error::SqliteFailure(code, message) => {
            DriverError::database(code_name(*code), message.clone())
        }
        other => {
            let message = other.to_string();
            let code = code_in_message(&message).unwrap_or("");
            DriverError::database(code, message)
        }
    }
}

fn closed_error() -> IamError {
    IamError::with_status("STORE_CLOSED", "Database adapter is closed", 500)
}

// --- sessions: where statements run ----------------------------------------------------------------

type LocalConnection = Arc<Mutex<Option<rusqlite::Connection>>>;
type RemoteTransaction = Arc<tokio::sync::Mutex<Option<libsql::Transaction>>>;

/// One place statements run: the local connection, the remote connection, or a remote transaction.
#[derive(Clone)]
enum Session {
    Local(LocalConnection),
    Remote(Arc<RemoteClient>),
    RemoteTransaction(RemoteTransaction),
}

fn local_values(values: &[SqlValue]) -> Vec<SqliteValue> {
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

fn remote_values(values: &[SqlValue]) -> Vec<libsql::Value> {
    values
        .iter()
        .map(|value| match value {
            SqlValue::Null => libsql::Value::Null,
            SqlValue::Integer(value) => libsql::Value::Integer(*value),
            SqlValue::Real(value) => libsql::Value::Real(*value),
            SqlValue::Text(value) => libsql::Value::Text(value.clone()),
        })
        .collect()
}

fn local_json(value: ValueRef<'_>) -> Value {
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(value) => js::number(value as f64).unwrap_or(Value::Null),
        ValueRef::Real(value) => js::number(value).unwrap_or(Value::Null),
        ValueRef::Text(text) => Value::String(String::from_utf8_lossy(text).into_owned()),
        ValueRef::Blob(bytes) => {
            Value::Array(bytes.iter().map(|byte| Value::from(*byte)).collect())
        }
    }
}

fn remote_json(value: libsql::Value) -> Value {
    match value {
        libsql::Value::Null => Value::Null,
        libsql::Value::Integer(value) => js::number(value as f64).unwrap_or(Value::Null),
        libsql::Value::Real(value) => js::number(value).unwrap_or(Value::Null),
        libsql::Value::Text(text) => Value::String(text),
        libsql::Value::Blob(bytes) => Value::Array(bytes.into_iter().map(Value::from).collect()),
    }
}

async fn remote_rows(mut rows: libsql::Rows) -> Result<Vec<SqlRow>, DriverError> {
    let names: Vec<String> = (0..rows.column_count())
        .map(|index| rows.column_name(index).unwrap_or_default().to_owned())
        .collect();
    let mut out = Vec::new();
    while let Some(row) = rows.next().await.map_err(remote_error)? {
        let mut map = Map::new();
        for (index, name) in names.iter().enumerate() {
            map.insert(
                name.clone(),
                remote_json(row.get_value(index as i32).map_err(remote_error)?),
            );
        }
        out.push(map);
    }
    Ok(out)
}

impl Session {
    /// Rows keyed by column name (`plainRows`).
    async fn rows(&self, text: &str, values: &[SqlValue]) -> Result<Vec<SqlRow>, DriverError> {
        match self {
            Session::Local(connection) => {
                let (connection, text, values) =
                    (connection.clone(), text.to_owned(), local_values(values));
                tokio::task::spawn_blocking(move || {
                    let guard = connection
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let Some(connection) = guard.as_ref() else {
                        return Err(DriverError::Iam(closed_error()));
                    };
                    let mut statement = connection.prepare(&text).map_err(local_error)?;
                    let names: Vec<String> = statement
                        .column_names()
                        .into_iter()
                        .map(str::to_owned)
                        .collect();
                    let mut rows = statement
                        .query(rusqlite::params_from_iter(values))
                        .map_err(local_error)?;
                    let mut out = Vec::new();
                    while let Some(row) = rows.next().map_err(local_error)? {
                        let mut map = Map::new();
                        for (index, name) in names.iter().enumerate() {
                            map.insert(
                                name.clone(),
                                local_json(row.get_ref(index).map_err(local_error)?),
                            );
                        }
                        out.push(map);
                    }
                    Ok(out)
                })
                .await
                .map_err(|error| DriverError::database("SQLITE_ERROR", error.to_string()))?
            }
            Session::Remote(client) => {
                let connection = client.connection().await?;
                remote_rows(
                    connection
                        .query(text, remote_values(values))
                        .await
                        .map_err(remote_error)?,
                )
                .await
            }
            Session::RemoteTransaction(transaction) => {
                let guard = transaction.lock().await;
                let Some(transaction) = guard.as_ref() else {
                    return Err(DriverError::Iam(IamError::with_status(
                        "TRANSACTION_CLOSED",
                        "Transaction has already completed",
                        500,
                    )));
                };
                remote_rows(
                    transaction
                        .query(text, remote_values(values))
                        .await
                        .map_err(remote_error)?,
                )
                .await
            }
        }
    }

    /// Rows changed by a statement (`rowsAffected`).
    async fn execute(&self, text: &str, values: &[SqlValue]) -> Result<u64, DriverError> {
        match self {
            Session::Local(connection) => {
                let (connection, text, values) =
                    (connection.clone(), text.to_owned(), local_values(values));
                tokio::task::spawn_blocking(move || {
                    let guard = connection
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let Some(connection) = guard.as_ref() else {
                        return Err(DriverError::Iam(closed_error()));
                    };
                    let mut statement = connection.prepare_cached(&text).map_err(local_error)?;
                    statement
                        .execute(rusqlite::params_from_iter(values))
                        .map(|changed| changed as u64)
                        .map_err(local_error)
                })
                .await
                .map_err(|error| DriverError::database("SQLITE_ERROR", error.to_string()))?
            }
            Session::Remote(client) => {
                let connection = client.connection().await?;
                connection
                    .execute(text, remote_values(values))
                    .await
                    .map_err(remote_error)
            }
            Session::RemoteTransaction(transaction) => {
                let guard = transaction.lock().await;
                let Some(transaction) = guard.as_ref() else {
                    return Err(DriverError::Iam(IamError::with_status(
                        "TRANSACTION_CLOSED",
                        "Transaction has already completed",
                        500,
                    )));
                };
                transaction
                    .execute(text, remote_values(values))
                    .await
                    .map_err(remote_error)
            }
        }
    }

    async fn storage_rows(
        &self,
        text: &str,
        values: &[SqlValue],
    ) -> Result<Vec<StorageRow>, DriverError> {
        let text_of = |value: Option<&Value>| match value {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Null) | None => "null".to_owned(),
            Some(other) => js::stringify(other),
        };
        Ok(self
            .rows(text, values)
            .await?
            .iter()
            .map(|row| StorageRow {
                collection: text_of(row.get("collection")),
                id: text_of(row.get("id")),
                tenant_id: text_of(row.get("tenant_id")),
                unique_key: match row.get("unique_key") {
                    None | Some(Value::Null) => None,
                    other => Some(text_of(other)),
                },
                data: text_of(row.get("data")),
            })
            .collect())
    }
}

/// A remote database, connected on first use (`createClient` connects lazily too).
struct RemoteClient {
    url: String,
    auth_token: String,
    connection: tokio::sync::OnceCell<(libsql::Database, libsql::Connection)>,
    closed: AtomicBool,
}

impl RemoteClient {
    async fn connection(&self) -> Result<libsql::Connection, DriverError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(DriverError::Iam(closed_error()));
        }
        let (_, connection) = self
            .connection
            .get_or_try_init(|| async {
                let database =
                    libsql::Builder::new_remote(self.url.clone(), self.auth_token.clone())
                        .build()
                        .await
                        .map_err(remote_error)?;
                let connection = database.connect().map_err(remote_error)?;
                Ok::<_, DriverError>((database, connection))
            })
            .await?;
        Ok(connection.clone())
    }
}

/// The record driver of one session (`driverFor`).
struct Driver {
    session: Session,
}

#[async_trait::async_trait]
impl RecordDriver for Driver {
    async fn select(
        &self,
        collection: &str,
        id: Option<&str>,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StorageRow>, DriverError> {
        let mut sql = "SELECT collection, id, tenant_id, unique_key, data FROM iam_records WHERE collection = ?".to_owned();
        let mut args = vec![SqlValue::from(collection)];
        if let Some(id) = id {
            sql.push_str(" AND id = ?");
            args.push(SqlValue::from(id));
        }
        if let Some(tenant_id) = tenant_id {
            sql.push_str(" AND tenant_id = ?");
            args.push(SqlValue::from(tenant_id));
        }
        self.session
            .storage_rows(&format!("{sql} ORDER BY id ASC"), &args)
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
        self.session
            .storage_rows(&statement.text, &statement.values)
            .await
    }

    fn has_collections(&self) -> bool {
        true
    }

    async fn collections(&self) -> Result<Vec<String>, DriverError> {
        let rows = self.session.rows(COLLECTIONS_SQL, &[]).await?;
        Ok(rows
            .iter()
            .map(|row| match row.get("collection") {
                Some(Value::String(name)) => name.clone(),
                Some(other) => js::stringify(other),
                None => "undefined".to_owned(),
            })
            .collect())
    }

    async fn insert(&self, row: &StorageRow) -> Result<(), DriverError> {
        let args = vec![
            SqlValue::from(row.collection.as_str()),
            SqlValue::from(row.id.as_str()),
            SqlValue::from(row.tenant_id.as_str()),
            row.unique_key
                .clone()
                .map(SqlValue::Text)
                .unwrap_or(SqlValue::Null),
            SqlValue::from(row.data.as_str()),
        ];
        self.session
            .execute("INSERT INTO iam_records (collection, id, tenant_id, unique_key, data) VALUES (?, ?, ?, ?, ?)", &args)
            .await
            .map(|_| ())
    }

    async fn update(&self, row: &StorageRow) -> Result<bool, DriverError> {
        let args = vec![
            SqlValue::from(row.data.as_str()),
            row.unique_key
                .clone()
                .map(SqlValue::Text)
                .unwrap_or(SqlValue::Null),
            SqlValue::from(row.collection.as_str()),
            SqlValue::from(row.id.as_str()),
            SqlValue::from(row.tenant_id.as_str()),
        ];
        let changed = self
            .session
            .execute("UPDATE iam_records SET data = ?, unique_key = ? WHERE collection = ? AND id = ? AND tenant_id = ?", &args)
            .await?;
        Ok(changed == 1)
    }

    async fn delete(&self, collection: &str, id: &str) -> Result<(), DriverError> {
        self.session
            .execute(
                "DELETE FROM iam_records WHERE collection = ? AND id = ?",
                &[SqlValue::from(collection), SqlValue::from(id)],
            )
            .await
            .map(|_| ())
    }
}

/// A session as a [`SqlExecutor`].
struct Executor {
    session: Session,
}

#[async_trait::async_trait]
impl SqlExecutor for Executor {
    async fn execute(&self, text: &str, values: &[SqlValue]) -> Result<Vec<SqlRow>, DriverError> {
        self.session.rows(text, values).await
    }
}

// --- the store -----------------------------------------------------------------------------------

struct TransactionContext {
    active: AtomicBool,
    rollback_only: AtomicBool,
    session: Session,
}

/// Where the database lives (`location`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Location {
    Memory,
    File,
    Remote,
}

impl Location {
    fn as_str(self) -> &'static str {
        match self {
            Location::Memory => "memory",
            Location::File => "file",
            Location::Remote => "remote",
        }
    }
}

struct Shared {
    root: Session,
    mutex: Arc<DatabaseMutex>,
    scope: usize,
    location: Location,
}

/// A libSQL store (`LibsqlStore`): the root store, or a transaction handle when `context` is set.
pub struct LibsqlStore {
    shared: Arc<Shared>,
    context: Option<Arc<TransactionContext>>,
    closed: AtomicBool,
}

impl LibsqlStore {
    fn handle(&self, context: Arc<TransactionContext>) -> Arc<dyn IamStore> {
        Arc::new(LibsqlStore {
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

    /// Opens the write transaction: `BEGIN IMMEDIATE` locally, a write transaction remotely.
    async fn begin(&self) -> Result<Session, DriverError> {
        match &self.shared.root {
            Session::Local(_) => {
                self.shared.root.execute("BEGIN IMMEDIATE", &[]).await?;
                Ok(self.shared.root.clone())
            }
            Session::Remote(client) => {
                let connection = client.connection().await?;
                let transaction = connection
                    .transaction_with_behavior(libsql::TransactionBehavior::Immediate)
                    .await
                    .map_err(remote_error)?;
                Ok(Session::RemoteTransaction(Arc::new(
                    tokio::sync::Mutex::new(Some(transaction)),
                )))
            }
            Session::RemoteTransaction(_) => Err(DriverError::Iam(IamError::with_status(
                "INTERNAL_ERROR",
                "Nested root transaction",
                500,
            ))),
        }
    }

    async fn finish(&self, session: &Session, commit: bool) -> Result<(), DriverError> {
        match session {
            Session::Local(_) => session
                .execute(if commit { "COMMIT" } else { "ROLLBACK" }, &[])
                .await
                .map(|_| ()),
            Session::RemoteTransaction(transaction) => {
                let Some(transaction) = transaction.lock().await.take() else {
                    return Ok(());
                };
                if commit {
                    transaction.commit().await
                } else {
                    transaction.rollback().await
                }
                .map_err(remote_error)
            }
            Session::Remote(_) => Ok(()),
        }
    }

    async fn describe_on(&self, session: Session) -> IamResult<StoreDescription> {
        let executor = Executor { session };
        // Remote servers may refuse PRAGMA statements; the queries below still surface outages.
        let journal_mode = match executor.execute("PRAGMA journal_mode", &[]).await {
            Ok(rows) => match rows.first().and_then(|row| row.values().next().cloned()) {
                Some(Value::String(mode)) => Value::String(mode),
                Some(other) => Value::String(js::stringify(&other)),
                None => Value::Null,
            },
            Err(_) => Value::Null,
        };
        let mut settings = Map::new();
        settings.insert(
            "location".into(),
            Value::String(self.shared.location.as_str().into()),
        );
        settings.insert(
            "inMemory".into(),
            Value::Bool(self.shared.location == Location::Memory),
        );
        settings.insert("journalMode".into(), journal_mode);
        describe_records(&executor, "libsql", settings)
            .await
            .map_err(storage_error)
    }
}

#[async_trait::async_trait]
impl RecordAccess for LibsqlStore {
    async fn read(&self, operation: DriverOperation) -> IamResult<OperationValue> {
        if let Some(context) = self.active()? {
            return operation(Arc::new(Driver {
                session: context.session.clone(),
            }))
            .await
            .map_err(|error| {
                context.rollback_only.store(true, Ordering::SeqCst);
                storage_error(error)
            });
        }
        // Root reads wait for the current transaction: an in-memory database has a single connection.
        self.shared
            .mutex
            .run(async {
                self.active()?;
                operation(Arc::new(Driver {
                    session: self.shared.root.clone(),
                }))
                .await
                .map_err(storage_error)
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
impl IamStore for LibsqlStore {
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
        if let Some(context) = self.active()? {
            return self.describe_on(context.session.clone()).await;
        }
        self.shared
            .mutex
            .run(async {
                self.active()?;
                self.describe_on(self.shared.root.clone()).await
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
                // A write transaction starts with BEGIN IMMEDIATE, so the writer lock is held before any read.
                let session = self.begin().await.map_err(storage_error)?;
                let context = Arc::new(TransactionContext {
                    active: AtomicBool::new(true),
                    rollback_only: AtomicBool::new(false),
                    session: session.clone(),
                });
                let outcome = task_scope::run(
                    self.shared.scope,
                    context.clone(),
                    run(self.handle(context.clone())),
                )
                .await;
                let outcome = match outcome {
                    Ok(_) if context.rollback_only.load(Ordering::SeqCst) => {
                        Err(IamError::with_status(
                            "TRANSACTION_ABORTED",
                            "A nested database operation failed; transaction rolled back",
                            409,
                        ))
                    }
                    Ok(value) => self
                        .finish(&session, true)
                        .await
                        .map(|()| value)
                        .map_err(storage_error),
                    Err(error) => Err(error),
                };
                if outcome.is_err() {
                    // Preserve the original failure.
                    let _ = self.finish(&session, false).await;
                }
                context.active.store(false, Ordering::SeqCst);
                outcome
            })
            .await
    }

    async fn migrate(&self) -> IamResult<()> {
        let scope = self.shared.scope;
        let run: TransactionFn<'_> = Box::new(move |_tx| {
            Box::pin(async move {
                let context =
                    task_scope::current::<TransactionContext>(scope).ok_or_else(|| {
                        IamError::with_status("INTERNAL_ERROR", "No migration transaction", 500)
                    })?;
                let executor = Executor {
                    session: context.session.clone(),
                };
                apply_migrations(&executor, SqlDialect::Sqlite, MigrationOptions::default())
                    .await
                    .map_err(storage_error)?;
                Ok(Box::new(()) as TransactionValue)
            })
        });
        self.transaction_dyn(run).await.map(|_| ())
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
                    match &self.shared.root {
                        Session::Local(connection) => {
                            let connection = connection.clone();
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
                        Session::Remote(client) => client.closed.store(true, Ordering::SeqCst),
                        Session::RemoteTransaction(_) => {}
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

/// Opens a libSQL store (`libsqlAdapter`): local files and remote Turso or sqld databases.
pub fn libsql_adapter(options: LibsqlAdapterOptions) -> IamResult<Arc<dyn IamStore>> {
    libsql_store(options).map(|store| store as Arc<dyn IamStore>)
}

/// [`libsql_adapter`] returning the concrete store.
pub fn libsql_store(options: LibsqlAdapterOptions) -> IamResult<Arc<LibsqlStore>> {
    if options.url.is_empty() {
        return Err(invalid_config(
            "libSQL requires a url: :memory:, file:, libsql:, https:, or wss:",
        ));
    }
    let supported = ["file:", "libsql:", "http:", "https:", "ws:", "wss:"]
        .iter()
        .any(|prefix| options.url.starts_with(prefix));
    if !memory(&options.url) && !supported && has_scheme(&options.url) {
        return Err(invalid_config("Unsupported libSQL URL scheme"));
    }
    let timeout = options.busy_timeout_ms.unwrap_or(5000);
    if !(0..=60_000).contains(&timeout) {
        return Err(invalid_config("busyTimeoutMs must be between 0 and 60000"));
    }
    if options.sync_url.is_some() {
        return Err(IamError::not_implemented(
            "libSQL embedded replicas (syncUrl) need the libSQL core, which the Rust adapter does not link",
        ));
    }
    if options.encryption_key.is_some() {
        return Err(IamError::not_implemented(
            "Encrypted libSQL files (encryptionKey) need the libSQL core, which the Rust adapter does not link",
        ));
    }
    let url = if memory(&options.url) || has_scheme(&options.url) {
        options.url.clone()
    } else {
        format!("file:{}", options.url)
    };
    let location = if memory(&url) {
        Location::Memory
    } else if url.starts_with("file:") {
        Location::File
    } else {
        Location::Remote
    };
    let root = match location {
        Location::Remote => {
            // The Rust client speaks Hrana over HTTP; WebSocket URLs name the same server.
            let http = if let Some(rest) = url.strip_prefix("wss://") {
                format!("https://{rest}")
            } else if let Some(rest) = url.strip_prefix("ws://") {
                format!("http://{rest}")
            } else {
                url.clone()
            };
            Session::Remote(Arc::new(RemoteClient {
                url: http,
                auth_token: options.auth_token.clone().unwrap_or_default(),
                connection: tokio::sync::OnceCell::new(),
                closed: AtomicBool::new(false),
            }))
        }
        Location::Memory | Location::File => {
            let open = || -> Result<rusqlite::Connection, rusqlite::Error> {
                let connection = if location == Location::Memory {
                    rusqlite::Connection::open_in_memory()?
                } else {
                    rusqlite::Connection::open(local_path(&url))?
                };
                connection.busy_timeout(Duration::from_millis(timeout as u64))?;
                connection.set_prepared_statement_cache_capacity(256);
                Ok(connection)
            };
            let connection = open().map_err(|error| storage_error(local_error(error)))?;
            Session::Local(Arc::new(Mutex::new(Some(connection))))
        }
    };
    Ok(Arc::new(LibsqlStore {
        shared: Arc::new(Shared {
            root,
            mutex: mutex_for(&url),
            scope: task_scope::new_key(),
            location,
        }),
        context: None,
        closed: AtomicBool::new(false),
    }))
}
