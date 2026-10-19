//! PostgreSQL storage for Better IAM (`@better-iam/adapter-postgres`): the same schema, migrations, SQL, jsonb value
//! encoding and advisory-lock transactions as the TypeScript adapter, so TypeScript and Rust servers can share one
//! database.
//!
//! Transactions serialize through a database advisory lock, including other adapter instances.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use better_iam_core::sql::{
    COLLECTIONS_SQL, EncodeLegacyPostgresRows, MigrationOptions, SqlDialect, SqlExecutor, SqlRow,
    SqlValue, apply_migrations, decode_jsonb_document, describe_records, encode_jsonb_document,
    is_missing_table, postgres_select,
};
use better_iam_core::storage::{
    DriverError, DriverOperation, OperationValue, QueryCapabilities, RecordAccess, RecordDriver,
    RecordQuery, StorageRow, record_store, storage_error,
};
use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, IamStore, OrderOptions, Record, StoreDescription,
    TransactionFn, TransactionValue, js, task_scope,
};
use bytes::{BufMut, BytesMut};
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod, Runtime};
use serde_json::{Map, Value};
use tokio_postgres::Row;
use tokio_postgres::types::{IsNull, ToSql, Type, to_sql_checked};

/// How long a migration waits for other instances' transactions, including another migration.
const MIGRATION_LOCK_TIMEOUT_MS: i64 = 10 * 60_000;

/// `PostgresAdapterOptions`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PostgresAdapterOptions {
    /// `postgres://` or `postgresql://` URL.
    pub connection_string: String,
    /// Connections in the pool (default 10, 1 to 100).
    pub pool_size: Option<i64>,
    /// How long a transaction waits for the advisory lock, and a caller for a pooled connection (default 5000, 1 to
    /// 60000).
    pub lock_timeout_ms: Option<i64>,
}

impl PostgresAdapterOptions {
    pub fn new(connection_string: impl Into<String>) -> Self {
        Self {
            connection_string: connection_string.into(),
            ..Self::default()
        }
    }
}

// --- parameters and rows -------------------------------------------------------------------------

/// A parameter bound like node-postgres binds JavaScript values: the server infers the type and the value is
/// written in that type's format.
#[derive(Debug)]
struct Param(SqlValue);

type BoxError = Box<dyn std::error::Error + Sync + Send>;

impl ToSql for Param {
    fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, BoxError> {
        let text = |value: &str, out: &mut BytesMut| {
            if *ty == Type::JSONB {
                out.put_u8(1);
            }
            out.extend_from_slice(value.as_bytes());
        };
        match &self.0 {
            SqlValue::Null => return Ok(IsNull::Yes),
            SqlValue::Text(value) => match *ty {
                Type::INT8 => value.parse::<i64>()?.to_sql(ty, out)?,
                Type::INT4 => value.parse::<i32>()?.to_sql(ty, out)?,
                Type::FLOAT8 => value.parse::<f64>()?.to_sql(ty, out)?,
                _ => {
                    text(value, out);
                    IsNull::No
                }
            },
            SqlValue::Integer(value) => match *ty {
                Type::INT8 => value.to_sql(ty, out)?,
                Type::INT4 => i32::try_from(*value)?.to_sql(ty, out)?,
                Type::INT2 => i16::try_from(*value)?.to_sql(ty, out)?,
                Type::FLOAT8 => (*value as f64).to_sql(ty, out)?,
                Type::FLOAT4 => (*value as f32).to_sql(ty, out)?,
                _ => {
                    text(&value.to_string(), out);
                    IsNull::No
                }
            },
            SqlValue::Real(value) => match *ty {
                Type::FLOAT8 => value.to_sql(ty, out)?,
                Type::FLOAT4 => (*value as f32).to_sql(ty, out)?,
                _ => {
                    text(&js::number_to_string(*value), out);
                    IsNull::No
                }
            },
        };
        Ok(IsNull::No)
    }

    fn accepts(_: &Type) -> bool {
        true
    }

    to_sql_checked!();
}

fn params(values: &[SqlValue]) -> Vec<Param> {
    values.iter().cloned().map(Param).collect()
}

fn refs(params: &[Param]) -> Vec<&(dyn ToSql + Sync)> {
    params
        .iter()
        .map(|param| param as &(dyn ToSql + Sync))
        .collect()
}

fn pg_error(error: tokio_postgres::Error) -> DriverError {
    let message = error
        .as_db_error()
        .map(|db| db.message().to_owned())
        .unwrap_or_else(|| error.to_string());
    DriverError::database(
        error
            .code()
            .map(|state| state.code().to_owned())
            .unwrap_or_default(),
        message,
    )
}

fn pool_error(error: deadpool_postgres::PoolError) -> DriverError {
    match error {
        deadpool_postgres::PoolError::Backend(error) => pg_error(error),
        deadpool_postgres::PoolError::Closed => DriverError::Iam(closed_error()),
        other => DriverError::database("", other.to_string()),
    }
}

fn closed_error() -> IamError {
    IamError::with_status("STORE_CLOSED", "Database adapter is closed", 500)
}

fn json_column(row: &Row, index: usize) -> Value {
    let column = &row.columns()[index];
    let number = |value: Option<f64>| value.and_then(js::number).unwrap_or(Value::Null);
    match *column.type_() {
        Type::INT8 => number(
            row.try_get::<_, Option<i64>>(index)
                .ok()
                .flatten()
                .map(|value| value as f64),
        ),
        Type::INT4 => number(
            row.try_get::<_, Option<i32>>(index)
                .ok()
                .flatten()
                .map(f64::from),
        ),
        Type::INT2 => number(
            row.try_get::<_, Option<i16>>(index)
                .ok()
                .flatten()
                .map(f64::from),
        ),
        Type::FLOAT8 => number(row.try_get::<_, Option<f64>>(index).ok().flatten()),
        Type::FLOAT4 => number(
            row.try_get::<_, Option<f32>>(index)
                .ok()
                .flatten()
                .map(f64::from),
        ),
        Type::BOOL => row
            .try_get::<_, Option<bool>>(index)
            .ok()
            .flatten()
            .map(Value::Bool)
            .unwrap_or(Value::Null),
        _ => row
            .try_get::<_, Option<String>>(index)
            .ok()
            .flatten()
            .map(Value::String)
            .unwrap_or(Value::Null),
    }
}

fn plain_rows(rows: &[Row]) -> Vec<SqlRow> {
    rows.iter()
        .map(|row| {
            let mut map = Map::new();
            for (index, column) in row.columns().iter().enumerate() {
                map.insert(column.name().to_owned(), json_column(row, index));
            }
            map
        })
        .collect()
}

/// Documents are stored jsonb-compatible (`encodeJsonbDocument`) and decoded on every read (`loaded`).
fn loaded(rows: Vec<Row>) -> Result<Vec<StorageRow>, DriverError> {
    rows.iter()
        .map(|row| {
            let get = |name: &str| row.try_get::<_, String>(name).map_err(pg_error);
            Ok(StorageRow {
                collection: get("collection")?,
                id: get("id")?,
                tenant_id: get("tenant_id")?,
                unique_key: row
                    .try_get::<_, Option<String>>("unique_key")
                    .map_err(pg_error)?,
                data: decode_jsonb_document(&get("data")?)?,
            })
        })
        .collect()
}

// --- connections ---------------------------------------------------------------------------------

/// Where a statement runs: a pooled connection per statement (outside transactions) or the transaction's own.
#[derive(Clone)]
enum Connection {
    Pool(Pool),
    Client(Arc<Object>),
}

impl Connection {
    async fn client(&self) -> Result<ClientRef, DriverError> {
        match self {
            Connection::Pool(pool) => Ok(ClientRef::Owned(Box::new(
                pool.get().await.map_err(pool_error)?,
            ))),
            Connection::Client(client) => Ok(ClientRef::Shared(client.clone())),
        }
    }

    async fn query(&self, text: &str, values: &[SqlValue]) -> Result<Vec<Row>, DriverError> {
        let client = self.client().await?;
        let params = params(values);
        client
            .object()
            .query(text, &refs(&params))
            .await
            .map_err(pg_error)
    }

    async fn execute(&self, text: &str, values: &[SqlValue]) -> Result<u64, DriverError> {
        let client = self.client().await?;
        let params = params(values);
        client
            .object()
            .execute(text, &refs(&params))
            .await
            .map_err(pg_error)
    }
}

enum ClientRef {
    Owned(Box<Object>),
    Shared(Arc<Object>),
}

impl ClientRef {
    fn object(&self) -> &Object {
        match self {
            ClientRef::Owned(object) => object,
            ClientRef::Shared(object) => object,
        }
    }
}

/// The record driver of one connection (`driverFor`).
struct Driver {
    connection: Connection,
}

const SELECT: &str = "SELECT collection, id, tenant_id, unique_key, data FROM iam_records";

#[async_trait::async_trait]
impl RecordDriver for Driver {
    async fn select(
        &self,
        collection: &str,
        id: Option<&str>,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StorageRow>, DriverError> {
        let mut text = format!("{SELECT} WHERE collection = $1");
        let mut values = vec![SqlValue::from(collection)];
        if let Some(id) = id {
            values.push(SqlValue::from(id));
            text.push_str(&format!(" AND id = ${}", values.len()));
        }
        if let Some(tenant_id) = tenant_id {
            values.push(SqlValue::from(tenant_id));
            text.push_str(&format!(" AND tenant_id = ${}", values.len()));
        }
        text.push_str(" ORDER BY id ASC");
        loaded(self.connection.query(&text, &values).await?)
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
            SqlValue::Text(encode_jsonb_document(&row.data)?),
        ];
        self.connection
            .execute("INSERT INTO iam_records (collection, id, tenant_id, unique_key, data) VALUES ($1, $2, $3, $4, $5)", &values)
            .await
            .map(|_| ())
    }

    async fn update(&self, row: &StorageRow) -> Result<bool, DriverError> {
        let values = vec![
            SqlValue::Text(encode_jsonb_document(&row.data)?),
            row.unique_key
                .clone()
                .map(SqlValue::Text)
                .unwrap_or(SqlValue::Null),
            SqlValue::from(row.collection.as_str()),
            SqlValue::from(row.id.as_str()),
            SqlValue::from(row.tenant_id.as_str()),
        ];
        let changed = self
            .connection
            .execute("UPDATE iam_records SET data = $1, unique_key = $2 WHERE collection = $3 AND id = $4 AND tenant_id = $5", &values)
            .await?;
        Ok(changed == 1)
    }

    async fn delete(&self, collection: &str, id: &str) -> Result<(), DriverError> {
        self.connection
            .execute(
                "DELETE FROM iam_records WHERE collection = $1 AND id = $2",
                &[SqlValue::from(collection), SqlValue::from(id)],
            )
            .await
            .map(|_| ())
    }

    fn has_query(&self) -> bool {
        true
    }

    fn query_capabilities(&self) -> QueryCapabilities {
        QueryCapabilities {
            json: true,
            order: true,
        }
    }

    async fn query(&self, query: &RecordQuery) -> Result<Vec<StorageRow>, DriverError> {
        let statement = postgres_select(query)?;
        loaded(
            self.connection
                .query(&statement.text, &statement.values)
                .await?,
        )
    }

    fn has_collections(&self) -> bool {
        true
    }

    async fn collections(&self) -> Result<Vec<String>, DriverError> {
        let rows = plain_rows(&self.connection.query(COLLECTIONS_SQL, &[]).await?);
        Ok(rows
            .iter()
            .map(|row| {
                row.get("collection")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect())
    }
}

/// A connection as a [`SqlExecutor`] (`executor`).
struct Executor {
    connection: Connection,
}

#[async_trait::async_trait]
impl SqlExecutor for Executor {
    async fn execute(&self, text: &str, values: &[SqlValue]) -> Result<Vec<SqlRow>, DriverError> {
        Ok(plain_rows(&self.connection.query(text, values).await?))
    }
}

// --- the store -----------------------------------------------------------------------------------

struct TransactionContext {
    active: AtomicBool,
    rollback_only: AtomicBool,
    client: Mutex<Option<Arc<Object>>>,
}

impl TransactionContext {
    fn connection(&self) -> Result<Connection, DriverError> {
        self.client
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .map(Connection::Client)
            .ok_or_else(|| {
                DriverError::Iam(IamError::with_status(
                    "TRANSACTION_CLOSED",
                    "Transaction has already completed",
                    500,
                ))
            })
    }
}

struct Shared {
    pool: Pool,
    /// The `AsyncLocalStorage` of this adapter instance.
    scope: usize,
    timeout: i64,
}

/// A PostgreSQL store (`PostgresStore`): the root store, or a transaction handle when `context` is set.
pub struct PostgresStore {
    shared: Arc<Shared>,
    context: Option<Arc<TransactionContext>>,
    closed: AtomicBool,
}

impl PostgresStore {
    fn handle(&self, context: Arc<TransactionContext>) -> Arc<dyn IamStore> {
        Arc::new(PostgresStore {
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

    async fn serialized(
        &self,
        run: TransactionFn<'_>,
        lock_timeout_ms: i64,
    ) -> IamResult<TransactionValue> {
        if let Some(current) = self.active()? {
            return run(self.handle(current.clone())).await.inspect_err(|_| {
                current.rollback_only.store(true, Ordering::SeqCst);
            });
        }
        let client = Arc::new(
            self.shared
                .pool
                .get()
                .await
                .map_err(|error| storage_error(pool_error(error)))?,
        );
        let connection = Connection::Client(client.clone());
        connection
            .execute("start transaction isolation level read committed", &[])
            .await
            .map_err(storage_error)?;
        let prepare = async {
            // All application transactions take the same database advisory lock before reading. READ COMMITTED
            // deliberately takes its data snapshot AFTER this wait.
            connection
                .query(
                    "SELECT set_config('lock_timeout', $1, true)",
                    &[SqlValue::Text(format!("{lock_timeout_ms}ms"))],
                )
                .await?;
            connection
                .query("SELECT pg_advisory_xact_lock(1647206759, 1)", &[])
                .await
        };
        if let Err(error) = prepare.await {
            let _ = connection.execute("rollback", &[]).await;
            return Err(storage_error(error));
        }
        let context = Arc::new(TransactionContext {
            active: AtomicBool::new(true),
            rollback_only: AtomicBool::new(false),
            client: Mutex::new(Some(client.clone())),
        });
        let outcome = task_scope::run(
            self.shared.scope,
            context.clone(),
            run(self.handle(context.clone())),
        )
        .await;
        let outcome = match outcome {
            Ok(_) if context.rollback_only.load(Ordering::SeqCst) => Err(IamError::with_status(
                "TRANSACTION_ABORTED",
                "A nested database operation failed; transaction rolled back",
                409,
            )),
            other => other,
        };
        context.active.store(false, Ordering::SeqCst);
        context
            .client
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        match outcome {
            Ok(value) => {
                if let Err(error) = connection.execute("commit", &[]).await {
                    let _ = connection.execute("rollback", &[]).await;
                    return Err(storage_error(error));
                }
                Ok(value)
            }
            Err(error) => {
                if connection.execute("rollback", &[]).await.is_err() {
                    // A connection that cannot roll back must not return to the pool.
                    drop(connection);
                    if let Ok(object) = Arc::try_unwrap(client) {
                        let _ = Object::take(object);
                    }
                }
                Err(error)
            }
        }
    }
}

#[async_trait::async_trait]
impl RecordAccess for PostgresStore {
    async fn read(&self, operation: DriverOperation) -> IamResult<OperationValue> {
        let context = self.active()?;
        let connection = match &context {
            Some(context) => context.connection().map_err(storage_error)?,
            None => Connection::Pool(self.shared.pool.clone()),
        };
        operation(Arc::new(Driver { connection }))
            .await
            .map_err(|error| {
                if let Some(context) = &context {
                    context.rollback_only.store(true, Ordering::SeqCst);
                }
                storage_error(error)
            })
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
impl IamStore for PostgresStore {
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

    /// Always runs on the pool, never on a caller's transaction: a probe of a table that does not exist yet would
    /// abort that transaction. Inside a transaction it therefore reports committed data and needs a free connection.
    async fn describe(&self) -> IamResult<StoreDescription> {
        self.active()?;
        let executor = Executor {
            connection: Connection::Pool(self.shared.pool.clone()),
        };
        let single = |text: &'static str| {
            let executor = &executor;
            async move {
                match executor.execute(text, &[]).await {
                    Ok(rows) => Ok(rows
                        .first()
                        .and_then(|row| row.values().next().cloned())
                        .filter(|value| !value.is_null())),
                    Err(error) if is_missing_table(&error) => Ok(None),
                    Err(error) => Err(error),
                }
            }
        };
        let run = async {
            let size = single("SELECT pg_total_relation_size('iam_records') AS size").await?;
            let version = single("SHOW server_version").await?;
            let synchronous_commit = single("SHOW synchronous_commit").await?;
            let text = |value: Option<Value>| match value {
                None => Value::Null,
                Some(Value::String(text)) => Value::String(text),
                Some(other) => Value::String(js::stringify(&other)),
            };
            let mut settings = Map::new();
            settings.insert("serverVersion".into(), text(version));
            settings.insert("synchronousCommit".into(), text(synchronous_commit));
            settings.insert(
                "sizeBytes".into(),
                size.map(|size| js::number(js::to_number(&size)).unwrap_or(Value::Null))
                    .unwrap_or(Value::Null),
            );
            settings.insert("lockTimeoutMs".into(), Value::from(self.shared.timeout));
            describe_records(&executor, "postgres", settings).await
        };
        run.await.map_err(storage_error)
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
        self.serialized(run, self.shared.timeout).await
    }

    async fn migrate(&self) -> IamResult<()> {
        // Index builds on a large table can take minutes; other instances migrating at the same time wait for the
        // lock instead of failing with STORAGE_BUSY.
        let scope = self.shared.scope;
        let migrate: TransactionFn<'_> = Box::new(move |_tx| {
            Box::pin(async move {
                let context =
                    task_scope::current::<TransactionContext>(scope).ok_or_else(|| {
                        IamError::with_status("INTERNAL_ERROR", "No migration transaction", 500)
                    })?;
                let executor = Executor {
                    connection: context.connection().map_err(storage_error)?,
                };
                let hook = EncodeLegacyPostgresRows;
                let options = MigrationOptions {
                    now: None,
                    before: Some(&hook),
                };
                apply_migrations(&executor, SqlDialect::Postgres, options)
                    .await
                    .map_err(storage_error)?;
                Ok(Box::new(()) as TransactionValue)
            })
        });
        self.serialized(migrate, MIGRATION_LOCK_TIMEOUT_MS)
            .await
            .map(|_| ())
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
        self.closed.store(true, Ordering::SeqCst);
        self.shared.pool.close();
        Ok(())
    }
}

fn invalid_config(message: &str) -> IamError {
    IamError::new("INVALID_CONFIG", message)
}

fn tls() -> tokio_postgres_rustls::MakeRustlsConnect {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("rustls protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    tokio_postgres_rustls::MakeRustlsConnect::new(config)
}

/// Opens a PostgreSQL store (`postgresAdapter`). Transactions serialize through a database advisory lock, including
/// other adapter instances. No connection is made until the first operation.
pub fn postgres_adapter(options: PostgresAdapterOptions) -> IamResult<Arc<dyn IamStore>> {
    postgres_store(options).map(|store| store as Arc<dyn IamStore>)
}

/// [`postgres_adapter`] returning the concrete store.
pub fn postgres_store(options: PostgresAdapterOptions) -> IamResult<Arc<PostgresStore>> {
    let url = options.connection_string.as_str();
    if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
        return Err(invalid_config("A PostgreSQL connection string is required"));
    }
    let timeout = options.lock_timeout_ms.unwrap_or(5000);
    let max = options.pool_size.unwrap_or(10);
    if !(1..=60_000).contains(&timeout) || !(1..=100).contains(&max) {
        return Err(invalid_config(
            "Invalid PostgreSQL pool size or lock timeout",
        ));
    }
    let mut config: tokio_postgres::Config = url
        .parse()
        .map_err(|_| invalid_config("A PostgreSQL connection string is required"))?;
    // node-postgres connects without TLS unless the connection string asks for it.
    if !url.contains("sslmode=") {
        config.ssl_mode(tokio_postgres::config::SslMode::Disable);
    }
    config.connect_timeout(Duration::from_millis(timeout as u64));
    let manager = Manager::from_config(
        config,
        tls(),
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );
    let pool = Pool::builder(manager)
        .max_size(max as usize)
        .wait_timeout(Some(Duration::from_millis(timeout as u64)))
        .create_timeout(Some(Duration::from_millis(timeout as u64)))
        .runtime(Runtime::Tokio1)
        .build()
        .map_err(|_| invalid_config("Invalid PostgreSQL pool size or lock timeout"))?;
    Ok(Arc::new(PostgresStore {
        shared: Arc::new(Shared {
            pool,
            scope: task_scope::new_key(),
            timeout,
        }),
        context: None,
        closed: AtomicBool::new(false),
    }))
}
