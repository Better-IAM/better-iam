//! SQL shared by the reference adapters (`sql.ts`). Everything here is plain string building: adapters pass the
//! text and values to their own driver. Field names are validated against `QUERYABLE_FIELD` before they appear in
//! SQL; every value is a bound parameter.
//!
//! The schema steps are the exact statements of `spec/storage/migrations/<dialect>/`, embedded from the copies in
//! this crate's `migrations/` directory (a test keeps them identical to the spec).

use serde_json::{Map, Value};

use crate::js;
use crate::storage::{
    DriverError, FieldCondition, JSONB_ESCAPE_KEY, RecordQuery, SchemaMigration, queryable_field,
    storable_string,
};
use crate::{Direction, IamError, IamResult, StoreDescription};

/// A bound SQL parameter.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
}

impl SqlValue {
    /// The parameter as JSON (vectors, logs).
    pub fn to_json(&self) -> Value {
        match self {
            SqlValue::Null => Value::Null,
            SqlValue::Integer(value) => Value::from(*value),
            SqlValue::Real(value) => js::number(*value).unwrap_or(Value::Null),
            SqlValue::Text(value) => Value::String(value.clone()),
        }
    }

    /// A JavaScript number as a parameter: integral values as integers.
    pub fn number(value: f64) -> Self {
        if js::is_safe_integer(value) {
            SqlValue::Integer(value as i64)
        } else {
            SqlValue::Real(value)
        }
    }
}

impl From<&str> for SqlValue {
    fn from(value: &str) -> Self {
        SqlValue::Text(value.to_owned())
    }
}

impl From<String> for SqlValue {
    fn from(value: String) -> Self {
        SqlValue::Text(value)
    }
}

impl From<i64> for SqlValue {
    fn from(value: i64) -> Self {
        SqlValue::Integer(value)
    }
}

/// A statement and its parameters (`SqlStatement`).
#[derive(Debug, Clone, PartialEq)]
pub struct SqlStatement {
    pub text: String,
    pub values: Vec<SqlValue>,
}

/// `SqlDialect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlDialect {
    Sqlite,
    Postgres,
}

/// A row of a query result, keyed by column name.
pub type SqlRow = Map<String, Value>;

/// Runs one statement on the adapter's connection (`SqlExecutor`).
#[async_trait::async_trait]
pub trait SqlExecutor: Send + Sync {
    async fn execute(&self, text: &str, values: &[SqlValue]) -> Result<Vec<SqlRow>, DriverError>;
}

const COLUMNS: &str = "collection, id, tenant_id, unique_key, data";

fn field(name: &str) -> IamResult<&str> {
    if !queryable_field(name) {
        return Err(IamError::new(
            "INVALID_FILTER",
            "Field names in SQL conditions must be identifiers",
        ));
    }
    Ok(name)
}

fn direction(direction: Direction) -> &'static str {
    match direction {
        Direction::Desc => "DESC",
        Direction::Asc => "ASC",
    }
}

/// SQLite path literal. Identical text in the query and the index lets the planner use the index.
fn sqlite_path(name: &str) -> String {
    format!("'$.\"{name}\"'")
}

/// SELECT for SQLite and libSQL (JSON1) (`sqliteSelect`). `json` conditions are not supported.
pub fn sqlite_select(query: &RecordQuery) -> IamResult<SqlStatement> {
    let mut clauses = vec!["collection = ?".to_owned()];
    let mut values = vec![SqlValue::Text(query.collection.clone())];
    for (column, value) in [
        ("id", &query.id),
        ("tenant_id", &query.tenant_id),
        ("unique_key", &query.unique_key),
    ] {
        if let Some(value) = value {
            clauses.push(format!("{column} = ?"));
            values.push(SqlValue::Text(value.clone()));
        }
    }
    // BINARY collation compares UTF-8 bytes, which is code-point order (`compareIds`).
    if let Some(after) = &query.after {
        clauses.push("id > ?".to_owned());
        values.push(SqlValue::Text(after.clone()));
    }
    for condition in &query.conditions {
        let path = sqlite_path(field(condition.field())?);
        let kind = format!("json_type(data, {path})");
        let value = format!("json_extract(data, {path})");
        match condition {
            FieldCondition::String { value: text, .. } => {
                clauses.push(format!("{kind} = 'text' AND {value} = ?"));
                values.push(SqlValue::Text(text.clone()));
            }
            FieldCondition::Number { value: number, .. } => {
                // Compare the literal's text, not a parsed double: every stored number and every bound value is
                // JSON.stringify output of a double.
                clauses.push(format!(
                    "{kind} IN ('integer', 'real') AND (data -> {path}) = ?"
                ));
                values.push(SqlValue::Text(js::number_to_string(*number)));
            }
            FieldCondition::Boolean { value: flag, .. } => {
                clauses.push(format!(
                    "{kind} = '{}'",
                    if *flag { "true" } else { "false" }
                ));
            }
            FieldCondition::Null { .. } => clauses.push(format!("{kind} = 'null'")),
            FieldCondition::Absent { .. } => clauses.push(format!("{kind} IS NULL")),
            FieldCondition::Json { .. } => {
                return Err(IamError::new(
                    "INVALID_FILTER",
                    "SQLite adapters do not evaluate JSON conditions",
                ));
            }
        }
    }
    let mut order_by = "id".to_owned();
    if let Some(order) = &query.order {
        let path = sqlite_path(field(&order.field)?);
        let value = format!("json_extract(data, {path})");
        // `IS NOT NULL` repeats the partial index predicate so the ordered indexes qualify.
        clauses.push(format!(
            "{value} IS NOT NULL AND json_type(data, {path}) IN ('integer', 'real')"
        ));
        // Bounds are parsed from JSON text like stored values, so large integers compare consistently.
        for (operator, bound) in [(">=", order.from), ("<=", order.to)] {
            if let Some(bound) = bound {
                clauses.push(format!("{value} {operator} json_extract(?, '$')"));
                values.push(SqlValue::Text(js::number_to_string(bound)));
            }
        }
        order_by = format!("{value} {}, id", direction(order.direction));
    }
    let mut text = format!(
        "SELECT {COLUMNS} FROM iam_records WHERE {} ORDER BY {order_by}",
        clauses.join(" AND ")
    );
    if let Some(page) = &query.page {
        text.push_str(" LIMIT ? OFFSET ?");
        values.push(SqlValue::Integer(page.limit.unwrap_or(-1)));
        values.push(SqlValue::Integer(page.offset));
    }
    Ok(SqlStatement { text, values })
}

/// SELECT for PostgreSQL (`postgresSelect`). Scalar tests share one jsonb containment test, served by a GIN index.
pub fn postgres_select(query: &RecordQuery) -> IamResult<SqlStatement> {
    let mut values: Vec<SqlValue> = Vec::new();
    let mut bind = |value: SqlValue| {
        values.push(value);
        format!("${}", values.len())
    };
    let mut clauses = vec![format!(
        "collection = {}",
        bind(SqlValue::Text(query.collection.clone()))
    )];
    if let Some(id) = &query.id {
        clauses.push(format!("id = {}", bind(SqlValue::Text(id.clone()))));
    }
    if let Some(tenant_id) = &query.tenant_id {
        clauses.push(format!(
            "tenant_id = {}",
            bind(SqlValue::Text(tenant_id.clone()))
        ));
    }
    if let Some(unique_key) = &query.unique_key {
        clauses.push(format!(
            "unique_key = {}",
            bind(SqlValue::Text(unique_key.clone()))
        ));
    }
    // The id column uses the "C" collation: byte order, which is code-point order.
    if let Some(after) = &query.after {
        clauses.push(format!("id > {}", bind(SqlValue::Text(after.clone()))));
    }
    let mut contains = Map::new();
    for condition in &query.conditions {
        let name = field(condition.field())?;
        let member = format!(
            "((data::jsonb) -> {}::text)",
            bind(SqlValue::Text(name.to_owned()))
        );
        let typed = |contains: &mut Map<String, Value>, value: Value, kind: &str| {
            // Containment finds candidates through the index; the type test makes it exact equality.
            contains.insert(name.to_owned(), value);
            format!("jsonb_typeof{member} = '{kind}'")
        };
        match condition {
            FieldCondition::String { value, .. } => {
                clauses.push(typed(&mut contains, Value::String(value.clone()), "string"))
            }
            FieldCondition::Number { value, .. } => clauses.push(typed(
                &mut contains,
                js::number(*value).unwrap_or(Value::Null),
                "number",
            )),
            FieldCondition::Boolean { value, .. } => {
                clauses.push(typed(&mut contains, Value::Bool(*value), "boolean"))
            }
            FieldCondition::Null { .. } => clauses.push(typed(&mut contains, Value::Null, "null")),
            FieldCondition::Absent { .. } => clauses.push(format!("{member} IS NULL")),
            FieldCondition::Json { value, .. } => {
                clauses.push(format!(
                    "{member} = {}::jsonb",
                    bind(SqlValue::Text(value.clone()))
                ));
            }
        }
    }
    if !contains.is_empty() {
        let document = js::stringify_object(&contains);
        clauses.push(format!(
            "(data::jsonb) @> {}::jsonb",
            bind(SqlValue::Text(document))
        ));
    }
    let mut order_by = "id".to_owned();
    if let Some(order) = &query.order {
        // The validated field name is inlined so the expression matches the ordered indexes.
        let member = format!("((data::jsonb) -> '{}')", field(&order.field)?);
        clauses.push(format!("jsonb_typeof{member} = 'number'"));
        if let Some(from) = order.from {
            clauses.push(format!(
                "{member} >= {}::jsonb",
                bind(SqlValue::Text(js::number_to_string(from)))
            ));
        }
        if let Some(to) = order.to {
            clauses.push(format!(
                "{member} <= {}::jsonb",
                bind(SqlValue::Text(js::number_to_string(to)))
            ));
        }
        order_by = format!("{member} {}, id", direction(order.direction));
    }
    let mut text = format!(
        "SELECT {COLUMNS} FROM iam_records WHERE {} ORDER BY {order_by}",
        clauses.join(" AND ")
    );
    if let Some(page) = &query.page {
        let limit = match page.limit {
            None => "ALL".to_owned(),
            Some(limit) => bind(SqlValue::Integer(limit)),
        };
        let offset = bind(SqlValue::Integer(page.offset));
        text.push_str(&format!(" LIMIT {limit} OFFSET {offset}"));
    }
    Ok(SqlStatement { text, values })
}

/// The embedded migration files of a dialect: (name, file text).
fn migration_files(dialect: SqlDialect) -> [(&'static str, &'static str); 6] {
    match dialect {
        SqlDialect::Sqlite => [
            (
                "0001_records",
                include_str!("../migrations/sqlite/0001_records.sql"),
            ),
            (
                "0002_query_indexes",
                include_str!("../migrations/sqlite/0002_query_indexes.sql"),
            ),
            (
                "0003_ordered_indexes",
                include_str!("../migrations/sqlite/0003_ordered_indexes.sql"),
            ),
            (
                "0004_expiry_indexes",
                include_str!("../migrations/sqlite/0004_expiry_indexes.sql"),
            ),
            (
                "0005_lookup_indexes",
                include_str!("../migrations/sqlite/0005_lookup_indexes.sql"),
            ),
            (
                "0006_protection_indexes",
                include_str!("../migrations/sqlite/0006_protection_indexes.sql"),
            ),
        ],
        SqlDialect::Postgres => [
            (
                "0001_records",
                include_str!("../migrations/postgres/0001_records.sql"),
            ),
            (
                "0002_query_indexes",
                include_str!("../migrations/postgres/0002_query_indexes.sql"),
            ),
            (
                "0003_ordered_indexes",
                include_str!("../migrations/postgres/0003_ordered_indexes.sql"),
            ),
            (
                "0004_expiry_indexes",
                include_str!("../migrations/postgres/0004_expiry_indexes.sql"),
            ),
            (
                "0005_lookup_indexes",
                include_str!("../migrations/postgres/0005_lookup_indexes.sql"),
            ),
            (
                "0006_protection_indexes",
                include_str!("../migrations/postgres/0006_protection_indexes.sql"),
            ),
        ],
    }
}

/// The embedded migration file text of one step (`migrations/<dialect>/<name>.sql`).
pub fn migration_file(dialect: SqlDialect, name: &str) -> Option<&'static str> {
    migration_files(dialect)
        .into_iter()
        .find(|(step, _)| *step == name)
        .map(|(_, text)| text)
}

/// Ordered, append-only schema steps (`schemaMigrations`). Never edit a released step; add a new one.
///
/// Secondary indexes end in `id` so one index both finds rows and yields them in `ORDER BY id` order.
pub fn schema_migrations(dialect: SqlDialect) -> Vec<SchemaMigration> {
    migration_files(dialect)
        .into_iter()
        .map(|(name, text)| SchemaMigration {
            name: name.to_owned(),
            statements: text
                .lines()
                .map(str::trim_end)
                .filter(|line| !line.is_empty())
                .map(|line| line.strip_suffix(';').unwrap_or(line).to_owned())
                .collect(),
        })
        .collect()
}

/// A hook run before a migration's statements, in the same transaction (`MigrationOptions.before`).
#[async_trait::async_trait]
pub trait MigrationHook: Send + Sync {
    async fn before(&self, name: &str, execute: &dyn SqlExecutor) -> Result<(), DriverError>;
}

/// `MigrationOptions`.
#[derive(Default)]
pub struct MigrationOptions<'a> {
    /// The migration clock in epoch milliseconds (default: now).
    pub now: Option<f64>,
    /// Runs before a migration's statements, in the same transaction (for data rewrites).
    pub before: Option<&'a dyn MigrationHook>,
}

/// Creates the schema and applies missing named migrations, recording each in `iam_migrations`
/// (`applyMigrations`). Run it inside the adapter's serialized write transaction. Returns the names applied now.
pub async fn apply_migrations(
    execute: &dyn SqlExecutor,
    dialect: SqlDialect,
    options: MigrationOptions<'_>,
) -> Result<Vec<String>, DriverError> {
    let now = options.now.unwrap_or_else(js::now_ms);
    execute
        .execute(
            "CREATE TABLE IF NOT EXISTS iam_schema_version (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL)",
            &[],
        )
        .await?;
    let version = execute
        .execute("SELECT version FROM iam_schema_version WHERE id = 1", &[])
        .await?;
    if let Some(row) = version.first()
        && number_of(row.get("version")) != 1.0
    {
        return Err(IamError::with_status(
            "SCHEMA_VERSION",
            "Unsupported database schema version",
            500,
        )
        .into());
    }
    execute
        .execute("CREATE TABLE IF NOT EXISTS iam_migrations (name TEXT PRIMARY KEY, applied_at BIGINT NOT NULL)", &[])
        .await?;
    let applied: std::collections::HashSet<String> = execute
        .execute("SELECT name FROM iam_migrations", &[])
        .await?
        .iter()
        .map(|row| string_of(row.get("name")))
        .collect();
    let insert = match dialect {
        SqlDialect::Postgres => "INSERT INTO iam_migrations (name, applied_at) VALUES ($1, $2)",
        SqlDialect::Sqlite => "INSERT INTO iam_migrations (name, applied_at) VALUES (?, ?)",
    };
    let mut ran = Vec::new();
    for migration in schema_migrations(dialect) {
        if applied.contains(&migration.name) {
            continue;
        }
        if let Some(hook) = options.before {
            hook.before(&migration.name, execute).await?;
        }
        for statement in &migration.statements {
            execute.execute(statement, &[]).await?;
        }
        execute
            .execute(
                insert,
                &[
                    SqlValue::Text(migration.name.clone()),
                    SqlValue::number(now),
                ],
            )
            .await?;
        ran.push(migration.name);
    }
    execute
        .execute("INSERT INTO iam_schema_version (id, version) VALUES (1, 1) ON CONFLICT (id) DO NOTHING", &[])
        .await?;
    Ok(ran)
}

/// `Number(value)` of a result column.
fn number_of(value: Option<&Value>) -> f64 {
    match value {
        Some(Value::Number(number)) => js::number_value(number),
        Some(Value::String(text)) => text.trim().parse().unwrap_or(f64::NAN),
        Some(Value::Bool(flag)) => f64::from(u8::from(*flag)),
        Some(Value::Null) => 0.0,
        _ => f64::NAN,
    }
}

/// `String(value)` of a result column.
fn string_of(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => js::number_to_string(js::number_value(number)),
        Some(Value::Bool(flag)) => flag.to_string(),
        Some(Value::Null) => "null".to_owned(),
        None => "undefined".to_owned(),
        Some(other) => js::stringify(other),
    }
}

/// A query failed because a table does not exist (PostgreSQL 42P01, SQLite "no such table") (`isMissingTable`).
pub fn is_missing_table(error: &DriverError) -> bool {
    match error {
        DriverError::Database { code, message } => {
            code == "42P01" || message.to_lowercase().contains("no such table")
        }
        DriverError::Iam(error) => {
            error.code == "42P01" || error.message.to_lowercase().contains("no such table")
        }
    }
}

/// Distinct collection names in the records table.
pub const COLLECTIONS_SQL: &str = "SELECT DISTINCT collection FROM iam_records ORDER BY collection";

/// The adapter-independent part of `IamStore::describe` (`describeRecords`): schema version, applied migrations,
/// and record counts per collection. Missing tables read as empty; any other failure is returned.
pub async fn describe_records(
    execute: &dyn SqlExecutor,
    adapter: &str,
    settings: Map<String, Value>,
) -> Result<StoreDescription, DriverError> {
    let attempt = |text: &'static str| async move {
        match execute.execute(text, &[]).await {
            Ok(rows) => Ok(rows),
            Err(error) if is_missing_table(&error) => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    };
    let version = attempt("SELECT version FROM iam_schema_version WHERE id = 1").await?;
    let migrations = attempt("SELECT name, applied_at FROM iam_migrations ORDER BY name")
        .await?
        .iter()
        .map(|row| crate::MigrationRecord {
            name: string_of(row.get("name")),
            applied_at: number_of(row.get("applied_at")),
        })
        .collect();
    let collections =
        attempt("SELECT collection, COUNT(*) AS records FROM iam_records GROUP BY collection ORDER BY collection")
            .await?
            .iter()
            .map(|row| crate::CollectionCount {
                name: string_of(row.get("collection")),
                records: number_of(row.get("records")),
            })
            .collect();
    Ok(StoreDescription {
        adapter: adapter.to_owned(),
        schema_version: version.first().map(|row| number_of(row.get("version"))),
        migrations,
        collections,
        settings,
    })
}

// --- PostgreSQL value encoding -------------------------------------------------------------------
//
// PostgreSQL's jsonb rejects U+0000 and unpaired surrogates, and the PostgreSQL adapter indexes `data::jsonb`.
// Record values may still hold such strings, so that adapter stores them encoded: a string becomes
// `{ [JSONB_ESCAPE_KEY]: "<UTF-16 code units as hex>" }`, and an object's keys that are unstorable (or equal to the
// escape key itself) move into `[JSONB_ESCAPE_KEY]: [[hex key, value], ...]`. The transform works on JSON text with
// UTF-16 strings, so documents the TypeScript adapter wrote (unpaired surrogates included) convert byte for byte.

/// A JSON value with UTF-16 strings, as JavaScript holds it.
#[derive(Debug, Clone)]
enum Json16 {
    Null,
    Bool(bool),
    Number(f64),
    String(Vec<u16>),
    Array(Vec<Json16>),
    Object(Vec<(Vec<u16>, Json16)>),
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn whitespace(&mut self) {
        while self.at < self.bytes.len()
            && matches!(self.bytes[self.at], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.at += 1;
        }
    }

    fn value(&mut self) -> Option<Json16> {
        self.whitespace();
        match *self.bytes.get(self.at)? {
            b'n' => self.literal(b"null", Json16::Null),
            b't' => self.literal(b"true", Json16::Bool(true)),
            b'f' => self.literal(b"false", Json16::Bool(false)),
            b'"' => self.string().map(Json16::String),
            b'[' => {
                self.at += 1;
                let mut items = Vec::new();
                self.whitespace();
                if self.bytes.get(self.at) == Some(&b']') {
                    self.at += 1;
                    return Some(Json16::Array(items));
                }
                loop {
                    items.push(self.value()?);
                    self.whitespace();
                    match self.bytes.get(self.at)? {
                        b',' => self.at += 1,
                        b']' => {
                            self.at += 1;
                            return Some(Json16::Array(items));
                        }
                        _ => return None,
                    }
                }
            }
            b'{' => {
                self.at += 1;
                let mut members: Vec<(Vec<u16>, Json16)> = Vec::new();
                self.whitespace();
                if self.bytes.get(self.at) == Some(&b'}') {
                    self.at += 1;
                    return Some(Json16::Object(members));
                }
                loop {
                    self.whitespace();
                    if self.bytes.get(self.at) != Some(&b'"') {
                        return None;
                    }
                    let key = self.string()?;
                    self.whitespace();
                    if self.bytes.get(self.at) != Some(&b':') {
                        return None;
                    }
                    self.at += 1;
                    let value = self.value()?;
                    // JSON.parse: a repeated key keeps its first position and takes the last value.
                    match members.iter_mut().find(|(existing, _)| *existing == key) {
                        Some(member) => member.1 = value,
                        None => members.push((key, value)),
                    }
                    self.whitespace();
                    match self.bytes.get(self.at)? {
                        b',' => self.at += 1,
                        b'}' => {
                            self.at += 1;
                            return Some(Json16::Object(members));
                        }
                        _ => return None,
                    }
                }
            }
            _ => self.number(),
        }
    }

    fn literal(&mut self, text: &[u8], value: Json16) -> Option<Json16> {
        if self.bytes[self.at..].starts_with(text) {
            self.at += text.len();
            Some(value)
        } else {
            None
        }
    }

    fn number(&mut self) -> Option<Json16> {
        let start = self.at;
        if self.bytes.get(self.at) == Some(&b'-') {
            self.at += 1;
        }
        let digits = |parser: &mut Self| {
            let begin = parser.at;
            while parser.at < parser.bytes.len() && parser.bytes[parser.at].is_ascii_digit() {
                parser.at += 1;
            }
            parser.at > begin
        };
        if self.bytes.get(self.at) == Some(&b'0') {
            self.at += 1;
        } else if !digits(self) {
            return None;
        }
        if self.bytes.get(self.at) == Some(&b'.') {
            self.at += 1;
            if !digits(self) {
                return None;
            }
        }
        if matches!(self.bytes.get(self.at), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.bytes.get(self.at), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if !digits(self) {
                return None;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at]).ok()?;
        text.parse::<f64>().ok().map(Json16::Number)
    }

    fn string(&mut self) -> Option<Vec<u16>> {
        self.at += 1;
        let mut out = Vec::new();
        loop {
            let byte = *self.bytes.get(self.at)?;
            match byte {
                b'"' => {
                    self.at += 1;
                    return Some(out);
                }
                b'\\' => {
                    let escape = *self.bytes.get(self.at + 1)?;
                    self.at += 2;
                    match escape {
                        b'"' => out.push(0x22),
                        b'\\' => out.push(0x5C),
                        b'/' => out.push(0x2F),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0C),
                        b'n' => out.push(0x0A),
                        b'r' => out.push(0x0D),
                        b't' => out.push(0x09),
                        b'u' => {
                            let hex =
                                std::str::from_utf8(self.bytes.get(self.at..self.at + 4)?).ok()?;
                            out.push(u16::from_str_radix(hex, 16).ok()?);
                            self.at += 4;
                        }
                        _ => return None,
                    }
                }
                byte if byte < 0x20 => return None,
                _ => {
                    // One UTF-8 character (the parser only stops on ASCII bytes, so this is a char boundary).
                    let c = self.text.get(self.at..)?.chars().next()?;
                    let mut units = [0u16; 2];
                    out.extend_from_slice(c.encode_utf16(&mut units));
                    self.at += c.len_utf8();
                }
            }
        }
    }
}

fn parse16(text: &str) -> Option<Json16> {
    let mut parser = Parser {
        text,
        bytes: text.as_bytes(),
        at: 0,
    };
    let value = parser.value()?;
    parser.whitespace();
    (parser.at == parser.bytes.len()).then_some(value)
}

fn quote16(units: &[u16], out: &mut String) {
    out.push('"');
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        match unit {
            0x22 => out.push_str("\\\""),
            0x5C => out.push_str("\\\\"),
            0x08 => out.push_str("\\b"),
            0x0C => out.push_str("\\f"),
            0x0A => out.push_str("\\n"),
            0x0D => out.push_str("\\r"),
            0x09 => out.push_str("\\t"),
            unit if unit < 0x20 => out.push_str(&format!("\\u{unit:04x}")),
            0xD800..=0xDBFF
                if units
                    .get(index + 1)
                    .is_some_and(|next| (0xDC00..=0xDFFF).contains(next)) =>
            {
                let c = char::decode_utf16([unit, units[index + 1]])
                    .next()
                    .and_then(Result::ok)
                    .unwrap_or('\u{fffd}');
                out.push(c);
                index += 1;
            }
            0xD800..=0xDFFF => out.push_str(&format!("\\u{unit:04x}")),
            unit => out.push(char::from_u32(u32::from(unit)).unwrap_or('\u{fffd}')),
        }
        index += 1;
    }
    out.push('"');
}

fn key_text(key: &[u16]) -> String {
    String::from_utf16_lossy(key)
}

fn stringify16(value: &Json16, out: &mut String) {
    match value {
        Json16::Null => out.push_str("null"),
        Json16::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Json16::Number(number) => {
            if number.is_finite() {
                out.push_str(&js::number_to_string(*number))
            } else {
                out.push_str("null")
            }
        }
        Json16::String(units) => quote16(units, out),
        Json16::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                stringify16(item, out);
            }
            out.push(']');
        }
        Json16::Object(members) => {
            out.push('{');
            for (index, (key, item)) in ordered16(members).into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                quote16(key, out);
                out.push(':');
                stringify16(item, out);
            }
            out.push('}');
        }
    }
}

/// Members in JavaScript property order.
fn ordered16(members: &[(Vec<u16>, Json16)]) -> Vec<&(Vec<u16>, Json16)> {
    let mut indexes: Vec<(u64, &(Vec<u16>, Json16))> = Vec::new();
    let mut rest = Vec::new();
    for member in members {
        let text = key_text(&member.0);
        if js::is_array_index(&text) {
            indexes.push((text.parse().unwrap_or(0), member));
        } else {
            rest.push(member);
        }
    }
    indexes.sort_by_key(|(index, _)| *index);
    indexes
        .into_iter()
        .map(|(_, member)| member)
        .chain(rest)
        .collect()
}

fn storable16(units: &[u16]) -> bool {
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        if unit == 0 {
            return false;
        }
        if (0xD800..=0xDBFF).contains(&unit) {
            if !units
                .get(index + 1)
                .is_some_and(|next| (0xDC00..=0xDFFF).contains(next))
            {
                return false;
            }
            index += 1;
        } else if (0xDC00..=0xDFFF).contains(&unit) {
            return false;
        }
        index += 1;
    }
    true
}

fn hex16(units: &[u16]) -> Vec<u16> {
    units
        .iter()
        .flat_map(|unit| format!("{unit:04x}").encode_utf16().collect::<Vec<_>>())
        .collect()
}

fn from_hex16(value: &Json16) -> IamResult<Vec<u16>> {
    let invalid = || IamError::with_status("STORAGE_CORRUPT", "Invalid escaped value", 500);
    let Json16::String(units) = value else {
        return Err(invalid());
    };
    if units.len() % 4 != 0
        || !units
            .iter()
            .all(|unit| matches!(*unit, 0x30..=0x39 | 0x61..=0x66))
    {
        return Err(invalid());
    }
    units
        .chunks(4)
        .map(|chunk| {
            u16::from_str_radix(&String::from_utf16_lossy(chunk), 16).map_err(|_| invalid())
        })
        .collect()
}

fn escape_key16() -> Vec<u16> {
    JSONB_ESCAPE_KEY.encode_utf16().collect()
}

fn encode16(value: &Json16) -> Json16 {
    match value {
        Json16::String(units) => {
            if storable16(units) {
                value.clone()
            } else {
                Json16::Object(vec![(escape_key16(), Json16::String(hex16(units)))])
            }
        }
        Json16::Array(items) => Json16::Array(items.iter().map(encode16).collect()),
        Json16::Object(members) => {
            let escape = escape_key16();
            let mut out: Vec<(Vec<u16>, Json16)> = Vec::new();
            let mut escaped = Vec::new();
            for (key, item) in ordered16(members) {
                if *key == escape || !storable16(key) {
                    escaped.push(Json16::Array(vec![
                        Json16::String(hex16(key)),
                        encode16(item),
                    ]));
                } else {
                    out.push((key.clone(), encode16(item)));
                }
            }
            if !escaped.is_empty() {
                out.push((escape, Json16::Array(escaped)));
            }
            Json16::Object(out)
        }
        _ => value.clone(),
    }
}

fn decode16(value: &Json16) -> IamResult<Json16> {
    match value {
        Json16::Array(items) => Ok(Json16::Array(
            items.iter().map(decode16).collect::<IamResult<_>>()?,
        )),
        Json16::Object(members) => {
            let escape = escape_key16();
            let marker = members
                .iter()
                .find(|(key, _)| *key == escape)
                .map(|(_, item)| item);
            if let Some(marker @ Json16::String(_)) = marker
                && members.len() == 1
            {
                return Ok(Json16::String(from_hex16(marker)?));
            }
            let mut out: Vec<(Vec<u16>, Json16)> = Vec::new();
            let assign = |out: &mut Vec<(Vec<u16>, Json16)>, key: Vec<u16>, item: Json16| match out
                .iter_mut()
                .find(|(existing, _)| *existing == key)
            {
                Some(member) => member.1 = item,
                None => out.push((key, item)),
            };
            for (key, item) in ordered16(members) {
                if *key != escape {
                    assign(&mut out, key.clone(), decode16(item)?);
                }
            }
            if let Some(marker) = marker {
                let invalid =
                    || IamError::with_status("STORAGE_CORRUPT", "Invalid escaped keys", 500);
                let Json16::Array(pairs) = marker else {
                    return Err(invalid());
                };
                for pair in pairs {
                    let Json16::Array(pair) = pair else {
                        return Err(invalid());
                    };
                    if pair.len() != 2 {
                        return Err(invalid());
                    }
                    assign(&mut out, from_hex16(&pair[0])?, decode16(&pair[1])?);
                }
            }
            Ok(Json16::Object(out))
        }
        _ => Ok(value.clone()),
    }
}

fn escaped_json(data: &str) -> bool {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    PATTERN
        .get_or_init(|| {
            regex::Regex::new(r"(?i)\\u0000|\\ud[89a-f][0-9a-f]{2}|\\u0001better-iam")
                .expect("valid pattern")
        })
        .is_match(data)
}

fn reencode(data: &str, transform: impl Fn(&Json16) -> IamResult<Json16>) -> IamResult<String> {
    // JSON.parse throws on invalid text; the adapter maps that to STORAGE_ERROR like any driver failure.
    let parsed = parse16(data)
        .ok_or_else(|| IamError::with_status("STORAGE_ERROR", "Database operation failed", 500))?;
    let mut out = String::with_capacity(data.len());
    stringify16(&transform(&parsed)?, &mut out);
    Ok(out)
}

/// Record JSON as the PostgreSQL adapter stores it: valid jsonb, reversible by [`decode_jsonb_document`]
/// (`encodeJsonbDocument`).
pub fn encode_jsonb_document(data: &str) -> IamResult<String> {
    // Only JSON text containing one of the escapes can need a rewrite (false positives re-encode to the same
    // text); JSON.stringify never writes these characters unescaped.
    if escaped_json(data) {
        reencode(data, |value| Ok(encode16(value)))
    } else {
        Ok(data.to_owned())
    }
}

/// The original record JSON of a document written by [`encode_jsonb_document`] (`decodeJsonbDocument`).
pub fn decode_jsonb_document(data: &str) -> IamResult<String> {
    if data.contains("\\u0001better-iam") {
        reencode(data, decode16)
    } else {
        Ok(data.to_owned())
    }
}

/// The scan of [`encode_legacy_postgres_rows`].
pub const LEGACY_POSTGRES_ROWS_SQL: &str = "SELECT collection, id, data FROM iam_records WHERE strpos(data, '\\u0000') > 0 OR data ~* '\\\\ud[89a-f]'";

/// Migration hook for PostgreSQL (`encodeLegacyPostgresRows`): rewrites rows written before the value encoding
/// existed, whose text jsonb would reject, so the jsonb index of `0002_query_indexes` can be built.
pub struct EncodeLegacyPostgresRows;

#[async_trait::async_trait]
impl MigrationHook for EncodeLegacyPostgresRows {
    async fn before(&self, name: &str, execute: &dyn SqlExecutor) -> Result<(), DriverError> {
        if name != "0002_query_indexes" {
            return Ok(());
        }
        let rows = execute.execute(LEGACY_POSTGRES_ROWS_SQL, &[]).await?;
        for row in rows {
            let data = string_of(row.get("data"));
            let encoded = encode_jsonb_document(&data)?;
            if encoded != data {
                execute
                    .execute(
                        "UPDATE iam_records SET data = $1 WHERE collection = $2 AND id = $3",
                        &[
                            SqlValue::Text(encoded),
                            SqlValue::Text(string_of(row.get("collection"))),
                            SqlValue::Text(string_of(row.get("id"))),
                        ],
                    )
                    .await?;
            }
        }
        Ok(())
    }
}

/// `storableString` on JSON text members (used by tests of the encoding).
pub fn storable_json_string(value: &str) -> bool {
    storable_string(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonb_encoding_round_trips_unpaired_surrogates() {
        let data = r#"{"id":"a","tenantId":"t","name":"x\ud800"}"#;
        let encoded = encode_jsonb_document(data).unwrap();
        assert_eq!(
            encoded,
            r#"{"id":"a","tenantId":"t","name":{"\u0001better-iam":"0078d800"}}"#
        );
        assert_eq!(decode_jsonb_document(&encoded).unwrap(), data);
    }

    #[test]
    fn migrations_parse_one_statement_per_line() {
        let sqlite = schema_migrations(SqlDialect::Sqlite);
        assert_eq!(sqlite.len(), 6);
        assert_eq!(sqlite[0].statements.len(), 2);
        assert!(!sqlite[0].statements[0].ends_with(';'));
        let postgres = schema_migrations(SqlDialect::Postgres);
        assert!(postgres[4].statements.is_empty());
    }
}
