//! Low-level adapter building blocks (`storage.ts`). Applications use the [`crate::IamStore`] contract; adapters build
//! on [`RecordDriver`], [`RecordAccess`] and the shared record-store logic in [`record_store`], which keeps SQLite,
//! libSQL and PostgreSQL semantically identical to each other and to the TypeScript adapters.

use std::cmp::Ordering;
use std::future::Future;
use std::sync::Arc;

use futures::future::BoxFuture;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::js;
use crate::{FindOptions, IamError, IamResult, IamStore, OrderOptions, Record};

/// One row of the `iam_records` table (`StorageRow`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageRow {
    pub collection: String,
    pub id: String,
    pub tenant_id: String,
    pub unique_key: Option<String>,
    pub data: String,
}

/// A filter over records: strict equality against top-level JSON members (`Record<string, unknown>` in
/// TypeScript). A member set to `None` is JavaScript `undefined`: it matches records that lack the member.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Filter {
    entries: Vec<(String, Option<Value>)>,
}

impl Filter {
    /// The empty filter (every record).
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `key === value`.
    pub fn eq(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.set(key, Some(value.into()));
        self
    }

    /// Adds `key === undefined` (the member is absent).
    pub fn absent(mut self, key: impl Into<String>) -> Self {
        self.set(key, None);
        self
    }

    /// Sets a member, keeping its position when it already exists (JavaScript assignment).
    pub fn set(&mut self, key: impl Into<String>, value: Option<Value>) {
        let key = key.into();
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|(existing, _)| *existing == key)
        {
            entry.1 = value;
        } else {
            self.entries.push((key, value));
        }
    }

    /// Removes a member (`delete filter[key]`).
    pub fn remove(&mut self, key: &str) {
        self.entries.retain(|(existing, _)| existing != key);
    }

    /// The member: None when the filter has no such key, `Some(None)` when it is `undefined`.
    pub fn get(&self, key: &str) -> Option<Option<&Value>> {
        self.entries
            .iter()
            .find(|(existing, _)| existing == key)
            .map(|(_, value)| value.as_ref())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The members in JavaScript property order (`Object.entries(filter)`).
    pub fn entries(&self) -> Vec<(&str, Option<&Value>)> {
        let mut indexes: Vec<(u64, (&str, Option<&Value>))> = Vec::new();
        let mut rest = Vec::new();
        for (key, value) in &self.entries {
            if js::is_array_index(key) {
                indexes.push((key.parse().unwrap_or(0), (key.as_str(), value.as_ref())));
            } else {
                rest.push((key.as_str(), value.as_ref()));
            }
        }
        indexes.sort_by_key(|(index, _)| *index);
        indexes
            .into_iter()
            .map(|(_, entry)| entry)
            .chain(rest)
            .collect()
    }

    /// The keys in JavaScript property order (`Object.keys(filter)`).
    pub fn keys(&self) -> Vec<&str> {
        self.entries().into_iter().map(|(key, _)| key).collect()
    }

    /// The filter as a JSON object, `undefined` members left out.
    pub fn to_map(&self) -> Map<String, Value> {
        self.entries
            .iter()
            .filter_map(|(key, value)| value.as_ref().map(|value| (key.clone(), value.clone())))
            .collect()
    }
}

impl From<Map<String, Value>> for Filter {
    fn from(map: Map<String, Value>) -> Self {
        Self {
            entries: map
                .into_iter()
                .map(|(key, value)| (key, Some(value)))
                .collect(),
        }
    }
}

impl<K: Into<String>> FromIterator<(K, Option<Value>)> for Filter {
    fn from_iter<I: IntoIterator<Item = (K, Option<Value>)>>(items: I) -> Self {
        let mut filter = Filter::new();
        for (key, value) in items {
            filter.set(key, value);
        }
        filter
    }
}

/// A typed equality test on one top-level JSON field (`FieldCondition`). Each kind matches exactly the records the
/// in-memory filter would match for that field, so a driver can evaluate it in SQL.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldCondition {
    String {
        field: String,
        value: String,
    },
    Number {
        field: String,
        value: f64,
    },
    Boolean {
        field: String,
        value: bool,
    },
    /// The field is present and JSON `null`.
    Null {
        field: String,
    },
    /// The field is not present in the stored document.
    Absent {
        field: String,
    },
    /// Deep JSON equality with an object or array (object key order ignored, array order kept); `value` is the
    /// `JSON.stringify` text.
    Json {
        field: String,
        value: String,
    },
}

impl FieldCondition {
    pub fn field(&self) -> &str {
        match self {
            FieldCondition::String { field, .. }
            | FieldCondition::Number { field, .. }
            | FieldCondition::Boolean { field, .. }
            | FieldCondition::Null { field }
            | FieldCondition::Absent { field }
            | FieldCondition::Json { field, .. } => field,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            FieldCondition::String { .. } => "string",
            FieldCondition::Number { .. } => "number",
            FieldCondition::Boolean { .. } => "boolean",
            FieldCondition::Null { .. } => "null",
            FieldCondition::Absent { .. } => "absent",
            FieldCondition::Json { .. } => "json",
        }
    }

    /// The condition as the TypeScript object `{ field, kind, value? }`.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("field".into(), Value::String(self.field().to_owned()));
        map.insert("kind".into(), Value::String(self.kind().to_owned()));
        match self {
            FieldCondition::String { value, .. } | FieldCondition::Json { value, .. } => {
                map.insert("value".into(), Value::String(value.clone()));
            }
            FieldCondition::Number { value, .. } => {
                map.insert("value".into(), js::number(*value).unwrap_or(Value::Null));
            }
            FieldCondition::Boolean { value, .. } => {
                map.insert("value".into(), Value::Bool(*value));
            }
            FieldCondition::Null { .. } | FieldCondition::Absent { .. } => {}
        }
        Value::Object(map)
    }

    /// Reads the TypeScript object form.
    pub fn from_value(value: &Value) -> Option<Self> {
        let field = value.get("field")?.as_str()?.to_owned();
        Some(match value.get("kind")?.as_str()? {
            "string" => FieldCondition::String {
                field,
                value: value.get("value")?.as_str()?.to_owned(),
            },
            "number" => FieldCondition::Number {
                field,
                value: js::as_number(value.get("value")?)?,
            },
            "boolean" => FieldCondition::Boolean {
                field,
                value: value.get("value")?.as_bool()?,
            },
            "null" => FieldCondition::Null { field },
            "absent" => FieldCondition::Absent { field },
            "json" => FieldCondition::Json {
                field,
                value: value.get("value")?.as_str()?.to_owned(),
            },
            _ => return None,
        })
    }
}

/// `RecordQuery.order`: order by a numeric top-level field instead of id (ties by id, ascending), keeping only rows
/// whose field is a JSON number within `[from, to]`.
#[derive(Debug, Clone, PartialEq)]
pub struct QueryOrder {
    pub field: String,
    pub direction: crate::Direction,
    pub from: Option<f64>,
    pub to: Option<f64>,
}

/// `RecordQuery.page`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryPage {
    pub offset: i64,
    pub limit: Option<i64>,
}

/// A filtered read a driver evaluates (`RecordQuery`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RecordQuery {
    pub collection: String,
    pub id: Option<String>,
    pub tenant_id: Option<String>,
    pub unique_key: Option<String>,
    pub conditions: Vec<FieldCondition>,
    /// Only rows whose id sorts after this id in code-point order (`id > after`); never with `order`.
    pub after: Option<String>,
    pub order: Option<QueryOrder>,
    /// Present only when the query expresses the caller's complete filter. The driver then returns the requested
    /// page of rows ordered by id in code-point (UTF-8 byte) order, or by `order`.
    pub page: Option<QueryPage>,
}

impl RecordQuery {
    /// The query as the TypeScript object (member order as `planQuery` and the callers build it).
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("collection".into(), Value::String(self.collection.clone()));
        map.insert(
            "conditions".into(),
            Value::Array(
                self.conditions
                    .iter()
                    .map(FieldCondition::to_value)
                    .collect(),
            ),
        );
        for (key, value) in [
            ("id", &self.id),
            ("tenantId", &self.tenant_id),
            ("uniqueKey", &self.unique_key),
        ] {
            if let Some(value) = value {
                map.insert(key.into(), Value::String(value.clone()));
            }
        }
        if let Some(after) = &self.after {
            map.insert("after".into(), Value::String(after.clone()));
        }
        if let Some(order) = &self.order {
            let mut item = Map::new();
            item.insert("field".into(), Value::String(order.field.clone()));
            item.insert(
                "direction".into(),
                Value::String(order.direction.as_str().into()),
            );
            if let Some(from) = order.from {
                item.insert("from".into(), js::number(from).unwrap_or(Value::Null));
            }
            if let Some(to) = order.to {
                item.insert("to".into(), js::number(to).unwrap_or(Value::Null));
            }
            map.insert("order".into(), Value::Object(item));
        }
        if let Some(page) = &self.page {
            let mut item = Map::new();
            item.insert("offset".into(), Value::from(page.offset));
            if let Some(limit) = page.limit {
                item.insert("limit".into(), Value::from(limit));
            }
            map.insert("page".into(), Value::Object(item));
        }
        Value::Object(map)
    }

    /// Reads the TypeScript object form (vectors, tooling).
    pub fn from_value(value: &Value) -> Option<Self> {
        let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_owned);
        let conditions = value
            .get("conditions")?
            .as_array()?
            .iter()
            .map(FieldCondition::from_value)
            .collect::<Option<Vec<_>>>()?;
        let order = match value.get("order") {
            Some(order) => Some(QueryOrder {
                field: order.get("field")?.as_str()?.to_owned(),
                direction: if order.get("direction").and_then(Value::as_str) == Some("desc") {
                    crate::Direction::Desc
                } else {
                    crate::Direction::Asc
                },
                from: order.get("from").and_then(js::as_number),
                to: order.get("to").and_then(js::as_number),
            }),
            None => None,
        };
        let page = value.get("page").map(|page| QueryPage {
            offset: page.get("offset").and_then(Value::as_i64).unwrap_or(0),
            limit: page.get("limit").and_then(Value::as_i64),
        });
        Some(Self {
            collection: text("collection")?,
            id: text("id"),
            tenant_id: text("tenantId"),
            unique_key: text("uniqueKey"),
            conditions,
            after: text("after"),
            order,
            page,
        })
    }
}

/// What a driver's `query` can evaluate (`QueryCapabilities`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryCapabilities {
    /// The driver evaluates `json` (object and array) conditions. Scalar kinds are always required.
    #[serde(default)]
    pub json: bool,
    /// The driver evaluates `RecordQuery.order`.
    #[serde(default)]
    pub order: bool,
}

/// Numeric fields SQL adapters index for `findOrdered` within a tenant (audit time and sequence).
pub const ORDERED_FIELDS: [&str; 2] = ["timestamp", "sequence"];
/// Numeric fields SQL adapters index for `findOrdered` across a whole collection (`0004_expiry_indexes`).
pub const EXPIRY_FIELDS: [&str; 3] = ["expiresAt", "deliveredAt", "failedAt"];

/// The lookup fields each schema step indexes (SQLite and libSQL; PostgreSQL's document index covers every field).
/// A released step never changes: new fields get a new step.
pub const LOOKUP_INDEX_STEPS: [(&str, &[&str]); 3] = [
    (
        "0002_query_indexes",
        &[
            "tokenHash",
            "identityId",
            "email",
            "parentId",
            "subjectId",
            "groupId",
            "roleId",
            "credentialId",
            "originalIdentityId",
            "impersonatorSessionId",
            "accountId",
            "clientId",
            "uidHash",
            "userCodeHash",
            "grantIdHash",
            "connectionId",
            "targetId",
            "streamId",
            "jti",
        ],
    ),
    // Session cascades: role and temporary sessions by their source session, and by trust.
    ("0005_lookup_indexes", &["sourceSessionId", "trustId"]),
    // Data protection: deterministic token lookups and erasure by value (keyed value fingerprints).
    ("0006_protection_indexes", &["fingerprint"]),
];

/// The fields of one lookup index step.
pub fn lookup_index_step(name: &str) -> &'static [&'static str] {
    LOOKUP_INDEX_STEPS
        .iter()
        .find(|(step, _)| *step == name)
        .map(|(_, fields)| *fields)
        .unwrap_or(&[])
}

/// High-cardinality string fields SQL adapters index (`INDEXED_FIELDS`); the list only affects performance.
pub fn indexed_fields() -> Vec<&'static str> {
    LOOKUP_INDEX_STEPS
        .iter()
        .flat_map(|(_, fields)| fields.iter().copied())
        .collect()
}

/// `QUERYABLE_FIELD`: `/^[A-Za-z_][A-Za-z0-9_]{0,127}$/`, the field names a driver may inline into SQL paths.
pub fn queryable_field(field: &str) -> bool {
    let bytes = field.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

/// Reserved object key of the PostgreSQL value encoding (`encodeJsonbDocument`).
pub const JSONB_ESCAPE_KEY: &str = "\u{0001}better-iam";

/// Most typed conditions `plan_query` hands to a driver; further keys are filtered in memory.
pub const MAX_QUERY_CONDITIONS: usize = 24;

/// True when the string has no U+0000 and no unpaired surrogate (`storableString`). Rust strings never hold
/// unpaired surrogates, so only U+0000 makes a string unstorable here.
pub fn storable_string(value: &str) -> bool {
    !value.contains('\u{0}')
}

fn identifier_error(name: &str) -> IamError {
    IamError::new(
        "INVALID_RECORD",
        format!("{name} must be a nonempty string of at most 512 UTF-8 bytes"),
    )
}

/// `validIdentifier`: a nonempty string of at most 512 UTF-16 code units and 512 UTF-8 bytes, without C0 controls.
pub fn valid_identifier(value: &str, name: &str) -> IamResult<()> {
    if value.is_empty()
        || js::utf16_len(value) > 512
        || value.len() > 512
        || value.chars().any(|c| (c as u32) < 0x20)
    {
        return Err(identifier_error(name));
    }
    Ok(())
}

fn valid_identifier_value<'a>(value: Option<&'a Value>, name: &str) -> IamResult<&'a str> {
    match value {
        Some(Value::String(text)) => {
            valid_identifier(text, name)?;
            Ok(text)
        }
        _ => Err(identifier_error(name)),
    }
}

/// `storableIdentifier`: a valid identifier a database column can hold unchanged.
fn storable_identifier<'a>(value: Option<&'a Value>, name: &str) -> IamResult<&'a str> {
    let text = valid_identifier_value(value, name)?;
    // Rust strings cannot hold unpaired surrogates; the TypeScript check is vacuous here.
    Ok(text)
}

/// `jsonValue`: JSON data only, at most 64 levels, no `__proto__`/`constructor`/`prototype` keys.
pub fn json_value(value: &Value, depth: usize) -> IamResult<()> {
    if depth > 64 {
        return Err(IamError::new(
            "INVALID_RECORD",
            "Record nesting exceeds 64 levels",
        ));
    }
    match value {
        Value::Array(items) => {
            for item in items {
                json_value(item, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(map) => json_members(map, depth),
        _ => Ok(()),
    }
}

fn unsafe_key(key: &str) -> bool {
    key == "__proto__" || key == "constructor" || key == "prototype"
}

fn json_members(map: &Map<String, Value>, depth: usize) -> IamResult<()> {
    for (key, item) in js::entries(map) {
        if unsafe_key(key) {
            return Err(IamError::new("INVALID_RECORD", "Unsafe JSON property"));
        }
        json_value(item, depth + 1)?;
    }
    Ok(())
}

fn json_filter(filter: &Filter) -> IamResult<()> {
    for (key, item) in filter.entries() {
        if unsafe_key(key) {
            return Err(IamError::new("INVALID_RECORD", "Unsafe JSON property"));
        }
        if let Some(item) = item {
            json_value(item, 1)?;
        }
    }
    Ok(())
}

/// `pushableJson`: a filter value a database can compare exactly.
fn pushable_json(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
        Value::String(text) => storable_string(text),
        Value::Array(items) => items.iter().all(pushable_json),
        Value::Object(map) => map.iter().all(|(key, item)| {
            key != JSONB_ESCAPE_KEY && storable_string(key) && pushable_json(item)
        }),
    }
}

/// `rowFor`: validates a record and builds its row.
pub fn row_for(collection: &str, record: &Record) -> IamResult<StorageRow> {
    storable_identifier(Some(&Value::String(collection.to_owned())), "collection")?;
    let id = storable_identifier(record.get("id"), "id")?;
    let tenant_id = storable_identifier(record.get("tenantId"), "tenantId")?;
    let unique_key = match record.get("uniqueKey") {
        None => None,
        Some(value) => Some(storable_identifier(Some(value), "uniqueKey")?.to_owned()),
    };
    json_members(record, 0)?;
    let data = js::stringify_object(record);
    if js::utf16_len(&data) > 1_048_576 {
        return Err(IamError::new(
            "INVALID_RECORD",
            "Record exceeds one million characters",
        ));
    }
    Ok(StorageRow {
        collection: collection.to_owned(),
        id: id.to_owned(),
        tenant_id: tenant_id.to_owned(),
        unique_key,
        data,
    })
}

/// `decode`: the record of a row, checked against its columns.
pub fn decode(row: &StorageRow) -> IamResult<Record> {
    let value = js::parse(&row.data)
        .map_err(|_| IamError::with_status("STORAGE_CORRUPT", "Invalid stored JSON", 500))?;
    let mismatch = || IamError::with_status("STORAGE_CORRUPT", "Record metadata mismatch", 500);
    let Value::Object(record) = value else {
        return Err(mismatch());
    };
    let unique_key = match record.get("uniqueKey") {
        None | Some(Value::Null) => None,
        Some(Value::String(key)) => Some(key.as_str()),
        Some(_) => return Err(mismatch()),
    };
    if record.get("id").and_then(Value::as_str) != Some(row.id.as_str())
        || record.get("tenantId").and_then(Value::as_str) != Some(row.tenant_id.as_str())
        || unique_key != row.unique_key.as_deref()
    {
        return Err(mismatch());
    }
    Ok(record)
}

/// `equal(actual, expected)` with `undefined` as None.
fn equal(actual: Option<&Value>, expected: Option<&Value>) -> bool {
    match (actual, expected) {
        (None, None) => true,
        (Some(actual), Some(expected)) => js::deep_equal(actual, expected),
        _ => false,
    }
}

/// The in-memory definition of filter semantics (`matchesFilter`). Drivers' SQL must agree with it.
pub fn matches_filter(record: &Record, filter: &Filter) -> bool {
    filter
        .entries
        .iter()
        .all(|(key, value)| equal(record.get(key), value.as_ref()))
}

/// Code-point (UTF-8 byte) order, the order of SQLite's BINARY and PostgreSQL's "C" collation (`compareIds`).
pub fn compare_ids(left: &str, right: &str) -> Ordering {
    left.as_bytes().cmp(right.as_bytes())
}

/// The result of [`plan_query`] (`FindPlan`).
#[derive(Debug, Clone, PartialEq)]
pub struct FindPlan {
    pub query: RecordQuery,
    /// Every filter key became part of the query, so the driver's rows need no further filtering.
    pub exact: bool,
    /// A column filter no stored record can satisfy (an identifier no column can hold).
    pub empty: bool,
}

/// Splits a validated filter into driver conditions and keys left to the in-memory filter (`planQuery`).
pub fn plan_query(collection: &str, filter: &Filter, capabilities: QueryCapabilities) -> FindPlan {
    let mut query = RecordQuery {
        collection: collection.to_owned(),
        ..RecordQuery::default()
    };
    let mut exact = true;
    let mut empty = false;
    for (field, value) in filter.entries() {
        if let Some(Value::String(text)) = value
            && (field == "id" || field == "tenantId" || field == "uniqueKey")
        {
            if !storable_string(text) {
                empty = true;
            } else if field == "id" {
                query.id = Some(text.clone());
            } else if field == "tenantId" {
                query.tenant_id = Some(text.clone());
            } else {
                query.unique_key = Some(text.clone());
            }
            continue;
        }
        if !queryable_field(field) || query.conditions.len() >= MAX_QUERY_CONDITIONS {
            exact = false;
            continue;
        }
        let field = field.to_owned();
        match value {
            Some(Value::String(text)) if storable_string(text) => {
                query.conditions.push(FieldCondition::String {
                    field,
                    value: text.clone(),
                })
            }
            Some(Value::Number(number)) => query.conditions.push(FieldCondition::Number {
                field,
                value: js::number_value(number),
            }),
            Some(Value::Bool(flag)) => query.conditions.push(FieldCondition::Boolean {
                field,
                value: *flag,
            }),
            Some(Value::Null) => query.conditions.push(FieldCondition::Null { field }),
            None => query.conditions.push(FieldCondition::Absent { field }),
            Some(value @ (Value::Array(_) | Value::Object(_)))
                if capabilities.json && pushable_json(value) =>
            {
                query.conditions.push(FieldCondition::Json {
                    field,
                    value: js::stringify(value),
                })
            }
            _ => exact = false,
        }
    }
    FindPlan {
        query,
        exact,
        empty,
    }
}

/// A database failure as a driver reports it, before [`storage_error`] maps it.
#[derive(Debug, Clone, PartialEq)]
pub enum DriverError {
    /// An error of Better IAM itself, passed through unchanged.
    Iam(IamError),
    /// A database error: `code` is the SQLSTATE (PostgreSQL) or the SQLite extended result code name
    /// (`SQLITE_CONSTRAINT_UNIQUE`); `message` is for logs and never reaches callers.
    Database { code: String, message: String },
}

impl From<IamError> for DriverError {
    fn from(error: IamError) -> Self {
        DriverError::Iam(error)
    }
}

impl DriverError {
    pub fn database(code: impl Into<String>, message: impl Into<String>) -> Self {
        DriverError::Database {
            code: code.into(),
            message: message.into(),
        }
    }

    /// The `code` property the TypeScript mapper reads.
    pub fn code(&self) -> Option<&str> {
        match self {
            DriverError::Iam(error) => Some(&error.code),
            DriverError::Database { code, .. } => Some(code),
        }
    }
}

/// Map database failures without leaking SQL or credential-bearing record data (`storageError`).
pub fn storage_error(error: DriverError) -> IamError {
    let code = match error {
        DriverError::Iam(error) => return error,
        DriverError::Database { code, .. } => code,
    };
    if code == "23505"
        || code == "SQLITE_CONSTRAINT_UNIQUE"
        || code == "SQLITE_CONSTRAINT_PRIMARYKEY"
    {
        return IamError::with_status(
            "CONFLICT",
            "A record with this identifier or tenant key already exists",
            409,
        );
    }
    if [
        "40001",
        "40P01",
        "55P03",
        "57014",
        "SQLITE_BUSY",
        "SQLITE_BUSY_SNAPSHOT",
        "SQLITE_LOCKED",
    ]
    .contains(&code.as_str())
    {
        return IamError::with_status(
            "STORAGE_BUSY",
            "Database is busy; retry the complete operation",
            503,
        );
    }
    IamError::with_status("STORAGE_ERROR", "Database operation failed", 500)
}

/// The rows one adapter connection reads and writes (`RecordDriver`).
#[async_trait::async_trait]
pub trait RecordDriver: Send + Sync {
    async fn select(
        &self,
        collection: &str,
        id: Option<&str>,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StorageRow>, DriverError>;
    async fn insert(&self, row: &StorageRow) -> Result<(), DriverError>;
    async fn update(&self, row: &StorageRow) -> Result<bool, DriverError>;
    async fn delete(&self, collection: &str, id: &str) -> Result<(), DriverError>;
    /// Whether the driver implements [`RecordDriver::query`] (`driver.query !== undefined`).
    fn has_query(&self) -> bool {
        false
    }
    fn query_capabilities(&self) -> QueryCapabilities {
        QueryCapabilities::default()
    }
    /// Optional filtered read. It must return exactly the rows of `collection` matching every column and field
    /// condition, ordered by id in code-point order, applying `page` when present.
    async fn query(&self, _query: &RecordQuery) -> Result<Vec<StorageRow>, DriverError> {
        Err(DriverError::Iam(IamError::with_status(
            "UNSUPPORTED",
            "This driver cannot run queries",
            501,
        )))
    }
    /// Whether the driver implements [`RecordDriver::collections`].
    fn has_collections(&self) -> bool {
        false
    }
    /// Optional: the distinct collection names in the table, sorted.
    async fn collections(&self) -> Result<Vec<String>, DriverError> {
        Err(DriverError::Iam(IamError::with_status(
            "UNSUPPORTED",
            "This adapter cannot list its collections",
            501,
        )))
    }
}

/// A value an operation produces, type-erased for the object-safe [`RecordAccess`].
pub type OperationValue = Box<dyn std::any::Any + Send>;

/// One record operation against a driver, type-erased: [`record_store`] builds them, adapters run them.
pub type DriverOperation = Box<
    dyn FnOnce(Arc<dyn RecordDriver>) -> BoxFuture<'static, Result<OperationValue, DriverError>>
        + Send,
>;

/// How an adapter runs record operations (`RecordStore.read` / `RecordStore.write`): with the right connection,
/// inside or outside the current transaction, with errors mapped by [`storage_error`] and a failure inside a
/// transaction marking it rollback-only. `write` refuses outside a transaction (`TRANSACTION_REQUIRED`).
#[async_trait::async_trait]
pub trait RecordAccess: Send + Sync {
    async fn read(&self, operation: DriverOperation) -> IamResult<OperationValue>;
    async fn write(&self, operation: DriverOperation) -> IamResult<OperationValue>;
}

fn operation<T, F, Fut>(run: F) -> DriverOperation
where
    T: Send + 'static,
    F: FnOnce(Arc<dyn RecordDriver>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, DriverError>> + Send + 'static,
{
    Box::new(move |driver| {
        Box::pin(async move {
            run(driver)
                .await
                .map(|value| Box::new(value) as OperationValue)
        })
    })
}

fn typed<T: 'static>(value: OperationValue) -> IamResult<T> {
    value.downcast::<T>().map(|value| *value).map_err(|_| {
        IamError::with_status(
            "INTERNAL_ERROR",
            "Storage operation result type mismatch",
            500,
        )
    })
}

async fn read<A, T, F, Fut>(store: &A, run: F) -> IamResult<T>
where
    A: RecordAccess + ?Sized,
    T: Send + 'static,
    F: FnOnce(Arc<dyn RecordDriver>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, DriverError>> + Send + 'static,
{
    typed(store.read(operation(run)).await?)
}

async fn write<A, T, F, Fut>(store: &A, run: F) -> IamResult<T>
where
    A: RecordAccess + ?Sized,
    T: Send + 'static,
    F: FnOnce(Arc<dyn RecordDriver>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, DriverError>> + Send + 'static,
{
    typed(store.write(operation(run)).await?)
}

fn slice(records: Vec<Record>, offset: usize, limit: Option<usize>) -> Vec<Record> {
    let end = limit.map(|limit| offset.saturating_add(limit));
    records
        .into_iter()
        .skip(offset)
        .take(
            end.map(|end| end.saturating_sub(offset))
                .unwrap_or(usize::MAX),
        )
        .collect()
}

fn decode_rows(rows: &[StorageRow]) -> Result<Vec<Record>, DriverError> {
    rows.iter()
        .map(|row| decode(row).map_err(DriverError::Iam))
        .collect()
}

fn pagination(offset: Option<i64>, limit: Option<i64>) -> IamResult<(usize, Option<usize>)> {
    let offset = offset.unwrap_or(0);
    let safe = |value: i64| (0..=js::MAX_SAFE_INTEGER as i64).contains(&value);
    if !safe(offset) || limit.is_some_and(|limit| !safe(limit)) {
        return Err(IamError::new(
            "INVALID_FILTER",
            "Pagination must use nonnegative safe integers",
        ));
    }
    Ok((offset as usize, limit.map(|limit| limit as usize)))
}

/// Validated `OrderOptions` with defaults applied (`orderOptions`).
#[derive(Debug, Clone)]
pub struct ValidOrder {
    pub field: String,
    pub direction: crate::Direction,
    pub from: Option<f64>,
    pub to: Option<f64>,
    pub offset: usize,
    pub limit: Option<usize>,
}

/// `orderOptions`: validates order options and applies defaults.
pub fn order_options(order: &OrderOptions) -> IamResult<ValidOrder> {
    if !queryable_field(&order.field) {
        return Err(IamError::new(
            "INVALID_FILTER",
            "The order field must be a top-level identifier",
        ));
    }
    for bound in [order.from, order.to].into_iter().flatten() {
        if !bound.is_finite() {
            return Err(IamError::new(
                "INVALID_FILTER",
                "Range bounds must be finite numbers",
            ));
        }
    }
    let (offset, limit) = pagination(order.offset, order.limit)?;
    Ok(ValidOrder {
        field: order.field.clone(),
        direction: order.direction,
        from: order.from,
        to: order.to,
        offset,
        limit,
    })
}

/// `inRange`.
fn in_range(record: &Record, order: &ValidOrder) -> bool {
    match record.get(&order.field).and_then(js::as_number) {
        Some(value) => {
            order.from.is_none_or(|from| value >= from) && order.to.is_none_or(|to| value <= to)
        }
        None => false,
    }
}

/// `orderRecords`: by the numeric field, ties by id ascending.
fn order_records(
    mut records: Vec<Record>,
    field: &str,
    direction: crate::Direction,
) -> Vec<Record> {
    let value = |record: &Record| {
        record
            .get(field)
            .and_then(js::as_number)
            .unwrap_or(f64::NAN)
    };
    records.sort_by(|left, right| {
        let mut ordering = value(left)
            .partial_cmp(&value(right))
            .unwrap_or(Ordering::Equal);
        if direction == crate::Direction::Desc {
            ordering = ordering.reverse();
        }
        ordering.then_with(|| compare_ids(crate::record_id(left), crate::record_id(right)))
    });
    records
}

/// The shared record-store logic of the TypeScript `RecordStore` class: adapters implement [`RecordAccess`] and
/// delegate their [`IamStore`] data methods here.
pub mod record_store {
    use super::*;

    /// `RecordStore.get`.
    pub async fn get<A: RecordAccess + ?Sized>(
        store: &A,
        collection: &str,
        id: &str,
    ) -> IamResult<Option<Record>> {
        valid_identifier(collection, "collection")?;
        valid_identifier(id, "id")?;
        let (collection, id) = (collection.to_owned(), id.to_owned());
        read(store, move |driver| async move {
            // Writes refuse such identifiers; querying would match the row of another spelling.
            if !storable_string(&collection) || !storable_string(&id) {
                return Ok(None);
            }
            let rows = driver.select(&collection, Some(&id), None).await?;
            match rows.first() {
                Some(row) => Ok(Some(decode(row)?)),
                None => Ok(None),
            }
        })
        .await
    }

    /// The `wanted` predicate of `RecordStore.find`: the filter, and the cursor when there is one.
    fn wanted(record: &Record, filter: &Filter, after: Option<&str>) -> bool {
        matches_filter(record, filter)
            && after.is_none_or(|after| {
                compare_ids(crate::record_id(record), after) == Ordering::Greater
            })
    }

    /// The in-memory ordering of `RecordStore.findOrdered`.
    fn in_order(records: Vec<Record>, filter: &Filter, valid: &ValidOrder) -> Vec<Record> {
        let kept = records
            .into_iter()
            .filter(|record| matches_filter(record, filter) && in_range(record, valid))
            .collect();
        slice(
            order_records(kept, &valid.field, valid.direction),
            valid.offset,
            valid.limit,
        )
    }

    /// The body of `RecordStore.find` inside its read (`after` already validated).
    pub(super) async fn find_with_driver(
        driver: Arc<dyn RecordDriver>,
        collection: &str,
        filter: &Filter,
        offset: usize,
        limit: Option<usize>,
        after: Option<&str>,
    ) -> Result<Vec<Record>, DriverError> {
        if limit == Some(0) || !storable_string(collection) {
            return Ok(Vec::new());
        }
        if driver.has_query() {
            let plan = plan_query(collection, filter, driver.query_capabilities());
            if plan.empty {
                return Ok(Vec::new());
            }
            // A cursor the database cannot hold exactly is applied in memory.
            let mut query = plan.query;
            if let Some(after) = after.filter(|after| storable_string(after)) {
                query.after = Some(after.to_owned());
            }
            if plan.exact && query.after.as_deref() == after {
                // With a cursor, read from it and skip `offset` here: a driver that ignores the cursor then
                // returns a row at or before it whenever that would change the page, which fails the check below
                // instead of silently shifting the page.
                let window = match after {
                    None => QueryPage {
                        offset: offset as i64,
                        limit: limit.map(|limit| limit as i64),
                    },
                    Some(_) => QueryPage {
                        offset: 0,
                        limit: limit.map(|limit| (offset + limit) as i64),
                    },
                };
                let paged = RecordQuery {
                    page: Some(window),
                    ..query.clone()
                };
                let records = decode_rows(&driver.query(&paged).await?)?;
                if records.iter().all(|record| wanted(record, filter, after)) {
                    return Ok(if after.is_none() {
                        records
                    } else {
                        slice(records, offset, None)
                    });
                }
                // A driver that disagrees with the reference semantics (or ignores the cursor) must not shift
                // pages: redo the query without paging and filter in memory.
            }
            let records = decode_rows(&driver.query(&query).await?)?;
            return Ok(slice(
                records
                    .into_iter()
                    .filter(|record| wanted(record, filter, after))
                    .collect(),
                offset,
                limit,
            ));
        }
        for column in ["id", "tenantId"] {
            if let Some(Some(Value::String(text))) = filter.get(column)
                && !storable_string(text)
            {
                return Ok(Vec::new());
            }
        }
        let column = |name: &str| match filter.get(name) {
            Some(Some(Value::String(text))) => Some(text.clone()),
            _ => None,
        };
        let (id, tenant_id) = (column("id"), column("tenantId"));
        let rows = driver
            .select(collection, id.as_deref(), tenant_id.as_deref())
            .await?;
        let mut records: Vec<Record> = decode_rows(&rows)?
            .into_iter()
            .filter(|record| wanted(record, filter, after))
            .collect();
        // Do not inherit installation-dependent collation from a third-party driver.
        records.sort_by(|left, right| compare_ids(crate::record_id(left), crate::record_id(right)));
        Ok(slice(records, offset, limit))
    }

    /// `RecordStore.find`.
    pub async fn find<A: RecordAccess + ?Sized>(
        store: &A,
        collection: &str,
        filter: &Filter,
        options: &FindOptions,
    ) -> IamResult<Vec<Record>> {
        valid_identifier(collection, "collection")?;
        json_filter(filter)?;
        let (offset, limit) = pagination(options.offset, options.limit)?;
        let (collection, filter, after) =
            (collection.to_owned(), filter.clone(), options.after.clone());
        read(store, move |driver| async move {
            find_with_driver(
                driver,
                &collection,
                &filter,
                offset,
                limit,
                after.as_deref(),
            )
            .await
        })
        .await
    }

    /// `RecordStore.findOrdered`.
    pub async fn find_ordered<A: RecordAccess + ?Sized>(
        store: &A,
        collection: &str,
        filter: &Filter,
        order: &OrderOptions,
    ) -> IamResult<Vec<Record>> {
        valid_identifier(collection, "collection")?;
        json_filter(filter)?;
        let valid = order_options(order)?;
        let (collection, filter) = (collection.to_owned(), filter.clone());
        read(store, move |driver| async move {
            if valid.limit == Some(0) || !storable_string(&collection) {
                return Ok(Vec::new());
            }
            if driver.has_query() && driver.query_capabilities().order {
                let plan = plan_query(&collection, &filter, driver.query_capabilities());
                if plan.empty {
                    return Ok(Vec::new());
                }
                let query = RecordQuery {
                    order: Some(QueryOrder {
                        field: valid.field.clone(),
                        direction: valid.direction,
                        from: valid.from,
                        to: valid.to,
                    }),
                    ..plan.query
                };
                if plan.exact {
                    let paged = RecordQuery {
                        page: Some(QueryPage {
                            offset: valid.offset as i64,
                            limit: valid.limit.map(|limit| limit as i64),
                        }),
                        ..query.clone()
                    };
                    let records = decode_rows(&driver.query(&paged).await?)?;
                    if records
                        .iter()
                        .all(|record| matches_filter(record, &filter) && in_range(record, &valid))
                    {
                        return Ok(records);
                    }
                }
                return Ok(in_order(
                    decode_rows(&driver.query(&query).await?)?,
                    &filter,
                    &valid,
                ));
            }
            // Stores without ordered queries: read the matching records and order them here.
            let records = find_with_driver(driver, &collection, &filter, 0, None, None).await?;
            Ok(in_order(records, &filter, &valid))
        })
        .await
    }

    /// `RecordStore.collections`: sorted by code point; `UNSUPPORTED` (501) when the driver cannot list them. The
    /// refusal is raised after the read, so probing it inside a transaction does not roll the transaction back.
    pub async fn collections<A: RecordAccess + ?Sized>(store: &A) -> IamResult<Vec<String>> {
        let listed = read(store, |driver| async move {
            if driver.has_collections() {
                driver.collections().await.map(Some)
            } else {
                Ok(None)
            }
        })
        .await?;
        let Some(mut listed) = listed else {
            return Err(IamError::with_status(
                "UNSUPPORTED",
                "This adapter cannot list its collections",
                501,
            ));
        };
        listed.sort_by(|left, right| compare_ids(left, right));
        Ok(listed)
    }

    /// `RecordStore.insert`.
    pub async fn insert<A: RecordAccess + ?Sized>(
        store: &A,
        collection: &str,
        record: &Record,
    ) -> IamResult<Record> {
        let row = row_for(collection, record)?;
        write(store, move |driver| async move {
            driver.insert(&row).await?;
            Ok(decode(&row)?)
        })
        .await
    }

    /// `RecordStore.put`.
    pub async fn put<A: RecordAccess + ?Sized>(
        store: &A,
        collection: &str,
        record: &Record,
    ) -> IamResult<Record> {
        let row = row_for(collection, record)?;
        write(store, move |driver| async move {
            let existing = driver.select(&row.collection, Some(&row.id), None).await?;
            let Some(existing) = existing.first() else {
                return Err(IamError::with_status(
                    "NOT_FOUND",
                    "Cannot update a missing record",
                    404,
                )
                .into());
            };
            if existing.tenant_id != row.tenant_id {
                return Err(IamError::with_status(
                    "CONFLICT",
                    "Record tenant cannot be changed",
                    409,
                )
                .into());
            }
            if !driver.update(&row).await? {
                return Err(IamError::with_status(
                    "NOT_FOUND",
                    "Cannot update a missing record",
                    404,
                )
                .into());
            }
            Ok(decode(&row)?)
        })
        .await
    }

    /// `RecordStore.delete`.
    pub async fn delete<A: RecordAccess + ?Sized>(
        store: &A,
        collection: &str,
        id: &str,
    ) -> IamResult<()> {
        valid_identifier(collection, "collection")?;
        valid_identifier(id, "id")?;
        let (collection, id) = (collection.to_owned(), id.to_owned());
        write(store, move |driver| async move {
            // No stored record can have such an identifier (see get).
            if storable_string(&collection) && storable_string(&id) {
                driver.delete(&collection, &id).await?;
            }
            Ok(())
        })
        .await
    }
}

/// An in-memory predicate for [`find_ordered`] (`order.where`).
pub type RecordPredicate<'a> = &'a (dyn Fn(&Record) -> bool + Send + Sync);

/// Records matching `filter` whose numeric `order.field` lies in `[from, to]`, ordered by that field (ties by id,
/// ascending) and paged (`findOrdered`). Uses the store's `find_ordered` when it has one and otherwise orders a plain
/// `find` in memory. `where_` adds an in-memory predicate (for example a glob); the store is then read in ordered
/// chunks until the page is full, so it never loads everything.
pub async fn find_ordered(
    store: &dyn IamStore,
    collection: &str,
    filter: &Filter,
    order: &OrderOptions,
    where_: Option<RecordPredicate<'_>>,
) -> IamResult<Vec<Record>> {
    let valid = order_options(order)?;
    if !store.has_find_ordered() {
        let records: Vec<Record> = store
            .find(collection, filter, &FindOptions::default())
            .await?
            .into_iter()
            .filter(|record| {
                in_range(record, &valid) && where_.is_none_or(|predicate| predicate(record))
            })
            .collect();
        return Ok(slice(
            order_records(records, &valid.field, valid.direction),
            valid.offset,
            valid.limit,
        ));
    }
    let Some(predicate) = where_ else {
        return store.find_ordered(collection, filter, order).await;
    };
    let wanted = valid.limit.map(|limit| valid.offset + limit);
    let chunk = match wanted {
        None => 500,
        Some(wanted) => (wanted.saturating_mul(2)).clamp(100, 2000),
    };
    let mut matches: Vec<Record> = Vec::new();
    let mut read = 0usize;
    while wanted.is_none_or(|wanted| matches.len() < wanted) {
        let options = OrderOptions {
            offset: Some(read as i64),
            limit: Some(chunk as i64),
            ..order.clone()
        };
        let batch = store.find_ordered(collection, filter, &options).await?;
        let length = batch.len();
        matches.extend(batch.into_iter().filter(|record| predicate(record)));
        if length < chunk {
            break;
        }
        read += chunk;
    }
    Ok(slice(matches, valid.offset, valid.limit))
}

/// A named, idempotent schema step (`SchemaMigration`). The ledger `iam_migrations` records which ones ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaMigration {
    pub name: String,
    pub statements: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn indexed_fields_flatten_the_steps() {
        assert_eq!(indexed_fields().len(), 22);
        assert_eq!(indexed_fields()[0], "tokenHash");
        assert_eq!(*indexed_fields().last().unwrap(), "fingerprint");
    }

    #[test]
    fn rows_validate_records() {
        let record = crate::record(json!({"id": "a", "tenantId": "t", "n": 1.0}));
        assert_eq!(
            row_for("items", &record).unwrap().data,
            r#"{"id":"a","tenantId":"t","n":1}"#
        );
        let bad = crate::record(json!({"id": "a", "tenantId": "t", "__proto__": 1}));
        assert_eq!(
            row_for("items", &bad).unwrap_err().message,
            "Unsafe JSON property"
        );
    }
}
