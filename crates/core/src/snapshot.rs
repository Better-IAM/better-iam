//! Portable store snapshots (`snapshot.ts`): every record of every collection as JSON Lines, independent of the
//! adapter, for backups, moving from SQLite to PostgreSQL, and test fixtures. Records are copied verbatim, so audit
//! hash chains, token hashes, and encrypted secrets stay valid. A snapshot holds credential hashes and encrypted
//! secrets: protect it like the database itself.
//!
//! Format: a header line `{ format, version, createdAt, collections }`, one `{ c, r }` line per record, and a
//! trailer `{ end: true, records, collections }` with counts, so a truncated file is detected before anything is
//! committed.

use std::cmp::Ordering;
use std::sync::Arc;

use serde_json::{Map, Value};

use crate::js;
use crate::storage::{Filter, compare_ids};
use crate::{FindOptions, IamError, IamResult, IamStore, IamStoreExt, Record};

/// `SNAPSHOT_FORMAT`.
pub const SNAPSHOT_FORMAT: &str = "better-iam-store";
/// `SNAPSHOT_VERSION`.
pub const SNAPSHOT_VERSION: u32 = 1;

/// `SnapshotSummary`: records in total and per collection (collection order as visited).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SnapshotSummary {
    pub records: u64,
    pub collections: Vec<(String, u64)>,
}

impl SnapshotSummary {
    fn add(&mut self, collection: &str, count: u64) {
        match self
            .collections
            .iter_mut()
            .find(|(name, _)| name == collection)
        {
            Some(entry) => entry.1 += count,
            None => self.collections.push((collection.to_owned(), count)),
        }
        self.records += count;
    }

    fn collections_value(&self) -> Map<String, Value> {
        self.collections
            .iter()
            .map(|(name, count)| (name.clone(), Value::from(*count)))
            .collect()
    }

    /// The summary as the TypeScript object `{ records, collections }`.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("records".into(), Value::from(self.records));
        map.insert(
            "collections".into(),
            Value::Object(self.collections_value()),
        );
        Value::Object(map)
    }
}

/// `SnapshotOptions`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SnapshotOptions {
    /// Collections to include; defaults to every collection the store lists (`collections()`).
    pub collections: Option<Vec<String>>,
    /// Records read per query while exporting (default 1000).
    pub page_size: Option<i64>,
    /// Rust-only: the header's `createdAt` time in epoch milliseconds (default: now), for reproducible snapshots.
    pub now: Option<f64>,
}

/// The store's collections, or None when it cannot list them (no method, or `UNSUPPORTED`).
async fn list_collections(store: &dyn IamStore) -> IamResult<Option<Vec<String>>> {
    if !store.has_collections() {
        return Ok(None);
    }
    match store.collections().await {
        Ok(collections) => Ok(Some(collections)),
        Err(error) if error.code == "UNSUPPORTED" => Ok(None),
        Err(error) => Err(error),
    }
}

async fn collections_of(store: &dyn IamStore, options: &SnapshotOptions) -> IamResult<Vec<String>> {
    if let Some(collections) = &options.collections {
        let mut unique: Vec<String> = Vec::new();
        for collection in collections {
            if !unique.contains(collection) {
                unique.push(collection.clone());
            }
        }
        unique.sort_by(|left, right| js::cmp_utf16(left, right));
        return Ok(unique);
    }
    list_collections(store).await?.ok_or_else(|| {
        IamError::with_status(
            "UNSUPPORTED",
            "This store cannot list its collections; pass the collections to copy explicitly",
            501,
        )
    })
}

fn page_size_of(options: &SnapshotOptions) -> IamResult<usize> {
    let size = options.page_size.unwrap_or(1000);
    if !(1..=100_000).contains(&size) {
        return Err(IamError::new(
            "INVALID_INPUT",
            "pageSize must be between 1 and 100000",
        ));
    }
    Ok(size as usize)
}

/// Reads every record of the listed collections, a page at a time, in id order (`eachRecord`). Pages follow an id
/// cursor (`after`); a store that ignores the cursor is detected and paged by offset instead.
async fn each_record<V>(
    tx: &dyn IamStore,
    collections: &[String],
    page_size: usize,
    mut visit: V,
) -> IamResult<SnapshotSummary>
where
    V: FnMut(&str, Record) -> futures::future::BoxFuture<'static, IamResult<()>> + Send,
{
    let mut summary = SnapshotSummary::default();
    for collection in collections {
        let mut count = 0u64;
        let mut cursor: Option<String> = None;
        let mut keyset = true;
        loop {
            let after = cursor.clone();
            let options = match &after {
                None => FindOptions {
                    limit: Some(page_size as i64),
                    ..FindOptions::default()
                },
                Some(after) if keyset => FindOptions {
                    after: Some(after.clone()),
                    limit: Some(page_size as i64),
                    ..FindOptions::default()
                },
                Some(_) => FindOptions {
                    offset: Some(count as i64),
                    limit: Some(page_size as i64),
                    ..FindOptions::default()
                },
            };
            let mut page = tx.find(collection, &Filter::new(), &options).await?;
            if keyset
                && let Some(after) = &after
                && page
                    .iter()
                    .any(|record| compare_ids(crate::record_id(record), after) != Ordering::Greater)
            {
                keyset = false;
                let offset = FindOptions {
                    offset: Some(count as i64),
                    limit: Some(page_size as i64),
                    ..FindOptions::default()
                };
                page = tx.find(collection, &Filter::new(), &offset).await?;
            }
            cursor = page
                .last()
                .map(|record| crate::record_id(record).to_owned());
            let length = page.len();
            for record in page {
                visit(collection, record).await?;
                count += 1;
            }
            if length < page_size {
                break;
            }
        }
        summary.add(collection, count);
    }
    Ok(summary)
}

/// Writes a snapshot through `write`, one line at a time (without newlines) (`exportStore`). Runs in one store
/// transaction, so the snapshot is consistent; that also holds the store's write lock until done.
pub async fn export_store<W>(
    store: &dyn IamStore,
    write: W,
    options: &SnapshotOptions,
) -> IamResult<SnapshotSummary>
where
    W: FnMut(String) -> IamResult<()> + Send + 'static,
{
    let page_size = page_size_of(options)?;
    let options = options.clone();
    let write = Arc::new(std::sync::Mutex::new(write));
    store
        .transaction(move |tx| async move {
            let collections = collections_of(tx.as_ref(), &options).await?;
            let emit = |line: String| -> IamResult<()> {
                let mut writer = write.lock().map_err(|_| {
                    IamError::with_status("INTERNAL_ERROR", "Snapshot writer failed", 500)
                })?;
                (writer)(line)
            };
            let mut header = Map::new();
            header.insert("format".into(), Value::String(SNAPSHOT_FORMAT.into()));
            header.insert("version".into(), Value::from(SNAPSHOT_VERSION));
            let created_at =
                js::iso_string(options.now.unwrap_or_else(js::now_ms)).unwrap_or_default();
            header.insert("createdAt".into(), Value::String(created_at));
            header.insert(
                "collections".into(),
                Value::Array(collections.iter().cloned().map(Value::String).collect()),
            );
            emit(js::stringify_object(&header))?;
            let writer = write.clone();
            let summary = each_record(
                tx.as_ref(),
                &collections,
                page_size,
                move |collection, record| {
                    let mut line = Map::new();
                    line.insert("c".into(), Value::String(collection.to_owned()));
                    line.insert("r".into(), Value::Object(record));
                    let text = js::stringify_object(&line);
                    let writer = writer.clone();
                    Box::pin(async move {
                        let mut writer = writer.lock().map_err(|_| {
                            IamError::with_status("INTERNAL_ERROR", "Snapshot writer failed", 500)
                        })?;
                        (writer)(text)
                    })
                },
            )
            .await?;
            let mut trailer = Map::new();
            trailer.insert("end".into(), Value::Bool(true));
            trailer.insert("records".into(), Value::from(summary.records));
            trailer.insert(
                "collections".into(),
                Value::Object(summary.collections_value()),
            );
            emit(js::stringify_object(&trailer))?;
            Ok(summary)
        })
        .await
}

async fn assert_empty(tx: &dyn IamStore, collections: Option<&[String]>) -> IamResult<()> {
    let existing = list_collections(tx).await?;
    if let Some(existing) = &existing {
        if !existing.is_empty() {
            let shown: Vec<&str> = existing.iter().take(5).map(String::as_str).collect();
            return Err(IamError::with_status(
                "STORE_NOT_EMPTY",
                format!(
                    "The target store already holds records ({}); import into an empty, migrated database",
                    shown.join(", ")
                ),
                409,
            ));
        }
        return Ok(());
    }
    let defaults = ["tenants".to_owned(), "identities".to_owned()];
    for collection in collections.unwrap_or(&defaults) {
        if !tx
            .find(collection, &Filter::new(), &FindOptions::limit(1))
            .await?
            .is_empty()
        {
            return Err(IamError::with_status(
                "STORE_NOT_EMPTY",
                "The target store already holds records",
                409,
            ));
        }
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("SNAPSHOT_INVALID", message)
}

/// Loads a snapshot into an empty, migrated store in one transaction (`importStore`): a malformed line, a record the
/// store refuses, or a missing or mismatched trailer rolls everything back.
pub async fn import_store<I>(store: &dyn IamStore, lines: I) -> IamResult<SnapshotSummary>
where
    I: IntoIterator<Item = String> + Send + 'static,
    I::IntoIter: Send,
{
    store
        .transaction(move |tx| async move {
            let mut summary = SnapshotSummary::default();
            let mut header = false;
            let mut trailer: Option<(f64, Map<String, Value>)> = None;
            let mut line_number = 0usize;
            for raw in lines {
                line_number += 1;
                let line = js::trim(&raw);
                if line.is_empty() {
                    continue;
                }
                if trailer.is_some() {
                    return Err(invalid(format!(
                        "Content after the trailer on line {line_number}"
                    )));
                }
                let entry = js::parse(line)
                    .map_err(|_| invalid(format!("Line {line_number} is not JSON")))?;
                let Value::Object(entry) = entry else {
                    return Err(invalid(format!("Line {line_number} is not an object")));
                };
                if !header {
                    let format_ok =
                        entry.get("format").and_then(Value::as_str) == Some(SNAPSHOT_FORMAT);
                    let version_ok = entry.get("version").and_then(js::as_number)
                        == Some(f64::from(SNAPSHOT_VERSION));
                    if !format_ok || !version_ok {
                        return Err(invalid(format!(
                            "Not a {SNAPSHOT_FORMAT} version {SNAPSHOT_VERSION} snapshot"
                        )));
                    }
                    header = true;
                    let declared: Option<Vec<String>> = entry
                        .get("collections")
                        .and_then(Value::as_array)
                        .map(|names| {
                            names
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_owned)
                                .collect()
                        });
                    assert_empty(tx.as_ref(), declared.as_deref()).await?;
                    continue;
                }
                if entry.get("end") == Some(&Value::Bool(true)) {
                    let Some(Value::Object(listed)) = entry.get("collections") else {
                        return Err(invalid(format!(
                            "The trailer on line {line_number} has no counts"
                        )));
                    };
                    let records = entry.get("records").map(js::to_number).unwrap_or(f64::NAN);
                    trailer = Some((records, listed.clone()));
                    continue;
                }
                let (
                    Some(Value::String(collection)),
                    Some(record @ (Value::Object(_) | Value::Array(_))),
                ) = (entry.get("c"), entry.get("r"))
                else {
                    return Err(invalid(format!("Line {line_number} is not a record entry")));
                };
                let Value::Object(record) = record else {
                    crate::storage::valid_identifier(collection, "collection")?;
                    return Err(IamError::new("INVALID_RECORD", "Record must be an object"));
                };
                tx.insert(collection, record).await?;
                summary.add(collection, 1);
            }
            if !header {
                return Err(invalid("The snapshot is empty"));
            }
            let Some((records, listed)) = trailer else {
                return Err(IamError::new(
                    "SNAPSHOT_TRUNCATED",
                    "The snapshot has no trailer; nothing was imported",
                ));
            };
            let expected: Vec<(&String, &Value)> = js::entries(&listed)
                .into_iter()
                .filter(|(_, count)| !js::strict_equal(count, &Value::from(0)))
                .collect();
            let mismatch = records != summary.records as f64
                || expected.len() != summary.collections.len()
                || expected.iter().any(|(name, count)| {
                    match summary
                        .collections
                        .iter()
                        .find(|(collection, _)| collection == *name)
                    {
                        None => true,
                        Some((_, actual)) => !js::strict_equal(&Value::from(*actual), count),
                    }
                });
            if mismatch {
                return Err(IamError::new(
                    "SNAPSHOT_TRUNCATED",
                    "Record counts do not match the snapshot trailer; nothing was imported",
                ));
            }
            Ok(summary)
        })
        .await
}

/// Copies every record from `source` into an empty, migrated `target` (`copyStore`). Reads in one source
/// transaction and writes in one target transaction, so the copy is consistent and all-or-nothing.
pub async fn copy_store<'a>(
    source: &'a dyn IamStore,
    target: &'a dyn IamStore,
    options: &SnapshotOptions,
) -> IamResult<SnapshotSummary> {
    let page_size = page_size_of(options)?;
    let options = options.clone();
    let result = source
        .transaction(move |from| async move {
            let collections = collections_of(from.as_ref(), &options).await?;
            target
                .transaction(move |to| async move {
                    assert_empty(to.as_ref(), Some(&collections)).await?;
                    let destination = to.clone();
                    each_record(
                        from.as_ref(),
                        &collections,
                        page_size,
                        move |collection, record| {
                            let destination = destination.clone();
                            let collection = collection.to_owned();
                            Box::pin(async move {
                                destination.insert(&collection, &record).await?;
                                Ok(())
                            })
                        },
                    )
                    .await
                })
                .await
        })
        .await;
    match result {
        // SQLite and libSQL refuse a second instance's transaction on a file the caller already holds.
        Err(error) if error.code == "DATABASE_IN_USE" => Err(IamError::with_status(
            "SAME_DATABASE",
            "The source and target are the same database",
            409,
        )),
        other => other,
    }
}
