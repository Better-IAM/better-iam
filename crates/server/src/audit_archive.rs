//! Port of `packages/server/src/audit-archive.ts`: continuous audit archiving to a configured sink, and the JSON
//! Lines file sink (`createJsonlAuditArchive`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use better_iam_core::{
    AUDIT_GENESIS, Filter, FindOptions, IamError, IamResult, IamStoreExt, OrderOptions, Record,
    VerifyAuditChainOptions, find_ordered, js as core_js, verify_audit_chain,
};
use indexmap::IndexMap;
use serde_json::{Map, Value, json};

use crate::context::ServerContext;
use crate::options::{AuditArchiveBatch, AuditArchiveOptions};
use crate::utils::date_now;

const CURSORS: &str = "auditArchiveCursors";

/// `AuditArchiveResult.failed[]`.
struct Failure {
    tenant_id: String,
    code: &'static str,
    message: String,
}

/// `AuditArchiveResult.gaps[]`.
struct Gap {
    tenant_id: String,
    from_sequence: f64,
    to_sequence: f64,
}

/// `AuditArchiveResult`.
#[derive(Default)]
struct ArchiveResult {
    archived: IndexMap<String, f64>,
    batches: f64,
    failed: Vec<Failure>,
    gaps: Vec<Gap>,
    busy: Vec<String>,
    truncated: bool,
}

impl ArchiveResult {
    fn mark_busy(&mut self, tenant_id: &str) {
        if !self.busy.iter().any(|busy| busy == tenant_id) {
            self.busy.push(tenant_id.to_owned());
        }
    }

    fn to_json(&self) -> Value {
        let number = crate::js::number;
        json!({
            "archived": self
                .archived
                .iter()
                .map(|(tenant, count)| (tenant.clone(), number(*count)))
                .collect::<Map<String, Value>>(),
            "batches": number(self.batches),
            "failed": self
                .failed
                .iter()
                .map(|failure| json!({
                    "tenantId": failure.tenant_id,
                    "code": failure.code,
                    "message": failure.message,
                }))
                .collect::<Vec<_>>(),
            "gaps": self
                .gaps
                .iter()
                .map(|gap| json!({
                    "tenantId": gap.tenant_id,
                    "fromSequence": number(gap.from_sequence),
                    "toSequence": number(gap.to_sequence),
                }))
                .collect::<Vec<_>>(),
            "busy": self.busy,
            "truncated": self.truncated,
        })
    }
}

fn number_member(record: &Record, key: &str) -> Option<f64> {
    record.get(key).and_then(core_js::as_number)
}

/// `message.slice(0, 256)`: the first 256 UTF-16 code units.
fn slice_utf16(message: &str, max: usize) -> String {
    let mut units = 0;
    let mut out = String::new();
    for c in message.chars() {
        units += c.len_utf16();
        if units > max {
            break;
        }
        out.push(c);
    }
    out
}

/// Continuous audit archiving: copies each tenant's hash-chained audit events, verified and in order, to the
/// configured sink, and records how far each chain has been archived. One run at a time holds a tenant (a lease on
/// its cursor), so overlapping runs never race each other's batches. `pruneAudit` never deletes past the cursor, so
/// the database only ever drops events the archive already holds.
pub struct AuditArchive {
    ctx: Arc<ServerContext>,
    batch_size: f64,
    lease_ms: f64,
}

/// `createAuditArchive(ctx)`: validates `auditArchive.batchSize` and `auditArchive.leaseMs` (INVALID_CONFIG).
pub fn create_audit_archive(ctx: &Arc<ServerContext>) -> IamResult<AuditArchive> {
    let sink = ctx.options.audit_archive.as_ref();
    let batch_size = sink.and_then(|sink| sink.batch_size).unwrap_or(1000.0);
    let lease_ms = sink
        .and_then(|sink| sink.lease_ms)
        .unwrap_or(10.0 * 60_000.0);
    if sink.is_some()
        && (!core_js::is_safe_integer(batch_size) || !(1.0..=10_000.0).contains(&batch_size))
    {
        return Err(crate::js::invalid_config(
            "auditArchive.batchSize must be between 1 and 10000",
        ));
    }
    if sink.is_some()
        && (!core_js::is_safe_integer(lease_ms) || !(60_000.0..=3_600_000.0).contains(&lease_ms))
    {
        return Err(crate::js::invalid_config(
            "auditArchive.leaseMs must be between 60000 and 3600000",
        ));
    }
    Ok(AuditArchive {
        ctx: ctx.clone(),
        batch_size,
        lease_ms,
    })
}

impl AuditArchive {
    /// Takes or renews this run's lease on a tenant; None when another live run holds it.
    async fn claim(&self, tenant_id: &str, lease_id: &str) -> IamResult<Option<Record>> {
        let ctx = &self.ctx;
        let lease_ms = self.lease_ms;
        ctx.store
            .transaction(|tx| async move {
                let current = tx.get(CURSORS, tenant_id).await?;
                let now = date_now();
                if let Some(current) = &current
                    && let Some(held) = current
                        .get("leaseId")
                        .filter(|held| crate::js::truthy(Some(held)))
                    && held.as_str() != Some(lease_id)
                    && number_member(current, "leaseUntil").unwrap_or(0.0) > now
                {
                    return Ok(None);
                }
                let member = |key: &str| {
                    current
                        .as_ref()
                        .and_then(|current| current.get(key))
                        .filter(|value| !value.is_null())
                        .cloned()
                };
                let mut next = Record::new();
                next.insert("id".into(), Value::String(tenant_id.to_owned()));
                next.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
                next.insert(
                    "sequence".into(),
                    member("sequence").unwrap_or_else(|| json!(0)),
                );
                next.insert(
                    "hash".into(),
                    member("hash").unwrap_or_else(|| Value::String(AUDIT_GENESIS.to_owned())),
                );
                next.insert(
                    "updatedAt".into(),
                    member("updatedAt").unwrap_or_else(|| crate::js::number(ctx.now())),
                );
                next.insert("leaseId".into(), Value::String(lease_id.to_owned()));
                next.insert("leaseUntil".into(), crate::js::number(now + lease_ms));
                if current.is_some() {
                    tx.put(CURSORS, &next).await?;
                } else {
                    tx.insert(CURSORS, &next).await?;
                }
                Ok(Some(next))
            })
            .await
    }

    async fn release(&self, tenant_id: &str, lease_id: &str) -> IamResult<()> {
        self.ctx
            .store
            .transaction(|tx| async move {
                let current = tx.get(CURSORS, tenant_id).await?;
                if let Some(mut current) = current
                    && current.get("leaseId").and_then(Value::as_str) == Some(lease_id)
                {
                    current.shift_remove("leaseId");
                    current.shift_remove("leaseUntil");
                    tx.put(CURSORS, &current).await?;
                }
                Ok(())
            })
            .await
    }

    async fn archive_tenant(
        &self,
        tenant_id: &str,
        limit: f64,
        result: &mut ArchiveResult,
    ) -> IamResult<bool> {
        let lease_id = uuid::Uuid::new_v4().to_string();
        let outcome = self
            .archive_batches(tenant_id, &lease_id, limit, result)
            .await;
        let released = self.release(tenant_id, &lease_id).await;
        match released {
            Err(error) => Err(error),
            Ok(()) => outcome,
        }
    }

    async fn archive_batches(
        &self,
        tenant_id: &str,
        lease_id: &str,
        limit: f64,
        result: &mut ArchiveResult,
    ) -> IamResult<bool> {
        let ctx = &self.ctx;
        loop {
            let budget = limit - result.archived.values().sum::<f64>();
            let size = self.batch_size.min(budget);
            if size == 0.0 {
                return Ok(false);
            }
            // Renewed before every batch, so a run that holds the lease never loses it mid-batch unless one write
            // outlasts the whole lease.
            let Some(cursor) = self.claim(tenant_id, lease_id).await? else {
                result.mark_busy(tenant_id);
                return Ok(true);
            };
            let after = number_member(&cursor, "sequence").unwrap_or(0.0);
            let events = find_ordered(
                ctx.store.as_ref(),
                "audit",
                &Filter::new().eq("tenantId", tenant_id),
                &OrderOptions {
                    field: "sequence".into(),
                    from: Some(after + 1.0),
                    limit: Some(size as i64),
                    ..OrderOptions::default()
                },
                None,
            )
            .await?;
            let Some(first) = events.first() else {
                return Ok(true);
            };
            let first_sequence = number_member(first, "sequence").unwrap_or(f64::NAN);
            let contiguous = first_sequence == after + 1.0;
            if !contiguous {
                result.gaps.push(Gap {
                    tenant_id: tenant_id.to_owned(),
                    from_sequence: after + 1.0,
                    to_sequence: first_sequence - 1.0,
                });
            }
            let previous_hash = if contiguous {
                cursor
                    .get("hash")
                    .and_then(Value::as_str)
                    .unwrap_or(AUDIT_GENESIS)
                    .to_owned()
            } else {
                first
                    .get("previousHash")
                    .and_then(Value::as_str)
                    .unwrap_or(AUDIT_GENESIS)
                    .to_owned()
            };
            let verification = verify_audit_chain(
                &events,
                &VerifyAuditChainOptions {
                    previous_hash: Some(previous_hash.clone()),
                    head: None,
                },
            );
            if !verification.valid || verification.checked as usize != events.len() {
                let at = verification
                    .failure
                    .as_ref()
                    .map(|failure| failure.sequence)
                    .unwrap_or(first_sequence);
                result.failed.push(Failure {
                    tenant_id: tenant_id.to_owned(),
                    code: "AUDIT_CHAIN_BROKEN",
                    message: format!(
                        "The chain does not verify at sequence {}",
                        core_js::number_to_string(at)
                    ),
                });
                return Ok(true);
            }
            let count = events.len() as f64;
            let batch = AuditArchiveBatch {
                tenant_id: tenant_id.to_owned(),
                from_sequence: first_sequence,
                to_sequence: verification.last.unwrap_or(first_sequence),
                previous_hash,
                last_hash: verification.last_hash.clone().unwrap_or_default(),
                events,
            };
            let (to_sequence, last_hash) = (batch.to_sequence, batch.last_hash.clone());
            // Outside any transaction: the sink is an external side effect.
            let written = match ctx
                .options
                .audit_archive
                .as_ref()
                .and_then(|sink| sink.write.clone())
            {
                Some(write) => write(batch).await,
                None => Err(IamError::with_status(
                    "INTERNAL_ERROR",
                    "sink.write is not a function",
                    500,
                )),
            };
            if let Err(error) = written {
                result.failed.push(Failure {
                    tenant_id: tenant_id.to_owned(),
                    code: if error.code == "ARCHIVE_CONFLICT" {
                        "ARCHIVE_CONFLICT"
                    } else {
                        "ARCHIVE_WRITE_FAILED"
                    },
                    message: slice_utf16(&error.message, 256),
                });
                return Ok(true);
            }
            let advanced = ctx
                .store
                .transaction(|tx| async move {
                    let Some(mut current) = tx.get(CURSORS, tenant_id).await? else {
                        return Ok(false);
                    };
                    // Only the lease holder moves the cursor, and only from where it read.
                    if current.get("leaseId").and_then(Value::as_str) != Some(lease_id)
                        || number_member(&current, "sequence") != Some(after)
                    {
                        return Ok(false);
                    }
                    current.insert("sequence".into(), crate::js::number(to_sequence));
                    current.insert("hash".into(), Value::String(last_hash));
                    current.insert("updatedAt".into(), crate::js::number(ctx.now()));
                    tx.put(CURSORS, &current).await?;
                    Ok(true)
                })
                .await?;
            if !advanced {
                result.mark_busy(tenant_id);
                return Ok(true);
            }
            *result.archived.entry(tenant_id.to_owned()).or_insert(0.0) += count;
            result.batches += 1.0;
            if count < size {
                return Ok(true);
            }
        }
    }

    /// Archives every tenant's new audit events (or one `tenantId`'s), at most `limit` events per run (default
    /// 100000). A scheduler job; run it before `pruneAudit`.
    pub async fn archive_audit(&self, input: Option<&Value>) -> IamResult<Value> {
        if self.ctx.options.audit_archive.is_none() {
            return Err(IamError::with_status(
                "NO_AUDIT_ARCHIVE",
                "Configure auditArchive (for example createJsonlAuditArchive) to archive audit events",
                501,
            ));
        }
        let empty = Map::new();
        let input = match input {
            None => &empty,
            Some(Value::Object(input)) => input,
            // Reading a member of null throws a TypeError in TypeScript.
            Some(Value::Null) => return Err(crate::js::internal_error()),
            Some(_) => &empty,
        };
        let limit = match input.get("limit") {
            None | Some(Value::Null) => Some(100_000.0),
            Some(value) => core_js::as_number(value),
        };
        let limit = match limit {
            Some(limit)
                if core_js::is_safe_integer(limit) && (1.0..=10_000_000.0).contains(&limit) =>
            {
                limit
            }
            _ => {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "limit must be between 1 and 10000000",
                ));
            }
        };
        let mut result = ArchiveResult::default();
        let tenants: Vec<String> = match input.get("tenantId") {
            Some(value) => vec![
                value
                    .as_str()
                    .ok_or_else(|| crate::js::invalid_input("Invalid tenantId"))?
                    .to_owned(),
            ],
            None => self
                .ctx
                .store
                .find("auditChains", &Filter::new(), &FindOptions::default())
                .await?
                .iter()
                .map(|head| better_iam_core::record_id(head).to_owned())
                .collect(),
        };
        for tenant_id in tenants {
            if !self.archive_tenant(&tenant_id, limit, &mut result).await? {
                result.truncated = true;
                break;
            }
        }
        Ok(result.to_json())
    }

    /// The archive position of one tenant's chain, or undefined when nothing was archived yet.
    pub async fn archive_cursor(&self, tenant_id: &str) -> IamResult<Option<Value>> {
        Ok(self
            .ctx
            .store
            .get(CURSORS, tenant_id)
            .await?
            .map(Value::Object))
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        match method {
            "archiveAudit" => Some(self.archive_audit(args.first()).await),
            "archiveCursor" => Some(
                async {
                    let tenant_id = args
                        .first()
                        .and_then(Value::as_str)
                        .ok_or_else(|| crate::js::invalid_input("Invalid tenantId"))?;
                    Ok(self
                        .archive_cursor(tenant_id)
                        .await?
                        .unwrap_or_else(crate::port::undefined))
                }
                .await,
            ),
            _ => None,
        }
    }
}

/// An I/O failure of the file sink, reported like the exception Node throws (the archive records its message).
fn io_error(error: std::io::Error) -> IamError {
    IamError::with_status("INTERNAL_ERROR", error.to_string(), 500)
}

/// Flushes a directory entry (a created or renamed file) to disk; Windows cannot open directories for that.
fn sync_directory(path: &Path) -> std::io::Result<()> {
    if cfg!(windows) {
        return Ok(());
    }
    std::fs::File::open(path)?.sync_all()
}

/// `/^[\w.-]{1,200}$/` and not starting with `.`.
fn safe_file_name(tenant_id: &str) -> bool {
    !tenant_id.is_empty()
        && tenant_id.len() <= 200
        && tenant_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        && !tenant_id.starts_with('.')
}

fn write_batch(root: &Path, batch: &AuditArchiveBatch) -> IamResult<()> {
    if !safe_file_name(&batch.tenant_id) {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Tenant id is not a safe file name",
        ));
    }
    let folder = root.join(&batch.tenant_id);
    // A newly created tenant folder must itself be durable before its files are.
    let existed = folder.is_dir();
    std::fs::create_dir_all(&folder).map_err(io_error)?;
    if !existed {
        sync_directory(root).map_err(io_error)?;
    }
    let pad = |value: f64| format!("{:0>12}", core_js::number_to_string(value));
    let name = format!(
        "{}-{}.jsonl",
        pad(batch.from_sequence),
        pad(batch.to_sequence)
    );
    let target = folder.join(&name);
    let mut content = batch
        .events
        .iter()
        .map(core_js::stringify_object)
        .collect::<Vec<_>>()
        .join("\n");
    content.push('\n');
    let temporary = folder.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    let published = (|| -> IamResult<()> {
        {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary).map_err(io_error)?;
            use std::io::Write;
            file.write_all(content.as_bytes()).map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
        }
        match std::fs::hard_link(&temporary, &target) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                // Already archived: fine when identical, a conflict otherwise; the stored file stays.
                let stored = std::fs::read_to_string(&target).map_err(io_error)?;
                if stored != content {
                    return Err(IamError::with_status(
                        "ARCHIVE_CONFLICT",
                        format!("{}/{name} already holds different events", batch.tenant_id),
                        409,
                    ));
                }
                Ok(())
            }
            Err(error) => Err(io_error(error)),
        }
    })();
    let _ = std::fs::remove_file(&temporary);
    published?;
    sync_directory(&folder).map_err(io_error)
}

/// A file sink for `auditArchive`: one JSON Lines file per batch at
/// `{directory}/{tenantId}/{fromSequence}-{toSequence}.jsonl` (sequences zero-padded, so files sort in chain order).
/// Files are write-once: each is written under a unique temporary name, flushed, and published with a hard link that
/// never replaces an existing file. Writing the same batch again is accepted; a different batch under an existing
/// name is refused (`ARCHIVE_CONFLICT`), so a restored or tampered database can never overwrite archived events.
/// After a crash, files can overlap; read events by `sequence`.
pub fn create_jsonl_audit_archive(directory: impl AsRef<Path>) -> AuditArchiveOptions {
    let directory = directory.as_ref();
    let root: PathBuf = std::path::absolute(directory).unwrap_or_else(|_| directory.to_path_buf());
    let root = Arc::new(root);
    AuditArchiveOptions {
        write: Some(Arc::new(move |batch: AuditArchiveBatch| {
            let root = root.clone();
            Box::pin(async move {
                tokio::task::spawn_blocking(move || write_batch(&root, &batch))
                    .await
                    .map_err(|_| crate::js::internal_error())?
            })
        })),
        batch_size: None,
        lease_ms: None,
    }
}
