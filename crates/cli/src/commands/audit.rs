//! Audit chain operations (`commands/audit.ts`): they read storage directly and never record events themselves.

use std::io::Write as _;
use std::sync::LazyLock;

use better_iam_core::{
    ChainHead, Filter, FindOptions, IamError, IamStore, Record, VerifyAuditChainOptions, js,
    verify_audit_chain,
};
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::{object, to_json};
use crate::errors::{CliError, CliResult, io_error, usage_error};
use crate::framework::{CommandSpec, CommandTarget, FlagSpec, define_command};
use crate::output::{OutputFormat, stringify};

fn tenant() -> FlagSpec {
    FlagSpec::string("The tenant whose audit chain to read")
        .value("TENANT_ID")
        .required()
}

fn sequence_of(event: &Record) -> Option<f64> {
    event.get("sequence").and_then(js::as_number)
}

/// A tenant's chained events in sequence order, straight from storage (no credential, no audit event).
async fn chain(store: &dyn IamStore, tenant_id: &str) -> CliResult<(Option<Record>, Vec<Record>)> {
    let head = store.get("auditChains", tenant_id).await?;
    let mut events: Vec<Record> = store
        .find(
            "audit",
            &Filter::new().eq("tenantId", tenant_id),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .filter(|event| sequence_of(event).is_some())
        .collect();
    events.sort_by(|a, b| {
        sequence_of(a)
            .partial_cmp(&sequence_of(b))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok((head, events))
}

fn head_summary(head: &Record) -> Value {
    json!({
        "sequence": head.get("sequence").cloned().unwrap_or(Value::Null),
        "hash": head.get("hash").cloned().unwrap_or(Value::Null),
    })
}

/// Creates a file that must not exist yet, owner-only (`writeFile(path, body, { flag: 'wx', mode: 0o600 })`).
pub(crate) fn write_new_file(path: &std::path::Path, body: &[u8], mode: u32) -> CliResult<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options
        .open(path)
        .map_err(|error| io_error(&error, "open", path))?;
    file.write_all(body)
        .map_err(|error| io_error(&error, "write", path))
}

static TENANT_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.-]{1,200}$").expect("regex"));
static ARCHIVE_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9]{12}-[0-9]{12}\.jsonl$").expect("regex"));

pub fn audit_commands() -> Vec<CommandSpec> {
    vec![
        define_command("audit-verify", "Recompute and check a tenant's audit hash chain", |context| async move {
            let tenant_id = context.flags.string("tenant").unwrap_or_default().to_owned();
            let instance = context.iam()?;
            let store = instance.store.as_ref();
            // A mistyped tenant has no chain to break; it must not pass a CI gate as "valid".
            if store.get("tenants", &tenant_id).await?.is_none() {
                return Err(IamError::new("NOT_FOUND", format!("No tenant {tenant_id}")).into());
            }
            let (head, mut events) = chain(store, &tenant_id).await?;
            // Events stripped of their chain fields are handed to the verifier too, which refuses them once a chain
            // exists.
            let unchained: Vec<Record> = store
                .find("audit", &Filter::new().eq("tenantId", tenant_id.as_str()), &FindOptions::default())
                .await?
                .into_iter()
                .filter(|event| sequence_of(event).is_none())
                .collect();
            events.extend(unchained);
            let verification = verify_audit_chain(
                &events,
                &VerifyAuditChainOptions {
                    previous_hash: None,
                    head: head.as_ref().map(|head| ChainHead {
                        sequence: head.get("sequence").and_then(js::as_number).unwrap_or(0.0),
                        hash: head.get("hash").and_then(Value::as_str).unwrap_or("").to_owned(),
                    }),
                },
            );
            let mut report = Map::new();
            report.insert("tenantId".into(), Value::String(tenant_id));
            if let Value::Object(members) = to_json(&verification)? {
                report.extend(members);
            }
            report.insert("head".into(), head.map_or(Value::Null, Value::Object));
            context.print(&Value::Object(report))?;
            if !verification.valid {
                return Err(IamError::new("AUDIT_CHAIN_BROKEN", "The audit chain does not verify").into());
            }
            Ok(None)
        })
        .group("Audit")
        .description(
            "audit-verify recomputes a tenant's audit hash chain from storage and exits non-zero (AUDIT_CHAIN_BROKEN) when it does not verify; it records nothing.",
        )
        .target(CommandTarget::Config)
        .flag("tenant", tenant()),
        define_command("audit-export", "Write a tenant's audit chain as JSON Lines", |context| async move {
            let flags = &context.flags;
            let tenant_id = flags.string("tenant").unwrap_or_default().to_owned();
            let instance = context.iam()?;
            let (head, events) = chain(instance.store.as_ref(), &tenant_id).await?;
            let output = context.path(flags.string("output").unwrap_or_default());
            // Owner-only, like store-export: every event names its actor, action, outcome and session.
            let body = events
                .iter()
                .map(|event| stringify(&Value::Object(event.clone()), None))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            write_new_file(&output, body.as_bytes(), 0o600)?;
            Ok(Some(json!({
                "tenantId": tenant_id,
                "output": crate::paths::display(&output),
                "count": events.len(),
                "firstSequence": events.first().and_then(|event| event.get("sequence").cloned()).unwrap_or(Value::Null),
                "lastSequence": events.last().and_then(|event| event.get("sequence").cloned()).unwrap_or(Value::Null),
                "head": head.as_ref().map_or(Value::Null, head_summary),
            })))
        })
        // One line, as scripts that read this output by line have always received it.
        .default_format(OutputFormat::Compact)
        .group("Audit")
        .description(
            "audit-export writes a tenant's audit chain as JSON Lines for archiving (never overwriting a file); it records nothing.",
        )
        .target(CommandTarget::Config)
        .flag("tenant", tenant())
        .flag(
            "output",
            FlagSpec::string("The .jsonl file to create (it must not exist)").value("PATH").required(),
        ),
        define_command("audit-prune", "Delete a tenant's archived audit events past retention", |context| async move {
            let flags = &context.flags;
            let input = json!({
                "tenantId": flags.string("tenant").unwrap_or_default(),
                "retentionMs": flags.integer("retention-days").unwrap_or(365) * 86_400_000,
            });
            Ok(Some(context.iam()?.prune_audit(&input).await?))
        })
        // One line, as scripts that read this output by line have always received it.
        .default_format(OutputFormat::Compact)
        .group("Audit")
        .description(
            "audit-prune deletes a tenant's events older than --retention-days (365) after you archived them and appends an audit:prune checkpoint so the remaining chain still verifies. With an auditArchive configured, it only deletes events the archive already holds.",
        )
        .target(CommandTarget::Config)
        .flag("tenant", tenant())
        .flag(
            "retention-days",
            FlagSpec::integer("Keep events newer than this many days")
                .min(0)
                .max(36500)
                .default_number(365)
                // Deletes audit history: only `cli.defaults['audit-prune']` may change it, never a shared '*' default.
                .no_wildcard_default(),
        ),
        define_command("audit-archive", "Copy new audit events to the configured archive", |context| async move {
            let flags = &context.flags;
            let input = object(vec![
                ("tenantId", flags.string("tenant").map(Value::from)),
                ("limit", flags.integer("limit").map(Value::from)),
            ]);
            let result = context.iam()?.archive_audit(Some(&input)).await?;
            context.print(&result)?;
            let failed = result.get("failed").and_then(Value::as_array).cloned().unwrap_or_default();
            if !failed.is_empty() {
                let listed: Vec<String> = failed
                    .iter()
                    .map(|failure| {
                        format!(
                            "{} ({})",
                            better_iam_server::js::js_string(failure.get("tenantId")),
                            better_iam_server::js::js_string(failure.get("code"))
                        )
                    })
                    .collect();
                return Err(IamError::new(
                    "AUDIT_ARCHIVE_FAILED",
                    format!("{} tenant(s) could not be archived: {}", failed.len(), listed.join(", ")),
                )
                .into());
            }
            Ok(None)
        })
        .group("Audit")
        .description(
            "audit-archive copies new audit events, verified and in chain order, to the configured auditArchive; with an archive configured, audit-prune only deletes events it already holds.",
        )
        .target(CommandTarget::Config)
        .flag("tenant", FlagSpec::string("Only this tenant (default: all)").value("TENANT_ID"))
        .flag("limit", FlagSpec::integer("Most events archived per tenant and run").min(1)),
        define_command("audit-verify-archive", "Verify an archived audit chain from its files alone", |context| async move {
            let flags = &context.flags;
            let tenant_id = flags.string("tenant").unwrap_or_default().to_owned();
            if !TENANT_FILE.is_match(&tenant_id) || tenant_id.starts_with('.') {
                return Err(usage_error("Tenant id is not a safe file name", None));
            }
            let folder = crate::paths::resolve_path(
                &context.path(flags.string("directory").unwrap_or_default()),
                std::path::Path::new(&tenant_id),
            );
            let mut files: Vec<String> = std::fs::read_dir(&folder)
                .map_err(|error| io_error(&error, "scandir", &folder))?
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| ARCHIVE_FILE.is_match(name))
                .collect();
            files.sort();
            // Files can overlap after a crash; each sequence must then carry the identical event.
            let mut by_sequence: IndexMap<String, (Record, String)> = IndexMap::new();
            let mut conflicts = 0usize;
            for name in &files {
                let path = folder.join(name);
                let text = std::fs::read_to_string(&path).map_err(|error| io_error(&error, "open", &path))?;
                for line in text.split('\n') {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let event = match js::parse(line) {
                        Ok(Value::Object(event)) => event,
                        Ok(_) => return Err(CliError::unknown(
                            format!("{name} holds a line that is not an audit event"),
                            line.chars().take(80).collect::<String>(),
                        )),
                        Err(error) => return Err(CliError::unknown(format!("{error}"), format!("{name}: {error}"))),
                    };
                    let key = event.get("sequence").map_or_else(|| "undefined".to_owned(), |value| stringify(value, None));
                    match by_sequence.get(&key) {
                        Some((_, seen)) if seen != line => conflicts += 1,
                        Some(_) => {}
                        None => {
                            by_sequence.insert(key, (event, line.to_owned()));
                        }
                    }
                }
            }
            let events: Vec<Record> = by_sequence.into_values().map(|(event, _)| event).collect();
            let verification = verify_audit_chain(&events, &VerifyAuditChainOptions::default());
            let mut report = Map::new();
            report.insert("tenantId".into(), Value::String(tenant_id.clone()));
            report.insert("files".into(), Value::from(files.len()));
            report.insert("conflicts".into(), Value::from(conflicts));
            if let Value::Object(members) = to_json(&verification)? {
                report.extend(members);
            }
            context.print(&Value::Object(report))?;
            // An archive with nothing in it proves nothing: a CI gate must not pass on an empty or misnamed directory.
            if events.is_empty() {
                return Err(IamError::new(
                    "AUDIT_ARCHIVE_INVALID",
                    format!("No archived events of {tenant_id} were found"),
                )
                .into());
            }
            if !verification.valid || conflicts > 0 {
                let message = if conflicts > 0 {
                    format!("{conflicts} archived event(s) disagree with another copy of the same sequence")
                } else {
                    let failure = to_json(&verification.failure)?;
                    format!(
                        "The archived chain does not verify ({} at sequence {})",
                        better_iam_server::js::js_string(failure.get("reason")),
                        better_iam_server::js::js_string(failure.get("sequence"))
                    )
                };
                return Err(IamError::new("AUDIT_ARCHIVE_INVALID", message).into());
            }
            Ok(None)
        })
        .group("Audit")
        .description(
            "audit-verify-archive verifies one tenant's archived chain from createJsonlAuditArchive files alone, without the database: every sequence present once, hashes recomputed, links intact.",
        )
        .usage("better-iam audit-verify-archive --directory /var/lib/better-iam/audit --tenant TENANT_ID")
        .flag(
            "directory",
            FlagSpec::string("The archive directory (createJsonlAuditArchive)").value("PATH").required(),
        )
        .flag("tenant", tenant().description("The tenant whose archive to verify")),
    ]
}
