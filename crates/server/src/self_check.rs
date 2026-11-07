//! Port of `packages/server/src/self-check.ts`: `iam.selfCheck()`, the read-only deployment health check.

use std::sync::{Arc, LazyLock};

use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, OrderOptions, Record, SqlDialect, StoreDescription,
    find_ordered, schema_migrations,
};
use indexmap::IndexSet;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::ServerContext;
use crate::port::Callback;

/// What `countDue` needs to judge the sweep backlog the way the scheduled sweep would.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DueOptions {
    #[serde(rename = "cap")]
    pub cap: f64,
    #[serde(
        rename = "deliveryRetentionMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub delivery_retention_ms: Option<f64>,
    #[serde(rename = "graceMs", default, skip_serializing_if = "Option::is_none")]
    pub grace_ms: Option<f64>,
    /// Count only records due for at least this long, so a sweep on schedule never shows a backlog.
    #[serde(rename = "overdueMs")]
    pub overdue_ms: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

const MINUTE: f64 = 60_000.0;
const DAY: f64 = 86_400_000.0;
/// A sweep scheduled at least daily leaves nothing due for this long.
const SWEEP_OVERDUE_MS: f64 = 2.0 * DAY;
/// `PLACEHOLDER` (case-insensitive in TypeScript, for ASCII letters only: the secret is lowercased in ASCII first).
static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"change[-_ ]?me|replace[-_ ]?me|example|placeholder|^(?:secret|password)")
        .expect("valid placeholder pattern")
});

/// Checks a running deployment for configuration and storage problems an operator should act on: a schema behind
/// this release, a platform never bootstrapped, a guessable secret, settings that lose data (an in-memory database,
/// SQLite durability that can corrupt, PostgreSQL asynchronous commit), missing delivery transports, and scheduled
/// jobs that are not running (records `sweep` or `purge` would remove, stalled outbox and audit hook deliveries).
/// It only reads.
pub fn create_self_check(
    ctx: &Arc<ServerContext>,
    count_due: Callback,
    sample_secrets: Callback,
) -> IamResult<SelfCheck> {
    Ok(SelfCheck {
        ctx: ctx.clone(),
        count_due,
        sample_secrets,
    })
}

/// `selfCheck(options)`: the function `createSelfCheck` returns (`iam.selfCheck`).
pub struct SelfCheck {
    ctx: Arc<ServerContext>,
    /// `retention.countDue(options)`: JSON options in, the counts by collection out.
    count_due: Callback,
    /// `(limit) => rotateSecrets({ dryRun: true, limit })`: the limit in, the rotation report out.
    sample_secrets: Callback,
}

/// One finding (`SelfCheckFinding`).
fn finding(check: &str, severity: &str, message: String, fix: &str, count: Option<f64>) -> Value {
    let mut out = Map::new();
    out.insert("check".into(), Value::String(check.to_owned()));
    out.insert("severity".into(), Value::String(severity.to_owned()));
    out.insert("message".into(), Value::String(message));
    out.insert("fix".into(), Value::String(fix.to_owned()));
    if let Some(count) = count {
        out.insert("count".into(), crate::js::number(count));
    }
    Value::Object(out)
}

/// `{ ok, findings, storage }` (`SelfCheckResult`).
fn result(findings: Vec<Value>, storage: &Option<StoreDescription>) -> IamResult<Value> {
    let ok = !findings
        .iter()
        .any(|finding| finding.get("severity").and_then(Value::as_str) == Some("error"));
    let storage = match storage {
        Some(description) => {
            serde_json::to_value(description).map_err(|_| crate::js::internal_error())?
        }
        None => Value::Null,
    };
    Ok(json!({ "ok": ok, "findings": findings, "storage": storage }))
}

/// The counts of a JSON object of numbers (`Record<string, number>`), in member order.
fn counts(value: Option<&Value>) -> Vec<(String, f64)> {
    match value {
        Some(Value::Object(map)) => better_iam_core::js::entries(map)
            .into_iter()
            .map(|(key, count)| {
                (
                    key.clone(),
                    better_iam_core::js::as_number(count).unwrap_or(f64::NAN),
                )
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// `Object.values(counts).reduce((sum, count) => sum + count, 0)`.
fn total(entries: &[(String, f64)]) -> f64 {
    entries.iter().map(|(_, count)| *count).sum()
}

/// `${collection}: ${count}` joined with `, `.
fn listing(entries: &[(String, f64)]) -> String {
    entries
        .iter()
        .map(|(collection, count)| {
            format!(
                "{collection}: {}",
                better_iam_core::js::number_to_string(*count)
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `${count >= cap ? `${cap}+` : count}`.
fn capped(count: f64, cap: f64) -> String {
    if count >= cap {
        format!("{}+", better_iam_core::js::number_to_string(cap))
    } else {
        better_iam_core::js::number_to_string(count)
    }
}

/// An optional option that must be a safe integer between 0 and `max`.
fn optional_integer(options: Option<&Value>, name: &str, max: f64) -> IamResult<Option<f64>> {
    match crate::js::member(options, name) {
        None => Ok(None),
        Some(value) => match better_iam_core::js::as_number(value) {
            Some(number)
                if better_iam_core::js::is_safe_integer(number)
                    && number >= 0.0
                    && number <= max =>
            {
                Ok(Some(number))
            }
            _ => Err(IamError::new(
                "INVALID_INPUT",
                format!(
                    "{name} must be an integer between 0 and {}",
                    better_iam_core::js::number_to_string(max)
                ),
            )),
        },
    }
}

fn number_of(record: &Record, key: &str) -> Option<f64> {
    record.get(key).and_then(better_iam_core::js::as_number)
}

impl SelfCheck {
    /// `selfCheck(options = {})`: the findings (`SelfCheckResult` as JSON).
    pub async fn run(&self, options: Option<&Value>) -> IamResult<Value> {
        let cap = match crate::js::member(options, "cap") {
            None => 1000.0,
            Some(value) => match better_iam_core::js::as_number(value) {
                Some(number)
                    if better_iam_core::js::is_safe_integer(number)
                        && (1.0..=100_000.0).contains(&number) =>
                {
                    number
                }
                _ => {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "cap must be an integer between 1 and 100000",
                    ));
                }
            },
        };
        let delivery_retention_ms = optional_integer(options, "deliveryRetentionMs", 3650.0 * DAY)?;
        let grace_ms = optional_integer(options, "graceMs", DAY)?;
        let ctx = &self.ctx;
        let settings = &ctx.options;
        let store = &ctx.store;
        let mut findings: Vec<Value> = Vec::new();
        let now = ctx.now();

        // --- storage ---------------------------------------------------------------------------
        let storage: Option<StoreDescription> = if store.has_describe() {
            Some(store.describe().await?)
        } else {
            None
        };
        match &storage {
            Some(description) => {
                let applied: IndexSet<&str> = description
                    .migrations
                    .iter()
                    .map(|migration| migration.name.as_str())
                    .collect();
                let missing: Vec<String> = schema_migrations(SqlDialect::Sqlite)
                    .into_iter()
                    .map(|migration| migration.name)
                    .filter(|name| !applied.contains(name.as_str()))
                    .collect();
                if description.schema_version.is_none() || !missing.is_empty() {
                    findings.push(finding(
                        "schema-behind",
                        "error",
                        if description.schema_version.is_none() {
                            "The database has no IAM schema".to_owned()
                        } else {
                            format!("Schema migrations not applied: {}", missing.join(", "))
                        },
                        "Run `better-iam migrate` (or `iam.initialize()`) before serving traffic",
                        None,
                    ));
                }
                let values = &description.settings;
                if values.get("inMemory") == Some(&Value::Bool(true))
                    || values.get("location").and_then(Value::as_str) == Some("memory")
                {
                    findings.push(finding(
                        "in-memory-database",
                        "warning",
                        "The database lives in memory; everything is lost when the process exits"
                            .to_owned(),
                        "Configure a file or server database for anything but tests",
                        None,
                    ));
                }
                let synchronous = values.get("synchronous").and_then(Value::as_str);
                if description.adapter == "sqlite"
                    && values.get("inMemory") == Some(&Value::Bool(false))
                    && values.get("journalMode").and_then(Value::as_str) == Some("delete")
                    && matches!(synchronous, Some("normal") | Some("off"))
                {
                    findings.push(finding(
                        "sqlite-durability",
                        "error",
                        format!(
                            "SQLite runs a rollback journal with synchronous={}, which a power failure can corrupt",
                            synchronous.unwrap_or_default()
                        ),
                        "Use `durability: 'full'`, or WAL mode (the default journalMode)",
                        None,
                    ));
                }
                if values.get("synchronousCommit").and_then(Value::as_str) == Some("off") {
                    findings.push(finding(
                        "postgres-async-commit",
                        "warning",
                        "PostgreSQL synchronous_commit is off: a crash can lose recently committed changes"
                            .to_owned(),
                        "Set synchronous_commit to on (or remote_apply with replicas) for the IAM database",
                        None,
                    ));
                }
            }
            None => findings.push(finding(
                "storage-undescribed",
                "info",
                "The storage adapter cannot describe its schema, so migrations were not checked"
                    .to_owned(),
                "Implement `IamStore.describe()` in the adapter",
                None,
            )),
        }

        // --- platform ----------------------------------------------------------------------------
        let schema_missing = storage
            .as_ref()
            .is_some_and(|description| description.schema_version.is_none());
        if !schema_missing {
            let roots = store
                .find(
                    "tenants",
                    &Filter::new().eq("parentId", Value::Null),
                    &FindOptions {
                        limit: Some(2),
                        ..FindOptions::default()
                    },
                )
                .await?;
            if roots.is_empty() {
                findings.push(finding(
                    "not-bootstrapped",
                    "error",
                    "No root tenant exists yet".to_owned(),
                    "Run `better-iam bootstrap` with BETTER_IAM_ROOT_EMAIL and BETTER_IAM_ROOT_PASSWORD",
                    None,
                ));
            }
        }
        let secret = &settings.secret;
        // Random hex, base64, or UUID secrets of the required length use far more than 8 characters.
        let variety = secret.chars().collect::<IndexSet<char>>().len();
        if variety < 8 || PLACEHOLDER.is_match(&secret.to_ascii_lowercase()) {
            findings.push(finding(
                "weak-secret",
                "warning",
                "The deployment secret looks like a placeholder or has little variety".to_owned(),
                "Use a random value, for example `openssl rand -base64 48`, kept in a secret store",
                None,
            ));
        }
        let metrics_token = settings.observability.as_ref().and_then(|observability| {
            match &observability.metrics {
                Some(crate::options::Toggle::Options(metrics)) => metrics.bearer_token.clone(),
                _ => None,
            }
        });
        if metrics_token
            .as_deref()
            .is_some_and(|token| better_iam_core::js::utf16_len(token) < 24)
        {
            findings.push(finding(
                "weak-metrics-token",
                "warning",
                "The metrics bearer token is shorter than 24 characters".to_owned(),
                "Use a random token of at least 24 characters",
                None,
            ));
        }
        if !settings
            .authentication
            .as_ref()
            .is_some_and(|authentication| authentication.send_email.is_some())
        {
            findings.push(finding(
                "no-email-transport",
                "warning",
                "No email transport: invitations, password resets, and verification emails cannot be sent"
                    .to_owned(),
                "Configure `authentication.sendEmail`",
                None,
            ));
        }

        if schema_missing {
            return result(findings, &storage);
        }

        // --- sealed values ----------------------------------------------------------------------
        // A secret changed without listing the old one in `previousSecrets` silently breaks every authenticator app
        // and webhook signature; a sample of the stored values shows it.
        let sealed = (self.sample_secrets)(vec![crate::js::number(cap)]).await?;
        let unreadable_counts = counts(sealed.get("unreadable"));
        let unreadable = total(&unreadable_counts);
        if unreadable != 0.0 {
            findings.push(finding(
                "unreadable-secrets",
                "error",
                format!(
                    "{} stored secret value(s) open with no configured secret ({}); the deployment secret was probably changed without previousSecrets",
                    better_iam_core::js::number_to_string(unreadable),
                    listing(&unreadable_counts)
                ),
                "Put the old secret in `previousSecrets`, run `better-iam rotate-secrets`, then remove it",
                Some(unreadable),
            ));
        }
        let pending = total(&counts(sealed.get("resealed")));
        if pending != 0.0 {
            findings.push(finding(
                "secret-rotation-pending",
                "warning",
                format!(
                    "{} stored secret value(s) are still sealed with a previous secret",
                    better_iam_core::js::number_to_string(pending)
                ),
                "Run `better-iam rotate-secrets` (or `iam.rotateSecrets()`) until it reports `done: true`, then remove `previousSecrets` a day later",
                Some(pending),
            ));
        } else if settings
            .previous_secrets
            .as_ref()
            .is_some_and(|previous| !previous.is_empty())
        {
            if crate::js::truthy(sealed.get("complete")) {
                findings.push(finding(
                    "previous-secrets-configured",
                    "info",
                    "previousSecrets is set, and no stored value needs it any more".to_owned(),
                    "A day after the rotation (pending links and assertions), remove `previousSecrets` and give downstream verifiers only `iam.assertionKey()`",
                    None,
                ));
            } else {
                // The sample covers the first records only, which a rotation also re-seals first.
                findings.push(finding(
                    "secret-rotation-unverified",
                    "warning",
                    format!(
                        "previousSecrets is set; no value in a sample of {} per collection needs it, but not every record was examined",
                        better_iam_core::js::number_to_string(cap)
                    ),
                    "Run `better-iam rotate-secrets --dry-run` and remove `previousSecrets` only when it reports `done: true`",
                    None,
                ));
            }
        }

        // --- scheduled jobs ----------------------------------------------------------------------
        // Judged by age, with the sweep's own settings: a sweep that runs at least daily leaves nothing that has been
        // due for two days, however busy the deployment is.
        let mut due_options = Map::new();
        due_options.insert("cap".into(), crate::js::number(cap));
        if let Some(delivery_retention_ms) = delivery_retention_ms {
            due_options.insert(
                "deliveryRetentionMs".into(),
                crate::js::number(delivery_retention_ms),
            );
        }
        if let Some(grace_ms) = grace_ms {
            due_options.insert("graceMs".into(), crate::js::number(grace_ms));
        }
        due_options.insert("overdueMs".into(), crate::js::number(SWEEP_OVERDUE_MS));
        let due_counts = (self.count_due)(vec![Value::Object(due_options)]).await?;
        let due = counts(Some(&due_counts));
        let backlog = cap.min(total(&due));
        if backlog != 0.0 {
            let listed: Vec<(String, f64)> = due
                .iter()
                .filter(|(_, count)| *count != 0.0 && !count.is_nan())
                .cloned()
                .collect();
            findings.push(finding(
                "sweep-backlog",
                "warning",
                format!(
                    "{} record(s) have been due for the retention sweep for more than two days ({})",
                    capped(backlog, cap),
                    listing(&listed)
                ),
                "Schedule `better-iam sweep` (or `iam.sweepExpired()`) hourly or daily, with a `limit` that keeps up",
                Some(backlog),
            ));
        }
        let mut lapsed = 0usize;
        for collection in ["bindings", "groupMembers", "authChallenges"] {
            lapsed += find_ordered(
                store.as_ref(),
                collection,
                &Filter::new(),
                &OrderOptions {
                    to: Some(now - DAY),
                    limit: Some(1),
                    ..OrderOptions::by("expiresAt")
                },
                None,
            )
            .await?
            .len();
        }
        if lapsed != 0 {
            findings.push(finding(
                "purge-not-running",
                "warning",
                "Expired bindings, memberships, or challenges are more than a day old".to_owned(),
                "Schedule `better-iam purge` (or `iam.purgeDeleted()`) at least daily",
                None,
            ));
        }
        let limit = Some(cap as i64);
        let stalled = find_ordered(
            store.as_ref(),
            "outbox",
            &Filter::new().absent("deliveredAt").absent("failedAt"),
            &OrderOptions {
                to: Some(now - 15.0 * MINUTE),
                limit,
                ..OrderOptions::by("createdAt")
            },
            None,
        )
        .await?
        .len() as f64;
        if stalled != 0.0 {
            findings.push(finding(
                "outbox-stalled",
                "warning",
                format!(
                    "{} outgoing message(s) have waited more than 15 minutes",
                    capped(stalled, cap)
                ),
                "Schedule `better-iam outbox` (or `iam.auth.dispatchOutbox()`) every minute, and check the delivery callbacks",
                Some(stalled),
            ));
        }
        let abandoned = find_ordered(
            store.as_ref(),
            "outbox",
            &Filter::new(),
            &OrderOptions {
                from: Some(now - DAY),
                limit,
                ..OrderOptions::by("failedAt")
            },
            None,
        )
        .await?
        .len() as f64;
        if abandoned != 0.0 {
            findings.push(finding(
                "outbox-abandoned",
                "warning",
                format!(
                    "{} outgoing message(s) were abandoned in the last day after repeated failures",
                    better_iam_core::js::number_to_string(abandoned)
                ),
                "Check the email, SMS, and webhook delivery callbacks and their `lastError`",
                Some(abandoned),
            ));
        }
        let hooks = store
            .find(
                "auditHooks",
                &Filter::new().eq("delivered", false),
                &FindOptions {
                    limit,
                    ..FindOptions::default()
                },
            )
            .await?;
        let waiting = hooks
            .iter()
            .filter(|row| {
                crate::js::member(row.get("event"), "timestamp")
                    .and_then(better_iam_core::js::as_number)
                    .is_some_and(|timestamp| timestamp <= now - 15.0 * MINUTE)
            })
            .count() as f64;
        if waiting != 0.0 {
            findings.push(finding(
                "audit-hooks-stalled",
                "warning",
                format!(
                    "{} audit event(s) have waited more than 15 minutes for plugins, subscribers, or onEvent",
                    better_iam_core::js::number_to_string(waiting)
                ),
                "Call `iam.dispatchAuditHooks()` every minute in the application process that registers event subscribers (the CLI `outbox` command serves only plugins and `events.onEvent`)",
                Some(waiting),
            ));
        }
        if settings.audit_archive.is_some() {
            // A tenant whose oldest unarchived event is over a day old: the archive job is not keeping up. Every
            // tenant is examined (a page of chain heads at a time); counting stops at `cap`.
            let mut behind = 0.0;
            let mut after: Option<String> = None;
            while behind < cap {
                let heads: Vec<Record> = store
                    .find(
                        "auditChains",
                        &Filter::new(),
                        &FindOptions {
                            limit: Some(500),
                            after: after.clone(),
                            ..FindOptions::default()
                        },
                    )
                    .await?;
                for head in &heads {
                    let head_id = head.get("id").and_then(Value::as_str).unwrap_or_default();
                    let cursor = store
                        .get("auditArchiveCursors", head_id)
                        .await?
                        .and_then(|cursor| number_of(&cursor, "sequence"))
                        .unwrap_or(0.0);
                    if number_of(head, "sequence").unwrap_or(f64::NAN) <= cursor {
                        continue;
                    }
                    let oldest = find_ordered(
                        store.as_ref(),
                        "audit",
                        &Filter::new().eq("tenantId", head_id),
                        &OrderOptions {
                            from: Some(cursor + 1.0),
                            limit: Some(1),
                            ..OrderOptions::by("sequence")
                        },
                        None,
                    )
                    .await?;
                    if oldest.first().is_some_and(|event| {
                        number_of(event, "timestamp")
                            .is_some_and(|timestamp| timestamp <= now - DAY)
                    }) {
                        behind += 1.0;
                    }
                    if behind >= cap {
                        break;
                    }
                }
                if heads.len() < 500 {
                    break;
                }
                after = heads
                    .last()
                    .and_then(|head| head.get("id"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
            if behind != 0.0 {
                findings.push(finding(
                    "audit-archive-behind",
                    "warning",
                    format!(
                        "{} tenant(s) have audit events older than a day that are not archived",
                        capped(behind, cap)
                    ),
                    "Schedule `better-iam audit-archive` (or `iam.archiveAudit()`) at least hourly, and check the sink for failures",
                    Some(behind),
                ));
            }
        }
        result(findings, &storage)
    }
}
