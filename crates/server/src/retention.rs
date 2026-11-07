//! Port of `packages/server/src/retention.ts`: the retention sweep that deletes records the rest of the system
//! already treats as dead, and the read-only backlog count `selfCheck` uses.

use std::sync::{Arc, Mutex};

use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, IamStoreExt, OrderOptions, Record, find_ordered,
    js as core_js,
};
use futures::future::BoxFuture;
use indexmap::IndexMap;
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::self_check::DueOptions;
use crate::utils::date_now;

const DAY: f64 = 86_400_000.0;

/// Session kinds whose expired records nothing reads: user sessions, role sessions (classic and web identity),
/// session tokens, and delegated agent sessions. API keys stay: they are listed as expired and can be renewed.
const SWEPT_SESSION_KINDS: &[&str] = &["user", "role", "session-token", "delegated"];

/// Expired OAuth Grant rows stay this long: an IAM session (at most 30 days) bound to the grant may end later, and
/// back-channel logout (`logoutEndedSessions`) finds the client through the row.
const GRANT_RETENTION_MS: f64 = 31.0 * DAY;

/// Due records that must stay anyway; the walk steps over them instead of reading them again.
type Keep = Arc<dyn Fn(&Record) -> bool + Send + Sync>;

struct SweepTarget {
    collection: &'static str,
    /// Equality filter; used only for legacy records that lack the indexed field.
    filter: Option<Filter>,
    /// The numeric field the collection-wide expiry indexes order by; absent for flag-only targets.
    field: Option<&'static str>,
    /// The newest field value that is due.
    cutoff: Option<f64>,
    keep: Option<Keep>,
}

impl SweepTarget {
    fn keeps(&self, record: &Record) -> bool {
        self.keep.as_ref().is_some_and(|keep| keep(record))
    }
}

/// `bounded(value, fallback, min, max, name)`: `value ?? fallback` as a safe integer within `[min, max]`.
fn bounded(value: Option<&Value>, fallback: f64, min: f64, max: f64, name: &str) -> IamResult<f64> {
    let resolved = match value {
        None | Some(Value::Null) => Some(fallback),
        Some(value) => core_js::as_number(value),
    };
    match resolved {
        Some(resolved)
            if core_js::is_safe_integer(resolved) && resolved >= min && resolved <= max =>
        {
            Ok(resolved)
        }
        _ => Err(IamError::new(
            "INVALID_INPUT",
            format!(
                "{name} must be an integer between {} and {}",
                core_js::number_to_string(min),
                core_js::number_to_string(max)
            ),
        )),
    }
}

/// [`bounded`] for an already typed optional number.
fn bounded_number(
    value: Option<f64>,
    fallback: f64,
    min: f64,
    max: f64,
    name: &str,
) -> IamResult<f64> {
    match value {
        None => bounded(None, fallback, min, max, name),
        Some(value) => match core_js::number(value) {
            Some(json) => bounded(Some(&json), fallback, min, max, name),
            // NaN and the infinities are numbers but never safe integers.
            None => bounded(Some(&Value::Bool(false)), fallback, min, max, name),
        },
    }
}

fn expired(collection: &'static str, now: f64, grace: f64, keep: Option<Keep>) -> SweepTarget {
    SweepTarget {
        collection,
        filter: None,
        field: Some("expiresAt"),
        cutoff: Some(now - grace),
        keep,
    }
}

fn number_member(record: &Record, key: &str) -> Option<f64> {
    record.get(key).and_then(core_js::as_number)
}

/// The sweep's targets for one run; also what `countDue` counts.
///
/// The sweep deletes records the rest of the system already treats as dead, so storage stops growing with traffic,
/// and never removes anything a person or report can still use: expired user and role sessions and session tokens
/// (API keys stay), trusted devices, relationship tuples, redeemed web-identity tokens, OAuth artifacts (grants 31
/// days after expiry) and login states, SAML request, relay-state and replay records, delivered or abandoned
/// deliveries older than the delivery retention, dispatched audit hook rows, and lapsed guest invitations 90 days on.
fn sweep_targets(
    ctx: &ServerContext,
    now: Option<f64>,
    retention: f64,
    grace: f64,
) -> Vec<SweepTarget> {
    let app_now = now.unwrap_or_else(|| ctx.now());
    let wall_now = now.unwrap_or_else(date_now);
    let app = |collection: &'static str| expired(collection, app_now, grace, None);
    let wall = |collection: &'static str| expired(collection, wall_now, grace, None);
    vec![
        expired(
            "sessions",
            app_now,
            grace,
            Some(Arc::new(|record: &Record| {
                !record
                    .get("kind")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| SWEPT_SESSION_KINDS.contains(&kind))
            })),
        ),
        app("authDevices"),
        app("relationships"),
        // Written on the authentication clock (the exchange verifies tokens against ctx.now()).
        app("webIdentityReplays"),
        expired(
            "oauthArtifacts",
            wall_now,
            grace,
            Some(Arc::new(move |record: &Record| {
                record.get("model").and_then(Value::as_str) == Some("Grant")
                    && number_member(record, "expiresAt")
                        .is_some_and(|expires| expires > wall_now - GRANT_RETENTION_MS)
            })),
        ),
        wall("oauthLoginStates"),
        wall("samlRequests"),
        wall("samlRelays"),
        wall("samlAssertions"),
        // Inference metering (inference.ts): usage records past `inference.usageRetentionDays`, budget counters 35
        // days after their window, and unredeemed gateway tickets.
        app("inferenceUsage"),
        app("inferenceCounters"),
        app("inferenceTickets"),
        // Responses API ownership records, kept as long as usage records.
        app("inferenceResponses"),
        // Agent confirmation requests past their decision window or approval validity (delegations.ts).
        app("delegationConfirmations"),
        // Issued delegation tokens past their expiry (delegation-tokens.ts).
        app("delegationTokens"),
        // Agent directory entries whose attestation has expired (api/agents.ts).
        app("agentCards"),
        // Team memberships past their end (teams.ts); the backing group's copy lapsed with them.
        app("teamMembers"),
        // Vault access records past `vault.accessRetentionDays` (vault.ts).
        app("vaultAccess"),
        // Quota window counters a day after their window, and idle throttle buckets once full again (quotas.ts).
        app("quotaCounters"),
        // Data-subject request exports past their download window (api/privacy.ts).
        app("privacyExports"),
        // Finished workflow runs 180 days after they ended (api/workflows.ts); active runs carry no expiry.
        app("workflowRuns"),
        // Compliance results and runs 400 days after their evaluation (api/compliance.ts).
        app("complianceResults"),
        app("complianceRuns"),
        // Compliance exceptions (revoked ones too) 400 days after they expired, so evidence packs keep their history.
        expired(
            "complianceExceptions",
            app_now,
            grace,
            Some(Arc::new(move |record: &Record| {
                number_member(record, "expiresAt")
                    .is_some_and(|expires| expires > app_now - 400.0 * 86_400_000.0)
            })),
        ),
        // App assignments past their end (api/applications.ts).
        app("appAssignments"),
        // SSH certificate records `ssh.recordRetentionDays` after the certificate expired (ssh.ts).
        app("sshCertificates"),
        // Verifiable credential records past their retention, used or lapsed wallet offers, and proof nonces (vc.ts).
        app("vcIssued"),
        app("vcOffers"),
        app("vcNonces"),
        // Device enrollment codes past their expiry, used or not (devices.ts).
        app("deviceEnrollments"),
        // Received Shared Signals events 90 days after receipt (signal-receiver.ts).
        app("signalEvents"),
        // License pools 400 days after their term ended (licenses.ts).
        app("licensePools"),
        // Guest invitations 90 days after they lapsed, once redeemed, revoked or expired (guests.ts); a pending one
        // waits for `iam.guests.sweep`, and the audit trail keeps every invitation.
        SweepTarget {
            collection: "guestInvitations",
            filter: None,
            field: Some("expiresAt"),
            cutoff: Some(app_now - 90.0 * DAY),
            keep: Some(Arc::new(|record: &Record| {
                record.get("status").and_then(Value::as_str) == Some("pending")
            })),
        },
        SweepTarget {
            collection: "outbox",
            filter: None,
            field: Some("deliveredAt"),
            cutoff: Some(app_now - retention),
            keep: None,
        },
        SweepTarget {
            collection: "outbox",
            filter: None,
            field: Some("failedAt"),
            cutoff: Some(app_now - retention),
            keep: None,
        },
        SweepTarget {
            collection: "ssfDeliveries",
            filter: None,
            field: Some("failedAt"),
            cutoff: Some(wall_now - retention),
            keep: None,
        },
        SweepTarget {
            collection: "auditHooks",
            filter: None,
            field: Some("deliveredAt"),
            cutoff: Some(app_now - grace),
            keep: None,
        },
        // Rows written before these timestamps existed: not indexed, but a shrinking set.
        SweepTarget {
            collection: "ssfDeliveries",
            filter: Some(Filter::new().eq("status", "failed").absent("failedAt")),
            field: Some("createdAt"),
            cutoff: Some(wall_now - retention),
            keep: None,
        },
        SweepTarget {
            collection: "auditHooks",
            filter: Some(Filter::new().eq("delivered", true).absent("deliveredAt")),
            field: None,
            cutoff: None,
            keep: None,
        },
    ]
}

/// What `act` returns for one batch: the records it left in place, and whether the walk should stop.
struct Acted {
    survivors: Vec<Record>,
    stop: bool,
}

type Act = Arc<dyn Fn(Store, Vec<Record>) -> BoxFuture<'static, IamResult<Acted>> + Send + Sync>;

/// Two field values are the same (`===`): numbers by value, anything else structurally.
fn same(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (
        left.and_then(core_js::as_number),
        right.and_then(core_js::as_number),
    ) {
        (Some(left), Some(right)) => left == right,
        _ => left.is_some() && left == right,
    }
}

/// Walks one target's due records oldest first, a batch at a time. `act` receives each batch (inside a transaction
/// when deleting) and returns the records it left in place; the walk steps over those by moving its lower bound
/// (`from`) and skipping the ones at the bound, so nothing is read twice. Stops when the target is exhausted or
/// `act` returns `stop`.
async fn walk(
    store: &Store,
    target: &SweepTarget,
    batch_size: &(dyn Fn() -> f64 + Send + Sync),
    act: Act,
    transactional: bool,
) -> IamResult<bool> {
    let mut from: Option<f64> = None;
    let mut skip: usize = 0;
    let everything = Filter::new();
    loop {
        let size = batch_size();
        if size == 0.0 {
            return Ok(false);
        }
        let filter = target.filter.as_ref().unwrap_or(&everything);
        let step = |reader: Store| {
            let act = act.clone();
            async move {
                let read: Vec<Record> = match target.field {
                    None => {
                        reader
                            .find(
                                target.collection,
                                filter,
                                &FindOptions {
                                    offset: Some(skip as i64),
                                    limit: Some(size as i64),
                                    after: None,
                                },
                            )
                            .await?
                    }
                    Some(field) => {
                        find_ordered(
                            reader.as_ref(),
                            target.collection,
                            filter,
                            &OrderOptions {
                                field: field.to_owned(),
                                from,
                                to: target.cutoff,
                                offset: Some(skip as i64),
                                limit: Some(size as i64),
                                ..OrderOptions::default()
                            },
                            None,
                        )
                        .await?
                    }
                };
                let acted = act(reader, read.clone()).await?;
                Ok::<_, IamError>((read, acted))
            }
        };
        // Deleting: each batch reads and deletes in one short transaction, so a record renewed between batches is
        // judged again on its current state.
        let (read, acted) = if transactional {
            store.transaction(step).await?
        } else {
            step(store.clone()).await?
        };
        if (read.len() as f64) < size {
            return Ok(true);
        }
        if acted.stop {
            return Ok(false);
        }
        let Some(field) = target.field else {
            skip += acted.survivors.len();
            continue;
        };
        let last = read.last().and_then(|record| record.get(field)).cloned();
        let at_last = acted
            .survivors
            .iter()
            .filter(|record| same(record.get(field), last.as_ref()))
            .count();
        let last_number = last.as_ref().and_then(core_js::as_number);
        if from.is_some() && from == last_number {
            skip += at_last;
        } else {
            from = last_number;
            skip = at_last;
        }
    }
}

/// The running `SweepResult` of one sweep, and the records it may still delete.
#[derive(Default)]
struct SweepState {
    deleted: IndexMap<String, f64>,
    total: f64,
    truncated: bool,
    remaining: f64,
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub struct Retention {
    ctx: Arc<ServerContext>,
}

/// `createRetention(ctx)`.
pub fn create_retention(ctx: &Arc<ServerContext>) -> IamResult<Retention> {
    Ok(Retention { ctx: ctx.clone() })
}

impl Retention {
    /// `sweepExpired(options = {})`: deletes expired sessions, protocol artifacts, and old delivery records. Returns
    /// `{ deleted, total, truncated }`.
    pub async fn sweep_expired(&self, options: Option<&Value>) -> IamResult<Value> {
        let empty = Map::new();
        let options = match options {
            None => &empty,
            Some(Value::Object(options)) => options,
            // Reading a member of null throws a TypeError in TypeScript.
            Some(Value::Null) => return Err(crate::js::internal_error()),
            Some(_) => &empty,
        };
        let now = match options.get("now") {
            None => None,
            Some(value) => match core_js::as_number(value) {
                Some(now) if now.is_finite() => Some(now),
                _ => {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "now must be a finite number of milliseconds",
                    ));
                }
            },
        };
        let batch_size = bounded(options.get("batchSize"), 500.0, 1.0, 5000.0, "batchSize")?;
        let limit = bounded(options.get("limit"), 10_000.0, 1.0, 1_000_000.0, "limit")?;
        let retention = bounded(
            options.get("deliveryRetentionMs"),
            30.0 * DAY,
            0.0,
            3650.0 * DAY,
            "deliveryRetentionMs",
        )?;
        let grace = bounded(options.get("graceMs"), 5.0 * 60_000.0, 0.0, DAY, "graceMs")?;
        let state = Arc::new(Mutex::new(SweepState {
            remaining: limit,
            ..SweepState::default()
        }));
        for target in sweep_targets(&self.ctx, now, retention, grace) {
            let target = Arc::new(target);
            let size_state = state.clone();
            let batch = move || batch_size.min(locked(&size_state).remaining);
            let act_state = state.clone();
            let act_target = target.clone();
            let act: Act = Arc::new(move |tx: Store, records: Vec<Record>| {
                let state = act_state.clone();
                let target = act_target.clone();
                Box::pin(async move {
                    let mut survivors = Vec::new();
                    for record in &records {
                        if target.keeps(record) {
                            survivors.push(record.clone());
                        } else {
                            tx.delete(target.collection, better_iam_core::record_id(record))
                                .await?;
                        }
                    }
                    let deleted = (records.len() - survivors.len()) as f64;
                    if deleted > 0.0 {
                        let mut state = locked(&state);
                        *state
                            .deleted
                            .entry(target.collection.to_owned())
                            .or_insert(0.0) += deleted;
                        state.total += deleted;
                        state.remaining -= deleted;
                    }
                    Ok(Acted {
                        survivors,
                        stop: false,
                    })
                })
            });
            let finished = walk(&self.ctx.store, &target, &batch, act, true).await?;
            if !finished {
                locked(&state).truncated = true;
                break;
            }
        }
        let state = locked(&state);
        let deleted: Map<String, Value> = state
            .deleted
            .iter()
            .map(|(collection, count)| (collection.clone(), crate::js::number(*count)))
            .collect();
        Ok(json!({
            "deleted": deleted,
            "total": crate::js::number(state.total),
            "truncated": state.truncated,
        }))
    }

    /// Records a sweep with these settings would delete that have been due for at least `overdueMs`, per collection,
    /// counting at most `cap` per collection. Reads only; `selfCheck` uses it to spot a sweep that is not running or
    /// not keeping up.
    pub async fn count_due(&self, options: &DueOptions) -> IamResult<IndexMap<String, f64>> {
        let cap = options.cap;
        let retention = bounded_number(
            options.delivery_retention_ms,
            30.0 * DAY,
            0.0,
            3650.0 * DAY,
            "deliveryRetentionMs",
        )?;
        let grace = bounded_number(options.grace_ms, 5.0 * 60_000.0, 0.0, DAY, "graceMs")?;
        let counts: Arc<Mutex<IndexMap<String, f64>>> = Arc::new(Mutex::new(IndexMap::new()));
        for mut target in sweep_targets(&self.ctx, None, retention, grace) {
            if let Some(cutoff) = target.cutoff.as_mut() {
                *cutoff -= options.overdue_ms;
            }
            let target = Arc::new(target);
            let collection = target.collection;
            let seen = {
                let counts = counts.clone();
                move || locked(&counts).get(collection).copied().unwrap_or(0.0)
            };
            let size_seen = seen.clone();
            let batch = move || 500.0_f64.min(cap - size_seen() + 1.0);
            let act_counts = counts.clone();
            let act_target = target.clone();
            let act: Act = Arc::new(move |_store: Store, records: Vec<Record>| {
                let counts = act_counts.clone();
                let target = act_target.clone();
                Box::pin(async move {
                    let due = records
                        .iter()
                        .filter(|record| !target.keeps(record))
                        .count() as f64;
                    let mut counts = locked(&counts);
                    let seen = counts.get(target.collection).copied().unwrap_or(0.0) + due;
                    counts.insert(target.collection.to_owned(), seen);
                    Ok(Acted {
                        survivors: records,
                        stop: seen >= cap,
                    })
                })
            });
            walk(&self.ctx.store, &target, &batch, act, false).await?;
            let total = seen().min(cap);
            locked(&counts).insert(collection.to_owned(), total);
        }
        let counts = locked(&counts).clone();
        Ok(counts)
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        match method {
            "sweepExpired" => Some(self.sweep_expired(args.first()).await),
            "countDue" => Some(
                async {
                    let options: DueOptions =
                        serde_json::from_value(args.first().cloned().unwrap_or(Value::Null))
                            .map_err(|_| crate::js::internal_error())?;
                    let counts = self.count_due(&options).await?;
                    Ok(Value::Object(
                        counts
                            .into_iter()
                            .map(|(collection, count)| (collection, crate::js::number(count)))
                            .collect(),
                    ))
                }
                .await,
            ),
            _ => None,
        }
    }
}
