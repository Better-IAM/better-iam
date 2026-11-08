//! Port of `packages/server/src/threat-engine.ts`.
//!
//! The detection engine of the threats module (`threats.ts`): a scheduled job (`iam.detectThreats()`) that reads each
//! tenant's audit chain from a cursor, verifies the chain as it goes, evaluates the detection rules
//! (`threat-rules.ts`) over the unread events and their lookback window, records detections grouped into incidents,
//! keeps identity risk, and runs the tenant's playbooks for new detections. It reads the trail rather than hooking
//! the recorders, so it also sees what the protocol packages write without fan-out and never slows a sign-in.
//!
//! Events, cursors, baselines, detections, incidents and risk records are handled as stored records (`Record`) and
//! changed member by member, so a record the TypeScript server wrote keeps its member order and unknown members.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use better_iam_core::{
    AUDIT_GENESIS, Filter, FindOptions, IamResult, IamStore, IamStoreExt, Identity, OrderOptions,
    Record, audit_event_hash, find_ordered, js as core_js,
};
use futures::future::BoxFuture;
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::api::analysis::unrestricted_admin;
use crate::context::{ServerContext, Store};
use crate::models::{Binding, GroupMember, Policy, Role};
use crate::observe::SpanKind;
use crate::port::decode;
use crate::threat_response::{
    PlaybookBrake, ResponseActor, ResponseRequest, after_threat_responses, apply_response,
    threat_audit,
};
use crate::threat_rules::{
    DetectionCandidate, RuleFacts, RuleInput, RuleState, baseline_identity_ids_of,
    considered_record, evaluate_threat_rules, rule_window_ms,
};
use crate::threats::{
    DEFAULT_THREAT_SETTINGS, IdentityRisk, RESPONSE_ACTION_KINDS, RISK_POINTS,
    ResolvedThreatSettings, THREAT_ACTOR, THREAT_COLLECTIONS, ThreatDetection, ThreatDetectionRun,
    ThreatEvidence, ThreatIncident, ThreatPlaybook, ThreatResponse, ThreatSettings, ThreatSubject,
    effective_risk, max_severity, resolve_threat_settings, severity_at_least,
};
use crate::utils::{by_id, date_now, id};
use crate::validation::{integer, text};

const HOUR: f64 = 3_600_000.0;
const DAY: f64 = 24.0 * HOUR;
/// Default and largest number of unread events one run reads per tenant.
const DEFAULT_MAX_EVENTS: f64 = 2000.0;
const MAX_EVENTS_LIMIT: f64 = 20_000.0;
/// Most lookback events one run loads per tenant for the window rules (the newest are kept).
const MAX_HISTORY: usize = 20_000;
/// Most people whose sign-in baselines one run writes. Those writes happen in the run's transaction, which holds the
/// store's write lock, so a run reaching this many stops at that event and the next run continues from there.
const MAX_BASELINES_PER_RUN: usize = 500;
/// Detections an incident lists by id (newest last); older ones stay findable through `incidentId`.
const MAX_INCIDENT_DETECTIONS: usize = 200;
/// Risk contributions kept per identity (newest last); older ones have decayed to almost nothing.
const MAX_CONTRIBUTIONS: usize = 50;
/// Contributions older than this many half-lives (under 0.1% of their points) are pruned.
const CONTRIBUTION_HALF_LIVES: f64 = 10.0;
/// Longest `uniqueKey` the store accepts, in UTF-8 bytes; a longer key is stored as its hash.
const MAX_KEY_BYTES: usize = 512;

/// A collection name of `threatCollections`.
fn collection(name: &str) -> &'static str {
    match name {
        "detections" => "threatDetections",
        "incidents" => "threatIncidents",
        "notes" => "threatNotes",
        "risk" => "identityRisk",
        "baselines" => "threatBaselines",
        "cursors" => "threatCursors",
        "settings" => "threatSettings",
        "playbooks" => "threatPlaybooks",
        _ => "threatResponses",
    }
}

/// Keeps `THREAT_COLLECTIONS` and the names used here in step (debug builds only).
fn check_collections() {
    debug_assert!(
        ["detections", "incidents", "risk", "baselines", "cursors", "settings", "playbooks"]
            .iter()
            .all(|name| THREAT_COLLECTIONS.get(*name).and_then(Value::as_str) == Some(collection(name)))
    );
}

/// Why the chain failed verification (`ChainBreakReason`) and how a summary words it (`chainBreakText`).
#[derive(Clone, Copy)]
enum ChainBreakReason {
    SequenceGap,
    SequenceRepeated,
    PreviousHashMismatch,
    HashMismatch,
    HeadRolledBack,
    HeadMismatch,
}

impl ChainBreakReason {
    fn name(self) -> &'static str {
        match self {
            Self::SequenceGap => "sequence-gap",
            Self::SequenceRepeated => "sequence-repeated",
            Self::PreviousHashMismatch => "previous-hash-mismatch",
            Self::HashMismatch => "hash-mismatch",
            Self::HeadRolledBack => "head-rolled-back",
            Self::HeadMismatch => "head-mismatch",
        }
    }

    fn text(self) -> &'static str {
        match self {
            Self::SequenceGap => "events before it are missing",
            Self::SequenceRepeated => "its position in the chain is taken twice",
            Self::PreviousHashMismatch => "it does not follow the event before it",
            Self::HashMismatch => "its content no longer matches its hash",
            Self::HeadRolledBack => "the chain head moved back behind events already read",
            Self::HeadMismatch => "the latest event was replaced",
        }
    }
}

struct ChainBreak {
    reason: ChainBreakReason,
    sequence: f64,
    /// The event at which verification failed; absent when the chain head itself moved.
    event: Option<Record>,
}

/// What one tenant contributed to a run.
#[derive(Default)]
struct TenantOutcome {
    events_scanned: f64,
    detections: f64,
    incidents_opened: f64,
    responses: f64,
    braked: f64,
    chain_broken: bool,
    pending: bool,
}

/// `value ?? undefined` of a stored member: None for an absent member or JSON null.
fn defined(value: Option<&Value>) -> Option<&Value> {
    value.filter(|value| !value.is_null())
}

/// `a === b` for two optional members (`undefined === undefined`).
fn same(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => core_js::strict_equal(a, b),
        _ => false,
    }
}

fn number(value: f64) -> Value {
    crate::js::number(value)
}

fn number_member(record: &Record, name: &str) -> Option<f64> {
    record.get(name).and_then(core_js::as_number)
}

fn str_member<'r>(record: &'r Record, name: &str) -> Option<&'r str> {
    record.get(name).and_then(Value::as_str)
}

/// Runs detection for every active tenant (or only `tenantId`, NOT_FOUND when it does not exist): reads up to
/// `maxEvents` (default 2000, at most 20000) unread audit events per tenant (fewer when they hold the sign-ins of
/// more than 500 people, whose baselines the run writes; the rest stays pending), verifies their hash chain (a
/// break raises `audit-tampering` and detection continues), evaluates the rules, records detections and incidents,
/// updates risk and sign-in baselines, advances the tenant's cursor, and runs matching playbooks for new detections
/// (automatic containments braked at `maxAutomaticContainments` per tenant and run). A tenant whose evaluation
/// fails, or whose detection settings changed while it was evaluated, records nothing and keeps its cursor, so the
/// next run reads the same events again; the other tenants are unaffected. A deployment operation for schedulers:
/// no credential. The first run of a tenant starts one day back.
pub async fn detect_threats(
    ctx: &Arc<ServerContext>,
    input: Option<&Value>,
) -> IamResult<crate::threats::ThreatDetectionRun> {
    check_collections();
    // `input = {}`: an absent argument is the empty object; `null` has no members to read.
    if matches!(input, Some(Value::Null)) {
        return Err(crate::js::internal_error());
    }
    let member = |name: &str| crate::js::member(input, name);
    let max_events_value = match member("maxEvents") {
        None | Some(Value::Null) => number(DEFAULT_MAX_EVENTS),
        Some(value) => value.clone(),
    };
    let max_events = integer(Some(&max_events_value), "maxEvents", 1.0, MAX_EVENTS_LIMIT)?;
    let tenants: Vec<Record> = match member("tenantId") {
        Some(tenant_id) => {
            let tenant_id = text(Some(tenant_id), "tenantId", 256)?;
            let tenant = ctx.tenant(&ctx.store, &tenant_id).await?;
            // The stored record, so the sign-in policy is copied exactly as it was written.
            let stored = ctx.store.get("tenants", &tenant.id).await?;
            vec![stored.unwrap_or_else(|| crate::port::encode(&tenant))]
        }
        None => {
            let mut tenants = ctx
                .store
                .find(
                    "tenants",
                    &Filter::new().eq("status", "active"),
                    &FindOptions::default(),
                )
                .await?;
            tenants.sort_by(|a, b| {
                by_id(
                    str_member(a, "id").unwrap_or(""),
                    str_member(b, "id").unwrap_or(""),
                )
            });
            tenants
        }
    };
    let mut run = ThreatDetectionRun {
        tenants: 0.0,
        events_scanned: 0.0,
        detections: 0.0,
        incidents_opened: 0.0,
        responses: 0.0,
        braked: 0.0,
        chain_breaks: 0.0,
        pending: 0.0,
        extra: Map::new(),
    };
    for tenant in &tenants {
        // A tombstoned tenant only waits for the purge worker.
        if str_member(tenant, "status") == Some("deleted") {
            continue;
        }
        run.tenants += 1.0;
        let tenant_id = str_member(tenant, "id").unwrap_or("").to_owned();
        let outcome = ctx
            .observe
            .span(
                SpanKind::Operation,
                "threats:detect",
                Some(&tenant_id),
                detect_tenant(ctx, tenant, max_events as usize),
                None,
                None,
            )
            .await;
        // Nothing was recorded and the cursor stayed put, so the next run retries these events; the span reports it.
        let Ok(outcome) = outcome else {
            continue;
        };
        run.events_scanned += outcome.events_scanned;
        run.detections += outcome.detections;
        run.incidents_opened += outcome.incidents_opened;
        run.responses += outcome.responses;
        run.braked += outcome.braked;
        if outcome.chain_broken {
            run.chain_breaks += 1.0;
        }
        if outcome.pending {
            run.pending += 1.0;
        }
    }
    Ok(run)
}

/// What the write transaction of a tenant's run recorded.
struct Written {
    detections: f64,
    incidents_opened: f64,
    responses: Vec<ThreatResponse>,
}

async fn detect_tenant(
    ctx: &Arc<ServerContext>,
    tenant: &Record,
    max_events: usize,
) -> IamResult<TenantOutcome> {
    let store = &ctx.store;
    let tenant_id = str_member(tenant, "id").unwrap_or("").to_owned();
    let now = ctx.now();
    // Everything up to the rule results is read outside a transaction: hashing and evaluating thousands of events
    // would otherwise hold the store's write lock. The write transaction re-checks the cursor, so overlapping runs
    // never record the same events twice.
    let cursor = store.get(collection("cursors"), &tenant_id).await?;
    // Kept as read, so the write transaction can tell when threats.configure changed them meanwhile.
    let stored_settings = store.get(collection("settings"), &tenant_id).await?;
    let typed_settings: Option<ThreatSettings> = match &stored_settings {
        Some(record) => Some(decode(record.clone())?),
        None => None,
    };
    let settings = resolve_threat_settings(typed_settings.as_ref())?;
    let head = store.get("auditChains", &tenant_id).await?;
    let head_sequence_value = head
        .as_ref()
        .and_then(|head| number_member(head, "sequence"));
    let head_hash = head.as_ref().and_then(|head| head.get("hash")).cloned();
    let mut breaks: Vec<ChainBreak> = Vec::new();
    // The last verified chain position; None until known (the first run starts mid-chain).
    let mut sequence: Option<f64> = None;
    let mut hash: Option<Value> = None;
    if let Some(cursor) = &cursor {
        let cursor_sequence = number_member(cursor, "sequence").unwrap_or(f64::NAN);
        let head_sequence = head_sequence_value.unwrap_or(0.0);
        let rolled_back = cursor_sequence > head_sequence;
        let replaced = !rolled_back
            && head.is_some()
            && Some(cursor_sequence) == head_sequence_value
            && cursor.get("hash").is_some()
            && !same(cursor.get("hash"), head_hash.as_ref());
        if rolled_back || replaced {
            breaks.push(ChainBreak {
                reason: if rolled_back {
                    ChainBreakReason::HeadRolledBack
                } else {
                    ChainBreakReason::HeadMismatch
                },
                sequence: cursor_sequence,
                event: None,
            });
            // Continue from the head as it is now, so events appended after the rollback are still read.
            sequence = Some(head_sequence);
            hash = head_hash.clone();
        } else {
            sequence = Some(cursor_sequence);
            hash = cursor.get("hash").cloned();
        }
    }
    let by_sequence = |from: f64, limit: usize| OrderOptions {
        field: "sequence".into(),
        from: Some(from),
        limit: Some(limit as i64),
        ..OrderOptions::default()
    };
    let tenant_filter = Filter::new().eq("tenantId", tenant_id.as_str());
    let mut events: Vec<Record> = Vec::new();
    if let Some(sequence) = sequence {
        events = find_ordered(
            store.as_ref(),
            "audit",
            &tenant_filter,
            &by_sequence(sequence + 1.0, max_events + 1),
            None,
        )
        .await?;
    } else {
        // First run: start one day back instead of replaying the whole trail (both clocks, since server and
        // authentication events are stamped by different ones); the chain is verified from that event on.
        let first = first_event_since(
            store.as_ref(),
            &tenant_id,
            now.min(date_now()) - DAY,
            head_sequence_value.unwrap_or(0.0),
        )
        .await?;
        if let Some(first) = first {
            events = find_ordered(
                store.as_ref(),
                "audit",
                &tenant_filter,
                &by_sequence(
                    number_member(&first, "sequence").unwrap_or(f64::NAN),
                    max_events + 1,
                ),
                None,
            )
            .await?;
        } else {
            sequence = Some(head_sequence_value.unwrap_or(0.0));
            hash = head_hash.clone();
        }
    }
    let mut pending = events.len() > max_events;
    if pending {
        events.truncate(max_events);
    }
    let within = within_baseline_budget(&events);
    if within < events.len() {
        events.truncate(within);
        pending = true;
    }

    // Chain verification, every event including the module's own.
    let mut prunes: Option<Vec<Record>> = None;
    for event in &events {
        let position = number_member(event, "sequence").unwrap_or(f64::NAN);
        let previous: Option<Value> = match defined(hash.as_ref()) {
            Some(hash) => Some(hash.clone()),
            None if sequence == Some(0.0) => Some(Value::String(AUDIT_GENESIS.to_owned())),
            None => None,
        };
        let mut reason: Option<ChainBreakReason> = None;
        if let Some(known) = sequence.filter(|known| position != known + 1.0) {
            if position <= known {
                reason = Some(ChainBreakReason::SequenceRepeated);
            } else {
                // A gap left by `pruneAudit` while the cursor was behind: a checkpoint names the event just before
                // this one.
                if prunes.is_none() {
                    prunes = Some(
                        store
                            .find(
                                "audit",
                                &Filter::new()
                                    .eq("tenantId", tenant_id.as_str())
                                    .eq("action", "audit:prune"),
                                &FindOptions::default(),
                            )
                            .await?,
                    );
                }
                let pruned_before = prunes.as_deref().unwrap_or_default().iter().any(|prune| {
                    crate::js::member(prune.get("metadata"), "prunedThroughSequence")
                        .and_then(core_js::as_number)
                        == Some(position - 1.0)
                        && same(
                            crate::js::member(prune.get("metadata"), "prunedThroughHash"),
                            event.get("previousHash"),
                        )
                });
                if !pruned_before {
                    reason = Some(ChainBreakReason::SequenceGap);
                }
            }
        } else if let Some(previous) = &previous
            && !same(event.get("previousHash"), Some(previous))
        {
            reason = Some(ChainBreakReason::PreviousHashMismatch);
        }
        if reason.is_none()
            && !same(
                event.get("hash"),
                Some(&Value::String(audit_event_hash(event))),
            )
        {
            reason = Some(ChainBreakReason::HashMismatch);
        }
        if let Some(reason) = reason {
            breaks.push(ChainBreak {
                reason,
                sequence: position,
                event: Some(event.clone()),
            });
        }
        // Detection continues from the event as stored, so one break is reported once.
        sequence = Some(position);
        hash = event.get("hash").cloned();
    }
    let position_sequence = sequence.unwrap_or(0.0);
    let position_hash = hash;

    let mut candidates: Vec<DetectionCandidate> = Vec::new();
    let tampering = settings.rules.get("audit-tampering");
    if crate::js::truthy(crate::js::member(tampering, "enabled")) {
        let severity = crate::js::member(tampering, "severity")
            .cloned()
            .unwrap_or(Value::Null);
        for found in &breaks {
            candidates.push(tampering_candidate(tenant, found, &severity, now));
        }
    }

    // The module's own events never feed the rules, nor do malformed ones (the chain check above reports an edited
    // event; its fields are not trusted here).
    let rule_events: Vec<Record> = events
        .iter()
        .filter(|event| considered_record(event))
        .cloned()
        .collect();
    let mut baselines: IndexMap<String, Record> = IndexMap::new();
    // Baselines stored for this tenant when read (overwritten in place), and ids another tenant's baseline holds.
    let mut stored_baselines: IndexSet<String> = IndexSet::new();
    let mut foreign_baselines: IndexSet<String> = IndexSet::new();
    let mut state = RuleState {
        auth_policy: cursor
            .as_ref()
            .and_then(|cursor| cursor.get("authPolicy"))
            .filter(|policy| crate::js::truthy(Some(policy)))
            .and_then(Value::as_object)
            .map(to_index_map),
        extra: Map::new(),
    };
    let mut touched: IndexSet<String> = IndexSet::new();
    if !rule_events.is_empty() {
        let mut first = f64::INFINITY;
        let mut last = f64::NEG_INFINITY;
        for event in &rule_events {
            let at = number_member(event, "timestamp").unwrap_or(f64::NAN);
            first = first.min(at);
            last = last.max(at);
        }
        // Newest first, so a crowded window keeps the events closest to the ones being judged. One more than the cap
        // tells whether older events were left out.
        let considered: &(dyn Fn(&Record) -> bool + Send + Sync) = &considered_record;
        let newest = find_ordered(
            store.as_ref(),
            "audit",
            &tenant_filter,
            &OrderOptions {
                field: "timestamp".into(),
                direction: better_iam_core::Direction::Desc,
                from: Some(first - rule_window_ms(&settings)?),
                to: Some(last),
                limit: Some((MAX_HISTORY + 1) as i64),
                ..OrderOptions::default()
            },
            Some(considered),
        )
        .await?;
        let history_from_cut = newest.len() > MAX_HISTORY;
        let mut history: Vec<Record> = newest.into_iter().take(MAX_HISTORY).collect();
        history.reverse();
        let history_from = if history_from_cut {
            history
                .first()
                .and_then(|event| number_member(event, "timestamp"))
        } else {
            None
        };
        // Sign-ins compare against and update baselines; own sign-in method changes read the risky sign-in on them.
        for identity_id in baseline_identity_ids_of(rule_events.iter()) {
            let baseline = store.get(collection("baselines"), &identity_id).await?;
            match baseline {
                Some(baseline) if str_member(&baseline, "tenantId") == Some(tenant_id.as_str()) => {
                    baselines.insert(identity_id.clone(), baseline);
                    stored_baselines.insert(identity_id);
                }
                Some(_) => {
                    foreign_baselines.insert(identity_id);
                }
                None => {}
            }
        }
        let facts = EngineFacts::new(ctx.clone(), tenant_id.clone());
        let mut input = RuleInput {
            tenant_id: tenant_id.clone(),
            events: &rule_events,
            history: &history,
            history_from,
            settings: settings.clone(),
            baselines: std::mem::take(&mut baselines),
            state,
            facts: &facts,
            now,
        };
        let evaluated = evaluate_threat_rules(&mut input).await?;
        baselines = input.baselines;
        state = input.state;
        candidates.extend(evaluated.candidates);
        touched = evaluated.touched_baselines;
    }
    // With no sign-in policy seen yet (a first run, or none changed so far), the policy in force before this run's
    // events is the tenant's as read before them, so guardrail-weakened judges the first change after this run too.
    // Not while more events wait than one run reads: a later one may already be reflected in that read.
    if state.auth_policy.is_none() && !pending {
        state.auth_policy = Some(
            tenant
                .get("authPolicy")
                .filter(|policy| crate::js::truthy(Some(policy)))
                .and_then(Value::as_object)
                .map(to_index_map)
                .unwrap_or_default(),
        );
    }

    let mut brake = PlaybookBrake {
        contained: 0.0,
        braked: None,
        extra: Map::new(),
    };
    let written = {
        let (tenant_id, cursor, stored_settings, settings) =
            (&tenant_id, &cursor, &stored_settings, &settings);
        let (candidates, baselines, stored_baselines, foreign_baselines, touched, state, brake) = (
            &candidates,
            &mut baselines,
            &mut stored_baselines,
            &foreign_baselines,
            &mut touched,
            &state,
            &mut brake,
        );
        let position_hash = &position_hash;
        store
            .transaction(move |tx| async move {
                let current = tx.get(collection("cursors"), tenant_id).await?;
                // Another run advanced the cursor since it was read: it recorded these events.
                let member = |record: &Option<Record>, name: &str| {
                    record.as_ref().and_then(|r| r.get(name)).cloned()
                };
                if !same(
                    member(&current, "sequence").as_ref(),
                    member(cursor, "sequence").as_ref(),
                ) || !same(
                    member(&current, "hash").as_ref(),
                    member(cursor, "hash").as_ref(),
                ) || !same(
                    member(&current, "updatedAt").as_ref(),
                    member(cursor, "updatedAt").as_ref(),
                ) {
                    return Ok(None);
                }
                // The settings changed since this run read them (threats.configure): the events were judged under the
                // old ones, and playbooks would run with the old brake, trusted networks and recipients. Nothing is
                // recorded; the next run reads the same events under the new settings.
                let settings_now = tx.get(collection("settings"), tenant_id).await?;
                let serialized = |record: &Option<Record>| match record {
                    Some(record) => core_js::stringify_object(record),
                    None => "null".to_owned(),
                };
                if serialized(&settings_now) != serialized(stored_settings) {
                    return Ok(None);
                }
                let mut detections = 0.0;
                let mut incidents_opened = 0.0;
                let mut created: Vec<(Record, Record)> = Vec::new();
                for candidate in candidates {
                    let recorded =
                        record_candidate(ctx, &tx, tenant_id, candidate, settings, now).await?;
                    if !recorded.created {
                        continue;
                    }
                    detections += 1.0;
                    if recorded.incident_opened {
                        incidents_opened += 1.0;
                    }
                    let detection_id = str_member(&recorded.detection, "id")
                        .unwrap_or("")
                        .to_owned();
                    created.push((recorded.detection, recorded.incident));
                    if candidate.risky_sign_in == Some(true)
                        && let Some(identity_id) = &candidate.identity_id
                        && baseline_for(
                            &tx,
                            tenant_id,
                            identity_id,
                            baselines,
                            stored_baselines,
                            now,
                        )
                        .await?
                        && let Some(baseline) = baselines.get_mut(identity_id)
                    {
                        let risky = baseline.get("riskySignIn");
                        let replace = !crate::js::truthy(risky)
                            || crate::js::member(risky, "at")
                                .map(core_js::to_number)
                                .is_some_and(|at| at <= candidate.occurred_at);
                        if replace {
                            let mut risky = Map::new();
                            risky.insert("at".into(), number(candidate.occurred_at));
                            risky.insert("detectionId".into(), json!(detection_id));
                            risky.insert("ruleId".into(), candidate.rule_id.clone());
                            baseline.insert("riskySignIn".into(), Value::Object(risky));
                            touched.insert(identity_id.clone());
                        }
                    }
                }
                // Two round trips per person under the write lock, and at most `maxBaselinesPerRun` people per run.
                for identity_id in touched.iter() {
                    let Some(baseline) = baselines.get(identity_id) else {
                        continue;
                    };
                    if foreign_baselines.contains(identity_id) {
                        continue;
                    }
                    let mut record = baseline.clone();
                    record.insert("id".into(), json!(identity_id));
                    record.insert("tenantId".into(), json!(tenant_id));
                    record.insert("identityId".into(), json!(identity_id));
                    record.insert("updatedAt".into(), number(now));
                    // A baseline read from this tenant is overwritten; if identity deletion removed it meanwhile, the
                    // write fails and so does the run, and the next run skips the deleted person.
                    if stored_baselines.contains(identity_id) {
                        tx.put(collection("baselines"), &record).await?;
                    } else {
                        // A deleted identity's baseline went with it (identity deletion); a late sign-in event does
                        // not bring it back.
                        let identity = tx.get("identities", identity_id).await?;
                        let Some(identity) = identity else {
                            continue;
                        };
                        if str_member(&identity, "tenantId") != Some(tenant_id.as_str())
                            || str_member(&identity, "status") == Some("deleted")
                        {
                            continue;
                        }
                        tx.insert(collection("baselines"), &record).await?;
                    }
                }
                let mut next = Record::new();
                next.insert("id".into(), json!(tenant_id));
                next.insert("tenantId".into(), json!(tenant_id));
                next.insert("sequence".into(), number(position_sequence));
                if let Some(hash) = position_hash {
                    next.insert("hash".into(), hash.clone());
                }
                if let Some(policy) = &state.auth_policy {
                    next.insert(
                        "authPolicy".into(),
                        Value::Object(policy.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
                    );
                }
                next.insert("updatedAt".into(), number(now));
                if current.is_some() {
                    tx.put(collection("cursors"), &next).await?;
                } else {
                    tx.insert(collection("cursors"), &next).await?;
                }
                let mut responses: Vec<ThreatResponse> = Vec::new();
                for (detection, incident) in &created {
                    let detection: ThreatDetection = decode(detection.clone())?;
                    let incident: ThreatIncident = decode(incident.clone())?;
                    responses.extend(
                        run_playbooks(ctx, &tx, tenant_id, &detection, &incident, settings, brake)
                            .await?,
                    );
                }
                Ok(Some(Written {
                    detections,
                    incidents_opened,
                    responses,
                }))
            })
            .await?
    };
    let Some(written) = written else {
        return Ok(TenantOutcome::default());
    };
    after_threat_responses(ctx, &tenant_id, &written.responses).await?;
    Ok(TenantOutcome {
        events_scanned: events.len() as f64,
        detections: written.detections,
        incidents_opened: written.incidents_opened,
        responses: written
            .responses
            .iter()
            .filter(|response| response.outcome == "applied")
            .count() as f64,
        braked: brake.braked.unwrap_or(0.0),
        chain_broken: !breaks.is_empty(),
        pending,
    })
}

fn to_index_map(map: &Map<String, Value>) -> IndexMap<String, Value> {
    map.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// The earliest event of the tenant's chain stamped at or after `cutoff`, found by bisecting sequences (timestamps
/// rise along the chain, so this takes a few indexed reads however long the trail is; skew between the service and
/// authentication clocks only moves the start by as much). Pruned sequences are skipped. None when every event is
/// older.
async fn first_event_since(
    store: &dyn IamStore,
    tenant_id: &str,
    cutoff: f64,
    head_sequence: f64,
) -> IamResult<Option<Record>> {
    let filter = Filter::new().eq("tenantId", tenant_id);
    let mut low = 1.0;
    let mut high = head_sequence + 1.0;
    let mut found: Option<Record> = None;
    while low < high {
        let middle = ((low + high) / 2.0f64).floor();
        // The first event at or after a sequence.
        let event = find_ordered(
            store,
            "audit",
            &filter,
            &OrderOptions {
                field: "sequence".into(),
                from: Some(middle),
                limit: Some(1),
                ..OrderOptions::default()
            },
            None,
        )
        .await?
        .into_iter()
        .next();
        match event {
            Some(event) if number_member(&event, "timestamp").unwrap_or(f64::NAN) < cutoff => {
                low = number_member(&event, "sequence").unwrap_or(f64::NAN) + 1.0;
            }
            event => {
                if let Some(event) = event {
                    found = Some(event);
                }
                high = middle;
            }
        }
    }
    Ok(found)
}

/// The baseline a risky sign-in is marked on: preloaded, stored (noted in `storedBaselines`), or new; false when
/// another tenant holds the id. The baseline is then in `baselines`.
async fn baseline_for(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    baselines: &mut IndexMap<String, Record>,
    stored_baselines: &mut IndexSet<String>,
    now: f64,
) -> IamResult<bool> {
    if baselines.contains_key(identity_id) {
        return Ok(true);
    }
    let stored = tx.get(collection("baselines"), identity_id).await?;
    if let Some(stored) = &stored
        && str_member(stored, "tenantId") != Some(tenant_id)
    {
        return Ok(false);
    }
    if stored.is_some() {
        stored_baselines.insert(identity_id.to_owned());
    }
    let baseline = stored.unwrap_or_else(|| {
        let mut baseline = Record::new();
        baseline.insert("id".into(), json!(identity_id));
        baseline.insert("tenantId".into(), json!(tenant_id));
        baseline.insert("identityId".into(), json!(identity_id));
        baseline.insert("networks".into(), json!([]));
        baseline.insert("userAgents".into(), json!([]));
        baseline.insert("firstSeenAt".into(), number(now));
        baseline.insert("updatedAt".into(), number(now));
        baseline
    });
    baselines.insert(identity_id.to_owned(), baseline);
    Ok(true)
}

/// How many of a run's events it takes so that it learns sign-ins (or reads risky sign-ins) of at most
/// `maxBaselinesPerRun` people; every event when fewer people are involved.
fn within_baseline_budget(events: &[Record]) -> usize {
    let mut people: IndexSet<String> = IndexSet::new();
    for (index, event) in events.iter().enumerate() {
        if !considered_record(event) {
            continue;
        }
        for identity_id in baseline_identity_ids_of([event]) {
            if people.contains(&identity_id) {
                continue;
            }
            if people.len() >= MAX_BASELINES_PER_RUN {
                return index;
            }
            people.insert(identity_id);
        }
    }
    events.len()
}

fn tampering_candidate(
    tenant: &Record,
    found: &ChainBreak,
    severity: &Value,
    now: f64,
) -> DetectionCandidate {
    // The event failed verification: none of its fields is trusted to have the right type.
    let stamped = found
        .event
        .as_ref()
        .and_then(|event| number_member(event, "timestamp"));
    let at = stamped.filter(|stamped| stamped.is_finite()).unwrap_or(now);
    let action = found
        .event
        .as_ref()
        .and_then(|event| str_member(event, "action"))
        .map(str::to_owned);
    let event_id = found
        .event
        .as_ref()
        .and_then(|event| str_member(event, "id"))
        .map(str::to_owned);
    let tenant_name = crate::js::js_string(tenant.get("name"));
    let tenant_id = crate::js::js_string(tenant.get("id"));
    let sequence = core_js::number_to_string(found.sequence);
    let mut metadata = IndexMap::new();
    metadata.insert("reason".to_owned(), json!(found.reason.name()));
    metadata.insert("sequence".to_owned(), number(found.sequence));
    DetectionCandidate {
        rule_id: json!("audit-tampering"),
        severity: severity.clone(),
        title: "Audit trail tampering".to_owned(),
        summary: format!(
            "The audit trail of {tenant_name} no longer verifies at event {sequence}: {}.",
            found.reason.text()
        ),
        subject: ThreatSubject {
            r#type: json!("tenant"),
            id: tenant_id.clone(),
            name: tenant
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_owned),
            extra: Map::new(),
        },
        identity_id: None,
        network: None,
        dedupe_key: format!("{tenant_id}:{sequence}"),
        occurred_at: at,
        evidence: ThreatEvidence {
            event_ids: event_id.into_iter().collect(),
            count: 1.0,
            first_at: at,
            last_at: at,
            networks: None,
            identity_ids: None,
            actions: action.map(|action| vec![action]),
            extra: Map::new(),
        },
        metadata: Some(metadata),
        risky_sign_in: None,
        extra: Map::new(),
    }
}

/// The facts rules may ask about a tenant, read from the store and cached for the run (`ruleFacts`). Privileged
/// means owner, root administrator, or holder of a live standing binding (direct or through a live group
/// membership) of a role whose inline document, attached policies, or inherited roles grant `*` or `iam:*` on `*`
/// without conditions.
struct EngineFacts {
    ctx: Arc<ServerContext>,
    tenant_id: String,
    identities: Mutex<HashMap<String, Option<Identity>>>,
    admin_roles: Mutex<HashMap<String, bool>>,
    held_roles: Mutex<HashMap<String, IndexSet<String>>>,
    privileged: Mutex<HashMap<String, bool>>,
    incidents: Mutex<HashMap<String, Option<Record>>>,
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl EngineFacts {
    fn new(ctx: Arc<ServerContext>, tenant_id: String) -> Self {
        Self {
            ctx,
            tenant_id,
            identities: Mutex::new(HashMap::new()),
            admin_roles: Mutex::new(HashMap::new()),
            held_roles: Mutex::new(HashMap::new()),
            privileged: Mutex::new(HashMap::new()),
            incidents: Mutex::new(HashMap::new()),
        }
    }

    fn grants_admin<'s>(
        &'s self,
        role_id: String,
        seen: &'s mut IndexSet<String>,
    ) -> BoxFuture<'s, IamResult<bool>> {
        Box::pin(async move {
            if seen.contains(&role_id) || seen.len() >= 64 {
                return Ok(false);
            }
            seen.insert(role_id.clone());
            let store = &self.ctx.store;
            let Some(role) = store.get("roles", &role_id).await? else {
                return Ok(false);
            };
            if str_member(&role, "tenantId") != Some(self.tenant_id.as_str()) {
                return Ok(false);
            }
            let role: Role = decode(role)?;
            if unrestricted_admin(role.document.as_ref())? {
                return Ok(true);
            }
            for policy_id in &role.policy_ids {
                if let Some(policy) = store.get("policies", policy_id).await?
                    && str_member(&policy, "tenantId") == Some(self.tenant_id.as_str())
                {
                    let policy: Policy = decode(policy)?;
                    if unrestricted_admin(Some(&policy.document))? {
                        return Ok(true);
                    }
                }
            }
            for inherited in role.inherits.iter().flatten() {
                if self.grants_admin(inherited.clone(), seen).await? {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    async fn held(&self, identity_id: &str) -> IamResult<IndexSet<String>> {
        if let Some(cached) = locked(&self.held_roles).get(identity_id) {
            return Ok(cached.clone());
        }
        let ctx = &self.ctx;
        let store = &ctx.store;
        let mut roles: IndexSet<String> = IndexSet::new();
        let standing =
            |binding: &Binding| binding.eligible != Some(true) && ctx.live_binding(binding);
        let bindings_of = |subject_type: &str, subject_id: &str| {
            Filter::new()
                .eq("tenantId", self.tenant_id.as_str())
                .eq("subjectType", subject_type)
                .eq("subjectId", subject_id)
        };
        for binding in store
            .find(
                "bindings",
                &bindings_of("identity", identity_id),
                &FindOptions::default(),
            )
            .await?
        {
            let binding: Binding = decode(binding)?;
            if standing(&binding) {
                roles.insert(binding.role_id.clone());
            }
        }
        for member in store
            .find(
                "groupMembers",
                &Filter::new()
                    .eq("tenantId", self.tenant_id.as_str())
                    .eq("identityId", identity_id),
                &FindOptions::default(),
            )
            .await?
        {
            let member: GroupMember = decode(member)?;
            if !ctx.live_membership(&member) {
                continue;
            }
            for binding in store
                .find(
                    "bindings",
                    &bindings_of("group", &member.group_id),
                    &FindOptions::default(),
                )
                .await?
            {
                let binding: Binding = decode(binding)?;
                if standing(&binding) {
                    roles.insert(binding.role_id.clone());
                }
            }
        }
        locked(&self.held_roles).insert(identity_id.to_owned(), roles.clone());
        Ok(roles)
    }
}

#[async_trait::async_trait]
impl RuleFacts for EngineFacts {
    async fn identity(&self, identity_id: &str) -> IamResult<Option<Identity>> {
        if let Some(found) = locked(&self.identities).get(identity_id) {
            return Ok(found.clone());
        }
        let found = self.ctx.store.get("identities", identity_id).await?;
        let identity: Option<Identity> = match found {
            Some(found) if str_member(&found, "tenantId") == Some(self.tenant_id.as_str()) => {
                Some(decode(found)?)
            }
            _ => None,
        };
        locked(&self.identities).insert(identity_id.to_owned(), identity.clone());
        Ok(identity)
    }

    async fn is_privileged(&self, identity_id: &str) -> IamResult<bool> {
        if let Some(cached) = locked(&self.privileged).get(identity_id) {
            return Ok(*cached);
        }
        let found = self.identity(identity_id).await?;
        let mut result = false;
        if let Some(found) =
            found.filter(|found| found.status != better_iam_core::IdentityStatus::Deleted)
        {
            if found.owner || found.root_admin {
                result = true;
            } else {
                for role_id in self.held(identity_id).await? {
                    if self.is_admin_role(&role_id).await? {
                        result = true;
                        break;
                    }
                }
            }
        }
        locked(&self.privileged).insert(identity_id.to_owned(), result);
        Ok(result)
    }

    async fn is_admin_role(&self, role_id: &str) -> IamResult<bool> {
        if let Some(admin) = locked(&self.admin_roles).get(role_id) {
            return Ok(*admin);
        }
        let mut seen = IndexSet::new();
        let admin = self.grants_admin(role_id.to_owned(), &mut seen).await?;
        locked(&self.admin_roles).insert(role_id.to_owned(), admin);
        Ok(admin)
    }

    async fn holds_role(&self, identity_id: &str, role_id: &str) -> IamResult<bool> {
        Ok(self.held(identity_id).await?.contains(role_id))
    }

    async fn detection_stands(&self, detection_id: &str) -> IamResult<Option<bool>> {
        Ok(Some(
            still_counts(
                &self.ctx.store,
                &self.tenant_id,
                detection_id,
                &self.incidents,
            )
            .await?,
        ))
    }
}

/// A `uniqueKey` the store accepts: the value itself, or its prefix and hash when too long or not printable.
fn storage_key(value: &str) -> String {
    let printable = !value
        .chars()
        .any(|char| (char as u32) < 32 || char as u32 == 127);
    if printable && value.len() <= MAX_KEY_BYTES {
        return value.to_owned();
    }
    let prefix = match value.find(':') {
        Some(index) => &value[..=index],
        None => "key:",
    };
    format!(
        "{prefix}sha256:{}",
        hex::encode(Sha256::digest(value.as_bytes()))
    )
}

/// A readable name for a subject in titles.
fn subject_label(subject: Option<&Value>) -> String {
    match crate::js::member(subject, "name").filter(|name| !name.is_null()) {
        Some(name) => crate::js::js_string(Some(name)),
        None => crate::js::js_string(crate::js::member(subject, "id")),
    }
}

/// `subject.type` / `subject.id` of a stored detection or incident, as text.
fn subject_member(record: &Record, name: &str) -> String {
    crate::js::js_string(crate::js::member(record.get("subject"), name))
}

/// Adds a detection to the subject's open (or investigating) incident, or opens one (uniqueKey
/// `open:{subject.type}:{subject.id}`). An incident spanning several rules is retitled "N detections for X".
async fn join_incident(
    tx: &Store,
    tenant_id: &str,
    detection: &Record,
    now: f64,
) -> IamResult<(Record, bool)> {
    let unique_key = storage_key(&format!(
        "open:{}:{}",
        subject_member(detection, "type"),
        subject_member(detection, "id")
    ));
    let open = tx
        .find(
            collection("incidents"),
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("uniqueKey", unique_key.as_str()),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .next();
    let detection_rule = detection.get("ruleId").cloned().unwrap_or(Value::Null);
    let detection_identity = defined_member(detection, "identityId");
    let detection_network = defined_member(detection, "network");
    if let Some(open) = open {
        let mut rule_ids: Vec<Value> = open
            .get("ruleIds")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if !rule_ids
            .iter()
            .any(|rule| core_js::strict_equal(rule, &detection_rule))
        {
            rule_ids.push(detection_rule.clone());
        }
        let detection_count = open
            .get("detectionCount")
            .map(core_js::to_number)
            .unwrap_or(f64::NAN)
            + 1.0;
        let open_identity = defined_member(&open, "identityId");
        // An incident about the tenant (or a network, a connection) gathers detections of whoever acted: once two
        // name different identities it names none, so a response to it never acts on whoever happened to come first.
        let several = open.get("severalIdentities") == Some(&Value::Bool(true))
            || (subject_member(&open, "type") != "identity"
                && open_identity.is_some()
                && detection_identity.is_some()
                && !same(detection_identity.as_ref(), open_identity.as_ref()));
        let identity_id = if several {
            None
        } else {
            // `open.identityId ?? detection.identityId`: a null member is nullish too.
            open_identity
                .clone()
                .filter(|identity| !identity.is_null())
                .or_else(|| detection_identity.clone())
        };
        let mut incident = open.clone();
        incident.shift_remove("identityId");
        let mut detection_ids: Vec<Value> = open
            .get("detectionIds")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        detection_ids.push(detection.get("id").cloned().unwrap_or(Value::Null));
        if detection_ids.len() > MAX_INCIDENT_DETECTIONS {
            detection_ids.drain(..detection_ids.len() - MAX_INCIDENT_DETECTIONS);
        }
        let severity = max_severity(
            open.get("severity").unwrap_or(&Value::Null),
            detection.get("severity").unwrap_or(&Value::Null),
        )?;
        let title = if rule_ids.len() > 1 {
            json!(format!(
                "{} detections for {}",
                core_js::number_to_string(detection_count),
                subject_label(open.get("subject"))
            ))
        } else {
            open.get("title").cloned().unwrap_or(Value::Null)
        };
        incident.insert("detectionIds".into(), Value::Array(detection_ids));
        incident.insert("detectionCount".into(), number(detection_count));
        incident.insert("ruleIds".into(), Value::Array(rule_ids));
        incident.insert("severity".into(), severity);
        incident.insert("title".into(), title);
        incident.insert("lastDetectedAt".into(), number(now));
        incident.insert("updatedAt".into(), number(now));
        if let Some(identity_id) = identity_id {
            incident.insert("identityId".into(), identity_id);
        }
        if several {
            incident.insert("severalIdentities".into(), Value::Bool(true));
        }
        if open.get("network").is_none()
            && let Some(network) = &detection_network
        {
            incident.insert("network".into(), network.clone());
        }
        tx.put(collection("incidents"), &incident).await?;
        return Ok((incident, false));
    }
    let mut incident = Record::new();
    incident.insert("id".into(), json!(id()));
    incident.insert("tenantId".into(), json!(tenant_id));
    incident.insert("uniqueKey".into(), json!(unique_key));
    incident.insert(
        "subject".into(),
        detection.get("subject").cloned().unwrap_or(Value::Null),
    );
    if let Some(identity_id) = detection_identity {
        incident.insert("identityId".into(), identity_id);
    }
    if let Some(network) = detection_network {
        incident.insert("network".into(), network);
    }
    incident.insert(
        "severity".into(),
        detection.get("severity").cloned().unwrap_or(Value::Null),
    );
    incident.insert(
        "title".into(),
        detection.get("title").cloned().unwrap_or(Value::Null),
    );
    incident.insert("status".into(), json!("open"));
    incident.insert(
        "detectionIds".into(),
        json!([detection.get("id").cloned().unwrap_or(Value::Null)]),
    );
    incident.insert("detectionCount".into(), number(1.0));
    incident.insert("ruleIds".into(), json!([detection_rule]));
    incident.insert("firstDetectedAt".into(), number(now));
    incident.insert("lastDetectedAt".into(), number(now));
    incident.insert("createdAt".into(), number(now));
    incident.insert("updatedAt".into(), number(now));
    tx.insert(collection("incidents"), &incident).await?;
    Ok((incident, true))
}

/// A member that is not `undefined` (a stored record holds no `undefined`; JSON null is kept, as TypeScript keeps it).
fn defined_member(record: &Record, name: &str) -> Option<Value> {
    record.get(name).cloned()
}

/// What [`record_candidate`] did.
struct Recorded {
    detection: Record,
    incident: Record,
    incident_opened: bool,
    created: bool,
}

/// Records a candidate once: its `uniqueKey` is `{ruleId}:{dedupeKey}`, so a candidate raised again (the same burst
/// or triggering event) returns the existing detection with `created: false`. A new detection is `open`, joins its
/// subject's open incident or opens one, is audited as `threat:detection` (and `threat:incident-open`) under the
/// `threat-detection` actor, and adds `riskPoints[severity]` to its identity's risk (`recomputeRisk`).
pub async fn record_detection(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    candidate: &crate::threat_rules::DetectionCandidate,
    settings: &crate::threats::ResolvedThreatSettings,
    now: f64,
) -> IamResult<Value> {
    let recorded = record_candidate(ctx, tx, tenant_id, candidate, settings, now).await?;
    Ok(json!({
        "detection": Value::Object(recorded.detection),
        "incident": Value::Object(recorded.incident),
        "incidentOpened": recorded.incident_opened,
        "created": recorded.created,
    }))
}

async fn record_candidate(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    candidate: &DetectionCandidate,
    settings: &ResolvedThreatSettings,
    now: f64,
) -> IamResult<Recorded> {
    let rule_id = crate::js::js_string(Some(&candidate.rule_id));
    let unique_key = storage_key(&format!("{rule_id}:{}", candidate.dedupe_key));
    let existing = tx
        .find(
            collection("detections"),
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("uniqueKey", unique_key.as_str()),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .next();
    if let Some(existing) = existing {
        let linked = match existing.get("incidentId").and_then(Value::as_str) {
            Some(incident_id) => tx.get(collection("incidents"), incident_id).await?,
            None => None,
        };
        if let Some(linked) = linked
            && str_member(&linked, "tenantId") == Some(tenant_id)
        {
            return Ok(Recorded {
                detection: existing,
                incident: linked,
                incident_opened: false,
                created: false,
            });
        }
        // Its incident is gone: attach it to the subject's current one rather than leave it orphaned.
        let (incident, opened) = join_incident(tx, tenant_id, &existing, now).await?;
        let mut detection = existing;
        detection.insert(
            "incidentId".into(),
            incident.get("id").cloned().unwrap_or(Value::Null),
        );
        tx.put(collection("detections"), &detection).await?;
        return Ok(Recorded {
            detection,
            incident,
            incident_opened: opened,
            created: false,
        });
    }
    let mut detection = Record::new();
    detection.insert("id".into(), json!(id()));
    detection.insert("tenantId".into(), json!(tenant_id));
    detection.insert("uniqueKey".into(), json!(unique_key));
    detection.insert("ruleId".into(), candidate.rule_id.clone());
    detection.insert("severity".into(), candidate.severity.clone());
    detection.insert("title".into(), json!(candidate.title));
    detection.insert("summary".into(), json!(candidate.summary));
    detection.insert("subject".into(), to_json(&candidate.subject));
    if let Some(identity_id) = &candidate.identity_id {
        detection.insert("identityId".into(), json!(identity_id));
    }
    if let Some(network) = &candidate.network {
        detection.insert("network".into(), json!(network));
    }
    detection.insert("evidence".into(), to_json(&candidate.evidence));
    if let Some(metadata) = &candidate.metadata {
        detection.insert(
            "metadata".into(),
            Value::Object(
                metadata
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            ),
        );
    }
    detection.insert("status".into(), json!("open"));
    detection.insert("occurredAt".into(), number(candidate.occurred_at));
    detection.insert("detectedAt".into(), number(now));
    let (incident, opened) = join_incident(tx, tenant_id, &detection, now).await?;
    let incident_id = str_member(&incident, "id").unwrap_or("").to_owned();
    detection.insert("incidentId".into(), json!(incident_id));
    tx.insert(collection("detections"), &detection).await?;
    let detection_id = str_member(&detection, "id").unwrap_or("").to_owned();
    let automatic = ResponseActor::Automatic;
    let mut metadata: IndexMap<String, Value> = IndexMap::new();
    metadata.insert("ruleId".into(), candidate.rule_id.clone());
    metadata.insert("severity".into(), candidate.severity.clone());
    metadata.insert("subjectType".into(), candidate.subject.r#type.clone());
    metadata.insert("subjectId".into(), json!(candidate.subject.id));
    if let Some(identity_id) = &candidate.identity_id {
        metadata.insert("identityId".into(), json!(identity_id));
    }
    if let Some(network) = &candidate.network {
        metadata.insert("network".into(), json!(network));
    }
    metadata.insert("incidentId".into(), json!(incident_id));
    threat_audit(
        ctx,
        tx,
        tenant_id,
        &automatic,
        "threat:detection",
        &format!("threats/detections/{detection_id}"),
        &metadata,
    )
    .await?;
    if opened {
        let mut metadata: IndexMap<String, Value> = IndexMap::new();
        metadata.insert("ruleId".into(), candidate.rule_id.clone());
        metadata.insert(
            "severity".into(),
            incident.get("severity").cloned().unwrap_or(Value::Null),
        );
        metadata.insert(
            "subjectType".into(),
            json!(subject_member(&incident, "type")),
        );
        metadata.insert("subjectId".into(), json!(subject_member(&incident, "id")));
        if let Some(identity_id) = defined_member(&incident, "identityId") {
            metadata.insert("identityId".into(), identity_id);
        }
        threat_audit(
            ctx,
            tx,
            tenant_id,
            &automatic,
            "threat:incident-open",
            &format!("threats/incidents/{incident_id}"),
            &metadata,
        )
        .await?;
    }
    if let Some(identity_id) = &candidate.identity_id {
        let points = candidate
            .severity
            .as_str()
            .and_then(|severity| RISK_POINTS.get(severity))
            .cloned()
            .unwrap_or(Value::Null);
        let mut add = Record::new();
        add.insert("detectionId".into(), json!(detection_id));
        add.insert("ruleId".into(), candidate.rule_id.clone());
        add.insert("severity".into(), candidate.severity.clone());
        add.insert("points".into(), points);
        add.insert("at".into(), number(now));
        recompute(
            ctx,
            tx,
            tenant_id,
            identity_id,
            settings,
            now,
            None,
            Some(add),
            &[],
        )
        .await?;
    }
    Ok(Recorded {
        detection,
        incident,
        incident_opened: opened,
        created: true,
    })
}

/// `JSON.parse(JSON.stringify(value))` of a typed member, as the record stores it (numbers as JavaScript writes
/// them: `1`, not `1.0`).
fn to_json<T: serde::Serialize>(value: &T) -> Value {
    fn normalize(value: Value) -> Value {
        match value {
            Value::Number(number) => number_value(core_js::number_value(&number)),
            Value::Array(items) => Value::Array(items.into_iter().map(normalize).collect()),
            Value::Object(map) => {
                Value::Object(map.into_iter().map(|(k, v)| (k, normalize(v))).collect())
            }
            other => other,
        }
    }
    serde_json::to_value(value)
        .map(normalize)
        .unwrap_or(Value::Null)
}

fn number_value(value: f64) -> Value {
    crate::js::number(value)
}

/// Whether a contribution's detection still counts: not dismissed, and not resolved in an incident closed as a false
/// positive or benign. A detection that no longer exists does not count.
async fn still_counts(
    tx: &Store,
    tenant_id: &str,
    detection_id: &str,
    incidents: &Mutex<HashMap<String, Option<Record>>>,
) -> IamResult<bool> {
    let Some(detection) = tx.get(collection("detections"), detection_id).await? else {
        return Ok(false);
    };
    if str_member(&detection, "tenantId") != Some(tenant_id)
        || str_member(&detection, "status") == Some("dismissed")
    {
        return Ok(false);
    }
    let incident_id = match detection.get("incidentId") {
        Some(Value::String(incident_id)) => incident_id.clone(),
        _ => return Ok(true),
    };
    if str_member(&detection, "status") != Some("resolved") {
        return Ok(true);
    }
    let cached = locked(incidents).get(&incident_id).cloned();
    let incident = match cached {
        Some(incident) => incident,
        None => {
            let incident = tx.get(collection("incidents"), &incident_id).await?;
            locked(incidents).insert(incident_id.clone(), incident.clone());
            incident
        }
    };
    let resolution = incident
        .as_ref()
        .and_then(|incident| str_member(incident, "resolution"));
    Ok(resolution != Some("false-positive") && resolution != Some("benign"))
}

/// Recomputes an identity's risk record (`identityRisk`, id = identity id) in this tenant: adds `options.add`,
/// drops `options.drop` and, when nothing is added, every contribution whose detection was dismissed or resolved as
/// a false positive or benign; prunes contributions older than ten half-lives (ten days at least), keeps the newest
/// 50, drops a lapsed override, and stores the effective score and level. A level change is audited as
/// `threat:risk-change` (`{from, to, score}`, by `actorId` or the `threat-detection` actor). Undefined for
/// identities outside the tenant or deleted, and when there is no record and nothing to add.
#[allow(clippy::too_many_arguments)]
pub async fn recompute_risk(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    settings: &crate::threats::ResolvedThreatSettings,
    now: f64,
    actor_id: Option<&str>,
    options: Option<&Value>,
) -> IamResult<Option<crate::threats::IdentityRisk>> {
    let add = defined(crate::js::member(options, "add"))
        .and_then(Value::as_object)
        .cloned();
    let drop: Vec<String> = match crate::js::member(options, "drop") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| crate::js::js_string(Some(item)))
            .collect(),
        _ => Vec::new(),
    };
    match recompute(
        ctx,
        tx,
        tenant_id,
        identity_id,
        settings,
        now,
        actor_id,
        add,
        &drop,
    )
    .await?
    {
        Some(record) => Ok(Some(decode(record)?)),
        None => Ok(None),
    }
}

/// [`recompute_risk`] over stored records: `add` is the contribution to add, `drop` the detections to drop.
#[allow(clippy::too_many_arguments)]
async fn recompute(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    settings: &ResolvedThreatSettings,
    now: f64,
    actor_id: Option<&str>,
    add: Option<Record>,
    drop: &[String],
) -> IamResult<Option<Record>> {
    let Some(identity) = tx.get("identities", identity_id).await? else {
        return Ok(None);
    };
    if str_member(&identity, "tenantId") != Some(tenant_id)
        || str_member(&identity, "status") == Some("deleted")
    {
        return Ok(None);
    }
    let stored = tx.get(collection("risk"), identity_id).await?;
    if let Some(stored) = &stored
        && str_member(stored, "tenantId") != Some(tenant_id)
    {
        return Ok(None);
    }
    if stored.is_none() && add.is_none() {
        return Ok(None);
    }
    // Never sooner than ten default half-lives: a half-life shortened for a while (threats.configure) decays scores at
    // once, but restoring it brings them back rather than finding the contributions gone.
    let default_half_life = DEFAULT_THREAT_SETTINGS
        .get("riskHalfLifeHours")
        .and_then(Value::as_f64)
        .unwrap_or(24.0);
    let cutoff =
        now - CONTRIBUTION_HALF_LIVES * default_half_life.max(settings.risk_half_life_hours) * HOUR;
    let dropped: IndexSet<&str> = drop.iter().map(String::as_str).collect();
    let incidents: Mutex<HashMap<String, Option<Record>>> = Mutex::new(HashMap::new());
    let mut kept: Vec<Value> = Vec::new();
    let mut seen: IndexSet<String> = IndexSet::new();
    let contribution_id = |contribution: &Value| {
        crate::js::js_string(crate::js::member(Some(contribution), "detectionId"))
    };
    let contribution_at = |contribution: &Value| {
        crate::js::member(Some(contribution), "at")
            .map(core_js::to_number)
            .unwrap_or(f64::NAN)
    };
    let contributions: Vec<Value> = stored
        .as_ref()
        .and_then(|stored| stored.get("contributions"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for contribution in contributions {
        let detection_id = contribution_id(&contribution);
        if dropped.contains(detection_id.as_str()) || seen.contains(&detection_id) {
            continue;
        }
        if contribution_at(&contribution) < cutoff {
            continue;
        }
        // A new detection cannot have changed older ones; dismissals and resolutions recompute without adding.
        if add.is_none() && !still_counts(tx, tenant_id, &detection_id, &incidents).await? {
            continue;
        }
        seen.insert(detection_id);
        kept.push(contribution);
    }
    if let Some(add) = &add {
        let added = Value::Object(add.clone());
        let detection_id = contribution_id(&added);
        if !seen.contains(&detection_id) && !dropped.contains(detection_id.as_str()) {
            kept.push(added);
        }
    }
    kept.sort_by(|a, b| {
        let difference = contribution_at(a) - contribution_at(b);
        if difference.is_nan() {
            std::cmp::Ordering::Equal
        } else {
            difference.total_cmp(&0.0)
        }
    });
    if kept.len() > MAX_CONTRIBUTIONS {
        kept.drain(..kept.len() - MAX_CONTRIBUTIONS);
    }
    let mut next = match &stored {
        Some(stored) => {
            let mut next = stored.clone();
            next.insert("contributions".into(), Value::Array(kept));
            next.insert("updatedAt".into(), number(now));
            next
        }
        None => {
            let mut next = Record::new();
            next.insert("id".into(), json!(identity_id));
            next.insert("tenantId".into(), json!(tenant_id));
            next.insert("identityId".into(), json!(identity_id));
            next.insert("contributions".into(), Value::Array(kept));
            next.insert("score".into(), number(0.0));
            next.insert("level".into(), json!("none"));
            next.insert("updatedAt".into(), number(now));
            next
        }
    };
    let lapsed = crate::js::member(next.get("override"), "expiresAt")
        .is_some_and(|expires| core_js::to_number(expires) <= now);
    if lapsed {
        next.shift_remove("override");
    }
    let typed: IdentityRisk = decode(next.clone())?;
    let effective = effective_risk(Some(&typed), now, settings.risk_half_life_hours)?;
    let previous = stored
        .as_ref()
        .and_then(|stored| defined(stored.get("level")))
        .cloned()
        .unwrap_or_else(|| json!("none"));
    next.insert(
        "score".into(),
        effective
            .get("score")
            .and_then(core_js::as_number)
            .map(number)
            .unwrap_or(Value::Null),
    );
    next.insert(
        "level".into(),
        effective.get("level").cloned().unwrap_or(Value::Null),
    );
    if stored.is_some() {
        tx.put(collection("risk"), &next).await?;
    } else {
        tx.insert(collection("risk"), &next).await?;
    }
    let level = next.get("level").cloned().unwrap_or(Value::Null);
    if !core_js::strict_equal(&level, &previous) {
        let mut metadata = Map::new();
        metadata.insert("from".into(), previous);
        metadata.insert("to".into(), level);
        metadata.insert(
            "score".into(),
            next.get("score").cloned().unwrap_or(Value::Null),
        );
        let mut event = Record::new();
        event.insert("id".into(), json!(id()));
        event.insert("tenantId".into(), json!(tenant_id));
        event.insert("actorId".into(), json!(actor_id.unwrap_or(THREAT_ACTOR)));
        event.insert("action".into(), json!("threat:risk-change"));
        event.insert("resourceId".into(), json!(identity_id));
        event.insert("timestamp".into(), number(ctx.now()));
        event.insert("outcome".into(), json!("allow"));
        event.insert("metadata".into(), Value::Object(metadata));
        ctx.events()?.record_audit(tx, &event).await?;
    }
    Ok(Some(next))
}

/// A playbook fires for a detection when every trigger clause it sets matches (unset or empty clauses match all).
fn playbook_matches(playbook: &ThreatPlaybook, detection: &ThreatDetection) -> IamResult<bool> {
    let trigger = Some(&playbook.trigger).filter(|trigger| !trigger.is_null());
    let list = |name: &str| match crate::js::member(trigger, name) {
        Some(Value::Array(items)) if !items.is_empty() => Some(items.clone()),
        _ => None,
    };
    if let Some(rule_ids) = list("ruleIds")
        && !rule_ids
            .iter()
            .any(|rule| core_js::strict_equal(rule, &detection.rule_id))
    {
        return Ok(false);
    }
    if let Some(min_severity) =
        crate::js::member(trigger, "minSeverity").filter(|value| crate::js::truthy(Some(value)))
        && !severity_at_least(&detection.severity, min_severity)?
    {
        return Ok(false);
    }
    if let Some(subject_types) = list("subjectTypes")
        && !subject_types
            .iter()
            .any(|subject_type| core_js::strict_equal(subject_type, &detection.subject.r#type))
    {
        return Ok(false);
    }
    Ok(true)
}

/// Runs the tenant's enabled playbooks whose trigger matches a new detection, oldest playbook first, each action in
/// order through `applyResponse` under the automatic actor, and counts the run on the playbook (`runs`,
/// `lastRunAt`). Containments share `brake` (one per tenant and run). Returns every response recorded, applied or
/// skipped; after the transaction commits the caller runs `afterThreatResponses`.
pub async fn run_playbooks(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    detection: &crate::threats::ThreatDetection,
    incident: &crate::threats::ThreatIncident,
    settings: &crate::threats::ResolvedThreatSettings,
    brake: &mut crate::threat_response::PlaybookBrake,
) -> IamResult<Vec<crate::threats::ThreatResponse>> {
    let mut playbooks: Vec<(Record, ThreatPlaybook)> = Vec::new();
    for record in tx
        .find(
            collection("playbooks"),
            &Filter::new().eq("tenantId", tenant_id).eq("enabled", true),
            &FindOptions::default(),
        )
        .await?
    {
        let playbook: ThreatPlaybook = decode(record.clone())?;
        if playbook_matches(&playbook, detection)? {
            playbooks.push((record, playbook));
        }
    }
    playbooks.sort_by(|(_, a), (_, b)| {
        let difference = a.created_at - b.created_at;
        if difference != 0.0 && !difference.is_nan() {
            difference.total_cmp(&0.0)
        } else {
            by_id(&a.id, &b.id)
        }
    });
    let mut responses: Vec<ThreatResponse> = Vec::new();
    for (record, playbook) in playbooks {
        for action in &playbook.actions {
            if !action
                .kind
                .as_str()
                .is_some_and(|kind| RESPONSE_ACTION_KINDS.contains(&kind))
            {
                continue;
            }
            let request = ResponseRequest {
                action: action.clone(),
                subject: detection.subject.clone(),
                identity_id: detection.identity_id.clone(),
                network: detection.network.clone(),
                incident_id: Some(incident.id.clone()),
                detection_id: Some(detection.id.clone()),
                playbook_id: Some(playbook.id.clone()),
                reason: format!("Playbook {}: {}", playbook.name, detection.title),
                actor: ResponseActor::Automatic,
            };
            responses.push(
                apply_response(ctx, tx, tenant_id, &request, settings, Some(&mut *brake)).await?,
            );
        }
        let mut updated = record;
        let runs = match updated.get("runs") {
            None | Some(Value::Null) => 0.0,
            Some(runs) => core_js::to_number(runs),
        };
        updated.insert("runs".into(), number(runs + 1.0));
        updated.insert("lastRunAt".into(), number(ctx.now()));
        tx.put(collection("playbooks"), &updated).await?;
    }
    Ok(responses)
}
