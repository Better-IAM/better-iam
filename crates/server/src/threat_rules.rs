//! Port of `packages/server/src/threat-rules.ts`.
//!
//! The detection rules of the threats module (`threatRules` in threats.ts) as pure evaluation: given one run's
//! unread audit events of a tenant, the events before them that the rules' windows reach back to, the tenant's
//! settings, and read-only facts about identities and roles, it returns the detections to record. Nothing is written
//! here. The engine (threat-engine.ts) records the candidates (deduplicated by `{ruleId}:{dedupeKey}`), persists the
//! sign-in baselines the rules updated, and keeps `state` on its cursor.
//!
//! Per-event rules run in chain order, so a risky sign-in earlier in the run opens the account-takeover window for a
//! change later in it. Counting rules slide a window over history and new events together and fire only for windows
//! that end at a new event, so every event is judged once, and a burst keeps one dedupe key however many runs see it
//! (`burstAnchor`).
//!
//! Events are read as stored records (`Record`), not decoded `AuditEvent`s: a stored event with a missing or mistyped
//! member (one an intruder edited) must be skipped by `considered`, as the TypeScript does, rather than fail the run.

use std::collections::{HashMap, HashSet};

use better_iam_core::boxed;
use better_iam_core::{
    AuditEvent, IamResult, Identity, IdentityKind, Record, ip_counter_key, ip_matches,
    js as core_js,
};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::threats::{
    ResolvedThreatSettings, THREAT_ACTOR, ThreatEvidence, ThreatSubject, max_severity, threat_rule,
    threat_rule_ids,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionCandidate {
    #[serde(rename = "ruleId")]
    pub rule_id: crate::threats::ThreatRuleId,
    #[serde(rename = "severity")]
    pub severity: crate::threats::ThreatSeverity,
    #[serde(rename = "title")]
    pub title: String,
    #[serde(rename = "summary")]
    pub summary: String,
    #[serde(rename = "subject")]
    pub subject: crate::threats::ThreatSubject,
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(rename = "network", default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Stable per burst / per triggering event; uniqueKey = `${ruleId}:${dedupeKey}` (≤ 400 chars, no control chars).
    #[serde(rename = "dedupeKey")]
    pub dedupe_key: String,
    #[serde(rename = "occurredAt")]
    pub occurred_at: f64,
    #[serde(rename = "evidence")]
    pub evidence: crate::threats::ThreatEvidence,
    #[serde(rename = "metadata", default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<IndexMap<String, better_iam_core::Json>>,
    /// For sign-in rules: marks the baseline's riskySignIn after the engine stores the detection.
    #[serde(
        rename = "riskySignIn",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub risky_sign_in: Option<bool>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Read-only facts the rules may ask about a tenant (`RuleFacts`). The engine reads them from the store and caches
/// them for the run.
#[async_trait::async_trait]
pub trait RuleFacts: Send + Sync {
    /// Identity by id in this tenant (None when unknown/deleted).
    async fn identity(&self, id: &str) -> IamResult<Option<Identity>>;
    /// Owner, rootAdmin, or holds (directly or via a group; live standing binding) a role whose policies grant
    /// unconditional `*` or `iam:*` on `*` (analysis.ts unrestrictedAdmin logic).
    async fn is_privileged(&self, identity_id: &str) -> IamResult<bool>;
    /// Role grants unconditional `*`/`iam:*` on `*`.
    async fn is_admin_role(&self, role_id: &str) -> IamResult<bool>;
    /// Identity holds a live standing binding of the role, directly or through a group membership.
    async fn holds_role(&self, identity_id: &str, role_id: &str) -> IamResult<bool>;
    /// Whether a stored detection still stands: not dismissed, and not resolved in an incident closed as a false
    /// positive or benign. None (the TypeScript member absent): every stored detection stands.
    async fn detection_stands(&self, _detection_id: &str) -> IamResult<Option<bool>> {
        Ok(None)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleState {
    /// Tenant sign-in policy as last seen (cursor.authPolicy); rules update it when they read tenant:auth-policy.
    #[serde(
        rename = "authPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_policy: Option<IndexMap<String, better_iam_core::Json>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What one evaluation reads (`RuleInput`).
pub struct RuleInput<'a> {
    pub tenant_id: String,
    /// Unread events of this run, ascending by sequence (the engine already dropped `threat:*` actions and actor
    /// `threat-detection`).
    pub events: &'a [Record],
    /// Events in the lookback window before/overlapping `events` (timestamp >= min(event ts) - `ruleWindowMs`),
    /// ascending by timestamp; may include ids also in `events` (deduplicated by id). Same filtering as events.
    pub history: &'a [Record],
    /// Set when the lookback was cut short (the engine keeps only the newest events up to a cap): the timestamp of
    /// the oldest event loaded. A burst whose events reach back to within a window of it may have begun earlier, so
    /// its anchor is the start of its UTC day, which every later run computes alike (`findBursts`).
    pub history_from: Option<f64>,
    pub settings: ResolvedThreatSettings,
    /// Baselines (stored `threatBaselines` records) by identity id for the identities the engine preloaded
    /// (`baselineIdentityIds(events)`); rules mutate them in place and create missing ones for people who sign in.
    pub baselines: IndexMap<String, Record>,
    pub state: RuleState,
    pub facts: &'a dyn RuleFacts,
    pub now: f64,
}

/// What an evaluation returns: the detections to record, oldest first, and the identities whose baselines changed.
pub struct RuleEvaluation {
    pub candidates: Vec<DetectionCandidate>,
    pub touched_baselines: IndexSet<String>,
}

const MINUTE: f64 = 60_000.0;
const HOUR: f64 = 60.0 * MINUTE;
const DAY: f64 = 24.0 * HOUR;
/// Evidence lists (event ids, networks, identities, actions) keep at most this many entries.
const EVIDENCE_LIMIT: usize = 20;
/// Longest `uniqueKey` (`{ruleId}:{dedupeKey}`) a detection may have.
const UNIQUE_KEY_LIMIT: usize = 400;
const BASELINE_NETWORK_LIMIT: usize = 25;
const BASELINE_USER_AGENT_LIMIT: usize = 10;
/// The auth service caps recorded user agents at this length; stored baselines never hold longer ones.
const USER_AGENT_LENGTH: usize = 512;

/// Actors that stand for the deployment, a protocol, or the application rather than an identity.
const SYSTEM_ACTORS: &[&str] = &[
    "deployment-operator",
    THREAT_ACTOR,
    "directory-sync",
    "dynamic-registration",
    "access-package",
    "public-intake",
    "application",
];

/// Allowed actions mass-deletion counts. Domain events stand in for their operation envelopes where they exist:
/// `identity:delete` is written by identity, service-account, and agent deletion (whose envelopes are
/// `iam:identities:delete` and `iam:agents:delete`, so those are not counted twice), and `identity:offboard` rides on
/// `iam:identities:update`.
const DELETION_ACTIONS: &[&str] = &[
    "identity:delete",
    "identity:offboard",
    "iam:roles:delete",
    "iam:policies:delete",
    "iam:groups:delete",
    "iam:bindings:delete",
    "iam:credentials:revoke",
    "iam:trust:revoke",
    "iam:webhooks:delete",
    "iam:resource-types:delete",
];

/// Refusals recorded for callers nobody authenticated, under the identity they tried to act as. A web identity token
/// refused by `assumeRoleWithWebIdentity` is recorded as a denial of the trust's service account, but trust ids are
/// public (they sit in CI workflow files) and anyone may post tokens for one, so these never count as that account's
/// denials (denial-burst). token-replay still reads the replays among them, which only a verified token can cause.
const UNAUTHENTICATED_REFUSALS: &[&str] = &["role:assumed-with-web-identity"];

/// Changes to a person's own sign-in methods that keep an intruder in after a takeover, as summaries word them.
const PERSISTENCE_CHANGES: &[(&str, &str)] = &[
    ("auth:mfa:disable", "turned off their second factor"),
    // An intruder's own authenticator on an account that had none locks the account holder out of their next sign-in.
    ("auth:mfa:enable", "enrolled an authenticator app"),
    ("auth:passkey:create", "added a passkey"),
    ("auth:mfa:recovery-codes", "generated new recovery codes"),
    ("auth:device:trust", "remembered a device"),
    ("auth:email:change", "changed their email address"),
    ("auth:password:change", "changed their password"),
    ("iam:credentials:create", "created an API key"),
];

fn persistence_change(action: &str) -> Option<&'static str> {
    PERSISTENCE_CHANGES
        .iter()
        .find(|(name, _)| *name == action)
        .map(|(_, change)| *change)
}

type Weakened = fn(&IndexMap<String, Value>, &IndexMap<String, Value>) -> bool;

fn dropped_flag(
    name: &str,
    before: &IndexMap<String, Value>,
    after: &IndexMap<String, Value>,
) -> bool {
    before.get(name) == Some(&Value::Bool(true)) && after.get(name) != Some(&Value::Bool(true))
}

fn non_empty_list(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Array(items)) if !items.is_empty())
}

/// Protections of the tenant sign-in policy whose removal guardrail-weakened reports.
const POLICY_PROTECTIONS: &[(&str, &str, Weakened)] = &[
    ("requireMfa", "the MFA requirement", |before, after| {
        dropped_flag("requireMfa", before, after)
    }),
    (
        "requireMfaForOwners",
        "the MFA requirement for owners",
        |before, after| dropped_flag("requireMfaForOwners", before, after),
    ),
    (
        "bindSessionsToIp",
        "binding sessions to their network",
        |before, after| dropped_flag("bindSessionsToIp", before, after),
    ),
    ("allowedIpRanges", "the IP allowlist", |before, after| {
        non_empty_list(before.get("allowedIpRanges"))
            && !non_empty_list(after.get("allowedIpRanges"))
    }),
    ("notifyNewSignIn", "new sign-in notices", |before, after| {
        dropped_flag("notifyNewSignIn", before, after)
    }),
];

/// Rules that count events per key in a sliding window (`findBursts`).
const COUNTING_RULES: &[&str] = &[
    "password-spray",
    "brute-force",
    "mfa-bombardment",
    "mass-deletion",
    "directory-mass-change",
    "impersonation-burst",
    "denial-burst",
    "classified-access-attempts",
    "recon-burst",
];

/// An enabled rule's severity, threshold, and window, with the definition's defaults behind the tenant's values.
struct Tuned {
    setting: Value,
    severity: Value,
    threshold: f64,
    window_ms: f64,
}

/// A counting window: `{ threshold, windowMs }`.
#[derive(Clone, Copy)]
struct Window {
    threshold: f64,
    window_ms: f64,
}

impl Tuned {
    fn window(&self) -> Window {
        Window {
            threshold: self.threshold,
            window_ms: self.window_ms,
        }
    }
}

fn positive(value: Option<&Value>, fallback: f64) -> f64 {
    match value.and_then(core_js::as_number) {
        Some(number) if number.is_finite() && number > 0.0 => number,
        _ => fallback,
    }
}

/// JavaScript truthiness of an optional JSON value.
fn truthy(value: Option<&Value>) -> bool {
    crate::js::truthy(value)
}

/// The rule's tuning when the tenant has it enabled.
fn tuned(settings: &ResolvedThreatSettings, rule_id: &str) -> IamResult<Option<Tuned>> {
    let setting = settings.rules.get(rule_id);
    if !truthy(setting.and_then(|setting| crate::js::member(Some(setting), "enabled"))) {
        return Ok(None);
    }
    let setting = setting.cloned().unwrap_or(Value::Null);
    let definition = threat_rule(&json!(rule_id))?;
    Ok(Some(Tuned {
        severity: setting.get("severity").cloned().unwrap_or(Value::Null),
        threshold: positive(
            setting.get("threshold"),
            definition.threshold.unwrap_or(1.0),
        ),
        window_ms: positive(
            setting.get("windowMs"),
            definition.window_ms.unwrap_or(HOUR),
        ),
        setting,
    }))
}

/// The dedupe anchor of a qualifying window ending at `at`: the first event of its cluster (events of one key no more
/// than a window apart), but never before the start of the UTC day of `at`, so activity that never pauses raises at
/// most one detection a day. Every run that sees the window computes the same anchor as long as its history reaches
/// `burstReach` back. Windows of a day or longer use window-sized buckets instead.
fn burst_anchor(cluster_start: f64, at: f64, window_ms: f64) -> f64 {
    if window_ms >= DAY {
        return (at / window_ms).floor() * window_ms;
    }
    cluster_start.max((at / DAY).floor() * DAY)
}

/// History a counting rule needs for stable anchors: the anchor's day (or bucket) plus one window before it.
fn burst_reach(window_ms: f64) -> f64 {
    if window_ms >= DAY {
        window_ms
    } else {
        DAY + window_ms
    }
}

/// How far before a run's earliest event the engine loads history: the longest reach of an enabled rule, at least
/// one day. A counting rule reaches back one window plus the UTC day its burst anchor may lie in (`burstAnchor`),
/// so an ongoing burst keeps its dedupe key from run to run; brute-force-success reaches back its window. With the
/// default settings this is one day and fifteen minutes.
pub fn rule_window_ms(settings: &crate::threats::ResolvedThreatSettings) -> IamResult<f64> {
    let mut reach = DAY;
    for rule_id in COUNTING_RULES {
        if let Some(rule) = tuned(settings, rule_id)? {
            reach = reach.max(burst_reach(rule.window_ms));
        }
    }
    if let Some(success) = tuned(settings, "brute-force-success")? {
        reach = reach.max(success.window_ms);
    }
    Ok(reach)
}

/// Identities whose stored baselines the rules read for these events: people who signed in (not through
/// impersonation), whose baselines the sign-in rules compare and update, and people who changed their own sign-in
/// methods, for whom account-takeover-persistence reads the risky sign-in an earlier run marked. The engine
/// preloads these into `RuleInput.baselines`.
pub fn baseline_identity_ids(events: &[better_iam_core::AuditEvent]) -> IamResult<Vec<String>> {
    let records: Vec<Record> = events.iter().map(crate::port::encode).collect();
    Ok(baseline_identity_ids_of(records.iter()))
}

/// [`baseline_identity_ids`] over stored event records.
pub(crate) fn baseline_identity_ids_of<'r>(
    events: impl IntoIterator<Item = &'r Record>,
) -> Vec<String> {
    let mut ids: IndexSet<String> = IndexSet::new();
    for event in events {
        let action = action(event);
        if (action == "auth:session:create" && !truthy(event.get("impersonatorId")))
            || (persistence_change(action).is_some() && same_member(event, "resourceId", "actorId"))
        {
            ids.insert(js_text(event.get("actorId")));
        }
    }
    ids.into_iter().collect()
}

/// `event.a === event.b` for two members.
fn same_member(event: &Record, a: &str, b: &str) -> bool {
    match (event.get(a), event.get(b)) {
        (None, None) => true,
        (Some(left), Some(right)) => core_js::strict_equal(left, right),
        _ => false,
    }
}

/// `${value}` for the string members the rules read (only called on members `considered` checked).
fn js_text(value: Option<&Value>) -> String {
    crate::js::js_string(value)
}

/// A sign-in a rule flagged, opening the account-takeover-persistence window.
#[derive(Clone)]
struct RiskySignIn {
    at: f64,
    rule_id: Value,
    /// The sign-in event, when it was judged in this run.
    event_id: Option<String>,
    /// The stored detection, when an earlier run recorded it (the baseline's riskySignIn).
    detection_id: Option<Value>,
    /// The candidate's unique key, when it was raised in this run.
    unique_key: Option<String>,
}

/// One evaluation: its input, memoized reads, and the candidates found so far (merged by unique key).
struct Run<'i, 'a> {
    input: &'i mut RuleInput<'a>,
    identities: HashMap<String, Option<Identity>>,
    found: IndexMap<String, DetectionCandidate>,
}

impl Run<'_, '_> {
    async fn identity(&mut self, identity_id: &str) -> IamResult<Option<Identity>> {
        if let Some(identity) = self.identities.get(identity_id) {
            return Ok(identity.clone());
        }
        let identity = self.input.facts.identity(identity_id).await?;
        self.identities
            .insert(identity_id.to_owned(), identity.clone());
        Ok(identity)
    }

    fn add(&mut self, candidate: DetectionCandidate) {
        let unique_key = format!(
            "{}:{}",
            js_text(Some(&candidate.rule_id)),
            candidate.dedupe_key
        );
        if let Some(existing) = self.found.get_mut(&unique_key) {
            merge(existing, &candidate);
        } else {
            self.found.insert(unique_key, candidate);
        }
    }
}

/// True when the address lies in one of the tenant's trusted networks, which detections never report.
fn trusted(settings: &ResolvedThreatSettings, ip: &str) -> bool {
    settings
        .trusted_networks
        .iter()
        .any(|network| ip_matches(ip, network))
}

/// Evaluates every enabled rule over one run's events. Returns the detections to record, oldest first, and the
/// identities whose baselines changed (created, or updated by a sign-in); the engine persists those.
pub async fn evaluate_threat_rules(input: &mut RuleInput<'_>) -> IamResult<RuleEvaluation> {
    let events_in = input.events;
    let history_in = input.history;
    let ordered = chronological(history_in.iter().chain(events_in.iter()));
    let mut fresh: HashSet<&str> = HashSet::new();
    let mut events: Vec<&Record> = Vec::new();
    for event in events_in {
        if considered_record(event) && fresh.insert(id_of(event)) {
            events.push(event);
        }
    }
    let mut context = EventContext {
        sign_ins: index_sign_ins(&ordered),
        risky: HashMap::new(),
        touched: IndexSet::new(),
    };
    let mut run = Run {
        input,
        identities: HashMap::new(),
        found: IndexMap::new(),
    };
    for event in events {
        evaluate_event(&mut run, event, &mut context).await?;
    }
    evaluate_counting(&mut run, &ordered, &fresh).await?;
    let mut candidates: Vec<DetectionCandidate> = run.found.into_values().collect();
    candidates.sort_by(|a, b| a.occurred_at.total_cmp(&b.occurred_at));
    Ok(RuleEvaluation {
        candidates,
        touched_baselines: context.touched,
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Event shapes

/// Events the rules read: well formed, and not the threats module's own. The engine filters with it too, so a
/// stored event with a missing or mistyped field (one an intruder edited, say) is reported by the chain check and
/// otherwise skipped, never stopping detection for its tenant.
pub fn considered(event: &better_iam_core::AuditEvent) -> IamResult<bool> {
    Ok(considered_record(&crate::port::encode::<AuditEvent>(event)))
}

/// [`considered`] over a stored event record.
pub(crate) fn considered_record(event: &Record) -> bool {
    let string = |name: &str| matches!(event.get(name), Some(Value::String(_)));
    string("id")
        && string("action")
        && string("actorId")
        && string("resourceId")
        && event
            .get("timestamp")
            .and_then(core_js::as_number)
            .is_some_and(f64::is_finite)
        && actor_id(event) != THREAT_ACTOR
        && !action(event).starts_with("threat:")
}

fn str_member<'r>(event: &'r Record, name: &str) -> &'r str {
    event.get(name).and_then(Value::as_str).unwrap_or("")
}
fn id_of(event: &Record) -> &str {
    str_member(event, "id")
}
fn action(event: &Record) -> &str {
    str_member(event, "action")
}
fn actor_id(event: &Record) -> &str {
    str_member(event, "actorId")
}
fn resource_id(event: &Record) -> &str {
    str_member(event, "resourceId")
}
fn timestamp(event: &Record) -> f64 {
    event
        .get("timestamp")
        .and_then(core_js::as_number)
        .unwrap_or(f64::NAN)
}
fn outcome_is(event: &Record, outcome: &str) -> bool {
    event.get("outcome").and_then(Value::as_str) == Some(outcome)
}
/// `event.metadata?.[name]`.
fn meta<'r>(event: &'r Record, name: &str) -> Option<&'r Value> {
    crate::js::member(event.get("metadata"), name)
}
/// `event.metadata?.[name]` as a string, when it is one.
fn meta_str<'r>(event: &'r Record, name: &str) -> Option<&'r str> {
    meta(event, name).and_then(Value::as_str)
}

/// History and new events together, each once, oldest first.
fn chronological<'r>(events: impl IntoIterator<Item = &'r Record>) -> Vec<&'r Record> {
    let mut by_id: IndexMap<&str, &Record> = IndexMap::new();
    for event in events {
        if considered_record(event) {
            by_id.insert(id_of(event), event);
        }
    }
    let mut ordered: Vec<&Record> = by_id.into_values().collect();
    let sequence = |event: &Record| event.get("sequence").map(core_js::to_number).unwrap_or(0.0);
    ordered.sort_by(|a, b| {
        let by_time = timestamp(a) - timestamp(b);
        if by_time != 0.0 && !by_time.is_nan() {
            return by_time.total_cmp(&0.0);
        }
        let by_sequence = sequence(a) - sequence(b);
        if by_sequence != 0.0 && !by_sequence.is_nan() {
            return by_sequence.total_cmp(&0.0);
        }
        core_js::cmp_utf16(id_of(a), id_of(b))
    });
    ordered
}

/// Written by the service that owns the action, not an application `authorize()` call: those record only denials
/// and root overrides, under any action name the application passes and without metadata (a clearance refusal
/// carries only the server's `{ mandatory: 'clearance' }` marker, `mandatoryRefusal`).
fn recorded(event: &Record) -> bool {
    event.get("rootOverride") != Some(&Value::Bool(true))
}

/// Actors that are identities (people, service accounts, agents), not the deployment or a SCIM connection.
fn identity_actor(actor_id: &str) -> bool {
    !SYSTEM_ACTORS.contains(&actor_id)
        && !actor_id.starts_with("scim:")
        && !actor_id.starts_with("signal:")
}

/// Who is behind an event: the administrator of a "view as" session (`impersonatorId`) rather than the member it
/// shows as, so what support staff do while viewing as someone never counts against, or raises the risk of, that
/// person.
fn responsible_actor(event: &Record) -> &str {
    match event.get("impersonatorId") {
        Some(Value::String(impersonator)) if !impersonator.is_empty() => impersonator,
        _ => actor_id(event),
    }
}

/// Members a burst's events were performed as, through "view as" sessions of its actor.
fn viewed_as(events: &[&Record]) -> Vec<String> {
    limited(events.iter().map(|event| {
        (responsible_actor(event) != actor_id(event)).then(|| actor_id(event).to_owned())
    }))
}

/// How a summary notes a burst performed (partly) through "view as" sessions, with `viewedAs` metadata.
fn viewing(events: &[&Record]) -> (String, IndexMap<String, Value>) {
    let members = viewed_as(events);
    if members.is_empty() {
        return (String::new(), IndexMap::new());
    }
    let all = events
        .iter()
        .all(|event| responsible_actor(event) != actor_id(event));
    let whom = if members.len() == 1 {
        "someone else".to_owned()
    } else {
        format!("{} other people", members.len())
    };
    let mut metadata = IndexMap::new();
    metadata.insert("viewedAs".to_owned(), json!(members));
    (
        format!(
            ", {} while viewing as {whom}",
            if all { "all" } else { "some" }
        ),
        metadata,
    )
}

/// How a summary notes a burst an AI agent took part in (the actor is an agent, or its events were made in a
/// delegated session), with `agent` (and the first `agentId` seen) metadata.
fn agent_involvement(who: &Named, events: &[&Record]) -> (String, IndexMap<String, Value>) {
    let agent_id = events
        .iter()
        .find_map(|event| {
            crate::js::member(event.get("sessionContext"), "agentId")
                .filter(|value| truthy(Some(value)))
        })
        .cloned();
    let is_agent = who
        .identity
        .as_ref()
        .is_some_and(|identity| identity.kind == IdentityKind::Agent);
    let agent = is_agent || agent_id.is_some();
    let clause = if is_agent {
        " (an AI agent)"
    } else if agent_id.is_some() {
        ", acting through an AI agent,"
    } else {
        ""
    };
    let mut metadata = IndexMap::new();
    metadata.insert("agent".to_owned(), Value::Bool(agent));
    if let Some(agent_id) = agent_id {
        metadata.insert("agentId".to_owned(), agent_id);
    }
    (clause.to_owned(), metadata)
}

/// A failed sign-in the auth service recorded (`auth:signin:fail`), optionally of one reason.
fn sign_in_failure(event: &Record, reason: Option<&str>) -> bool {
    let recorded_reason = meta_str(event, "reason");
    action(event) == "auth:signin:fail"
        && outcome_is(event, "allow")
        && recorded(event)
        && recorded_reason.is_some()
        && reason.is_none_or(|reason| recorded_reason == Some(reason))
}

/// A decision refused by mandatory access control (security clearances): a `deny` recorded with the server's
/// `{ mandatory: 'clearance' }` marker, under whatever action the caller asked for. The marker says nothing about
/// the label or which dimension of it the session failed.
fn mandatory_refusal(event: &Record) -> bool {
    outcome_is(event, "deny")
        && meta_str(event, "mandatory").is_some_and(|marker| !marker.is_empty())
}

/// A sign-in session the person started themselves (`auth:session:create` without an impersonating administrator).
fn own_sign_in(event: &Record) -> bool {
    action(event) == "auth:session:create"
        && outcome_is(event, "allow")
        && !truthy(event.get("impersonatorId"))
        && recorded(event)
}

#[derive(Clone)]
struct ClientNetwork {
    ip: String,
    /// `ipCounterKey` form: an IPv4 address, or an IPv6 /64.
    key: String,
}

fn client_network(value: Option<&Value>) -> Option<ClientNetwork> {
    let ip = value?.as_str()?;
    let key = ip_counter_key(ip)?;
    Some(ClientNetwork {
        ip: ip.to_owned(),
        key,
    })
}

/// The network's key, unless it is trusted (trusted networks never appear in a detection).
fn reportable_key(
    settings: &ResolvedThreatSettings,
    network: Option<&ClientNetwork>,
) -> Option<String> {
    network
        .filter(|network| !trusted(settings, &network.ip))
        .map(|network| network.key.clone())
}

/// Distinct reportable networks the events came from.
fn reportable_networks(settings: &ResolvedThreatSettings, events: &[&Record]) -> Vec<String> {
    distinct_values(
        events
            .iter()
            .map(|event| reportable_key(settings, client_network(meta(event, "ip")).as_ref())),
    )
}

/// `{ [key: string]: Json }`: a JSON object.
fn json_object(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

// ---------------------------------------------------------------------------------------------------------------
// Per-event rules

/// Sign-in events per person, oldest first: failures of any reason, and sign-ins not made through impersonation.
struct SignInIndex<'r> {
    failures: HashMap<&'r str, Vec<&'r Record>>,
    sign_ins: HashMap<&'r str, Vec<&'r Record>>,
    /// Position of each sign-in in its person's list.
    positions: HashMap<&'r str, usize>,
    /// Position of each indexed failure and sign-in in the run's chronological order (timestamp, then chain
    /// sequence).
    order: HashMap<&'r str, usize>,
}

struct EventContext<'r> {
    sign_ins: SignInIndex<'r>,
    /// The latest risky sign-in flagged in this run, per identity.
    risky: HashMap<String, RiskySignIn>,
    /// Identities whose baselines changed.
    touched: IndexSet<String>,
}

fn index_sign_ins<'r>(ordered: &[&'r Record]) -> SignInIndex<'r> {
    let mut index = SignInIndex {
        failures: HashMap::new(),
        sign_ins: HashMap::new(),
        positions: HashMap::new(),
        order: HashMap::new(),
    };
    for (position, event) in ordered.iter().enumerate() {
        let event: &'r Record = event;
        if sign_in_failure(event, None) {
            index
                .failures
                .entry(actor_id(event))
                .or_default()
                .push(event);
        } else if own_sign_in(event) {
            let list = index.sign_ins.entry(actor_id(event)).or_default();
            list.push(event);
            index.positions.insert(id_of(event), list.len() - 1);
        } else {
            continue;
        }
        index.order.insert(id_of(event), position);
    }
    index
}

/// The first index of a time-ordered list whose event passes a test that, once passed, stays passed.
fn first_index(list: &[&Record], test: impl Fn(&Record) -> bool) -> usize {
    let mut low = 0;
    let mut high = list.len();
    while low < high {
        let middle = (low + high) / 2;
        if test(list[middle]) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    low
}

/// The person's failed sign-ins in the `windowMs` before a sign-in and after their previous one: the streak the
/// sign-in ended, as the auth service's sign-in ledger counts it. A failure belongs to the streak when it comes after
/// the previous sign-in in chronological order (so an attempt stamped in the same millisecond as that sign-in but
/// recorded after it, as the ledger restarted from it, still counts) and was refused no later than this sign-in: its
/// timestamp is the refusal time, while its record is written after the refusal was answered and may land behind the
/// sign-in in the chain.
fn failures_before<'r>(index: &SignInIndex<'r>, event: &Record, window_ms: f64) -> Vec<&'r Record> {
    let Some(failures) = index.failures.get(actor_id(event)) else {
        return Vec::new();
    };
    let position = index.positions.get(id_of(event)).copied();
    let previous = match position {
        Some(position) if position > 0 => index
            .sign_ins
            .get(actor_id(event))
            .and_then(|list| list.get(position - 1)),
        _ => None,
    };
    let after: i64 = previous
        .and_then(|previous| index.order.get(id_of(previous)))
        .map_or(-1, |order| *order as i64);
    let from = timestamp(event) - window_ms;
    let start = first_index(failures, |failure| {
        timestamp(failure) >= from
            && index
                .order
                .get(id_of(failure))
                .is_some_and(|order| *order as i64 > after)
    });
    let end = first_index(failures, |failure| timestamp(failure) > timestamp(event));
    if start >= end {
        return Vec::new();
    }
    failures[start..end].to_vec()
}

async fn evaluate_event<'r>(
    run: &mut Run<'_, '_>,
    event: &'r Record,
    context: &mut EventContext<'r>,
) -> IamResult<()> {
    match action(event) {
        "auth:session:create" => signed_in(run, event, context).await,
        "auth:session:mismatch" => session_mismatch(run, event).await,
        "iam:bindings:create" => binding_created(run, event).await,
        "iam:root:grant" => root_granted(run, event).await,
        "tenant:auth-policy" => auth_policy_changed(run, event).await,
        "security:network-unblock" => network_unblocked(run, event).await,
        "role:assumed-with-web-identity" => token_replayed(run, event).await,
        "invariant:broken" => invariant_broken(run, event).await,
        "signal:received" => upstream_signal(run, event).await,
        other => {
            if persistence_change(other).is_some() {
                persistence_changed(run, event, &context.risky).await
            } else {
                Ok(())
            }
        }
    }
}

fn number(value: f64) -> Value {
    crate::js::number(value)
}

/// `${n}` of a JavaScript number.
fn num(value: f64) -> String {
    core_js::number_to_string(value)
}

/// brute-force-success, dormant-reactivated, and new-network judge a sign-in against what came before it; then the
/// sign-in is learned into the person's baseline whether or not those rules are enabled.
async fn signed_in<'r>(
    run: &mut Run<'_, '_>,
    event: &'r Record,
    context: &mut EventContext<'r>,
) -> IamResult<()> {
    if !own_sign_in(event) {
        return Ok(());
    }
    let identity_id = actor_id(event).to_owned();
    let network = client_network(meta(event, "ip"));
    let baseline = run.input.baselines.get(&identity_id).cloned();
    let flag =
        |run: &mut Run<'_, '_>, context: &mut EventContext<'r>, candidate: DetectionCandidate| {
            context.risky.insert(
                identity_id.clone(),
                RiskySignIn {
                    at: candidate.occurred_at,
                    rule_id: candidate.rule_id.clone(),
                    event_id: Some(id_of(event).to_owned()),
                    detection_id: None,
                    unique_key: Some(format!(
                        "{}:{}",
                        js_text(Some(&candidate.rule_id)),
                        candidate.dedupe_key
                    )),
                },
            );
            run.add(candidate);
        };

    let success = tuned(&run.input.settings, "brute-force-success")?;
    let failures = match &success {
        Some(success) => failures_before(&context.sign_ins, event, success.window_ms),
        None => Vec::new(),
    };
    if let Some(success) = success
        .as_ref()
        .filter(|success| failures.len() as f64 >= success.threshold)
    {
        let failing: HashSet<Option<String>> = failures
            .iter()
            .map(|failure| client_network(meta(failure, "ip")).map(|network| network.key))
            .collect();
        let from_failing = network
            .as_ref()
            .is_some_and(|network| failing.contains(&Some(network.key.clone())));
        let who = identity_subject(run, &identity_id).await?;
        let mut evidence_events = failures.clone();
        evidence_events.push(event);
        let mut metadata = IndexMap::new();
        metadata.insert("failures".to_owned(), number(failures.len() as f64));
        metadata.insert("threshold".to_owned(), number(success.threshold));
        metadata.insert("windowMs".to_owned(), number(success.window_ms));
        metadata.insert("fromFailingNetwork".to_owned(), Value::Bool(from_failing));
        let candidate = DetectionCandidate {
            rule_id: json!("brute-force-success"),
            severity: if from_failing {
                success.severity.clone()
            } else {
                lower_severity(&success.severity)
            },
            title: titled("brute-force-success", Some(who.label.as_str()))?,
            summary: format!(
                "{} signed in after {} in the preceding {}{}.",
                who.label,
                plural(failures.len() as f64, "failed attempt", None),
                in_words(success.window_ms),
                if from_failing {
                    ", from a network that was failing"
                } else {
                    ""
                }
            ),
            subject: who.subject.clone(),
            identity_id: who.identity_id.clone(),
            network: reportable_key(&run.input.settings, network.as_ref()),
            dedupe_key: dedupe_key("brute-force-success", &[id_of(event).to_owned()]),
            occurred_at: timestamp(event),
            evidence: evidence_of(&run.input.settings, &evidence_events, Extra::default()),
            metadata: Some(metadata),
            risky_sign_in: Some(true),
            extra: Map::new(),
        };
        flag(run, context, candidate);
    }

    let dormant = tuned(&run.input.settings, "dormant-reactivated")?;
    let last_sign_in_at = baseline
        .as_ref()
        .and_then(|baseline| baseline.get("lastSignInAt"))
        .map(core_js::to_number);
    let dormant_days = run.input.settings.dormant_days.max(1.0);
    if let (Some(dormant), Some(last_sign_in_at)) = (&dormant, last_sign_in_at)
        && timestamp(event) - last_sign_in_at >= dormant_days * DAY
    {
        let idle_days = ((timestamp(event) - last_sign_in_at) / DAY).floor();
        let who = identity_subject(run, &identity_id).await?;
        let mut metadata = IndexMap::new();
        metadata.insert("lastSignInAt".to_owned(), number(last_sign_in_at));
        metadata.insert("idleDays".to_owned(), number(idle_days));
        metadata.insert("dormantDays".to_owned(), number(dormant_days));
        let candidate = DetectionCandidate {
            rule_id: json!("dormant-reactivated"),
            severity: dormant.severity.clone(),
            title: titled("dormant-reactivated", Some(who.label.as_str()))?,
            summary: format!(
                "{} signed in after {} without a sign-in (accounts count as dormant after {}).",
                who.label,
                plural(idle_days, "day", None),
                plural(dormant_days, "day", None)
            ),
            subject: who.subject.clone(),
            identity_id: who.identity_id.clone(),
            network: reportable_key(&run.input.settings, network.as_ref()),
            dedupe_key: dedupe_key("dormant-reactivated", &[id_of(event).to_owned()]),
            occurred_at: timestamp(event),
            evidence: evidence_of(&run.input.settings, &[event], Extra::default()),
            metadata: Some(metadata),
            risky_sign_in: Some(true),
            extra: Map::new(),
        };
        flag(run, context, candidate);
    }

    let unfamiliar = tuned(&run.input.settings, "new-network")?;
    let known_networks: Vec<Value> = baseline
        .as_ref()
        .and_then(|baseline| baseline.get("networks"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if let (Some(unfamiliar), Some(network)) = (&unfamiliar, &network)
        && !known_networks.is_empty()
        && !known_networks.iter().any(|known| {
            crate::js::member(Some(known), "key").and_then(Value::as_str)
                == Some(network.key.as_str())
        })
        && !trusted(&run.input.settings, &network.ip)
    {
        let privileged = run.input.facts.is_privileged(&identity_id).await?;
        if privileged || unfamiliar.setting.get("everyone") == Some(&Value::Bool(true)) {
            let who = identity_subject(run, &identity_id).await?;
            let mut metadata = IndexMap::new();
            metadata.insert("privileged".to_owned(), Value::Bool(privileged));
            metadata.insert(
                "knownNetworks".to_owned(),
                number(known_networks.len() as f64),
            );
            let candidate = DetectionCandidate {
                rule_id: json!("new-network"),
                severity: if privileged {
                    unfamiliar.severity.clone()
                } else {
                    json!("low")
                },
                title: titled("new-network", Some(who.label.as_str()))?,
                summary: format!(
                    "{}{} signed in from {}, a network not seen for them before.",
                    who.label,
                    if privileged {
                        ", a privileged account,"
                    } else {
                        ""
                    },
                    network.key
                ),
                subject: who.subject.clone(),
                identity_id: who.identity_id.clone(),
                network: Some(network.key.clone()),
                dedupe_key: dedupe_key("new-network", &[id_of(event).to_owned()]),
                occurred_at: timestamp(event),
                evidence: evidence_of(&run.input.settings, &[event], Extra::default()),
                metadata: Some(metadata),
                risky_sign_in: Some(true),
                extra: Map::new(),
            };
            flag(run, context, candidate);
        }
    }

    learn_sign_in(run.input, event, network.as_ref(), &mut context.touched);
    Ok(())
}

/// Records a sign-in on the person's baseline (created on first sight): its network, user agent, and time.
fn learn_sign_in(
    input: &mut RuleInput<'_>,
    event: &Record,
    network: Option<&ClientNetwork>,
    touched: &mut IndexSet<String>,
) {
    let identity_id = actor_id(event).to_owned();
    let now = input.now;
    let tenant_id = input.tenant_id.clone();
    let baseline = input
        .baselines
        .entry(identity_id.clone())
        .or_insert_with(|| {
            let mut baseline = Record::new();
            baseline.insert("id".into(), json!(identity_id));
            baseline.insert("tenantId".into(), json!(tenant_id));
            baseline.insert("identityId".into(), json!(identity_id));
            baseline.insert("networks".into(), json!([]));
            baseline.insert("userAgents".into(), json!([]));
            baseline.insert("firstSeenAt".into(), number(timestamp(event)));
            baseline.insert("updatedAt".into(), number(now));
            baseline
        });
    if let Some(network) = network {
        let mut networks: Vec<Value> = baseline
            .get("networks")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|known| {
                crate::js::member(Some(known), "key").and_then(Value::as_str)
                    != Some(network.key.as_str())
            })
            .collect();
        networks.push(json!({ "key": network.key, "lastAt": number(timestamp(event)) }));
        baseline.insert(
            "networks".into(),
            Value::Array(last_n(networks, BASELINE_NETWORK_LIMIT)),
        );
    }
    let user_agent = match meta(event, "userAgent") {
        Some(Value::String(agent)) => slice_utf16(&clean(agent), USER_AGENT_LENGTH),
        _ => String::new(),
    };
    if !user_agent.is_empty() {
        let mut agents: Vec<Value> = baseline
            .get("userAgents")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|known| {
                crate::js::member(Some(known), "value").and_then(Value::as_str)
                    != Some(user_agent.as_str())
            })
            .collect();
        agents.push(json!({ "value": user_agent, "lastAt": number(timestamp(event)) }));
        baseline.insert(
            "userAgents".into(),
            Value::Array(last_n(agents, BASELINE_USER_AGENT_LIMIT)),
        );
    }
    let last = match baseline.get("lastSignInAt") {
        None | Some(Value::Null) => timestamp(event),
        Some(value) => core_js::to_number(value),
    };
    baseline.insert(
        "lastSignInAt".into(),
        number(js_max(last, timestamp(event))),
    );
    baseline.insert("updatedAt".into(), number(now));
    touched.insert(identity_id);
}

/// `Math.max(a, b)`: NaN when either is NaN.
fn js_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.max(b)
    }
}

/// `list.slice(-n)`.
fn last_n<T>(mut list: Vec<T>, n: usize) -> Vec<T> {
    if list.len() > n {
        list.drain(..list.len() - n);
    }
    list
}

/// session-hijack: a session bound to one network was presented from another (one detection per session).
async fn session_mismatch(run: &mut Run<'_, '_>, event: &Record) -> IamResult<()> {
    let Some(rule) = tuned(&run.input.settings, "session-hijack")? else {
        return Ok(());
    };
    if !outcome_is(event, "allow") || !recorded(event) {
        return Ok(());
    }
    let session_id = meta_str(event, "sessionId")
        .filter(|session| !session.is_empty())
        .map(str::to_owned);
    let session_ip = meta_str(event, "sessionIp").unwrap_or("").to_owned();
    let ip = meta_str(event, "ip").map(str::to_owned);
    let presented = client_network(ip.as_ref().map(|ip| Value::String(ip.clone())).as_ref());
    let who = identity_subject(run, actor_id(event)).await?;
    let settings = &run.input.settings;
    let session_network = reportable_key(
        settings,
        client_network(Some(&Value::String(session_ip.clone()))).as_ref(),
    );
    let mut metadata = IndexMap::new();
    if let Some(session_id) = &session_id {
        metadata.insert("sessionId".to_owned(), json!(session_id));
    }
    metadata.insert("sessionIp".to_owned(), json!(session_ip));
    if let Some(ip) = ip.as_ref().filter(|ip| !ip.is_empty()) {
        metadata.insert("ip".to_owned(), json!(ip));
    }
    let candidate = DetectionCandidate {
        rule_id: json!("session-hijack"),
        severity: rule.severity.clone(),
        title: titled("session-hijack", Some(who.label.as_str()))?,
        summary: format!(
            "A session of {} bound to {} was presented from {}.",
            who.label,
            if session_ip.is_empty() {
                "one network".to_owned()
            } else {
                clean(&session_ip)
            },
            match ip.as_ref().filter(|ip| !ip.is_empty()) {
                Some(ip) => clean(ip),
                None => "another network".to_owned(),
            }
        ),
        subject: who.subject.clone(),
        identity_id: who.identity_id.clone(),
        network: reportable_key(settings, presented.as_ref()),
        dedupe_key: dedupe_key(
            "session-hijack",
            &[session_id
                .clone()
                .unwrap_or_else(|| id_of(event).to_owned())],
        ),
        occurred_at: timestamp(event),
        evidence: evidence_of(
            settings,
            &[event],
            Extra {
                networks: vec![session_network],
                ..Extra::default()
            },
        ),
        metadata: Some(metadata),
        risky_sign_in: None,
        extra: Map::new(),
    };
    run.add(candidate);
    Ok(())
}

/// account-takeover-persistence: a person changed their own sign-in methods within the window after a risky
/// sign-in, flagged earlier in this run or by an earlier run (the baseline's riskySignIn). The chain already orders
/// the two, so timestamps from different writers' clocks may disagree by up to a window.
async fn persistence_changed(
    run: &mut Run<'_, '_>,
    event: &Record,
    risky: &HashMap<String, RiskySignIn>,
) -> IamResult<()> {
    let rule = tuned(&run.input.settings, "account-takeover-persistence")?;
    let change = persistence_change(action(event));
    let (Some(rule), Some(change)) = (rule, change) else {
        return Ok(());
    };
    if !outcome_is(event, "allow") || resource_id(event) != actor_id(event) {
        return Ok(());
    }
    if action(event).starts_with("auth:") && !recorded(event) {
        return Ok(());
    }
    let mut sources: Vec<RiskySignIn> = Vec::new();
    let stored = run
        .input
        .baselines
        .get(actor_id(event))
        .and_then(|baseline| baseline.get("riskySignIn"))
        .cloned();
    // A risky sign-in an administrator has since judged harmless (dismissed, or closed as a false positive or
    // benign) opens no window.
    if let Some(stored) = stored.filter(|stored| truthy(Some(stored))) {
        let detection_id = crate::js::member(Some(&stored), "detectionId").cloned();
        let stands = run
            .input
            .facts
            .detection_stands(&js_text(detection_id.as_ref()))
            .await?;
        if stands != Some(false) {
            sources.push(RiskySignIn {
                at: crate::js::member(Some(&stored), "at")
                    .map(core_js::to_number)
                    .unwrap_or(f64::NAN),
                rule_id: crate::js::member(Some(&stored), "ruleId")
                    .cloned()
                    .unwrap_or(Value::Null),
                event_id: None,
                detection_id,
                unique_key: None,
            });
        }
    }
    if let Some(current) = risky.get(actor_id(event)) {
        sources.push(current.clone());
    }
    let mut source: Option<RiskySignIn> = None;
    for candidate in sources {
        if (timestamp(event) - candidate.at).abs() <= rule.window_ms
            && source
                .as_ref()
                .is_none_or(|source| candidate.at > source.at)
        {
            source = Some(candidate);
        }
    }
    let Some(source) = source else {
        return Ok(());
    };
    let who = identity_subject(run, actor_id(event)).await?;
    let elapsed = (timestamp(event) - source.at).max(0.0);
    let risky_title = if threat_rule_ids()?.iter().any(|id| *id == source.rule_id) {
        core_js::to_lower(&threat_rule(&source.rule_id)?.title)
    } else {
        clean(&js_text(Some(&source.rule_id)))
    };
    let mut event_ids = Vec::new();
    if let Some(event_id) = &source.event_id {
        event_ids.push(event_id.clone());
    }
    event_ids.push(id_of(event).to_owned());
    let actions = if source.event_id.is_some() {
        vec!["auth:session:create".to_owned(), action(event).to_owned()]
    } else {
        vec![action(event).to_owned()]
    };
    let mut metadata = IndexMap::new();
    metadata.insert("changedAction".to_owned(), json!(action(event)));
    metadata.insert("riskySignInRuleId".to_owned(), source.rule_id.clone());
    metadata.insert("riskySignInAt".to_owned(), number(source.at));
    if let Some(detection_id) = source.detection_id.as_ref().filter(|id| truthy(Some(id))) {
        metadata.insert("riskySignInDetectionId".to_owned(), detection_id.clone());
    }
    if let Some(unique_key) = source.unique_key.as_ref().filter(|key| !key.is_empty()) {
        metadata.insert("riskySignInKey".to_owned(), json!(unique_key));
    }
    let candidate = DetectionCandidate {
        rule_id: json!("account-takeover-persistence"),
        severity: rule.severity.clone(),
        title: titled("account-takeover-persistence", Some(who.label.as_str()))?,
        summary: format!(
            "{} {change} {} after a risky sign-in ({risky_title}).",
            who.label,
            if elapsed < MINUTE {
                "less than a minute".to_owned()
            } else {
                about(elapsed)
            }
        ),
        subject: who.subject.clone(),
        identity_id: who.identity_id.clone(),
        network: None,
        dedupe_key: dedupe_key("account-takeover-persistence", &[id_of(event).to_owned()]),
        occurred_at: timestamp(event),
        evidence: ThreatEvidence {
            count: if source.event_id.is_some() { 2.0 } else { 1.0 },
            event_ids,
            first_at: js_min(source.at, timestamp(event)),
            last_at: js_max(source.at, timestamp(event)),
            networks: None,
            identity_ids: None,
            actions: Some(actions),
            extra: Map::new(),
        },
        metadata: Some(metadata),
        risky_sign_in: None,
        extra: Map::new(),
    };
    run.add(candidate);
    Ok(())
}

/// `Math.min(a, b)`: NaN when either is NaN.
fn js_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

/// privilege-escalation: an administrator role was granted by someone who now holds it. The operation event names
/// only the role, so a holder granting the role to a colleague matches too; firings are kept to one per actor, role,
/// and UTC day (later grants add evidence), and root administrators and owners, who hold full access already, are
/// not judged.
async fn binding_created(run: &mut Run<'_, '_>, event: &Record) -> IamResult<()> {
    let Some(rule) = tuned(&run.input.settings, "privilege-escalation")? else {
        return Ok(());
    };
    if !outcome_is(event, "allow") || !identity_actor(actor_id(event)) {
        return Ok(());
    }
    let Some(actor) = run.identity(actor_id(event)).await? else {
        return Ok(());
    };
    if actor.root_admin || actor.owner {
        return Ok(());
    }
    let role_id = resource_id(event);
    if !run.input.facts.is_admin_role(role_id).await? {
        return Ok(());
    }
    if !run.input.facts.holds_role(&actor.id, role_id).await? {
        return Ok(());
    }
    let label = label_of(Some(&actor), &actor.id);
    let mut metadata = IndexMap::new();
    metadata.insert("roleId".to_owned(), json!(role_id));
    let candidate = DetectionCandidate {
        rule_id: json!("privilege-escalation"),
        severity: rule.severity.clone(),
        title: titled("privilege-escalation", Some(label.as_str()))?,
        summary: format!(
            "{label} granted the administrator role {} and now holds it.",
            clean(role_id)
        ),
        subject: identity_named(&actor.id, &label),
        identity_id: Some(actor.id.clone()),
        network: None,
        dedupe_key: dedupe_key(
            "privilege-escalation",
            &[
                actor.id.clone(),
                role_id.to_owned(),
                num(start_of_day(timestamp(event))),
            ],
        ),
        occurred_at: timestamp(event),
        evidence: evidence_of(
            &run.input.settings,
            &[event],
            Extra {
                actions: true,
                ..Extra::default()
            },
        ),
        metadata: Some(metadata),
        risky_sign_in: None,
        extra: Map::new(),
    };
    run.add(candidate);
    Ok(())
}

/// root-admin-granted: `iam:root:grant` left its target a root administrator (the same event also removes it).
async fn root_granted(run: &mut Run<'_, '_>, event: &Record) -> IamResult<()> {
    let Some(rule) = tuned(&run.input.settings, "root-admin-granted")? else {
        return Ok(());
    };
    if !outcome_is(event, "allow") {
        return Ok(());
    }
    let Some(target) = run
        .identity(resource_id(event))
        .await?
        .filter(|target| target.root_admin)
    else {
        return Ok(());
    };
    let label = label_of(Some(&target), &target.id);
    let granted_by = label_of(
        run.identity(actor_id(event)).await?.as_ref(),
        actor_id(event),
    );
    let mut metadata = IndexMap::new();
    metadata.insert("grantedBy".to_owned(), json!(actor_id(event)));
    let candidate = DetectionCandidate {
        rule_id: json!("root-admin-granted"),
        severity: rule.severity.clone(),
        title: titled("root-admin-granted", Some(label.as_str()))?,
        summary: format!("{granted_by} made {label} a root administrator of the deployment."),
        subject: identity_named(&target.id, &label),
        identity_id: Some(target.id.clone()),
        network: None,
        dedupe_key: dedupe_key("root-admin-granted", &[id_of(event).to_owned()]),
        occurred_at: timestamp(event),
        evidence: evidence_of(
            &run.input.settings,
            &[event],
            Extra {
                identity_ids: vec![target.id.clone()],
                actions: true,
                ..Extra::default()
            },
        ),
        metadata: Some(metadata),
        risky_sign_in: None,
        extra: Map::new(),
    };
    run.add(candidate);
    Ok(())
}

fn tenant_subject(tenant_id: &str) -> ThreatSubject {
    ThreatSubject {
        r#type: json!("tenant"),
        id: tenant_id.to_owned(),
        name: None,
        extra: Map::new(),
    }
}

fn identity_named(identity_id: &str, label: &str) -> ThreatSubject {
    ThreatSubject {
        r#type: json!("identity"),
        id: identity_id.to_owned(),
        name: Some(label.to_owned()),
        extra: Map::new(),
    }
}

fn to_index_map(map: &Map<String, Value>) -> IndexMap<String, Value> {
    map.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// guardrail-weakened (sign-in policy): compares the tenant's new sign-in policy with the one last seen, then
/// remembers the new one. Without a previous policy the rule only learns.
async fn auth_policy_changed(run: &mut Run<'_, '_>, event: &Record) -> IamResult<()> {
    if !outcome_is(event, "allow") || !recorded(event) || resource_id(event) != run.input.tenant_id
    {
        return Ok(());
    }
    let Some(metadata) = event.get("metadata").and_then(Value::as_object) else {
        return Ok(());
    };
    let Some(policy) = metadata.get("authPolicy") else {
        return Ok(());
    };
    let after: IndexMap<String, Value> = match policy {
        Value::Null => IndexMap::new(),
        other => match json_object(other) {
            Some(object) => to_index_map(object),
            None => return Ok(()),
        },
    };
    let before = run.input.state.auth_policy.replace(after.clone());
    let rule = tuned(&run.input.settings, "guardrail-weakened")?;
    let (Some(rule), Some(before)) = (rule, before) else {
        return Ok(());
    };
    let dropped: Vec<&(&str, &str, Weakened)> = POLICY_PROTECTIONS
        .iter()
        .filter(|(_, _, weakened)| weakened(&before, &after))
        .collect();
    if dropped.is_empty() {
        return Ok(());
    }
    let actor = actor_of(run, actor_id(event)).await?;
    let labels: Vec<String> = dropped
        .iter()
        .map(|(_, label, _)| (*label).to_owned())
        .collect();
    let mut metadata = IndexMap::new();
    metadata.insert("change".to_owned(), json!("auth-policy"));
    metadata.insert(
        "weakened".to_owned(),
        json!(dropped.iter().map(|(name, _, _)| *name).collect::<Vec<_>>()),
    );
    let candidate = DetectionCandidate {
        rule_id: json!("guardrail-weakened"),
        severity: rule.severity.clone(),
        title: titled("guardrail-weakened", Some("sign-in policy"))?,
        summary: format!(
            "{} removed {} from the tenant sign-in policy.",
            actor.0,
            series(&labels)
        ),
        subject: tenant_subject(&run.input.tenant_id),
        identity_id: actor.1,
        network: None,
        dedupe_key: dedupe_key("guardrail-weakened", &[id_of(event).to_owned()]),
        occurred_at: timestamp(event),
        evidence: evidence_of(
            &run.input.settings,
            &[event],
            Extra {
                actions: true,
                ..Extra::default()
            },
        ),
        metadata: Some(metadata),
        risky_sign_in: None,
        extra: Map::new(),
    };
    run.add(candidate);
    Ok(())
}

/// guardrail-weakened (network block lifted): every `security:network-unblock`.
async fn network_unblocked(run: &mut Run<'_, '_>, event: &Record) -> IamResult<()> {
    let rule = tuned(&run.input.settings, "guardrail-weakened")?;
    let network = meta_str(event, "network").map(str::to_owned);
    let (Some(rule), Some(network)) = (rule, network) else {
        return Ok(());
    };
    if !outcome_is(event, "allow") || !recorded(event) {
        return Ok(());
    }
    let platform = meta(event, "platform") == Some(&Value::Bool(true));
    let actor = actor_of(run, actor_id(event)).await?;
    let mut metadata = IndexMap::new();
    metadata.insert("change".to_owned(), json!("network-unblock"));
    metadata.insert("network".to_owned(), json!(network));
    metadata.insert("platform".to_owned(), Value::Bool(platform));
    metadata.insert("blockId".to_owned(), json!(resource_id(event)));
    let candidate = DetectionCandidate {
        rule_id: json!("guardrail-weakened"),
        severity: rule.severity.clone(),
        title: titled("guardrail-weakened", Some("network block lifted"))?,
        summary: format!(
            "{} lifted the {}block on {}.",
            actor.0,
            if platform { "platform-wide " } else { "" },
            clean(&network)
        ),
        subject: tenant_subject(&run.input.tenant_id),
        identity_id: actor.1,
        network: None,
        dedupe_key: dedupe_key("guardrail-weakened", &[id_of(event).to_owned()]),
        occurred_at: timestamp(event),
        evidence: evidence_of(
            &run.input.settings,
            &[event],
            Extra {
                actions: true,
                ..Extra::default()
            },
        ),
        metadata: Some(metadata),
        risky_sign_in: None,
        extra: Map::new(),
    };
    run.add(candidate);
    Ok(())
}

/// token-replay: a web identity token refused as already used (`role:assumed-with-web-identity`, reason `replay`).
async fn token_replayed(run: &mut Run<'_, '_>, event: &Record) -> IamResult<()> {
    let Some(rule) = tuned(&run.input.settings, "token-replay")? else {
        return Ok(());
    };
    if !outcome_is(event, "deny") || meta_str(event, "reason") != Some("replay") {
        return Ok(());
    }
    let who = identity_subject(run, actor_id(event)).await?;
    let mut details = IndexMap::new();
    details.insert("roleId".to_owned(), json!(resource_id(event)));
    for name in ["trustId", "providerId", "issuer", "subject"] {
        if let Some(value) = meta_str(event, name) {
            details.insert(name.to_owned(), json!(value));
        }
    }
    let external = meta_str(event, "subject").map(clean).unwrap_or_default();
    let candidate = DetectionCandidate {
        rule_id: json!("token-replay"),
        severity: rule.severity.clone(),
        title: titled("token-replay", Some(who.label.as_str()))?,
        summary: format!(
            "A web identity token was presented a second time to assume role {} as {}{}.",
            clean(resource_id(event)),
            who.label,
            if external.is_empty() {
                String::new()
            } else {
                format!(" (token subject {external})")
            }
        ),
        subject: who.subject.clone(),
        identity_id: who.identity_id.clone(),
        network: None,
        dedupe_key: dedupe_key("token-replay", &[id_of(event).to_owned()]),
        occurred_at: timestamp(event),
        evidence: evidence_of(&run.input.settings, &[event], Extra::default()),
        metadata: Some(details),
        risky_sign_in: None,
        extra: Map::new(),
    };
    run.add(candidate);
    Ok(())
}

/// invariant-broken: the invariant checker reported a newly broken invariant; enforced ones are at least high.
async fn invariant_broken(run: &mut Run<'_, '_>, event: &Record) -> IamResult<()> {
    let rule = tuned(&run.input.settings, "invariant-broken")?;
    let name = meta_str(event, "name").map(str::to_owned);
    let (Some(rule), Some(name)) = (rule, name) else {
        return Ok(());
    };
    if actor_id(event) != "deployment-operator" {
        return Ok(());
    }
    let enforce = meta_str(event, "mode") == Some("enforce");
    let mode = if enforce { "enforce" } else { "monitor" };
    let violations: Vec<String> = match meta(event, "violations") {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    };
    let error = meta_str(event, "error").map(str::to_owned);
    let detail = if !violations.is_empty() {
        format!(
            " for {}",
            plural(violations.len() as f64, "identity", Some("identities"))
        )
    } else if let Some(error) = error.as_ref().filter(|error| !error.is_empty()) {
        format!(" ({})", clean(error))
    } else {
        String::new()
    };
    let mut metadata = IndexMap::new();
    metadata.insert("name".to_owned(), json!(name));
    metadata.insert("mode".to_owned(), json!(mode));
    metadata.insert("invariantId".to_owned(), json!(resource_id(event)));
    metadata.insert(
        "violations".to_owned(),
        json!(violations.iter().take(EVIDENCE_LIMIT).collect::<Vec<_>>()),
    );
    if let Some(error) = error.as_ref().filter(|error| !error.is_empty()) {
        metadata.insert("error".to_owned(), json!(error));
    }
    let cleaned = clean(&name);
    let candidate = DetectionCandidate {
        rule_id: json!("invariant-broken"),
        severity: if enforce {
            max_severity(&json!("high"), &rule.severity)?
        } else {
            rule.severity.clone()
        },
        title: titled("invariant-broken", Some(cleaned.as_str()))?,
        summary: format!(
            "The {} access invariant \"{cleaned}\" stopped holding{detail}.",
            if enforce { "enforced" } else { "monitored" }
        ),
        subject: tenant_subject(&run.input.tenant_id),
        identity_id: None,
        network: None,
        dedupe_key: dedupe_key("invariant-broken", &[id_of(event).to_owned()]),
        occurred_at: timestamp(event),
        evidence: evidence_of(
            &run.input.settings,
            &[event],
            Extra {
                identity_ids: violations.clone(),
                ..Extra::default()
            },
        ),
        metadata: Some(metadata),
        risky_sign_in: None,
        extra: Map::new(),
    };
    run.add(candidate);
    Ok(())
}

/// Severity of an upstream Shared Signals event about a person; None for events that raise nothing.
fn upstream_severity(event_type: &str, current_level: Option<&Value>) -> Option<&'static str> {
    match event_type {
        "credential-compromise" => Some("high"),
        "account-disabled" | "account-purged" | "account-credential-change-required" => {
            Some("medium")
        }
        "credential-change" => Some("low"),
        "risk-level-change" => match current_level.and_then(Value::as_str) {
            Some("HIGH") => Some("high"),
            Some("MEDIUM") => Some("medium"),
            _ => None,
        },
        _ => None,
    }
}

/// upstream-signal: the Shared Signals receiver (signal-receiver.ts) matched an upstream provider's event to a person
/// of this tenant (`signal:received`, actor `signal:{sourceId}`). Session revocations and low risk raise nothing;
/// what the event reports sets the severity.
async fn upstream_signal(run: &mut Run<'_, '_>, event: &Record) -> IamResult<()> {
    if tuned(&run.input.settings, "upstream-signal")?.is_none() {
        return Ok(());
    }
    let source_id = meta_str(event, "sourceId").map(str::to_owned);
    let event_type = meta_str(event, "eventType").map(str::to_owned);
    let identity_id = meta_str(event, "identityId").map(str::to_owned);
    if !outcome_is(event, "allow") || !recorded(event) {
        return Ok(());
    }
    let (Some(source_id), Some(event_type), Some(identity_id)) =
        (source_id, event_type, identity_id)
    else {
        return Ok(());
    };
    if actor_id(event) != format!("signal:{source_id}") {
        return Ok(());
    }
    let Some(severity) = upstream_severity(&event_type, meta(event, "currentLevel")) else {
        return Ok(());
    };
    let who = identity_subject(run, &identity_id).await?;
    let reason = meta_str(event, "reasonAdmin")
        .map(clean)
        .unwrap_or_default();
    let mut details = IndexMap::new();
    details.insert("sourceId".to_owned(), json!(source_id));
    details.insert("eventType".to_owned(), json!(event_type));
    if let Some(jti) = meta_str(event, "jti") {
        details.insert("jti".to_owned(), json!(jti));
    }
    for name in ["currentLevel", "credentialType"] {
        if let Some(value) = meta_str(event, name) {
            details.insert(name.to_owned(), json!(value));
        }
    }
    let candidate = DetectionCandidate {
        rule_id: json!("upstream-signal"),
        severity: json!(severity),
        title: titled("upstream-signal", Some(who.label.as_str()))?,
        summary: format!(
            "An upstream identity provider reported {} for {}{}.",
            event_type.replace('-', " "),
            who.label,
            if reason.is_empty() {
                String::new()
            } else {
                format!(": {reason}")
            }
        ),
        subject: who.subject.clone(),
        identity_id: who.identity_id.clone(),
        network: None,
        dedupe_key: dedupe_key("upstream-signal", &[id_of(event).to_owned()]),
        occurred_at: timestamp(event),
        evidence: evidence_of(&run.input.settings, &[event], Extra::default()),
        metadata: Some(details),
        risky_sign_in: None,
        extra: Map::new(),
    };
    run.add(candidate);
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Counting rules

/// A counting key (or distinct value) of an event.
type KeyFn<'f> = Box<dyn Fn(&Record) -> Option<String> + 'f>;

/// What a counting rule counts: the key it counts per and, for distinct counts, the value that must differ.
struct Counter<'f> {
    key: KeyFn<'f>,
    /// Count distinct values (password spray: accounts) instead of events.
    distinct: Option<KeyFn<'f>>,
}

/// A qualifying burst of one key that this run's events are part of.
struct Burst<'r> {
    key: String,
    /// The burst's dedupe anchor (`burstAnchor`).
    anchor: f64,
    /// Events from the start of the first qualifying window to the last qualifying new event, oldest first.
    events: Vec<&'r Record>,
    /// The highest count (or distinct count) one window reached.
    peak: f64,
    last_at: f64,
}

/// Slides each key's window over history and new events (two pointers over the key's time-ordered events, so linear
/// after the one sort) and reports the windows that end at a new event and reach the threshold, grouped by anchor.
fn find_bursts<'r>(
    ordered: &[&'r Record],
    fresh: &HashSet<&str>,
    history_from: Option<f64>,
    window: Window,
    counter: &Counter<'_>,
) -> Vec<Burst<'r>> {
    let mut by_key: IndexMap<String, Vec<&'r Record>> = IndexMap::new();
    for event in ordered {
        if let Some(key) = (counter.key)(event) {
            by_key.entry(key).or_default().push(event);
        }
    }
    let mut bursts = Vec::new();
    for (key, list) in by_key {
        if !list.iter().any(|event| fresh.contains(id_of(event))) {
            continue;
        }
        let mut values: HashMap<String, i64> = HashMap::new();
        let count = |event: &Record, delta: i64, values: &mut HashMap<String, i64>| {
            let Some(distinct) = &counter.distinct else {
                return;
            };
            let Some(value) = distinct(event) else {
                return;
            };
            let next = values.get(&value).copied().unwrap_or(0) + delta;
            if next > 0 {
                values.insert(value, next);
            } else {
                values.remove(&value);
            }
        };
        struct Qualifying {
            anchor: f64,
            from: usize,
            to: usize,
            peak: f64,
        }
        let mut qualifying: IndexMap<u64, Qualifying> = IndexMap::new();
        let mut start = 0usize;
        let mut cluster_start = 0usize;
        for index in 0..list.len() {
            let event = list[index];
            if index > 0 && timestamp(event) - timestamp(list[index - 1]) > window.window_ms {
                cluster_start = index;
            }
            count(event, 1, &mut values);
            while timestamp(list[start]) < timestamp(event) - window.window_ms {
                count(list[start], -1, &mut values);
                start += 1;
            }
            if !fresh.contains(id_of(event)) {
                continue;
            }
            let size = if counter.distinct.is_some() {
                values.len() as f64
            } else {
                (index - start + 1) as f64
            };
            if size < window.threshold {
                continue;
            }
            // With the lookback cut short, a cluster whose first loaded event lies within a window of the cut may
            // have begun before it: its start is unknown, and the start of the day stands in, as it will for every
            // later run.
            let cut = cluster_start == 0
                && history_from.is_some_and(|from| timestamp(list[0]) - from <= window.window_ms);
            let anchor = burst_anchor(
                if cut {
                    f64::NEG_INFINITY
                } else {
                    timestamp(list[cluster_start])
                },
                timestamp(event),
                window.window_ms,
            );
            // Map keys compare by SameValueZero: -0 and 0 are one key.
            let anchor_key = if anchor == 0.0 { 0.0f64 } else { anchor }.to_bits();
            if let Some(burst) = qualifying.get_mut(&anchor_key) {
                burst.to = index;
                burst.peak = burst.peak.max(size);
            } else {
                qualifying.insert(
                    anchor_key,
                    Qualifying {
                        anchor,
                        from: start,
                        to: index,
                        peak: size,
                    },
                );
            }
        }
        for burst in qualifying.into_values() {
            bursts.push(Burst {
                key: key.clone(),
                anchor: burst.anchor,
                events: list[burst.from..=burst.to].to_vec(),
                peak: burst.peak,
                last_at: timestamp(list[burst.to]),
            });
        }
    }
    bursts
}

fn burst_metadata(
    window: Window,
    burst: &Burst<'_>,
    extra: IndexMap<String, Value>,
) -> IndexMap<String, Value> {
    let mut metadata = IndexMap::new();
    metadata.insert("peak".to_owned(), number(burst.peak));
    metadata.insert("threshold".to_owned(), number(window.threshold));
    metadata.insert("windowMs".to_owned(), number(window.window_ms));
    for (key, value) in extra {
        metadata.insert(key, value);
    }
    metadata
}

fn meta_map(entries: impl IntoIterator<Item = (&'static str, Value)>) -> IndexMap<String, Value> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

async fn evaluate_counting(
    run: &mut Run<'_, '_>,
    ordered: &[&Record],
    fresh: &HashSet<&str>,
) -> IamResult<()> {
    let history_from = run.input.history_from;
    let settings = run.input.settings.clone();

    if let Some(spray) = tuned(&settings, "password-spray")? {
        let bursts = find_bursts(
            ordered,
            fresh,
            history_from,
            spray.window(),
            &Counter {
                key: Box::new(|event| {
                    if sign_in_failure(event, Some("password")) {
                        reportable_key(&settings, client_network(meta(event, "ip")).as_ref())
                    } else {
                        None
                    }
                }),
                distinct: Some(Box::new(|event| Some(actor_id(event).to_owned()))),
            },
        );
        for burst in bursts {
            let accounts = distinct_values(
                burst
                    .events
                    .iter()
                    .map(|event| Some(actor_id(event).to_owned())),
            );
            let mut extra = IndexMap::new();
            extra.insert("accounts".to_owned(), number(accounts.len() as f64));
            run.add(DetectionCandidate {
                rule_id: json!("password-spray"),
                severity: spray.severity.clone(),
                title: format!("Password spray from {}", burst.key),
                summary: format!(
                    "{} failed password sign-in from {} within {} ({} in all).",
                    plural(burst.peak, "account", None),
                    burst.key,
                    in_words(spray.window_ms),
                    plural(burst.events.len() as f64, "attempt", None)
                ),
                subject: ThreatSubject {
                    r#type: json!("network"),
                    id: burst.key.clone(),
                    name: None,
                    extra: Map::new(),
                },
                identity_id: None,
                network: Some(burst.key.clone()),
                dedupe_key: dedupe_key("password-spray", &[burst.key.clone(), num(burst.anchor)]),
                occurred_at: burst.last_at,
                evidence: evidence_of(
                    &settings,
                    &burst.events,
                    Extra {
                        identity_ids: accounts.clone(),
                        ..Extra::default()
                    },
                ),
                metadata: Some(burst_metadata(spray.window(), &burst, extra)),
                risky_sign_in: None,
                extra: Map::new(),
            });
        }
    }

    for (rule_id, reason) in [("brute-force", "password"), ("mfa-bombardment", "mfa")] {
        let Some(rule) = tuned(&settings, rule_id)? else {
            continue;
        };
        let bursts = find_bursts(
            ordered,
            fresh,
            history_from,
            rule.window(),
            &Counter {
                key: Box::new(move |event| {
                    sign_in_failure(event, Some(reason)).then(|| actor_id(event).to_owned())
                }),
                distinct: None,
            },
        );
        for burst in bursts {
            let who = boxed(|| identity_subject(run, &burst.key)).await?;
            let networks = reportable_networks(&settings, &burst.events);
            let place = if networks.len() == 1 {
                format!(" from {}", networks[0])
            } else if networks.len() > 1 {
                format!(" from {}", plural(networks.len() as f64, "network", None))
            } else {
                String::new()
            };
            let summary = if rule_id == "brute-force" {
                format!(
                    "{} had {} within {}{place}.",
                    who.label,
                    plural(burst.peak, "failed password sign-in", None),
                    in_words(rule.window_ms)
                )
            } else {
                format!(
                    "{} had {} entered within {}{place}, so someone else likely knows the password.",
                    who.label,
                    plural(burst.peak, "wrong second-factor code", None),
                    in_words(rule.window_ms)
                )
            };
            let mut extra = IndexMap::new();
            extra.insert("networks".to_owned(), number(networks.len() as f64));
            run.add(DetectionCandidate {
                rule_id: json!(rule_id),
                severity: rule.severity.clone(),
                title: titled(rule_id, Some(who.label.as_str()))?,
                summary,
                subject: who.subject.clone(),
                identity_id: who.identity_id.clone(),
                network: (networks.len() == 1).then(|| networks[0].clone()),
                dedupe_key: dedupe_key(rule_id, &[burst.key.clone(), num(burst.anchor)]),
                occurred_at: burst.last_at,
                evidence: evidence_of(&settings, &burst.events, Extra::default()),
                metadata: Some(burst_metadata(rule.window(), &burst, extra)),
                risky_sign_in: None,
                extra: Map::new(),
            });
        }
    }

    if let Some(deletion) = tuned(&settings, "mass-deletion")? {
        let bursts = find_bursts(
            ordered,
            fresh,
            history_from,
            deletion.window(),
            &Counter {
                key: Box::new(|event| {
                    (DELETION_ACTIONS.contains(&action(event))
                        && outcome_is(event, "allow")
                        && identity_actor(responsible_actor(event))
                        && (action(event).starts_with("iam:") || recorded(event)))
                    .then(|| responsible_actor(event).to_owned())
                }),
                distinct: None,
            },
        );
        for burst in bursts {
            let who = boxed(|| identity_subject(run, &burst.key)).await?;
            let identities = distinct_values(
                burst
                    .events
                    .iter()
                    .filter(|event| action(event).starts_with("identity:"))
                    .map(|event| Some(resource_id(event).to_owned())),
            );
            let (clause, viewed) = viewing(&burst.events);
            let mut extra = IndexMap::new();
            extra.insert("identities".to_owned(), number(identities.len() as f64));
            extra.extend(viewed);
            run.add(DetectionCandidate {
                rule_id: json!("mass-deletion"),
                severity: deletion.severity.clone(),
                title: titled("mass-deletion", Some(who.label.as_str()))?,
                summary: format!(
                    "{} deleted or revoked {} within {}{clause}.",
                    who.label,
                    plural(burst.peak, "item", None),
                    in_words(deletion.window_ms)
                ),
                subject: who.subject.clone(),
                identity_id: who.identity_id.clone(),
                network: None,
                dedupe_key: dedupe_key("mass-deletion", &[burst.key.clone(), num(burst.anchor)]),
                occurred_at: burst.last_at,
                evidence: evidence_of(
                    &settings,
                    &burst.events,
                    Extra {
                        identity_ids: identities.clone(),
                        actions: true,
                        ..Extra::default()
                    },
                ),
                metadata: Some(burst_metadata(deletion.window(), &burst, extra)),
                risky_sign_in: None,
                extra: Map::new(),
            });
        }
    }

    if let Some(directory) = tuned(&settings, "directory-mass-change")? {
        let bursts = find_bursts(
            ordered,
            fresh,
            history_from,
            directory.window(),
            &Counter {
                key: Box::new(|event| {
                    ((action(event) == "iam:scim:UpdateUser"
                        || action(event) == "iam:scim:DeleteUser")
                        && outcome_is(event, "allow")
                        && actor_id(event).starts_with("scim:"))
                    .then(|| actor_id(event).to_owned())
                }),
                distinct: None,
            },
        );
        for burst in bursts {
            let deletions = burst
                .events
                .iter()
                .filter(|event| action(event) == "iam:scim:DeleteUser")
                .count() as f64;
            let connection = clean(&burst.key);
            let connection_id = utf16_from(&connection, "scim:".len());
            let extra = meta_map([("deletions", number(deletions))]);
            run.add(DetectionCandidate {
                rule_id: json!("directory-mass-change"),
                severity: directory.severity.clone(),
                title: titled("directory-mass-change", Some(connection.as_str()))?,
                summary: format!(
                    "SCIM connection {connection_id} updated or deleted people {} within {}{}.",
                    plural(burst.peak, "time", None),
                    in_words(directory.window_ms),
                    if deletions > 0.0 {
                        format!(" ({} in all)", plural(deletions, "deletion", None))
                    } else {
                        String::new()
                    }
                ),
                subject: ThreatSubject {
                    r#type: json!("connection"),
                    id: burst.key.clone(),
                    name: None,
                    extra: Map::new(),
                },
                identity_id: None,
                network: None,
                dedupe_key: dedupe_key(
                    "directory-mass-change",
                    &[burst.key.clone(), num(burst.anchor)],
                ),
                occurred_at: burst.last_at,
                evidence: evidence_of(
                    &settings,
                    &burst.events,
                    Extra {
                        actions: true,
                        ..Extra::default()
                    },
                ),
                metadata: Some(burst_metadata(directory.window(), &burst, extra)),
                risky_sign_in: None,
                extra: Map::new(),
            });
        }
    }

    if let Some(impersonation) = tuned(&settings, "impersonation-burst")? {
        let bursts = find_bursts(
            ordered,
            fresh,
            history_from,
            impersonation.window(),
            &Counter {
                key: Box::new(|event| {
                    (action(event) == "identity:impersonate"
                        && outcome_is(event, "allow")
                        && recorded(event)
                        && identity_actor(actor_id(event)))
                    .then(|| actor_id(event).to_owned())
                }),
                distinct: None,
            },
        );
        for burst in bursts {
            let who = boxed(|| identity_subject(run, &burst.key)).await?;
            let targets = distinct_values(
                burst
                    .events
                    .iter()
                    .map(|event| Some(resource_id(event).to_owned())),
            );
            let extra = meta_map([("targets", number(targets.len() as f64))]);
            run.add(DetectionCandidate {
                rule_id: json!("impersonation-burst"),
                severity: impersonation.severity.clone(),
                title: titled("impersonation-burst", Some(who.label.as_str()))?,
                summary: format!(
                    "{} started {} within {}, as {}.",
                    who.label,
                    plural(burst.peak, "\"view as\" session", None),
                    in_words(impersonation.window_ms),
                    plural(targets.len() as f64, "person", Some("people"))
                ),
                subject: who.subject.clone(),
                identity_id: who.identity_id.clone(),
                network: None,
                dedupe_key: dedupe_key(
                    "impersonation-burst",
                    &[burst.key.clone(), num(burst.anchor)],
                ),
                occurred_at: burst.last_at,
                evidence: evidence_of(
                    &settings,
                    &burst.events,
                    Extra {
                        identity_ids: targets.clone(),
                        ..Extra::default()
                    },
                ),
                metadata: Some(burst_metadata(impersonation.window(), &burst, extra)),
                risky_sign_in: None,
                extra: Map::new(),
            });
        }
    }

    if let Some(denial) = tuned(&settings, "denial-burst")? {
        let bursts = find_bursts(
            ordered,
            fresh,
            history_from,
            denial.window(),
            &Counter {
                key: Box::new(|event| {
                    (outcome_is(event, "deny")
                        && !UNAUTHENTICATED_REFUSALS.contains(&action(event))
                        && identity_actor(responsible_actor(event)))
                    .then(|| responsible_actor(event).to_owned())
                }),
                distinct: None,
            },
        );
        for burst in bursts {
            let who = boxed(|| identity_subject(run, &burst.key)).await?;
            let actions = distinct_values(
                burst
                    .events
                    .iter()
                    .map(|event| Some(action(event).to_owned())),
            );
            let (agent_clause, agent) = agent_involvement(&who, &burst.events);
            let (clause, viewed) = viewing(&burst.events);
            let mut extra = agent;
            extra.extend(viewed);
            run.add(DetectionCandidate {
                rule_id: json!("denial-burst"),
                severity: denial.severity.clone(),
                title: titled("denial-burst", Some(who.label.as_str()))?,
                summary: format!(
                    "{}{agent_clause} was denied {} within {}, across {}{clause}.",
                    who.label,
                    plural(burst.peak, "time", None),
                    in_words(denial.window_ms),
                    plural(actions.len() as f64, "action", None)
                ),
                subject: who.subject.clone(),
                identity_id: who.identity_id.clone(),
                network: None,
                dedupe_key: dedupe_key("denial-burst", &[burst.key.clone(), num(burst.anchor)]),
                occurred_at: burst.last_at,
                evidence: evidence_of(
                    &settings,
                    &burst.events,
                    Extra {
                        actions: true,
                        ..Extra::default()
                    },
                ),
                metadata: Some(burst_metadata(denial.window(), &burst, extra)),
                risky_sign_in: None,
                extra: Map::new(),
            });
        }
    }

    // Clearance refusals (mandatory access control) per responsible actor: someone reading up, or probing for what is
    // classified. The refusals' marker carries no label, so neither does the detection: it counts the resources only.
    if let Some(classified) = tuned(&settings, "classified-access-attempts")? {
        let bursts = find_bursts(
            ordered,
            fresh,
            history_from,
            classified.window(),
            &Counter {
                key: Box::new(|event| {
                    (mandatory_refusal(event)
                        && !UNAUTHENTICATED_REFUSALS.contains(&action(event))
                        && identity_actor(responsible_actor(event)))
                    .then(|| responsible_actor(event).to_owned())
                }),
                distinct: None,
            },
        );
        for burst in bursts {
            let who = boxed(|| identity_subject(run, &burst.key)).await?;
            let resources = distinct_values(
                burst
                    .events
                    .iter()
                    .map(|event| Some(resource_id(event).to_owned())),
            )
            .len() as f64;
            let (agent_clause, agent) = agent_involvement(&who, &burst.events);
            let (clause, viewed) = viewing(&burst.events);
            let mut extra = meta_map([("resources", number(resources))]);
            extra.extend(agent);
            extra.extend(viewed);
            run.add(DetectionCandidate {
                rule_id: json!("classified-access-attempts"),
                severity: classified.severity.clone(),
                title: titled("classified-access-attempts", Some(who.label.as_str()))?,
                summary: format!(
                    "{}{agent_clause} was refused {} for want of a clearance within {}, on {}{clause}.",
                    who.label,
                    plural(burst.peak, "time", None),
                    in_words(classified.window_ms),
                    plural(resources, "classified resource", None)
                ),
                subject: who.subject.clone(),
                identity_id: who.identity_id.clone(),
                network: None,
                dedupe_key: dedupe_key(
                    "classified-access-attempts",
                    &[burst.key.clone(), num(burst.anchor)],
                ),
                occurred_at: burst.last_at,
                evidence: evidence_of(
                    &settings,
                    &burst.events,
                    Extra {
                        actions: true,
                        ..Extra::default()
                    },
                ),
                metadata: Some(burst_metadata(classified.window(), &burst, extra)),
                risky_sign_in: None,
                extra: Map::new(),
            });
        }
    }

    if let Some(recon) = tuned(&settings, "recon-burst")? {
        let reads = find_bursts(
            ordered,
            fresh,
            history_from,
            recon.window(),
            &Counter {
                key: Box::new(|event| {
                    (outcome_is(event, "allow")
                        && action(event).starts_with("iam:")
                        && action(event).ends_with(":read")
                        && action(event) != "iam:threats:read"
                        && identity_actor(responsible_actor(event)))
                    .then(|| responsible_actor(event).to_owned())
                }),
                distinct: None,
            },
        );
        for burst in reads {
            let who = boxed(|| identity_subject(run, &burst.key)).await?;
            let (clause, viewed) = viewing(&burst.events);
            let mut extra = meta_map([("kind", json!("reads"))]);
            extra.extend(viewed);
            run.add(DetectionCandidate {
                rule_id: json!("recon-burst"),
                severity: recon.severity.clone(),
                title: titled("recon-burst", Some(who.label.as_str()))?,
                summary: format!(
                    "{} made {} within {}{clause}.",
                    who.label,
                    plural(burst.peak, "administrative read", None),
                    in_words(recon.window_ms)
                ),
                subject: who.subject.clone(),
                identity_id: who.identity_id.clone(),
                network: None,
                dedupe_key: dedupe_key(
                    "recon-burst",
                    &[burst.key.clone(), "reads".to_owned(), num(burst.anchor)],
                ),
                occurred_at: burst.last_at,
                evidence: evidence_of(
                    &settings,
                    &burst.events,
                    Extra {
                        actions: true,
                        ..Extra::default()
                    },
                ),
                metadata: Some(burst_metadata(recon.window(), &burst, extra)),
                risky_sign_in: None,
                extra: Map::new(),
            });
        }
        let export_window = Window {
            threshold: 3f64.max((recon.threshold / 50.0).floor()),
            window_ms: recon.window_ms,
        };
        let exports = find_bursts(
            ordered,
            fresh,
            history_from,
            export_window,
            &Counter {
                key: Box::new(|event| {
                    (action(event) == "identity:export"
                        && outcome_is(event, "allow")
                        && recorded(event)
                        && identity_actor(responsible_actor(event)))
                    .then(|| responsible_actor(event).to_owned())
                }),
                distinct: None,
            },
        );
        for burst in exports {
            let who = boxed(|| identity_subject(run, &burst.key)).await?;
            let exported = distinct_values(
                burst
                    .events
                    .iter()
                    .map(|event| Some(resource_id(event).to_owned())),
            );
            let (clause, viewed) = viewing(&burst.events);
            let mut extra = meta_map([
                ("kind", json!("exports")),
                ("exported", number(exported.len() as f64)),
            ]);
            extra.extend(viewed);
            run.add(DetectionCandidate {
                rule_id: json!("recon-burst"),
                severity: recon.severity.clone(),
                title: titled("recon-burst", Some(who.label.as_str()))?,
                summary: format!(
                    "{} exported {} within {}{clause}.",
                    who.label,
                    plural(burst.peak, "identity", Some("identities")),
                    in_words(recon.window_ms)
                ),
                subject: who.subject.clone(),
                identity_id: who.identity_id.clone(),
                network: None,
                dedupe_key: dedupe_key(
                    "recon-burst",
                    &[burst.key.clone(), "exports".to_owned(), num(burst.anchor)],
                ),
                occurred_at: burst.last_at,
                evidence: evidence_of(
                    &settings,
                    &burst.events,
                    Extra {
                        identity_ids: exported.clone(),
                        actions: true,
                        ..Extra::default()
                    },
                ),
                metadata: Some(burst_metadata(export_window, &burst, extra)),
                risky_sign_in: None,
                extra: Map::new(),
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Candidates

/// An identity as a detection subject (`Named`).
struct Named {
    identity: Option<Identity>,
    label: String,
    /// The subject and, for an identity of this tenant, the identity whose risk the detection raises.
    subject: ThreatSubject,
    identity_id: Option<String>,
}

/// An identity as a detection subject. Only identities of this tenant carry `identityId` (risk is kept in the
/// identity's own tenant); an actor from another tenant or one since deleted is still the subject.
async fn identity_subject(run: &mut Run<'_, '_>, identity_id: &str) -> IamResult<Named> {
    let identity = run.identity(identity_id).await?;
    let label = label_of(identity.as_ref(), identity_id);
    Ok(match identity {
        Some(identity) => Named {
            subject: identity_named(identity_id, &label),
            identity_id: Some(identity_id.to_owned()),
            identity: Some(identity),
            label,
        },
        None => Named {
            subject: ThreatSubject {
                r#type: json!("identity"),
                id: identity_id.to_owned(),
                name: None,
                extra: Map::new(),
            },
            identity_id: None,
            identity: None,
            label,
        },
    })
}

/// The actor of a tenant-level change: its name, and `identityId` when it is an identity of this tenant.
async fn actor_of(run: &mut Run<'_, '_>, actor_id: &str) -> IamResult<(String, Option<String>)> {
    let identity = if identity_actor(actor_id) {
        run.identity(actor_id).await?
    } else {
        None
    };
    Ok(match identity {
        Some(identity) => (label_of(Some(&identity), actor_id), Some(identity.id)),
        None => (clean(actor_id), None),
    })
}

/// How detections name an identity (subject names and summaries): name and email where it has both; its id when it
/// is unknown. Detections the threats API records itself use it too.
pub fn identity_label(
    identity: Option<&better_iam_core::Identity>,
    identity_id: &str,
) -> IamResult<String> {
    Ok(label_of(identity, identity_id))
}

fn label_of(identity: Option<&Identity>, identity_id: &str) -> String {
    let Some(identity) = identity else {
        return clean(identity_id);
    };
    let name = core_js::trim(&clean(&identity.name)).to_owned();
    let email = identity
        .email
        .as_deref()
        .filter(|email| !email.is_empty())
        .map(clean)
        .unwrap_or_default();
    if !name.is_empty() && !email.is_empty() && name != email {
        return format!("{name} ({email})");
    }
    if !email.is_empty() {
        return email;
    }
    if !name.is_empty() {
        return name;
    }
    clean(&identity.id)
}

/// The extra lists of [`evidence_of`].
#[derive(Default)]
struct Extra {
    identity_ids: Vec<String>,
    networks: Vec<Option<String>>,
    actions: bool,
}

/// Evidence for the events (oldest first): the last 20 ids, counts, span, and the networks the events came from.
fn evidence_of(
    settings: &ResolvedThreatSettings,
    events: &[&Record],
    extra: Extra,
) -> ThreatEvidence {
    let mut first_at = f64::INFINITY;
    let mut last_at = f64::NEG_INFINITY;
    for event in events {
        first_at = js_min(first_at, timestamp(event));
        last_at = js_max(last_at, timestamp(event));
    }
    let networks = limited(
        reportable_networks(settings, events)
            .into_iter()
            .map(Some)
            .chain(extra.networks),
    );
    let identity_ids = limited(extra.identity_ids.into_iter().map(Some));
    let actions = if extra.actions {
        limited(events.iter().map(|event| Some(action(event).to_owned())))
    } else {
        Vec::new()
    };
    let skip = events.len().saturating_sub(EVIDENCE_LIMIT);
    ThreatEvidence {
        event_ids: events[skip..]
            .iter()
            .map(|event| id_of(event).to_owned())
            .collect(),
        count: events.len() as f64,
        first_at,
        last_at,
        networks: (!networks.is_empty()).then_some(networks),
        identity_ids: (!identity_ids.is_empty()).then_some(identity_ids),
        actions: (!actions.is_empty()).then_some(actions),
        extra: Map::new(),
    }
}

/// Folds another firing of a unique key already found in this run into the first one.
fn merge(into: &mut DetectionCandidate, other: &DetectionCandidate) {
    let a = &into.evidence;
    let b = &other.evidence;
    let list = |list: &Option<Vec<String>>| list.clone().unwrap_or_default();
    let networks = limited(
        list(&a.networks)
            .into_iter()
            .chain(list(&b.networks))
            .map(Some),
    );
    let identity_ids = limited(
        list(&a.identity_ids)
            .into_iter()
            .chain(list(&b.identity_ids))
            .map(Some),
    );
    let actions = limited(
        list(&a.actions)
            .into_iter()
            .chain(list(&b.actions))
            .map(Some),
    );
    let event_ids = distinct_values(
        a.event_ids
            .iter()
            .chain(b.event_ids.iter())
            .map(|id| Some(id.clone())),
    );
    into.evidence = ThreatEvidence {
        event_ids: last_n(event_ids, EVIDENCE_LIMIT),
        count: a.count + b.count,
        first_at: js_min(a.first_at, b.first_at),
        last_at: js_max(a.last_at, b.last_at),
        networks: (!networks.is_empty()).then_some(networks),
        identity_ids: (!identity_ids.is_empty()).then_some(identity_ids),
        actions: (!actions.is_empty()).then_some(actions),
        extra: Map::new(),
    };
    into.occurred_at = js_max(into.occurred_at, other.occurred_at);
}

/// Distinct defined values in first-seen order.
fn distinct_values(values: impl IntoIterator<Item = Option<String>>) -> Vec<String> {
    let mut result: IndexSet<String> = IndexSet::new();
    for value in values.into_iter().flatten() {
        result.insert(value);
    }
    result.into_iter().collect()
}

/// Distinct defined values in first-seen order, at most `evidenceLimit`.
fn limited(values: impl IntoIterator<Item = Option<String>>) -> Vec<String> {
    let mut result: IndexSet<String> = IndexSet::new();
    for value in values.into_iter().flatten() {
        result.insert(value);
        if result.len() == EVIDENCE_LIMIT {
            break;
        }
    }
    result.into_iter().collect()
}

/// `{part}:{part}...` without control characters, short enough for `{ruleId}:{dedupeKey}` to fit a unique key.
fn dedupe_key(rule_id: &str, parts: &[String]) -> String {
    slice_utf16(
        &clean(&parts.join(":")),
        UNIQUE_KEY_LIMIT - core_js::utf16_len(rule_id) - 1,
    )
}

/// `value.slice(0, length)` in UTF-16 code units. A character that would be cut in half (a surrogate pair straddling
/// the end) is left out, since a Rust string cannot hold the lone half JavaScript would keep.
fn slice_utf16(value: &str, length: usize) -> String {
    let mut units = 0;
    let mut result = String::new();
    for char in value.chars() {
        units += char.len_utf16();
        if units > length {
            break;
        }
        result.push(char);
    }
    result
}

/// `value.slice(start)` in UTF-16 code units.
fn utf16_from(value: &str, start: usize) -> String {
    let mut units = 0;
    let mut result = String::new();
    for char in value.chars() {
        if units >= start {
            result.push(char);
        }
        units += char.len_utf16();
    }
    result
}

/// Drops control characters (C0, DEL, C1) from text that reaches keys and summaries.
fn clean(value: &str) -> String {
    value
        .chars()
        .filter(|char| {
            let code = *char as u32;
            code >= 32 && !(127..=159).contains(&code)
        })
        .collect()
}

fn lower_severity(severity: &Value) -> Value {
    match severity.as_str() {
        Some("critical") => json!("high"),
        Some("high") => json!("medium"),
        Some("medium") | Some("low") => json!("low"),
        _ => Value::Null,
    }
}

fn start_of_day(at: f64) -> f64 {
    (at / DAY).floor() * DAY
}

/// A rule's title, followed by what the detection is about when that has a name.
fn titled(rule_id: &str, name: Option<&str>) -> IamResult<String> {
    let title = threat_rule(&json!(rule_id))?.title;
    Ok(match name.filter(|name| !name.is_empty()) {
        Some(name) => format!("{title}: {name}"),
        None => title,
    })
}

fn plural(count: f64, singular: &str, plural_form: Option<&str>) -> String {
    let word = if count == 1.0 {
        singular.to_owned()
    } else {
        plural_form.map_or_else(|| format!("{singular}s"), str::to_owned)
    };
    format!("{} {word}", num(count))
}

/// "a", "a and b", "a, b and c".
fn series(items: &[String]) -> String {
    if items.len() <= 1 {
        return items.join("");
    }
    format!(
        "{} and {}",
        items[..items.len() - 1].join(", "),
        items[items.len() - 1]
    )
}

/// A window length in words, in the largest whole unit that divides it: "15 minutes", "1 hour", "7 days".
fn in_words(ms: f64) -> String {
    if ms % DAY == 0.0 {
        return plural(ms / DAY, "day", None);
    }
    if ms % HOUR == 0.0 {
        return plural(ms / HOUR, "hour", None);
    }
    if ms % MINUTE == 0.0 {
        return plural(ms / MINUTE, "minute", None);
    }
    about(ms)
}

/// `Math.round`: halves round up.
fn js_round(value: f64) -> f64 {
    (value + 0.5).floor()
}

/// An elapsed time in words, rounded to the largest unit it reaches.
fn about(ms: f64) -> String {
    if ms >= DAY {
        return plural(js_round(ms / DAY), "day", None);
    }
    if ms >= HOUR {
        return plural(js_round(ms / HOUR), "hour", None);
    }
    plural(js_round(ms / MINUTE).max(1.0), "minute", None)
}
