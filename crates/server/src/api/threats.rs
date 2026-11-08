//! Port of `packages/server/src/api/threats.ts`: the `threats` API group.
//!
//! Identity threat detection and response. Detection rules (sign-in attacks, session theft, account takeover,
//! privilege escalation, mass changes, weakened guardrails, audit tampering) read each tenant's audit trail through
//! the `iam.detectThreats()` job, group detections into incidents per subject, and raise a decaying risk score per
//! identity that policies read as `principal.riskLevel` / `principal.riskScore`. Administrators tune the rules,
//! investigate and resolve incidents, respond by hand (end sessions, forget devices, contain an identity, block a
//! network, notify), and define playbooks that respond automatically. Reading needs `iam:threats:read`, tuning and
//! triage `iam:threats:manage`, and acting on identities and networks `iam:threats:respond`, all on `iam/threats/...`;
//! people report suspicious activity on their own account without a permission.
//!
//! Records are read and written as raw JSON records, so member order and members this port does not know survive a
//! round trip (a mixed fleet shares the database with TypeScript). The threats module (threats.ts), the engine
//! (threat-engine.ts), responses (threat-response.ts) and the rules (threat-rules.ts) are reached through the bridge
//! below, which converts between these records and those modules' typed signatures through serde.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

use better_iam_core::js as core_js;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Direction, Filter, FindOptions,
    IamError, IamResult, IamStoreExt, Identity, OrderOptions, Record, SessionKind, find_ordered,
    ip_counter_key, is_ip_range,
};
use better_iam_types::api::threats;
use indexmap::IndexSet;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply};
use crate::clearances::assert_clearances;
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, OperationDenied, OperationFailure};
use crate::js::{number_to_string, truthy, utf16_len};
use crate::metrics::locale_compare;
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::port::decode;
use crate::session_kinds::acts_in_own_right;
use crate::utils::{by_id, by_newest_records, id};
use crate::validation::{email, integer, object, text};

const MINUTE: f64 = 60_000.0;
const HOUR: f64 = 60.0 * MINUTE;
const DAY: f64 = 24.0 * HOUR;
/// Playbooks a tenant may define.
const MAX_PLAYBOOKS: usize = 50;
/// Notes one incident may hold.
const MAX_NOTES_PER_INCIDENT: usize = 500;
/// Reports one person may file in 24 hours.
const MAX_REPORTS_PER_DAY: usize = 5;
const INCIDENT_STATUSES: [&str; 2] = ["open", "investigating"];
const DETECTION_STATUSES: [&str; 3] = ["open", "dismissed", "resolved"];
const ALL_INCIDENT_STATUSES: [&str; 3] = ["open", "investigating", "resolved"];
const RESOLUTIONS: [&str; 3] = ["true-positive", "false-positive", "benign"];
const RAISED_LEVELS: [&str; 3] = ["low", "medium", "high"];
const SUBJECT_TYPES: [&str; 4] = ["identity", "network", "tenant", "connection"];
/// The members of `threats.configure` other than `rules` that it compares before and after.
const SETTING_KEYS: [&str; 5] = [
    "trustedNetworks",
    "dormantDays",
    "riskHalfLifeHours",
    "notify",
    "maxAutomaticContainments",
];

fn detection_resource(detection_id: &str) -> String {
    format!("threats/detections/{detection_id}")
}

fn incident_resource(incident_id: &str) -> String {
    format!("threats/incidents/{incident_id}")
}

fn risk_resource(identity_id: &str) -> String {
    format!("threats/risk/{identity_id}")
}

fn playbook_resource(playbook_id: &str) -> String {
    format!("threats/playbooks/{playbook_id}")
}

// --- bridge to threats.ts, threat-engine.ts, threat-response.ts and threat-rules.ts ---------------------------------

fn internal() -> IamError {
    IamError::with_status("INTERNAL_ERROR", "Internal server error", 500)
}

fn to_json<T: Serialize + ?Sized>(value: &T) -> IamResult<Value> {
    serde_json::to_value(value).map_err(|_| internal())
}

fn from_json<T: DeserializeOwned>(value: Value) -> IamResult<T> {
    serde_json::from_value(value).map_err(|_| internal())
}

/// A string as one of the threats module's string unions (`ThreatSeverity`, `RiskLevel`, `ThreatRuleId`, ...).
fn typed<T: DeserializeOwned>(value: &str) -> IamResult<T> {
    from_json(Value::String(value.to_owned()))
}

/// `threatCollections[name]`.
fn collection(name: &str) -> IamResult<String> {
    let collections = to_json(&*crate::threats::THREAT_COLLECTIONS)?;
    collections
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(internal)
}

/// `resolveThreatSettings(stored)`, as JSON.
fn resolve(stored: Option<&Record>) -> IamResult<Value> {
    let stored: Option<crate::threats::ThreatSettings> =
        stored.map(|record| decode(record.clone())).transpose()?;
    to_json(&crate::threats::resolve_threat_settings(stored.as_ref())?)
}

/// Resolved settings (JSON) as the engine and the response module take them.
fn engine_settings(settings: &Value) -> IamResult<crate::threats::ResolvedThreatSettings> {
    from_json(settings.clone())
}

/// `threatRules`, as JSON, in display order.
fn rule_catalog() -> IamResult<Vec<Value>> {
    crate::threats::threat_rules()?
        .iter()
        .map(to_json)
        .collect()
}

/// `threatRule(id)`, as JSON.
fn rule_definition(rule_id: &str) -> IamResult<Value> {
    to_json(&crate::threats::threat_rule(&typed(rule_id)?)?)
}

/// `threatRuleIds.has(id)`.
fn known_rule(rule_id: &str) -> IamResult<bool> {
    Ok(crate::threats::threat_rule_ids()?.iter().any(|known| {
        to_json(known)
            .ok()
            .is_some_and(|known| known.as_str() == Some(rule_id))
    }))
}

fn severity_at_least(severity: &str, floor: &str) -> IamResult<bool> {
    crate::threats::severity_at_least(&typed(severity)?, &typed(floor)?)
}

fn risk_level_at_least(level: &str, floor: &str) -> IamResult<bool> {
    crate::threats::risk_level_at_least(&typed(level)?, &typed(floor)?)
}

/// `effectiveRisk(record, now, halfLifeHours)`: the score and level in force.
fn effective(record: Option<&Record>, now: f64, half_life_hours: f64) -> IamResult<(f64, String)> {
    let record: Option<crate::threats::IdentityRisk> =
        record.map(|record| decode(record.clone())).transpose()?;
    let risk = to_json(&crate::threats::effective_risk(
        record.as_ref(),
        now,
        half_life_hours,
    )?)?;
    Ok((
        risk.get("score").and_then(Value::as_f64).unwrap_or(0.0),
        risk.get("level")
            .and_then(Value::as_str)
            .unwrap_or("none")
            .to_owned(),
    ))
}

/// `riskScore(contributions, now, halfLifeHours)`.
fn score_of(contributions: &[Value], now: f64, half_life_hours: f64) -> IamResult<f64> {
    let contributions = contributions
        .iter()
        .map(|contribution| from_json(contribution.clone()))
        .collect::<IamResult<Vec<crate::threats::RiskContribution>>>()?;
    crate::threats::risk_score(&contributions, now, half_life_hours)
}

/// How detections name a person: as the detection rules do, name and email (`identityLabel(identity, identity.id)`).
fn detection_label(identity: &Identity) -> IamResult<String> {
    crate::threat_rules::identity_label(Some(identity), &identity.id)
}

/// The response module's actor for a person responding (`{ principal }`): the principal's identity, session and
/// device proof, as JSON.
fn actor_of(principal: &AuthenticatedPrincipal) -> IamResult<Value> {
    let mut person = Map::new();
    person.insert("identity".into(), to_json(&principal.identity)?);
    person.insert("session".into(), to_json(&principal.session)?);
    if let Some(proof) = &principal.device_proof {
        person.insert("deviceProof".into(), Value::String(proof.clone()));
    }
    Ok(json!({ "principal": Value::Object(person) }))
}

/// `recordDetection(ctx, tx, tenantId, candidate, settings, now)`: `{ created, detection, incident }`.
async fn record_detection(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    candidate: Value,
    settings: &Value,
    now: f64,
) -> IamResult<Value> {
    let candidate: crate::threat_rules::DetectionCandidate = from_json(candidate)?;
    let recorded = crate::threat_engine::record_detection(
        ctx,
        tx,
        tenant_id,
        &candidate,
        &engine_settings(settings)?,
        now,
    )
    .await?;
    to_json(&recorded)
}

/// `recomputeRisk(ctx, tx, tenantId, identityId, settings, now, actorId, options)`.
#[allow(clippy::too_many_arguments)]
async fn recompute_risk(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    settings: &Value,
    now: f64,
    actor_id: &str,
    options: Option<Value>,
) -> IamResult<()> {
    crate::threat_engine::recompute_risk(
        ctx,
        tx,
        tenant_id,
        identity_id,
        &engine_settings(settings)?,
        now,
        Some(actor_id),
        options.as_ref(),
    )
    .await?;
    Ok(())
}

/// `applyResponse(ctx, tx, tenantId, request, settings)` for a person responding (no brake).
async fn apply_response(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    request: Value,
    settings: &Value,
) -> IamResult<Value> {
    let request: crate::threat_response::ResponseRequest = from_json(request)?;
    let response = crate::threat_response::apply_response(
        ctx,
        tx,
        tenant_id,
        &request,
        &engine_settings(settings)?,
        None,
    )
    .await?;
    to_json(&response)
}

/// `afterThreatResponses(ctx, tenantId, responses)`.
async fn after_threat_responses(
    ctx: &Arc<ServerContext>,
    tenant_id: &str,
    responses: &[Value],
) -> IamResult<()> {
    let responses = responses
        .iter()
        .map(|response| from_json(response.clone()))
        .collect::<IamResult<Vec<crate::threats::ThreatResponse>>>()?;
    crate::threat_response::after_threat_responses(ctx, tenant_id, &responses).await
}

/// Runs the tenant's playbooks for a detection the API itself recorded; nothing runs for a detection seen before.
async fn playbooks_for(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    recorded: &Value,
    settings: &Value,
) -> IamResult<Vec<Value>> {
    if !truthy(recorded.get("created")) {
        return Ok(Vec::new());
    }
    let detection: crate::threats::ThreatDetection =
        from_json(recorded.get("detection").cloned().unwrap_or(Value::Null))?;
    let incident: crate::threats::ThreatIncident =
        from_json(recorded.get("incident").cloned().unwrap_or(Value::Null))?;
    let brake: crate::threat_response::PlaybookBrake = from_json(json!({ "contained": 0 }))?;
    crate::threat_engine::run_playbooks(
        ctx,
        tx,
        tenant_id,
        &detection,
        &incident,
        &engine_settings(settings)?,
        &brake,
    )
    .await?
    .iter()
    .map(to_json)
    .collect()
}

// --- record helpers -----------------------------------------------------------------------------------------------

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

fn str_of<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn str_member<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn num_member(value: Option<&Value>, key: &str) -> Option<f64> {
    value
        .and_then(|value| value.get(key))
        .and_then(core_js::as_number)
}

/// A present string member (`record.key` when it is a non-empty string, as `if (record.key)` reads it).
fn given_str(record: &Record, key: &str) -> Option<String> {
    record
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn number(value: f64) -> Value {
    crate::js::number(value)
}

/// `b - a` as a sort comparator (NaN compares equal).
fn descending(a: f64, b: f64) -> Ordering {
    b.partial_cmp(&a).unwrap_or(Ordering::Equal)
}

/// `Math.round`.
fn js_round(value: f64) -> f64 {
    (value + 0.5).floor()
}

/// `value.trim()`.
fn trimmed(value: String) -> String {
    core_js::trim(&value).to_owned()
}

fn stringify(value: &Value) -> String {
    core_js::stringify(value)
}

async fn find(tx: &Store, collection: &str, filter: &Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, filter, &FindOptions::default()).await
}

fn tenant_filter(tenant_id: &str) -> Filter {
    Filter::new().eq("tenantId", tenant_id)
}

fn oneof(value: Option<&Value>, allowed: &[&str], name: &str) -> IamResult<String> {
    match value {
        Some(Value::String(value)) if allowed.contains(&value.as_str()) => Ok(value.clone()),
        _ => Err(invalid(format!(
            "{name} must be one of {}",
            allowed.join(", ")
        ))),
    }
}

fn rule_id_of(value: Option<&Value>, name: &str) -> IamResult<String> {
    match value {
        Some(Value::String(value)) if known_rule(value)? => Ok(value.clone()),
        _ => Err(invalid(format!("{name} names an unknown detection rule"))),
    }
}

fn flag(value: Option<&Value>, name: &str) -> IamResult<bool> {
    match value {
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(invalid(format!("{name} must be a boolean"))),
    }
}

/// JSON with object keys sorted, to compare settings regardless of the order their keys were written in.
fn canonical(value: Option<&Value>) -> String {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut entries: Vec<(&String, &Value)> = map.iter().collect();
                entries.sort_by(|(a, _), (b, _)| crate::js::cmp_utf16(a, b));
                Value::Object(
                    entries
                        .into_iter()
                        .map(|(key, item)| (key.clone(), sorted(item)))
                        .collect(),
                )
            }
            Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    match value {
        Some(value) => stringify(&sorted(value)),
        None => "undefined".into(),
    }
}

/// The effective values of a resolved rule setting, for telling whether a change altered what the rule does.
fn rule_signature(setting: Option<&Value>) -> String {
    let member = |key: &str| {
        setting
            .and_then(|setting| setting.get(key))
            .cloned()
            .unwrap_or(Value::Null)
    };
    stringify(&json!([
        member("enabled"),
        member("severity"),
        member("threshold"),
        member("windowMs"),
        setting.and_then(|setting| setting.get("everyone")) == Some(&Value::Bool(true)),
    ]))
}

/// `settings.rules[ruleId]`.
fn rule_setting<'a>(settings: &'a Value, rule_id: &str) -> Option<&'a Value> {
    settings.get("rules").and_then(|rules| rules.get(rule_id))
}

fn enabled(setting: Option<&Value>) -> bool {
    truthy(setting.and_then(|setting| setting.get("enabled")))
}

/// One way a settings change weakens detection or response (`threats.configure` reports it as guardrail-weakened).
struct Weakening {
    /// The setting as audit metadata names it: `rules.brute-force.threshold`, `riskHalfLifeHours`, ...
    key: String,
    /// What the caller did, for the detection's summary.
    words: String,
}

/// A few items in words: "a", "a and b", "a, b and 3 more".
fn listed(items: &[String], limit: usize) -> String {
    let shown = &items[..items.len().min(limit)];
    let rest = items.len() - shown.len();
    if rest > 0 {
        return format!("{} and {rest} more", shown.join(", "));
    }
    if shown.len() <= 1 {
        return shown.join("");
    }
    format!(
        "{} and {}",
        shown[..shown.len() - 1].join(", "),
        shown[shown.len() - 1]
    )
}

fn strings_of(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// What a settings change weakens besides turning rules off (reported on its own): a rule that stays on made less
/// sensitive (a higher threshold, a shorter window, a lower severity, new-network no longer reporting everyone), a
/// shorter risk half-life (every score decays at once), a longer dormancy period, newly trusted networks (never
/// reported, never blocked), a lower automatic containment brake, and fewer people emailed about incidents.
fn weakenings(before: &Value, after: &Value) -> IamResult<Vec<Weakening>> {
    let mut found = Vec::new();
    for rule in rule_catalog()? {
        let rule_id = str_member(&rule, "id");
        let was = rule_setting(before, rule_id);
        let is = rule_setting(after, rule_id);
        if !enabled(was) || !enabled(is) {
            continue;
        }
        let key = format!("rules.{rule_id}");
        let name = format!("\"{}\"", str_member(&rule, "title"));
        if let (Some(was_threshold), Some(is_threshold)) =
            (num_member(was, "threshold"), num_member(is, "threshold"))
            && is_threshold > was_threshold
        {
            found.push(Weakening {
                key: format!("{key}.threshold"),
                words: format!(
                    "raised the threshold of {name} from {} to {}",
                    number_to_string(was_threshold),
                    number_to_string(is_threshold)
                ),
            });
        }
        if let (Some(was_window), Some(is_window)) =
            (num_member(was, "windowMs"), num_member(is, "windowMs"))
            && is_window < was_window
        {
            found.push(Weakening {
                key: format!("{key}.windowMs"),
                words: format!(
                    "shortened the window of {name} from {} to {} minutes",
                    number_to_string(js_round(was_window / MINUTE)),
                    number_to_string(js_round(is_window / MINUTE))
                ),
            });
        }
        let was_severity = was
            .and_then(|was| was.get("severity"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let is_severity = is
            .and_then(|is| is.get("severity"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !severity_at_least(is_severity, was_severity)? {
            found.push(Weakening {
                key: format!("{key}.severity"),
                words: format!(
                    "lowered the severity of {name} from {was_severity} to {is_severity}"
                ),
            });
        }
        let everyone = |setting: Option<&Value>| {
            setting.and_then(|setting| setting.get("everyone")) == Some(&Value::Bool(true))
        };
        if everyone(was) && !everyone(is) {
            found.push(Weakening {
                key: format!("{key}.everyone"),
                words: format!("stopped {name} reporting everyone"),
            });
        }
    }
    let number_of = |settings: &Value, key: &str| num_member(Some(settings), key).unwrap_or(0.0);
    let (before_half_life, after_half_life) = (
        number_of(before, "riskHalfLifeHours"),
        number_of(after, "riskHalfLifeHours"),
    );
    if after_half_life < before_half_life {
        found.push(Weakening {
            key: "riskHalfLifeHours".into(),
            words: format!(
                "shortened the risk half-life from {} to {} hours",
                number_to_string(before_half_life),
                number_to_string(after_half_life)
            ),
        });
    }
    let (before_dormant, after_dormant) = (
        number_of(before, "dormantDays"),
        number_of(after, "dormantDays"),
    );
    if after_dormant > before_dormant {
        found.push(Weakening {
            key: "dormantDays".into(),
            words: format!(
                "lengthened the dormancy period from {} to {} days",
                number_to_string(before_dormant),
                number_to_string(after_dormant)
            ),
        });
    }
    let before_networks = strings_of(before.get("trustedNetworks"));
    let trusted: Vec<String> = strings_of(after.get("trustedNetworks"))
        .into_iter()
        .filter(|network| !before_networks.contains(network))
        .collect();
    if !trusted.is_empty() {
        found.push(Weakening {
            key: "trustedNetworks".into(),
            words: format!("trusted {}", listed(&trusted, 3)),
        });
    }
    let (before_brake, after_brake) = (
        number_of(before, "maxAutomaticContainments"),
        number_of(after, "maxAutomaticContainments"),
    );
    if after_brake < before_brake {
        found.push(Weakening {
            key: "maxAutomaticContainments".into(),
            words: format!(
                "lowered the automatic containment limit from {} to {}",
                number_to_string(before_brake),
                number_to_string(after_brake)
            ),
        });
    }
    let before_notify = before.get("notify");
    let after_notify = after.get("notify");
    let after_emails = strings_of(after_notify.and_then(|notify| notify.get("emails")));
    let removed = strings_of(before_notify.and_then(|notify| notify.get("emails")))
        .iter()
        .filter(|address| !after_emails.contains(address))
        .count();
    let owners = |notify: Option<&Value>| truthy(notify.and_then(|notify| notify.get("owners")));
    let stopped_owners = owners(before_notify) && !owners(after_notify);
    if stopped_owners || removed > 0 {
        found.push(Weakening {
            key: "notify".into(),
            words: if stopped_owners {
                "stopped emailing owners about incidents".into()
            } else {
                format!(
                    "removed {removed} incident email recipient{}",
                    if removed == 1 { "" } else { "s" }
                )
            },
        });
    }
    Ok(found)
}

/// `value ?? fallback`.
fn or_default(value: Option<&Value>, fallback: f64) -> Value {
    match value {
        Some(value) if !value.is_null() => value.clone(),
        _ => number(fallback),
    }
}

fn paging(input: &Map<String, Value>) -> IamResult<(usize, usize)> {
    let limit = integer(
        Some(&or_default(input.get("limit"), 100.0)),
        "limit",
        1.0,
        1000.0,
    )?;
    let offset = integer(
        Some(&or_default(input.get("offset"), 0.0)),
        "offset",
        0.0,
        1_000_000.0,
    )?;
    Ok((limit as usize, offset as usize))
}

/// `items.slice(offset, offset + limit)`.
fn page<T: Clone>(items: &[T], offset: usize, limit: usize) -> Vec<T> {
    items.iter().skip(offset).take(limit).cloned().collect()
}

/// `listIncidents`' `status`: one status, or a list of one to three distinct ones.
fn incident_statuses_of(value: Option<&Value>) -> IamResult<Vec<String>> {
    let Some(Value::Array(entries)) = value else {
        return Ok(vec![oneof(value, &ALL_INCIDENT_STATUSES, "status")?]);
    };
    if entries.is_empty() || entries.len() > ALL_INCIDENT_STATUSES.len() {
        return Err(invalid(format!(
            "status must list 1-{} incident statuses",
            ALL_INCIDENT_STATUSES.len()
        )));
    }
    let mut statuses: Vec<String> = Vec::new();
    for entry in entries {
        let status = oneof(Some(entry), &ALL_INCIDENT_STATUSES, "status")?;
        if !statuses.contains(&status) {
            statuses.push(status);
        }
    }
    Ok(statuses)
}

/// Identity kinds by id already looked up during one read (`None` for an identity outside the tenant).
type SubjectKinds = HashMap<String, Option<Value>>;

/// Detections or incidents as the API returns them: identity subjects gain the identity's `kind` when the identity
/// belongs to the tenant. Each identity is read once per read (pass the same `kinds` to share lookups between calls);
/// the kind is never stored.
async fn with_subject_kinds(
    tx: &Store,
    tenant_id: &str,
    records: &[Record],
    kinds: &mut SubjectKinds,
) -> IamResult<Vec<Value>> {
    let identity_subject = |record: &Record| -> Option<String> {
        let subject = record.get("subject")?;
        if subject.get("type").and_then(Value::as_str) != Some("identity") {
            return None;
        }
        subject.get("id").and_then(Value::as_str).map(str::to_owned)
    };
    for record in records {
        if let Some(subject_id) = identity_subject(record)
            && !kinds.contains_key(&subject_id)
        {
            let identity = tx.get("identities", &subject_id).await?;
            let kind = identity
                .filter(|identity| {
                    identity.get("tenantId").and_then(Value::as_str) == Some(tenant_id)
                })
                .and_then(|identity| identity.get("kind").cloned());
            kinds.insert(subject_id, kind);
        }
    }
    Ok(records
        .iter()
        .map(|record| {
            let kind = identity_subject(record)
                .and_then(|subject_id| kinds.get(&subject_id).cloned().flatten())
                .filter(|kind| truthy(Some(kind)));
            let mut out = record.clone();
            if let Some(kind) = kind
                && let Some(Value::Object(subject)) = out.get_mut("subject")
            {
                subject.insert("kind".into(), kind);
            }
            Value::Object(out)
        })
        .collect())
}

/// One detection or incident as the API returns it (see `with_subject_kinds`).
async fn with_subject_kind(
    tx: &Store,
    tenant_id: &str,
    record: &Record,
    kinds: &mut SubjectKinds,
) -> IamResult<Value> {
    Ok(
        with_subject_kinds(tx, tenant_id, std::slice::from_ref(record), kinds)
            .await?
            .remove(0),
    )
}

/// Free text over several lines (notes, reports): line breaks are normalized to `\n`, tabs kept, every other control
/// character dropped; 1 to `max` characters after trimming.
fn multiline(value: Option<&Value>, name: &str, max: usize) -> IamResult<String> {
    let value = match value {
        Some(Value::String(value)) if utf16_len(value) <= max * 4 => value,
        _ => return Err(invalid(format!("Invalid {name}"))),
    };
    let mut cleaned = String::new();
    let mut previous = 0u32;
    for character in value.chars() {
        let code = character as u32;
        if code == 13 {
            cleaned.push('\n');
        } else if code == 10 {
            if previous != 13 {
                cleaned.push('\n');
            }
        } else if code == 9 || (32..127).contains(&code) || code >= 160 {
            cleaned.push(character);
        }
        previous = code;
    }
    let cleaned = core_js::trim(&cleaned).to_owned();
    if cleaned.is_empty() || utf16_len(&cleaned) > max {
        return Err(invalid(format!("{name} must be 1-{max} characters")));
    }
    Ok(cleaned)
}

/// True for a CIDR block wider than /8 (IPv4, including IPv4-mapped IPv6 blocks) or /32 (IPv6): trusting it would
/// switch the network rules off, and exempt it from network blocks, for a large part of the internet.
fn too_wide(network: &str) -> bool {
    let Some(slash) = network.find('/') else {
        return false;
    };
    let address = &network[..slash];
    let prefix = core_js::to_number(&Value::String(network[slash + 1..].to_owned()));
    // ipCounterKey folds IPv4-mapped IPv6 addresses to their IPv4 form, so only real IPv6 keys keep a colon.
    let ipv6 = ip_counter_key(address).is_none_or(|key| key.contains(':'));
    let mapped = !ipv6 && address.contains(':');
    prefix
        < if ipv6 {
            32.0
        } else if mapped {
            104.0
        } else {
            8.0
        }
}

fn trusted_networks_of(value: Option<&Value>) -> IamResult<Vec<String>> {
    let entries = match value {
        Some(Value::Array(entries)) if entries.len() <= 50 => entries,
        _ => return Err(invalid("trustedNetworks must list at most 50 networks")),
    };
    let mut networks: IndexSet<String> = IndexSet::new();
    for entry in entries {
        let network = trimmed(text(Some(entry), "trustedNetworks", 64)?);
        if !is_ip_range(&network) {
            return Err(invalid(
                "trustedNetworks entries must be IPv4/IPv6 addresses or CIDR blocks",
            ));
        }
        if too_wide(&network) {
            return Err(invalid(
                "Trusted networks may be at most /8 (IPv4) or /32 (IPv6) wide",
            ));
        }
        networks.insert(network);
    }
    Ok(networks.into_iter().collect())
}

fn notify_of(value: Option<&Value>, current: Option<&Value>) -> IamResult<Value> {
    let input = object(value)?;
    for key in input.keys() {
        if key != "owners" && key != "emails" {
            return Err(invalid(format!(
                "Unknown notify setting {}",
                slice_utf16(key, 64)
            )));
        }
    }
    let mut owners = truthy(current.and_then(|current| current.get("owners")));
    let mut emails = strings_of(current.and_then(|current| current.get("emails")));
    if input.contains_key("owners") {
        owners = flag(input.get("owners"), "notify.owners")?;
    }
    if input.contains_key("emails") {
        let entries = match input.get("emails") {
            Some(Value::Array(entries)) if entries.len() <= 20 => entries,
            _ => return Err(invalid("notify.emails must list at most 20 addresses")),
        };
        let mut unique: IndexSet<String> = IndexSet::new();
        for entry in entries {
            unique.insert(email(Some(entry))?);
        }
        emails = unique.into_iter().collect();
    }
    Ok(json!({ "owners": owners, "emails": emails }))
}

/// `value.slice(0, length)` in UTF-16 code units.
fn slice_utf16(value: &str, length: usize) -> String {
    let units: Vec<u16> = value.encode_utf16().take(length).collect();
    String::from_utf16_lossy(&units)
}

/// Merges per-rule changes into a tenant's rule settings; a rule left without adjustments is dropped.
fn merge_rules(
    current: &Map<String, Value>,
    value: Option<&Value>,
) -> IamResult<Map<String, Value>> {
    let mut next = current.clone();
    for (key, change) in object(value)? {
        let rule = rule_definition(&rule_id_of(Some(&Value::String(key.clone())), "rules")?)?;
        let rule_id = str_member(&rule, "id").to_owned();
        if change.is_null() {
            next.shift_remove(&rule_id);
            continue;
        }
        let mut setting: Map<String, Value> = match next.get(&rule_id) {
            Some(Value::Object(existing)) => existing.clone(),
            _ => Map::new(),
        };
        for (field, raw) in object(Some(change))? {
            let name = format!("rules.{rule_id}.{field}");
            match field.as_str() {
                "enabled" => {
                    if raw.is_null() {
                        setting.shift_remove("enabled");
                    } else {
                        setting.insert("enabled".into(), Value::Bool(flag(Some(raw), &name)?));
                    }
                }
                "severity" => {
                    if raw.is_null() {
                        setting.shift_remove("severity");
                    } else {
                        setting.insert(
                            "severity".into(),
                            Value::String(oneof(
                                Some(raw),
                                crate::threats::THREAT_SEVERITIES,
                                &name,
                            )?),
                        );
                    }
                }
                "threshold" | "windowMs" => {
                    let bounds = rule
                        .get("tunable")
                        .and_then(|tunable| tunable.get(field.as_str()))
                        .and_then(Value::as_array);
                    if raw.is_null() {
                        setting.shift_remove(field.as_str());
                    } else if let Some(bounds) = bounds {
                        let bound = |index: usize| {
                            bounds
                                .get(index)
                                .and_then(core_js::as_number)
                                .unwrap_or(f64::NAN)
                        };
                        let value = integer(Some(raw), &name, bound(0), bound(1))?;
                        setting.insert(field.clone(), number(value));
                    } else {
                        return Err(invalid(format!(
                            "The {rule_id} rule has no adjustable {field}"
                        )));
                    }
                }
                "everyone" => {
                    if rule_id != "new-network" {
                        return Err(invalid("everyone applies to the new-network rule only"));
                    }
                    if raw.is_null() {
                        setting.shift_remove("everyone");
                    } else {
                        setting.insert("everyone".into(), Value::Bool(flag(Some(raw), &name)?));
                    }
                }
                _ => {
                    return Err(invalid(format!(
                        "Unknown setting {} for {rule_id}",
                        slice_utf16(field, 64)
                    )));
                }
            }
        }
        if setting.is_empty() {
            next.shift_remove(&rule_id);
        } else {
            next.insert(rule_id, Value::Object(setting));
        }
    }
    Ok(next)
}

fn rule_view(rule: &Value, settings: &Value, stored: Option<&Record>) -> Value {
    let rule_id = str_member(rule, "id");
    let effective = rule_setting(settings, rule_id);
    let own = stored
        .and_then(|stored| stored.get("rules"))
        .and_then(|rules| rules.get(rule_id));
    let member = |value: &Value, key: &str| value.get(key).cloned().unwrap_or(Value::Null);
    let mut view = Map::new();
    view.insert("id".into(), member(rule, "id"));
    view.insert("title".into(), member(rule, "title"));
    view.insert("description".into(), member(rule, "description"));
    view.insert("category".into(), member(rule, "category"));
    view.insert("subject".into(), member(rule, "subject"));
    view.insert("technique".into(), member(rule, "technique"));
    let mut defaults = Map::new();
    defaults.insert("enabled".into(), member(rule, "enabledByDefault"));
    defaults.insert("severity".into(), member(rule, "severity"));
    for key in ["threshold", "windowMs"] {
        if let Some(value) = rule.get(key).filter(|value| !value.is_null()) {
            defaults.insert(key.into(), value.clone());
        }
    }
    view.insert("defaults".into(), Value::Object(defaults));
    if let Some(tunable) = rule.get("tunable").filter(|tunable| truthy(Some(tunable))) {
        view.insert("tunable".into(), tunable.clone());
    }
    let effective_member = |key: &str| effective.and_then(|effective| effective.get(key));
    view.insert(
        "enabled".into(),
        effective_member("enabled").cloned().unwrap_or(Value::Null),
    );
    view.insert(
        "severity".into(),
        effective_member("severity").cloned().unwrap_or(Value::Null),
    );
    for key in ["threshold", "windowMs"] {
        if let Some(value) = effective_member(key) {
            view.insert(key.into(), value.clone());
        }
    }
    if rule_id == "new-network" {
        view.insert(
            "everyone".into(),
            Value::Bool(effective_member("everyone") == Some(&Value::Bool(true))),
        );
    }
    // `own !== undefined && Object.keys(own).length > 0`.
    let customized = match own {
        Some(Value::Object(own)) => !own.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::String(text)) => !text.is_empty(),
        _ => false,
    };
    view.insert("customized".into(), Value::Bool(customized));
    Value::Object(view)
}

fn settings_view(tenant_id: &str, stored: Option<&Record>) -> IamResult<Value> {
    let mut view = Map::new();
    view.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    view.insert("configured".into(), Value::Bool(stored.is_some()));
    if let Value::Object(resolved) = resolve(stored)? {
        for (key, value) in resolved {
            view.insert(key, value);
        }
    }
    if let Some(stored) = stored {
        for key in ["updatedAt", "updatedBy"] {
            if let Some(value) = stored.get(key) {
                view.insert(key.into(), value.clone());
            }
        }
    }
    Ok(Value::Object(view))
}

/// The tenant's stored settings (absent until `threats.configure` first saves them).
async fn stored_settings(tx: &Store, tenant_id: &str) -> IamResult<Option<Record>> {
    let stored = tx.get(&collection("settings")?, tenant_id).await?;
    Ok(stored.filter(|stored| str_of(stored, "tenantId") == tenant_id))
}

async fn risk_record(tx: &Store, tenant_id: &str, identity_id: &str) -> IamResult<Option<Record>> {
    let record = tx.get(&collection("risk")?, identity_id).await?;
    Ok(record.filter(|record| str_of(record, "tenantId") == tenant_id))
}

/// The containment in force: the risk record's mark while the identity is still disabled. An identity re-enabled
/// outside the threats module (identities.setStatus, agents.resume) is no longer contained, whatever the mark says.
fn containment<'a>(identity: &Record, record: Option<&'a Record>) -> Option<&'a Value> {
    if str_of(identity, "status") == "disabled" {
        record
            .and_then(|record| record.get("contained"))
            .filter(|contained| truthy(Some(contained)))
    } else {
        None
    }
}

fn contributions_of(record: Option<&Record>) -> Vec<Value> {
    match record.and_then(|record| record.get("contributions")) {
        Some(Value::Array(contributions)) => contributions.clone(),
        _ => Vec::new(),
    }
}

fn risk_view(
    identity: &Record,
    record: Option<&Record>,
    settings: &Value,
    now: f64,
) -> IamResult<Value> {
    let half_life = num_member(Some(settings), "riskHalfLifeHours").unwrap_or(f64::NAN);
    let (score, level) = effective(record, now, half_life)?;
    let contained = containment(identity, record);
    let mut view = Map::new();
    view.insert(
        "identityId".into(),
        identity.get("id").cloned().unwrap_or(Value::Null),
    );
    for key in ["name", "email"] {
        if let Some(value) = identity.get(key).filter(|value| truthy(Some(value))) {
            view.insert(key.into(), value.clone());
        }
    }
    view.insert(
        "kind".into(),
        identity.get("kind").cloned().unwrap_or(Value::Null),
    );
    view.insert(
        "status".into(),
        identity.get("status").cloned().unwrap_or(Value::Null),
    );
    view.insert("score".into(), number(score));
    view.insert("level".into(), Value::String(level));
    if let Some(Value::Object(override_)) = record
        .and_then(|record| record.get("override"))
        .filter(|override_| truthy(Some(override_)))
    {
        let mut out = Map::new();
        for key in ["level", "reason", "by", "at"] {
            out.insert(
                key.into(),
                override_.get(key).cloned().unwrap_or(Value::Null),
            );
        }
        let expires_at = override_.get("expiresAt");
        if let Some(expires_at) = expires_at {
            out.insert("expiresAt".into(), expires_at.clone());
        }
        let active = match expires_at {
            None => true,
            Some(value) => core_js::as_number(value).is_some_and(|expires_at| expires_at > now),
        };
        out.insert("active".into(), Value::Bool(active));
        view.insert("override".into(), Value::Object(out));
    }
    if let Some(contained) = contained {
        view.insert("contained".into(), contained.clone());
    }
    let mut contributions = Vec::new();
    for contribution in contributions_of(record) {
        let current = score_of(std::slice::from_ref(&contribution), now, half_life)?;
        let mut entry = match contribution {
            Value::Object(entry) => entry,
            _ => Map::new(),
        };
        entry.insert("current".into(), number(current));
        contributions.push(Value::Object(entry));
    }
    contributions.sort_by(|a, b| {
        descending(
            num_member(Some(a), "at").unwrap_or(f64::NAN),
            num_member(Some(b), "at").unwrap_or(f64::NAN),
        )
    });
    view.insert("contributions".into(), Value::Array(contributions));
    if let Some(record) = record {
        view.insert(
            "updatedAt".into(),
            record.get("updatedAt").cloned().unwrap_or(Value::Null),
        );
    }
    Ok(Value::Object(view))
}

/// Takes the contributions of `detection_ids` out of an identity's risk and recomputes it, auditing a level change
/// under the caller; nothing happens when none of them contributes.
#[allow(clippy::too_many_arguments)]
async fn drop_contributions(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    detection_ids: &IndexSet<String>,
    settings: &Value,
    now: f64,
    actor_id: &str,
) -> IamResult<()> {
    let record = risk_record(tx, tenant_id, identity_id).await?;
    let contributes = contributions_of(record.as_ref())
        .iter()
        .any(|contribution| {
            contribution
                .get("detectionId")
                .and_then(Value::as_str)
                .is_some_and(|detection_id| detection_ids.contains(detection_id))
        });
    if record.is_none() || !contributes {
        return Ok(());
    }
    let drop: Vec<&String> = detection_ids.iter().collect();
    recompute_risk(
        ctx,
        tx,
        tenant_id,
        identity_id,
        settings,
        now,
        actor_id,
        Some(json!({ "drop": drop })),
    )
    .await
}

fn response_actions_of(value: Option<&Value>, name: &str) -> IamResult<Vec<Value>> {
    let entries = match value {
        Some(Value::Array(entries)) if !entries.is_empty() && entries.len() <= 5 => entries,
        _ => return Err(invalid(format!("{name} must list 1-5 response actions"))),
    };
    let mut seen: Vec<String> = Vec::new();
    let mut actions = Vec::new();
    for entry in entries {
        let input = object(Some(entry))?;
        for key in input.keys() {
            if key != "kind" && key != "durationMs" && key != "keepApiKeys" {
                return Err(invalid(format!(
                    "Unknown response action field {}",
                    slice_utf16(key, 64)
                )));
            }
        }
        let kind = oneof(
            input.get("kind"),
            crate::threats::RESPONSE_ACTION_KINDS,
            &format!("{name} kind"),
        )?;
        if seen.contains(&kind) {
            return Err(invalid(format!("{name} may list each kind of action once")));
        }
        seen.push(kind.clone());
        let mut action = Map::new();
        action.insert("kind".into(), Value::String(kind.clone()));
        if input.contains_key("durationMs") {
            if kind != "block-network" {
                return Err(invalid("durationMs applies to block-network only"));
            }
            action.insert(
                "durationMs".into(),
                number(integer(
                    input.get("durationMs"),
                    "durationMs",
                    MINUTE,
                    30.0 * DAY,
                )?),
            );
        }
        if input.contains_key("keepApiKeys") {
            if kind != "revoke-sessions" {
                return Err(invalid("keepApiKeys applies to revoke-sessions only"));
            }
            action.insert(
                "keepApiKeys".into(),
                Value::Bool(flag(input.get("keepApiKeys"), "keepApiKeys")?),
            );
        }
        actions.push(Value::Object(action));
    }
    Ok(actions)
}

fn suspends_clearances(actions: Option<&Value>) -> bool {
    matches!(actions, Some(Value::Array(actions)) if actions
        .iter()
        .any(|action| action.get("kind").and_then(Value::as_str) == Some("suspend-clearance")))
}

/// A playbook that suspends clearances acts as a clearance officer would: it needs the `clearances` option
/// (FEATURE_DISABLED otherwise), and whoever writes it must be allowed to suspend any clearance of the tenant
/// (iam:clearances:suspend on iam/clearances, an audited ACCESS_DENIED otherwise), so holding iam:threats:manage alone
/// never lets someone suspend people's clearances through the threat-detection actor.
async fn assert_may_suspend_clearances(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
) -> Result<(), OperationFailure> {
    assert_clearances(ctx)?;
    let decision = ctx
        .decisions()?
        .decide(
            tx,
            principal,
            &AuthorizationRequest {
                credential: CredentialInput::default(),
                tenant_id: tenant_id.to_owned(),
                action: "iam:clearances:suspend".into(),
                resource: ResourceTarget {
                    kind: "iam".into(),
                    id: "clearances".into(),
                },
            },
            true,
        )
        .await?;
    if !decision.allowed {
        return Err(OperationDenied::new(Some(
            "Playbooks that suspend clearances need iam:clearances:suspend",
        )));
    }
    Ok(())
}

fn playbook_name(value: Option<&Value>) -> IamResult<String> {
    let name = trimmed(text(value, "name", 100)?);
    if name.is_empty() {
        return Err(invalid("name is required"));
    }
    Ok(name)
}

fn playbook_trigger(value: Option<&Value>) -> IamResult<Value> {
    if value.is_none() {
        return Err(invalid("trigger is required ({} matches every detection)"));
    }
    let input = object(value)?;
    let mut trigger = Map::new();
    for key in input.keys() {
        if key != "ruleIds" && key != "minSeverity" && key != "subjectTypes" {
            return Err(invalid(format!(
                "Unknown trigger field {}",
                slice_utf16(key, 64)
            )));
        }
    }
    if let Some(rule_ids) = input.get("ruleIds").filter(|value| !value.is_null()) {
        let rule_count = rule_catalog()?.len();
        let entries = match rule_ids {
            Value::Array(entries) if !entries.is_empty() && entries.len() <= rule_count => entries,
            _ => {
                return Err(invalid(format!(
                    "trigger.ruleIds must list 1-{rule_count} detection rules"
                )));
            }
        };
        let mut unique: IndexSet<String> = IndexSet::new();
        for entry in entries {
            unique.insert(rule_id_of(Some(entry), "trigger.ruleIds")?);
        }
        trigger.insert(
            "ruleIds".into(),
            json!(unique.into_iter().collect::<Vec<_>>()),
        );
    }
    if let Some(min_severity) = input.get("minSeverity").filter(|value| !value.is_null()) {
        trigger.insert(
            "minSeverity".into(),
            Value::String(oneof(
                Some(min_severity),
                crate::threats::THREAT_SEVERITIES,
                "trigger.minSeverity",
            )?),
        );
    }
    if let Some(subject_types) = input.get("subjectTypes").filter(|value| !value.is_null()) {
        let entries = match subject_types {
            Value::Array(entries)
                if !entries.is_empty() && entries.len() <= SUBJECT_TYPES.len() =>
            {
                entries
            }
            _ => {
                return Err(invalid(format!(
                    "trigger.subjectTypes must list 1-{} subject types",
                    SUBJECT_TYPES.len()
                )));
            }
        };
        let mut unique: IndexSet<String> = IndexSet::new();
        for entry in entries {
            unique.insert(oneof(Some(entry), &SUBJECT_TYPES, "trigger.subjectTypes")?);
        }
        trigger.insert(
            "subjectTypes".into(),
            json!(unique.into_iter().collect::<Vec<_>>()),
        );
    }
    Ok(Value::Object(trigger))
}

/// Audit metadata describing a playbook's settings.
fn playbook_metadata(playbook: &Record) -> Map<String, Value> {
    let trigger = playbook.get("trigger");
    let mut trigger_out = Map::new();
    for key in ["ruleIds", "minSeverity", "subjectTypes"] {
        if let Some(value) = trigger
            .and_then(|trigger| trigger.get(key))
            .filter(|value| truthy(Some(value)))
        {
            trigger_out.insert(key.into(), value.clone());
        }
    }
    let actions: Vec<Value> = match playbook.get("actions") {
        Some(Value::Array(actions)) => actions
            .iter()
            .map(|action| {
                let mut out = Map::new();
                out.insert(
                    "kind".into(),
                    action.get("kind").cloned().unwrap_or(Value::Null),
                );
                for key in ["durationMs", "keepApiKeys"] {
                    if let Some(value) = action.get(key) {
                        out.insert(key.into(), value.clone());
                    }
                }
                Value::Object(out)
            })
            .collect(),
        _ => Vec::new(),
    };
    let mut metadata = Map::new();
    metadata.insert(
        "name".into(),
        playbook.get("name").cloned().unwrap_or(Value::Null),
    );
    metadata.insert(
        "enabled".into(),
        playbook.get("enabled").cloned().unwrap_or(Value::Null),
    );
    metadata.insert("trigger".into(), Value::Object(trigger_out));
    metadata.insert("actions".into(), Value::Array(actions));
    metadata
}

/// True when one of `identity_ids` is the caller's own identity and the caller is not a root administrator: nobody
/// else clears risk raised against themselves, so a compromised administrator account cannot erase its own signal.
async fn clears_own_risk(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    identity_ids: impl IntoIterator<Item = Option<String>>,
) -> IamResult<bool> {
    for identity_id in identity_ids {
        if identity_id.as_deref() == Some(principal.identity.id.as_str()) {
            return Ok(!ctx.root_principal(tx, principal).await?);
        }
    }
    Ok(false)
}

/// How responses name a person: their name, else their email (as the response module does).
fn person_label(identity: &Identity) -> String {
    if !identity.name.is_empty() {
        return identity.name.clone();
    }
    match &identity.email {
        Some(email) if !email.is_empty() => email.clone(),
        _ => identity.id.clone(),
    }
}

fn audit_outcome() -> AuditOutcome {
    AuditOutcome::Allow
}

fn metadata(entries: Vec<(&str, Value)>) -> Map<String, Value> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

/// The JSON array of responses an operation returned (`{ value, responses }`).
fn responses_of(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(responses)) => responses.clone(),
        _ => Vec::new(),
    }
}

/// The `threats` API group (`createThreatsApi(ctx)`): one method per route `threats/{method}`.
pub struct ThreatsApi {
    ctx: Arc<ServerContext>,
}

/// `createThreatsApi(ctx)`.
pub fn create_threats_api(ctx: &Arc<ServerContext>) -> IamResult<ThreatsApi> {
    Ok(ThreatsApi { ctx: ctx.clone() })
}

impl ThreatsApi {
    /// `threats/addNote`: adds an investigation note (1-4000 characters over several lines) to an incident, resolved
    /// ones included; at most 500 per incident. Requires iam:threats:manage on iam/threats/incidents/{id}; audited as
    /// `threat:note` (without the text).
    pub async fn add_note(
        &self,
        credential: &CredentialInput,
        input: Body<threats::AddNoteInput>,
    ) -> IamResult<Reply<threats::AddNoteOutput>> {
        let incident_id = text(input.get("incidentId"), "incidentId", 256)?;
        let body = multiline(input.get("body"), "body", 4000)?;
        let ctx = &self.ctx;
        let (incident_ref, body_ref) = (&incident_id, &body);
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    let incidents = collection("incidents")?;
                    let notes = collection("notes")?;
                    let incident = ctx
                        .scoped(
                            &tx,
                            &incidents,
                            Some(&Value::String(incident_ref.clone())),
                            &tenant.id,
                        )
                        .await?;
                    let incident_id = str_of(&incident, "id").to_owned();
                    let existing = find(
                        &tx,
                        &notes,
                        &tenant_filter(&tenant.id).eq("incidentId", incident_id.clone()),
                    )
                    .await?;
                    if existing.len() >= MAX_NOTES_PER_INCIDENT {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!("An incident holds at most {MAX_NOTES_PER_INCIDENT} notes"),
                            409,
                        )
                        .into());
                    }
                    let note = tx
                        .insert(
                            &notes,
                            &metadata(vec![
                                ("id", Value::String(id())),
                                ("tenantId", Value::String(tenant.id.clone())),
                                ("incidentId", Value::String(incident_id.clone())),
                                ("authorId", Value::String(principal.identity.id.clone())),
                                ("body", Value::String(body_ref.clone())),
                                ("createdAt", number(ctx.now())),
                            ]),
                        )
                        .await?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "threat:note",
                            &tenant.id,
                            &incident_resource(&incident_id),
                            audit_outcome(),
                            false,
                            Some(metadata(vec![
                                ("noteId", note.get("id").cloned().unwrap_or(Value::Null)),
                                ("length", number(utf16_len(body_ref) as f64)),
                            ])),
                        )
                        .await?;
                    Ok(Value::Object(note))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:manage",
                &incident_resource(&incident_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/configure`: tunes detection: per-rule `enabled`, `severity`, `threshold` and `windowMs` (within the
    /// rule's `tunable` bounds; `null` restores a default, a rule set to `null` drops all its adjustments), `everyone`
    /// for new-network, trusted networks, the dormancy period, the risk half-life, notification recipients and the
    /// automatic containment brake. Turning a rule off, or weakening detection or response otherwise, also records a
    /// `guardrail-weakened` detection against the caller, since the engine never reads the module's own events.
    /// Nobody shortens the half-life while detections raise their own risk (root administrators excepted). Requires
    /// iam:threats:manage on iam/threats/settings and recent authentication; audited as `threat:settings`.
    pub async fn configure(
        &self,
        credential: &CredentialInput,
        input: Body<threats::ConfigureInput>,
    ) -> IamResult<Reply<threats::ConfigureOutput>> {
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let ctx = &self.ctx;
        let body: &Map<String, Value> = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let stored = stored_settings(&tx, &tenant.id).await?;
                    let before = resolve(stored.as_ref())?;
                    let now = ctx.now();
                    let stored_rules = match stored.as_ref().and_then(|stored| stored.get("rules"))
                    {
                        Some(Value::Object(rules)) => rules.clone(),
                        _ => Map::new(),
                    };
                    let rules = if body.contains_key("rules") {
                        merge_rules(&stored_rules, body.get("rules"))?
                    } else {
                        stored_rules
                    };
                    let before_member = |key: &str| before.get(key).cloned().unwrap_or(Value::Null);
                    let trusted_networks = if body.contains_key("trustedNetworks") {
                        json!(trusted_networks_of(body.get("trustedNetworks"))?)
                    } else {
                        before_member("trustedNetworks")
                    };
                    let bounded = |key: &str, min: f64, max: f64| -> IamResult<Value> {
                        if body.contains_key(key) {
                            Ok(number(integer(body.get(key), key, min, max)?))
                        } else {
                            Ok(before_member(key))
                        }
                    };
                    let dormant_days = bounded("dormantDays", 7.0, 3650.0)?;
                    let risk_half_life_hours = bounded("riskHalfLifeHours", 1.0, 720.0)?;
                    let notify = if body.contains_key("notify") {
                        notify_of(body.get("notify"), before.get("notify"))?
                    } else {
                        before_member("notify")
                    };
                    let max_automatic_containments =
                        bounded("maxAutomaticContainments", 0.0, 100.0)?;
                    let next = metadata(vec![
                        ("id", Value::String(tenant.id.clone())),
                        ("tenantId", Value::String(tenant.id.clone())),
                        ("rules", Value::Object(rules)),
                        ("trustedNetworks", trusted_networks),
                        ("dormantDays", dormant_days),
                        ("riskHalfLifeHours", risk_half_life_hours.clone()),
                        ("notify", notify),
                        ("maxAutomaticContainments", max_automatic_containments),
                        ("updatedAt", number(now)),
                        ("updatedBy", Value::String(principal.identity.id.clone())),
                    ]);
                    // A shorter half-life decays every score at once, the caller's too: as with dismissals, nobody clears
                    // risk raised against themselves.
                    let before_half_life =
                        num_member(Some(&before), "riskHalfLifeHours").unwrap_or(f64::NAN);
                    if core_js::as_number(&risk_half_life_hours)
                        .is_some_and(|next| next < before_half_life)
                        && score_of(
                            &contributions_of(
                                risk_record(&tx, &tenant.id, &principal.identity.id)
                                    .await?
                                    .as_ref(),
                            ),
                            now,
                            before_half_life,
                        )? > 0.0
                        && clears_own_risk(
                            ctx,
                            &tx,
                            &principal,
                            [Some(principal.identity.id.clone())],
                        )
                        .await?
                    {
                        return Err(OperationDenied::new(Some(
                            "While detections raise your own risk, another administrator shortens the risk half-life",
                        )));
                    }
                    let settings_collection = collection("settings")?;
                    if stored.is_some() {
                        tx.put(&settings_collection, &next).await?;
                    } else {
                        tx.insert(&settings_collection, &next).await?;
                    }
                    let after = resolve(Some(&next))?;
                    let catalog = rule_catalog()?;
                    let rule_ids: Vec<&str> =
                        catalog.iter().map(|rule| str_member(rule, "id")).collect();
                    let changed_rules: Vec<&str> = rule_ids
                        .iter()
                        .copied()
                        .filter(|rule_id| {
                            rule_signature(rule_setting(&before, rule_id))
                                != rule_signature(rule_setting(&after, rule_id))
                        })
                        .collect();
                    let mut changed: Vec<&str> = Vec::new();
                    if !changed_rules.is_empty() {
                        changed.push("rules");
                    }
                    for key in SETTING_KEYS {
                        if canonical(before.get(key)) != canonical(after.get(key)) {
                            changed.push(key);
                        }
                    }
                    let disabled_rules: Vec<&str> = rule_ids
                        .iter()
                        .copied()
                        .filter(|rule_id| {
                            enabled(rule_setting(&before, rule_id))
                                && !enabled(rule_setting(&after, rule_id))
                        })
                        .collect();
                    let weakened = weakenings(&before, &after)?;
                    let weakened_keys: Vec<&str> =
                        weakened.iter().map(|item| item.key.as_str()).collect();
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "threat:settings",
                            &tenant.id,
                            "threats/settings",
                            audit_outcome(),
                            false,
                            Some(metadata(vec![
                                ("changed", json!(changed)),
                                ("changedRules", json!(changed_rules)),
                                ("disabledRules", json!(disabled_rules)),
                                ("weakened", json!(weakened_keys)),
                            ])),
                        )
                        .await?;
                    let mut responses: Vec<Value> = Vec::new();
                    // Judged by the guardrail rule as it stood before the change, so turning that rule off (or down) in
                    // the same call is reported too; a tenant that had already turned it off is not.
                    let guardrail = rule_setting(&before, "guardrail-weakened")
                        .cloned()
                        .unwrap_or(Value::Null);
                    if (!disabled_rules.is_empty() || !weakened.is_empty())
                        && enabled(Some(&guardrail))
                    {
                        let mut reporting = after.clone();
                        if let Some(Value::Object(rules)) = reporting.get_mut("rules") {
                            rules.insert("guardrail-weakened".into(), guardrail.clone());
                        }
                        let mut titles = Vec::new();
                        for rule_id in &disabled_rules {
                            titles.push(str_member(&rule_definition(rule_id)?, "title").to_owned());
                        }
                        let count = format!(
                            "{} detection rule{}",
                            disabled_rules.len(),
                            if disabled_rules.len() == 1 { "" } else { "s" }
                        );
                        let mut changes: Vec<String> = Vec::new();
                        if !disabled_rules.is_empty() {
                            changes.push(format!("turned off {count}: {}", titles.join(", ")));
                        }
                        changes.extend(weakened.iter().map(|item| item.words.clone()));
                        let candidate = json!({
                            "ruleId": "guardrail-weakened",
                            "severity": guardrail.get("severity").cloned().unwrap_or(Value::Null),
                            "title": if weakened.is_empty() {
                                "Detection rules turned off"
                            } else {
                                "Threat detection weakened"
                            },
                            "summary": format!(
                                "{} {}.",
                                detection_label(&principal.identity)?,
                                listed(&changes, 6)
                            ),
                            "subject": { "type": "tenant", "id": tenant.id, "name": tenant.name },
                            "identityId": principal.identity.id,
                            "dedupeKey": format!("settings:{}", id()),
                            "occurredAt": number(now),
                            "evidence": {
                                "eventIds": [],
                                "count": disabled_rules.len() + weakened.len(),
                                "firstAt": number(now),
                                "lastAt": number(now),
                                "identityIds": [principal.identity.id],
                                "actions": ["threat:settings"],
                            },
                            "metadata": {
                                "disabledRules": disabled_rules,
                                "weakened": weakened_keys,
                                "changedBy": principal.identity.id,
                            },
                        });
                        let recorded =
                            record_detection(ctx, &tx, &tenant.id, candidate, &reporting, now)
                                .await?;
                        responses =
                            playbooks_for(ctx, &tx, &tenant.id, &recorded, &reporting).await?;
                    }
                    Ok(json!({
                        "value": settings_view(&tenant.id, Some(&next))?,
                        "responses": responses,
                    }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id.clone())),
                "iam:threats:manage",
                "threats/settings",
                mutation,
                false,
            )
            .await?;
        after_threat_responses(ctx, &tenant_id, &responses_of(result.get("responses"))).await?;
        Ok(Reply::json(
            result.get("value").cloned().unwrap_or(Value::Null),
        ))
    }

    /// `threats/createPlaybook`: defines an automatic response: when a new detection matches `trigger` (rules,
    /// minimum severity, subject types; fields left out match everything), `actions` run in order as the
    /// threat-detection actor. Names are unique per tenant; at most 50 playbooks. Requires iam:threats:manage on
    /// iam/threats/playbooks and recent authentication, plus iam:clearances:suspend on iam/clearances for a playbook
    /// that suspends clearances (FEATURE_DISABLED without the `clearances` option); audited as
    /// `threat:playbook-create`.
    pub async fn create_playbook(
        &self,
        credential: &CredentialInput,
        input: Body<threats::CreatePlaybookInput>,
    ) -> IamResult<Reply<threats::CreatePlaybookOutput>> {
        let ctx = &self.ctx;
        let body: &Map<String, Value> = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let name = playbook_name(body.get("name"))?;
                    let description = if body.contains_key("description") {
                        Some(trimmed(text(body.get("description"), "description", 512)?))
                    } else {
                        None
                    };
                    let enabled = if body.contains_key("enabled") {
                        flag(body.get("enabled"), "enabled")?
                    } else {
                        true
                    };
                    let trigger = playbook_trigger(body.get("trigger"))?;
                    let actions =
                        Value::Array(response_actions_of(body.get("actions"), "actions")?);
                    if suspends_clearances(Some(&actions)) {
                        assert_may_suspend_clearances(ctx, &tx, &principal, &tenant.id).await?;
                    }
                    let unique_key = format!("name:{}", core_js::to_lower(&name));
                    let playbooks = collection("playbooks")?;
                    let existing = find(&tx, &playbooks, &tenant_filter(&tenant.id)).await?;
                    if existing
                        .iter()
                        .any(|playbook| str_of(playbook, "uniqueKey") == unique_key)
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A playbook with this name exists",
                            409,
                        )
                        .into());
                    }
                    if existing.len() >= MAX_PLAYBOOKS {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!("A tenant can define at most {MAX_PLAYBOOKS} playbooks"),
                            409,
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let mut record = metadata(vec![
                        ("id", Value::String(id())),
                        ("tenantId", Value::String(tenant.id.clone())),
                        ("uniqueKey", Value::String(unique_key)),
                        ("name", Value::String(name)),
                    ]);
                    if let Some(description) =
                        description.filter(|description| !description.is_empty())
                    {
                        record.insert("description".into(), Value::String(description));
                    }
                    for (key, value) in [
                        ("enabled", Value::Bool(enabled)),
                        ("trigger", trigger),
                        ("actions", actions),
                        ("createdAt", number(now)),
                        ("createdBy", Value::String(principal.identity.id.clone())),
                        ("updatedAt", number(now)),
                        ("updatedBy", Value::String(principal.identity.id.clone())),
                        ("runs", number(0.0)),
                    ] {
                        record.insert(key.into(), value);
                    }
                    let playbook = tx.insert(&playbooks, &record).await?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "threat:playbook-create",
                            &tenant.id,
                            &playbook_resource(str_of(&playbook, "id")),
                            audit_outcome(),
                            false,
                            Some(playbook_metadata(&playbook)),
                        )
                        .await?;
                    Ok(Value::Object(playbook))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:manage",
                "threats/playbooks",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/deletePlaybook`: deletes a playbook; responses it already took stay on their incidents. Requires
    /// iam:threats:manage on iam/threats/playbooks/{id} and recent authentication; audited as
    /// `threat:playbook-delete`.
    pub async fn delete_playbook(
        &self,
        credential: &CredentialInput,
        input: Body<threats::DeletePlaybookInput>,
    ) -> IamResult<Reply<threats::DeletePlaybookOutput>> {
        let playbook_id = text(input.get("playbookId"), "playbookId", 256)?;
        let ctx = &self.ctx;
        let playbook_ref = &playbook_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let playbooks = collection("playbooks")?;
                    let playbook = ctx
                        .scoped(
                            &tx,
                            &playbooks,
                            Some(&Value::String(playbook_ref.clone())),
                            &tenant.id,
                        )
                        .await?;
                    tx.delete(&playbooks, str_of(&playbook, "id")).await?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "threat:playbook-delete",
                            &tenant.id,
                            &playbook_resource(str_of(&playbook, "id")),
                            audit_outcome(),
                            false,
                            Some(metadata(vec![(
                                "name",
                                playbook.get("name").cloned().unwrap_or(Value::Null),
                            )])),
                        )
                        .await?;
                    Ok(json!({ "deleted": true }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:manage",
                &playbook_resource(&playbook_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/detect`: runs detection for the tenant now instead of waiting for the scheduled
    /// `iam.detectThreats()` job, and returns what the run did. Requires iam:threats:manage on
    /// iam/threats/detections.
    pub async fn detect(
        &self,
        credential: &CredentialInput,
        input: Body<threats::DetectInput>,
    ) -> IamResult<Reply<threats::DetectOutput>> {
        let ctx = &self.ctx;
        // The engine opens its own transactions, so it runs once the permission check has committed.
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tenant, .. }| {
            Box::pin(async move { Ok(Value::String(tenant.id.clone())) })
        });
        let tenant_id = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:manage",
                "threats/detections",
                mutation,
                false,
            )
            .await?;
        let run =
            crate::threat_engine::detect_threats(ctx, Some(&json!({ "tenantId": tenant_id })))
                .await?;
        Ok(Reply::json(to_json(&run)?))
    }

    /// `threats/dismissDetection`: marks an open detection as a false alarm and takes its points out of the identity's
    /// risk; the incident stays open for a person to resolve. Detections about the caller are dismissed by someone
    /// else (root administrators excepted). Requires iam:threats:manage on iam/threats/detections/{id} and recent
    /// authentication; audited as `threat:detection-dismiss`.
    pub async fn dismiss_detection(
        &self,
        credential: &CredentialInput,
        input: Body<threats::DismissDetectionInput>,
    ) -> IamResult<Reply<threats::DismissDetectionOutput>> {
        let detection_id = text(input.get("detectionId"), "detectionId", 256)?;
        let ctx = &self.ctx;
        let body: &Map<String, Value> = &input;
        let detection_ref = &detection_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let reason = trimmed(text(body.get("reason"), "reason", 512)?);
                    let detections = collection("detections")?;
                    let detection = ctx
                        .scoped(
                            &tx,
                            &detections,
                            Some(&Value::String(detection_ref.clone())),
                            &tenant.id,
                        )
                        .await?;
                    if str_of(&detection, "status") != "open" {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "Only open detections can be dismissed",
                            409,
                        )
                        .into());
                    }
                    let identity_id = given_str(&detection, "identityId");
                    if clears_own_risk(
                        ctx,
                        &tx,
                        &principal,
                        [detection
                            .get("identityId")
                            .and_then(Value::as_str)
                            .map(str::to_owned)],
                    )
                    .await?
                    {
                        return Err(OperationDenied::new(Some(
                            "Detections about yourself are dismissed by another administrator",
                        )));
                    }
                    let now = ctx.now();
                    let mut changed = detection.clone();
                    changed.insert("status".into(), Value::String("dismissed".into()));
                    changed.insert(
                        "dismissedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    changed.insert("dismissedAt".into(), number(now));
                    changed.insert("dismissReason".into(), Value::String(reason.clone()));
                    let next = tx.put(&detections, &changed).await?;
                    let own_id = str_of(&detection, "id").to_owned();
                    if let Some(identity_id) = &identity_id {
                        let settings = resolve(stored_settings(&tx, &tenant.id).await?.as_ref())?;
                        let ids: IndexSet<String> = [own_id.clone()].into_iter().collect();
                        drop_contributions(
                            ctx,
                            &tx,
                            &tenant.id,
                            identity_id,
                            &ids,
                            &settings,
                            now,
                            &principal.identity.id,
                        )
                        .await?;
                    }
                    let mut details = metadata(vec![
                        (
                            "ruleId",
                            detection.get("ruleId").cloned().unwrap_or(Value::Null),
                        ),
                        (
                            "severity",
                            detection.get("severity").cloned().unwrap_or(Value::Null),
                        ),
                        ("reason", Value::String(reason)),
                    ]);
                    if let Some(identity_id) = identity_id {
                        details.insert("identityId".into(), Value::String(identity_id));
                    }
                    if let Some(incident_id) = given_str(&detection, "incidentId") {
                        details.insert("incidentId".into(), Value::String(incident_id));
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "threat:detection-dismiss",
                            &tenant.id,
                            &detection_resource(&own_id),
                            audit_outcome(),
                            false,
                            Some(details),
                        )
                        .await?;
                    Ok(with_subject_kind(&tx, &tenant.id, &next, &mut SubjectKinds::new()).await?)
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:manage",
                &detection_resource(&detection_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/getDetection`: one detection with its evidence. Requires iam:threats:read on
    /// iam/threats/detections/{id}.
    pub async fn get_detection(
        &self,
        credential: &CredentialInput,
        input: Body<threats::GetDetectionInput>,
    ) -> IamResult<Reply<threats::GetDetectionOutput>> {
        let detection_id = text(input.get("detectionId"), "detectionId", 256)?;
        let ctx = &self.ctx;
        let detection_ref = &detection_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let detection = ctx
                    .scoped(
                        &tx,
                        &collection("detections")?,
                        Some(&Value::String(detection_ref.clone())),
                        &tenant.id,
                    )
                    .await?;
                Ok(
                    with_subject_kind(&tx, &tenant.id, &detection, &mut SubjectKinds::new())
                        .await?,
                )
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:read",
                &detection_resource(&detection_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/getIncident`: an incident with its detections (up to 200, newest first), notes (oldest first),
    /// responses (newest first) and the risk of the identity it concerns. Requires iam:threats:read on
    /// iam/threats/incidents/{id}.
    pub async fn get_incident(
        &self,
        credential: &CredentialInput,
        input: Body<threats::GetIncidentInput>,
    ) -> IamResult<Reply<threats::GetIncidentOutput>> {
        let incident_id = text(input.get("incidentId"), "incidentId", 256)?;
        let ctx = &self.ctx;
        let incident_ref = &incident_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let incident = ctx
                    .scoped(
                        &tx,
                        &collection("incidents")?,
                        Some(&Value::String(incident_ref.clone())),
                        &tenant.id,
                    )
                    .await?;
                let own_id = str_of(&incident, "id").to_owned();
                let detections = find_ordered(
                    tx.as_ref(),
                    &collection("detections")?,
                    &tenant_filter(&tenant.id).eq("incidentId", own_id.clone()),
                    &OrderOptions {
                        direction: Direction::Desc,
                        limit: Some(200),
                        ..OrderOptions::by("detectedAt")
                    },
                    None,
                )
                .await?;
                let mut notes = find(
                    &tx,
                    &collection("notes")?,
                    &tenant_filter(&tenant.id).eq("incidentId", own_id.clone()),
                )
                .await?;
                notes.sort_by(|a, b| by_newest_records(b, a));
                let mut responses = find(
                    &tx,
                    &collection("responses")?,
                    &tenant_filter(&tenant.id).eq("incidentId", own_id.clone()),
                )
                .await?;
                responses.sort_by(by_newest_records);
                // The incident and its detections are mostly about one subject: each identity is looked up once.
                let mut kinds = SubjectKinds::new();
                let mut detail = Map::new();
                detail.insert(
                    "incident".into(),
                    with_subject_kind(&tx, &tenant.id, &incident, &mut kinds).await?,
                );
                detail.insert(
                    "detections".into(),
                    Value::Array(
                        with_subject_kinds(&tx, &tenant.id, &detections, &mut kinds).await?,
                    ),
                );
                detail.insert(
                    "notes".into(),
                    Value::Array(notes.into_iter().map(Value::Object).collect()),
                );
                detail.insert(
                    "responses".into(),
                    Value::Array(responses.into_iter().map(Value::Object).collect()),
                );
                if let Some(identity_id) = given_str(&incident, "identityId")
                    && let Some(identity) = tx.get("identities", &identity_id).await?
                    && str_of(&identity, "tenantId") == tenant.id
                {
                    let settings = resolve(stored_settings(&tx, &tenant.id).await?.as_ref())?;
                    let record = risk_record(&tx, &tenant.id, str_of(&identity, "id")).await?;
                    detail.insert(
                        "risk".into(),
                        risk_view(&identity, record.as_ref(), &settings, ctx.now())?,
                    );
                }
                Ok(Value::Object(detail))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:read",
                &incident_resource(&incident_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/getRisk`: one identity's risk (level `none` when nothing was ever detected). Requires iam:threats:read
    /// on iam/threats/risk/{id}.
    pub async fn get_risk(
        &self,
        credential: &CredentialInput,
        input: Body<threats::GetRiskInput>,
    ) -> IamResult<Reply<threats::GetRiskOutput>> {
        let identity_id = text(input.get("identityId"), "identityId", 256)?;
        let ctx = &self.ctx;
        let identity_ref = &identity_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let identity = ctx
                    .scoped(
                        &tx,
                        "identities",
                        Some(&Value::String(identity_ref.clone())),
                        &tenant.id,
                    )
                    .await?;
                let record = risk_record(&tx, &tenant.id, str_of(&identity, "id")).await?;
                let settings = resolve(stored_settings(&tx, &tenant.id).await?.as_ref())?;
                Ok(risk_view(&identity, record.as_ref(), &settings, ctx.now())?)
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:read",
                &risk_resource(&identity_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/getSettings`: the tenant's detection settings with defaults applied. Requires iam:threats:read on
    /// iam/threats/settings.
    pub async fn get_settings(
        &self,
        credential: &CredentialInput,
        input: Body<threats::GetSettingsInput>,
    ) -> IamResult<Reply<threats::GetSettingsOutput>> {
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let stored = stored_settings(&tx, &tenant.id).await?;
                Ok(settings_view(&tenant.id, stored.as_ref())?)
            })
        });
        let result = self
            .ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:read",
                "threats/settings",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/listDetections`: the tenant's detections, newest first, optionally narrowed by status, rule,
    /// severity, identity, incident and a `since` time (epoch milliseconds, by detection time). Requires
    /// iam:threats:read on iam/threats/detections.
    pub async fn list_detections(
        &self,
        credential: &CredentialInput,
        input: Body<threats::ListDetectionsInput>,
    ) -> IamResult<Reply<threats::ListDetectionsOutput>> {
        let (limit, offset) = paging(&input)?;
        let mut filter = Filter::new();
        if input.contains_key("status") {
            filter.set(
                "status",
                Some(Value::String(oneof(
                    input.get("status"),
                    &DETECTION_STATUSES,
                    "status",
                )?)),
            );
        }
        if input.contains_key("ruleId") {
            filter.set(
                "ruleId",
                Some(Value::String(rule_id_of(input.get("ruleId"), "ruleId")?)),
            );
        }
        if input.contains_key("severity") {
            filter.set(
                "severity",
                Some(Value::String(oneof(
                    input.get("severity"),
                    crate::threats::THREAT_SEVERITIES,
                    "severity",
                )?)),
            );
        }
        for key in ["identityId", "incidentId"] {
            if input.contains_key(key) {
                filter.set(key, Some(Value::String(text(input.get(key), key, 256)?)));
            }
        }
        let since = if input.contains_key("since") {
            Some(integer(
                input.get("since"),
                "since",
                0.0,
                crate::js::MAX_SAFE_INTEGER,
            )?)
        } else {
            None
        };
        let filter = &filter;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let mut tenant_scoped = filter.clone();
                tenant_scoped.set("tenantId", Some(Value::String(tenant.id.clone())));
                let detections = find_ordered(
                    tx.as_ref(),
                    &collection("detections")?,
                    &tenant_scoped,
                    &OrderOptions {
                        direction: Direction::Desc,
                        from: since,
                        ..OrderOptions::by("detectedAt")
                    },
                    None,
                )
                .await?;
                let shown = page(&detections, offset, limit);
                Ok(json!({
                    "detections": with_subject_kinds(&tx, &tenant.id, &shown, &mut SubjectKinds::new()).await?,
                    "total": detections.len(),
                }))
            })
        });
        let result = self
            .ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:read",
                "threats/detections",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/listIncidents`: the tenant's incidents, most recently active first, optionally narrowed by status (one,
    /// or a list such as `['open', 'investigating']` for every active incident), severity, assignee and identity.
    /// Requires iam:threats:read on iam/threats/incidents.
    pub async fn list_incidents(
        &self,
        credential: &CredentialInput,
        input: Body<threats::ListIncidentsInput>,
    ) -> IamResult<Reply<threats::ListIncidentsOutput>> {
        let (limit, offset) = paging(&input)?;
        let wanted = if input.contains_key("status") {
            Some(incident_statuses_of(input.get("status"))?)
        } else {
            None
        };
        // Every status is no narrowing at all; otherwise each status is read on its own (never the resolved backlog
        // when only active incidents are wanted) and the results merged.
        let statuses: Vec<Option<String>> = match wanted {
            Some(wanted) if wanted.len() != ALL_INCIDENT_STATUSES.len() => {
                wanted.into_iter().map(Some).collect()
            }
            _ => vec![None],
        };
        let mut filter = Filter::new();
        if input.contains_key("severity") {
            filter.set(
                "severity",
                Some(Value::String(oneof(
                    input.get("severity"),
                    crate::threats::THREAT_SEVERITIES,
                    "severity",
                )?)),
            );
        }
        for key in ["assigneeId", "identityId"] {
            if input.contains_key(key) {
                filter.set(key, Some(Value::String(text(input.get(key), key, 256)?)));
            }
        }
        let (filter, statuses) = (&filter, &statuses);
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let incidents_collection = collection("incidents")?;
                let mut found: Vec<Vec<Record>> = Vec::new();
                for status in statuses {
                    let mut scoped = filter.clone();
                    if let Some(status) = status {
                        scoped.set("status", Some(Value::String(status.clone())));
                    }
                    scoped.set("tenantId", Some(Value::String(tenant.id.clone())));
                    found.push(
                        find_ordered(
                            tx.as_ref(),
                            &incidents_collection,
                            &scoped,
                            &OrderOptions {
                                direction: Direction::Desc,
                                ..OrderOptions::by("lastDetectedAt")
                            },
                            None,
                        )
                        .await?,
                    );
                }
                let several = found.len() > 1;
                let mut incidents: Vec<Record> = found.into_iter().flatten().collect();
                if several {
                    incidents.sort_by(|a, b| {
                        let last = |record: &Record| {
                            record
                                .get("lastDetectedAt")
                                .and_then(core_js::as_number)
                                .unwrap_or(f64::NAN)
                        };
                        descending(last(a), last(b))
                            .then_with(|| by_id(str_of(a, "id"), str_of(b, "id")))
                    });
                }
                let shown = page(&incidents, offset, limit);
                Ok(json!({
                    "incidents": with_subject_kinds(&tx, &tenant.id, &shown, &mut SubjectKinds::new()).await?,
                    "total": incidents.len(),
                }))
            })
        });
        let result = self
            .ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:read",
                "threats/incidents",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/listPlaybooks`: the tenant's playbooks by name. Requires iam:threats:read on iam/threats/playbooks.
    pub async fn list_playbooks(
        &self,
        credential: &CredentialInput,
        input: Body<threats::ListPlaybooksInput>,
    ) -> IamResult<Reply<threats::ListPlaybooksOutput>> {
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let mut playbooks =
                    find(&tx, &collection("playbooks")?, &tenant_filter(&tenant.id)).await?;
                playbooks.sort_by(|a, b| locale_compare(str_of(a, "name"), str_of(b, "name")));
                Ok(Value::Array(
                    playbooks.into_iter().map(Value::Object).collect(),
                ))
            })
        });
        let result = self
            .ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:read",
                "threats/playbooks",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/listRisk`: identities whose effective risk is at least `minLevel` (default `low`), or that are
    /// contained, highest score first. Requires iam:threats:read on iam/threats/risk.
    pub async fn list_risk(
        &self,
        credential: &CredentialInput,
        input: Body<threats::ListRiskInput>,
    ) -> IamResult<Reply<threats::ListRiskOutput>> {
        let (limit, offset) = paging(&input)?;
        let floor = if input.contains_key("minLevel") {
            oneof(input.get("minLevel"), &RAISED_LEVELS, "minLevel")?
        } else {
            "low".to_owned()
        };
        let ctx = &self.ctx;
        let floor = &floor;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let settings = resolve(stored_settings(&tx, &tenant.id).await?.as_ref())?;
                let half_life =
                    num_member(Some(&settings), "riskHalfLifeHours").unwrap_or(f64::NAN);
                let now = ctx.now();
                let mut identities: Vec<Value> = Vec::new();
                for record in find(&tx, &collection("risk")?, &tenant_filter(&tenant.id)).await? {
                    let (_, level) = effective(Some(&record), now, half_life)?;
                    let raised = risk_level_at_least(&level, floor)?;
                    if !raised && !truthy(record.get("contained")) {
                        continue;
                    }
                    let identity = tx.get("identities", str_of(&record, "identityId")).await?;
                    let Some(identity) = identity.filter(|identity| {
                        str_of(identity, "tenantId") == tenant.id
                            && str_of(identity, "status") != "deleted"
                    }) else {
                        continue;
                    };
                    if raised || containment(&identity, Some(&record)).is_some() {
                        identities.push(risk_view(&identity, Some(&record), &settings, now)?);
                    }
                }
                identities.sort_by(|a, b| {
                    descending(
                        num_member(Some(a), "score").unwrap_or(f64::NAN),
                        num_member(Some(b), "score").unwrap_or(f64::NAN),
                    )
                    .then_with(|| {
                        if str_member(a, "identityId") < str_member(b, "identityId") {
                            Ordering::Less
                        } else {
                            Ordering::Greater
                        }
                    })
                });
                Ok(json!({
                    "identities": page(&identities, offset, limit),
                    "total": identities.len(),
                }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:read",
                "threats/risk",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/release`: lifts a containment: the identity becomes active again and signs in as usual (its sessions
    /// stay ended, its API keys work again); its risk score is kept. Only an identity the threats module contained and
    /// that is still disabled can be released (INVALID_TRANSITION otherwise), a root administrator only by root.
    /// Requires iam:threats:respond on iam/threats/responses and recent authentication; audited as `threat:release`.
    pub async fn release(
        &self,
        credential: &CredentialInput,
        input: Body<threats::ReleaseInput>,
    ) -> IamResult<Reply<threats::ReleaseOutput>> {
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let identity_id = text(input.get("identityId"), "identityId", 256)?;
        let note = if input.contains_key("note") {
            Some(trimmed(text(input.get("note"), "note", 512)?))
        } else {
            None
        };
        let ctx = &self.ctx;
        let (identity_ref, note_ref) = (&identity_id, &note);
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let response = crate::threat_response::release_identity(
                        ctx,
                        &tx,
                        &tenant.id,
                        identity_ref,
                        &actor_of(&principal)?,
                        note_ref.as_deref(),
                    )
                    .await?;
                    Ok(to_json(&response)?)
                })
            },
        );
        let response = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id.clone())),
                "iam:threats:respond",
                "threats/responses",
                mutation,
                false,
            )
            .await?;
        after_threat_responses(ctx, &tenant_id, std::slice::from_ref(&response)).await?;
        Ok(Reply::json(response))
    }

    /// `threats/reportSuspicious`: "This wasn't me": the signed-in person reports suspicious activity on their own
    /// account, optionally with a note (up to 1000 characters) and the id of the session they do not recognize.
    /// Records a `user-reported` detection (raising their risk and opening an incident administrators see), ends every
    /// other session of the account except API keys (the reporting session stays) and its pending sign-in challenges,
    /// forgets remembered devices, and runs the tenant's playbooks. Needs only an ordinary sign-in session of the
    /// tenant (not an impersonation); at most five reports a day; refused with FEATURE_DISABLED when the tenant turned
    /// the rule off. Audited as `threat:user-report`, with the two responses as `threat:revoke-sessions` and
    /// `threat:forget-devices`.
    pub async fn report_suspicious(
        &self,
        credential: &CredentialInput,
        input: Body<threats::ReportSuspiciousInput>,
    ) -> IamResult<Reply<threats::ReportSuspiciousOutput>> {
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let note = if input.contains_key("note") {
            Some(multiline(input.get("note"), "note", 1000)?)
        } else {
            None
        };
        let session_id = if input.contains_key("sessionId") {
            Some(text(input.get("sessionId"), "sessionId", 256)?)
        } else {
            None
        };
        let ctx = self.ctx.clone();
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let store = ctx.store.clone();
        let inner = ctx.clone();
        let tenant = tenant_id.clone();
        let (report, responses) = store
            .transaction(move |tx| async move {
                let ctx = inner;
                let tenant_id = tenant;
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                if principal
                    .session
                    .impersonator_id
                    .as_deref()
                    .is_some_and(|impersonator| !impersonator.is_empty())
                {
                    return Err(IamError::with_status(
                        "IMPERSONATION_RESTRICTED",
                        "Suspicious activity cannot be reported while impersonating",
                        403,
                    ));
                }
                let identity = principal.identity.clone();
                let session = &principal.session;
                if session.kind != SessionKind::User
                    || !acts_in_own_right(session.kind)
                    || session.tenant_id != tenant_id
                    || identity.tenant_id != tenant_id
                {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Suspicious activity is reported from a sign-in session of the account\u{2019}s own tenant",
                        403,
                    ));
                }
                let realm = ctx.tenant(&tx, &tenant_id).await?;
                let settings = resolve(stored_settings(&tx, &tenant_id).await?.as_ref())?;
                let rule = rule_setting(&settings, "user-reported")
                    .cloned()
                    .unwrap_or(Value::Null);
                if !enabled(Some(&rule)) {
                    return Err(IamError::with_status(
                        "FEATURE_DISABLED",
                        "This organization does not take reports of suspicious activity",
                        403,
                    ));
                }
                let now = ctx.now();
                let recent = find_ordered(
                    tx.as_ref(),
                    &collection("detections")?,
                    &tenant_filter(&tenant_id)
                        .eq("ruleId", "user-reported")
                        .eq("identityId", identity.id.clone()),
                    &OrderOptions {
                        from: Some(now - DAY),
                        ..OrderOptions::by("detectedAt")
                    },
                    None,
                )
                .await?;
                if recent.len() >= MAX_REPORTS_PER_DAY {
                    return Err(IamError::with_status(
                        "LIMIT_EXCEEDED",
                        format!(
                            "At most {MAX_REPORTS_PER_DAY} reports a day; administrators already have the earlier ones"
                        ),
                        409,
                    ));
                }
                if let Some(session_id) = &session_id
                    && let Some(reported) = tx.get("sessions", session_id).await?
                    && (str_of(&reported, "identityId") != identity.id
                        || str_of(&reported, "tenantId") != tenant_id)
                {
                    return Err(IamError::with_status("NOT_FOUND", "Session not found", 404));
                }
                let label = detection_label(&identity)?;
                let subject = json!({ "type": "identity", "id": identity.id, "name": label });
                let mut candidate_metadata = Map::new();
                if let Some(note) = &note {
                    candidate_metadata.insert("note".into(), Value::String(note.clone()));
                }
                if let Some(session_id) = &session_id {
                    candidate_metadata.insert("sessionId".into(), Value::String(session_id.clone()));
                }
                let candidate = json!({
                    "ruleId": "user-reported",
                    "severity": rule.get("severity").cloned().unwrap_or(Value::Null),
                    "title": str_member(&rule_definition("user-reported")?, "title"),
                    "summary": format!("{label} reported activity on their account that was not them."),
                    "subject": subject,
                    "identityId": identity.id,
                    "dedupeKey": id(),
                    "occurredAt": number(now),
                    "evidence": {
                        "eventIds": [],
                        "count": 1,
                        "firstAt": number(now),
                        "lastAt": number(now),
                        "identityIds": [identity.id],
                        "actions": ["threat:user-report"],
                    },
                    "metadata": Value::Object(candidate_metadata),
                });
                let recorded =
                    record_detection(&ctx, &tx, &tenant_id, candidate, &settings, now).await?;
                let detection_id = recorded
                    .get("detection")
                    .map(|detection| str_member(detection, "id").to_owned())
                    .unwrap_or_default();
                let incident_id = recorded
                    .get("incident")
                    .map(|incident| str_member(incident, "id").to_owned())
                    .unwrap_or_default();
                // The person's own responses, filed under the new incident: every other credential of the account
                // ends (API keys and the reporting session stay, pending sign-in challenges go), then remembered
                // devices.
                let actor = actor_of(&principal)?;
                let own = |action: Value| {
                    json!({
                        "action": action,
                        "subject": subject,
                        "identityId": identity.id,
                        "incidentId": incident_id,
                        "detectionId": detection_id,
                        "reason": "Reported by the account holder",
                        "actor": actor,
                    })
                };
                let revoked = apply_response(
                    &ctx,
                    &tx,
                    &tenant_id,
                    own(json!({ "kind": "revoke-sessions", "keepApiKeys": true })),
                    &settings,
                )
                .await?;
                let forgotten = apply_response(
                    &ctx,
                    &tx,
                    &tenant_id,
                    own(json!({ "kind": "forget-devices" })),
                    &settings,
                )
                .await?;
                let count = |response: &Value, key: &str| {
                    response
                        .get("details")
                        .and_then(|details| details.get(key))
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0)
                };
                let sessions_ended = count(&revoked, "revoked");
                let devices_forgotten = count(&forgotten, "removed");
                let report = json!({
                    "detectionId": detection_id,
                    "incidentId": incident_id,
                    "sessionsEnded": number(sessions_ended),
                    "devicesForgotten": number(devices_forgotten),
                });
                let mut details = metadata(vec![
                    ("detectionId", Value::String(detection_id.clone())),
                    ("incidentId", Value::String(incident_id.clone())),
                    ("sessionsEnded", number(sessions_ended)),
                    ("devicesForgotten", number(devices_forgotten)),
                    ("withNote", Value::Bool(note.is_some())),
                ]);
                if let Some(session_id) = &session_id {
                    details.insert("sessionId".into(), Value::String(session_id.clone()));
                }
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "threat:user-report",
                        &realm.id,
                        &identity.id,
                        audit_outcome(),
                        false,
                        Some(details),
                    )
                    .await?;
                let responses = playbooks_for(&ctx, &tx, &tenant_id, &recorded, &settings).await?;
                Ok((report, responses))
            })
            .await?;
        after_threat_responses(&ctx, &tenant_id, &responses).await?;
        Ok(Reply::json(report))
    }

    /// `threats/resolveIncident`: closes an incident as `true-positive`, `false-positive` or `benign`, optionally with
    /// a closing note. Its open detections become resolved; a false positive or benign finding also takes their points
    /// out of the identities' risk (not for risk raised against the caller, unless a root administrator resolves). A
    /// new detection about the same subject opens a new incident. Requires iam:threats:manage on
    /// iam/threats/incidents/{id} and recent authentication; audited as `threat:incident-resolve`.
    pub async fn resolve_incident(
        &self,
        credential: &CredentialInput,
        input: Body<threats::ResolveIncidentInput>,
    ) -> IamResult<Reply<threats::ResolveIncidentOutput>> {
        let incident_id = text(input.get("incidentId"), "incidentId", 256)?;
        let resolution = oneof(input.get("resolution"), &RESOLUTIONS, "resolution")?;
        let note = if input.contains_key("note") {
            Some(multiline(input.get("note"), "note", 4000)?)
        } else {
            None
        };
        let ctx = &self.ctx;
        let (incident_ref, resolution_ref, note_ref) = (&incident_id, &resolution, &note);
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let incidents = collection("incidents")?;
                    let detections_collection = collection("detections")?;
                    let incident = ctx
                        .scoped(
                            &tx,
                            &incidents,
                            Some(&Value::String(incident_ref.clone())),
                            &tenant.id,
                        )
                        .await?;
                    if str_of(&incident, "status") == "resolved" {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "The incident is already resolved",
                            409,
                        )
                        .into());
                    }
                    let own_id = str_of(&incident, "id").to_owned();
                    let detections = find(
                        &tx,
                        &detections_collection,
                        &tenant_filter(&tenant.id).eq("incidentId", own_id.clone()),
                    )
                    .await?;
                    let clears = resolution_ref != "true-positive";
                    let detected: Vec<Option<String>> = detections
                        .iter()
                        .map(|detection| {
                            detection
                                .get("identityId")
                                .and_then(Value::as_str)
                                .map(str::to_owned)
                        })
                        .collect();
                    if clears && clears_own_risk(ctx, &tx, &principal, detected).await? {
                        return Err(OperationDenied::new(Some(
                            "Incidents that raised your own risk are closed as false positives by another administrator",
                        )));
                    }
                    let now = ctx.now();
                    let mut changed = incident.clone();
                    changed.shift_remove("uniqueKey");
                    changed.insert("status".into(), Value::String("resolved".into()));
                    changed.insert("resolution".into(), Value::String(resolution_ref.clone()));
                    changed.insert(
                        "resolvedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    changed.insert("resolvedAt".into(), number(now));
                    changed.insert("updatedAt".into(), number(now));
                    let next = tx.put(&incidents, &changed).await?;
                    let mut resolved = 0usize;
                    for detection in &detections {
                        if str_of(detection, "status") == "open" {
                            let mut closed = detection.clone();
                            closed.insert("status".into(), Value::String("resolved".into()));
                            tx.put(&detections_collection, &closed).await?;
                            resolved += 1;
                        }
                    }
                    if clears {
                        let mut by_identity: indexmap::IndexMap<String, IndexSet<String>> =
                            indexmap::IndexMap::new();
                        for detection in &detections {
                            if let Some(identity_id) = given_str(detection, "identityId") {
                                by_identity
                                    .entry(identity_id)
                                    .or_default()
                                    .insert(str_of(detection, "id").to_owned());
                            }
                        }
                        let settings = resolve(stored_settings(&tx, &tenant.id).await?.as_ref())?;
                        for (identity_id, detection_ids) in &by_identity {
                            drop_contributions(
                                ctx,
                                &tx,
                                &tenant.id,
                                identity_id,
                                detection_ids,
                                &settings,
                                now,
                                &principal.identity.id,
                            )
                            .await?;
                        }
                    }
                    if let Some(note) = note_ref {
                        tx.insert(
                            &collection("notes")?,
                            &metadata(vec![
                                ("id", Value::String(id())),
                                ("tenantId", Value::String(tenant.id.clone())),
                                ("incidentId", Value::String(own_id.clone())),
                                ("authorId", Value::String(principal.identity.id.clone())),
                                ("body", Value::String(note.clone())),
                                ("createdAt", number(now)),
                            ]),
                        )
                        .await?;
                    }
                    let subject = incident.get("subject");
                    let mut details = metadata(vec![
                        ("resolution", Value::String(resolution_ref.clone())),
                        (
                            "severity",
                            incident.get("severity").cloned().unwrap_or(Value::Null),
                        ),
                        (
                            "subjectType",
                            subject
                                .and_then(|subject| subject.get("type"))
                                .cloned()
                                .unwrap_or(Value::Null),
                        ),
                        (
                            "subjectId",
                            subject
                                .and_then(|subject| subject.get("id"))
                                .cloned()
                                .unwrap_or(Value::Null),
                        ),
                        ("detectionsResolved", number(resolved as f64)),
                    ]);
                    if let Some(identity_id) = given_str(&incident, "identityId") {
                        details.insert("identityId".into(), Value::String(identity_id));
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "threat:incident-resolve",
                            &tenant.id,
                            &incident_resource(&own_id),
                            audit_outcome(),
                            false,
                            Some(details),
                        )
                        .await?;
                    Ok(with_subject_kind(&tx, &tenant.id, &next, &mut SubjectKinds::new()).await?)
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:manage",
                &incident_resource(&incident_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/respond`: responds by hand to an incident (its subject), an identity or a network: exactly one target,
    /// one to five actions (`revoke-sessions`, `forget-devices`, `contain`, `suspend-clearance`, `block-network` with
    /// `durationMs`, `notify`) run in order. A response to an identity or network with an open incident is filed under
    /// it. Actions that do not apply to the target, or that protections refuse, come back `skipped` with a reason.
    /// Requires iam:threats:respond on iam/threats/incidents/{id} (iam/threats/responses without an incident) and
    /// recent authentication; each action is audited as `threat:{action}`.
    pub async fn respond(
        &self,
        credential: &CredentialInput,
        input: Body<threats::RespondInput>,
    ) -> IamResult<Reply<threats::RespondOutput>> {
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let incident_id = if input.contains_key("incidentId") {
            Some(text(input.get("incidentId"), "incidentId", 256)?)
        } else {
            None
        };
        let identity_id = if input.contains_key("identityId") {
            Some(text(input.get("identityId"), "identityId", 256)?)
        } else {
            None
        };
        let network = if input.contains_key("network") {
            Some(trimmed(text(input.get("network"), "network", 64)?))
        } else {
            None
        };
        let targets = [
            incident_id.is_some(),
            identity_id.is_some(),
            network.is_some(),
        ]
        .iter()
        .filter(|given| **given)
        .count();
        if targets != 1 {
            return Err(invalid(
                "Respond to exactly one of incidentId, identityId or network",
            ));
        }
        if let Some(network) = &network
            && !is_ip_range(network)
        {
            return Err(invalid(
                "network must be an IPv4/IPv6 address or CIDR block",
            ));
        }
        let actions = response_actions_of(input.get("actions"), "actions")?;
        let resource = match &incident_id {
            Some(incident_id) => incident_resource(incident_id),
            None => "threats/responses".to_owned(),
        };
        let ctx = &self.ctx;
        let body: &Map<String, Value> = &input;
        let (incident_ref, identity_ref, network_ref, actions_ref) =
            (&incident_id, &identity_id, &network, &actions);
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let reason = trimmed(text(body.get("reason"), "reason", 512)?);
                    let settings = resolve(stored_settings(&tx, &tenant.id).await?.as_ref())?;
                    let incidents = collection("incidents")?;
                    let open_incident =
                        async |subject_type: &str, subject_id: &str| -> IamResult<Option<Record>> {
                            Ok(find(
                                &tx,
                                &incidents,
                                &tenant_filter(&tenant.id)
                                    .eq("uniqueKey", format!("open:{subject_type}:{subject_id}")),
                            )
                            .await?
                            .into_iter()
                            .next())
                        };
                    let mut target = Map::new();
                    if let Some(incident_id) = incident_ref {
                        let incident = ctx
                            .scoped(
                                &tx,
                                &incidents,
                                Some(&Value::String(incident_id.clone())),
                                &tenant.id,
                            )
                            .await?;
                        target.insert(
                            "subject".into(),
                            incident.get("subject").cloned().unwrap_or(Value::Null),
                        );
                        target.insert(
                            "incidentId".into(),
                            incident.get("id").cloned().unwrap_or(Value::Null),
                        );
                        if let Some(identity_id) = given_str(&incident, "identityId") {
                            target.insert("identityId".into(), Value::String(identity_id));
                        }
                        if let Some(network) = given_str(&incident, "network") {
                            target.insert("network".into(), Value::String(network));
                        }
                    } else if let Some(identity_id) = identity_ref {
                        let identity = ctx.active_identity(&tx, identity_id, &tenant.id).await?;
                        let subject = json!({
                            "type": "identity",
                            "id": identity.id,
                            "name": person_label(&identity),
                        });
                        let incident = open_incident("identity", &identity.id).await?;
                        target.insert("subject".into(), subject);
                        target.insert("identityId".into(), Value::String(identity.id.clone()));
                        if let Some(incident) = incident {
                            target.insert(
                                "incidentId".into(),
                                incident.get("id").cloned().unwrap_or(Value::Null),
                            );
                        }
                    } else {
                        let network = network_ref.clone().unwrap_or_default();
                        let incident = open_incident("network", &network).await?;
                        target.insert(
                            "subject".into(),
                            json!({ "type": "network", "id": network }),
                        );
                        target.insert("network".into(), Value::String(network));
                        if let Some(incident) = incident {
                            target.insert(
                                "incidentId".into(),
                                incident.get("id").cloned().unwrap_or(Value::Null),
                            );
                        }
                    }
                    let actor = actor_of(&principal)?;
                    let mut taken: Vec<Value> = Vec::new();
                    for action in actions_ref {
                        let mut request = Map::new();
                        request.insert("action".into(), action.clone());
                        for (key, value) in &target {
                            request.insert(key.clone(), value.clone());
                        }
                        request.insert("reason".into(), Value::String(reason.clone()));
                        request.insert("actor".into(), actor.clone());
                        taken.push(
                            apply_response(ctx, &tx, &tenant.id, Value::Object(request), &settings)
                                .await?,
                        );
                    }
                    Ok(Value::Array(taken))
                })
            },
        );
        let responses = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id.clone())),
                "iam:threats:respond",
                &resource,
                mutation,
                false,
            )
            .await?;
        after_threat_responses(ctx, &tenant_id, &responses_of(Some(&responses))).await?;
        Ok(Reply::json(responses))
    }

    /// `threats/rules`: every detection rule with its defaults and the setting in force for the tenant. Requires
    /// iam:threats:read on iam/threats/rules.
    pub async fn rules(
        &self,
        credential: &CredentialInput,
        input: Body<threats::RulesInput>,
    ) -> IamResult<Reply<threats::RulesOutput>> {
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let stored = stored_settings(&tx, &tenant.id).await?;
                let settings = resolve(stored.as_ref())?;
                Ok(Value::Array(
                    rule_catalog()?
                        .iter()
                        .map(|rule| rule_view(rule, &settings, stored.as_ref()))
                        .collect(),
                ))
            })
        });
        let result = self
            .ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:read",
                "threats/rules",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/setRisk`: sets an identity's risk by hand: `low`, `medium` or `high` sets a floor ("confirmed
    /// compromised") that holds until `expiresInMs` (one hour to 90 days) or indefinitely; `none` clears the override
    /// and every detection's contribution. Nobody sets their own risk. Requires iam:threats:respond on
    /// iam/threats/risk/{id} and recent authentication; audited as `threat:risk-override`, plus `threat:risk-change`
    /// when the effective level moves.
    pub async fn set_risk(
        &self,
        credential: &CredentialInput,
        input: Body<threats::SetRiskInput>,
    ) -> IamResult<Reply<threats::SetRiskOutput>> {
        let identity_id = text(input.get("identityId"), "identityId", 256)?;
        let level = oneof(input.get("level"), crate::threats::RISK_LEVELS, "level")?;
        let expires_in_ms = if input.contains_key("expiresInMs") {
            Some(integer(
                input.get("expiresInMs"),
                "expiresInMs",
                HOUR,
                90.0 * DAY,
            )?)
        } else {
            None
        };
        if level == "none" && expires_in_ms.is_some() {
            return Err(invalid("expiresInMs applies to a raised level only"));
        }
        let ctx = &self.ctx;
        let body: &Map<String, Value> = &input;
        let (identity_ref, level_ref) = (&identity_id, &level);
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let reason = trimmed(text(body.get("reason"), "reason", 512)?);
                    let identity = ctx
                        .scoped(
                            &tx,
                            "identities",
                            Some(&Value::String(identity_ref.clone())),
                            &tenant.id,
                        )
                        .await?;
                    let own_id = str_of(&identity, "id").to_owned();
                    if own_id == principal.identity.id {
                        return Err(OperationDenied::new(Some(
                            "Your own risk level is set by another administrator",
                        )));
                    }
                    let settings = resolve(stored_settings(&tx, &tenant.id).await?.as_ref())?;
                    let now = ctx.now();
                    let risk = collection("risk")?;
                    let record = risk_record(&tx, &tenant.id, &own_id).await?;
                    let mut cleared = 0usize;
                    let mut expires_at: Option<f64> = None;
                    if level_ref == "none" {
                        if let Some(record) = &record {
                            cleared = contributions_of(Some(record)).len();
                            let mut next = record.clone();
                            next.shift_remove("override");
                            next.insert("contributions".into(), json!([]));
                            tx.put(&risk, &next).await?;
                        }
                    } else {
                        expires_at = expires_in_ms.map(|expires_in_ms| now + expires_in_ms);
                        let mut override_ = metadata(vec![
                            ("level", Value::String(level_ref.clone())),
                            ("reason", Value::String(reason.clone())),
                            ("by", Value::String(principal.identity.id.clone())),
                            ("at", number(now)),
                        ]);
                        if let Some(expires_at) = expires_at {
                            override_.insert("expiresAt".into(), number(expires_at));
                        }
                        match &record {
                            Some(record) => {
                                let mut next = record.clone();
                                next.insert("override".into(), Value::Object(override_));
                                tx.put(&risk, &next).await?;
                            }
                            None => {
                                tx.insert(
                                    &risk,
                                    &metadata(vec![
                                        ("id", Value::String(own_id.clone())),
                                        ("tenantId", Value::String(tenant.id.clone())),
                                        ("identityId", Value::String(own_id.clone())),
                                        ("contributions", json!([])),
                                        ("score", number(0.0)),
                                        ("level", Value::String("none".into())),
                                        ("override", Value::Object(override_)),
                                        ("updatedAt", number(now)),
                                    ]),
                                )
                                .await?;
                            }
                        }
                    }
                    let mut details = metadata(vec![
                        ("level", Value::String(level_ref.clone())),
                        ("reason", Value::String(reason)),
                    ]);
                    if let Some(expires_at) = expires_at {
                        details.insert("expiresAt".into(), number(expires_at));
                    }
                    if level_ref == "none" {
                        details.insert("clearedContributions".into(), number(cleared as f64));
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "threat:risk-override",
                            &tenant.id,
                            &own_id,
                            audit_outcome(),
                            false,
                            Some(details),
                        )
                        .await?;
                    recompute_risk(
                        ctx,
                        &tx,
                        &tenant.id,
                        &own_id,
                        &settings,
                        now,
                        &principal.identity.id,
                        None,
                    )
                    .await?;
                    let record = risk_record(&tx, &tenant.id, &own_id).await?;
                    Ok(risk_view(&identity, record.as_ref(), &settings, now)?)
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:respond",
                &risk_resource(&identity_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/summary`: counts for a dashboard: open incidents by severity, incidents under investigation,
    /// identities by risk level, contained identities, detections in the last 24 hours by rule, and when detection
    /// last ran. Requires iam:threats:read on iam/threats/incidents.
    pub async fn summary(
        &self,
        credential: &CredentialInput,
        input: Body<threats::SummaryInput>,
    ) -> IamResult<Reply<threats::SummaryOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let now = ctx.now();
                let settings = resolve(stored_settings(&tx, &tenant.id).await?.as_ref())?;
                let half_life =
                    num_member(Some(&settings), "riskHalfLifeHours").unwrap_or(f64::NAN);
                let incidents = collection("incidents")?;
                let increment = |counts: &mut Map<String, Value>, key: &str| {
                    // `counts[key]++`: a key outside the record becomes NaN (null in JSON).
                    let next = match counts.get(key) {
                        Some(value) => core_js::as_number(value).map(|count| count + 1.0),
                        None => None,
                    };
                    counts.insert(key.to_owned(), next.map(number).unwrap_or(Value::Null));
                };
                let mut open_incidents = metadata(vec![
                    ("low", number(0.0)),
                    ("medium", number(0.0)),
                    ("high", number(0.0)),
                    ("critical", number(0.0)),
                ]);
                for incident in find(
                    &tx,
                    &incidents,
                    &tenant_filter(&tenant.id).eq("status", "open"),
                )
                .await?
                {
                    increment(
                        &mut open_incidents,
                        &crate::js::js_string(incident.get("severity")),
                    );
                }
                let investigating = find(
                    &tx,
                    &incidents,
                    &tenant_filter(&tenant.id).eq("status", "investigating"),
                )
                .await?
                .len();
                let mut risky_identities = metadata(vec![
                    ("low", number(0.0)),
                    ("medium", number(0.0)),
                    ("high", number(0.0)),
                ]);
                let mut contained = 0usize;
                for record in find(&tx, &collection("risk")?, &tenant_filter(&tenant.id)).await? {
                    let (_, level) = effective(Some(&record), now, half_life)?;
                    if level == "none" && !truthy(record.get("contained")) {
                        continue;
                    }
                    let identity = tx.get("identities", str_of(&record, "identityId")).await?;
                    let Some(identity) = identity.filter(|identity| {
                        str_of(identity, "tenantId") == tenant.id
                            && str_of(identity, "status") != "deleted"
                    }) else {
                        continue;
                    };
                    if level != "none" {
                        increment(&mut risky_identities, &level);
                    }
                    if containment(&identity, Some(&record)).is_some() {
                        contained += 1;
                    }
                }
                let mut detections24h = 0usize;
                let mut by_rule = Map::new();
                for detection in find_ordered(
                    tx.as_ref(),
                    &collection("detections")?,
                    &tenant_filter(&tenant.id),
                    &OrderOptions {
                        from: Some(now - DAY),
                        ..OrderOptions::by("detectedAt")
                    },
                    None,
                )
                .await?
                {
                    detections24h += 1;
                    let rule_id = crate::js::js_string(detection.get("ruleId"));
                    let count = by_rule
                        .get(&rule_id)
                        .and_then(core_js::as_number)
                        .unwrap_or(0.0);
                    by_rule.insert(rule_id, number(count + 1.0));
                }
                let mut summary = metadata(vec![
                    ("openIncidents", Value::Object(open_incidents)),
                    ("investigating", number(investigating as f64)),
                    ("riskyIdentities", Value::Object(risky_identities)),
                    ("contained", number(contained as f64)),
                    ("detections24h", number(detections24h as f64)),
                    ("byRule24h", Value::Object(by_rule)),
                ]);
                if let Some(cursor) = tx.get(&collection("cursors")?, &tenant.id).await?
                    && str_of(&cursor, "tenantId") == tenant.id
                    && let Some(updated_at) = cursor.get("updatedAt")
                {
                    summary.insert("lastRunAt".into(), updated_at.clone());
                }
                Ok(Value::Object(summary))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:read",
                "threats/incidents",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/timeline`: the identity's recent audit trail, newest first: events it performed and events about it,
    /// from `since` up to and including `until` (epoch milliseconds, after `since`; default now), where `since`
    /// defaults to seven days before `until`; at most `limit` (default 200, up to 500). Requires iam:threats:read on
    /// iam/threats/risk/{id}.
    pub async fn timeline(
        &self,
        credential: &CredentialInput,
        input: Body<threats::TimelineInput>,
    ) -> IamResult<Reply<threats::TimelineOutput>> {
        let identity_id = text(input.get("identityId"), "identityId", 256)?;
        let limit = integer(
            Some(&or_default(input.get("limit"), 200.0)),
            "limit",
            1.0,
            500.0,
        )?;
        let bound = |key: &str| -> IamResult<Option<f64>> {
            if input.contains_key(key) {
                Ok(Some(integer(
                    input.get(key),
                    key,
                    0.0,
                    crate::js::MAX_SAFE_INTEGER,
                )?))
            } else {
                Ok(None)
            }
        };
        let since = bound("since")?;
        let until = bound("until")?;
        if let (Some(since), Some(until)) = (since, until)
            && until <= since
        {
            return Err(invalid("until must be after since"));
        }
        let ctx = &self.ctx;
        let identity_ref = &identity_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let identity = ctx
                    .scoped(
                        &tx,
                        "identities",
                        Some(&Value::String(identity_ref.clone())),
                        &tenant.id,
                    )
                    .await?;
                let own_id = Value::String(str_of(&identity, "id").to_owned());
                let about = |event: &Record| {
                    ["actorId", "resourceId", "originalActorId"]
                        .iter()
                        .any(|key| event.get(*key) == Some(&own_id))
                };
                let events = find_ordered(
                    tx.as_ref(),
                    "audit",
                    &tenant_filter(&tenant.id),
                    &OrderOptions {
                        direction: Direction::Desc,
                        from: Some(since.unwrap_or_else(|| {
                            (until.unwrap_or_else(|| ctx.now()) - 7.0 * DAY).max(0.0)
                        })),
                        to: until,
                        limit: Some(limit as i64),
                        ..OrderOptions::by("timestamp")
                    },
                    Some(&about),
                )
                .await?;
                Ok(Value::Array(
                    events.into_iter().map(Value::Object).collect(),
                ))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:read",
                &risk_resource(&identity_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/updateIncident`: triage: moves an incident between `open` and `investigating`, assigns it to an active
    /// identity of the tenant (`null` unassigns), or changes its severity. Resolved incidents are closed to changes.
    /// Requires iam:threats:manage on iam/threats/incidents/{id}; audited as `threat:incident-update`.
    pub async fn update_incident(
        &self,
        credential: &CredentialInput,
        input: Body<threats::UpdateIncidentInput>,
    ) -> IamResult<Reply<threats::UpdateIncidentOutput>> {
        let incident_id = text(input.get("incidentId"), "incidentId", 256)?;
        let ctx = &self.ctx;
        let body: &Map<String, Value> = &input;
        let incident_ref = &incident_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    let incidents = collection("incidents")?;
                    let incident = ctx
                        .scoped(
                            &tx,
                            &incidents,
                            Some(&Value::String(incident_ref.clone())),
                            &tenant.id,
                        )
                        .await?;
                    if str_of(&incident, "status") == "resolved" {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "Resolved incidents cannot be changed",
                            409,
                        )
                        .into());
                    }
                    let status = if body.contains_key("status") {
                        Value::String(oneof(body.get("status"), &INCIDENT_STATUSES, "status")?)
                    } else {
                        incident.get("status").cloned().unwrap_or(Value::Null)
                    };
                    let severity = if body.contains_key("severity") {
                        Value::String(oneof(
                            body.get("severity"),
                            crate::threats::THREAT_SEVERITIES,
                            "severity",
                        )?)
                    } else {
                        incident.get("severity").cloned().unwrap_or(Value::Null)
                    };
                    let previous_assignee = incident.get("assigneeId").cloned();
                    let mut assignee_id = previous_assignee.clone();
                    match body.get("assigneeId") {
                        Some(Value::Null) => assignee_id = None,
                        Some(value) => {
                            let assignee = ctx
                                .active_identity(
                                    &tx,
                                    &text(Some(value), "assigneeId", 256)?,
                                    &tenant.id,
                                )
                                .await?;
                            if assignee.status != better_iam_core::IdentityStatus::Active {
                                return Err(
                                    invalid("Incidents are assigned to active identities").into()
                                );
                            }
                            assignee_id = Some(Value::String(assignee.id));
                        }
                        None => {}
                    }
                    let mut changes: Vec<&str> = Vec::new();
                    if Some(&status) != incident.get("status") {
                        changes.push("status");
                    }
                    if Some(&severity) != incident.get("severity") {
                        changes.push("severity");
                    }
                    if assignee_id != previous_assignee {
                        changes.push("assigneeId");
                    }
                    let mut changed = incident.clone();
                    changed.shift_remove("assigneeId");
                    changed.insert("status".into(), status.clone());
                    changed.insert("severity".into(), severity.clone());
                    if let Some(assignee_id) = &assignee_id {
                        changed.insert("assigneeId".into(), assignee_id.clone());
                    }
                    changed.insert("updatedAt".into(), number(ctx.now()));
                    let next = tx.put(&incidents, &changed).await?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "threat:incident-update",
                            &tenant.id,
                            &incident_resource(str_of(&incident, "id")),
                            audit_outcome(),
                            false,
                            Some(metadata(vec![
                                ("changes", json!(changes)),
                                ("status", status),
                                ("severity", severity),
                                ("assigneeId", assignee_id.unwrap_or(Value::Null)),
                            ])),
                        )
                        .await?;
                    Ok(with_subject_kind(&tx, &tenant.id, &next, &mut SubjectKinds::new()).await?)
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:manage",
                &incident_resource(&incident_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `threats/updatePlaybook`: changes a playbook; fields left out keep their value and `description: null` clears
    /// the description. Requires iam:threats:manage on iam/threats/playbooks/{id} and recent authentication; audited
    /// as `threat:playbook-update` with the settings before and after.
    pub async fn update_playbook(
        &self,
        credential: &CredentialInput,
        input: Body<threats::UpdatePlaybookInput>,
    ) -> IamResult<Reply<threats::UpdatePlaybookOutput>> {
        let playbook_id = text(input.get("playbookId"), "playbookId", 256)?;
        let ctx = &self.ctx;
        let body: &Map<String, Value> = &input;
        let playbook_ref = &playbook_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let playbooks = collection("playbooks")?;
                    let playbook = ctx
                        .scoped(
                            &tx,
                            &playbooks,
                            Some(&Value::String(playbook_ref.clone())),
                            &tenant.id,
                        )
                        .await?;
                    let own_id = str_of(&playbook, "id").to_owned();
                    let name = if body.contains_key("name") {
                        playbook_name(body.get("name"))?
                    } else {
                        str_of(&playbook, "name").to_owned()
                    };
                    let unique_key = format!("name:{}", core_js::to_lower(&name));
                    if find(
                        &tx,
                        &playbooks,
                        &tenant_filter(&tenant.id).eq("uniqueKey", unique_key.clone()),
                    )
                    .await?
                    .iter()
                    .any(|other| str_of(other, "id") != own_id)
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A playbook with this name exists",
                            409,
                        )
                        .into());
                    }
                    let description: Option<Value> = match body.get("description") {
                        None => playbook.get("description").cloned(),
                        Some(Value::Null) => None,
                        Some(value) => Some(Value::String(trimmed(text(
                            Some(value),
                            "description",
                            512,
                        )?))),
                    };
                    let enabled = if body.contains_key("enabled") {
                        Value::Bool(flag(body.get("enabled"), "enabled")?)
                    } else {
                        playbook.get("enabled").cloned().unwrap_or(Value::Null)
                    };
                    let trigger = if body.contains_key("trigger") {
                        playbook_trigger(body.get("trigger"))?
                    } else {
                        playbook.get("trigger").cloned().unwrap_or(Value::Null)
                    };
                    let actions = if body.contains_key("actions") {
                        Value::Array(response_actions_of(body.get("actions"), "actions")?)
                    } else {
                        playbook.get("actions").cloned().unwrap_or(Value::Null)
                    };
                    let mut changed = playbook.clone();
                    changed.shift_remove("description");
                    changed.insert("uniqueKey".into(), Value::String(unique_key));
                    changed.insert("name".into(), Value::String(name));
                    if let Some(description) =
                        description.filter(|description| truthy(Some(description)))
                    {
                        changed.insert("description".into(), description);
                    }
                    changed.insert("enabled".into(), enabled);
                    changed.insert("trigger".into(), trigger);
                    changed.insert("actions".into(), actions);
                    changed.insert("updatedAt".into(), number(ctx.now()));
                    changed.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let next = tx.put(&playbooks, &changed).await?;
                    // Widening what a playbook that suspends clearances does (adding the action, changing what triggers
                    // it, or switching it on) takes what writing one takes; renaming, describing or switching it off does
                    // not. A refusal rolls the change back.
                    let trigger_of = |record: &Record| {
                        record
                            .get("trigger")
                            .map(stringify)
                            .unwrap_or_else(|| "undefined".into())
                    };
                    if suspends_clearances(next.get("actions"))
                        && (!suspends_clearances(playbook.get("actions"))
                            || trigger_of(&next) != trigger_of(&playbook)
                            || (truthy(next.get("enabled")) && !truthy(playbook.get("enabled"))))
                    {
                        assert_may_suspend_clearances(ctx, &tx, &principal, &tenant.id).await?;
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "threat:playbook-update",
                            &tenant.id,
                            &playbook_resource(&own_id),
                            audit_outcome(),
                            false,
                            Some(metadata(vec![
                                ("before", Value::Object(playbook_metadata(&playbook))),
                                ("after", Value::Object(playbook_metadata(&next))),
                            ])),
                        )
                        .await?;
                    Ok(Value::Object(next))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:threats:manage",
                &playbook_resource(&playbook_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiline_normalizes_line_breaks_and_drops_controls() {
        let value = json!("line one\r\nline two\u{7}");
        assert_eq!(
            multiline(Some(&value), "note", 1000).unwrap(),
            "line one\nline two"
        );
        assert_eq!(
            multiline(Some(&json!("a\rb\n\nc\td")), "note", 1000).unwrap(),
            "a\nb\n\nc\td"
        );
        let blank = multiline(Some(&json!(" \u{1}\u{2} ")), "body", 10).unwrap_err();
        assert_eq!(blank.message, "body must be 1-10 characters");
        assert_eq!(
            multiline(Some(&json!(3)), "body", 10).unwrap_err().message,
            "Invalid body"
        );
        assert_eq!(
            multiline(Some(&json!("x".repeat(41))), "body", 10)
                .unwrap_err()
                .message,
            "Invalid body"
        );
        assert_eq!(
            multiline(Some(&json!("x".repeat(11))), "body", 10)
                .unwrap_err()
                .message,
            "body must be 1-10 characters"
        );
    }

    #[test]
    fn too_wide_networks() {
        assert!(too_wide("0.0.0.0/0"));
        assert!(too_wide("10.0.0.0/7"));
        assert!(!too_wide("10.0.0.0/8"));
        assert!(!too_wide("198.51.100.7"));
        assert!(too_wide("::ffff:0:0/96"));
        assert!(!too_wide("::ffff:10.0.0.0/104"));
        assert!(too_wide("2001:db8::/31"));
        assert!(!too_wide("2001:db8::/32"));
    }

    #[test]
    fn trusted_networks_validation() {
        assert_eq!(
            trusted_networks_of(Some(&json!([" 10.0.0.0/8 ", "10.0.0.0/8"]))).unwrap(),
            vec!["10.0.0.0/8".to_owned()]
        );
        for bad in [
            json!(["0.0.0.0/0"]),
            json!(["::ffff:0:0/96"]),
            json!(["not an ip"]),
            json!("10.0.0.0/8"),
        ] {
            assert_eq!(
                trusted_networks_of(Some(&bad)).unwrap_err().code,
                "INVALID_INPUT"
            );
        }
    }

    #[test]
    fn listed_in_words() {
        let items = |list: &[&str]| list.iter().map(|item| item.to_string()).collect::<Vec<_>>();
        assert_eq!(listed(&items(&[]), 3), "");
        assert_eq!(listed(&items(&["a"]), 3), "a");
        assert_eq!(listed(&items(&["a", "b"]), 3), "a and b");
        assert_eq!(listed(&items(&["a", "b", "c"]), 3), "a, b and c");
        assert_eq!(
            listed(&items(&["a", "b", "c", "d", "e"]), 3),
            "a, b, c and 2 more"
        );
    }

    #[test]
    fn canonical_ignores_key_order() {
        assert_eq!(
            canonical(Some(&json!({ "owners": true, "emails": ["a@b.c"] }))),
            canonical(Some(&json!({ "emails": ["a@b.c"], "owners": true })))
        );
        assert_ne!(
            canonical(Some(&json!({ "owners": true }))),
            canonical(Some(&json!({ "owners": false })))
        );
        assert_eq!(canonical(Some(&json!(90.0))), canonical(Some(&json!(90))));
    }

    #[test]
    fn notify_validation() {
        let current = json!({ "owners": false, "emails": ["x@acme.test"] });
        assert_eq!(
            notify_of(Some(&json!({ "owners": true })), Some(&current)).unwrap(),
            json!({ "owners": true, "emails": ["x@acme.test"] })
        );
        assert_eq!(
            notify_of(
                Some(&json!({ "emails": ["A@Acme.test", "a@acme.test"] })),
                Some(&current)
            )
            .unwrap(),
            json!({ "owners": false, "emails": ["a@acme.test"] })
        );
        assert_eq!(
            notify_of(Some(&json!({ "emails": ["nope"] })), Some(&current))
                .unwrap_err()
                .code,
            "INVALID_INPUT"
        );
        assert_eq!(
            notify_of(Some(&json!({ "colour": 1 })), Some(&current))
                .unwrap_err()
                .message,
            "Unknown notify setting colour"
        );
    }

    #[test]
    fn response_action_validation() {
        assert_eq!(
            response_actions_of(
                Some(&json!([{ "kind": "block-network", "durationMs": 60_000 }, { "kind": "notify" }])),
                "actions"
            )
            .unwrap(),
            vec![
                json!({ "kind": "block-network", "durationMs": 60_000 }),
                json!({ "kind": "notify" })
            ]
        );
        for (bad, message) in [
            (json!([]), "actions must list 1-5 response actions"),
            (
                json!([{ "kind": "notify" }, { "kind": "notify" }]),
                "actions may list each kind of action once",
            ),
            (
                json!([{ "kind": "notify", "durationMs": 60_000 }]),
                "durationMs applies to block-network only",
            ),
            (
                json!([{ "kind": "contain", "keepApiKeys": true }]),
                "keepApiKeys applies to revoke-sessions only",
            ),
            (
                json!([{ "kind": "notify", "extra": 1 }]),
                "Unknown response action field extra",
            ),
            (
                json!([{ "kind": "explode" }]),
                "actions kind must be one of revoke-sessions, forget-devices, contain, suspend-clearance, block-network, notify",
            ),
        ] {
            assert_eq!(
                response_actions_of(Some(&bad), "actions")
                    .unwrap_err()
                    .message,
                message
            );
        }
    }

    #[test]
    fn incident_status_lists() {
        assert_eq!(
            incident_statuses_of(Some(&json!(["open", "open"]))).unwrap(),
            vec!["open".to_owned()]
        );
        assert_eq!(
            incident_statuses_of(Some(&json!("resolved"))).unwrap(),
            vec!["resolved".to_owned()]
        );
        for bad in [
            json!([]),
            json!(["open", "closed"]),
            json!("closed"),
            json!(3),
            json!(["open", "investigating", "resolved", "open"]),
        ] {
            assert_eq!(
                incident_statuses_of(Some(&bad)).unwrap_err().code,
                "INVALID_INPUT"
            );
        }
    }

    #[test]
    fn rule_signatures_compare_effective_values() {
        let a = json!({ "enabled": true, "severity": "high", "threshold": 10.0 });
        let b = json!({ "severity": "high", "enabled": true, "threshold": 10, "everyone": false });
        assert_eq!(rule_signature(Some(&a)), rule_signature(Some(&b)));
        let c = json!({ "enabled": true, "severity": "high", "threshold": 10, "everyone": true });
        assert_ne!(rule_signature(Some(&a)), rule_signature(Some(&c)));
    }
}
