//! Port of `packages/server/src/quotas.ts`.
//!
//! API usage plans and quotas (like AWS API Gateway usage plans): a plan throttles a meter (a token bucket of
//! `ratePerSecond` with room for `burst`) and caps it per minute, hour, day, week or month. Plans apply to API keys,
//! agents, people and groups, or to everyone in the tenant by default; `iam.quotas.consume` counts use and refuses
//! what a plan does not allow, with the time to retry. Counters live in the database, so every server instance sees
//! the same totals.

use std::sync::{Arc, LazyLock};

use better_iam_core::{Filter, FindOptions, IamError, IamResult, Record, SessionKind};
use futures::future::BoxFuture;
use indexmap::{IndexMap, IndexSet};
use jiff::Timestamp;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::js::{ThrownError, invalid_input, number, number_to_string};
use crate::port::{ErrorDetails, decode, with_details};
use crate::validation::{integer, object, text};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuotaAssignment {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// `{meter}:{subjectType}:{subjectId}`: one plan per meter for each subject.
    #[serde(rename = "uniqueKey")]
    pub unique_key: String,
    #[serde(rename = "planId")]
    pub plan_id: String,
    #[serde(rename = "meter")]
    pub meter: String,
    #[serde(rename = "subjectType")]
    pub subject_type: crate::quotas::QuotaSubjectType,
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "id")]
    pub id: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuotaCounter {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "kind")]
    pub kind: String,
    #[serde(rename = "planId")]
    pub plan_id: String,
    #[serde(rename = "subjectKey")]
    pub subject_key: String,
    /// Windows: the period and its bounds.
    #[serde(rename = "period", default, skip_serializing_if = "Option::is_none")]
    pub period: Option<String>,
    #[serde(
        rename = "windowStart",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub window_start: Option<f64>,
    #[serde(rename = "windowEnd", default, skip_serializing_if = "Option::is_none")]
    pub window_end: Option<f64>,
    #[serde(rename = "used", default, skip_serializing_if = "Option::is_none")]
    pub used: Option<f64>,
    /// Thresholds already recorded in this window, and when the window was first exceeded.
    #[serde(rename = "alerted", default, skip_serializing_if = "Option::is_none")]
    pub alerted: Option<Vec<f64>>,
    #[serde(
        rename = "exceededAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub exceeded_at: Option<f64>,
    /// Buckets: tokens left at `updatedAt`.
    #[serde(rename = "tokens", default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<f64>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<f64>,
    /// When the retention sweep may delete the record.
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    #[serde(rename = "id")]
    pub id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuotaDecision {
    #[serde(rename = "allowed")]
    pub allowed: bool,
    #[serde(rename = "meter")]
    pub meter: String,
    /// The plan that decided, or null when none applies (use is unlimited).
    #[serde(rename = "plan", default)]
    pub plan: Option<String>,
    #[serde(rename = "via", default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(rename = "cost")]
    pub cost: f64,
    #[serde(rename = "limits")]
    pub limits: Vec<crate::quotas::QuotaLimitStatus>,
    /// Tokens left in the throttle's bucket after this call.
    #[serde(rename = "throttle", default, skip_serializing_if = "Option::is_none")]
    pub throttle: Option<Value>,
    /// Why a refusal happened: `throttle`, or the period whose limit is spent.
    #[serde(rename = "reason", default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When a refused call may succeed.
    #[serde(
        rename = "retryAfterMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub retry_after_ms: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl QuotaDecision {
    /// The decision as the TypeScript object, in its member order and with JavaScript numbers.
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("allowed".into(), Value::Bool(self.allowed));
        out.insert("meter".into(), Value::String(self.meter.clone()));
        out.insert(
            "plan".into(),
            self.plan.clone().map(Value::String).unwrap_or(Value::Null),
        );
        if let Some(via) = &self.via {
            out.insert("via".into(), Value::String(via.clone()));
        }
        out.insert("cost".into(), number(self.cost));
        out.insert(
            "limits".into(),
            Value::Array(self.limits.iter().map(QuotaLimitStatus::to_json).collect()),
        );
        if let Some(throttle) = &self.throttle {
            out.insert("throttle".into(), throttle.clone());
        }
        if let Some(reason) = &self.reason {
            out.insert("reason".into(), Value::String(reason.clone()));
        }
        if let Some(retry) = self.retry_after_ms {
            out.insert("retryAfterMs".into(), number(retry));
        }
        for (key, value) in &self.extra {
            out.insert(key.clone(), value.clone());
        }
        Value::Object(out)
    }
}

/// The error `enforce` throws: 429 with the time to retry (`Retry-After` over HTTP).
#[derive(Debug, Clone, PartialEq)]
pub struct QuotaExceededError {
    pub error: IamError,
    pub decision: QuotaDecision,
    pub retry_after_ms: Option<f64>,
}

impl QuotaExceededError {
    /// `new QuotaExceededError(decision, retryAfterMs)`.
    pub fn new(decision: &crate::quotas::QuotaDecision, retry_after_ms: Option<f64>) -> Self {
        let meter = &decision.meter;
        let message = if decision.reason.as_deref() == Some("throttle") {
            format!("Too many {meter} requests; slow down")
        } else {
            format!(
                "The {} {meter} quota of plan {} is used up",
                decision.reason.as_deref().unwrap_or("undefined"),
                decision.plan.as_deref().unwrap_or("null"),
            )
        };
        let error = with_details(
            IamError::with_status("QUOTA_EXCEEDED", message, 429),
            ErrorDetails {
                retry_after_ms,
                ..ErrorDetails::default()
            },
        );
        Self {
            error,
            decision: decision.clone(),
            retry_after_ms,
        }
    }
}

impl From<QuotaExceededError> for IamError {
    fn from(error: QuotaExceededError) -> Self {
        error.error
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuotaLimit {
    #[serde(rename = "period")]
    pub period: String,
    /// Units of the meter a subject may use per period window.
    #[serde(rename = "limit")]
    pub limit: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl QuotaLimit {
    /// `{ period, limit }`.
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("period".into(), Value::String(self.period.clone()));
        out.insert("limit".into(), number(self.limit));
        for (key, value) in &self.extra {
            out.insert(key.clone(), value.clone());
        }
        Value::Object(out)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuotaLimitStatus {
    #[serde(rename = "period")]
    pub period: String,
    #[serde(rename = "limit")]
    pub limit: f64,
    #[serde(rename = "used")]
    pub used: f64,
    #[serde(rename = "remaining")]
    pub remaining: f64,
    /// When the window ends and the count starts over.
    #[serde(rename = "resetAt")]
    pub reset_at: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl QuotaLimitStatus {
    /// `{ period, limit, used, remaining, resetAt }`.
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("period".into(), Value::String(self.period.clone()));
        out.insert("limit".into(), number(self.limit));
        out.insert("used".into(), number(self.used));
        out.insert("remaining".into(), number(self.remaining));
        out.insert("resetAt".into(), number(self.reset_at));
        for (key, value) in &self.extra {
            out.insert(key.clone(), value.clone());
        }
        Value::Object(out)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuotaPlan {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "uniqueKey")]
    pub unique_key: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    /// What the plan counts: the meter `consume` names (`requests`, `exports`, `tokens`...).
    #[serde(rename = "meter")]
    pub meter: String,
    #[serde(rename = "throttle", default, skip_serializing_if = "Option::is_none")]
    pub throttle: Option<crate::quotas::QuotaThrottle>,
    #[serde(rename = "limits")]
    pub limits: Vec<crate::quotas::QuotaLimit>,
    /// `subject`: each API key, agent or person has its own counters; `tenant`: everyone the plan covers shares one.
    #[serde(rename = "scope")]
    pub scope: String,
    /// The plan for everyone in the tenant without a plan of their own for the meter.
    #[serde(rename = "default")]
    pub default: bool,
    /// Among several group plans for the same meter, the highest priority applies.
    #[serde(rename = "priority")]
    pub priority: f64,
    /// Day, week and month windows start at midnight (Monday, the 1st) in this IANA time zone.
    #[serde(rename = "timeZone")]
    pub time_zone: String,
    /// Percentages of a period limit that record `quota:threshold` once per window.
    #[serde(rename = "alertThresholds")]
    pub alert_thresholds: Vec<f64>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "updatedBy")]
    pub updated_by: String,
    #[serde(rename = "id")]
    pub id: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `QuotaSubjectType`: `apiKey`, `identity` or `group`.
pub type QuotaSubjectType = String;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuotaThrottle {
    /// Tokens added per second.
    #[serde(rename = "ratePerSecond")]
    pub rate_per_second: f64,
    /// The most tokens the bucket holds: the largest burst after a quiet spell.
    #[serde(rename = "burst")]
    pub burst: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl QuotaThrottle {
    /// `{ ratePerSecond, burst }` (and any member the stored object carries).
    pub fn to_json(&self) -> Map<String, Value> {
        let mut out = Map::new();
        out.insert("ratePerSecond".into(), number(self.rate_per_second));
        out.insert("burst".into(), number(self.burst));
        for (key, value) in &self.extra {
            out.insert(key.clone(), value.clone());
        }
        out
    }
}

/// `quotaCollections.plans`.
pub const QUOTA_PLANS: &str = "quotaPlans";
/// `quotaCollections.assignments`.
pub const QUOTA_ASSIGNMENTS: &str = "quotaAssignments";
/// `quotaCollections.counters`.
pub const QUOTA_COUNTERS: &str = "quotaCounters";

/// `quotaPeriods`.
pub const QUOTA_PERIODS: [&str; 5] = ["minute", "hour", "day", "week", "month"];

// --- validation ----------------------------------------------------------------------------------

static NAME_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9._-]{0,63}$").expect("name pattern"));

fn period_index(period: &str) -> usize {
    QUOTA_PERIODS
        .iter()
        .position(|candidate| *candidate == period)
        .unwrap_or(usize::MAX)
}

pub fn alert_thresholds(value: Option<&Value>) -> IamResult<Vec<f64>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Value::Array(items) = value else {
        return Err(invalid_input("alertThresholds lists at most 5 percentages"));
    };
    if items.len() > 5 {
        return Err(invalid_input("alertThresholds lists at most 5 percentages"));
    }
    let mut seen: Vec<f64> = Vec::new();
    for item in items {
        let threshold = integer(Some(item), "alert threshold", 1.0, 100.0)?;
        if !seen.contains(&threshold) {
            seen.push(threshold);
        }
    }
    seen.sort_by(|a, b| a.total_cmp(b));
    Ok(seen)
}

/// API usage plans and quotas (like AWS API Gateway usage plans): a plan throttles a meter (a token bucket of
/// `ratePerSecond` with room for `burst`) and caps it per minute, hour, day, week or month. Plans apply to API
/// keys, agents, people and groups, or to everyone in the tenant by default; `iam.quotas.consume` counts use and
/// refuses what a plan does not allow, with the time to retry. Counters live in the database, so every server
/// instance sees the same totals.
pub static QUOTA_COLLECTIONS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
    || json!({"plans":"quotaPlans","assignments":"quotaAssignments","counters":"quotaCounters"}),
);

pub fn quota_limits(value: Option<&Value>) -> IamResult<Vec<crate::quotas::QuotaLimit>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let items = match value {
        Value::Array(items) if items.len() <= QUOTA_PERIODS.len() => items,
        _ => {
            return Err(invalid_input(
                "limits must list at most one limit per period",
            ));
        }
    };
    let mut seen: IndexSet<String> = IndexSet::new();
    let mut limits = Vec::new();
    for item in items {
        let entry = object(Some(item))?;
        let period = match entry.get("period") {
            Some(Value::String(period)) if QUOTA_PERIODS.contains(&period.as_str()) => {
                period.clone()
            }
            _ => {
                return Err(invalid_input(
                    "period must be minute, hour, day, week or month",
                ));
            }
        };
        if seen.contains(&period) {
            return Err(invalid_input(format!("Only one {period} limit per plan")));
        }
        seen.insert(period.clone());
        let limit = integer(
            entry.get("limit"),
            &format!("{period} limit"),
            1.0,
            1_000_000_000_000.0,
        )?;
        limits.push(QuotaLimit {
            period,
            limit,
            extra: Map::new(),
        });
    }
    limits.sort_by_key(|limit| period_index(&limit.period));
    Ok(limits)
}

pub fn quota_name(value: Option<&Value>, name: Option<&str>) -> IamResult<String> {
    let name = name.unwrap_or("name");
    let result = text(value, name, 64)?;
    if !NAME_PATTERN.is_match(&result) {
        return Err(invalid_input(format!(
            "{name} must be 1-64 lowercase letters, digits and ._- starting with a letter or digit"
        )));
    }
    Ok(result)
}

pub fn quota_throttle(value: Option<&Value>) -> IamResult<Option<crate::quotas::QuotaThrottle>> {
    let value = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(value) => value,
    };
    let input = object(Some(value))?;
    let rate = match input.get("ratePerSecond").and_then(crate::js::as_number) {
        Some(rate) if rate.is_finite() && (0.001..=1_000_000.0).contains(&rate) => rate,
        _ => {
            return Err(invalid_input(
                "throttle.ratePerSecond must be 0.001 to 1000000",
            ));
        }
    };
    let burst = match input.get("burst") {
        None => rate.ceil().max(1.0),
        Some(burst) => integer(Some(burst), "throttle.burst", 1.0, 1_000_000_000.0)?,
    };
    Ok(Some(QuotaThrottle {
        rate_per_second: rate,
        burst,
        extra: Map::new(),
    }))
}

pub fn time_zone(value: Option<&Value>) -> IamResult<String> {
    if value.is_none() {
        return Ok("UTC".into());
    }
    let zone = text(value, "timeZone", 64)?;
    if !crate::timezones::is_valid_time_zone(&zone) {
        return Err(invalid_input("Unknown timeZone"));
    }
    Ok(zone)
}

// --- windows -------------------------------------------------------------------------------------

const MINUTE: f64 = 60_000.0;
const HOUR: f64 = 60.0 * MINUTE;
const DAY: f64 = 24.0 * HOUR;

/// A window of a period: `{ start, end }` in epoch milliseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QuotaWindow {
    pub start: f64,
    pub end: f64,
}

/// The wall-clock parts of an instant in a time zone.
struct Zoned {
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
    weekday: i64,
}

fn range_error() -> ThrownError {
    ThrownError::new("RangeError", "Invalid time value")
}

/// `zoned(at, zone)`: what `Intl.DateTimeFormat(...).formatToParts(new Date(at))` reports.
fn zoned(at: f64, zone: &str) -> Result<Zoned, ThrownError> {
    let zone = crate::timezones::load_time_zone(zone)?;
    if !at.is_finite() || at.abs() > 8.64e15 {
        return Err(range_error());
    }
    let local = Timestamp::from_millisecond(at.trunc() as i64)
        .map_err(|_| range_error())?
        .to_zoned(zone);
    Ok(Zoned {
        year: i64::from(local.year()),
        month: i64::from(local.month()),
        day: i64::from(local.day()),
        hour: i64::from(local.hour()) % 24,
        minute: i64::from(local.minute()),
        second: i64::from(local.second()),
        weekday: i64::from(local.weekday().to_sunday_zero_offset()),
    })
}

/// `Date.UTC(year, month, day, hour, minute, second)` with JavaScript's overflow of months and days.
fn date_utc(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> f64 {
    let year = year + month.div_euclid(12);
    let month = month.rem_euclid(12);
    let days = better_iam_core::js::days_from_civil(year, month + 1, 1) + day - 1;
    (days * 86_400_000 + hour * 3_600_000 + minute * 60_000 + second * 1000) as f64
}

/// `new Date(Date.UTC(year, month, day))` read back as UTC year, month (1-12) and day.
fn utc_date(year: i64, month: i64, day: i64) -> (i64, i64, i64) {
    let ms = date_utc(year, month, day, 0, 0, 0) as i64;
    better_iam_core::js::civil_from_days(ms.div_euclid(86_400_000))
}

/// The instant a local date's midnight falls on in a time zone (the first instant of that local day).
fn local_midnight(year: i64, month: i64, day: i64, zone: &str) -> Result<f64, ThrownError> {
    let mut guess = date_utc(year, month - 1, day, 0, 0, 0);
    // Two corrections settle the zone offset, including on days a daylight-saving change shifts it.
    for _ in 0..2 {
        let parts = zoned(guess, zone)?;
        let shown = date_utc(
            parts.year,
            parts.month - 1,
            parts.day,
            parts.hour,
            parts.minute,
            parts.second,
        );
        guess -= shown - date_utc(year, month - 1, day, 0, 0, 0);
    }
    Ok(guess)
}

/// The window of a period that contains `at`: minutes and hours in UTC, days, ISO weeks and months in `zone`.
pub fn quota_window(period: &str, at: f64, zone: &str) -> IamResult<QuotaWindow> {
    window(period, at, zone).map_err(IamError::from)
}

fn window(period: &str, at: f64, zone: &str) -> Result<QuotaWindow, ThrownError> {
    if period == "minute" {
        let start = (at / MINUTE).floor() * MINUTE;
        return Ok(QuotaWindow {
            start,
            end: start + MINUTE,
        });
    }
    if period == "hour" {
        let start = (at / HOUR).floor() * HOUR;
        return Ok(QuotaWindow {
            start,
            end: start + HOUR,
        });
    }
    let local = zoned(at, zone)?;
    if period == "day" {
        let start = local_midnight(local.year, local.month, local.day, zone)?;
        let (year, month, day) = utc_date(local.year, local.month - 1, local.day + 1);
        return Ok(QuotaWindow {
            start,
            end: local_midnight(year, month, day, zone)?,
        });
    }
    if period == "week" {
        let back = (local.weekday + 6) % 7; // days since Monday
        let monday = utc_date(local.year, local.month - 1, local.day - back);
        let following = utc_date(local.year, local.month - 1, local.day - back + 7);
        return Ok(QuotaWindow {
            start: local_midnight(monday.0, monday.1, monday.2, zone)?,
            end: local_midnight(following.0, following.1, following.2, zone)?,
        });
    }
    let next_month = utc_date(local.year, local.month, 1);
    Ok(QuotaWindow {
        start: local_midnight(local.year, local.month, 1, zone)?,
        end: local_midnight(next_month.0, next_month.1, 1, zone)?,
    })
}

// --- resolution ----------------------------------------------------------------------------------

/// Who a consumption counts against, and the plan that applies.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct QuotaSubject {
    pub tenant_id: String,
    pub identity_id: String,
    /// The API key the request used, when it used one.
    pub api_key_id: Option<String>,
    /// The agent acting in a delegated session.
    pub agent_id: Option<String>,
}

/// The plan for a subject and meter.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedPlan {
    pub plan: QuotaPlan,
    /// How the plan applies: through the API key, the agent, the identity, a group, or the tenant default.
    pub via: String,
    /// The counters' key: the subject that uses them.
    pub subject_key: String,
}

/// The subject of a principal: its API key (for an API-key session), the agent of a delegated session, the
/// identity.
pub fn subject_of(principal: &better_iam_core::AuthenticatedPrincipal) -> QuotaSubject {
    let session = &principal.session;
    QuotaSubject {
        tenant_id: session.tenant_id.clone(),
        identity_id: principal.identity.id.clone(),
        api_key_id: (session.kind == SessionKind::ApiKey).then(|| session.id.clone()),
        agent_id: session.agent_id.clone().filter(|agent| !agent.is_empty()),
    }
}

fn by_name(a: &QuotaPlan, b: &QuotaPlan) -> std::cmp::Ordering {
    crate::js::cmp_utf16(&a.name, &b.name)
}

/// The plan for a subject and meter, most specific first: an assignment to the API key, to the acting agent, to the
/// identity, to one of its groups (the highest priority, then the name), else the tenant's default plan for the
/// meter.
pub async fn resolve_plan(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    subject: &QuotaSubject,
    meter: &str,
) -> IamResult<Option<ResolvedPlan>> {
    let mut plans: IndexMap<String, QuotaPlan> = IndexMap::new();
    let mut assigned =
        async |subject_type: &str, subject_id: &str| -> IamResult<Option<QuotaPlan>> {
            let found = tx
                .find(
                    QUOTA_ASSIGNMENTS,
                    &Filter::new()
                        .eq("tenantId", subject.tenant_id.clone())
                        .eq("uniqueKey", format!("{meter}:{subject_type}:{subject_id}")),
                    &FindOptions::default(),
                )
                .await?
                .into_iter()
                .next();
            let Some(found) = found else {
                return Ok(None);
            };
            let assignment: QuotaAssignment = decode(found)?;
            let plan_id = assignment.plan_id;
            if !plans.contains_key(&plan_id)
                && let Some(record) = tx.get(QUOTA_PLANS, &plan_id).await?
            {
                let plan: QuotaPlan = decode(record)?;
                if plan.tenant_id == subject.tenant_id {
                    plans.insert(plan_id.clone(), plan);
                }
            }
            Ok(plans.get(&plan_id).cloned())
        };
    let key_of = |plan: &QuotaPlan, own: String| {
        if plan.scope == "tenant" {
            "tenant".to_owned()
        } else {
            own
        }
    };
    let resolved = |plan: QuotaPlan, via: &str, own: String| {
        let subject_key = key_of(&plan, own);
        Some(ResolvedPlan {
            plan,
            via: via.to_owned(),
            subject_key,
        })
    };
    if let Some(api_key_id) = subject.api_key_id.as_deref().filter(|id| !id.is_empty())
        && let Some(plan) = assigned("apiKey", api_key_id).await?
    {
        return Ok(resolved(plan, "apiKey", format!("key:{api_key_id}")));
    }
    if let Some(agent_id) = subject.agent_id.as_deref().filter(|id| !id.is_empty())
        && let Some(plan) = assigned("identity", agent_id).await?
    {
        return Ok(resolved(plan, "agent", format!("identity:{agent_id}")));
    }
    if let Some(own) = assigned("identity", &subject.identity_id).await? {
        return Ok(resolved(
            own,
            "identity",
            format!("identity:{}", subject.identity_id),
        ));
    }
    let sources = ctx
        .decisions()?
        .grant_sources(tx, &subject.identity_id, &subject.tenant_id)
        .await?;
    let mut candidates: Vec<QuotaPlan> = Vec::new();
    for group_id in &sources.group_ids {
        if let Some(plan) = assigned("group", group_id).await? {
            candidates.push(plan);
        }
    }
    candidates.sort_by(|a, b| {
        let by_priority = b.priority - a.priority;
        if by_priority != 0.0 && !by_priority.is_nan() {
            return by_priority.total_cmp(&0.0);
        }
        by_name(a, b)
    });
    if let Some(first) = candidates.into_iter().next() {
        return Ok(resolved(
            first,
            "group",
            format!("identity:{}", subject.identity_id),
        ));
    }
    let mut defaults: Vec<QuotaPlan> = tx
        .find(
            QUOTA_PLANS,
            &Filter::new()
                .eq("tenantId", subject.tenant_id.clone())
                .eq("meter", meter.to_owned())
                .eq("default", true),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .map(decode)
        .collect::<IamResult<_>>()?;
    // `(a, b) => (a.name < b.name ? -1 : 1)`.
    defaults.sort_by(|a, b| {
        if by_name(a, b) == std::cmp::Ordering::Less {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });
    Ok(defaults.into_iter().next().and_then(|fallback| {
        resolved(
            fallback,
            "default",
            format!("identity:{}", subject.identity_id),
        )
    }))
}

// --- consumption ---------------------------------------------------------------------------------

fn counter_id(plan_id: &str, subject_key: &str, suffix: &str) -> String {
    format!("quota:{plan_id}:{subject_key}:{suffix}")
}

/// What an audit event of the quota machinery records: `(tx, action, metadata)`.
pub type QuotaRecorder<'a> = dyn Fn(Store, &'static str, Map<String, Value>) -> BoxFuture<'a, IamResult<()>>
    + Send
    + Sync
    + 'a;

/// A window of a period limit with its counter record, if any.
struct LimitWindow {
    limit: QuotaLimit,
    window: QuotaWindow,
    record: Option<Record>,
    counter: Option<QuotaCounter>,
}

/// `{ ...plan.throttle, tokens }`.
fn throttle_status(throttle: &QuotaThrottle, tokens: f64) -> Value {
    let mut out = throttle.to_json();
    out.insert("tokens".into(), number(tokens));
    Value::Object(out)
}

/// Counts `cost` units of `meter` for a subject inside the caller's transaction, or refuses without counting
/// anything when the throttle or a period limit would be exceeded. `dryRun` reports the status without counting.
pub async fn consume_quota(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    subject: &QuotaSubject,
    meter: &str,
    cost: f64,
    record: &QuotaRecorder<'_>,
    dry_run: bool,
) -> IamResult<crate::quotas::QuotaDecision> {
    let Some(resolved) = resolve_plan(ctx, tx, subject, meter).await? else {
        return Ok(QuotaDecision {
            allowed: true,
            meter: meter.to_owned(),
            plan: None,
            via: None,
            cost,
            limits: Vec::new(),
            throttle: None,
            reason: None,
            retry_after_ms: None,
            extra: Map::new(),
        });
    };
    let plan = &resolved.plan;
    let subject_key = resolved.subject_key.as_str();
    let now = ctx.now();
    let mut reason: Option<String> = None;
    let mut retry_after_ms: Option<f64> = None;
    // The throttle: a token bucket refilled continuously.
    let mut bucket: Option<Record> = None;
    let mut tokens = 0.0;
    if let Some(throttle) = &plan.throttle {
        bucket = tx
            .get(QUOTA_COUNTERS, &counter_id(&plan.id, subject_key, "bucket"))
            .await?;
        let counter: Option<QuotaCounter> = bucket.clone().map(decode).transpose()?;
        let elapsed = match counter.as_ref().and_then(|counter| counter.updated_at) {
            None => f64::INFINITY,
            Some(updated_at) => (now - updated_at).max(0.0),
        };
        tokens = throttle.burst.min(
            counter
                .as_ref()
                .and_then(|counter| counter.tokens)
                .unwrap_or(throttle.burst)
                + (elapsed / 1000.0) * throttle.rate_per_second,
        );
        if tokens < cost && !dry_run {
            reason = Some("throttle".into());
            retry_after_ms = if cost > throttle.burst {
                None
            } else {
                Some((((cost - tokens) / throttle.rate_per_second) * 1000.0).ceil())
            };
        }
    }
    // Period limits: fixed windows.
    let mut windows: Vec<LimitWindow> = Vec::new();
    for limit in &plan.limits {
        let window = quota_window(&limit.period, now, &plan.time_zone)?;
        let record = tx
            .get(
                QUOTA_COUNTERS,
                &counter_id(
                    &plan.id,
                    subject_key,
                    &format!("{}:{}", limit.period, number_to_string(window.start)),
                ),
            )
            .await?;
        let counter: Option<QuotaCounter> = record.clone().map(decode).transpose()?;
        let used = counter
            .as_ref()
            .and_then(|counter| counter.used)
            .unwrap_or(0.0);
        if reason.is_none() && !dry_run && used + cost > limit.limit {
            reason = Some(limit.period.clone());
            retry_after_ms = if cost > limit.limit {
                None
            } else {
                Some(window.end - now)
            };
        }
        windows.push(LimitWindow {
            limit: limit.clone(),
            window,
            record,
            counter,
        });
    }
    let allowed = reason.is_none();
    let statuses = |spent: f64| -> Vec<QuotaLimitStatus> {
        windows
            .iter()
            .map(|entry| {
                let used = entry
                    .counter
                    .as_ref()
                    .and_then(|counter| counter.used)
                    .unwrap_or(0.0)
                    + spent;
                QuotaLimitStatus {
                    period: entry.limit.period.clone(),
                    limit: entry.limit.limit,
                    used,
                    remaining: (entry.limit.limit - used).max(0.0),
                    reset_at: entry.window.end,
                    extra: Map::new(),
                }
            })
            .collect()
    };
    let decision =
        |allowed: bool, cost: f64, limits: Vec<QuotaLimitStatus>, tokens: f64| QuotaDecision {
            allowed,
            meter: meter.to_owned(),
            plan: Some(plan.name.clone()),
            via: Some(resolved.via.clone()),
            cost,
            limits,
            throttle: plan
                .throttle
                .as_ref()
                .map(|throttle| throttle_status(throttle, tokens.floor())),
            reason: None,
            retry_after_ms: None,
            extra: Map::new(),
        };
    if dry_run {
        return Ok(decision(true, 0.0, statuses(0.0), tokens));
    }
    let base = |out: &mut Record, id: String| {
        out.insert("id".into(), Value::String(id));
        out.insert("tenantId".into(), Value::String(plan.tenant_id.clone()));
        out.insert("planId".into(), Value::String(plan.id.clone()));
        out.insert("subjectKey".into(), Value::String(subject_key.to_owned()));
    };
    let new_window = |entry: &LimitWindow| {
        let mut counter = Record::new();
        base(
            &mut counter,
            counter_id(
                &plan.id,
                subject_key,
                &format!(
                    "{}:{}",
                    entry.limit.period,
                    number_to_string(entry.window.start)
                ),
            ),
        );
        counter.insert("kind".into(), Value::String("window".into()));
        counter.insert("period".into(), Value::String(entry.limit.period.clone()));
        counter.insert("windowStart".into(), number(entry.window.start));
        counter.insert("windowEnd".into(), number(entry.window.end));
        counter
    };
    if !allowed {
        let reason = reason.unwrap_or_default();
        // Recorded once per window, the first time the window refuses.
        let refused = windows.iter().find(|entry| entry.limit.period == reason);
        if let Some(refused) = refused
            && refused
                .counter
                .as_ref()
                .is_none_or(|counter| counter.exceeded_at.is_none())
        {
            let mut next = match &refused.record {
                Some(record) => record.clone(),
                None => {
                    let mut counter = new_window(refused);
                    counter.insert("used".into(), number(0.0));
                    counter.insert("expiresAt".into(), number(refused.window.end + DAY));
                    counter
                }
            };
            next.insert("exceededAt".into(), number(now));
            if refused.record.is_some() {
                tx.put(QUOTA_COUNTERS, &next).await?;
            } else {
                tx.insert(QUOTA_COUNTERS, &next).await?;
            }
            let mut metadata = Map::new();
            metadata.insert("plan".into(), Value::String(plan.name.clone()));
            metadata.insert("meter".into(), Value::String(meter.to_owned()));
            metadata.insert("period".into(), Value::String(refused.limit.period.clone()));
            metadata.insert("limit".into(), number(refused.limit.limit));
            metadata.insert("subject".into(), Value::String(subject_key.to_owned()));
            record(tx.clone(), "quota:exceeded", metadata).await?;
        }
        let mut refusal = decision(false, cost, statuses(0.0), tokens);
        refusal.reason = Some(reason);
        refusal.retry_after_ms = retry_after_ms;
        return Ok(refusal);
    }
    if let Some(throttle) = &plan.throttle {
        let mut next = Record::new();
        base(&mut next, counter_id(&plan.id, subject_key, "bucket"));
        next.insert("kind".into(), Value::String("bucket".into()));
        next.insert("tokens".into(), number(tokens - cost));
        next.insert("updatedAt".into(), number(now));
        // A full bucket after this long is the same as no record.
        next.insert(
            "expiresAt".into(),
            number(now + ((throttle.burst / throttle.rate_per_second) * 1000.0).ceil() + MINUTE),
        );
        if bucket.is_some() {
            tx.put(QUOTA_COUNTERS, &next).await?;
        } else {
            tx.insert(QUOTA_COUNTERS, &next).await?;
        }
    }
    for entry in &windows {
        let alerted: Vec<f64> = entry
            .counter
            .as_ref()
            .and_then(|counter| counter.alerted.clone())
            .unwrap_or_default();
        let used = entry
            .counter
            .as_ref()
            .and_then(|counter| counter.used)
            .unwrap_or(0.0)
            + cost;
        let crossed: Vec<f64> = plan
            .alert_thresholds
            .iter()
            .copied()
            .filter(|threshold| {
                used * 100.0 >= threshold * entry.limit.limit && !alerted.contains(threshold)
            })
            .collect();
        let mut next = match &entry.record {
            Some(record) => record.clone(),
            None => {
                let mut counter = new_window(entry);
                counter.insert("expiresAt".into(), number(entry.window.end + DAY));
                counter
            }
        };
        next.insert("used".into(), number(used));
        if !crossed.is_empty() {
            let mut all: Vec<f64> = alerted.iter().chain(crossed.iter()).copied().collect();
            all.sort_by(|a, b| a.total_cmp(b));
            next.insert(
                "alerted".into(),
                Value::Array(all.into_iter().map(number).collect()),
            );
        }
        if entry.record.is_some() {
            tx.put(QUOTA_COUNTERS, &next).await?;
        } else {
            tx.insert(QUOTA_COUNTERS, &next).await?;
        }
        for threshold in crossed {
            let mut metadata = Map::new();
            metadata.insert("plan".into(), Value::String(plan.name.clone()));
            metadata.insert("meter".into(), Value::String(meter.to_owned()));
            metadata.insert("period".into(), Value::String(entry.limit.period.clone()));
            metadata.insert("threshold".into(), number(threshold));
            metadata.insert("limit".into(), number(entry.limit.limit));
            metadata.insert("used".into(), number(used));
            metadata.insert("subject".into(), Value::String(subject_key.to_owned()));
            record(tx.clone(), "quota:threshold", metadata).await?;
        }
    }
    Ok(decision(true, cost, statuses(cost), tokens - cost))
}
