//! Port of `packages/server/src/billing-service.ts`: the billing engine behind the `billing` API group and
//! `iam.billing`: recording, spend reports, budgets and alerts, statements and credits, subscriptions, the seat recorder
//! and anomaly detection.
//!
//! Records stay JSON objects (`Record`): read-modify-write keeps their members and member order, and new records are
//! built in the TypeScript insertion order. The typed helpers of `billing.rs` get records decoded to their types.

use std::cmp::Ordering;
use std::sync::{Arc, Mutex, Weak};

use better_iam_auth::outbox::EnqueueInput;
use better_iam_core::{
    AuthenticatedPrincipal, Filter, FindOptions, IamError, IamResult, IamStoreExt, Identity,
    OrderOptions, OutboxKind, Record, Tenant, TenantStatus, js as core_js,
};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::billing::{BillingSettings, ChargedRow, Directory, MeterCharge, SpendCache};
use crate::context::{ServerContext, Store};
use crate::js::number as num;
use crate::port::decode;
use crate::utils::id;
use crate::validation::{integer, text};

/// Settings of anomaly detection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyOptions {
    /// The day to check, `YYYY-MM-DD` in the billing time zone (default yesterday).
    #[serde(rename = "day", default, skip_serializing_if = "Option::is_none")]
    pub day: Option<String>,
    /// Days before it that make the baseline average (3 to 90, default 14).
    #[serde(
        rename = "baselineDays",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub baseline_days: Option<f64>,
    /// How many times the baseline counts as a spike (1.1 to 1000, default 3).
    #[serde(rename = "factor", default, skip_serializing_if = "Option::is_none")]
    pub factor: Option<f64>,
    /// Smallest spend and increase worth reporting, in currency units (default 10).
    #[serde(rename = "minimum", default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A budget with its spend in the current window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetStatus {
    #[serde(rename = "budgetId")]
    pub budget_id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "subjectType")]
    pub subject_type: crate::billing::BudgetSubjectType,
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    #[serde(
        rename = "subjectName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub subject_name: Option<String>,
    #[serde(rename = "period")]
    pub period: crate::billing::BudgetPeriodKind,
    /// First and last billing period of the current window.
    #[serde(rename = "windowStart")]
    pub window_start: String,
    #[serde(rename = "windowEnd")]
    pub window_end: String,
    #[serde(rename = "amountMicros")]
    pub amount_micros: f64,
    #[serde(rename = "amount")]
    pub amount: f64,
    #[serde(rename = "spentMicros")]
    pub spent_micros: f64,
    #[serde(rename = "spent")]
    pub spent: f64,
    /// Spent as a percent of the amount (one decimal).
    #[serde(rename = "percent")]
    pub percent: f64,
    #[serde(
        rename = "forecastMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub forecast_micros: Option<f64>,
    #[serde(
        rename = "forecastPercent",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub forecast_percent: Option<f64>,
    #[serde(rename = "thresholds")]
    pub thresholds: Vec<f64>,
    /// Thresholds already reached in this window.
    #[serde(rename = "reached")]
    pub reached: Vec<f64>,
    #[serde(rename = "exceeded")]
    pub exceeded: bool,
    #[serde(rename = "enforce")]
    pub enforce: bool,
    #[serde(rename = "meters", default, skip_serializing_if = "Option::is_none")]
    pub meters: Option<Vec<String>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClosePeriodResult {
    #[serde(rename = "period")]
    pub period: String,
    #[serde(rename = "issued")]
    pub issued: Vec<Value>,
    /// Invoices kept (or refreshed) as drafts (`draft`, or `billing.autoFinalize: false`).
    #[serde(rename = "drafted")]
    pub drafted: Vec<Value>,
    #[serde(rename = "skipped")]
    pub skipped: Value,
    /// Raw usage events past their retention that were deleted.
    #[serde(rename = "sweptUsage")]
    pub swept_usage: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A person, team or meter whose spend on one day jumped. Members are in the order the TypeScript object gets them
/// (`label` is added last), and `factor` is `null` for new spending.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpendAnomaly {
    #[serde(rename = "dimension")]
    pub dimension: String,
    #[serde(rename = "key")]
    pub key: String,
    #[serde(rename = "day")]
    pub day: String,
    #[serde(rename = "costMicros")]
    pub cost_micros: f64,
    /// Average daily spend over the baseline days.
    #[serde(rename = "baselineMicros")]
    pub baseline_micros: f64,
    /// `costMicros / baselineMicros`, rounded; null for new spending (no baseline).
    #[serde(rename = "factor")]
    pub factor: Option<f64>,
    #[serde(rename = "label", default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Whether usage may go ahead under the enforced budgets that cover it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpendCheck {
    #[serde(rename = "allowed")]
    pub allowed: bool,
    /// Every enforced budget that covers the usage.
    #[serde(rename = "budgets")]
    pub budgets: Vec<crate::billing_service::BudgetStatus>,
    /// The first spent budget, when refused.
    #[serde(rename = "blockedBy", default, skip_serializing_if = "Option::is_none")]
    pub blocked_by: Option<crate::billing_service::BudgetStatus>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Narrows a spend report to part of its scope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpendFilters {
    /// Only this meter key.
    #[serde(rename = "meter", default, skip_serializing_if = "Option::is_none")]
    pub meter: Option<String>,
    /// Only usage by this person, service account or agent.
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    /// Only usage attributed to this team (and the teams below it unless `rollUp` is false).
    #[serde(rename = "teamId", default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// Only usage of people in this department (and those below it unless `rollUp` is false).
    #[serde(
        rename = "departmentId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub department_id: Option<String>,
    /// Only usage in this tenant (a project) and the tenants below it.
    #[serde(
        rename = "subTenantId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sub_tenant_id: Option<String>,
    /// Include descendant teams and departments (default true).
    #[serde(rename = "rollUp", default, skip_serializing_if = "Option::is_none")]
    pub roll_up: Option<bool>,
    /// Only what statements bill: leaves out chargeback meters an account defines for itself.
    #[serde(
        rename = "billableOnly",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub billable_only: Option<bool>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// How spend reports group their rows. `tag:{name}` groups by a usage tag.
/// TODO(port): a union or intersection type in TypeScript; JSON until ported.
pub type SpendGroupBy = Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpendQuery {
    /// `YYYY-MM`; the current period by default.
    #[serde(rename = "period", default, skip_serializing_if = "Option::is_none")]
    pub period: Option<String>,
    #[serde(rename = "groupBy", default, skip_serializing_if = "Option::is_none")]
    pub group_by: Option<String>,
    /// Grouped by identity, agent, team or department: spread the spend nobody in that dimension caused (shared
    /// services, project-level usage) over the groups that did, in proportion to their spend (showback).
    #[serde(
        rename = "shareUnattributed",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub share_unattributed: Option<bool>,
    /// Only this meter key.
    #[serde(rename = "meter", default, skip_serializing_if = "Option::is_none")]
    pub meter: Option<String>,
    /// Only usage by this person, service account or agent.
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    /// Only usage attributed to this team (and the teams below it unless `rollUp` is false).
    #[serde(rename = "teamId", default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// Only usage of people in this department (and those below it unless `rollUp` is false).
    #[serde(
        rename = "departmentId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub department_id: Option<String>,
    /// Only usage in this tenant (a project) and the tenants below it.
    #[serde(
        rename = "subTenantId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sub_tenant_id: Option<String>,
    /// Include descendant teams and departments (default true).
    #[serde(rename = "rollUp", default, skip_serializing_if = "Option::is_none")]
    pub roll_up: Option<bool>,
    /// Only what statements bill: leaves out chargeback meters an account defines for itself.
    #[serde(
        rename = "billableOnly",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub billable_only: Option<bool>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpendReport {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "currency")]
    pub currency: String,
    #[serde(rename = "period")]
    pub period: String,
    #[serde(rename = "periodStart")]
    pub period_start: f64,
    #[serde(rename = "periodEnd")]
    pub period_end: f64,
    #[serde(rename = "groupBy")]
    pub group_by: crate::billing_service::SpendGroupBy,
    #[serde(rename = "rows")]
    pub rows: Vec<Value>,
    #[serde(rename = "total")]
    pub total: Value,
    /// For the current period: the total projected linearly to the end of the period.
    #[serde(rename = "forecast", default, skip_serializing_if = "Option::is_none")]
    pub forecast: Option<Value>,
    /// With `shareUnattributed`: the unattributed spend that was spread over the groups.
    #[serde(
        rename = "sharedMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub shared_micros: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpendTrend {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "currency")]
    pub currency: String,
    #[serde(rename = "months")]
    pub months: Vec<Value>,
    /// Projection of the current period (the last month).
    #[serde(rename = "forecast", default, skip_serializing_if = "Option::is_none")]
    pub forecast: Option<Value>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A statement before it is numbered and stored (`previewStatement`, `closePeriod`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatementDraft {
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "paymentTermsDays")]
    pub payment_terms_days: f64,
    /// Pending invoice items the invoice bills.
    #[serde(rename = "invoiceItemIds")]
    pub invoice_item_ids: Vec<String>,
    /// Subscription months it bills in advance.
    #[serde(rename = "advanceBilled")]
    pub advance_billed: Vec<Value>,
    /// A negative balance (credit items above the charges) that becomes account credit when it is finalized.
    #[serde(rename = "carryForwardMicros")]
    pub carry_forward_micros: f64,
    #[serde(rename = "period")]
    pub period: String,
    #[serde(rename = "currency")]
    pub currency: String,
    #[serde(rename = "periodStart")]
    pub period_start: f64,
    #[serde(rename = "periodEnd")]
    pub period_end: f64,
    #[serde(rename = "lines")]
    pub lines: Vec<crate::billing::StatementLine>,
    /// Why the invoice exists: the monthly close (default), a new subscription's first period, or an invoice made by
    /// hand.
    #[serde(
        rename = "billingReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub billing_reason: Option<String>,
    /// The sum of the lines.
    #[serde(rename = "subtotalMicros")]
    pub subtotal_micros: f64,
    /// Coupon discounts (`billing.redeemCoupon`), after the contract discount.
    #[serde(rename = "coupons", default, skip_serializing_if = "Option::is_none")]
    pub coupons: Option<Vec<Value>>,
    /// The account's negotiated discount on usage (`billing.setTerms`).
    #[serde(rename = "discount", default, skip_serializing_if = "Option::is_none")]
    pub discount: Option<Value>,
    /// What the month fell short of the account's minimum monthly commitment, billed on top.
    #[serde(
        rename = "commitment",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub commitment: Option<Value>,
    #[serde(rename = "creditsMicros")]
    pub credits_micros: f64,
    #[serde(rename = "creditsApplied")]
    pub credits_applied: Vec<Value>,
    /// Tax on the amount due after discount, commitment and credit.
    #[serde(rename = "tax", default, skip_serializing_if = "Option::is_none")]
    pub tax: Option<Value>,
    #[serde(rename = "totalMicros")]
    pub total_micros: f64,
    /// Where the billable spend came from (largest first; teams, departments and people capped at 50).
    #[serde(rename = "breakdown")]
    pub breakdown: Value,
    #[serde(rename = "billTo")]
    pub bill_to: Value,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// ---------------------------------------------------------------------------------------------------------------
// Collections, constants and small helpers

const METERS: &str = "billingMeters";
const USAGE: &str = "billingUsage";
const ROLLUPS: &str = "billingRollups";
const BUDGETS: &str = "billingBudgets";
const ALERTS: &str = "billingBudgetAlerts";
const CREDITS: &str = "billingCredits";
const STATEMENTS: &str = "billingStatements";
const INVOICE_ITEMS: &str = "billingInvoiceItems";
const CREDIT_NOTES: &str = "billingCreditNotes";
const PLANS: &str = "billingPlans";
const SUBSCRIPTIONS: &str = "billingSubscriptions";
const DISCOUNTS: &str = "billingDiscounts";
const TERMS: &str = "billingTerms";

const DAY_MS: f64 = 86_400_000.0;
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
const STATUS_CACHE_MS: f64 = 30_000.0;

/// `unattributed`: the group keys of spend without a person, agent, team, department or tag.
const UNATTRIBUTED_IDENTITY: &str = "(unattributed)";
const UNATTRIBUTED_AGENT: &str = "(none)";
const UNATTRIBUTED_TEAM: &str = "(no team)";
const UNATTRIBUTED_DEPARTMENT: &str = "(no department)";
const UNATTRIBUTED_TAG: &str = "(untagged)";

/// `builtInMeters`: built-in reported meters other modules push to; defined on the root tenant the first time they
/// are used (key, name, unit, description).
const BUILT_IN_METERS: &[(&str, &str, &str, &str)] = &[(
    "inference",
    "AI inference",
    "token",
    "Model calls through inference access control, at each model\u{2019}s token prices.",
)];

/// Whether a key names a built-in meter: only the platform (the root tenant) defines those.
pub fn built_in_meter_key(key: &str) -> IamResult<bool> {
    Ok(is_built_in_meter(key))
}

fn is_built_in_meter(key: &str) -> bool {
    BUILT_IN_METERS.iter().any(|(known, ..)| *known == key)
}

/// `Math.round`: halves round toward positive infinity.
fn js_round(value: f64) -> f64 {
    if !value.is_finite() {
        return value;
    }
    let floor = value.floor();
    if value - floor >= 0.5 {
        floor + 1.0
    } else {
        floor
    }
}

/// `Math.max(a, b)`: NaN when either is NaN.
fn js_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.max(b)
    }
}

/// `Math.min(a, b)`: NaN when either is NaN.
fn js_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

fn one_decimal(value: f64) -> f64 {
    js_round(value * 10.0) / 10.0
}

/// `Number.prototype.toFixed(digits)`: the exact decimal value rounded to `digits` places, ties to the larger
/// magnitude.
fn to_fixed(value: f64, digits: usize) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.abs() >= 1e21 || value.is_infinite() {
        return core_js::number_to_string(value);
    }
    let negative = value < 0.0;
    let magnitude = value.abs();
    // The exact decimal expansion decides ties, which Rust formatting would round to even.
    let exact = format!("{magnitude:.1100}");
    let point = exact.find('.').unwrap_or(exact.len());
    let rest = exact.get(point + 1 + digits..).unwrap_or("");
    let tie = rest.starts_with('5') && rest[1..].bytes().all(|byte| byte == b'0');
    let formatted = if tie {
        let scale = 10f64.powi(digits as i32);
        let up = ((magnitude * scale).floor() + 1.0) / scale;
        format!("{up:.digits$}")
    } else {
        format!("{magnitude:.digits$}")
    };
    if negative {
        format!("-{formatted}")
    } else {
        formatted
    }
}

/// `String(n).padStart(width, '0')`.
fn pad_start(value: f64, width: usize) -> String {
    let text = core_js::number_to_string(value);
    if text.len() >= width {
        text
    } else {
        format!("{}{text}", "0".repeat(width - text.len()))
    }
}

fn str_of<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

fn num_of(record: &Record, key: &str) -> Option<f64> {
    record.get(key).and_then(core_js::as_number)
}

fn bool_of(record: &Record, key: &str) -> bool {
    matches!(record.get(key), Some(Value::Bool(true)))
}

fn strings_of(record: &Record, key: &str) -> Vec<String> {
    record
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn object_of(value: Option<&Value>) -> Record {
    match value {
        Some(Value::Object(map)) => map.clone(),
        _ => Record::new(),
    }
}

fn records_of(value: Option<&Value>) -> Vec<Record> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_object().cloned())
                .collect()
        })
        .unwrap_or_default()
}

fn strings_value(items: impl IntoIterator<Item = String>) -> Value {
    Value::Array(items.into_iter().map(Value::String).collect())
}

/// `diff || tie`: the sign of a numeric comparator difference, else the tie-breaker.
fn by_difference(difference: f64, tie: impl FnOnce() -> Ordering) -> Ordering {
    if difference > 0.0 {
        Ordering::Greater
    } else if difference < 0.0 {
        Ordering::Less
    } else {
        tie()
    }
}

/// `new Date(at).toISOString().slice(0, 10)`.
fn iso_day(at: f64) -> String {
    core_js::iso_string(at)
        .map(|iso| iso[..10].to_owned())
        .unwrap_or_default()
}

fn email_input(
    tenant_id: &str,
    to: &str,
    template: &str,
    payload: Map<String, Value>,
) -> EnqueueInput {
    EnqueueInput {
        tenant_id: tenant_id.to_owned(),
        kind: OutboxKind::Email,
        to: to.to_owned(),
        template: template.to_owned(),
        payload,
        reference: None,
    }
}

/// A system audit event.
fn system_event(
    tenant_id: &str,
    actor_id: &str,
    action: &str,
    resource_id: &str,
    timestamp: f64,
    metadata: Map<String, Value>,
) -> Record {
    let mut event = Record::new();
    event.insert("id".into(), Value::String(id()));
    event.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    event.insert("actorId".into(), Value::String(actor_id.to_owned()));
    event.insert("action".into(), Value::String(action.to_owned()));
    event.insert("resourceId".into(), Value::String(resource_id.to_owned()));
    event.insert("timestamp".into(), num(timestamp));
    event.insert("outcome".into(), Value::String("allow".into()));
    event.insert("metadata".into(), Value::Object(metadata));
    event
}

async fn first_record(tx: &Store, collection: &str, filter: Filter) -> IamResult<Option<Record>> {
    Ok(tx
        .find(collection, &filter, &FindOptions::default())
        .await?
        .into_iter()
        .next())
}

async fn find_all(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

async fn get_tenant(tx: &Store, tenant_id: &str) -> IamResult<Option<Tenant>> {
    match tx.get("tenants", tenant_id).await? {
        Some(record) => Ok(Some(decode(record)?)),
        None => Ok(None),
    }
}

/// The `name` member of a stored record.
async fn name_in(tx: &Store, collection: &str, record_id: &str) -> IamResult<Option<String>> {
    Ok(tx
        .get(collection, record_id)
        .await?
        .and_then(|record| str_of(&record, "name").map(str::to_owned)))
}

/// Formats micros as money in the deployment currency (for emails): `Intl.NumberFormat('en-US', { style:
/// 'currency', currency })`.
pub fn format_money(micros: f64, currency: &str) -> IamResult<String> {
    let units = crate::billing::units_of(micros)?;
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Ok(format!("{currency} {}", to_fixed(units, 2)));
    }
    Ok(currency_format(units, &currency.to_ascii_uppercase()))
}

/// The en-US symbol of a currency (CLDR), when it has one other than its code.
fn currency_symbol(code: &str) -> Option<&'static str> {
    Some(match code {
        "USD" => "$",
        "EUR" => "\u{20ac}",
        "GBP" => "\u{a3}",
        "JPY" => "\u{a5}",
        "CNY" => "CN\u{a5}",
        "INR" => "\u{20b9}",
        "KRW" => "\u{20a9}",
        "CAD" => "CA$",
        "AUD" => "A$",
        "NZD" => "NZ$",
        "HKD" => "HK$",
        "MXN" => "MX$",
        "BRL" => "R$",
        "ILS" => "\u{20aa}",
        "TWD" => "NT$",
        "VND" => "\u{20ab}",
        "XAF" => "FCFA",
        "XOF" => "F\u{202f}CFA",
        "XPF" => "CFPF",
        "XCD" => "EC$",
        "PHP" => "\u{20b1}",
        _ => return None,
    })
}

/// Fraction digits of a currency (CLDR), 2 unless listed.
fn currency_digits(code: &str) -> usize {
    match code {
        "ADP" | "AFN" | "ALL" | "BIF" | "BYR" | "CLP" | "DJF" | "ESP" | "GNF" | "IQD" | "IRR"
        | "ISK" | "ITL" | "JPY" | "KMF" | "KPW" | "KRW" | "LAK" | "LBP" | "LUF" | "MGA" | "MGF"
        | "MMK" | "MRO" | "PYG" | "RSD" | "RWF" | "SLL" | "SOS" | "STD" | "SYP" | "TMM" | "TRL"
        | "UGX" | "UYI" | "VND" | "VUV" | "XAF" | "XOF" | "XPF" | "YER" | "ZMK" | "ZWD" => 0,
        "BHD" | "JOD" | "KWD" | "LYD" | "OMR" | "TND" => 3,
        "CLF" | "UYW" => 4,
        _ => 2,
    }
}

fn currency_format(units: f64, code: &str) -> String {
    // A symbol (or code) that ends in a letter is set apart from the digits by a no-break space.
    let prefix = match currency_symbol(code) {
        Some(symbol) if !symbol.chars().last().is_some_and(char::is_alphabetic) => {
            symbol.to_owned()
        }
        Some(symbol) => format!("{symbol}\u{a0}"),
        None => format!("{code}\u{a0}"),
    };
    let sign = if units < 0.0 { "-" } else { "" };
    if units.is_nan() {
        return format!("{prefix}NaN");
    }
    if units.is_infinite() {
        return format!("{sign}{prefix}\u{221e}");
    }
    let fixed = to_fixed(units.abs(), currency_digits(code));
    let (whole, fraction) = match fixed.split_once('.') {
        Some((whole, fraction)) => (whole.to_owned(), Some(fraction.to_owned())),
        None => (fixed.clone(), None),
    };
    let mut grouped = String::new();
    for (index, digit) in whole.chars().enumerate() {
        if index > 0 && (whole.len() - index) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    match fraction {
        Some(fraction) => format!("{sign}{prefix}{grouped}.{fraction}"),
        None => format!("{sign}{prefix}{grouped}"),
    }
}

/// `spendGroupBy(value)`.
fn spend_group_by(value: Option<&Value>) -> IamResult<String> {
    if let Some(Value::String(text)) = value {
        if matches!(
            text.as_str(),
            "meter" | "identity" | "agent" | "team" | "department" | "tenant" | "day"
        ) {
            return Ok(text.clone());
        }
        if let Some(name) = text.strip_prefix("tag:") {
            let mut chars = name.chars();
            let valid = chars
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic())
                && name.len() <= 64
                && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'));
            if valid {
                return Ok(text.clone());
            }
        }
    }
    Err(IamError::new(
        "INVALID_INPUT",
        "groupBy must be 'meter', 'identity', 'agent', 'team', 'department', 'tenant', 'day' or 'tag:{name}'",
    ))
}

/// RFC 4180 CSV; cells that spreadsheet programs would read as formulas are prefixed with a quote. Only plain numbers
/// (`-12.5`) keep a leading minus: `-1+cmd|...` is a formula.
fn csv(rows: &[Vec<String>]) -> String {
    fn plain_number(value: &str) -> bool {
        let digits = value.strip_prefix('-').unwrap_or(value);
        let (whole, fraction) = match digits.split_once('.') {
            Some((whole, fraction)) => (whole, Some(fraction)),
            None => (digits, None),
        };
        !whole.is_empty()
            && whole.bytes().all(|byte| byte.is_ascii_digit())
            && fraction.is_none_or(|fraction| {
                !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit())
            })
    }
    let cell = |value: &str| {
        let formula = value
            .chars()
            .next()
            .is_some_and(|first| matches!(first, '=' | '+' | '-' | '@' | '\t' | '\r'));
        let safe = if formula && !plain_number(value) {
            format!("'{value}")
        } else {
            value.to_owned()
        };
        if safe.contains(['"', ',', '\r', '\n']) {
            format!("\"{}\"", safe.replace('"', "\"\""))
        } else {
            safe
        }
    };
    let lines: Vec<String> = rows
        .iter()
        .map(|row| {
            row.iter()
                .map(|value| cell(value))
                .collect::<Vec<_>>()
                .join(",")
        })
        .collect();
    format!("{}\r\n", lines.join("\r\n"))
}

/// The policy context keys billing derives (`principal.spendExceeded`, `principal.budgetsExceeded`).
pub const SPEND_CONTEXT_KEYS: [&str; 2] = ["principal.spendExceeded", "principal.budgetsExceeded"];

/// Whether any statement of the documents names a spend context key, so decisions read budgets only when needed.
pub fn mentions_spend(documents: &[&better_iam_core::PolicyDocument]) -> bool {
    documents.iter().any(|document| {
        let serialized =
            core_js::stringify(&serde_json::to_value(&document.statements).unwrap_or(Value::Null));
        SPEND_CONTEXT_KEYS
            .iter()
            .any(|key| serialized.contains(key))
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Adapters over the JSON-typed helpers of billing.rs

/// `periodBounds(period, tz)` as `(start, end)`.
fn period_bounds(period: &str, tz: &str) -> IamResult<(f64, f64)> {
    let bounds = crate::billing::period_bounds(period, tz)?;
    let start = crate::js::member(Some(&bounds), "start").and_then(core_js::as_number);
    let end = crate::js::member(Some(&bounds), "end").and_then(core_js::as_number);
    Ok((start.unwrap_or(f64::NAN), end.unwrap_or(f64::NAN)))
}

fn charged_rows(value: Option<&Value>) -> IamResult<Vec<ChargedRow>> {
    let Some(Value::Array(items)) = value else {
        return Ok(Vec::new());
    };
    items
        .iter()
        .map(|item| decode(object_of(Some(item))))
        .collect()
}

/// One account's spend of `accountSpend` / `scopeSpend`.
struct AccountSpend {
    account_id: String,
    charges: Vec<MeterCharge>,
    rows: Vec<ChargedRow>,
}

fn account_spend_of(value: &Value) -> IamResult<AccountSpend> {
    let record = object_of(Some(value));
    let charges = match record.get("charges") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| decode(object_of(Some(item))))
            .collect::<IamResult<Vec<MeterCharge>>>()?,
        _ => Vec::new(),
    };
    Ok(AccountSpend {
        account_id: str_of(&record, "accountId").unwrap_or_default().to_owned(),
        charges,
        rows: charged_rows(record.get("rows"))?,
    })
}

async fn account_spend(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    account: &Tenant,
    period: &str,
    cache: &SpendCache,
) -> IamResult<AccountSpend> {
    let value = crate::billing::account_spend(ctx, tx, account, period, Some(cache)).await?;
    account_spend_of(&value)
}

async fn scope_spend(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    scope: &Tenant,
    period: &str,
    cache: &SpendCache,
) -> IamResult<(Vec<ChargedRow>, Vec<AccountSpend>)> {
    let value = crate::billing::scope_spend(ctx, tx, scope, period, Some(cache)).await?;
    let rows = charged_rows(crate::js::member(Some(&value), "rows"))?;
    let accounts = match crate::js::member(Some(&value), "accounts") {
        Some(Value::Array(items)) => items
            .iter()
            .map(account_spend_of)
            .collect::<IamResult<Vec<_>>>()?,
        _ => Vec::new(),
    };
    Ok((rows, accounts))
}

/// `Attribution` of `attributionFor`.
struct Attribution {
    identity_id: Option<String>,
    agent_id: Option<String>,
    team_ids: Vec<String>,
    department_id: Option<String>,
}

/// `invoiceAmounts` of billing.rs with its `credit` callback, which the JSON input of the generated
/// `crate::billing::invoice_amounts` signature cannot carry: the subtotal through the contract discount, the
/// minimum-commitment true-up, coupons, credit and tax. Members in the TypeScript order; `carryForwardMicros` comes
/// back separately.
fn invoice_amounts(
    subtotal_micros: f64,
    terms: Option<&Record>,
    commitment: bool,
    discounts: &[Record],
    credit: &mut dyn FnMut(f64) -> IamResult<f64>,
) -> IamResult<(Map<String, Value>, f64)> {
    use crate::billing::{round_cents, round_micros};
    let discount_percent = terms.and_then(|terms| num_of(terms, "discountPercent"));
    let minimum = terms.and_then(|terms| num_of(terms, "minimumCommitmentMicros"));
    let tax_rate = terms.and_then(|terms| num_of(terms, "taxRatePercent"));
    let contract_micros = match discount_percent {
        Some(percent) if subtotal_micros > 0.0 => round_cents(subtotal_micros * percent / 100.0)?,
        _ => 0.0,
    };
    let mut net = round_micros(subtotal_micros - contract_micros)?;
    let true_up_micros = match minimum {
        Some(minimum) if commitment => round_cents(js_max(0.0, minimum - net))?,
        _ => 0.0,
    };
    net = round_micros(net + true_up_micros)?;
    let mut coupons: Vec<Value> = Vec::new();
    for discount in discounts {
        if net <= 0.0 {
            break;
        }
        let off = match num_of(discount, "percentOff") {
            Some(percent) => net * percent / 100.0,
            None => num_of(discount, "amountOffMicros").unwrap_or(0.0),
        };
        let amount = round_cents(js_min(net, off))?;
        if amount <= 0.0 {
            continue;
        }
        let mut coupon = Map::new();
        coupon.insert(
            "discountId".into(),
            discount.get("id").cloned().unwrap_or(Value::Null),
        );
        coupon.insert(
            "code".into(),
            discount.get("code").cloned().unwrap_or(Value::Null),
        );
        coupon.insert(
            "name".into(),
            discount.get("name").cloned().unwrap_or(Value::Null),
        );
        coupon.insert("amountMicros".into(), num(amount));
        coupons.push(Value::Object(coupon));
        net = round_micros(net - amount)?;
    }
    let carry_forward_micros = if net < 0.0 { round_micros(-net)? } else { 0.0 };
    let due = js_max(0.0, net);
    let credits_micros = if due > 0.0 {
        round_micros(js_min(due, credit(due)?))?
    } else {
        0.0
    };
    let taxable = round_micros(due - credits_micros)?;
    let tax_micros = match tax_rate {
        Some(rate) => round_cents(taxable * rate / 100.0)?,
        None => 0.0,
    };
    let mut amounts = Map::new();
    if let Some(percent) = discount_percent {
        amounts.insert(
            "discount".into(),
            json!({ "percent": num(percent), "amountMicros": num(contract_micros) }),
        );
    }
    if let (true, Some(minimum)) = (commitment, minimum) {
        amounts.insert(
            "commitment".into(),
            json!({ "minimumMicros": num(minimum), "trueUpMicros": num(true_up_micros) }),
        );
    }
    if !coupons.is_empty() {
        amounts.insert("coupons".into(), Value::Array(coupons));
    }
    amounts.insert("creditsMicros".into(), num(credits_micros));
    if let Some(rate) = tax_rate {
        let label = terms
            .and_then(|terms| terms.get("taxLabel"))
            .filter(|label| !label.is_null())
            .cloned()
            .unwrap_or_else(|| Value::String("Tax".into()));
        let mut tax = Map::new();
        tax.insert("label".into(), label);
        tax.insert("ratePercent".into(), num(rate));
        tax.insert("amountMicros".into(), num(tax_micros));
        amounts.insert("tax".into(), Value::Object(tax));
    }
    amounts.insert(
        "totalMicros".into(),
        num(round_micros(taxable + tax_micros)?),
    );
    Ok((amounts, carry_forward_micros))
}

// ---------------------------------------------------------------------------------------------------------------
// The service

/// `RecordExtras`: what trusted callers of `record` add (a reported cost, the agent, a source key, budget
/// enforcement, the meter already resolved).
#[derive(Debug, Clone, Default)]
pub struct RecordExtras {
    pub cost_micros: Option<f64>,
    pub agent_id: Option<String>,
    pub source_id: Option<String>,
    pub enforce_budgets: bool,
    pub meter: Option<crate::billing::BillingMeter>,
}

/// A subscription's first invoice (`draftStatement`'s `first`): its advance lines.
#[derive(Debug, Clone)]
pub struct FirstLines {
    pub lines: Vec<Value>,
    pub subscription_id: String,
}

/// What `issue` and `finalizeDraft` return: the finalized invoice and the emails sent.
#[derive(Debug, Clone)]
pub struct Issued {
    pub statement: Record,
    pub recipients: usize,
}

/// What `recordPayment` returns.
#[derive(Debug, Clone)]
pub struct PaymentRecorded {
    pub statement: Record,
    pub payment: Record,
}

/// What `createCreditNote` returns.
#[derive(Debug, Clone)]
pub struct CreditNoteIssued {
    pub statement: Record,
    pub credit_note: Record,
}

/// What `subscribe` returns: the subscription and its first invoice (outside a trial).
#[derive(Debug, Clone)]
pub struct Subscribed {
    pub subscription: Record,
    pub invoice: Option<Record>,
}

/// What `updateSeats`, `cancelSubscription` and `changePlan` return: the subscription and its proration items.
#[derive(Debug, Clone)]
pub struct SubscriptionChange {
    pub subscription: Record,
    pub items: Vec<Record>,
}

/// A row filter of `report` and `trend` (`rowFilter`).
pub type RowFilter<'a> = &'a (dyn Fn(&ChargedRow) -> bool + Send + Sync);

/// Validated spend filters (`SpendFilters`).
#[derive(Debug, Clone, Default)]
struct Filters {
    meter: Option<String>,
    identity_id: Option<String>,
    roll_up: Option<bool>,
    billable_only: Option<bool>,
    team_id: Option<String>,
    department_id: Option<String>,
}

/// Where anomaly detection reads charged rows (`rowsFor`): a scope's subtree or one billing account.
#[derive(Clone, Copy)]
enum RowSource<'a> {
    Scope(&'a Tenant),
    Account(&'a Tenant),
}

struct CachedStatus {
    at: f64,
    updated_at: Option<f64>,
    status: BudgetStatus,
}

/// Validated anomaly settings.
struct AnomalySettings {
    day: String,
    baseline_days: f64,
    factor: f64,
    minimum_micros: f64,
}

/// A spend report group (`SpendRow` while it is summed).
struct Group {
    key: String,
    cost_micros: f64,
    events: f64,
    quantities: IndexMap<String, f64>,
    shared_micros: Option<f64>,
}

type ServiceEntry = (Weak<ServerContext>, Arc<BillingService>);
static SERVICES: Mutex<Vec<ServiceEntry>> = Mutex::new(Vec::new());

/// The billing service of a server (one per instance, shared by the API group, `iam.billing` and `ctx.billing`).
pub fn billing_service_of(ctx: &Arc<ServerContext>) -> IamResult<Arc<BillingService>> {
    {
        let mut entries = SERVICES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|(weak, _)| weak.strong_count() > 0);
        if let Some((_, service)) = entries
            .iter()
            .find(|(weak, _)| weak.upgrade().is_some_and(|live| Arc::ptr_eq(&live, ctx)))
        {
            return Ok(service.clone());
        }
    }
    let service = Arc::new(create_billing_service(ctx)?);
    SERVICES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push((Arc::downgrade(ctx), service.clone()));
    Ok(service)
}

/// `createBillingService(ctx)`: validates the `billing` option (INVALID_CONFIG).
fn create_billing_service(ctx: &Arc<ServerContext>) -> IamResult<BillingService> {
    let options = crate::options_value::options_value(&ctx.options);
    let settings =
        match crate::billing::billing_settings(crate::js::member(Some(&options), "billing")) {
            Ok(settings) => Ok(settings),
            // While billing.ts is not ported its validator is a stub: construction must not fail every server, so
            // the methods that need the settings report it instead.
            Err(error) if error.code == "NOT_IMPLEMENTED" => Err(error),
            Err(error) => return Err(error),
        };
    Ok(BillingService {
        ctx: Arc::downgrade(ctx),
        settings,
        status_cache: Mutex::new(IndexMap::new()),
    })
}

/// `BillingService` (`ReturnType<typeof createBillingService>`): the ledger behind `api.billing`, the billing runtime
/// and the hooks other modules push priced usage through.
pub struct BillingService {
    ctx: Weak<ServerContext>,
    settings: Result<BillingSettings, IamError>,
    status_cache: Mutex<IndexMap<String, CachedStatus>>,
}

struct BillingServiceHooks {
    service: Arc<BillingService>,
}

#[async_trait::async_trait]
impl crate::contracts::BillingHooks for BillingServiceHooks {
    async fn record_priced(&self, tx: &Store, input: &Value) {
        self.service.record_priced(tx, input).await;
    }
}

fn member<'a>(input: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    crate::js::member(input, key)
}

/// `UsageReceipt` of a stored usage record.
fn receipt(record: &Record, duplicate: bool) -> crate::billing::UsageReceipt {
    crate::billing::UsageReceipt {
        id: str_of(record, "id").unwrap_or_default().to_owned(),
        tenant_id: str_of(record, "tenantId").unwrap_or_default().to_owned(),
        meter: str_of(record, "meter").unwrap_or_default().to_owned(),
        quantity: num_of(record, "quantity").unwrap_or(f64::NAN),
        cost_micros: num_of(record, "costMicros"),
        period: str_of(record, "period").unwrap_or_default().to_owned(),
        occurred_at: num_of(record, "occurredAt").unwrap_or(f64::NAN),
        identity_id: str_of(record, "identityId").map(str::to_owned),
        team_ids: strings_of(record, "teamIds"),
        department_id: str_of(record, "departmentId").map(str::to_owned),
        duplicate,
        extra: Map::new(),
    }
}

fn attribution_of(value: &Value) -> Attribution {
    let record = object_of(Some(value));
    Attribution {
        identity_id: str_of(&record, "identityId").map(str::to_owned),
        agent_id: str_of(&record, "agentId").map(str::to_owned),
        team_ids: strings_of(&record, "teamIds"),
        department_id: str_of(&record, "departmentId").map(str::to_owned),
    }
}

fn sends_email(ctx: &ServerContext) -> bool {
    ctx.options
        .authentication
        .as_ref()
        .is_some_and(|authentication| authentication.send_email.is_some())
}

/// A tenant's subtree as ids.
async fn subtree_ids(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant: &Tenant,
) -> IamResult<IndexSet<String>> {
    Ok(crate::billing::subtree(ctx, tx, tenant)
        .await?
        .into_iter()
        .map(|realm| realm.id)
        .collect())
}

impl BillingService {
    fn ctx(&self) -> IamResult<Arc<ServerContext>> {
        self.ctx.upgrade().ok_or_else(|| {
            IamError::with_status("INTERNAL_ERROR", "The server is no longer running", 500)
        })
    }

    /// `settings`: the deployment's validated billing settings.
    pub fn settings(&self) -> IamResult<&BillingSettings> {
        self.settings.as_ref().map_err(Clone::clone)
    }

    /// `hooks`: what other modules (inference) push already-priced usage through.
    pub fn hooks(self: &Arc<Self>) -> Arc<dyn crate::contracts::BillingHooks> {
        Arc::new(BillingServiceHooks {
            service: self.clone(),
        })
    }

    /// `currentPeriod()`: the billing period of now.
    pub fn current_period(&self) -> IamResult<String> {
        let ctx = self.ctx()?;
        crate::billing::period_of(ctx.now(), &self.settings()?.time_zone)
    }

    /// The non-void statement of an account for a period, if it has been invoiced.
    pub async fn statement_for(
        &self,
        tx: &Store,
        account_id: &str,
        period: &str,
    ) -> IamResult<Option<Record>> {
        first_record(
            tx,
            STATEMENTS,
            Filter::new()
                .eq("tenantId", account_id)
                .eq("uniqueKey", format!("period:{period}")),
        )
        .await
    }

    /// `record(tx, input, recordedBy, extra)`: records one usage event (`UsageInput` as JSON).
    pub async fn record(
        &self,
        tx: &Store,
        input: &Value,
        recorded_by: &str,
        extra: RecordExtras,
    ) -> IamResult<crate::billing::UsageReceipt> {
        use crate::billing::{amount_micros, meter_key, resolve_meter, round_micros};
        let ctx = self.ctx()?;
        let settings = self.settings()?;
        let tz = settings.time_zone.as_str();
        let input = Some(input);
        let tenant = ctx
            .tenant(tx, &text(member(input, "tenantId"), "tenantId", 256)?)
            .await?;
        if tenant.status == TenantStatus::Deleted {
            return Err(IamError::new(
                "INVALID_TRANSITION",
                "Deleted tenants cannot record usage",
            ));
        }
        let chain = ctx.ancestry(tx, &tenant).await?;
        let key = meter_key(member(input, "meter"))?;
        let meter = match extra.meter.clone() {
            Some(meter) => Some(meter),
            None => resolve_meter(tx, &chain, &key).await?,
        };
        let Some(meter) = meter else {
            return Err(IamError::with_status(
                "NOT_FOUND",
                format!("Unknown billing meter {key}"),
                404,
            ));
        };
        if meter.archived {
            return Err(IamError::with_status(
                "METER_ARCHIVED",
                "This meter no longer accepts usage",
                409,
            ));
        }
        let quantity = match member(input, "quantity") {
            None => 1.0,
            Some(Value::Number(number)) => {
                let quantity = core_js::number_value(number);
                if !quantity.is_finite() || !(0.0..=1e15).contains(&quantity) {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "quantity must be a number from 0 to 1e15",
                    ));
                }
                quantity
            }
            Some(_) => {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "quantity must be a number from 0 to 1e15",
                ));
            }
        };
        let mut cost_micros: Option<f64> = None;
        if meter.pricing == "reported" {
            let cost = match extra.cost_micros {
                Some(cost) => Some(cost),
                None => match member(input, "cost") {
                    None => None,
                    Some(value) => Some(amount_micros(Some(value), "cost")?),
                },
            };
            let Some(cost) = cost else {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "This meter needs the cost of each event (cost)",
                ));
            };
            cost_micros = Some(round_micros(cost)?);
        } else if member(input, "cost").is_some() || extra.cost_micros.is_some() {
            return Err(IamError::new(
                "INVALID_INPUT",
                "This meter is priced from the rate card; leave cost out",
            ));
        }
        let now = ctx.now();
        let occurred_at = match member(input, "occurredAt") {
            None => now,
            Some(value) => integer(Some(value), "occurredAt", 0.0, MAX_SAFE_INTEGER)?,
        };
        if occurred_at > now + 300_000.0 {
            return Err(IamError::new(
                "INVALID_INPUT",
                "occurredAt must not be in the future",
            ));
        }
        if occurred_at < now - 366.0 * DAY_MS {
            return Err(IamError::new(
                "INVALID_INPUT",
                "occurredAt must be within the last year",
            ));
        }
        let period = crate::billing::period_of(occurred_at, tz)?;
        let unique_key = match member(input, "idempotencyKey") {
            Some(value) => Some(format!(
                "idem:{}",
                text(Some(value), "idempotencyKey", 200)?
            )),
            None => extra
                .source_id
                .as_ref()
                .map(|source| format!("src:{}:{source}", meter.key)),
        };
        if let Some(unique_key) = &unique_key {
            let existing = first_record(
                tx,
                USAGE,
                Filter::new()
                    .eq("tenantId", tenant.id.as_str())
                    .eq("uniqueKey", unique_key.as_str()),
            )
            .await?;
            if let Some(existing) = existing {
                if str_of(&existing, "meterId") != Some(meter.id.as_str()) {
                    return Err(IamError::with_status(
                        "CONFLICT",
                        "This idempotency key was used for another meter",
                        409,
                    ));
                }
                return Ok(receipt(&existing, true));
            }
        }
        let account = crate::billing::account_of(&ctx, tx, &tenant).await?;
        // A draft invoice is recomputed when it is finalized, so its period still takes usage.
        let invoiced = self.statement_for(tx, &account.id, &period).await?;
        if let Some(invoiced) = invoiced
            && str_of(&invoiced, "status") != Some("draft")
        {
            return Err(IamError::with_status(
                "BILLING_PERIOD_CLOSED",
                format!("{period} has already been invoiced for this billing account"),
                409,
            ));
        }
        // Attribution stays inside the organization: only trusted server code and platform (root tenant) identities
        // attribute usage to the platform's own people and teams, whose budgets and reports it would count toward.
        let recorder = if recorded_by == "deployment" {
            None
        } else {
            tx.get("identities", recorded_by).await?
        };
        let root_id = chain.last().map(|root| root.id.clone()).unwrap_or_default();
        let attributable: &[Tenant] = if recorded_by == "deployment"
            || recorder
                .as_ref()
                .and_then(|recorder| str_of(recorder, "tenantId"))
                == Some(root_id.as_str())
        {
            &chain
        } else {
            &chain[..chain.len().saturating_sub(1)]
        };
        let mut who = Map::new();
        if let Some(value) = member(input, "identityId") {
            who.insert("identityId".into(), value.clone());
        }
        if let Some(agent_id) = &extra.agent_id {
            who.insert("agentId".into(), Value::String(agent_id.clone()));
        }
        if let Some(value) = member(input, "teamId") {
            who.insert("teamId".into(), value.clone());
        }
        let attribution = attribution_of(
            &crate::billing::attribution_for(&ctx, tx, attributable, &Value::Object(who), settings)
                .await?,
        );
        if meter.aggregation == "unique"
            && attribution.identity_id.as_deref().unwrap_or("").is_empty()
        {
            return Err(IamError::new(
                "INVALID_INPUT",
                "Meters that count people need identityId",
            ));
        }
        let tags = crate::billing::usage_tags(member(input, "tags"))?;
        if extra.enforce_budgets {
            let mut query = Map::new();
            if let Some(identity_id) = &attribution.identity_id {
                query.insert("identityId".into(), Value::String(identity_id.clone()));
            }
            query.insert("meter".into(), Value::String(meter.key.clone()));
            let verdict = self.check(tx, &tenant, &Value::Object(query)).await?;
            if !verdict.allowed {
                let name = verdict
                    .blocked_by
                    .as_ref()
                    .map(|status| status.name.clone())
                    .unwrap_or_default();
                return Err(IamError::with_status(
                    "SPEND_LIMIT_REACHED",
                    format!("The budget \u{201c}{name}\u{201d} is spent"),
                    402,
                ));
            }
        }
        let day = crate::billing::day_of(occurred_at, tz)?;
        let mut bucket = Map::new();
        if let Some(identity_id) = &attribution.identity_id {
            bucket.insert("identityId".into(), Value::String(identity_id.clone()));
        }
        if let Some(agent_id) = &attribution.agent_id {
            bucket.insert("agentId".into(), Value::String(agent_id.clone()));
        }
        bucket.insert(
            "teamIds".into(),
            strings_value(attribution.team_ids.iter().cloned()),
        );
        if let Some(department_id) = &attribution.department_id {
            bucket.insert("departmentId".into(), Value::String(department_id.clone()));
        }
        if let Some(tags) = &tags {
            bucket.insert(
                "tags".into(),
                Value::Object(
                    tags.iter()
                        .map(|(name, value)| (name.clone(), Value::String(value.clone())))
                        .collect(),
                ),
            );
        }
        let bucket_id =
            crate::billing::rollup_id(&tenant.id, &day, &meter.id, &Value::Object(bucket.clone()))?;
        match tx.get(ROLLUPS, &bucket_id).await? {
            Some(mut existing) => {
                let quantity_before = num_of(&existing, "quantity").unwrap_or(f64::NAN);
                let cost_before = num_of(&existing, "costMicros").unwrap_or(f64::NAN);
                let events_before = num_of(&existing, "events").unwrap_or(f64::NAN);
                existing.insert("quantity".into(), num(quantity_before + quantity));
                existing.insert(
                    "costMicros".into(),
                    num(round_micros(cost_before + cost_micros.unwrap_or(0.0))?),
                );
                existing.insert("events".into(), num(events_before + 1.0));
                existing.insert("updatedAt".into(), num(now));
                tx.put(ROLLUPS, &existing).await?;
            }
            None => {
                let mut rollup = Record::new();
                rollup.insert("id".into(), Value::String(bucket_id.clone()));
                rollup.insert("tenantId".into(), Value::String(tenant.id.clone()));
                rollup.insert("period".into(), Value::String(period.clone()));
                rollup.insert("day".into(), Value::String(day.clone()));
                rollup.insert("meterId".into(), Value::String(meter.id.clone()));
                rollup.insert("meter".into(), Value::String(meter.key.clone()));
                rollup.extend(bucket.clone());
                rollup.insert("quantity".into(), num(quantity));
                rollup.insert("costMicros".into(), num(cost_micros.unwrap_or(0.0)));
                rollup.insert("events".into(), num(1.0));
                rollup.insert("updatedAt".into(), num(now));
                tx.insert(ROLLUPS, &rollup).await?;
            }
        }
        let mut usage = Record::new();
        usage.insert("id".into(), Value::String(id()));
        usage.insert("tenantId".into(), Value::String(tenant.id.clone()));
        if let Some(unique_key) = &unique_key {
            usage.insert("uniqueKey".into(), Value::String(unique_key.clone()));
        }
        usage.insert("meterId".into(), Value::String(meter.id.clone()));
        usage.insert("meter".into(), Value::String(meter.key.clone()));
        usage.insert("quantity".into(), num(quantity));
        if let Some(cost_micros) = cost_micros {
            usage.insert("costMicros".into(), num(cost_micros));
        }
        usage.extend(bucket);
        usage.insert("occurredAt".into(), num(occurred_at));
        usage.insert("period".into(), Value::String(period.clone()));
        usage.insert("day".into(), Value::String(day));
        usage.insert("recordedAt".into(), num(now));
        usage.insert("recordedBy".into(), Value::String(recorded_by.to_owned()));
        if let Some(source_id) = &extra.source_id {
            usage.insert("sourceId".into(), Value::String(source_id.clone()));
        }
        usage.insert("rollupId".into(), Value::String(bucket_id));
        usage.insert(
            "expiresAt".into(),
            num(crate::billing::usage_expiry(&period, settings)?),
        );
        let stored = tx.insert(USAGE, &usage).await?;
        Ok(receipt(&stored, false))
    }

    /// Defines a built-in reported meter on the root tenant the first time a module pushes to it.
    async fn built_in_meter(
        &self,
        tx: &Store,
        chain: &[Tenant],
        key: &str,
    ) -> IamResult<Option<crate::billing::BillingMeter>> {
        let Some((_, name, unit, description)) =
            BUILT_IN_METERS.iter().find(|(known, ..)| *known == key)
        else {
            return Ok(None);
        };
        let ctx = self.ctx()?;
        let Some(root) = chain.last() else {
            return Ok(None);
        };
        let now = ctx.now();
        let mut meter = Record::new();
        meter.insert("id".into(), Value::String(id()));
        meter.insert("tenantId".into(), Value::String(root.id.clone()));
        meter.insert("uniqueKey".into(), Value::String(key.to_owned()));
        meter.insert("key".into(), Value::String(key.to_owned()));
        meter.insert("name".into(), Value::String((*name).to_owned()));
        meter.insert("unit".into(), Value::String((*unit).to_owned()));
        meter.insert(
            "description".into(),
            Value::String((*description).to_owned()),
        );
        meter.insert("aggregation".into(), Value::String("sum".into()));
        meter.insert("pricing".into(), Value::String("reported".into()));
        meter.insert("archived".into(), Value::Bool(false));
        meter.insert("createdAt".into(), num(now));
        meter.insert("createdBy".into(), Value::String("deployment".into()));
        meter.insert("updatedAt".into(), num(now));
        meter.insert("updatedBy".into(), Value::String("deployment".into()));
        let stored = tx.insert(METERS, &meter).await?;
        Ok(Some(decode(stored)?))
    }

    /// `hooks.recordPriced(tx, input)`: records already-priced usage in the caller's transaction. Never fails: billing
    /// problems must not fail the work being billed. A meter the tenant does not have yet is defined on the root
    /// tenant for the built-in keys (`inference`); other unknown meters are skipped.
    pub async fn record_priced(&self, tx: &Store, input: &Value) {
        // Billing never fails the work it bills.
        let _ = self.record_priced_or_fail(tx, input).await;
    }

    async fn record_priced_or_fail(&self, tx: &Store, input: &Value) -> IamResult<()> {
        let ctx = self.ctx()?;
        let input = Some(input);
        let Some(tenant_id) = member(input, "tenantId").and_then(Value::as_str) else {
            return Ok(());
        };
        let Some(tenant) = get_tenant(tx, tenant_id).await? else {
            return Ok(());
        };
        if tenant.status == TenantStatus::Deleted {
            return Ok(());
        }
        let chain = ctx.ancestry(tx, &tenant).await?;
        let key = crate::billing::meter_key(member(input, "meter"))?;
        // A built-in meter is always the platform's, even where a tenant defined a meter with its key.
        let meter = if is_built_in_meter(&key) {
            let root = &chain[chain.len().saturating_sub(1)..];
            match crate::billing::resolve_meter(tx, root, &key).await? {
                Some(meter) => Some(meter),
                None => self.built_in_meter(tx, &chain, &key).await?,
            }
        } else {
            crate::billing::resolve_meter(tx, &chain, &key).await?
        };
        let Some(meter) = meter.filter(|meter| !meter.archived) else {
            return Ok(());
        };
        let identity = match member(input, "identityId") {
            Some(value) => match value.as_str() {
                Some(identity_id) => tx.get("identities", identity_id).await?,
                None => None,
            },
            None => None,
        };
        let quantity = match member(input, "quantity") {
            None | Some(Value::Null) => 1.0,
            Some(value) => core_js::to_number(value),
        };
        let mut usage = Map::new();
        usage.insert("tenantId".into(), Value::String(tenant.id.clone()));
        usage.insert("meter".into(), Value::String(key.clone()));
        usage.insert("quantity".into(), num(js_max(0.0, quantity)));
        // Identities outside the tenant's ancestry (or gone) leave the usage unattributed.
        if let Some(identity) = &identity
            && str_of(identity, "status") != Some("deleted")
            && chain
                .iter()
                .any(|realm| Some(realm.id.as_str()) == str_of(identity, "tenantId"))
            && let Some(identity_id) = identity.get("id")
        {
            usage.insert("identityId".into(), identity_id.clone());
        }
        if let Some(tags) = member(input, "tags")
            && crate::js::truthy(Some(tags))
        {
            usage.insert("tags".into(), tags.clone());
        }
        if let Some(occurred_at) = member(input, "occurredAt") {
            usage.insert("occurredAt".into(), occurred_at.clone());
        }
        let cost_micros = if meter.pricing == "reported" {
            let cost = member(input, "costMicros")
                .map(core_js::to_number)
                .unwrap_or(f64::NAN);
            Some(js_max(0.0, cost))
        } else {
            None
        };
        let extra = RecordExtras {
            cost_micros,
            agent_id: member(input, "agentId")
                .and_then(Value::as_str)
                .map(str::to_owned),
            source_id: member(input, "sourceId")
                .and_then(Value::as_str)
                .map(str::to_owned),
            enforce_budgets: false,
            meter: Some(meter),
        };
        self.record(tx, &Value::Object(usage), "deployment", extra)
            .await?;
        Ok(())
    }

    /// Reads the teams and departments of the tenants in play, for filters, roll-ups and labels.
    async fn directory(
        &self,
        ctx: &Arc<ServerContext>,
        tx: &Store,
        rows: &[ChargedRow],
        extra: &[String],
    ) -> IamResult<Directory> {
        let mut tenant_ids: IndexSet<String> = extra.iter().cloned().collect();
        for row in rows {
            tenant_ids.insert(row.tenant_id.clone());
        }
        // Teams and departments live in the person's tenant, often the organization above a project.
        for tenant_id in tenant_ids.clone() {
            for ancestor in ctx.ancestor_ids(tx, &tenant_id).await? {
                tenant_ids.insert(ancestor);
            }
        }
        crate::billing::directory_for(tx, &strings_value(tenant_ids)).await
    }

    /// `weigher(filters, dir, within)(row)`: the weight (0-1) with which a row counts under the filters.
    fn weigh(
        &self,
        filters: &Filters,
        dir: &Directory,
        within: Option<&IndexSet<String>>,
        row: &ChargedRow,
    ) -> IamResult<f64> {
        let roll_up = filters.roll_up != Some(false);
        if filters.billable_only == Some(true) && row.internal {
            return Ok(0.0);
        }
        if let Some(meter) = &filters.meter
            && row.meter != *meter
        {
            return Ok(0.0);
        }
        if let Some(within) = within
            && !within.contains(&row.tenant_id)
        {
            return Ok(0.0);
        }
        if let Some(identity_id) = &filters.identity_id
            && row.identity_id.as_ref() != Some(identity_id)
            && row.agent_id.as_ref() != Some(identity_id)
        {
            return Ok(0.0);
        }
        if let Some(department_id) = &filters.department_id
            && !crate::billing::in_department(row, department_id, dir, roll_up)?
        {
            return Ok(0.0);
        }
        if let Some(team_id) = &filters.team_id {
            return crate::billing::team_share(row, team_id, dir, self.settings()?, roll_up);
        }
        Ok(1.0)
    }

    /// `validateFilters(tx, scope, input)`: the filters and the tenants a `subTenantId` narrows to.
    async fn validate_filters(
        &self,
        ctx: &Arc<ServerContext>,
        tx: &Store,
        scope: &Tenant,
        input: Option<&Value>,
    ) -> IamResult<(Filters, Option<IndexSet<String>>)> {
        let mut filters = Filters::default();
        if let Some(value) = member(input, "meter") {
            filters.meter = Some(crate::billing::meter_key(Some(value))?);
        }
        if let Some(value) = member(input, "identityId") {
            filters.identity_id = Some(text(Some(value), "identityId", 256)?);
        }
        if let Some(value) = member(input, "rollUp") {
            let Value::Bool(flag) = value else {
                return Err(IamError::new("INVALID_INPUT", "rollUp must be a boolean"));
            };
            filters.roll_up = Some(*flag);
        }
        if let Some(value) = member(input, "billableOnly") {
            let Value::Bool(flag) = value else {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "billableOnly must be a boolean",
                ));
            };
            filters.billable_only = Some(*flag);
        }
        let mut tenants: Option<IndexSet<String>> = None;
        // Teams and departments of the scope, or of the organization a project belongs to.
        if let Some(value) = member(input, "teamId") {
            let team_id = text(Some(value), "teamId", 256)?;
            let team = tx.get("teams", &team_id).await?;
            let mut found = None;
            if let Some(team) = team {
                let owner = str_of(&team, "tenantId").unwrap_or_default().to_owned();
                if tenants.is_none() {
                    tenants = Some(subtree_ids(ctx, tx, scope).await?);
                }
                let reachable = tenants.as_ref().is_some_and(|ids| ids.contains(&owner))
                    || ctx.ancestor_ids(tx, &scope.id).await?.contains(&owner);
                if reachable {
                    found = str_of(&team, "id").map(str::to_owned);
                }
            }
            let Some(team_id) = found else {
                return Err(IamError::with_status("NOT_FOUND", "Team not found", 404));
            };
            filters.team_id = Some(team_id);
        }
        if let Some(value) = member(input, "departmentId") {
            let department_id = text(Some(value), "departmentId", 256)?;
            let department = tx.get("departments", &department_id).await?;
            let mut found = None;
            if let Some(department) = department {
                let owner = str_of(&department, "tenantId")
                    .unwrap_or_default()
                    .to_owned();
                if tenants.is_none() {
                    tenants = Some(subtree_ids(ctx, tx, scope).await?);
                }
                let reachable = tenants.as_ref().is_some_and(|ids| ids.contains(&owner))
                    || ctx.ancestor_ids(tx, &scope.id).await?.contains(&owner);
                if reachable {
                    found = str_of(&department, "id").map(str::to_owned);
                }
            }
            let Some(department_id) = found else {
                return Err(IamError::with_status(
                    "NOT_FOUND",
                    "Department not found",
                    404,
                ));
            };
            filters.department_id = Some(department_id);
        }
        let mut within: Option<IndexSet<String>> = None;
        if let Some(value) = member(input, "subTenantId") {
            let sub = ctx
                .tenant(tx, &text(Some(value), "subTenantId", 256)?)
                .await?;
            if tenants.is_none() {
                tenants = Some(subtree_ids(ctx, tx, scope).await?);
            }
            if !tenants.as_ref().is_some_and(|ids| ids.contains(&sub.id)) {
                return Err(IamError::with_status("NOT_FOUND", "Tenant not found", 404));
            }
            within = Some(subtree_ids(ctx, tx, &sub).await?);
        }
        Ok((filters, within))
    }

    /// Labels for report keys.
    async fn label_for(
        &self,
        tx: &Store,
        group_by: &str,
        key: &str,
        dir: &Directory,
        meter_names: &IndexMap<String, String>,
    ) -> IamResult<Option<String>> {
        if key.starts_with('(') {
            return Ok(None);
        }
        Ok(match group_by {
            "identity" | "agent" => {
                let Some(identity) = tx.get("identities", key).await? else {
                    return Ok(None);
                };
                let name = str_of(&identity, "name").unwrap_or_default();
                match str_of(&identity, "email").filter(|email| !email.is_empty()) {
                    Some(email) => Some(format!("{name} <{email}>")),
                    None => identity
                        .get("name")
                        .map(|name| crate::js::js_string(Some(name))),
                }
            }
            "team" => dir.teams.get(key).map(|team| team.name.clone()),
            "department" => dir.departments.get(key).map(|department| {
                match department.code.as_deref().filter(|code| !code.is_empty()) {
                    Some(code) => format!("{} ({code})", department.name),
                    None => department.name.clone(),
                }
            }),
            "tenant" => name_in(tx, "tenants", key).await?,
            "meter" => meter_names.get(key).cloned(),
            _ => None,
        })
    }

    fn forecast_of(&self, period: &str, total_micros: f64) -> IamResult<Option<Value>> {
        if period != self.current_period()? {
            return Ok(None);
        }
        let ctx = self.ctx()?;
        let (start, end) = period_bounds(period, &self.settings()?.time_zone)?;
        let elapsed = ctx.now() - start;
        if elapsed < DAY_MS {
            return Ok(None);
        }
        let cost_micros = crate::billing::round_micros(total_micros * (end - start) / elapsed)?;
        Ok(Some(json!({
            "costMicros": num(cost_micros),
            "amount": num(crate::billing::units_of(cost_micros)?),
        })))
    }

    /// Weighted rows of a scope and period under validated filters.
    #[allow(clippy::too_many_arguments)]
    async fn weighted_rows(
        &self,
        ctx: &Arc<ServerContext>,
        tx: &Store,
        scope: &Tenant,
        period: &str,
        input: Option<&Value>,
        cache: &SpendCache,
        row_filter: Option<RowFilter<'_>>,
    ) -> IamResult<(Vec<(ChargedRow, f64)>, Directory, Filters)> {
        let (filters, within) = self.validate_filters(ctx, tx, scope, input).await?;
        let (rows, _) = scope_spend(ctx, tx, scope, period, cache).await?;
        let dir = self
            .directory(ctx, tx, &rows, std::slice::from_ref(&scope.id))
            .await?;
        let mut weighted: Vec<(ChargedRow, f64)> = Vec::new();
        for row in rows {
            if let Some(row_filter) = row_filter
                && !row_filter(&row)
            {
                continue;
            }
            let weight = self.weigh(&filters, &dir, within.as_ref(), &row)?;
            if weight > 0.0 {
                weighted.push((row, weight));
            }
        }
        Ok((weighted, dir, filters))
    }

    /// `report(tx, scope, query, cache, rowFilter)`: a spend report for a tenant's subtree (`SpendQuery` as JSON).
    pub async fn report(
        &self,
        tx: &Store,
        scope: &Tenant,
        query: &Value,
        cache: Option<&SpendCache>,
        row_filter: Option<RowFilter<'_>>,
    ) -> IamResult<SpendReport> {
        use crate::billing::{round_micros, units_of};
        let ctx = self.ctx()?;
        let settings = self.settings()?;
        let own_cache = SpendCache::default();
        let cache = cache.unwrap_or(&own_cache);
        let query = Some(query);
        let period = match member(query, "period") {
            None => self.current_period()?,
            Some(value) => crate::billing::billing_period(Some(value), None)?,
        };
        let group_by = match member(query, "groupBy") {
            None | Some(Value::Null) => "meter".to_owned(),
            Some(value) => spend_group_by(Some(value))?,
        };
        let (weighted, dir, filters) = self
            .weighted_rows(&ctx, tx, scope, &period, query, cache, row_filter)
            .await?;
        let mut groups: IndexMap<String, Group> = IndexMap::new();
        fn add(groups: &mut IndexMap<String, Group>, key: &str, row: &ChargedRow, weight: f64) {
            let group = groups.entry(key.to_owned()).or_insert_with(|| Group {
                key: key.to_owned(),
                cost_micros: 0.0,
                events: 0.0,
                quantities: IndexMap::new(),
                shared_micros: None,
            });
            group.cost_micros += row.cost_micros * weight;
            group.events += row.events;
            *group.quantities.entry(row.meter.clone()).or_insert(0.0) += row.quantity * weight;
        }
        // Grouping by team under a team filter keeps to the filter's teams.
        let allowed_teams: Option<IndexSet<String>> = filters.team_id.as_ref().map(|team_id| {
            let mut allowed: IndexSet<String> = IndexSet::new();
            allowed.insert(team_id.clone());
            if filters.roll_up != Some(false) {
                for team in crate::teams::team_descendants_of(dir.teams.values(), team_id) {
                    allowed.insert(team.id);
                }
            }
            allowed
        });
        let mut total_micros = 0.0;
        let mut events = 0.0;
        for (row, weight) in &weighted {
            total_micros += row.cost_micros * weight;
            events += row.events;
            match group_by.as_str() {
                "team" => {
                    let teams: Vec<&String> = row
                        .team_ids
                        .iter()
                        .filter(|team| {
                            allowed_teams
                                .as_ref()
                                .is_none_or(|allowed| allowed.contains(*team))
                        })
                        .collect();
                    if row.team_ids.is_empty() {
                        add(&mut groups, UNATTRIBUTED_TEAM, row, *weight);
                    }
                    let each = if settings.team_attribution == "full" {
                        1.0
                    } else {
                        1.0 / row.team_ids.len() as f64
                    };
                    for team in teams {
                        add(&mut groups, team, row, each);
                    }
                }
                "meter" => add(&mut groups, &row.meter, row, *weight),
                "identity" => add(
                    &mut groups,
                    row.identity_id.as_deref().unwrap_or(UNATTRIBUTED_IDENTITY),
                    row,
                    *weight,
                ),
                "agent" => add(
                    &mut groups,
                    row.agent_id.as_deref().unwrap_or(UNATTRIBUTED_AGENT),
                    row,
                    *weight,
                ),
                "department" => add(
                    &mut groups,
                    row.department_id
                        .as_deref()
                        .unwrap_or(UNATTRIBUTED_DEPARTMENT),
                    row,
                    *weight,
                ),
                "tenant" => add(&mut groups, &row.tenant_id, row, *weight),
                "day" => add(&mut groups, &row.day, row, *weight),
                _ => {
                    let tag = row
                        .tags
                        .as_ref()
                        .and_then(|tags| tags.get(&group_by[4..]))
                        .cloned()
                        .unwrap_or_else(|| UNATTRIBUTED_TAG.to_owned());
                    add(&mut groups, &tag, row, *weight);
                }
            }
        }
        total_micros = round_micros(total_micros)?;
        let mut meter_names: IndexMap<String, String> = IndexMap::new();
        if group_by == "meter" {
            for (row, _) in &weighted {
                if !meter_names.contains_key(&row.meter)
                    && let Some(name) = name_in(tx, METERS, &row.meter_id).await?
                {
                    meter_names.insert(row.meter.clone(), name);
                }
            }
        }
        // Shared costs: what no person, team or department used is spread over those that did, by their share of
        // spend.
        let mut shared_micros: Option<f64> = None;
        let pool = match group_by.as_str() {
            "identity" => Some(UNATTRIBUTED_IDENTITY),
            "agent" => Some(UNATTRIBUTED_AGENT),
            "team" => Some(UNATTRIBUTED_TEAM),
            "department" => Some(UNATTRIBUTED_DEPARTMENT),
            _ => None,
        };
        let share_unattributed = member(query, "shareUnattributed");
        if let (Some(Value::Bool(true)), Some(pool)) = (share_unattributed, pool)
            && groups.contains_key(pool)
        {
            let unassigned = groups
                .get(pool)
                .map(|group| group.cost_micros)
                .unwrap_or(0.0);
            let base: f64 = groups
                .values()
                .filter(|group| group.key != pool)
                .map(|group| group.cost_micros)
                .sum();
            if base > 0.0 {
                for group in groups.values_mut().filter(|group| group.key != pool) {
                    let extra = unassigned * group.cost_micros / base;
                    group.cost_micros += extra;
                    group.shared_micros = Some(round_micros(extra)?);
                }
                shared_micros = Some(round_micros(unassigned)?);
                groups.shift_remove(pool);
            }
        } else if let Some(value) = share_unattributed
            && !matches!(value, Value::Bool(_))
        {
            return Err(IamError::new(
                "INVALID_INPUT",
                "shareUnattributed must be a boolean",
            ));
        }
        let mut rows: Vec<(String, f64, Value)> = Vec::new();
        for group in groups.into_values() {
            let cost_micros = round_micros(group.cost_micros)?;
            let mut row = Map::new();
            row.insert("key".into(), Value::String(group.key.clone()));
            row.insert("costMicros".into(), num(cost_micros));
            row.insert("amount".into(), num(units_of(cost_micros)?));
            row.insert(
                "share".into(),
                num(if total_micros > 0.0 {
                    one_decimal(cost_micros / total_micros * 100.0)
                } else {
                    0.0
                }),
            );
            row.insert("events".into(), num(group.events));
            row.insert(
                "quantities".into(),
                Value::Object(
                    group
                        .quantities
                        .iter()
                        .map(|(meter, quantity)| {
                            (meter.clone(), num(js_round(quantity * 1e6) / 1e6))
                        })
                        .collect(),
                ),
            );
            if let Some(shared) = group.shared_micros {
                row.insert("sharedMicros".into(), num(shared));
            }
            if let Some(label) = self
                .label_for(tx, &group_by, &group.key, &dir, &meter_names)
                .await?
            {
                row.insert("label".into(), Value::String(label));
            }
            rows.push((group.key, cost_micros, Value::Object(row)));
        }
        rows.sort_by(|a, b| by_difference(b.1 - a.1, || a.0.cmp(&b.0)));
        if group_by == "day" {
            rows.sort_by(|a, b| a.0.cmp(&b.0));
        }
        let (start, end) = period_bounds(&period, &settings.time_zone)?;
        let forecast = self.forecast_of(&period, total_micros)?;
        Ok(SpendReport {
            tenant_id: scope.id.clone(),
            currency: settings.currency.clone(),
            period,
            period_start: start,
            period_end: end,
            group_by: Value::String(group_by),
            rows: rows.into_iter().map(|(_, _, row)| row).collect(),
            total: json!({
                "costMicros": num(total_micros),
                "amount": num(units_of(total_micros)?),
                "events": num(events),
            }),
            forecast,
            shared_micros,
            extra: Map::new(),
        })
    }

    /// `trend(tx, scope, input, rowFilter)`: monthly totals for the last `months` (default 6, at most 24) periods.
    pub async fn trend(
        &self,
        tx: &Store,
        scope: &Tenant,
        input: &Value,
        row_filter: Option<RowFilter<'_>>,
    ) -> IamResult<SpendTrend> {
        let settings = self.settings()?;
        let months = match member(Some(input), "months") {
            None => 6.0,
            Some(value) => integer(Some(value), "months", 1.0, 24.0)?,
        };
        let cache = SpendCache::default();
        let current = self.current_period()?;
        let mut result: Vec<Value> = Vec::new();
        let mut last: Option<SpendReport> = None;
        let mut index = months - 1.0;
        while index >= 0.0 {
            let mut query = object_of(Some(input));
            query.insert(
                "period".into(),
                Value::String(crate::billing::shift_period(&current, -index)?),
            );
            query.insert("groupBy".into(), Value::String("meter".into()));
            let report = self
                .report(tx, scope, &Value::Object(query), Some(&cache), row_filter)
                .await?;
            result.push(json!({
                "period": report.period,
                "costMicros": report.total.get("costMicros").cloned().unwrap_or(Value::Null),
                "amount": report.total.get("amount").cloned().unwrap_or(Value::Null),
            }));
            last = Some(report);
            index -= 1.0;
        }
        Ok(SpendTrend {
            tenant_id: scope.id.clone(),
            currency: settings.currency.clone(),
            months: result,
            forecast: last.and_then(|report| report.forecast),
            extra: Map::new(),
        })
    }
}

/// `allocations(rows, keyOf, names, limit)`: spend per key, largest first.
fn allocations(
    rows: &[ChargedRow],
    key_of: impl Fn(&ChargedRow) -> Vec<(String, f64)>,
    names: impl Fn(&str) -> Option<String>,
    limit: Option<usize>,
) -> IamResult<Vec<Map<String, Value>>> {
    let mut totals: IndexMap<String, f64> = IndexMap::new();
    for row in rows {
        for (key, weight) in key_of(row) {
            *totals.entry(key).or_insert(0.0) += row.cost_micros * weight;
        }
    }
    let mut list: Vec<(String, f64, Map<String, Value>)> = Vec::new();
    for (key, micros) in totals {
        let cost_micros = crate::billing::round_micros(micros)?;
        if cost_micros <= 0.0 || cost_micros.is_nan() {
            continue;
        }
        let mut entry = Map::new();
        entry.insert("id".into(), Value::String(key.clone()));
        entry.insert(
            "name".into(),
            Value::String(names(&key).unwrap_or_else(|| key.clone())),
        );
        entry.insert("costMicros".into(), num(cost_micros));
        list.push((key, cost_micros, entry));
    }
    list.sort_by(|a, b| by_difference(b.1 - a.1, || a.0.cmp(&b.0)));
    let entries = list.into_iter().map(|(_, _, entry)| entry);
    Ok(match limit {
        Some(limit) => entries.take(limit).collect(),
        None => entries.collect(),
    })
}

/// `invoiceItemLine(item)`: an invoice line for a pending invoice item.
fn invoice_item_line(item: &Record) -> Value {
    let mut line = Map::new();
    line.insert("kind".into(), Value::String("item".into()));
    line.insert(
        "name".into(),
        item.get("description").cloned().unwrap_or(Value::Null),
    );
    line.insert("unit".into(), Value::String("unit".into()));
    line.insert(
        "quantity".into(),
        item.get("quantity").cloned().unwrap_or(Value::Null),
    );
    line.insert(
        "unitAmountMicros".into(),
        item.get("unitAmountMicros").cloned().unwrap_or(Value::Null),
    );
    line.insert(
        "amountMicros".into(),
        item.get("amountMicros").cloned().unwrap_or(Value::Null),
    );
    line.insert(
        "invoiceItemId".into(),
        item.get("id").cloned().unwrap_or(Value::Null),
    );
    if let Some(subscription_id) = item.get("subscriptionId") {
        line.insert("subscriptionId".into(), subscription_id.clone());
    }
    if str_of(item, "source") == Some("proration") {
        line.insert("description".into(), Value::String("Proration".into()));
    }
    Value::Object(line)
}

/// The members of a draft that are not part of the invoice body.
const DRAFT_ONLY: [&str; 5] = [
    "accountId",
    "paymentTermsDays",
    "carryForwardMicros",
    "invoiceItemIds",
    "advanceBilled",
];

fn draft_body(draft: &Record) -> Record {
    draft
        .iter()
        .filter(|(key, _)| !DRAFT_ONLY.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn non_empty_array(record: &Record, key: &str) -> Option<Value> {
    record
        .get(key)
        .filter(|value| value.as_array().is_some_and(|items| !items.is_empty()))
        .cloned()
}

/// `billable(draft)`: whether a monthly invoice has something to bill: lines, or a minimum commitment the month fell
/// short of.
fn billable(draft: &Record) -> bool {
    let lines = draft
        .get("lines")
        .and_then(Value::as_array)
        .is_some_and(|lines| !lines.is_empty());
    let true_up = member(draft.get("commitment"), "trueUpMicros")
        .and_then(core_js::as_number)
        .unwrap_or(0.0);
    lines || true_up > 0.0
}

impl BillingService {
    // -----------------------------------------------------------------------------------------------------------
    // Budgets

    async fn subject_name(
        &self,
        tx: &Store,
        subject_type: &str,
        subject_id: &str,
    ) -> IamResult<Option<String>> {
        match subject_type {
            "tenant" => name_in(tx, "tenants", subject_id).await,
            "identity" => name_in(tx, "identities", subject_id).await,
            "team" => name_in(tx, "teams", subject_id).await,
            "department" => name_in(tx, "departments", subject_id).await,
            _ => Ok(None),
        }
    }

    /// `budgetStatus(tx, budget, cache)`: a budget with its spend in the current window.
    pub async fn budget_status(
        &self,
        tx: &Store,
        budget: &Record,
        cache: Option<&SpendCache>,
    ) -> IamResult<BudgetStatus> {
        use crate::billing::{round_micros, units_of};
        let ctx = self.ctx()?;
        let settings = self.settings()?;
        let tz = settings.time_zone.as_str();
        let own_cache = SpendCache::default();
        let cache = cache.unwrap_or(&own_cache);
        let current = self.current_period()?;
        let periods =
            crate::billing::window_periods(budget.get("period").unwrap_or(&Value::Null), &current)?;
        let owner = ctx
            .tenant(tx, str_of(budget, "tenantId").unwrap_or_default())
            .await?;
        let subject_type = str_of(budget, "subjectType").unwrap_or_default();
        let subject_id = str_of(budget, "subjectId").unwrap_or_default();
        let scope = if subject_type == "tenant" {
            get_tenant(tx, subject_id)
                .await?
                .unwrap_or_else(|| owner.clone())
        } else {
            owner.clone()
        };
        let meters: Option<Vec<String>> = budget
            .get("meters")
            .filter(|value| value.is_array())
            .map(|_| strings_of(budget, "meters"));
        let amount_micros = num_of(budget, "amountMicros").unwrap_or(f64::NAN);
        let mut spent = 0.0;
        for period in &periods {
            if *period > current {
                break;
            }
            let (rows, accounts) = scope_spend(&ctx, tx, &scope, period, cache).await?;
            // Chargeback meters an account defines and prices for itself count toward its own budgets, never toward
            // budgets set above it (the platform's), which an organization could otherwise spend with made-up prices.
            // The scope's rows are the accounts' rows in scope, in order: rows are matched to their account by walking
            // both lists together.
            let mut foreign: IndexSet<usize> = IndexSet::new();
            let mut cursor = 0;
            for spend in &accounts {
                let below = spend.account_id != owner.id
                    && ctx
                        .ancestor_ids(tx, &spend.account_id)
                        .await?
                        .contains(&owner.id);
                for row in &spend.rows {
                    if cursor < rows.len() && rows[cursor] == *row {
                        if below && row.internal {
                            foreign.insert(cursor);
                        }
                        cursor += 1;
                    }
                }
            }
            let dir = if subject_type == "team" || subject_type == "department" {
                Some(
                    self.directory(&ctx, tx, &rows, std::slice::from_ref(&owner.id))
                        .await?,
                )
            } else {
                None
            };
            for (index, row) in rows.iter().enumerate() {
                if let Some(meters) = &meters
                    && !meters.contains(&row.meter)
                {
                    continue;
                }
                if foreign.contains(&index) {
                    continue;
                }
                let weight = match subject_type {
                    "tenant" => 1.0,
                    "identity" => {
                        if row.identity_id.as_deref() == Some(subject_id)
                            || row.agent_id.as_deref() == Some(subject_id)
                        {
                            1.0
                        } else {
                            0.0
                        }
                    }
                    "team" => crate::billing::team_share(
                        row,
                        subject_id,
                        dir.as_ref().expect("directory of a team budget"),
                        settings,
                        true,
                    )?,
                    _ => {
                        if crate::billing::in_department(
                            row,
                            subject_id,
                            dir.as_ref().expect("directory of a department budget"),
                            true,
                        )? {
                            1.0
                        } else {
                            0.0
                        }
                    }
                };
                spent += row.cost_micros * weight;
            }
        }
        let spent_micros = round_micros(spent)?;
        let window_start = periods.first().cloned().unwrap_or_default();
        let window_end = periods.last().cloned().unwrap_or_default();
        let (start, _) = period_bounds(&window_start, tz)?;
        let (_, end) = period_bounds(&window_end, tz)?;
        let elapsed = ctx.now() - start;
        let forecast_micros = if elapsed >= DAY_MS {
            Some(round_micros(spent_micros * (end - start) / elapsed)?)
        } else {
            None
        };
        let percent = one_decimal(spent_micros / amount_micros * 100.0);
        let name = self.subject_name(tx, subject_type, subject_id).await?;
        let thresholds: Vec<f64> = budget
            .get("thresholds")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(core_js::as_number).collect())
            .unwrap_or_default();
        let reached = thresholds
            .iter()
            .copied()
            .filter(|threshold| spent_micros >= amount_micros * threshold / 100.0)
            .collect();
        Ok(BudgetStatus {
            budget_id: str_of(budget, "id").unwrap_or_default().to_owned(),
            tenant_id: str_of(budget, "tenantId").unwrap_or_default().to_owned(),
            name: str_of(budget, "name").unwrap_or_default().to_owned(),
            subject_type: budget.get("subjectType").cloned().unwrap_or(Value::Null),
            subject_id: subject_id.to_owned(),
            subject_name: name,
            period: budget.get("period").cloned().unwrap_or(Value::Null),
            window_start,
            window_end,
            amount_micros,
            amount: units_of(amount_micros)?,
            spent_micros,
            spent: units_of(spent_micros)?,
            percent,
            forecast_micros,
            forecast_percent: forecast_micros
                .map(|forecast| one_decimal(forecast / amount_micros * 100.0)),
            thresholds,
            reached,
            exceeded: spent_micros >= amount_micros,
            enforce: bool_of(budget, "enforce"),
            meters,
            extra: Map::new(),
        })
    }

    /// Budget status for enforcement, cached briefly so checks on hot paths stay cheap.
    async fn cached_status(
        &self,
        tx: &Store,
        budget: &Record,
        cache: &SpendCache,
    ) -> IamResult<BudgetStatus> {
        let ctx = self.ctx()?;
        let budget_id = str_of(budget, "id").unwrap_or_default().to_owned();
        let updated_at = num_of(budget, "updatedAt");
        let now = ctx.now();
        {
            let entries = self
                .status_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(hit) = entries.get(&budget_id)
                && hit.updated_at == updated_at
                && now - hit.at < STATUS_CACHE_MS
            {
                return Ok(hit.status.clone());
            }
        }
        let status = self.budget_status(tx, budget, Some(cache)).await?;
        let mut entries = self
            .status_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.insert(
            budget_id,
            CachedStatus {
                at: now,
                updated_at,
                status: status.clone(),
            },
        );
        if entries.len() > 10_000 {
            entries.shift_remove_index(0);
        }
        Ok(status)
    }

    /// `check(tx, tenant, { identityId?, meter? })`: the enforced budgets covering usage in `tenant` (by `identityId`,
    /// of `meter`): tenant budgets on the tenant or an ancestor, the person's own budgets, and budgets of their teams
    /// (and parent teams) and departments. Refused once one is spent. Statuses may lag recorded usage by up to 30
    /// seconds.
    pub async fn check(&self, tx: &Store, tenant: &Tenant, input: &Value) -> IamResult<SpendCheck> {
        let input = Some(input);
        let statuses = self
            .covering_statuses(
                tx,
                tenant,
                member(input, "identityId"),
                member(input, "meter"),
                true,
            )
            .await?;
        let blocked_by = statuses.iter().find(|status| status.exceeded).cloned();
        Ok(SpendCheck {
            allowed: blocked_by.is_none(),
            budgets: statuses,
            blocked_by,
            extra: Map::new(),
        })
    }

    /// The (cached) standing of every budget covering usage in `tenant` by `identityId` (of `meter`).
    async fn covering_statuses(
        &self,
        tx: &Store,
        tenant: &Tenant,
        identity_id: Option<&Value>,
        meter: Option<&Value>,
        enforced_only: bool,
    ) -> IamResult<Vec<BudgetStatus>> {
        let ctx = self.ctx()?;
        let chain = ctx.ancestry(tx, tenant).await?;
        let chain_ids: IndexSet<String> = chain.iter().map(|realm| realm.id.clone()).collect();
        let mut identity_ids: Vec<String> = Vec::new();
        let mut teams: Vec<String> = Vec::new();
        let mut departments: Vec<String> = Vec::new();
        if let Some(value) = identity_id {
            let identity_id = text(Some(value), "identityId", 256)?;
            if let Some(identity) = tx.get("identities", &identity_id).await? {
                let own_id = str_of(&identity, "id").unwrap_or_default().to_owned();
                let sponsor = member(identity.get("agent"), "sponsorId")
                    .and_then(Value::as_str)
                    .filter(|sponsor| !sponsor.is_empty());
                let person = match sponsor {
                    Some(sponsor) if str_of(&identity, "kind") == Some("agent") => {
                        sponsor.to_owned()
                    }
                    _ => own_id.clone(),
                };
                identity_ids = vec![own_id.clone()];
                if person != own_id {
                    identity_ids.push(person.clone());
                }
                let home = str_of(&identity, "tenantId").unwrap_or_default().to_owned();
                teams =
                    crate::teams::teams_of_at(tx, &home, &person, Some(ctx.now()), true).await?;
                if let Some(department_id) = crate::departments::department_of(tx, &home, &person)
                    .await?
                    .filter(|department| !department.is_empty())
                {
                    departments =
                        crate::departments::department_path(tx, &home, &department_id).await?;
                }
            }
        }
        let meter = match meter {
            None => None,
            Some(value) => Some(crate::billing::meter_key(Some(value))?),
        };
        let cache = SpendCache::default();
        let mut statuses: Vec<BudgetStatus> = Vec::new();
        for realm in &chain {
            let filter = if enforced_only {
                Filter::new()
                    .eq("tenantId", realm.id.as_str())
                    .eq("enforce", true)
            } else {
                Filter::new().eq("tenantId", realm.id.as_str())
            };
            for budget in find_all(tx, BUDGETS, filter).await? {
                if let (Some(Value::Array(_)), Some(meter)) = (budget.get("meters"), &meter)
                    && !strings_of(&budget, "meters").contains(meter)
                {
                    continue;
                }
                let subject_id = str_of(&budget, "subjectId").unwrap_or_default().to_owned();
                let covers = match str_of(&budget, "subjectType").unwrap_or_default() {
                    "tenant" => chain_ids.contains(&subject_id),
                    "identity" => identity_ids.contains(&subject_id),
                    "team" => teams.contains(&subject_id),
                    _ => departments.contains(&subject_id),
                };
                if covers {
                    statuses.push(self.cached_status(tx, &budget, &cache).await?);
                }
            }
        }
        Ok(statuses)
    }

    /// `spendContext(tx, tenant, identityId?)`: policy context. `principal.budgetsExceeded` names every spent budget
    /// that covers the principal in `tenant` (tenant budgets up the tree, and for a person of the tenant their own,
    /// their teams' and their department's), and `principal.spendExceeded` is true when one of them is enforced.
    /// Statuses may lag usage by up to 30 seconds.
    pub async fn spend_context(
        &self,
        tx: &Store,
        tenant: &Tenant,
        identity_id: Option<&str>,
    ) -> IamResult<Map<String, Value>> {
        let identity = identity_id.map(|identity_id| Value::String(identity_id.to_owned()));
        let exceeded: Vec<BudgetStatus> = self
            .covering_statuses(tx, tenant, identity.as_ref(), None, false)
            .await?
            .into_iter()
            .filter(|status| status.exceeded)
            .collect();
        let mut names: Vec<String> = Vec::new();
        for status in &exceeded {
            if !names.contains(&status.name) {
                names.push(status.name.clone());
            }
        }
        crate::js::sort_strings(&mut names);
        let mut context = Map::new();
        context.insert(
            "principal.spendExceeded".into(),
            Value::Bool(exceeded.iter().any(|status| status.enforce)),
        );
        context.insert("principal.budgetsExceeded".into(), strings_value(names));
        Ok(context)
    }

    async fn emails_of(&self, tx: &Store, identity_ids: &[String]) -> IamResult<Vec<String>> {
        let mut result = Vec::new();
        for identity_id in identity_ids {
            if let Some(identity) = tx.get("identities", identity_id).await?
                && str_of(&identity, "status") == Some("active")
                && let Some(email) = str_of(&identity, "email").filter(|email| !email.is_empty())
            {
                result.push(email.to_owned());
            }
        }
        Ok(result)
    }

    async fn owners(&self, tx: &Store, tenant_id: &str) -> IamResult<Vec<String>> {
        Ok(find_all(
            tx,
            "identities",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("owner", true)
                .eq("status", "active"),
        )
        .await?
        .iter()
        .filter_map(|owner| str_of(owner, "email").filter(|email| !email.is_empty()))
        .map(str::to_owned)
        .collect())
    }

    async fn budget_recipients(&self, tx: &Store, budget: &Record) -> IamResult<Vec<String>> {
        let ctx = self.ctx()?;
        let notify = object_of(budget.get("notify"));
        let mut addresses: IndexSet<String> = strings_of(&notify, "emails").into_iter().collect();
        if crate::js::truthy(notify.get("owners")) {
            for address in self
                .owners(tx, str_of(budget, "tenantId").unwrap_or_default())
                .await?
            {
                addresses.insert(address);
            }
        }
        if crate::js::truthy(notify.get("subject")) {
            let subject_id = str_of(budget, "subjectId").unwrap_or_default();
            let mut subject_ids: Vec<String> = Vec::new();
            match str_of(budget, "subjectType").unwrap_or_default() {
                "identity" => subject_ids.push(subject_id.to_owned()),
                "team" => {
                    if let Some(team) = tx.get("teams", subject_id).await? {
                        subject_ids.extend(
                            crate::teams::team_maintainers(
                                tx,
                                str_of(&team, "tenantId").unwrap_or_default(),
                                str_of(&team, "id").unwrap_or_default(),
                                Some(ctx.now()),
                            )
                            .await?,
                        );
                    }
                }
                "department" => {
                    if let Some(department) = tx.get("departments", subject_id).await? {
                        subject_ids.extend(
                            crate::departments::department_heads_of(
                                tx,
                                str_of(&department, "tenantId").unwrap_or_default(),
                                str_of(&department, "id").unwrap_or_default(),
                                false,
                            )
                            .await?,
                        );
                    }
                }
                _ => {}
            }
            for address in self.emails_of(tx, &subject_ids).await? {
                addresses.insert(address);
            }
        }
        let mut sorted: Vec<String> = addresses.into_iter().collect();
        crate::js::sort_strings(&mut sorted);
        Ok(sorted)
    }

    /// `checkBudgets({ tenantId? })`: alerts on budgets: every threshold reached in the current window (once each), and
    /// a forecast alert when the projection passes 100%. Each alert is audited as `billing:budget-alert` (webhooks can
    /// forward it) and, with an email transport, sent to the budget's recipients as `spend-alert`. A scheduler job;
    /// `tenantId` limits it to the budgets that tenant owns. Answers `BudgetAlertResult` as JSON.
    pub async fn check_budgets(&self, input: Option<&Value>) -> IamResult<Value> {
        let ctx = self.ctx()?;
        let settings = self.settings()?;
        let tenant_id = member(input, "tenantId").cloned();
        let mut budgets: Vec<Record> = ctx
            .store
            .transaction(move |tx| async move {
                let filter = match &tenant_id {
                    None => Filter::new(),
                    Some(value) => {
                        Filter::new().eq("tenantId", text(Some(value), "tenantId", 256)?)
                    }
                };
                find_all(&tx, BUDGETS, filter).await
            })
            .await?;
        budgets.sort_by(|a, b| {
            str_of(a, "id")
                .unwrap_or_default()
                .cmp(str_of(b, "id").unwrap_or_default())
        });
        let mut checked = 0.0;
        let mut alerts: Vec<Value> = Vec::new();
        let cache = SpendCache::default();
        for candidate in budgets {
            let candidate_id = str_of(&candidate, "id").unwrap_or_default().to_owned();
            let cache = &cache;
            let ctx_ref = &ctx;
            let outcome: Option<Vec<Value>> = ctx
                .store
                .transaction(move |tx| async move {
                    let Some(budget) = tx.get(BUDGETS, &candidate_id).await? else {
                        return Ok(None);
                    };
                    let budget_tenant = str_of(&budget, "tenantId").unwrap_or_default().to_owned();
                    let budget_id = str_of(&budget, "id").unwrap_or_default().to_owned();
                    let budget_name = str_of(&budget, "name").unwrap_or_default().to_owned();
                    let owner = get_tenant(&tx, &budget_tenant).await?;
                    // Pending and suspended tenants can still spend; only deleted ones are done.
                    let Some(owner) = owner.filter(|owner| owner.status != TenantStatus::Deleted)
                    else {
                        return Ok(None);
                    };
                    let status = self.budget_status(&tx, &budget, Some(cache)).await?;
                    let mut due: Vec<(&str, f64)> = status
                        .reached
                        .iter()
                        .map(|threshold| ("actual", *threshold))
                        .collect();
                    if crate::js::truthy(budget.get("forecastAlerts"))
                        && !status.exceeded
                        && status.forecast_percent.unwrap_or(0.0) >= 100.0
                    {
                        due.push(("forecast", 100.0));
                    }
                    let mut fired: Vec<(&str, f64)> = Vec::new();
                    for (kind, threshold) in due {
                        let unique_key = format!(
                            "{budget_id}:{}:{kind}:{}",
                            status.window_start,
                            core_js::number_to_string(threshold)
                        );
                        if !find_all(
                            &tx,
                            ALERTS,
                            Filter::new()
                                .eq("tenantId", budget_tenant.as_str())
                                .eq("uniqueKey", unique_key.as_str()),
                        )
                        .await?
                        .is_empty()
                        {
                            continue;
                        }
                        let mut alert = Record::new();
                        alert.insert("id".into(), Value::String(id()));
                        alert.insert("tenantId".into(), Value::String(budget_tenant.clone()));
                        alert.insert("uniqueKey".into(), Value::String(unique_key));
                        alert.insert("budgetId".into(), Value::String(budget_id.clone()));
                        alert.insert("window".into(), Value::String(status.window_start.clone()));
                        alert.insert("kind".into(), Value::String(kind.to_owned()));
                        alert.insert("threshold".into(), num(threshold));
                        alert.insert("spentMicros".into(), num(status.spent_micros));
                        alert.insert("alertedAt".into(), num(ctx_ref.now()));
                        tx.insert(ALERTS, &alert).await?;
                        fired.push((kind, threshold));
                    }
                    if fired.is_empty() {
                        return Ok(Some(Vec::new()));
                    }
                    let recipients = if sends_email(ctx_ref) {
                        self.budget_recipients(&tx, &budget).await?
                    } else {
                        Vec::new()
                    };
                    // One email per check: the highest threshold newly reached (or the forecast warning).
                    let mut actual: Vec<(&str, f64)> = fired
                        .iter()
                        .copied()
                        .filter(|(kind, _)| *kind == "actual")
                        .collect();
                    actual.sort_by(|a, b| by_difference(b.1 - a.1, || Ordering::Equal));
                    let headline = actual.first().copied().unwrap_or(fired[0]);
                    let amount_micros = num_of(&budget, "amountMicros").unwrap_or(f64::NAN);
                    for to in &recipients {
                        let mut payload = Map::new();
                        payload.insert("tenantId".into(), Value::String(budget_tenant.clone()));
                        payload.insert("tenantName".into(), Value::String(owner.name.clone()));
                        payload.insert("budgetId".into(), Value::String(budget_id.clone()));
                        payload.insert("budgetName".into(), Value::String(budget_name.clone()));
                        payload.insert(
                            "subjectType".into(),
                            budget.get("subjectType").cloned().unwrap_or(Value::Null),
                        );
                        payload.insert(
                            "subjectName".into(),
                            match &status.subject_name {
                                Some(name) => Value::String(name.clone()),
                                None => budget.get("subjectId").cloned().unwrap_or(Value::Null),
                            },
                        );
                        payload.insert("kind".into(), Value::String(headline.0.to_owned()));
                        payload.insert(
                            "threshold".into(),
                            Value::String(core_js::number_to_string(headline.1)),
                        );
                        payload.insert(
                            "percent".into(),
                            Value::String(core_js::number_to_string(status.percent)),
                        );
                        payload.insert(
                            "spent".into(),
                            Value::String(format_money(status.spent_micros, &settings.currency)?),
                        );
                        payload.insert(
                            "amount".into(),
                            Value::String(format_money(amount_micros, &settings.currency)?),
                        );
                        if let Some(forecast) = status.forecast_micros {
                            payload.insert(
                                "forecast".into(),
                                Value::String(format_money(forecast, &settings.currency)?),
                            );
                        }
                        payload.insert(
                            "windowStart".into(),
                            Value::String(status.window_start.clone()),
                        );
                        payload
                            .insert("windowEnd".into(), Value::String(status.window_end.clone()));
                        ctx_ref
                            .auth
                            .enqueue_delivery(
                                &tx,
                                email_input(&budget_tenant, to, "spend-alert", payload),
                            )
                            .await?;
                    }
                    let mut alerts = Vec::new();
                    for (kind, threshold) in fired {
                        let mut metadata = Map::new();
                        metadata.insert("budgetId".into(), Value::String(budget_id.clone()));
                        metadata.insert("name".into(), Value::String(budget_name.clone()));
                        metadata.insert("kind".into(), Value::String(kind.to_owned()));
                        metadata.insert("threshold".into(), num(threshold));
                        metadata.insert("spentMicros".into(), num(status.spent_micros));
                        metadata.insert("amountMicros".into(), num(amount_micros));
                        metadata
                            .insert("window".into(), Value::String(status.window_start.clone()));
                        metadata.insert("recipients".into(), num(recipients.len() as f64));
                        ctx_ref
                            .events()?
                            .record_audit(
                                &tx,
                                &system_event(
                                    &budget_tenant,
                                    "deployment-operator",
                                    "billing:budget-alert",
                                    &format!("billing/budgets/{budget_id}"),
                                    ctx_ref.now(),
                                    metadata,
                                ),
                            )
                            .await?;
                        alerts.push(json!({
                            "budgetId": budget_id,
                            "tenantId": budget_tenant,
                            "name": budget_name,
                            "kind": kind,
                            "threshold": num(threshold),
                            "spentMicros": num(status.spent_micros),
                            "recipients": num(recipients.len() as f64),
                        }));
                    }
                    Ok(Some(alerts))
                })
                .await?;
            if let Some(fired) = outcome {
                checked += 1.0;
                alerts.extend(fired);
            }
        }
        Ok(json!({ "checked": num(checked), "alerts": alerts }))
    }

    // -----------------------------------------------------------------------------------------------------------
    // Statements

    /// Usage lines of an invoice: the billable meters, with the tiers and free units their quantity used.
    fn usage_lines(&self, charges: &[MeterCharge]) -> IamResult<Vec<Value>> {
        let mut lines = Vec::new();
        for charge in charges.iter().filter(|charge| !charge.internal) {
            let mut line = Map::new();
            line.insert("meter".into(), Value::String(charge.meter.clone()));
            line.insert("name".into(), Value::String(charge.name.clone()));
            line.insert("unit".into(), Value::String(charge.unit.clone()));
            line.insert(
                "quantity".into(),
                num(js_round(charge.quantity * 1e6) / 1e6),
            );
            // Invoices bill whole cents; the spend reports keep the exact amount.
            line.insert(
                "amountMicros".into(),
                num(crate::billing::round_cents(charge.amount_micros)?),
            );
            line.insert("pricing".into(), Value::String(charge.pricing.clone()));
            if let Some(price) = charge
                .price
                .as_ref()
                .filter(|price| crate::js::truthy(Some(price)))
            {
                let spec = member(Some(price), "spec").cloned().unwrap_or(Value::Null);
                let mut summary = Map::new();
                summary.insert(
                    "model".into(),
                    member(Some(&spec), "model").cloned().unwrap_or(Value::Null),
                );
                summary.insert(
                    "effectiveFrom".into(),
                    member(Some(price), "effectiveFrom")
                        .cloned()
                        .unwrap_or(Value::Null),
                );
                if member(Some(price), "source").and_then(Value::as_str) == Some("plan") {
                    summary.insert("source".into(), Value::String("plan".into()));
                }
                line.insert("price".into(), Value::Object(summary));
                let breakdown = crate::billing::price_breakdown(&spec, charge.quantity)?;
                if member(Some(&spec), "model").and_then(Value::as_str) == Some("per-unit") {
                    line.insert(
                        "unitAmountMicros".into(),
                        member(Some(&spec), "unitAmountMicros")
                            .filter(|value| !value.is_null())
                            .cloned()
                            .unwrap_or_else(|| num(0.0)),
                    );
                }
                if let Some(tiers) = member(Some(&breakdown), "tiers")
                    .filter(|tiers| tiers.as_array().is_some_and(|items| !items.is_empty()))
                {
                    line.insert("tiers".into(), tiers.clone());
                }
                if let Some(included) = member(Some(&breakdown), "includedQuantity") {
                    line.insert("includedQuantity".into(), included.clone());
                }
                if let Some(raw) = member(Some(&breakdown), "rawMicros")
                    && core_js::as_number(raw) != Some(charge.amount_micros)
                {
                    line.insert("adjustedFromMicros".into(), raw.clone());
                }
            }
            if charge.unpriced == Some(true) {
                line.insert("unpriced".into(), Value::Bool(true));
            }
            lines.push(Value::Object(line));
        }
        Ok(lines)
    }

    /// Pending invoice items the account's invoice for `period` bills: those without a period or for it or before.
    async fn pending_items(
        &self,
        tx: &Store,
        account_id: &str,
        period: &str,
    ) -> IamResult<Vec<Record>> {
        let mut items: Vec<Record> = find_all(
            tx,
            INVOICE_ITEMS,
            Filter::new()
                .eq("tenantId", account_id)
                .eq("status", "pending"),
        )
        .await?
        .into_iter()
        .filter(|item| match item.get("period") {
            None => true,
            Some(value) => value
                .as_str()
                .is_some_and(|item_period| item_period <= period),
        })
        .collect();
        items.sort_by(|a, b| {
            by_difference(
                num_of(a, "createdAt").unwrap_or(f64::NAN)
                    - num_of(b, "createdAt").unwrap_or(f64::NAN),
                || {
                    str_of(a, "id")
                        .unwrap_or_default()
                        .cmp(str_of(b, "id").unwrap_or_default())
                },
            )
        });
        Ok(items)
    }

    /// `draftStatement(tx, account, period, cache, first)`: builds (without storing) an account's invoice
    /// (`StatementDraft` as a record). The monthly invoice for `period` bills the month's usage, the subscriptions'
    /// fees and seats (arrears for the month, advance for the next), and pending invoice items, and the minimum
    /// commitment applies; a subscription's first invoice (`first`) bills its first month's advance lines. Then the
    /// contract discount, coupons, credit (earliest expiry first) and tax.
    pub async fn draft_statement(
        &self,
        tx: &Store,
        account: &Tenant,
        period: &str,
        cache: Option<&SpendCache>,
        first: Option<FirstLines>,
    ) -> IamResult<Record> {
        use crate::billing::round_micros;
        let ctx = self.ctx()?;
        let settings = self.settings()?;
        let tz = settings.time_zone.as_str();
        let own_cache = SpendCache::default();
        let cache = cache.unwrap_or(&own_cache);
        let (start, end) = period_bounds(period, tz)?;
        let mut lines: Vec<Value> = Vec::new();
        let mut rows: Vec<ChargedRow> = Vec::new();
        let mut invoice_item_ids: Vec<String> = Vec::new();
        let advance_billed: Vec<Value>;
        if let Some(first) = &first {
            lines.extend(first.lines.iter().cloned());
            advance_billed =
                vec![json!({ "subscriptionId": first.subscription_id, "period": period })];
        } else {
            let spend = account_spend(&ctx, tx, account, period, cache).await?;
            lines.extend(self.usage_lines(&spend.charges)?);
            rows = spend.rows.into_iter().filter(|row| !row.internal).collect();
            let recurring =
                crate::billing_plans::subscription_lines(tx, &account.id, period, tz).await?;
            if let Some(Value::Array(recurring_lines)) = member(Some(&recurring), "lines") {
                lines.extend(recurring_lines.iter().cloned());
            }
            advance_billed = member(Some(&recurring), "advance")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let items = self.pending_items(tx, &account.id, period).await?;
            lines.extend(items.iter().map(invoice_item_line));
            invoice_item_ids = items
                .iter()
                .map(|item| str_of(item, "id").unwrap_or_default().to_owned())
                .collect();
        }
        let subtotal_micros = round_micros(
            lines
                .iter()
                .map(|line| {
                    member(Some(line), "amountMicros")
                        .and_then(core_js::as_number)
                        .unwrap_or(f64::NAN)
                })
                .sum(),
        )?;
        let mut credits: Vec<Record> = find_all(
            tx,
            CREDITS,
            Filter::new().eq("tenantId", account.id.as_str()),
        )
        .await?
        .into_iter()
        .filter(|credit| {
            // Any credit that is live when the statement is drawn up and was valid at some point in the period.
            credit.get("revokedAt").is_none()
                && num_of(credit, "remainingMicros").is_some_and(|remaining| remaining > 0.0)
                && match credit.get("expiresAt") {
                    None => true,
                    Some(value) => core_js::as_number(value).is_some_and(|expires| expires > start),
                }
        })
        .collect();
        credits.sort_by(|a, b| {
            let expiry = |credit: &Record| num_of(credit, "expiresAt").unwrap_or(MAX_SAFE_INTEGER);
            by_difference(expiry(a) - expiry(b), || {
                by_difference(
                    num_of(a, "grantedAt").unwrap_or(f64::NAN)
                        - num_of(b, "grantedAt").unwrap_or(f64::NAN),
                    || {
                        str_of(a, "id")
                            .unwrap_or_default()
                            .cmp(str_of(b, "id").unwrap_or_default())
                    },
                )
            })
        });
        let mut discounts: Vec<Record> = Vec::new();
        for discount in find_all(
            tx,
            DISCOUNTS,
            Filter::new().eq("tenantId", account.id.as_str()),
        )
        .await?
        {
            let typed: crate::billing::BillingDiscount = decode(discount.clone())?;
            if crate::billing::discount_active(&typed, period, tz)? {
                discounts.push(discount);
            }
        }
        discounts.sort_by(|a, b| {
            by_difference(
                num_of(a, "redeemedAt").unwrap_or(f64::NAN)
                    - num_of(b, "redeemedAt").unwrap_or(f64::NAN),
                || {
                    str_of(a, "id")
                        .unwrap_or_default()
                        .cmp(str_of(b, "id").unwrap_or_default())
                },
            )
        });
        let terms = crate::billing::account_terms_of(&ctx, tx, account)
            .await?
            .map(|terms| crate::port::encode(&terms));
        let mut credits_applied: Vec<Value> = Vec::new();
        let mut credit = |due_micros: f64| -> IamResult<f64> {
            let mut due = due_micros;
            for credit in &credits {
                if due <= 0.0 {
                    break;
                }
                let remaining = num_of(credit, "remainingMicros").unwrap_or(f64::NAN);
                let amount = round_micros(js_min(due, remaining))?;
                credits_applied.push(json!({
                    "creditId": credit.get("id").cloned().unwrap_or(Value::Null),
                    "amountMicros": num(amount),
                }));
                due = round_micros(due - amount)?;
            }
            round_micros(due_micros - due)
        };
        let (amounts, carry_forward_micros) = invoice_amounts(
            subtotal_micros,
            terms.as_ref(),
            first.is_none(),
            &discounts,
            &mut credit,
        )?;
        let dir = self
            .directory(&ctx, tx, &rows, std::slice::from_ref(&account.id))
            .await?;
        let mut tenant_names: IndexMap<String, String> = IndexMap::new();
        for row in &rows {
            if !tenant_names.contains_key(&row.tenant_id) {
                let name = name_in(tx, "tenants", &row.tenant_id)
                    .await?
                    .unwrap_or_else(|| row.tenant_id.clone());
                tenant_names.insert(row.tenant_id.clone(), name);
            }
        }
        let mut identity_names: IndexMap<String, String> = IndexMap::new();
        for row in &rows {
            if let Some(key) = row.agent_id.as_ref().or(row.identity_id.as_ref())
                && !key.is_empty()
                && !identity_names.contains_key(key)
            {
                let name = name_in(tx, "identities", key)
                    .await?
                    .unwrap_or_else(|| key.clone());
                identity_names.insert(key.clone(), name);
            }
        }
        let profile = crate::billing::profile_of(tx, &account.id)
            .await?
            .map(|profile| crate::port::encode(&profile));
        let profile_emails = profile
            .as_ref()
            .map(|profile| strings_of(profile, "billingEmails"))
            .unwrap_or_default();
        let emails = if !profile_emails.is_empty() {
            profile_emails
        } else {
            self.owners(tx, &account.id).await?
        };
        let full = settings.team_attribution == "full";
        let tenants = allocations(
            &rows,
            |row| vec![(row.tenant_id.clone(), 1.0)],
            |key| tenant_names.get(key).cloned(),
            None,
        )?;
        let teams = allocations(
            &rows,
            |row| {
                row.team_ids
                    .iter()
                    .map(|team| {
                        (
                            team.clone(),
                            if full {
                                1.0
                            } else {
                                1.0 / row.team_ids.len() as f64
                            },
                        )
                    })
                    .collect()
            },
            |key| dir.teams.get(key).map(|team| team.name.clone()),
            Some(50),
        )?;
        let departments: Vec<Value> = allocations(
            &rows,
            |row| match row.department_id.as_ref().filter(|id| !id.is_empty()) {
                Some(department_id) => vec![(department_id.clone(), 1.0)],
                None => Vec::new(),
            },
            |key| {
                dir.departments
                    .get(key)
                    .map(|department| department.name.clone())
            },
            Some(50),
        )?
        .into_iter()
        .map(|mut entry| {
            let cost_center = str_of(&entry, "id")
                .and_then(|id| dir.departments.get(id))
                .and_then(|department| department.cost_center.clone())
                .filter(|cost_center| !cost_center.is_empty());
            if let Some(cost_center) = cost_center {
                entry.insert("costCenter".into(), Value::String(cost_center));
            }
            Value::Object(entry)
        })
        .collect();
        let identities = allocations(
            &rows,
            |row| match row
                .agent_id
                .as_ref()
                .or(row.identity_id.as_ref())
                .filter(|key| !key.is_empty())
            {
                Some(key) => vec![(key.clone(), 1.0)],
                None => Vec::new(),
            },
            |key| identity_names.get(key).cloned(),
            Some(50),
        )?;
        let mut bill_to = Map::new();
        bill_to.insert("name".into(), Value::String(account.name.clone()));
        if let Some(profile) = &profile {
            for key in [
                "companyName",
                "taxId",
                "address",
                "purchaseOrder",
                "costCenter",
            ] {
                if let Some(value) = profile.get(key)
                    && crate::js::truthy(Some(value))
                {
                    bill_to.insert(key.into(), value.clone());
                }
            }
        }
        bill_to.insert("emails".into(), strings_value(emails));
        let payment_terms_days = profile
            .as_ref()
            .and_then(|profile| profile.get("paymentTermsDays"))
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or_else(|| num(settings.payment_terms_days));
        let mut draft = Record::new();
        draft.insert("accountId".into(), Value::String(account.id.clone()));
        draft.insert("period".into(), Value::String(period.to_owned()));
        draft.insert("currency".into(), Value::String(settings.currency.clone()));
        draft.insert("periodStart".into(), num(start));
        draft.insert("periodEnd".into(), num(end));
        draft.insert("lines".into(), Value::Array(lines));
        draft.insert(
            "billingReason".into(),
            Value::String(
                if first.is_some() {
                    "subscription"
                } else {
                    "period"
                }
                .into(),
            ),
        );
        draft.insert("subtotalMicros".into(), num(subtotal_micros));
        draft.extend(amounts);
        draft.insert("creditsApplied".into(), Value::Array(credits_applied));
        draft.insert(
            "breakdown".into(),
            json!({
                "tenants": tenants,
                "teams": teams,
                "departments": departments,
                "identities": identities,
            }),
        );
        draft.insert("billTo".into(), Value::Object(bill_to));
        draft.insert("paymentTermsDays".into(), payment_terms_days);
        draft.insert("invoiceItemIds".into(), strings_value(invoice_item_ids));
        draft.insert("advanceBilled".into(), Value::Array(advance_billed));
        draft.insert("carryForwardMicros".into(), num(carry_forward_micros));
        Ok(draft)
    }

    /// Stores (or refreshes) a monthly invoice as a draft: no number, nothing consumed yet.
    async fn save_draft(
        &self,
        tx: &Store,
        account: &Tenant,
        draft: &Record,
        existing: Option<&Record>,
    ) -> IamResult<Record> {
        let ctx = self.ctx()?;
        let now = ctx.now();
        let payment_terms_days = num_of(draft, "paymentTermsDays").unwrap_or(f64::NAN);
        let mut record = Record::new();
        record.insert(
            "id".into(),
            existing
                .and_then(|existing| existing.get("id").cloned())
                .unwrap_or_else(|| Value::String(id())),
        );
        record.insert("tenantId".into(), Value::String(account.id.clone()));
        record.insert(
            "uniqueKey".into(),
            Value::String(format!(
                "period:{}",
                str_of(draft, "period").unwrap_or_default()
            )),
        );
        record.insert("number".into(), Value::String(String::new()));
        record.insert("status".into(), Value::String("draft".into()));
        record.insert("issuedAt".into(), num(now));
        record.insert("dueAt".into(), num(now + payment_terms_days * DAY_MS));
        record.insert("hash".into(), Value::String(String::new()));
        record.extend(draft_body(draft));
        if let Some(ids) = non_empty_array(draft, "invoiceItemIds") {
            record.insert("invoiceItemIds".into(), ids);
        }
        if let Some(advance) = non_empty_array(draft, "advanceBilled") {
            record.insert("advanceBilled".into(), advance);
        }
        match existing {
            Some(_) => tx.put(STATEMENTS, &record).await,
            None => tx.insert(STATEMENTS, &record).await,
        }
    }

    /// `issue(tx, account, draft, { uniqueKey, existing?, actorId? })`: finalizes an invoice: numbers it
    /// (`{prefix}-{YYYYMM}-{sequence}`), seals its content hash, draws the credit it uses, turns a negative balance into
    /// account credit, marks its invoice items invoiced and its advance months billed, counts its coupons, emails the
    /// billing contacts (`billing-statement`) and audits `billing:statement`. An invoice with nothing to pay is paid on
    /// issue.
    async fn issue(
        &self,
        tx: &Store,
        account: &Tenant,
        draft: &Record,
        unique_key: &str,
        existing: Option<&Record>,
        actor_id: Option<&str>,
    ) -> IamResult<Issued> {
        use crate::billing::round_micros;
        let ctx = self.ctx()?;
        let settings = self.settings()?;
        let actor_id = actor_id.unwrap_or("deployment-operator");
        let period = str_of(draft, "period").unwrap_or_default().to_owned();
        let numbered = find_all(tx, STATEMENTS, Filter::new().eq("period", period.as_str()))
            .await?
            .iter()
            .filter(|statement| crate::js::truthy(statement.get("number")))
            .count();
        let number = format!(
            "{}-{}-{}",
            settings.statement_prefix,
            period.replacen('-', "", 1),
            pad_start(numbered as f64 + 1.0, 4)
        );
        let issued_at = ctx.now();
        let payment_terms_days = num_of(draft, "paymentTermsDays").unwrap_or(f64::NAN);
        let carry_forward_micros = num_of(draft, "carryForwardMicros").unwrap_or(0.0);
        let invoice_item_ids = strings_of(draft, "invoiceItemIds");
        let advance_billed = records_of(draft.get("advanceBilled"));
        let content = draft_body(draft);
        let mut carry_forward: Option<Value> = None;
        if carry_forward_micros > 0.0 {
            let mut credit = Record::new();
            credit.insert("id".into(), Value::String(id()));
            credit.insert("tenantId".into(), Value::String(account.id.clone()));
            credit.insert("amountMicros".into(), num(carry_forward_micros));
            credit.insert("remainingMicros".into(), num(carry_forward_micros));
            credit.insert(
                "reason".into(),
                Value::String(format!("Credit balance from {number}")),
            );
            credit.insert("grantedAt".into(), num(issued_at));
            credit.insert("grantedBy".into(), Value::String(actor_id.to_owned()));
            let credit = tx.insert(CREDITS, &credit).await?;
            carry_forward = Some(json!({
                "creditId": credit.get("id").cloned().unwrap_or(Value::Null),
                "amountMicros": num(carry_forward_micros),
            }));
        }
        let settled = num_of(&content, "totalMicros").is_some_and(|total| total <= 0.0);
        let mut hashed = content.clone();
        hashed.insert("number".into(), Value::String(number.clone()));
        hashed.insert("tenantId".into(), Value::String(account.id.clone()));
        let hash = crate::billing::statement_hash(&Value::Object(hashed))?;
        let mut record = Record::new();
        record.insert(
            "id".into(),
            existing
                .and_then(|existing| existing.get("id").cloned())
                .unwrap_or_else(|| Value::String(id())),
        );
        record.insert("tenantId".into(), Value::String(account.id.clone()));
        record.insert("uniqueKey".into(), Value::String(unique_key.to_owned()));
        record.insert("number".into(), Value::String(number.clone()));
        record.insert(
            "status".into(),
            Value::String(if settled { "paid" } else { "finalized" }.into()),
        );
        record.insert("issuedAt".into(), num(issued_at));
        record.insert("dueAt".into(), num(issued_at + payment_terms_days * DAY_MS));
        record.extend(content.clone());
        if !invoice_item_ids.is_empty() {
            record.insert(
                "invoiceItemIds".into(),
                strings_value(invoice_item_ids.iter().cloned()),
            );
        }
        if !advance_billed.is_empty() {
            record.insert(
                "advanceBilled".into(),
                Value::Array(advance_billed.iter().cloned().map(Value::Object).collect()),
            );
        }
        if let Some(carry_forward) = carry_forward {
            record.insert("carryForward".into(), carry_forward);
        }
        if settled {
            record.insert("paidAt".into(), num(issued_at));
        }
        record.insert("hash".into(), Value::String(hash));
        let statement = match existing {
            Some(_) => tx.put(STATEMENTS, &record).await?,
            None => tx.insert(STATEMENTS, &record).await?,
        };
        let statement_id = str_of(&statement, "id").unwrap_or_default().to_owned();
        for applied in records_of(content.get("creditsApplied")) {
            let credit_id = str_of(&applied, "creditId").unwrap_or_default();
            if let Some(mut credit) = tx.get(CREDITS, credit_id).await? {
                let remaining = num_of(&credit, "remainingMicros").unwrap_or(f64::NAN)
                    - num_of(&applied, "amountMicros").unwrap_or(f64::NAN);
                credit.insert(
                    "remainingMicros".into(),
                    num(round_micros(js_max(0.0, remaining))?),
                );
                tx.put(CREDITS, &credit).await?;
            }
        }
        for item_id in &invoice_item_ids {
            if let Some(mut item) = tx.get(INVOICE_ITEMS, item_id).await?
                && str_of(&item, "status") == Some("pending")
            {
                item.insert("status".into(), Value::String("invoiced".into()));
                item.insert("statementId".into(), Value::String(statement_id.clone()));
                tx.put(INVOICE_ITEMS, &item).await?;
            }
        }
        for entry in &advance_billed {
            let subscription_id = str_of(entry, "subscriptionId").unwrap_or_default();
            let entry_period = str_of(entry, "period").unwrap_or_default().to_owned();
            if let Some(mut subscription) = tx.get(SUBSCRIPTIONS, subscription_id).await? {
                let mut billed = strings_of(&subscription, "billedAdvance");
                if !billed.contains(&entry_period) {
                    billed.push(entry_period);
                    crate::js::sort_strings(&mut billed);
                    subscription.insert("billedAdvance".into(), strings_value(billed));
                    tx.put(SUBSCRIPTIONS, &subscription).await?;
                }
            }
        }
        for coupon in records_of(content.get("coupons")) {
            let discount_id = str_of(&coupon, "discountId").unwrap_or_default();
            if let Some(mut discount) = tx.get(DISCOUNTS, discount_id).await? {
                let applied = num_of(&discount, "appliedInvoices").unwrap_or(f64::NAN);
                discount.insert("appliedInvoices".into(), num(applied + 1.0));
                if str_of(&discount, "duration") == Some("once") {
                    discount.insert("endedAt".into(), num(issued_at));
                }
                tx.put(DISCOUNTS, &discount).await?;
            }
        }
        let recipients: Vec<String> = if sends_email(&ctx) {
            strings_of(&object_of(content.get("billTo")), "emails")
        } else {
            Vec::new()
        };
        for to in &recipients {
            let mut payload = Map::new();
            payload.insert("tenantId".into(), Value::String(account.id.clone()));
            payload.insert("tenantName".into(), Value::String(account.name.clone()));
            payload.insert("statementId".into(), Value::String(statement_id.clone()));
            payload.insert("number".into(), Value::String(number.clone()));
            payload.insert(
                "period".into(),
                content.get("period").cloned().unwrap_or(Value::Null),
            );
            for (key, member_name) in [
                ("total", "totalMicros"),
                ("subtotal", "subtotalMicros"),
                ("credits", "creditsMicros"),
            ] {
                payload.insert(
                    key.into(),
                    Value::String(format_money(
                        num_of(&statement, member_name).unwrap_or(f64::NAN),
                        &settings.currency,
                    )?),
                );
            }
            payload.insert(
                "dueAt".into(),
                Value::String(iso_day(num_of(&statement, "dueAt").unwrap_or(f64::NAN))),
            );
            if str_of(&content, "billingReason") == Some("subscription") {
                payload.insert("reason".into(), Value::String("subscription".into()));
            }
            ctx.auth
                .enqueue_delivery(
                    tx,
                    email_input(&account.id, to, "billing-statement", payload),
                )
                .await?;
        }
        let mut metadata = Map::new();
        metadata.insert("number".into(), Value::String(number.clone()));
        metadata.insert(
            "period".into(),
            content.get("period").cloned().unwrap_or(Value::Null),
        );
        metadata.insert(
            "billingReason".into(),
            content
                .get("billingReason")
                .filter(|value| !value.is_null())
                .cloned()
                .unwrap_or_else(|| Value::String("period".into())),
        );
        for key in ["subtotalMicros", "creditsMicros", "totalMicros"] {
            metadata.insert(
                key.into(),
                statement.get(key).cloned().unwrap_or(Value::Null),
            );
        }
        metadata.insert("invoiceItems".into(), num(invoice_item_ids.len() as f64));
        metadata.insert("recipients".into(), num(recipients.len() as f64));
        ctx.events()?
            .record_audit(
                tx,
                &system_event(
                    &account.id,
                    actor_id,
                    "billing:statement",
                    &format!("billing/statements/{statement_id}"),
                    issued_at,
                    metadata,
                ),
            )
            .await?;
        Ok(Issued {
            statement,
            recipients: recipients.len(),
        })
    }

    /// `finalizeDraft(tx, statement, actorId?)`: finalizes a draft invoice, recomputed first so late usage and new
    /// invoice items are on it.
    pub async fn finalize_draft(
        &self,
        tx: &Store,
        statement: &Record,
        actor_id: Option<&str>,
    ) -> IamResult<Issued> {
        let ctx = self.ctx()?;
        let status = str_of(statement, "status").unwrap_or_default();
        if status != "draft" {
            return Err(IamError::with_status(
                "INVALID_TRANSITION",
                format!("The invoice is {status}"),
                409,
            ));
        }
        let account = ctx
            .tenant(tx, str_of(statement, "tenantId").unwrap_or_default())
            .await?;
        let period = str_of(statement, "period").unwrap_or_default().to_owned();
        let draft = self
            .draft_statement(tx, &account, &period, None, None)
            .await?;
        if !billable(&draft) {
            return Err(IamError::with_status(
                "INVALID_TRANSITION",
                "The invoice has nothing left to bill",
                409,
            ));
        }
        self.issue(
            tx,
            &account,
            &draft,
            &format!("period:{period}"),
            Some(statement),
            actor_id,
        )
        .await
    }

    /// Deletes raw usage events past their retention (daily roll-ups and statements stay).
    async fn sweep_usage(&self) -> IamResult<f64> {
        let ctx = self.ctx()?;
        let mut swept = 0.0;
        for _ in 0..50 {
            let now = ctx.now();
            let batch: usize = ctx
                .store
                .transaction(move |tx| async move {
                    let due = better_iam_core::find_ordered(
                        tx.as_ref(),
                        USAGE,
                        &Filter::new(),
                        &OrderOptions {
                            field: "expiresAt".into(),
                            to: Some(now),
                            limit: Some(500),
                            ..OrderOptions::default()
                        },
                        None,
                    )
                    .await?;
                    for record in &due {
                        tx.delete(USAGE, str_of(record, "id").unwrap_or_default())
                            .await?;
                    }
                    Ok(due.len())
                })
                .await?;
            swept += batch as f64;
            if batch < 500 {
                break;
            }
        }
        Ok(swept)
    }

    /// `closePeriod({ period?, tenantId?, draft? })`: invoices a past period (default the previous one): one invoice
    /// per billing account with something to bill (usage of meters defined above it, subscription fees and seats,
    /// pending invoice items, a minimum commitment the month fell short of). Accounts already invoiced for the period
    /// are skipped, so the job can run daily. With `draft` (default: `!billing.autoFinalize`) invoices are kept as
    /// drafts, refreshed on every run, until finalized (`finalizeInvoice`, or a run with `draft: false`). Usage for a
    /// finalized period is refused afterwards (BILLING_PERIOD_CLOSED); void the invoice to reopen it. Also deletes raw
    /// usage events past their retention.
    pub async fn close_period(&self, input: Option<&Value>) -> IamResult<ClosePeriodResult> {
        let ctx = self.ctx()?;
        let settings = self.settings()?;
        let tz = settings.time_zone.as_str();
        let current = self.current_period()?;
        let period = match member(input, "period") {
            None => crate::billing::shift_period(&current, -1.0)?,
            Some(value) => crate::billing::billing_period(Some(value), None)?,
        };
        if period >= current {
            return Err(IamError::new(
                "INVALID_INPUT",
                "Only periods that have ended can be closed",
            ));
        }
        let draft_only = match member(input, "draft") {
            None => !settings.auto_finalize,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => {
                return Err(IamError::new("INVALID_INPUT", "draft must be a boolean"));
            }
        };
        let (start, _) = period_bounds(&period, tz)?;
        let (_, next_end) = period_bounds(&crate::billing::shift_period(&period, 1.0)?, tz)?;
        let tenant_id = member(input, "tenantId").cloned();
        let ctx_ref = &ctx;
        let period_ref = period.as_str();
        let mut accounts: Vec<Tenant> = ctx
            .store
            .transaction(move |tx| async move {
                let mut found: IndexMap<String, Tenant> = IndexMap::new();
                let mut tenant_ids: Vec<String> = Vec::new();
                if let Some(value) = &tenant_id {
                    let realm = ctx_ref
                        .tenant(&tx, &text(Some(value), "tenantId", 256)?)
                        .await?;
                    tenant_ids.push(realm.id);
                } else {
                    let mut ids: IndexSet<String> = IndexSet::new();
                    for rollup in
                        find_all(&tx, ROLLUPS, Filter::new().eq("period", period_ref)).await?
                    {
                        ids.insert(str_of(&rollup, "tenantId").unwrap_or_default().to_owned());
                    }
                    // Subscriptions running in the period or the next (advance billing), and pending invoice items.
                    for subscription in find_all(&tx, SUBSCRIPTIONS, Filter::new()).await? {
                        let started = num_of(&subscription, "startedAt").unwrap_or(f64::NAN);
                        let running = match subscription.get("endsAt") {
                            None => true,
                            Some(value) => {
                                core_js::as_number(value).is_some_and(|ends| ends > start)
                            }
                        };
                        if started < next_end && running {
                            ids.insert(
                                str_of(&subscription, "tenantId")
                                    .unwrap_or_default()
                                    .to_owned(),
                            );
                        }
                    }
                    for item in
                        find_all(&tx, INVOICE_ITEMS, Filter::new().eq("status", "pending")).await?
                    {
                        let due = match item.get("period") {
                            None => true,
                            Some(value) => value
                                .as_str()
                                .is_some_and(|item_period| item_period <= period_ref),
                        };
                        if due {
                            ids.insert(str_of(&item, "tenantId").unwrap_or_default().to_owned());
                        }
                    }
                    // A minimum commitment is owed even for a month without usage (terms apply to invoices issued
                    // after them).
                    for terms in find_all(&tx, TERMS, Filter::new()).await? {
                        if crate::js::truthy(terms.get("minimumCommitmentMicros")) {
                            let terms_tenant =
                                str_of(&terms, "tenantId").unwrap_or_default().to_owned();
                            let status = tx
                                .get("tenants", &terms_tenant)
                                .await?
                                .and_then(|realm| str_of(&realm, "status").map(str::to_owned));
                            if status.as_deref() != Some("deleted") {
                                ids.insert(terms_tenant);
                            }
                        }
                    }
                    tenant_ids.extend(ids);
                }
                for tenant_id in tenant_ids {
                    let Some(realm) = get_tenant(&tx, &tenant_id).await? else {
                        continue;
                    };
                    let account = crate::billing::account_of(ctx_ref, &tx, &realm).await?;
                    found.insert(account.id.clone(), account);
                }
                Ok(found.into_values().collect::<Vec<Tenant>>())
            })
            .await?;
        accounts.sort_by(|a, b| a.id.cmp(&b.id));
        let mut issued: Vec<Value> = Vec::new();
        let mut drafted: Vec<Value> = Vec::new();
        let mut existing_count = 0.0;
        let mut empty_count = 0.0;
        enum Closed {
            Existing,
            Empty,
            Drafted(Value),
            Issued(Value),
        }
        for candidate in accounts {
            // The platform does not bill itself.
            if candidate.parent_id.is_none() {
                continue;
            }
            let candidate_id = candidate.id.clone();
            let closed: Closed = ctx
                .store
                .transaction(move |tx| async move {
                    let account = ctx_ref.tenant(&tx, &candidate_id).await?;
                    let existing = self.statement_for(&tx, &account.id, period_ref).await?;
                    if let Some(existing) = &existing
                        && str_of(existing, "status") != Some("draft")
                    {
                        return Ok(Closed::Existing);
                    }
                    let draft = self
                        .draft_statement(&tx, &account, period_ref, None, None)
                        .await?;
                    if !billable(&draft) {
                        if let Some(existing) = &existing {
                            tx.delete(STATEMENTS, str_of(existing, "id").unwrap_or_default())
                                .await?;
                        }
                        return Ok(Closed::Empty);
                    }
                    if draft_only {
                        let saved = self
                            .save_draft(&tx, &account, &draft, existing.as_ref())
                            .await?;
                        return Ok(Closed::Drafted(json!({
                            "accountId": account.id,
                            "statementId": saved.get("id").cloned().unwrap_or(Value::Null),
                            "totalMicros": saved.get("totalMicros").cloned().unwrap_or(Value::Null),
                        })));
                    }
                    let Issued {
                        statement,
                        recipients,
                    } = self
                        .issue(
                            &tx,
                            &account,
                            &draft,
                            &format!("period:{period_ref}"),
                            existing.as_ref(),
                            None,
                        )
                        .await?;
                    Ok(Closed::Issued(json!({
                        "accountId": account.id,
                        "statementId": statement.get("id").cloned().unwrap_or(Value::Null),
                        "number": statement.get("number").cloned().unwrap_or(Value::Null),
                        "totalMicros": statement.get("totalMicros").cloned().unwrap_or(Value::Null),
                        "recipients": num(recipients as f64),
                    })))
                })
                .await?;
            match closed {
                Closed::Existing => existing_count += 1.0,
                Closed::Empty => empty_count += 1.0,
                Closed::Drafted(entry) => drafted.push(entry),
                Closed::Issued(entry) => issued.push(entry),
            }
        }
        let swept_usage = self.sweep_usage().await?;
        Ok(ClosePeriodResult {
            period,
            issued,
            drafted,
            skipped: json!({ "existing": num(existing_count), "empty": num(empty_count) }),
            swept_usage,
            extra: Map::new(),
        })
    }
}

/// `daysBefore(day, count)`: the days `count` days before `day` (oldest first), as local dates.
fn days_before(day: &str, count: f64) -> Vec<String> {
    let mut parts = day.split('-').map(|part| part.parse::<i64>().unwrap_or(0));
    let year = parts.next().unwrap_or(0);
    let month = parts.next().unwrap_or(1);
    let date = parts.next().unwrap_or(1);
    let first = core_js::days_from_civil(year, month, 1);
    let count = count as i64;
    (0..count)
        .map(|index| {
            let days = first + (date - 1) - (count - index);
            iso_day(days as f64 * DAY_MS)
        })
        .collect()
}

/// `/^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/`.
fn valid_day(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    if !digits(0..4) || !digits(5..7) || !digits(8..10) {
        return false;
    }
    let month = (bytes[5] - b'0') * 10 + (bytes[6] - b'0');
    let date = (bytes[8] - b'0') * 10 + (bytes[9] - b'0');
    (1..=12).contains(&month) && (1..=31).contains(&date)
}

impl BillingService {
    /// `voidStatement(tx, statement, principal, reason)`: voids a finalized invoice: its credit is restored (and credit
    /// it created revoked), its invoice items are pending again, its advance months are unbilled, its coupons count one
    /// invoice less, and a monthly invoice's period reopens for the account. Invoices with payments or credit notes
    /// cannot be voided; issue a credit note instead. Nor can one whose credit balance (`carryForward`) a later invoice
    /// has used, until that invoice is voided.
    pub async fn void_statement(
        &self,
        tx: &Store,
        statement: &Record,
        principal: &AuthenticatedPrincipal,
        reason: &str,
    ) -> IamResult<Record> {
        use crate::billing::round_micros;
        let ctx = self.ctx()?;
        let status = str_of(statement, "status").unwrap_or_default();
        if status == "void" {
            return Err(IamError::with_status(
                "INVALID_TRANSITION",
                "The statement is already void",
                409,
            ));
        }
        if status == "draft" {
            return Err(IamError::with_status(
                "INVALID_TRANSITION",
                "Drafts are not voided; finalize the invoice or let the next close refresh it",
                409,
            ));
        }
        let payments = statement
            .get("payments")
            .and_then(Value::as_array)
            .is_some_and(|payments| !payments.is_empty());
        if payments || num_of(statement, "creditNotesMicros").unwrap_or(0.0) > 0.0 {
            return Err(IamError::with_status(
                "INVALID_TRANSITION",
                "The invoice has payments or credit notes; issue a credit note instead",
                409,
            ));
        }
        // Voiding puts the invoice's credit items back up for the next invoice, so the credit balance they created must
        // still be whole: once a later invoice used it (or it was revoked), voiding would hand the credit out twice.
        let carried_id = member(statement.get("carryForward"), "creditId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let carried = match (&carried_id, statement.get("carryForward")) {
            (Some(credit_id), Some(carry)) if crate::js::truthy(Some(carry)) => {
                tx.get(CREDITS, credit_id).await?
            }
            _ => None,
        };
        if let Some(carried) = &carried
            && num_of(carried, "remainingMicros").unwrap_or(f64::NAN)
                < num_of(carried, "amountMicros").unwrap_or(f64::NAN)
        {
            return Err(IamError::with_status(
                "INVALID_TRANSITION",
                "The credit balance this invoice created has been used or revoked; void the invoices that used it first",
                409,
            ));
        }
        for applied in records_of(statement.get("creditsApplied")) {
            if let Some(mut credit) = tx
                .get(CREDITS, str_of(&applied, "creditId").unwrap_or_default())
                .await?
            {
                let restored = js_min(
                    num_of(&credit, "amountMicros").unwrap_or(f64::NAN),
                    num_of(&credit, "remainingMicros").unwrap_or(f64::NAN)
                        + num_of(&applied, "amountMicros").unwrap_or(f64::NAN),
                );
                credit.insert("remainingMicros".into(), num(round_micros(restored)?));
                tx.put(CREDITS, &credit).await?;
            }
        }
        let now = ctx.now();
        if crate::js::truthy(statement.get("carryForward"))
            && let Some(credit_id) = &carried_id
            && let Some(mut credit) = tx.get(CREDITS, credit_id).await?
            && credit.get("revokedAt").is_none()
        {
            credit.insert("revokedAt".into(), num(now));
            tx.put(CREDITS, &credit).await?;
        }
        let statement_id = str_of(statement, "id").unwrap_or_default().to_owned();
        for item_id in strings_of(statement, "invoiceItemIds") {
            if let Some(mut item) = tx.get(INVOICE_ITEMS, &item_id).await?
                && str_of(&item, "statementId") == Some(statement_id.as_str())
            {
                item.shift_remove("statementId");
                item.insert("status".into(), Value::String("pending".into()));
                tx.put(INVOICE_ITEMS, &item).await?;
            }
        }
        for entry in records_of(statement.get("advanceBilled")) {
            let entry_period = str_of(&entry, "period").unwrap_or_default().to_owned();
            if let Some(mut subscription) = tx
                .get(
                    SUBSCRIPTIONS,
                    str_of(&entry, "subscriptionId").unwrap_or_default(),
                )
                .await?
            {
                let billed = strings_of(&subscription, "billedAdvance");
                if billed.contains(&entry_period) {
                    subscription.insert(
                        "billedAdvance".into(),
                        strings_value(billed.into_iter().filter(|period| *period != entry_period)),
                    );
                    tx.put(SUBSCRIPTIONS, &subscription).await?;
                }
            }
        }
        for coupon in records_of(statement.get("coupons")) {
            if let Some(mut discount) = tx
                .get(DISCOUNTS, str_of(&coupon, "discountId").unwrap_or_default())
                .await?
            {
                if str_of(&discount, "duration") == Some("once") {
                    discount.shift_remove("endedAt");
                }
                let applied = num_of(&discount, "appliedInvoices").unwrap_or(f64::NAN);
                discount.insert("appliedInvoices".into(), num(js_max(0.0, applied - 1.0)));
                tx.put(DISCOUNTS, &discount).await?;
            }
        }
        let mut next = statement.clone();
        next.insert(
            "uniqueKey".into(),
            Value::String(format!("void:{statement_id}")),
        );
        next.insert("status".into(), Value::String("void".into()));
        next.insert("voidedAt".into(), num(now));
        next.insert(
            "voidedBy".into(),
            Value::String(principal.identity.id.clone()),
        );
        next.insert("voidReason".into(), Value::String(reason.to_owned()));
        tx.put(STATEMENTS, &next).await
    }

    /// `recordPayment(tx, statement, { amount?, method?, reference?, receivedAt? }, actorId)`: records a payment against
    /// a finalized (or uncollectible) invoice, the full amount due by default. Once payments and credit notes cover the
    /// invoice it is paid; a payment above the amount due keeps the excess as account credit.
    pub async fn record_payment(
        &self,
        tx: &Store,
        statement: &Record,
        input: &Value,
        actor_id: &str,
    ) -> IamResult<PaymentRecorded> {
        use crate::billing::{amount_due, amount_micros, amount_paid, round_micros};
        let ctx = self.ctx()?;
        let input = Some(input);
        let status = str_of(statement, "status").unwrap_or_default();
        if status != "finalized" && status != "uncollectible" {
            return Err(IamError::with_status(
                "INVALID_TRANSITION",
                format!("The invoice is {status}"),
                409,
            ));
        }
        let typed: crate::billing::BillingStatement = decode(statement.clone())?;
        let due = amount_due(&typed)?;
        let amount = match member(input, "amount") {
            None => due,
            Some(value) => amount_micros(Some(value), "amount")?,
        };
        if amount <= 0.0 {
            return Err(IamError::new("INVALID_INPUT", "amount must be above 0"));
        }
        let method = match member(input, "method") {
            None => "manual".to_owned(),
            Some(value) => core_js::trim(&text(Some(value), "method", 32)?).to_owned(),
        };
        let reference = match member(input, "reference") {
            None => None,
            Some(value) => Some(core_js::trim(&text(Some(value), "reference", 128)?).to_owned()),
        };
        let reference = reference.filter(|reference| !reference.is_empty());
        let now = ctx.now();
        let issued_at = num_of(statement, "issuedAt").unwrap_or(f64::NAN);
        let received_at = match member(input, "receivedAt") {
            None => now,
            Some(value) => integer(
                Some(value),
                "receivedAt",
                issued_at - 366.0 * DAY_MS,
                now + 60_000.0,
            )?,
        };
        let applied = round_micros(js_min(amount, due))?;
        let overpayment_micros = round_micros(amount - applied)?;
        let mut payment = Record::new();
        payment.insert("id".into(), Value::String(id()));
        payment.insert("amountMicros".into(), num(amount));
        payment.insert("method".into(), Value::String(method));
        if let Some(reference) = &reference {
            payment.insert("reference".into(), Value::String(reference.clone()));
        }
        payment.insert("receivedAt".into(), num(received_at));
        payment.insert("recordedBy".into(), Value::String(actor_id.to_owned()));
        if overpayment_micros > 0.0 {
            let mut credit = Record::new();
            credit.insert("id".into(), Value::String(id()));
            credit.insert(
                "tenantId".into(),
                statement.get("tenantId").cloned().unwrap_or(Value::Null),
            );
            credit.insert("amountMicros".into(), num(overpayment_micros));
            credit.insert("remainingMicros".into(), num(overpayment_micros));
            credit.insert(
                "reason".into(),
                Value::String(format!(
                    "Overpayment of {}",
                    str_of(statement, "number").unwrap_or_default()
                )),
            );
            credit.insert("grantedAt".into(), num(now));
            credit.insert("grantedBy".into(), Value::String(actor_id.to_owned()));
            let credit = tx.insert(CREDITS, &credit).await?;
            payment.insert("overpaymentMicros".into(), num(overpayment_micros));
            payment.insert(
                "creditId".into(),
                credit.get("id").cloned().unwrap_or(Value::Null),
            );
        }
        let settled = round_micros(due - applied)? <= 0.0;
        let mut payments = statement
            .get("payments")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        payments.push(Value::Object(payment.clone()));
        let mut next = statement.clone();
        next.insert("payments".into(), Value::Array(payments));
        next.insert(
            "amountPaidMicros".into(),
            num(round_micros(amount_paid(&typed)? + applied)?),
        );
        if settled {
            next.insert("status".into(), Value::String("paid".into()));
            next.insert("paidAt".into(), num(received_at));
            next.insert("paidBy".into(), Value::String(actor_id.to_owned()));
            if let Some(reference) = &reference {
                next.insert("paymentReference".into(), Value::String(reference.clone()));
            }
        }
        let next = tx.put(STATEMENTS, &next).await?;
        Ok(PaymentRecorded {
            statement: next,
            payment,
        })
    }

    /// `markUncollectible(tx, statement)`: writes a finalized invoice off as uncollectible (a later payment still
    /// settles it).
    pub async fn mark_uncollectible(&self, tx: &Store, statement: &Record) -> IamResult<Record> {
        let ctx = self.ctx()?;
        let status = str_of(statement, "status").unwrap_or_default();
        if status != "finalized" {
            return Err(IamError::with_status(
                "INVALID_TRANSITION",
                format!("The invoice is {status}"),
                409,
            ));
        }
        let mut next = statement.clone();
        next.insert("status".into(), Value::String("uncollectible".into()));
        next.insert("markedUncollectibleAt".into(), num(ctx.now()));
        tx.put(STATEMENTS, &next).await
    }

    /// `createCreditNote(tx, statement, { amount?, reason?, memo?, refund? }, actorId)`: issues a credit note against a
    /// finalized, paid or uncollectible invoice, numbered `{invoice}-CN-{nn}`: it first reduces the amount due; the
    /// rest (a part already paid) becomes account credit, or is recorded as refunded outside Better IAM with `refund`.
    /// An invoice the credit notes and payments cover is paid.
    pub async fn create_credit_note(
        &self,
        tx: &Store,
        statement: &Record,
        input: &Value,
        actor_id: &str,
    ) -> IamResult<CreditNoteIssued> {
        use crate::billing::{amount_due, amount_micros, round_micros};
        let ctx = self.ctx()?;
        let settings = self.settings()?;
        let input = Some(input);
        let status = str_of(statement, "status").unwrap_or_default();
        if status != "finalized" && status != "paid" && status != "uncollectible" {
            return Err(IamError::with_status(
                "INVALID_TRANSITION",
                format!("The invoice is {status}"),
                409,
            ));
        }
        let credit_notes_micros = num_of(statement, "creditNotesMicros").unwrap_or(0.0);
        let creditable = round_micros(
            num_of(statement, "totalMicros").unwrap_or(f64::NAN) - credit_notes_micros,
        )?;
        let amount = match member(input, "amount") {
            None => creditable,
            Some(value) => amount_micros(Some(value), "amount")?,
        };
        if amount <= 0.0 {
            return Err(IamError::new("INVALID_INPUT", "amount must be above 0"));
        }
        if amount > creditable {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!(
                    "At most {} of the invoice can still be credited",
                    format_money(creditable, &settings.currency)?
                ),
            ));
        }
        let reason = crate::billing_invoices::credit_note_reason(member(input, "reason"))?;
        let memo = match member(input, "memo") {
            None => None,
            Some(value) => Some(core_js::trim(&text(Some(value), "memo", 512)?).to_owned()),
        };
        let refund = match member(input, "refund") {
            None => false,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => return Err(IamError::new("INVALID_INPUT", "refund must be a boolean")),
        };
        let typed: crate::billing::BillingStatement = decode(statement.clone())?;
        let due_micros = round_micros(js_min(amount, amount_due(&typed)?))?;
        let rest = round_micros(amount - due_micros)?;
        let credit_micros = if refund { 0.0 } else { rest };
        let refund_micros = if refund { rest } else { 0.0 };
        let statement_id = str_of(statement, "id").unwrap_or_default().to_owned();
        let tenant_id = statement.get("tenantId").cloned().unwrap_or(Value::Null);
        let count = find_all(
            tx,
            CREDIT_NOTES,
            Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("statementId", statement_id.as_str()),
        )
        .await?
        .len();
        let statement_number = str_of(statement, "number").unwrap_or_default().to_owned();
        let number = format!("{statement_number}-CN-{}", pad_start(count as f64 + 1.0, 2));
        let now = ctx.now();
        let mut credit_id: Option<Value> = None;
        if credit_micros > 0.0 {
            let mut credit = Record::new();
            credit.insert("id".into(), Value::String(id()));
            credit.insert("tenantId".into(), tenant_id.clone());
            credit.insert("amountMicros".into(), num(credit_micros));
            credit.insert("remainingMicros".into(), num(credit_micros));
            credit.insert(
                "reason".into(),
                Value::String(format!("Credit note {number}")),
            );
            credit.insert("grantedAt".into(), num(now));
            credit.insert("grantedBy".into(), Value::String(actor_id.to_owned()));
            credit_id = tx.insert(CREDITS, &credit).await?.get("id").cloned();
        }
        let mut note = Record::new();
        note.insert("id".into(), Value::String(id()));
        note.insert("tenantId".into(), tenant_id.clone());
        note.insert("uniqueKey".into(), Value::String(number.clone()));
        note.insert("number".into(), Value::String(number.clone()));
        note.insert("statementId".into(), Value::String(statement_id.clone()));
        note.insert(
            "statementNumber".into(),
            Value::String(statement_number.clone()),
        );
        note.insert("amountMicros".into(), num(amount));
        note.insert("reason".into(), reason);
        if let Some(memo) = memo.filter(|memo| !memo.is_empty()) {
            note.insert("memo".into(), Value::String(memo));
        }
        note.insert(
            "applied".into(),
            json!({
                "dueMicros": num(due_micros),
                "creditMicros": num(credit_micros),
                "refundMicros": num(refund_micros),
            }),
        );
        if let Some(credit_id) = credit_id.filter(|credit_id| crate::js::truthy(Some(credit_id))) {
            note.insert("creditId".into(), credit_id);
        }
        note.insert("issuedAt".into(), num(now));
        note.insert("issuedBy".into(), Value::String(actor_id.to_owned()));
        let credit_note = tx.insert(CREDIT_NOTES, &note).await?;
        let mut credited = statement.clone();
        credited.insert(
            "creditNotesMicros".into(),
            num(round_micros(credit_notes_micros + amount)?),
        );
        let credited_typed: crate::billing::BillingStatement = decode(credited.clone())?;
        let settled = status != "paid" && amount_due(&credited_typed)? <= 0.0;
        if settled {
            credited.insert("status".into(), Value::String("paid".into()));
            credited.insert("paidAt".into(), num(now));
            credited.insert("paidBy".into(), Value::String(actor_id.to_owned()));
        }
        let next = tx.put(STATEMENTS, &credited).await?;
        Ok(CreditNoteIssued {
            statement: next,
            credit_note,
        })
    }

    /// `sendPaymentReminders()`: emails the billing contacts of finalized invoices with an amount due
    /// (`payment-reminder`) at each step of `billing.paymentReminderDays` relative to the due date, once per step (a
    /// missed step is skipped for the latest one reached). Audited as `billing:payment-reminder`. A scheduler job, run
    /// daily. Answers `PaymentReminderResult` as JSON.
    pub async fn send_payment_reminders(&self) -> IamResult<Value> {
        let ctx = self.ctx()?;
        let settings = self.settings()?;
        let mut checked = 0.0;
        let mut reminders: Vec<Value> = Vec::new();
        if settings.payment_reminder_days.is_empty() {
            return Ok(json!({ "checked": num(checked), "reminders": reminders }));
        }
        let mut open: Vec<Record> = ctx
            .store
            .transaction(|tx| async move {
                find_all(&tx, STATEMENTS, Filter::new().eq("status", "finalized")).await
            })
            .await?;
        open.sort_by(|a, b| {
            by_difference(
                num_of(a, "dueAt").unwrap_or(f64::NAN) - num_of(b, "dueAt").unwrap_or(f64::NAN),
                || {
                    str_of(a, "id")
                        .unwrap_or_default()
                        .cmp(str_of(b, "id").unwrap_or_default())
                },
            )
        });
        let ctx_ref = &ctx;
        for candidate in open {
            checked += 1.0;
            let candidate_id = str_of(&candidate, "id").unwrap_or_default().to_owned();
            let reminder: Option<Value> = ctx
                .store
                .transaction(move |tx| async move {
                    let Some(statement) = tx.get(STATEMENTS, &candidate_id).await? else {
                        return Ok(None);
                    };
                    if str_of(&statement, "status") != Some("finalized") {
                        return Ok(None);
                    }
                    let typed: crate::billing::BillingStatement = decode(statement.clone())?;
                    let due = crate::billing::amount_due(&typed)?;
                    if due <= 0.0 {
                        return Ok(None);
                    }
                    let now = ctx_ref.now();
                    let due_at = num_of(&statement, "dueAt").unwrap_or(f64::NAN);
                    let issued_at = num_of(&statement, "issuedAt").unwrap_or(f64::NAN);
                    let reached: Vec<f64> = settings
                        .payment_reminder_days
                        .iter()
                        .copied()
                        .filter(|days| {
                            let at = due_at + days * DAY_MS;
                            at > issued_at && at <= now
                        })
                        .collect();
                    let Some(step) = reached.last().copied() else {
                        return Ok(None);
                    };
                    let sent: Vec<f64> = records_of(statement.get("reminders"))
                        .iter()
                        .map(|reminder| num_of(reminder, "days").unwrap_or(f64::NAN))
                        .collect();
                    if sent.iter().any(|days| *days >= step) {
                        return Ok(None);
                    }
                    let tenant_id = str_of(&statement, "tenantId")
                        .unwrap_or_default()
                        .to_owned();
                    let account = tx.get("tenants", &tenant_id).await?;
                    let bill_to = object_of(statement.get("billTo"));
                    let recipients: Vec<String> = if sends_email(ctx_ref) {
                        strings_of(&bill_to, "emails")
                    } else {
                        Vec::new()
                    };
                    let days = js_round((now - due_at) / DAY_MS);
                    let statement_id = str_of(&statement, "id").unwrap_or_default().to_owned();
                    let number = statement.get("number").cloned().unwrap_or(Value::Null);
                    for to in &recipients {
                        let mut payload = Map::new();
                        payload.insert("tenantId".into(), Value::String(tenant_id.clone()));
                        payload.insert(
                            "tenantName".into(),
                            account
                                .as_ref()
                                .and_then(|account| account.get("name").cloned())
                                .unwrap_or_else(|| {
                                    bill_to.get("name").cloned().unwrap_or(Value::Null)
                                }),
                        );
                        payload.insert("statementId".into(), Value::String(statement_id.clone()));
                        payload.insert("number".into(), number.clone());
                        payload.insert(
                            "period".into(),
                            statement.get("period").cloned().unwrap_or(Value::Null),
                        );
                        payload.insert(
                            "amountDue".into(),
                            Value::String(format_money(due, &settings.currency)?),
                        );
                        payload.insert(
                            "total".into(),
                            Value::String(format_money(
                                num_of(&statement, "totalMicros").unwrap_or(f64::NAN),
                                &settings.currency,
                            )?),
                        );
                        payload.insert("dueAt".into(), Value::String(iso_day(due_at)));
                        payload.insert(
                            "days".into(),
                            Value::String(core_js::number_to_string(days)),
                        );
                        payload.insert("overdue".into(), Value::String((now > due_at).to_string()));
                        ctx_ref
                            .auth
                            .enqueue_delivery(
                                &tx,
                                email_input(&tenant_id, to, "payment-reminder", payload),
                            )
                            .await?;
                    }
                    let mut next = statement.clone();
                    let mut sent_reminders = statement
                        .get("reminders")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    sent_reminders.push(json!({
                        "days": num(step),
                        "at": num(now),
                        "recipients": num(recipients.len() as f64),
                    }));
                    next.insert("reminders".into(), Value::Array(sent_reminders));
                    tx.put(STATEMENTS, &next).await?;
                    let mut metadata = Map::new();
                    metadata.insert("number".into(), number.clone());
                    metadata.insert("step".into(), num(step));
                    metadata.insert("amountDueMicros".into(), num(due));
                    metadata.insert("recipients".into(), num(recipients.len() as f64));
                    ctx_ref
                        .events()?
                        .record_audit(
                            &tx,
                            &system_event(
                                &tenant_id,
                                "deployment-operator",
                                "billing:payment-reminder",
                                &format!("billing/statements/{statement_id}"),
                                now,
                                metadata,
                            ),
                        )
                        .await?;
                    Ok(Some(json!({
                        "statementId": statement_id,
                        "accountId": tenant_id,
                        "number": number,
                        "step": num(step),
                        "amountDueMicros": num(due),
                        "recipients": num(recipients.len() as f64),
                    })))
                })
                .await?;
            if let Some(reminder) = reminder {
                reminders.push(reminder);
            }
        }
        Ok(json!({ "checked": num(checked), "reminders": reminders }))
    }

    // -----------------------------------------------------------------------------------------------------------
    // Subscriptions

    async fn plan_of(&self, tx: &Store, subscription: &Record) -> IamResult<Record> {
        tx.get(PLANS, str_of(subscription, "planId").unwrap_or_default())
            .await?
            .ok_or_else(|| IamError::with_status("NOT_FOUND", "Billing plan not found", 404))
    }

    fn assert_live(&self, subscription: &Record) -> IamResult<()> {
        let ctx = self.ctx()?;
        let typed: crate::billing::BillingSubscription = decode(subscription.clone())?;
        if crate::billing::subscription_status(&typed, ctx.now())? == "ended" {
            return Err(IamError::with_status(
                "INVALID_TRANSITION",
                "The subscription has ended",
                409,
            ));
        }
        Ok(())
    }

    async fn insert_items(&self, tx: &Store, items: &[Record]) -> IamResult<()> {
        for item in items {
            tx.insert(INVOICE_ITEMS, item).await?;
        }
        Ok(())
    }

    /// `prorationItems({ subscription, plan, at, timeZone, seats?, ending, createdBy })` as records.
    #[allow(clippy::too_many_arguments)]
    fn proration_items(
        &self,
        subscription: &Record,
        plan: &Record,
        at: f64,
        seats: Option<(f64, f64)>,
        ending: bool,
        created_by: &str,
    ) -> IamResult<Vec<Record>> {
        let mut input = Map::new();
        input.insert("subscription".into(), Value::Object(subscription.clone()));
        input.insert("plan".into(), Value::Object(plan.clone()));
        input.insert("at".into(), num(at));
        input.insert(
            "timeZone".into(),
            Value::String(self.settings()?.time_zone.clone()),
        );
        if let Some((before, after)) = seats {
            input.insert(
                "seats".into(),
                json!({ "before": num(before), "after": num(after) }),
            );
        }
        input.insert("ending".into(), Value::Bool(ending));
        input.insert("createdBy".into(), Value::String(created_by.to_owned()));
        Ok(
            crate::billing_plans::proration_items(&Value::Object(input))?
                .iter()
                .map(crate::port::encode)
                .collect(),
        )
    }

    /// The live subscription of an account to a plan; an ended one frees the plan for a new subscription.
    async fn live_subscription(
        &self,
        tx: &Store,
        account_id: &str,
        plan_id: &str,
    ) -> IamResult<Option<Record>> {
        let ctx = self.ctx()?;
        let Some(mut existing) = first_record(
            tx,
            SUBSCRIPTIONS,
            Filter::new()
                .eq("tenantId", account_id)
                .eq("uniqueKey", format!("plan:{plan_id}")),
        )
        .await?
        else {
            return Ok(None);
        };
        let typed: crate::billing::BillingSubscription = decode(existing.clone())?;
        if crate::billing::subscription_status(&typed, ctx.now())? != "ended" {
            return Ok(Some(existing));
        }
        let existing_id = str_of(&existing, "id").unwrap_or_default().to_owned();
        existing.insert(
            "uniqueKey".into(),
            Value::String(format!("ended:{existing_id}")),
        );
        tx.put(SUBSCRIPTIONS, &existing).await?;
        Ok(None)
    }

    /// `subscribe(tx, account, plan, { seats, trialDays? }, actorId)`: subscribes a billing account to a plan with
    /// `seats` and the plan's trial (or `trialDays`; 0 for none). The plan's own trial is granted once per account: an
    /// account that subscribed to the plan before starts without one. Outside a trial the first month's advance fees
    /// and seats are invoiced at once, prorated from today (a finalized invoice with `billingReason: 'subscription'`);
    /// after that each monthly invoice bills the month ahead.
    pub async fn subscribe(
        &self,
        tx: &Store,
        account: &Tenant,
        plan: &Record,
        seats: f64,
        trial_days: Option<f64>,
        actor_id: &str,
    ) -> IamResult<Subscribed> {
        let ctx = self.ctx()?;
        let settings = self.settings()?;
        if bool_of(plan, "archived") {
            return Err(IamError::with_status(
                "INVALID_TRANSITION",
                "The plan is archived",
                409,
            ));
        }
        let plan_id = str_of(plan, "id").unwrap_or_default().to_owned();
        if self
            .live_subscription(tx, &account.id, &plan_id)
            .await?
            .is_some()
        {
            return Err(IamError::with_status(
                "CONFLICT",
                "The account already subscribes to this plan",
                409,
            ));
        }
        let now = ctx.now();
        let subscribed_before = find_all(
            tx,
            SUBSCRIPTIONS,
            Filter::new().eq("tenantId", account.id.as_str()),
        )
        .await?
        .iter()
        .any(|subscription| str_of(subscription, "planId") == Some(plan_id.as_str()));
        let trial_days = match trial_days {
            Some(days) => days,
            None if subscribed_before => 0.0,
            None => num_of(plan, "trialDays").unwrap_or(0.0),
        };
        let subscription_id = id();
        let mut created = Record::new();
        created.insert("id".into(), Value::String(subscription_id.clone()));
        created.insert("tenantId".into(), Value::String(account.id.clone()));
        created.insert("uniqueKey".into(), Value::String(format!("plan:{plan_id}")));
        created.insert("planId".into(), Value::String(plan_id.clone()));
        created.insert(
            "planKey".into(),
            plan.get("key").cloned().unwrap_or(Value::Null),
        );
        created.insert(
            "planName".into(),
            plan.get("name").cloned().unwrap_or(Value::Null),
        );
        created.insert("startedAt".into(), num(now));
        if trial_days > 0.0 {
            created.insert("trialEndsAt".into(), num(now + trial_days * DAY_MS));
        }
        created.insert("cancelAtPeriodEnd".into(), Value::Bool(false));
        created.insert("seats".into(), num(seats));
        created.insert(
            "seatHistory".into(),
            json!([{ "at": num(now), "seats": num(seats) }]),
        );
        created.insert("billedAdvance".into(), json!([]));
        created.insert("createdAt".into(), num(now));
        created.insert("createdBy".into(), Value::String(actor_id.to_owned()));
        created.insert("updatedAt".into(), num(now));
        let created = tx.insert(SUBSCRIPTIONS, &created).await?;
        let mut invoice: Option<Record> = None;
        if created.get("trialEndsAt").is_none() {
            let typed_subscription: crate::billing::BillingSubscription = decode(created.clone())?;
            let typed_plan: crate::billing::BillingPlan = decode(plan.clone())?;
            let first = crate::billing_plans::first_period_lines(
                &typed_subscription,
                &typed_plan,
                &settings.time_zone,
            )?;
            let lines = member(Some(&first), "lines")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if !lines.is_empty() {
                let period = member(Some(&first), "period")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let draft = self
                    .draft_statement(
                        tx,
                        account,
                        &period,
                        None,
                        Some(FirstLines {
                            lines,
                            subscription_id: subscription_id.clone(),
                        }),
                    )
                    .await?;
                invoice = Some(
                    self.issue(
                        tx,
                        account,
                        &draft,
                        &format!("subscription:{subscription_id}"),
                        None,
                        Some(actor_id),
                    )
                    .await?
                    .statement,
                );
            }
        }
        let subscription = tx
            .get(SUBSCRIPTIONS, &subscription_id)
            .await?
            .unwrap_or(created);
        Ok(Subscribed {
            subscription,
            invoice,
        })
    }

    /// `updateSeats(tx, subscription, seats, actorId)`: changes the seat count; seats billed in advance for this month
    /// are prorated as invoice items.
    pub async fn update_seats(
        &self,
        tx: &Store,
        subscription: &Record,
        seats: f64,
        actor_id: &str,
    ) -> IamResult<SubscriptionChange> {
        self.assert_live(subscription)?;
        let current = num_of(subscription, "seats").unwrap_or(f64::NAN);
        if seats == current {
            return Ok(SubscriptionChange {
                subscription: subscription.clone(),
                items: Vec::new(),
            });
        }
        let ctx = self.ctx()?;
        let now = ctx.now();
        let plan = self.plan_of(tx, subscription).await?;
        let items = self.proration_items(
            subscription,
            &plan,
            now,
            Some((current, seats)),
            false,
            actor_id,
        )?;
        self.insert_items(tx, &items).await?;
        let mut next = subscription.clone();
        next.insert("seats".into(), num(seats));
        let mut history = subscription
            .get("seatHistory")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        history.push(json!({ "at": num(now), "seats": num(seats) }));
        next.insert("seatHistory".into(), Value::Array(history));
        next.insert("updatedAt".into(), num(now));
        let next = tx.put(SUBSCRIPTIONS, &next).await?;
        Ok(SubscriptionChange {
            subscription: next,
            items,
        })
    }

    /// `cancelSubscription(tx, subscription, atPeriodEnd, actorId)`: cancels a subscription at the end of the month (it
    /// keeps running until then, and can be resumed) or now, when the unused part of the month's advance fees and seats
    /// is credited as invoice items for the next invoice.
    pub async fn cancel_subscription(
        &self,
        tx: &Store,
        subscription: &Record,
        at_period_end: bool,
        actor_id: &str,
    ) -> IamResult<SubscriptionChange> {
        self.assert_live(subscription)?;
        let ctx = self.ctx()?;
        let tz = self.settings()?.time_zone.clone();
        let now = ctx.now();
        if at_period_end {
            let (_, end) = period_bounds(&crate::billing::period_of(now, &tz)?, &tz)?;
            let mut next = subscription.clone();
            next.insert("cancelAtPeriodEnd".into(), Value::Bool(true));
            next.insert("endsAt".into(), num(end));
            next.insert("canceledAt".into(), num(now));
            next.insert("canceledBy".into(), Value::String(actor_id.to_owned()));
            next.insert("updatedAt".into(), num(now));
            let next = tx.put(SUBSCRIPTIONS, &next).await?;
            return Ok(SubscriptionChange {
                subscription: next,
                items: Vec::new(),
            });
        }
        let plan = self.plan_of(tx, subscription).await?;
        let items = self.proration_items(subscription, &plan, now, None, true, actor_id)?;
        self.insert_items(tx, &items).await?;
        let subscription_id = str_of(subscription, "id").unwrap_or_default();
        let mut next = subscription.clone();
        next.insert(
            "uniqueKey".into(),
            Value::String(format!("ended:{subscription_id}")),
        );
        next.insert("cancelAtPeriodEnd".into(), Value::Bool(false));
        next.insert("endsAt".into(), num(now));
        next.insert("canceledAt".into(), num(now));
        next.insert("canceledBy".into(), Value::String(actor_id.to_owned()));
        next.insert("updatedAt".into(), num(now));
        let next = tx.put(SUBSCRIPTIONS, &next).await?;
        Ok(SubscriptionChange {
            subscription: next,
            items,
        })
    }

    /// `resumeSubscription(tx, subscription)`: undoes a cancellation at the end of the month before it takes effect.
    pub async fn resume_subscription(
        &self,
        tx: &Store,
        subscription: &Record,
    ) -> IamResult<Record> {
        self.assert_live(subscription)?;
        if !bool_of(subscription, "cancelAtPeriodEnd") {
            return Err(IamError::with_status(
                "INVALID_TRANSITION",
                "The subscription is not set to cancel",
                409,
            ));
        }
        let ctx = self.ctx()?;
        let mut next = subscription.clone();
        next.shift_remove("endsAt");
        next.shift_remove("canceledAt");
        next.shift_remove("canceledBy");
        next.insert("cancelAtPeriodEnd".into(), Value::Bool(false));
        next.insert("updatedAt".into(), num(ctx.now()));
        tx.put(SUBSCRIPTIONS, &next).await
    }

    /// `changePlan(tx, subscription, plan, actorId)`: moves a subscription to another plan now, keeping its seats and
    /// what is left of its trial: the old plan's unused advance charges are credited and the new plan's charges for the
    /// rest of the month added, both as proration items for the next invoice.
    pub async fn change_plan(
        &self,
        tx: &Store,
        subscription: &Record,
        plan: &Record,
        actor_id: &str,
    ) -> IamResult<SubscriptionChange> {
        self.assert_live(subscription)?;
        let ctx = self.ctx()?;
        let settings = self.settings()?;
        let plan_id = str_of(plan, "id").unwrap_or_default().to_owned();
        if Some(plan_id.as_str()) == str_of(subscription, "planId") {
            return Err(IamError::new(
                "INVALID_INPUT",
                "The subscription is already on this plan",
            ));
        }
        if bool_of(plan, "archived") {
            return Err(IamError::with_status(
                "INVALID_TRANSITION",
                "The plan is archived",
                409,
            ));
        }
        let tenant_id = str_of(subscription, "tenantId")
            .unwrap_or_default()
            .to_owned();
        if self
            .live_subscription(tx, &tenant_id, &plan_id)
            .await?
            .is_some()
        {
            return Err(IamError::with_status(
                "CONFLICT",
                "The account already subscribes to this plan",
                409,
            ));
        }
        let now = ctx.now();
        let current_plan = self.plan_of(tx, subscription).await?;
        let mut items =
            self.proration_items(subscription, &current_plan, now, None, true, actor_id)?;
        let subscription_id = str_of(subscription, "id").unwrap_or_default();
        let mut ended = subscription.clone();
        ended.insert(
            "uniqueKey".into(),
            Value::String(format!("ended:{subscription_id}")),
        );
        ended.insert("cancelAtPeriodEnd".into(), Value::Bool(false));
        ended.insert("endsAt".into(), num(now));
        ended.insert("canceledAt".into(), num(now));
        ended.insert("canceledBy".into(), Value::String(actor_id.to_owned()));
        ended.insert("updatedAt".into(), num(now));
        tx.put(SUBSCRIPTIONS, &ended).await?;
        let trial_ends_at = num_of(subscription, "trialEndsAt").filter(|ends| *ends > now);
        let seats = subscription.get("seats").cloned().unwrap_or(Value::Null);
        let created_id = id();
        let mut created = Record::new();
        created.insert("id".into(), Value::String(created_id.clone()));
        created.insert("tenantId".into(), Value::String(tenant_id.clone()));
        created.insert("uniqueKey".into(), Value::String(format!("plan:{plan_id}")));
        created.insert("planId".into(), Value::String(plan_id.clone()));
        created.insert(
            "planKey".into(),
            plan.get("key").cloned().unwrap_or(Value::Null),
        );
        created.insert(
            "planName".into(),
            plan.get("name").cloned().unwrap_or(Value::Null),
        );
        created.insert("startedAt".into(), num(now));
        if let Some(trial_ends_at) = trial_ends_at {
            created.insert("trialEndsAt".into(), num(trial_ends_at));
        }
        created.insert("cancelAtPeriodEnd".into(), Value::Bool(false));
        created.insert("seats".into(), seats.clone());
        created.insert(
            "seatHistory".into(),
            json!([{ "at": num(now), "seats": seats }]),
        );
        created.insert("billedAdvance".into(), json!([]));
        created.insert("createdAt".into(), num(now));
        created.insert("createdBy".into(), Value::String(actor_id.to_owned()));
        created.insert("updatedAt".into(), num(now));
        let typed_subscription: crate::billing::BillingSubscription = decode(created.clone())?;
        let typed_plan: crate::billing::BillingPlan = decode(plan.clone())?;
        let first = crate::billing_plans::first_period_lines(
            &typed_subscription,
            &typed_plan,
            &settings.time_zone,
        )?;
        let first_period = member(Some(&first), "period")
            .cloned()
            .unwrap_or(Value::Null);
        let plan_name = str_of(plan, "name").unwrap_or_default().to_owned();
        for line in records_of(member(Some(&first), "lines")) {
            let amount = line.get("amountMicros").cloned().unwrap_or(Value::Null);
            let mut item = Record::new();
            item.insert("id".into(), Value::String(id()));
            item.insert("tenantId".into(), Value::String(tenant_id.clone()));
            item.insert(
                "description".into(),
                Value::String(format!(
                    "{plan_name}: {} for the rest of the month",
                    crate::js::js_string(line.get("name"))
                )),
            );
            item.insert("quantity".into(), num(1.0));
            item.insert("unitAmountMicros".into(), amount.clone());
            item.insert("amountMicros".into(), amount);
            item.insert("period".into(), first_period.clone());
            item.insert("status".into(), Value::String("pending".into()));
            item.insert("source".into(), Value::String("proration".into()));
            item.insert("subscriptionId".into(), Value::String(created_id.clone()));
            item.insert("createdAt".into(), num(now));
            item.insert("createdBy".into(), Value::String(actor_id.to_owned()));
            items.push(item);
        }
        // The rest of this month is billed through those items rather than an invoice of its own.
        let advance = records_of(plan.get("items")).iter().any(|item| {
            str_of(item, "kind") != Some("usage") && str_of(item, "billing") != Some("arrears")
        });
        if advance {
            created.insert("billedAdvance".into(), Value::Array(vec![first_period]));
        }
        self.insert_items(tx, &items).await?;
        let next = tx.insert(SUBSCRIPTIONS, &created).await?;
        Ok(SubscriptionChange {
            subscription: next,
            items,
        })
    }

    /// `recordSeats({ meter?, tenantId?, kinds? })`: records one seat of `meter` (default `seats`) for every active
    /// person (or `kinds`) of every tenant the meter reaches, once per day (idempotent): a `sum` meter then counts
    /// seat-days, a `unique` meter active seats per month. Seats are attributed to the person, their teams and
    /// department. A tenant that fails is reported in `failedTenants` and the others are still recorded. A scheduler
    /// job, run daily. Answers `SeatRecordResult` as JSON.
    pub async fn record_seats(&self, input: Option<&Value>) -> IamResult<Value> {
        let ctx = self.ctx()?;
        let settings = self.settings()?;
        let key = match member(input, "meter") {
            None | Some(Value::Null) => crate::billing::meter_key(Some(&json!("seats")))?,
            Some(value) => crate::billing::meter_key(Some(value))?,
        };
        let kinds: Vec<String> = match member(input, "kinds") {
            None | Some(Value::Null) => vec!["user".to_owned()],
            Some(Value::Array(items))
                if !items.is_empty()
                    && items.iter().all(|kind| {
                        matches!(
                            kind.as_str(),
                            Some("user") | Some("service") | Some("agent")
                        )
                    }) =>
            {
                items
                    .iter()
                    .filter_map(|kind| kind.as_str().map(str::to_owned))
                    .collect()
            }
            Some(_) => {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "kinds must list 'user', 'service' or 'agent'",
                ));
            }
        };
        let day = crate::billing::day_of(ctx.now(), &settings.time_zone)?;
        let tenant_id = member(input, "tenantId").cloned();
        let ctx_ref = &ctx;
        let mut tenants: Vec<Tenant> = ctx
            .store
            .transaction(move |tx| async move {
                match &tenant_id {
                    None => find_all(&tx, "tenants", Filter::new().eq("status", "active"))
                        .await?
                        .into_iter()
                        .map(decode)
                        .collect::<IamResult<Vec<Tenant>>>(),
                    Some(value) => {
                        let realm = ctx_ref
                            .tenant(&tx, &text(Some(value), "tenantId", 256)?)
                            .await?;
                        Ok(crate::billing::subtree(ctx_ref, &tx, &realm)
                            .await?
                            .into_iter()
                            .filter(|realm| realm.status == TenantStatus::Active)
                            .collect())
                    }
                }
            })
            .await?;
        tenants.sort_by(|a, b| a.id.cmp(&b.id));
        let mut recorded = 0.0;
        let mut duplicates = 0.0;
        let mut skipped_tenants = 0.0;
        let mut failed_tenants: Vec<Value> = Vec::new();
        let key_ref = key.as_str();
        let day_ref = day.as_str();
        let kinds_ref = &kinds;
        for realm in tenants {
            if realm.parent_id.is_none() {
                continue;
            }
            let realm_id = realm.id.clone();
            let realm_ref = &realm;
            let counts: IamResult<Option<(f64, f64)>> = ctx
                .store
                .transaction(move |tx| async move {
                    let chain = ctx_ref.ancestry(&tx, realm_ref).await?;
                    let Some(meter) = crate::billing::resolve_meter(&tx, &chain, key_ref)
                        .await?
                        .filter(|meter| !meter.archived)
                    else {
                        return Ok(None);
                    };
                    let mut people: Vec<Record> = Vec::new();
                    for identity in find_all(
                        &tx,
                        "identities",
                        Filter::new()
                            .eq("tenantId", realm_ref.id.as_str())
                            .eq("status", "active"),
                    )
                    .await?
                    {
                        let kind = str_of(&identity, "kind").unwrap_or_default().to_owned();
                        if !kinds_ref.contains(&kind) {
                            continue;
                        }
                        let typed: Identity = decode(identity.clone())?;
                        if !ctx_ref.identity_expired(&typed) {
                            people.push(identity);
                        }
                    }
                    people.sort_by(|a, b| {
                        str_of(a, "id")
                            .unwrap_or_default()
                            .cmp(str_of(b, "id").unwrap_or_default())
                    });
                    let mut recorded = 0.0;
                    let mut duplicates = 0.0;
                    for identity in &people {
                        let identity_id = str_of(identity, "id").unwrap_or_default();
                        // Seats recorded under the caller-visible `idem:` key of earlier releases (by this job only)
                        // still count.
                        let legacy = first_record(
                            &tx,
                            USAGE,
                            Filter::new().eq("tenantId", realm_ref.id.as_str()).eq(
                                "uniqueKey",
                                format!("idem:seat:{key_ref}:{identity_id}:{day_ref}"),
                            ),
                        )
                        .await?;
                        if let Some(legacy) = &legacy
                            && str_of(legacy, "recordedBy") == Some("deployment")
                            && str_of(legacy, "meterId") == Some(meter.id.as_str())
                        {
                            duplicates += 1.0;
                            continue;
                        }
                        // A source key (`src:`), which callers of `record` cannot claim ahead of the job.
                        let seat = self
                            .record(
                                &tx,
                                &json!({
                                    "tenantId": realm_ref.id,
                                    "meter": key_ref,
                                    "quantity": 1,
                                    "identityId": identity_id,
                                }),
                                "deployment",
                                RecordExtras {
                                    meter: Some(meter.clone()),
                                    source_id: Some(format!("seat:{identity_id}:{day_ref}")),
                                    ..RecordExtras::default()
                                },
                            )
                            .await?;
                        if seat.duplicate {
                            duplicates += 1.0;
                        } else {
                            recorded += 1.0;
                        }
                    }
                    Ok(Some((recorded, duplicates)))
                })
                .await;
            match counts {
                Ok(None) => skipped_tenants += 1.0,
                Ok(Some((tenant_recorded, tenant_duplicates))) => {
                    recorded += tenant_recorded;
                    duplicates += tenant_duplicates;
                }
                // One tenant's failure never stops the platform-wide job.
                Err(error) => failed_tenants.push(json!({
                    "tenantId": realm_id,
                    "code": error.code,
                    "message": error.message,
                })),
            }
        }
        Ok(json!({
            "meter": key,
            "day": day,
            "recorded": num(recorded),
            "duplicates": num(duplicates),
            "skippedTenants": num(skipped_tenants),
            "failedTenants": failed_tenants,
        }))
    }

    /// `ownIdentities(tx, identity)`: every identity whose spend counts as a person's own: themselves and the agents
    /// they sponsor.
    pub async fn own_identities(
        &self,
        tx: &Store,
        identity: &Identity,
    ) -> IamResult<IndexSet<String>> {
        let mut own: IndexSet<String> = IndexSet::new();
        own.insert(identity.id.clone());
        for agent in find_all(
            tx,
            "identities",
            Filter::new()
                .eq("tenantId", identity.tenant_id.as_str())
                .eq("kind", "agent"),
        )
        .await?
        {
            if member(agent.get("agent"), "sponsorId").and_then(Value::as_str)
                == Some(identity.id.as_str())
                && let Some(agent_id) = str_of(&agent, "id")
            {
                own.insert(agent_id.to_owned());
            }
        }
        Ok(own)
    }

    /// `teamWithin(dir, candidate, teamId)`: whether a team is `teamId` or below it.
    pub fn team_within(dir: &Directory, candidate: &str, team_id: &str) -> bool {
        crate::teams::team_chain_of(&dir.teams, candidate)
            .iter()
            .any(|team| team.id == team_id)
    }

    /// `departmentWithin(dir, candidate, departmentId)`: whether a department is `departmentId` or below it.
    pub fn department_within(dir: &Directory, candidate: &str, department_id: &str) -> bool {
        crate::departments::department_chain_of(&dir.departments, candidate)
            .iter()
            .any(|department| department.id == department_id)
    }

    // -----------------------------------------------------------------------------------------------------------
    // Anomalies

    /// Validated anomaly settings.
    fn anomaly_options(&self, input: Option<&Value>) -> IamResult<AnomalySettings> {
        let ctx = self.ctx()?;
        let now = ctx.now();
        let day = match member(input, "day") {
            None => crate::billing::day_of(now - DAY_MS, &self.settings()?.time_zone)?,
            Some(value) => {
                let day = crate::js::js_string(Some(value));
                if !valid_day(&day) {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "day must be a date such as 2026-09-22",
                    ));
                }
                day
            }
        };
        let baseline_days = match member(input, "baselineDays") {
            None => 14.0,
            Some(value) => integer(Some(value), "baselineDays", 3.0, 90.0)?,
        };
        let factor = match member(input, "factor") {
            None => 3.0,
            Some(Value::Number(number)) => core_js::number_value(number),
            Some(_) => f64::NAN,
        };
        if !factor.is_finite() || !(1.1..=1000.0).contains(&factor) {
            return Err(IamError::new(
                "INVALID_INPUT",
                "factor must be a number from 1.1 to 1000",
            ));
        }
        let minimum_micros = match member(input, "minimum") {
            None => 10.0 * 1_000_000.0,
            Some(value) => crate::billing::amount_micros(Some(value), "minimum")?,
        };
        Ok(AnomalySettings {
            day,
            baseline_days,
            factor,
            minimum_micros,
        })
    }

    /// `findAnomalies(tx, rowsFor, input, scopeIds)`: spend spikes: people, teams and meters whose spend on `day`
    /// (default yesterday) is at least `factor` (3) times their average over the `baselineDays` (14) before it and at
    /// least `minimum` (10 currency units) above it, or new spenders above `minimum`. Rows come from the charged usage
    /// of one scope, so costs follow each month's blended rates.
    async fn find_anomalies(
        &self,
        tx: &Store,
        source: RowSource<'_>,
        input: Option<&Value>,
        scope_ids: &[String],
    ) -> IamResult<Vec<SpendAnomaly>> {
        use crate::billing::round_micros;
        let ctx = self.ctx()?;
        let settings = self.settings()?;
        let AnomalySettings {
            day,
            baseline_days,
            factor,
            minimum_micros,
        } = self.anomaly_options(input)?;
        let baseline = days_before(&day, baseline_days);
        let mut window: IndexSet<String> = baseline.into_iter().collect();
        window.insert(day.clone());
        let mut periods: IndexSet<String> = IndexSet::new();
        for value in &window {
            periods.insert(value.chars().take(7).collect());
        }
        let cache = SpendCache::default();
        let mut rows: Vec<ChargedRow> = Vec::new();
        for period in &periods {
            let period_rows = match source {
                RowSource::Scope(scope) => scope_spend(&ctx, tx, scope, period, &cache).await?.0,
                RowSource::Account(account) => {
                    account_spend(&ctx, tx, account, period, &cache).await?.rows
                }
            };
            rows.extend(
                period_rows
                    .into_iter()
                    .filter(|row| window.contains(&row.day)),
            );
        }
        let dir = self.directory(&ctx, tx, &rows, scope_ids).await?;
        let mut totals: IndexMap<String, (f64, f64)> = IndexMap::new();
        let mut meter_ids: IndexMap<String, String> = IndexMap::new();
        let mut add = |key: String, row: &ChargedRow, weight: f64| {
            let entry = totals.entry(key).or_insert((0.0, 0.0));
            if row.day == day {
                entry.0 += row.cost_micros * weight;
            } else {
                entry.1 += row.cost_micros * weight;
            }
        };
        for row in &rows {
            if let Some(principal) = row.agent_id.as_ref().or(row.identity_id.as_ref())
                && !principal.is_empty()
            {
                add(format!("identity|{principal}"), row, 1.0);
            }
            add(format!("meter|{}", row.meter), row, 1.0);
            meter_ids.insert(row.meter.clone(), row.meter_id.clone());
            let share = if settings.team_attribution == "full" {
                1.0
            } else {
                1.0 / (row.team_ids.len().max(1) as f64)
            };
            for team in &row.team_ids {
                add(format!("team|{team}"), row, share);
            }
        }
        let mut found: Vec<SpendAnomaly> = Vec::new();
        for (compound, (on_day, before)) in &totals {
            let cost_micros = round_micros(*on_day)?;
            let baseline_micros = round_micros(before / baseline_days)?;
            if cost_micros < minimum_micros || cost_micros - baseline_micros < minimum_micros {
                continue;
            }
            if baseline_micros > 0.0 && cost_micros < baseline_micros * factor {
                continue;
            }
            let mut parts = compound.split('|');
            let dimension = parts.next().unwrap_or_default().to_owned();
            let key = parts.next().unwrap_or_default().to_owned();
            found.push(SpendAnomaly {
                dimension,
                key,
                day: day.clone(),
                cost_micros,
                baseline_micros,
                factor: (baseline_micros > 0.0)
                    .then(|| js_round(cost_micros / baseline_micros * 10.0) / 10.0),
                label: None,
                extra: Map::new(),
            });
        }
        found.sort_by(|a, b| {
            by_difference(
                b.cost_micros - b.baseline_micros - (a.cost_micros - a.baseline_micros),
                || a.key.cmp(&b.key),
            )
        });
        found.truncate(50);
        for anomaly in &mut found {
            let label = match anomaly.dimension.as_str() {
                "team" => dir.teams.get(&anomaly.key).map(|team| team.name.clone()),
                "identity" => name_in(tx, "identities", &anomaly.key).await?,
                _ => {
                    let meter_id = meter_ids.get(&anomaly.key).cloned().unwrap_or_default();
                    name_in(tx, METERS, &meter_id).await?
                }
            };
            if label.is_some() {
                anomaly.label = label;
            }
        }
        Ok(found)
    }

    /// `anomalies(tx, scope, input)`: anomalies within a tenant's subtree, for `billing.anomalies` (`AnomalyOptions`
    /// as JSON).
    pub async fn anomalies(
        &self,
        tx: &Store,
        scope: &Tenant,
        input: Option<&Value>,
    ) -> IamResult<Vec<SpendAnomaly>> {
        self.find_anomalies(
            tx,
            RowSource::Scope(scope),
            input,
            std::slice::from_ref(&scope.id),
        )
        .await
    }

    /// `detectAnomalies({ tenantId?, ...options })`: checks every billing account for spend spikes on `day` (default
    /// yesterday) and alerts once per person, team or meter and day: audited as `billing:anomaly` and, with an email
    /// transport, one `spend-anomaly` email per account to its billing emails (or owners). A scheduler job, run daily
    /// after midnight in the billing time zone. Answers `AnomalyAlertResult` as JSON.
    pub async fn detect_anomalies(&self, input: Option<&Value>) -> IamResult<Value> {
        let ctx = self.ctx()?;
        let settings = self.settings()?;
        let tenant_id = member(input, "tenantId").cloned();
        let mut options = object_of(input);
        options.shift_remove("tenantId");
        let options = Value::Object(options);
        self.anomaly_options(Some(&options))?;
        let ctx_ref = &ctx;
        let mut accounts: Vec<Tenant> = ctx
            .store
            .transaction(move |tx| async move {
                let mut found: IndexMap<String, Tenant> = IndexMap::new();
                let candidates: Vec<Tenant> = match &tenant_id {
                    None => find_all(&tx, "tenants", Filter::new().eq("status", "active"))
                        .await?
                        .into_iter()
                        .map(decode)
                        .collect::<IamResult<Vec<Tenant>>>()?,
                    Some(value) => vec![
                        ctx_ref
                            .tenant(&tx, &text(Some(value), "tenantId", 256)?)
                            .await?,
                    ],
                };
                for realm in candidates {
                    if realm.parent_id.is_none() {
                        continue;
                    }
                    let account = crate::billing::account_of(ctx_ref, &tx, &realm).await?;
                    if tenant_id.is_some() || account.id == realm.id {
                        found.insert(account.id.clone(), account);
                    }
                }
                Ok(found.into_values().collect::<Vec<Tenant>>())
            })
            .await?;
        accounts.sort_by(|a, b| a.id.cmp(&b.id));
        let mut checked = 0.0;
        let mut anomalies: Vec<Value> = Vec::new();
        let options_ref = &options;
        for candidate in accounts {
            let candidate_id = candidate.id.clone();
            let outcome: Option<Vec<Value>> = ctx
                .store
                .transaction(move |tx| async move {
                    let account = ctx_ref.tenant(&tx, &candidate_id).await?;
                    if account.status == TenantStatus::Deleted {
                        return Ok(None);
                    }
                    let found = self
                        .find_anomalies(
                            &tx,
                            RowSource::Account(&account),
                            Some(options_ref),
                            std::slice::from_ref(&account.id),
                        )
                        .await?;
                    let mut fresh: Vec<SpendAnomaly> = Vec::new();
                    for anomaly in found {
                        let unique_key = format!(
                            "anomaly:{}:{}:{}",
                            anomaly.dimension, anomaly.key, anomaly.day
                        );
                        if !find_all(
                            &tx,
                            ALERTS,
                            Filter::new()
                                .eq("tenantId", account.id.as_str())
                                .eq("uniqueKey", unique_key.as_str()),
                        )
                        .await?
                        .is_empty()
                        {
                            continue;
                        }
                        let mut alert = Record::new();
                        alert.insert("id".into(), Value::String(id()));
                        alert.insert("tenantId".into(), Value::String(account.id.clone()));
                        alert.insert("uniqueKey".into(), Value::String(unique_key));
                        alert.insert("budgetId".into(), Value::String(String::new()));
                        alert.insert("window".into(), Value::String(anomaly.day.clone()));
                        alert.insert("kind".into(), Value::String("anomaly".into()));
                        alert.insert("threshold".into(), num(anomaly.factor.unwrap_or(0.0)));
                        alert.insert("spentMicros".into(), num(anomaly.cost_micros));
                        alert.insert("alertedAt".into(), num(ctx_ref.now()));
                        tx.insert(ALERTS, &alert).await?;
                        let mut metadata = Map::new();
                        metadata
                            .insert("dimension".into(), Value::String(anomaly.dimension.clone()));
                        metadata.insert("key".into(), Value::String(anomaly.key.clone()));
                        if let Some(label) = &anomaly.label {
                            metadata.insert("label".into(), Value::String(label.clone()));
                        }
                        metadata.insert("day".into(), Value::String(anomaly.day.clone()));
                        metadata.insert("costMicros".into(), num(anomaly.cost_micros));
                        metadata.insert("baselineMicros".into(), num(anomaly.baseline_micros));
                        metadata.insert(
                            "factor".into(),
                            anomaly.factor.map(num).unwrap_or(Value::Null),
                        );
                        ctx_ref
                            .events()?
                            .record_audit(
                                &tx,
                                &system_event(
                                    &account.id,
                                    "deployment-operator",
                                    "billing:anomaly",
                                    &format!(
                                        "billing/anomalies/{}/{}",
                                        anomaly.dimension, anomaly.key
                                    ),
                                    ctx_ref.now(),
                                    metadata,
                                ),
                            )
                            .await?;
                        fresh.push(anomaly);
                    }
                    if fresh.is_empty() {
                        return Ok(Some(Vec::new()));
                    }
                    let recipients: Vec<String> = if sends_email(ctx_ref) {
                        let emails = crate::billing::profile_of(&tx, &account.id)
                            .await?
                            .map(|profile| {
                                strings_of(&crate::port::encode(&profile), "billingEmails")
                            })
                            .unwrap_or_default();
                        if !emails.is_empty() {
                            emails
                        } else {
                            self.owners(&tx, &account.id).await?
                        }
                    } else {
                        Vec::new()
                    };
                    let mut lines: Vec<Value> = Vec::new();
                    for anomaly in fresh.iter().take(5) {
                        let what = match anomaly.dimension.as_str() {
                            "meter" => "Meter",
                            "team" => "Team",
                            _ => "Person",
                        };
                        lines.push(json!({
                            "what": format!(
                                "{what} {}",
                                anomaly.label.clone().unwrap_or_else(|| anomaly.key.clone())
                            ),
                            "spent": format_money(anomaly.cost_micros, &settings.currency)?,
                            "usual": format_money(anomaly.baseline_micros, &settings.currency)?,
                        }));
                    }
                    for to in &recipients {
                        let mut payload = Map::new();
                        payload.insert("tenantId".into(), Value::String(account.id.clone()));
                        payload.insert("tenantName".into(), Value::String(account.name.clone()));
                        payload.insert("day".into(), Value::String(fresh[0].day.clone()));
                        payload.insert("count".into(), Value::String(fresh.len().to_string()));
                        payload.insert(
                            "items".into(),
                            Value::String(core_js::stringify(&Value::Array(lines.clone()))),
                        );
                        ctx_ref
                            .auth
                            .enqueue_delivery(
                                &tx,
                                email_input(&account.id, to, "spend-anomaly", payload),
                            )
                            .await?;
                    }
                    let mut entries = Vec::new();
                    for anomaly in fresh {
                        let mut entry = Map::new();
                        entry.insert("accountId".into(), Value::String(account.id.clone()));
                        entry.extend(crate::port::encode(&anomaly));
                        entry.insert("recipients".into(), num(recipients.len() as f64));
                        entries.push(Value::Object(entry));
                    }
                    Ok(Some(entries))
                })
                .await?;
            if let Some(found) = outcome {
                checked += 1.0;
                anomalies.extend(found);
            }
        }
        Ok(json!({ "checked": num(checked), "anomalies": anomalies }))
    }

    // -----------------------------------------------------------------------------------------------------------
    // CSV

    /// `spendCsv(report)`: a spend report as CSV: one row per group with amount, share, events and a column per
    /// meter's quantity.
    pub fn spend_csv(&self, report: &SpendReport) -> String {
        let rows: Vec<Record> = report.rows.iter().map(|row| object_of(Some(row))).collect();
        let mut meters: Vec<String> = Vec::new();
        for row in &rows {
            for meter in object_of(row.get("quantities")).keys() {
                if !meters.contains(meter) {
                    meters.push(meter.clone());
                }
            }
        }
        crate::js::sort_strings(&mut meters);
        let money = |micros: Option<f64>| to_fixed(micros.unwrap_or(f64::NAN) / 1_000_000.0, 6);
        let mut lines: Vec<Vec<String>> = Vec::new();
        let mut header = vec![
            crate::js::js_string(Some(&report.group_by)),
            "label".to_owned(),
            format!("amount_{}", report.currency.to_lowercase()),
            "share_percent".to_owned(),
            "events".to_owned(),
        ];
        header.extend(meters.iter().map(|meter| format!("quantity_{meter}")));
        lines.push(header);
        for row in &rows {
            let quantities = object_of(row.get("quantities"));
            let mut line = vec![
                crate::js::js_string(row.get("key")),
                row.get("label")
                    .map(|label| crate::js::js_string(Some(label)))
                    .unwrap_or_default(),
                money(num_of(row, "costMicros")),
                crate::js::js_string(row.get("share")),
                crate::js::js_string(row.get("events")),
            ];
            line.extend(meters.iter().map(|meter| {
                quantities
                    .get(meter)
                    .map(|quantity| crate::js::js_string(Some(quantity)))
                    .unwrap_or_else(|| "0".to_owned())
            }));
            lines.push(line);
        }
        let mut total = vec![
            "total".to_owned(),
            String::new(),
            money(member(Some(&report.total), "costMicros").and_then(core_js::as_number)),
            "100".to_owned(),
            crate::js::js_string(member(Some(&report.total), "events")),
        ];
        total.extend(meters.iter().map(|_| String::new()));
        lines.push(total);
        csv(&lines)
    }

    /// `statementCsv(statement)`: a statement as CSV: its lines, credit and total, then the breakdown sections.
    pub fn statement_csv(&self, statement: &Record) -> String {
        let money = |micros: f64| to_fixed(micros / 1_000_000.0, 6);
        let number = |record: &Record, key: &str| num_of(record, key).unwrap_or(f64::NAN);
        let string = |record: &Record, key: &str| crate::js::js_string(record.get(key));
        let mut rows: Vec<Vec<String>> = vec![vec![
            "section".into(),
            "id".into(),
            "name".into(),
            "quantity".into(),
            "unit".into(),
            "amount".into(),
            "cost_center".into(),
        ]];
        for line in records_of(statement.get("lines")) {
            let kind = str_of(&line, "kind")
                .filter(|kind| !kind.is_empty() && *kind != "usage")
                .unwrap_or("line")
                .to_owned();
            let line_id = ["meter", "planItemId", "invoiceItemId"]
                .iter()
                .find_map(|key| line.get(*key).filter(|value| !value.is_null()))
                .map(|value| crate::js::js_string(Some(value)))
                .unwrap_or_default();
            rows.push(vec![
                kind,
                line_id,
                string(&line, "name"),
                string(&line, "quantity"),
                string(&line, "unit"),
                money(number(&line, "amountMicros")),
                String::new(),
            ]);
        }
        rows.push(vec![
            "subtotal".into(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            money(number(statement, "subtotalMicros")),
            String::new(),
        ]);
        if let Some(discount) = statement
            .get("discount")
            .filter(|value| crate::js::truthy(Some(value)))
        {
            let discount = object_of(Some(discount));
            rows.push(vec![
                "discount".into(),
                String::new(),
                format!("{}%", string(&discount, "percent")),
                String::new(),
                String::new(),
                money(-number(&discount, "amountMicros")),
                String::new(),
            ]);
        }
        if let Some(commitment) = statement
            .get("commitment")
            .filter(|value| crate::js::truthy(Some(value)))
        {
            let commitment = object_of(Some(commitment));
            if number(&commitment, "trueUpMicros") > 0.0 {
                rows.push(vec![
                    "commitment".into(),
                    String::new(),
                    "minimum commitment true-up".into(),
                    String::new(),
                    String::new(),
                    money(number(&commitment, "trueUpMicros")),
                    String::new(),
                ]);
            }
        }
        for coupon in records_of(statement.get("coupons")) {
            rows.push(vec![
                "coupon".into(),
                string(&coupon, "code"),
                string(&coupon, "name"),
                String::new(),
                String::new(),
                money(-number(&coupon, "amountMicros")),
                String::new(),
            ]);
        }
        rows.push(vec![
            "credit".into(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            money(-number(statement, "creditsMicros")),
            String::new(),
        ]);
        if let Some(tax) = statement
            .get("tax")
            .filter(|value| crate::js::truthy(Some(value)))
        {
            let tax = object_of(Some(tax));
            rows.push(vec![
                "tax".into(),
                String::new(),
                format!("{} {}%", string(&tax, "label"), string(&tax, "ratePercent")),
                String::new(),
                String::new(),
                money(number(&tax, "amountMicros")),
                String::new(),
            ]);
        }
        rows.push(vec![
            "total".into(),
            string(statement, "number"),
            string(statement, "period"),
            String::new(),
            string(statement, "currency"),
            money(number(statement, "totalMicros")),
            String::new(),
        ]);
        let breakdown = object_of(statement.get("breakdown"));
        for (section, key) in [
            ("tenant", "tenants"),
            ("team", "teams"),
            ("department", "departments"),
            ("identity", "identities"),
        ] {
            for entry in records_of(breakdown.get(key)) {
                rows.push(vec![
                    section.into(),
                    string(&entry, "id"),
                    string(&entry, "name"),
                    String::new(),
                    String::new(),
                    money(number(&entry, "costMicros")),
                    if section == "department" {
                        entry
                            .get("costCenter")
                            .filter(|value| !value.is_null())
                            .map(|value| crate::js::js_string(Some(value)))
                            .unwrap_or_default()
                    } else {
                        String::new()
                    },
                ]);
            }
        }
        csv(&rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collections_match_the_billing_module() {
        let collections = &*crate::billing::BILLING_COLLECTIONS;
        for (key, name) in [
            ("meters", METERS),
            ("usage", USAGE),
            ("rollups", ROLLUPS),
            ("budgets", BUDGETS),
            ("budgetAlerts", ALERTS),
            ("credits", CREDITS),
            ("statements", STATEMENTS),
            ("invoiceItems", INVOICE_ITEMS),
            ("creditNotes", CREDIT_NOTES),
            ("plans", PLANS),
            ("subscriptions", SUBSCRIPTIONS),
            ("discounts", DISCOUNTS),
            ("terms", TERMS),
        ] {
            assert_eq!(collections[key], name, "{key}");
        }
    }

    #[test]
    fn rounds_and_pads_like_javascript() {
        assert_eq!(js_round(2.5), 3.0);
        assert_eq!(js_round(-2.5), -2.0);
        assert_eq!(js_round(0.499_999_999_999_999_94), 0.0);
        assert_eq!(one_decimal(12.345), 12.3);
        assert_eq!(pad_start(7.0, 4), "0007");
        assert_eq!(pad_start(12_345.0, 4), "12345");
        assert!(js_max(0.0, f64::NAN).is_nan());
        assert_eq!(js_max(0.0, -3.0), 0.0);
    }

    #[test]
    fn formats_fixed_decimals_like_to_fixed() {
        assert_eq!(to_fixed(50.0, 6), "50.000000");
        assert_eq!(to_fixed(-20.0, 6), "-20.000000");
        // Ties of the exact value round up, where Rust formatting rounds to even.
        assert_eq!(to_fixed(0.007_812_5, 6), "0.007813");
        assert_eq!(to_fixed(2.5, 0), "3");
        assert_eq!(to_fixed(1.005, 2), "1.00");
        assert_eq!(to_fixed(-0.000_000_1, 6), "-0.000000");
        assert_eq!(to_fixed(-0.0, 2), "0.00");
        assert_eq!(to_fixed(1e21, 2), "1e+21");
    }

    #[test]
    fn formats_money_like_intl_in_en_us() {
        assert_eq!(currency_format(25.0, "USD"), "$25.00");
        assert_eq!(currency_format(1_234_567.89, "USD"), "$1,234,567.89");
        assert_eq!(currency_format(-5.5, "USD"), "-$5.50");
        assert_eq!(currency_format(0.0, "EUR"), "\u{20ac}0.00");
        assert_eq!(currency_format(1234.5, "JPY"), "\u{a5}1,235");
        assert_eq!(currency_format(10.0, "CHF"), "CHF\u{a0}10.00");
        assert_eq!(currency_format(1.5, "BHD"), "BHD\u{a0}1.500");
        assert_eq!(currency_format(99.0, "CAD"), "CA$99.00");
    }

    #[test]
    fn writes_csv_without_formulas() {
        let body = csv(&[vec![
            "=SUM(A1)".to_owned(),
            "-12.5".to_owned(),
            "a,b".to_owned(),
            "say \"hi\"".to_owned(),
            "-1+cmd|' /C calc'!A0".to_owned(),
            "@x".to_owned(),
        ]]);
        assert_eq!(
            body,
            "'=SUM(A1),-12.5,\"a,b\",\"say \"\"hi\"\"\",'-1+cmd|' /C calc'!A0,'@x\r\n"
        );
        assert_eq!(csv(&[vec!["a".into()], vec!["b".into()]]), "a\r\nb\r\n");
    }

    #[test]
    fn validates_group_by_and_days() {
        for valid in [
            "meter",
            "identity",
            "agent",
            "team",
            "department",
            "tenant",
            "day",
            "tag:env",
        ] {
            assert_eq!(spend_group_by(Some(&json!(valid))).unwrap(), valid);
        }
        let long = format!("tag:a{}", "b".repeat(63));
        assert!(spend_group_by(Some(&json!(long))).is_ok());
        let too_long = format!("tag:a{}", "b".repeat(64));
        for invalid in [json!("tag:1x"), json!(too_long), json!(7), json!("week")] {
            let error = spend_group_by(Some(&invalid)).unwrap_err();
            assert_eq!(error.code, "INVALID_INPUT");
        }
        assert!(valid_day("2026-09-22"));
        assert!(valid_day("2026-02-31"));
        assert!(!valid_day("2026-13-01"));
        assert!(!valid_day("2026-00-10"));
        assert!(!valid_day("26-09-22"));
        assert_eq!(
            days_before("2026-03-02", 3.0),
            ["2026-02-27", "2026-02-28", "2026-03-01"]
        );
        // Like Date.UTC, a day past the end of the month carries over.
        assert_eq!(days_before("2026-02-31", 1.0), ["2026-03-02"]);
    }
}
