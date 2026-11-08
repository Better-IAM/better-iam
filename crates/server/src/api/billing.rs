//! Port of `packages/server/src/api/billing.ts`.
//!
//! The `billing` group: usage-based billing and spend tracking. Billing managers (`iam:billing:manage`) define meters
//! and prices for their subtree, budgets, and the billing profile; `iam:billing:read` reads spend (by person, team,
//! department, project, meter, day or tag), budgets, credits and statements; `iam:billing:record` meters usage (a
//! backend's service account). People read their own spend (`mySpend`), team maintainers their team's (`teamSpend`),
//! department heads their department's (`departmentSpend`). Credits, period closing and payment status are root-only.
//! `iam.billing` ([`BillingRuntime`]) is the trusted, credential-free side for the deployment's own server code.

use std::cmp::Ordering;
use std::future::Future;
use std::sync::Arc;

use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, IdentityKind, Record, SessionKind, Tenant, TenantStatus, js as core_js,
};
use better_iam_types::api::billing;
use indexmap::IndexSet;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply};
use crate::billing::{
    BillingBudget, BillingCoupon, BillingCredit, BillingCreditNote, BillingDiscount,
    BillingInvoiceItem, BillingMeter, BillingPlan, BillingPrice, BillingProfile, BillingSettings,
    BillingStatement, BillingSubscription, BillingTerms, ChargedRow, MAX_METERS_PER_TENANT,
    SpendCache, UsageReceipt, account_of, account_spend, amount_due, amount_micros, amount_paid,
    billing_period, billing_settings, budget_thresholds, discount_active, meter_key,
    meter_settings, meters_for, period_of, price_for, price_quantity, price_spec, profile_of,
    public_price_spec, resolve_meter, round_micros, shift_period, statement_hash,
    subscription_status, subtree, terms_of, units_of,
};
use crate::billing_invoices::{
    coupon_code, coupon_settings, invoice_item_input, render_invoice_html,
};
use crate::billing_plans::{MAX_PLANS_PER_TENANT, plan_key, plan_settings};
use crate::billing_service::{
    BillingService, BudgetStatus, ClosePeriodResult, SpendAnomaly, SpendCheck, SpendReport,
    SpendTrend, StatementDraft, billing_service_of, built_in_meter_key,
};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, OperationDenied, OperationResult};
use crate::departments::department_heads_of;
use crate::js::number;
use crate::metrics::locale_compare;
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::port::{decode, not_ported};
use crate::session_kinds::acts_in_own_right;
use crate::teams::is_team_maintainer_at;
use crate::utils::id;
use crate::validation::{email, integer, object, text};

const METERS: &str = "billingMeters";
const PRICES: &str = "billingPrices";
const USAGE: &str = "billingUsage";
const ROLLUPS: &str = "billingRollups";
const BUDGETS: &str = "billingBudgets";
const BUDGET_ALERTS: &str = "billingBudgetAlerts";
const CREDITS: &str = "billingCredits";
const PROFILES: &str = "billingProfiles";
const STATEMENTS: &str = "billingStatements";
const TERMS: &str = "billingTerms";
const INVOICE_ITEMS: &str = "billingInvoiceItems";
const CREDIT_NOTES: &str = "billingCreditNotes";
const PLANS: &str = "billingPlans";
const SUBSCRIPTIONS: &str = "billingSubscriptions";
const COUPONS: &str = "billingCoupons";
const DISCOUNTS: &str = "billingDiscounts";

const MAX_BUDGETS_PER_TENANT: usize = 200;
const BUDGET_PERIODS: [&str; 3] = ["month", "quarter", "year"];
const SUBJECT_TYPES: [&str; 4] = ["tenant", "team", "department", "identity"];

// -------------------------------------------------------------------------------------------------------------------
// Small helpers

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

fn not_found(message: &str) -> IamError {
    IamError::with_status("NOT_FOUND", message, 404)
}

fn string(value: impl Into<String>) -> Value {
    Value::String(value.into())
}

fn trim(value: &str) -> String {
    core_js::trim(value).to_owned()
}

/// `record.member` as a string ("" when absent or not a string).
fn s<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// `record.member` as a number (0 when absent or not a number).
fn n(record: &Record, key: &str) -> f64 {
    record
        .get(key)
        .and_then(core_js::as_number)
        .unwrap_or_default()
}

/// A JavaScript-truthy member (`record.member ? ... : ...`).
fn truthy(value: Option<&Value>) -> bool {
    crate::js::truthy(value)
}

/// `value ?? fallback`: undefined and null take the fallback.
fn or_default(value: Option<&Value>, fallback: Value) -> Value {
    value
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or(fallback)
}

/// `{ ...input }` without some members.
fn without(input: &Map<String, Value>, keys: &[&str]) -> Map<String, Value> {
    input
        .iter()
        .filter(|(key, _)| !keys.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// `{ ...target, ...source }` in place: members already present keep their position.
fn spread(target: &mut Map<String, Value>, source: &Value) {
    if let Value::Object(source) = source {
        for (key, value) in source {
            target.insert(key.clone(), value.clone());
        }
    }
}

fn to_json<T: Serialize>(value: &T) -> IamResult<Value> {
    serde_json::to_value(value)
        .map_err(|_| IamError::with_status("INTERNAL_ERROR", "Internal server error", 500))
}

fn to_map<T: Serialize>(value: &T) -> IamResult<Map<String, Value>> {
    match to_json(value)? {
        Value::Object(map) => Ok(map),
        _ => Ok(Map::new()),
    }
}

fn decode_value<T: serde::de::DeserializeOwned>(value: Option<&Value>) -> IamResult<T> {
    match value {
        Some(Value::Object(map)) => decode(map.clone()),
        _ => decode(Record::new()),
    }
}

fn cmp_f64(a: f64, b: f64) -> Ordering {
    a.partial_cmp(&b).unwrap_or(Ordering::Equal)
}

fn cmp_str(a: &str, b: &str) -> Ordering {
    core_js::cmp_utf16(a, b)
}

/// `Math.round`.
fn js_round(value: f64) -> f64 {
    let floor = value.floor();
    if value - floor >= 0.5 {
        floor + 1.0
    } else {
        floor
    }
}

fn number_text(value: f64) -> String {
    core_js::number_to_string(value)
}

async fn find(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

/// `Array.prototype.sort` as V8 runs it (TimSort), for comparators that do not order equal elements consistently
/// (`(a, b) => (a.period < b.period ? 1 : -1) || ...` answers -1 both ways for one period): the order of such elements
/// follows from the algorithm, so it is reproduced rather than left to Rust's sort. Runs are counted and extended by
/// binary insertion exactly as V8 does; runs are merged one element at a time (V8's galloping finds the same split
/// points for comparators that are consistent across the merged runs).
fn js_sort<T: Clone>(items: &mut [T], compare: impl Fn(&T, &T) -> f64) {
    let length = items.len();
    if length < 2 {
        return;
    }
    let order = |a: &T, b: &T| {
        let value = compare(a, b);
        if value.is_nan() { 0.0 } else { value }
    };
    let count_and_make_run = |items: &mut [T], low: usize, high: usize| -> usize {
        let next = low + 1;
        if next == high {
            return 1;
        }
        let mut run = 2;
        let descending = order(&items[next], &items[low]) < 0.0;
        let mut previous = next;
        for index in next + 1..high {
            let value = order(&items[index], &items[previous]);
            if descending {
                if value >= 0.0 {
                    break;
                }
            } else if value < 0.0 {
                break;
            }
            previous = index;
            run += 1;
        }
        if descending {
            items[low..low + run].reverse();
        }
        run
    };
    let binary_insertion = |items: &mut [T], low: usize, start: usize, high: usize| {
        let mut start = if low == start { start + 1 } else { start };
        while start < high {
            let pivot = items[start].clone();
            let (mut left, mut right) = (low, start);
            while left < right {
                let mid = left + ((right - left) >> 1);
                if order(&pivot, &items[mid]) < 0.0 {
                    right = mid;
                } else {
                    left = mid + 1;
                }
            }
            let mut position = start;
            while position > left {
                items[position] = items[position - 1].clone();
                position -= 1;
            }
            items[left] = pivot;
            start += 1;
        }
    };
    let merge = |items: &mut [T], base: usize, left_length: usize, right_length: usize| {
        let left: Vec<T> = items[base..base + left_length].to_vec();
        let right: Vec<T> = items[base + left_length..base + left_length + right_length].to_vec();
        let (mut i, mut j, mut k) = (0, 0, base);
        while i < left.len() && j < right.len() {
            if order(&right[j], &left[i]) < 0.0 {
                items[k] = right[j].clone();
                j += 1;
            } else {
                items[k] = left[i].clone();
                i += 1;
            }
            k += 1;
        }
        while i < left.len() {
            items[k] = left[i].clone();
            i += 1;
            k += 1;
        }
        while j < right.len() {
            items[k] = right[j].clone();
            j += 1;
            k += 1;
        }
    };
    let mut min_run = length;
    let mut odd = 0;
    while min_run >= 64 {
        odd |= min_run & 1;
        min_run >>= 1;
    }
    min_run += odd;
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let (mut low, mut remaining) = (0, length);
    while remaining != 0 {
        let mut run = count_and_make_run(items, low, low + remaining);
        if run < min_run {
            let forced = min_run.min(remaining);
            binary_insertion(items, low, low + run, low + forced);
            run = forced;
        }
        runs.push((low, run));
        // MergeCollapse.
        while runs.len() > 1 {
            let count = runs.len();
            let at = if (count >= 3 && runs[count - 3].1 <= runs[count - 2].1 + runs[count - 1].1)
                || (count >= 4 && runs[count - 4].1 <= runs[count - 3].1 + runs[count - 2].1)
            {
                if runs[count - 3].1 < runs[count - 1].1 {
                    count - 3
                } else {
                    count - 2
                }
            } else if runs[count - 2].1 <= runs[count - 1].1 {
                count - 2
            } else {
                break;
            };
            let (base, left) = runs[at];
            let right = runs[at + 1].1;
            merge(items, base, left, right);
            runs[at] = (base, left + right);
            runs.remove(at + 1);
        }
        low += run;
        remaining -= run;
    }
    // MergeForceCollapse.
    while runs.len() > 1 {
        let count = runs.len();
        let at = if count >= 3 && runs[count - 3].1 < runs[count - 1].1 {
            count - 3
        } else {
            count - 2
        };
        let (base, left) = runs[at];
        let right = runs[at + 1].1;
        merge(items, base, left, right);
        runs[at] = (base, left + right);
        runs.remove(at + 1);
    }
}

fn mutation<'a, F, Fut>(run: F) -> Mutation<'a>
where
    F: FnOnce(MutationContext) -> Fut + Send + 'a,
    Fut: Future<Output = OperationResult<Value>> + Send + 'a,
{
    Box::new(move |context| Box::pin(run(context)))
}

fn writable(realm: &Tenant) -> IamResult<()> {
    if realm.status == TenantStatus::Deleted {
        return Err(IamError::new(
            "INVALID_TRANSITION",
            "Deleted tenants cannot be updated",
        ));
    }
    Ok(())
}

fn on_root(realm: &Tenant, what: &str) -> IamResult<()> {
    if realm.parent_id.is_some() {
        return Err(invalid(format!(
            "{what} are managed on the platform (root) tenant"
        )));
    }
    Ok(())
}

// -------------------------------------------------------------------------------------------------------------------
// Views

/// `termsView(accountId, terms, showSetBy)`: a billing account's contract terms as the API shows them.
fn terms_view(
    account_id: &str,
    terms: Option<&BillingTerms>,
    show_set_by: bool,
) -> IamResult<Value> {
    let mut view = Map::new();
    view.insert("accountId".into(), string(account_id));
    view.insert("inherited".into(), Value::Bool(false));
    if let Some(terms) = terms {
        if let Some(percent) = terms.discount_percent {
            view.insert("discountPercent".into(), number(percent));
        }
        if let Some(micros) = terms.minimum_commitment_micros {
            view.insert("minimumCommitmentMicros".into(), number(micros));
            view.insert("minimumCommitment".into(), number(units_of(micros)?));
        }
        if let Some(percent) = terms.tax_rate_percent {
            view.insert("taxRatePercent".into(), number(percent));
        }
        if let Some(label) = &terms.tax_label {
            view.insert("taxLabel".into(), string(label.clone()));
        }
        view.insert("setAt".into(), number(terms.set_at));
        if show_set_by {
            view.insert("setBy".into(), string(terms.set_by.clone()));
        }
    }
    Ok(Value::Object(view))
}

/// Finalized, past its due date, and not paid in full.
fn overdue(statement: &BillingStatement, now: f64) -> IamResult<bool> {
    Ok(statement.status == "finalized" && statement.due_at < now && amount_due(statement)? > 0.0)
}

/// `summary(statement, now, tenantName?)`: a statement as lists show it.
fn summary(statement: &BillingStatement, now: f64, tenant_name: Option<&str>) -> IamResult<Value> {
    let due = amount_due(statement)?;
    let mut view = Map::new();
    view.insert("id".into(), string(statement.id.clone()));
    view.insert("tenantId".into(), string(statement.tenant_id.clone()));
    if let Some(name) = tenant_name {
        view.insert("tenantName".into(), string(name));
    }
    view.insert("number".into(), string(statement.number.clone()));
    view.insert("period".into(), string(statement.period.clone()));
    view.insert("status".into(), string(statement.status.clone()));
    view.insert("currency".into(), string(statement.currency.clone()));
    view.insert("subtotalMicros".into(), number(statement.subtotal_micros));
    view.insert("creditsMicros".into(), number(statement.credits_micros));
    view.insert("totalMicros".into(), number(statement.total_micros));
    view.insert("total".into(), number(units_of(statement.total_micros)?));
    view.insert("amountPaidMicros".into(), number(amount_paid(statement)?));
    view.insert("amountDueMicros".into(), number(due));
    view.insert("amountDue".into(), number(units_of(due)?));
    if let Some(micros) = statement
        .credit_notes_micros
        .filter(|micros| *micros != 0.0 && !micros.is_nan())
    {
        view.insert("creditNotesMicros".into(), number(micros));
    }
    view.insert(
        "billingReason".into(),
        string(
            statement
                .billing_reason
                .clone()
                .unwrap_or_else(|| "period".into()),
        ),
    );
    view.insert("issuedAt".into(), number(statement.issued_at));
    view.insert("dueAt".into(), number(statement.due_at));
    if let Some(paid_at) = statement.paid_at {
        view.insert("paidAt".into(), number(paid_at));
    }
    view.insert("overdue".into(), Value::Bool(overdue(statement, now)?));
    Ok(Value::Object(view))
}

/// Not revoked, not expired, and something left.
fn credit_active(credit: &BillingCredit, now: f64) -> bool {
    credit.revoked_at.is_none()
        && credit.remaining_micros > 0.0
        && credit.expires_at.is_none_or(|expires_at| expires_at > now)
}

fn credit_view(credit: &BillingCredit, now: f64) -> IamResult<Value> {
    let mut view = Map::new();
    view.insert("id".into(), string(credit.id.clone()));
    view.insert("tenantId".into(), string(credit.tenant_id.clone()));
    view.insert("amountMicros".into(), number(credit.amount_micros));
    view.insert("amount".into(), number(units_of(credit.amount_micros)?));
    view.insert("remainingMicros".into(), number(credit.remaining_micros));
    view.insert(
        "remaining".into(),
        number(units_of(credit.remaining_micros)?),
    );
    view.insert("reason".into(), string(credit.reason.clone()));
    if let Some(expires_at) = credit.expires_at {
        view.insert("expiresAt".into(), number(expires_at));
    }
    view.insert("grantedAt".into(), number(credit.granted_at));
    view.insert("grantedBy".into(), string(credit.granted_by.clone()));
    if let Some(revoked_at) = credit.revoked_at {
        view.insert("revokedAt".into(), number(revoked_at));
    }
    view.insert("active".into(), Value::Bool(credit_active(credit, now)));
    Ok(Value::Object(view))
}

fn invoice_item_view(item: &BillingInvoiceItem) -> IamResult<Value> {
    let mut view = Map::new();
    view.insert("id".into(), string(item.id.clone()));
    view.insert("accountId".into(), string(item.tenant_id.clone()));
    view.insert("description".into(), string(item.description.clone()));
    view.insert("quantity".into(), number(item.quantity));
    view.insert("unitAmountMicros".into(), number(item.unit_amount_micros));
    view.insert(
        "unitAmount".into(),
        number(units_of(item.unit_amount_micros)?),
    );
    view.insert("amountMicros".into(), number(item.amount_micros));
    view.insert("amount".into(), number(units_of(item.amount_micros)?));
    if let Some(period) = &item.period {
        view.insert("period".into(), string(period.clone()));
    }
    view.insert("status".into(), string(item.status.clone()));
    if let Some(statement_id) = &item.statement_id {
        view.insert("statementId".into(), string(statement_id.clone()));
    }
    view.insert("source".into(), string(item.source.clone()));
    if let Some(subscription_id) = &item.subscription_id {
        view.insert("subscriptionId".into(), string(subscription_id.clone()));
    }
    if let Some(metadata) = &item.metadata {
        view.insert("metadata".into(), to_json(metadata)?);
    }
    view.insert("createdAt".into(), number(item.created_at));
    view.insert("createdBy".into(), string(item.created_by.clone()));
    Ok(Value::Object(view))
}

fn credit_note_view(note: &BillingCreditNote) -> IamResult<Value> {
    let mut view = Map::new();
    view.insert("id".into(), string(note.id.clone()));
    view.insert("accountId".into(), string(note.tenant_id.clone()));
    view.insert("number".into(), string(note.number.clone()));
    view.insert("statementId".into(), string(note.statement_id.clone()));
    view.insert(
        "statementNumber".into(),
        string(note.statement_number.clone()),
    );
    view.insert("amountMicros".into(), number(note.amount_micros));
    view.insert("amount".into(), number(units_of(note.amount_micros)?));
    view.insert("reason".into(), note.reason.clone());
    if let Some(memo) = &note.memo {
        view.insert("memo".into(), string(memo.clone()));
    }
    view.insert("applied".into(), note.applied.clone());
    if let Some(credit_id) = &note.credit_id {
        view.insert("creditId".into(), string(credit_id.clone()));
    }
    view.insert("issuedAt".into(), number(note.issued_at));
    view.insert("issuedBy".into(), string(note.issued_by.clone()));
    Ok(Value::Object(view))
}

fn plan_view(plan: &BillingPlan, subscribers: Option<usize>) -> IamResult<Value> {
    let mut items = Vec::with_capacity(plan.items.len());
    for item in &plan.items {
        let mut view = Map::new();
        view.insert("id".into(), string(item.id.clone()));
        view.insert("kind".into(), string(item.kind.clone()));
        view.insert("name".into(), string(item.name.clone()));
        if let Some(micros) = item.amount_micros {
            view.insert("amount".into(), number(micros / 1_000_000.0));
        }
        if let Some(micros) = item.unit_amount_micros {
            view.insert("unitAmount".into(), number(micros / 1_000_000.0));
        }
        if let Some(seats) = item.included_seats {
            view.insert("includedSeats".into(), number(seats));
        }
        if item.kind != "usage" {
            view.insert(
                "billing".into(),
                string(item.billing.clone().unwrap_or_else(|| "advance".into())),
            );
        }
        if let Some(meter) = &item.meter {
            view.insert("meter".into(), string(meter.clone()));
        }
        if let Some(price) = item.price.as_ref().filter(|price| truthy(Some(price))) {
            view.insert("price".into(), public_price_spec(price)?);
        }
        items.push(Value::Object(view));
    }
    let mut view = Map::new();
    view.insert("id".into(), string(plan.id.clone()));
    view.insert("key".into(), string(plan.key.clone()));
    view.insert("name".into(), string(plan.name.clone()));
    if let Some(description) = &plan.description {
        view.insert("description".into(), string(description.clone()));
    }
    view.insert("items".into(), Value::Array(items));
    if let Some(days) = plan.trial_days {
        view.insert("trialDays".into(), number(days));
    }
    view.insert("selfServe".into(), Value::Bool(plan.self_serve));
    view.insert("archived".into(), Value::Bool(plan.archived));
    if let Some(subscribers) = subscribers {
        view.insert("subscribers".into(), number(subscribers as f64));
    }
    view.insert("createdAt".into(), number(plan.created_at));
    view.insert("updatedAt".into(), number(plan.updated_at));
    Ok(Value::Object(view))
}

fn subscription_view(
    subscription: &BillingSubscription,
    now: f64,
    account_name: Option<&str>,
) -> IamResult<Value> {
    let mut view = Map::new();
    view.insert("id".into(), string(subscription.id.clone()));
    view.insert("accountId".into(), string(subscription.tenant_id.clone()));
    if let Some(name) = account_name {
        view.insert("accountName".into(), string(name));
    }
    view.insert("planId".into(), string(subscription.plan_id.clone()));
    view.insert("planKey".into(), string(subscription.plan_key.clone()));
    view.insert("planName".into(), string(subscription.plan_name.clone()));
    view.insert(
        "status".into(),
        string(subscription_status(subscription, now)?),
    );
    view.insert("startedAt".into(), number(subscription.started_at));
    if let Some(at) = subscription.trial_ends_at {
        view.insert("trialEndsAt".into(), number(at));
    }
    if let Some(at) = subscription.ends_at {
        view.insert("endsAt".into(), number(at));
    }
    view.insert(
        "cancelAtPeriodEnd".into(),
        Value::Bool(subscription.cancel_at_period_end),
    );
    if let Some(at) = subscription.canceled_at {
        view.insert("canceledAt".into(), number(at));
    }
    view.insert("seats".into(), number(subscription.seats));
    view.insert("billedAdvance".into(), json!(subscription.billed_advance));
    view.insert("createdAt".into(), number(subscription.created_at));
    view.insert("createdBy".into(), string(subscription.created_by.clone()));
    Ok(Value::Object(view))
}

fn coupon_active(coupon: &BillingCoupon, now: f64) -> bool {
    coupon.active
        && coupon.redeem_by.is_none_or(|redeem_by| redeem_by > now)
        && coupon
            .max_redemptions
            .is_none_or(|max| coupon.redemptions < max)
}

fn coupon_view(coupon: &BillingCoupon, now: f64) -> IamResult<Value> {
    let mut view = Map::new();
    view.insert("id".into(), string(coupon.id.clone()));
    view.insert("code".into(), string(coupon.code.clone()));
    view.insert("name".into(), string(coupon.name.clone()));
    if let Some(percent) = coupon.percent_off {
        view.insert("percentOff".into(), number(percent));
    }
    if let Some(micros) = coupon.amount_off_micros {
        view.insert("amountOffMicros".into(), number(micros));
        view.insert("amountOff".into(), number(units_of(micros)?));
    }
    view.insert("duration".into(), string(coupon.duration.clone()));
    if let Some(months) = coupon.duration_in_months {
        view.insert("durationInMonths".into(), number(months));
    }
    if let Some(max) = coupon.max_redemptions {
        view.insert("maxRedemptions".into(), number(max));
    }
    view.insert("redemptions".into(), number(coupon.redemptions));
    if let Some(redeem_by) = coupon.redeem_by {
        view.insert("redeemBy".into(), number(redeem_by));
    }
    view.insert("active".into(), Value::Bool(coupon_active(coupon, now)));
    view.insert("createdAt".into(), number(coupon.created_at));
    Ok(Value::Object(view))
}

fn discount_view(discount: &BillingDiscount, period: &str, time_zone: &str) -> IamResult<Value> {
    let mut view = Map::new();
    view.insert("id".into(), string(discount.id.clone()));
    view.insert("accountId".into(), string(discount.tenant_id.clone()));
    view.insert("couponId".into(), string(discount.coupon_id.clone()));
    view.insert("code".into(), string(discount.code.clone()));
    view.insert("name".into(), string(discount.name.clone()));
    if let Some(percent) = discount.percent_off {
        view.insert("percentOff".into(), number(percent));
    }
    if let Some(micros) = discount.amount_off_micros {
        view.insert("amountOffMicros".into(), number(micros));
        view.insert("amountOff".into(), number(units_of(micros)?));
    }
    view.insert("duration".into(), string(discount.duration.clone()));
    if let Some(months) = discount.duration_in_months {
        view.insert("durationInMonths".into(), number(months));
    }
    view.insert("appliedInvoices".into(), number(discount.applied_invoices));
    view.insert("redeemedAt".into(), number(discount.redeemed_at));
    view.insert("redeemedBy".into(), string(discount.redeemed_by.clone()));
    if let Some(ended_at) = discount.ended_at {
        view.insert("endedAt".into(), number(ended_at));
    }
    view.insert(
        "active".into(),
        Value::Bool(discount_active(discount, period, time_zone)?),
    );
    Ok(Value::Object(view))
}

fn price_view(
    price: &BillingPrice,
    show_set_by: bool,
    target_name: Option<&str>,
) -> IamResult<Value> {
    let mut view = Map::new();
    view.insert("meter".into(), string(price.meter.clone()));
    view.insert("targetTenantId".into(), string(price.tenant_id.clone()));
    if let Some(name) = target_name {
        view.insert("targetTenantName".into(), string(name));
    }
    view.insert("definerId".into(), string(price.definer_id.clone()));
    view.insert("effectiveFrom".into(), string(price.effective_from.clone()));
    view.insert("price".into(), public_price_spec(&price.spec)?);
    if let Some(note) = &price.note {
        view.insert("note".into(), string(note.clone()));
    }
    view.insert("setAt".into(), number(price.set_at));
    if show_set_by {
        view.insert("setBy".into(), string(price.set_by.clone()));
    }
    Ok(Value::Object(view))
}

fn sum_amounts(items: &[BillingInvoiceItem]) -> IamResult<f64> {
    round_micros(items.iter().fold(0.0, |sum, item| sum + item.amount_micros))
}

// -------------------------------------------------------------------------------------------------------------------
// The API group

/// The `billing` API group (`createBillingApi(ctx)`): one method per route `billing/{method}`.
pub struct BillingApi {
    ctx: Arc<ServerContext>,
    service: Arc<BillingService>,
}

/// `createBillingApi(ctx)`.
pub fn create_billing_api(ctx: &Arc<ServerContext>) -> IamResult<BillingApi> {
    Ok(BillingApi {
        ctx: ctx.clone(),
        service: billing_service_of(ctx)?,
    })
}

/// Who a role-based read (`readAs`) is about.
enum ReadVia {
    Team(String),
    Department(String),
}

impl BillingApi {
    /// `service.settings`: the validated `billing` option.
    fn settings(&self) -> IamResult<BillingSettings> {
        let options = crate::options_value::options_value(&self.ctx.options);
        billing_settings(options.get("billing"))
    }

    /// `service.currentPeriod()`.
    fn current_period(&self) -> IamResult<String> {
        period_of(self.ctx.now(), &self.settings()?.time_zone)
    }

    /// A string member that is a period when given (`input.period === undefined ? current : billingPeriod(...)`).
    fn period_or_current(&self, value: Option<&Value>) -> IamResult<String> {
        match value {
            None => self.current_period(),
            Some(value) => billing_period(Some(value), None),
        }
    }

    async fn run<'a, F, Fut>(
        &'a self,
        credential: &'a CredentialInput,
        tenant_id: Option<&'a Value>,
        action: &str,
        resource_id: &str,
        root_only: bool,
        work: F,
    ) -> IamResult<Value>
    where
        F: FnOnce(MutationContext) -> Fut + Send + 'a,
        Fut: Future<Output = OperationResult<Value>> + Send + 'a,
    {
        self.ctx
            .operations()?
            .operation(
                credential,
                tenant_id,
                action,
                resource_id,
                mutation(work),
                root_only,
            )
            .await
    }

    async fn own_meter(&self, tx: &Store, tenant_id: &str, key: &str) -> IamResult<Record> {
        find(
            tx,
            METERS,
            Filter::new().eq("tenantId", tenant_id).eq("uniqueKey", key),
        )
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| not_found("Billing meter not found"))
    }

    async fn audit(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        action: &str,
        tenant_id: &str,
        resource_id: &str,
        metadata: Map<String, Value>,
    ) -> IamResult<()> {
        self.ctx
            .events()?
            .audit(
                tx,
                principal,
                action,
                tenant_id,
                resource_id,
                AuditOutcome::Allow,
                false,
                Some(metadata),
            )
            .await
    }

    /// The price chain for a tenant's account: from the account up, or from the tenant for meters defined inside it.
    async fn effective_price(
        &self,
        tx: &Store,
        realm: &Tenant,
        meter: &BillingMeter,
        period: &str,
    ) -> IamResult<Option<BillingPrice>> {
        let account = account_of(&self.ctx, tx, realm).await?;
        let account_chain = self.ctx.ancestry(tx, &account).await?;
        let chain = if account_chain
            .iter()
            .any(|tenant| tenant.id == meter.tenant_id)
        {
            account_chain
        } else {
            self.ctx.ancestry(tx, realm).await?
        };
        price_for(tx, meter, &chain, period).await
    }

    /// Whether the caller sees who set a meter's prices: people of the tenant that defines the meter and of the
    /// tenants above it. Below, a platform meter's prices would name root administrators.
    async fn sees_price_setter(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        meter: &BillingMeter,
    ) -> IamResult<bool> {
        Ok(self
            .ctx
            .ancestor_ids(tx, &meter.tenant_id)
            .await?
            .contains(&principal.identity.tenant_id))
    }

    async fn meter_view(
        &self,
        tx: &Store,
        realm: &Tenant,
        meter: &BillingMeter,
        root_id: &str,
        principal: &AuthenticatedPrincipal,
    ) -> IamResult<Value> {
        let price = if meter.pricing == "rate-card" {
            self.effective_price(tx, realm, meter, &self.current_period()?)
                .await?
        } else {
            None
        };
        let mut view = Map::new();
        view.insert("key".into(), string(meter.key.clone()));
        view.insert("name".into(), string(meter.name.clone()));
        view.insert("unit".into(), string(meter.unit.clone()));
        if let Some(description) = &meter.description {
            view.insert("description".into(), string(description.clone()));
        }
        view.insert("aggregation".into(), string(meter.aggregation.clone()));
        view.insert("pricing".into(), string(meter.pricing.clone()));
        view.insert("archived".into(), Value::Bool(meter.archived));
        view.insert("definedBy".into(), string(meter.tenant_id.clone()));
        view.insert(
            "scope".into(),
            string(if meter.tenant_id == root_id {
                "platform"
            } else {
                "tenant"
            }),
        );
        view.insert("inherited".into(), Value::Bool(meter.tenant_id != realm.id));
        if let Some(price) = &price {
            let show = self.sees_price_setter(tx, principal, meter).await?;
            view.insert("price".into(), price_view(price, show, None)?);
        }
        view.insert("createdAt".into(), number(meter.created_at));
        view.insert("updatedAt".into(), number(meter.updated_at));
        Ok(Value::Object(view))
    }

    async fn in_subtree(&self, tx: &Store, realm: &Tenant, tenant_id: &str) -> IamResult<bool> {
        Ok(self
            .ctx
            .ancestor_ids(tx, tenant_id)
            .await?
            .contains(&realm.id))
    }

    async fn root_id(&self, tx: &Store, realm: &Tenant) -> IamResult<String> {
        Ok(self
            .ctx
            .ancestry(tx, realm)
            .await?
            .last()
            .map(|tenant| tenant.id.clone())
            .unwrap_or_default())
    }

    /// Whether the caller holds the role a `readAs` names over the data (team maintainer, department head).
    async fn read_role(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        realm: &Tenant,
        via: &ReadVia,
    ) -> IamResult<Option<&'static str>> {
        let ctx = &self.ctx;
        match via {
            ReadVia::Team(team_id) => {
                let Some(team) = tx.get("teams", team_id).await? else {
                    return Ok(None);
                };
                let team_tenant = s(&team, "tenantId").to_owned();
                // Maintainers read in the team's own tenant (or a project below it), never elsewhere.
                if principal.identity.tenant_id != team_tenant
                    || !ctx
                        .ancestor_ids(tx, &realm.id)
                        .await?
                        .contains(&team_tenant)
                {
                    return Ok(None);
                }
                Ok(is_team_maintainer_at(
                    tx,
                    &team_tenant,
                    s(&team, "id"),
                    &principal.identity.id,
                    Some(ctx.now()),
                    true,
                )
                .await?
                .then_some("team-maintainer"))
            }
            ReadVia::Department(department_id) => {
                let Some(department) = tx.get("departments", department_id).await? else {
                    return Ok(None);
                };
                let department_tenant = s(&department, "tenantId").to_owned();
                if principal.identity.tenant_id != department_tenant
                    || !ctx
                        .ancestor_ids(tx, &realm.id)
                        .await?
                        .contains(&department_tenant)
                {
                    return Ok(None);
                }
                Ok(
                    department_heads_of(tx, &department_tenant, s(&department, "id"), true)
                        .await?
                        .contains(&principal.identity.id)
                        .then_some("department-head"),
                )
            }
        }
    }

    /// `readAs`: a read allowed by `iam:billing:read` or by a role the caller holds over the data (team maintainer,
    /// department head). The role counts only for a person signed in as themselves in their own tenant;
    /// impersonation, delegated, role-session and API-key credentials read through the permission.
    async fn read_as(
        &self,
        credential: &CredentialInput,
        tenant_id: Option<&Value>,
        resource_id: &str,
        via: ReadVia,
        query: Value,
    ) -> IamResult<Value> {
        let ctx = &self.ctx;
        let target = text(tenant_id, "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let authenticated = &authenticated;
        let target = &target;
        let via = &via;
        let query = &query;
        let outcome = ctx
            .store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, authenticated)
                    .await?;
                let realm = ctx.tenant(&tx, target).await?;
                let own_session = principal.session.kind == SessionKind::User
                    && acts_in_own_right(principal.session.kind)
                    && principal
                        .session
                        .impersonator_id
                        .as_deref()
                        .is_none_or(str::is_empty)
                    && principal.session.tenant_id == principal.identity.tenant_id
                    && principal.identity.kind == IdentityKind::User;
                let role = if own_session {
                    self.read_role(&tx, &principal, &realm, via).await?
                } else {
                    None
                };
                if role.is_none() {
                    let decision = ctx
                        .operations()?
                        .recorded_decision(
                            &tx,
                            &principal,
                            &AuthorizationRequest {
                                credential: CredentialInput::default(),
                                tenant_id: realm.id.clone(),
                                action: "iam:billing:read".into(),
                                resource: ResourceTarget {
                                    kind: "iam".into(),
                                    id: resource_id.to_owned(),
                                },
                            },
                        )
                        .await?;
                    if !decision.allowed {
                        return Ok(None);
                    }
                }
                let report = self.service.report(&tx, &realm, query, None, None).await?;
                let value = to_json(&report)?;
                let mut metadata = Map::new();
                metadata.insert("via".into(), string(role.unwrap_or("permission")));
                self.audit(
                    &tx,
                    &principal,
                    "iam:billing:read",
                    &realm.id,
                    resource_id,
                    metadata,
                )
                .await?;
                Ok(Some(value))
            })
            .await?;
        outcome.ok_or_else(|| IamError::with_status("ACCESS_DENIED", "Access denied", 403))
    }

    async fn budget_view(&self, tx: &Store, budget: &BillingBudget) -> IamResult<Value> {
        let status: BudgetStatus = self.service.budget_status(tx, budget, None).await?;
        let mut view = to_map(&status)?;
        view.insert("forecastAlerts".into(), Value::Bool(budget.forecast_alerts));
        view.insert("notify".into(), budget.notify.clone());
        view.insert("createdAt".into(), number(budget.created_at));
        view.insert("createdBy".into(), string(budget.created_by.clone()));
        view.insert("updatedAt".into(), number(budget.updated_at));
        Ok(Value::Object(view))
    }

    /// Validates a budget subject against the budget's tenant.
    async fn budget_subject(
        &self,
        tx: &Store,
        realm: &Tenant,
        kind: Option<&Value>,
        subject_id: Option<&Value>,
    ) -> IamResult<(String, String)> {
        let ctx = &self.ctx;
        let subject_type = or_default(kind, string("tenant"));
        let Some(subject_type) = subject_type
            .as_str()
            .filter(|kind| SUBJECT_TYPES.contains(kind))
            .map(str::to_owned)
        else {
            return Err(invalid(
                "subjectType must be 'tenant', 'team', 'department' or 'identity'",
            ));
        };
        if subject_type == "tenant" {
            let target = match subject_id {
                None => realm.clone(),
                Some(value) => {
                    ctx.tenant(tx, &text(Some(value), "subjectId", 256)?)
                        .await?
                }
            };
            if !self.in_subtree(tx, realm, &target.id).await? {
                return Err(invalid(
                    "A tenant budget covers this tenant or one below it",
                ));
            }
            return Ok((subject_type, target.id));
        }
        let value = text(subject_id, "subjectId", 256)?;
        let in_scope = |tenant_id: String| async move {
            Ok::<bool, IamError>(
                self.in_subtree(tx, realm, &tenant_id).await?
                    || ctx.ancestor_ids(tx, &realm.id).await?.contains(&tenant_id),
            )
        };
        if subject_type == "identity" {
            let identity = tx.get("identities", &value).await?;
            let valid = match &identity {
                Some(identity) => {
                    s(identity, "status") != "deleted"
                        && self.in_subtree(tx, realm, s(identity, "tenantId")).await?
                }
                None => false,
            };
            if !valid {
                return Err(not_found("Identity not found"));
            }
        } else if subject_type == "team" {
            let team = tx.get("teams", &value).await?;
            let valid = match &team {
                Some(team) => in_scope(s(team, "tenantId").to_owned()).await?,
                None => false,
            };
            if !valid {
                return Err(not_found("Team not found"));
            }
        } else {
            let department = tx.get("departments", &value).await?;
            let valid = match &department {
                Some(department) => in_scope(s(department, "tenantId").to_owned()).await?,
                None => false,
            };
            if !valid {
                return Err(not_found("Department not found"));
            }
        }
        Ok((subject_type, value))
    }

    /// Validated budget settings; `current` supplies values an update leaves out.
    fn budget_settings(
        &self,
        input: &Map<String, Value>,
        current: Option<&BillingBudget>,
    ) -> IamResult<Map<String, Value>> {
        let name = match input.get("name") {
            None => current.map(|budget| budget.name.clone()),
            Some(value) => Some(trim(&text(Some(value), "name", 128)?)),
        };
        let Some(name) = name.filter(|name| !name.is_empty()) else {
            return Err(invalid("name is required"));
        };
        let amount = match input.get("amount") {
            None => current.map(|budget| budget.amount_micros),
            Some(value) => Some(amount_micros(Some(value), "amount")?),
        };
        let Some(amount) =
            amount.filter(|amount| *amount != 0.0 && !amount.is_nan() && *amount > 0.0)
        else {
            return Err(invalid("amount must be above 0"));
        };
        let period = match input.get("period").filter(|value| !value.is_null()) {
            Some(value) => value.clone(),
            None => current
                .map(|budget| budget.period.clone())
                .filter(|period| !period.is_null())
                .unwrap_or_else(|| string("month")),
        };
        if !period
            .as_str()
            .is_some_and(|period| BUDGET_PERIODS.contains(&period))
        {
            return Err(invalid("period must be 'month', 'quarter' or 'year'"));
        }
        let mut meters: Option<Vec<String>> = current.and_then(|budget| budget.meters.clone());
        match input.get("meters") {
            Some(Value::Null) => meters = None,
            None => {}
            Some(value) => {
                let Some(items) = value
                    .as_array()
                    .filter(|items| !items.is_empty() && items.len() <= 20)
                else {
                    return Err(invalid("meters must list 1-20 meter keys"));
                };
                let keys = items
                    .iter()
                    .map(|item| meter_key(Some(item)))
                    .collect::<IamResult<Vec<String>>>()?;
                let mut keys: Vec<String> = keys
                    .into_iter()
                    .collect::<IndexSet<String>>()
                    .into_iter()
                    .collect();
                keys.sort_by(|a, b| cmp_str(a, b));
                meters = Some(keys);
            }
        }
        let thresholds = match (input.get("thresholds"), current) {
            (None, Some(current)) => current.thresholds.clone(),
            (value, _) => budget_thresholds(value)?,
        };
        let flag = |value: Option<&Value>, fallback: bool, field: &str| -> IamResult<bool> {
            match value {
                None => Ok(fallback),
                Some(Value::Bool(flag)) => Ok(*flag),
                Some(_) => Err(invalid(format!("{field} must be a boolean"))),
            }
        };
        let empty = Map::new();
        let notify_input = match input.get("notify") {
            None => &empty,
            Some(value) => object(Some(value))?,
        };
        let current_notify = current.map(|budget| &budget.notify);
        let emails: Value = match notify_input.get("emails") {
            None => current_notify
                .and_then(|notify| notify.get("emails"))
                .filter(|emails| !emails.is_null())
                .cloned()
                .unwrap_or_else(|| json!([])),
            Some(value) => {
                let Some(items) = value.as_array().filter(|items| items.len() <= 10) else {
                    return Err(invalid("notify.emails must list at most 10 addresses"));
                };
                let addresses = items
                    .iter()
                    .map(|item| email(Some(item)))
                    .collect::<IamResult<Vec<String>>>()?;
                let mut addresses: Vec<String> = addresses
                    .into_iter()
                    .collect::<IndexSet<String>>()
                    .into_iter()
                    .collect();
                addresses.sort_by(|a, b| cmp_str(a, b));
                json!(addresses)
            }
        };
        let current_flag = |key: &str| -> Option<bool> {
            current_notify
                .and_then(|notify| notify.get(key))
                .and_then(Value::as_bool)
        };
        let forecast_alerts = flag(
            input.get("forecastAlerts"),
            current.map(|budget| budget.forecast_alerts).unwrap_or(true),
            "forecastAlerts",
        )?;
        let owners = flag(
            notify_input.get("owners"),
            current_flag("owners").unwrap_or(true),
            "notify.owners",
        )?;
        let subject = flag(
            notify_input.get("subject"),
            current_flag("subject").unwrap_or(true),
            "notify.subject",
        )?;
        let enforce = flag(
            input.get("enforce"),
            current.map(|budget| budget.enforce).unwrap_or(false),
            "enforce",
        )?;
        let mut fields = Map::new();
        fields.insert("name".into(), string(name));
        fields.insert("amountMicros".into(), number(amount));
        fields.insert("period".into(), period);
        if let Some(meters) = meters {
            fields.insert("meters".into(), json!(meters));
        }
        fields.insert(
            "thresholds".into(),
            Value::Array(thresholds.into_iter().map(number).collect()),
        );
        fields.insert("forecastAlerts".into(), Value::Bool(forecast_alerts));
        let mut notify = Map::new();
        notify.insert("owners".into(), Value::Bool(owners));
        notify.insert("subject".into(), Value::Bool(subject));
        notify.insert("emails".into(), emails);
        fields.insert("notify".into(), Value::Object(notify));
        fields.insert("enforce".into(), Value::Bool(enforce));
        Ok(fields)
    }

    async fn own_budget(
        &self,
        tx: &Store,
        tenant_id: &str,
        budget_id: Option<&Value>,
    ) -> IamResult<Record> {
        let budget_id = text(budget_id, "budgetId", 256)?;
        self.ctx
            .scoped(tx, BUDGETS, Some(&string(budget_id)), tenant_id)
            .await
    }

    /// Statements of the accounts in a tenant's subtree (every statement for the root).
    async fn scope_statements(&self, tx: &Store, realm: &Tenant) -> IamResult<Vec<Record>> {
        if realm.parent_id.is_none() {
            return find(tx, STATEMENTS, Filter::new()).await;
        }
        let mut result = Vec::new();
        for tenant in subtree(&self.ctx, tx, realm).await? {
            result.extend(
                find(
                    tx,
                    STATEMENTS,
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?,
            );
        }
        Ok(result)
    }

    /// A statement of an account in the tenant's subtree.
    async fn scoped_statement(
        &self,
        tx: &Store,
        realm: &Tenant,
        statement_id: Option<&Value>,
    ) -> IamResult<Record> {
        let statement_id = text(statement_id, "statementId", 256)?;
        match tx.get(STATEMENTS, &statement_id).await? {
            Some(statement)
                if self
                    .in_subtree(tx, realm, s(&statement, "tenantId"))
                    .await? =>
            {
                Ok(statement)
            }
            _ => Err(not_found("Statement not found")),
        }
    }

    /// The tenant a profile call is about: the operation's tenant, or `targetTenantId` below it.
    async fn profile_target(
        &self,
        tx: &Store,
        realm: &Tenant,
        target_tenant_id: Option<&Value>,
    ) -> IamResult<Tenant> {
        let Some(target_tenant_id) = target_tenant_id else {
            return Ok(realm.clone());
        };
        let target = self
            .ctx
            .tenant(tx, &text(Some(target_tenant_id), "targetTenantId", 256)?)
            .await?;
        if !self.in_subtree(tx, realm, &target.id).await? {
            return Err(not_found("Tenant not found"));
        }
        Ok(target)
    }

    async fn profile_view(
        &self,
        tx: &Store,
        target: &Tenant,
        profile: Option<&Record>,
    ) -> IamResult<Value> {
        let account = account_of(&self.ctx, tx, target).await?;
        let fields = match profile {
            Some(profile) => Value::Object(without(profile, &["id", "tenantId", "uniqueKey"])),
            None => Value::Null,
        };
        Ok(json!({
            "tenantId": target.id,
            "account": { "id": account.id, "name": account.name, "inherited": account.id != target.id },
            "profile": fields,
        }))
    }

    /// The stored profile record of a tenant (`profileOf`), as stored.
    async fn profile_record(&self, tx: &Store, tenant_id: &str) -> IamResult<Option<Record>> {
        let Some(profile) = profile_of(tx, tenant_id).await? else {
            return Ok(None);
        };
        let stored = tx.get(PROFILES, &profile.id).await?;
        Ok(Some(stored.unwrap_or_else(|| {
            crate::port::encode::<BillingProfile>(&profile)
        })))
    }

    /// The tenant as a billing account: invoices, subscriptions and discounts belong to accounts.
    async fn own_account(&self, tx: &Store, realm: &Tenant) -> IamResult<Tenant> {
        let account = account_of(&self.ctx, tx, realm).await?;
        if account.id != realm.id || realm.parent_id.is_none() {
            return Err(invalid(
                "Only a billing account (an organization or a tenant with a profile) has invoices and subscriptions",
            ));
        }
        Ok(account)
    }

    async fn root_of(&self, tx: &Store, realm: &Tenant) -> IamResult<Tenant> {
        Ok(self
            .ctx
            .ancestry(tx, realm)
            .await?
            .into_iter()
            .find(|tenant| tenant.parent_id.is_none())
            .unwrap_or_else(|| realm.clone()))
    }

    /// A platform plan by id or key.
    async fn plan_by_ref(
        &self,
        tx: &Store,
        realm: &Tenant,
        reference: Option<&Value>,
    ) -> IamResult<Record> {
        let value = text(reference, "plan", 128)?;
        let root = self.root_of(tx, realm).await?;
        find(tx, PLANS, Filter::new().eq("tenantId", root.id.clone()))
            .await?
            .into_iter()
            .find(|candidate| s(candidate, "id") == value || s(candidate, "key") == value)
            .ok_or_else(|| not_found("Billing plan not found"))
    }

    /// Account billing managers act on self-serve plans only; root administrators on any.
    async fn may_manage(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        plans: &[&BillingPlan],
    ) -> OperationResult<bool> {
        if self.ctx.root_principal(tx, principal).await? {
            return Ok(true);
        }
        if plans.iter().any(|plan| !plan.self_serve) {
            return Err(OperationDenied::new(Some(
                "Only root administrators manage subscriptions to plans that are not self-serve",
            )));
        }
        Ok(false)
    }

    /// The ids of the billing accounts a tenant's reads cover (None: every account, for the root).
    async fn covered_accounts(
        &self,
        tx: &Store,
        realm: &Tenant,
    ) -> IamResult<Option<IndexSet<String>>> {
        if realm.parent_id.is_none() {
            return Ok(None);
        }
        Ok(Some(
            subtree(&self.ctx, tx, realm)
                .await?
                .into_iter()
                .map(|tenant| tenant.id)
                .collect(),
        ))
    }

    async fn account_name(
        &self,
        tx: &Store,
        statement: &BillingStatement,
    ) -> IamResult<Option<String>> {
        Ok(tx
            .get("tenants", &statement.tenant_id)
            .await?
            .and_then(|tenant| {
                tenant
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            }))
    }

    /// An invoice of the tenant's own account or, called on the root tenant, of any account.
    async fn account_statement(
        &self,
        tx: &Store,
        realm: &Tenant,
        statement_id: Option<&Value>,
    ) -> IamResult<BillingStatement> {
        let statement_id = text(statement_id, "statementId", 256)?;
        match tx.get(STATEMENTS, &statement_id).await? {
            Some(statement)
                if s(&statement, "tenantId") == realm.id || realm.parent_id.is_none() =>
            {
                decode(statement)
            }
            _ => Err(not_found("Statement not found")),
        }
    }

    async fn scoped_record(
        &self,
        tx: &Store,
        collection: &str,
        value: Option<&Value>,
        name: &str,
        tenant_id: &str,
    ) -> IamResult<Record> {
        let record_id = text(value, name, 256)?;
        self.ctx
            .scoped(tx, collection, Some(&string(record_id)), tenant_id)
            .await
    }

    /// The summary of a statement the service returned, with its account's name.
    async fn named_summary(&self, tx: &Store, statement: &BillingStatement) -> IamResult<Value> {
        let name = self.account_name(tx, statement).await?;
        summary(statement, self.ctx.now(), name.as_deref())
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Meters and prices

    /// `billing/listMeters`: the meters that reach the tenant (its own and those of its ancestors), with the price
    /// that applies to the tenant's billing account this period. Requires iam:billing:read.
    pub async fn list_meters(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ListMetersInput>,
    ) -> IamResult<Reply<billing::ListMetersOutput>> {
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing",
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let chain = self.ctx.ancestry(&tx, &realm).await?;
                    let root_id = chain
                        .last()
                        .map(|tenant| tenant.id.clone())
                        .unwrap_or_default();
                    let mut meters: Vec<BillingMeter> =
                        meters_for(&tx, &chain).await?.into_values().collect();
                    meters.sort_by(|a, b| cmp_str(&a.key, &b.key));
                    let mut views = Vec::with_capacity(meters.len());
                    for meter in &meters {
                        views.push(
                            self.meter_view(&tx, &realm, meter, &root_id, &principal)
                                .await?,
                        );
                    }
                    Ok(Value::Array(views))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/createMeter`: defines a meter: on the root tenant a platform meter billed to every organization,
    /// elsewhere a meter for the tenant's own subtree (chargeback). Keys may not repeat a key an ancestor defines; at
    /// most 100 meters per tenant. Requires iam:billing:manage on `iam/billing/meters/{key}`; audited as
    /// `billing:meter-create`.
    pub async fn create_meter(
        &self,
        credential: &CredentialInput,
        input: Body<billing::CreateMeterInput>,
    ) -> IamResult<Reply<billing::CreateMeterOutput>> {
        let key = meter_key(input.get("key"))?;
        let resource = format!("billing/meters/{key}");
        let body = &input;
        let key = &key;
        let resource_ref = &resource;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                &resource,
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    writable(&realm)?;
                    let rest = without(
                        object(Some(&body.value()))?,
                        &["tenantId", "key", "archived"],
                    );
                    let fields = meter_settings(&rest, None)?;
                    let chain = self.ctx.ancestry(&tx, &realm).await?;
                    // Built-in meters (`inference`) are the platform's: other modules bill through them.
                    if realm.parent_id.is_some() && built_in_meter_key(key)? {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            format!("{key} is a built-in platform meter"),
                            409,
                        )
                        .into());
                    }
                    if resolve_meter(&tx, &chain, key).await?.is_some() {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A meter with this key already reaches this tenant",
                            409,
                        )
                        .into());
                    }
                    if find(&tx, METERS, Filter::new().eq("tenantId", realm.id.clone()))
                        .await?
                        .len() as f64
                        >= MAX_METERS_PER_TENANT
                    {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!(
                                "A tenant can define at most {} meters",
                                number_text(MAX_METERS_PER_TENANT)
                            ),
                            409,
                        )
                        .into());
                    }
                    let now = self.ctx.now();
                    let mut record = Record::new();
                    record.insert("id".into(), string(id()));
                    record.insert("tenantId".into(), string(realm.id.clone()));
                    record.insert("uniqueKey".into(), string(key.clone()));
                    record.insert("key".into(), string(key.clone()));
                    spread(&mut record, &fields);
                    record.insert("archived".into(), Value::Bool(false));
                    record.insert("createdAt".into(), number(now));
                    record.insert("createdBy".into(), string(principal.identity.id.clone()));
                    record.insert("updatedAt".into(), number(now));
                    record.insert("updatedBy".into(), string(principal.identity.id.clone()));
                    let stored = tx.insert(METERS, &record).await?;
                    let meter: BillingMeter = decode(stored)?;
                    let mut metadata = Map::new();
                    metadata.insert("key".into(), string(key.clone()));
                    metadata.insert("name".into(), string(meter.name.clone()));
                    metadata.insert("unit".into(), string(meter.unit.clone()));
                    metadata.insert("aggregation".into(), string(meter.aggregation.clone()));
                    metadata.insert("pricing".into(), string(meter.pricing.clone()));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:meter-create",
                        &realm.id,
                        resource_ref,
                        metadata,
                    )
                    .await?;
                    let root_id = chain
                        .last()
                        .map(|tenant| tenant.id.clone())
                        .unwrap_or_default();
                    Ok(self
                        .meter_view(&tx, &realm, &meter, &root_id, &principal)
                        .await?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/updateMeter`: renames a meter, changes its unit or description (`null` clears it), or archives it.
    /// Aggregation and pricing cannot change. Requires iam:billing:manage; audited as `billing:meter-update`.
    pub async fn update_meter(
        &self,
        credential: &CredentialInput,
        input: Body<billing::UpdateMeterInput>,
    ) -> IamResult<Reply<billing::UpdateMeterOutput>> {
        let key = meter_key(input.get("key"))?;
        let resource = format!("billing/meters/{key}");
        let body = &input;
        let key = &key;
        let resource_ref = &resource;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                &resource,
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    writable(&realm)?;
                    let mut raw = self.own_meter(&tx, &realm.id, key).await?;
                    let meter: BillingMeter = decode(raw.clone())?;
                    let rest = without(object(Some(&body.value()))?, &["tenantId", "key"]);
                    let fields = meter_settings(&rest, Some(&meter))?;
                    raw.shift_remove("description");
                    spread(&mut raw, &fields);
                    raw.insert("updatedAt".into(), number(self.ctx.now()));
                    raw.insert("updatedBy".into(), string(principal.identity.id.clone()));
                    let stored = tx.put(METERS, &raw).await?;
                    let next: BillingMeter = decode(stored)?;
                    let mut metadata = Map::new();
                    metadata.insert("key".into(), string(key.clone()));
                    metadata.insert("name".into(), string(next.name.clone()));
                    metadata.insert("unit".into(), string(next.unit.clone()));
                    metadata.insert("archived".into(), Value::Bool(next.archived));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:meter-update",
                        &realm.id,
                        resource_ref,
                        metadata,
                    )
                    .await?;
                    let root_id = self.root_id(&tx, &realm).await?;
                    Ok(self
                        .meter_view(&tx, &realm, &next, &root_id, &principal)
                        .await?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/deleteMeter`: deletes a meter that has never recorded usage, with its prices; a meter with history can
    /// only be archived (RESOURCE_IN_USE). Requires iam:billing:manage; audited as `billing:meter-delete`.
    pub async fn delete_meter(
        &self,
        credential: &CredentialInput,
        input: Body<billing::DeleteMeterInput>,
    ) -> IamResult<Reply<billing::DeleteMeterOutput>> {
        let key = meter_key(input.get("key"))?;
        let resource = format!("billing/meters/{key}");
        let key = &key;
        let resource_ref = &resource;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                &resource,
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let meter = self.own_meter(&tx, &realm.id, key).await?;
                    let meter_id = s(&meter, "id").to_owned();
                    if !tx
                        .find(
                            ROLLUPS,
                            &Filter::new().eq("meterId", meter_id.clone()),
                            &FindOptions::limit(1),
                        )
                        .await?
                        .is_empty()
                    {
                        return Err(IamError::with_status(
                            "RESOURCE_IN_USE",
                            "This meter has recorded usage; archive it instead",
                            409,
                        )
                        .into());
                    }
                    let prices =
                        find(&tx, PRICES, Filter::new().eq("meterId", meter_id.clone())).await?;
                    for price in &prices {
                        tx.delete(PRICES, s(price, "id")).await?;
                    }
                    tx.delete(METERS, &meter_id).await?;
                    let mut metadata = Map::new();
                    metadata.insert("key".into(), string(key.clone()));
                    metadata.insert("removedPrices".into(), number(prices.len() as f64));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:meter-delete",
                        &realm.id,
                        resource_ref,
                        metadata,
                    )
                    .await?;
                    Ok(json!({ "success": true, "removedPrices": prices.len() }))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/setPrice`: sets a rate-card price for a meter this tenant defines: its list price (on the tenant
    /// itself) or a negotiated price for a tenant below it (`targetTenantId`). `effectiveFrom` (default the current
    /// period; up to 12 periods back while none of them is invoiced for the tenants it reaches) starts it; `price:
    /// null` removes the entry. Requires iam:billing:manage; audited as `billing:price`.
    pub async fn set_price(
        &self,
        credential: &CredentialInput,
        input: Body<billing::SetPriceInput>,
    ) -> IamResult<Reply<billing::SetPriceOutput>> {
        let key = meter_key(input.get("meter"))?;
        let resource = format!("billing/meters/{key}");
        let body = &input;
        let key = &key;
        let resource_ref = &resource;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                &resource,
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: definer,
                 }| async move {
                    let ctx = &self.ctx;
                    let meter: BillingMeter = decode(self.own_meter(&tx, &definer.id, key).await?)?;
                    if meter.pricing != "rate-card" {
                        return Err(invalid("Reported meters carry their cost on each event").into());
                    }
                    let target = match body.get("targetTenantId") {
                        None => definer.clone(),
                        Some(value) => {
                            ctx.tenant(&tx, &text(Some(value), "targetTenantId", 256)?).await?
                        }
                    };
                    if !self.in_subtree(&tx, &definer, &target.id).await? {
                        return Err(invalid(
                            "targetTenantId must be the defining tenant or a tenant below it",
                        )
                        .into());
                    }
                    let current = self.current_period()?;
                    let effective_from = match body.get("effectiveFrom") {
                        None => current.clone(),
                        Some(value) => billing_period(Some(value), Some("effectiveFrom"))?,
                    };
                    if cmp_str(&effective_from, &current) == Ordering::Less {
                        // A past period may still be priced (usage recorded before its price was set) until it is
                        // invoiced.
                        if cmp_str(&effective_from, &shift_period(&current, -12.0)?) == Ordering::Less {
                            return Err(invalid("effectiveFrom may reach back at most 12 periods").into());
                        }
                        let mut affected: IndexSet<String> = subtree(ctx, &tx, &target)
                            .await?
                            .into_iter()
                            .map(|tenant| tenant.id)
                            .collect();
                        affected.insert(account_of(ctx, &tx, &target).await?.id);
                        let invoiced = find(&tx, STATEMENTS, Filter::new()).await?.iter().any(|statement| {
                            let status = s(statement, "status");
                            status != "void"
                                && status != "draft"
                                && cmp_str(s(statement, "period"), &effective_from) != Ordering::Less
                                && affected.contains(s(statement, "tenantId"))
                        });
                        if invoiced {
                            return Err(IamError::with_status(
                                "BILLING_PERIOD_CLOSED",
                                "A period from effectiveFrom on has already been invoiced; invoiced periods keep their prices",
                                409,
                            )
                            .into());
                        }
                    }
                    let unique_key = format!("{}:{effective_from}", meter.id);
                    let existing = find(
                        &tx,
                        PRICES,
                        Filter::new()
                            .eq("tenantId", target.id.clone())
                            .eq("uniqueKey", unique_key.clone()),
                    )
                    .await?
                    .into_iter()
                    .next();
                    if matches!(body.get("price"), Some(Value::Null)) {
                        if let Some(existing) = &existing {
                            tx.delete(PRICES, s(existing, "id")).await?;
                        }
                        let mut metadata = Map::new();
                        metadata.insert("meter".into(), string(key.clone()));
                        metadata.insert("targetTenantId".into(), string(target.id.clone()));
                        metadata.insert("effectiveFrom".into(), string(effective_from.clone()));
                        metadata.insert("price".into(), Value::Null);
                        self.audit(&tx, &principal, "billing:price", &definer.id, resource_ref, metadata)
                            .await?;
                        return Ok(Value::Null);
                    }
                    writable(&target)?;
                    let spec = price_spec(body.get("price"))?;
                    let mut entry = Record::new();
                    entry.insert(
                        "id".into(),
                        existing
                            .as_ref()
                            .and_then(|existing| existing.get("id").cloned())
                            .unwrap_or_else(|| string(id())),
                    );
                    entry.insert("tenantId".into(), string(target.id.clone()));
                    entry.insert("uniqueKey".into(), string(unique_key));
                    entry.insert("meterId".into(), string(meter.id.clone()));
                    entry.insert("meter".into(), string(key.clone()));
                    entry.insert("definerId".into(), string(definer.id.clone()));
                    entry.insert("effectiveFrom".into(), string(effective_from.clone()));
                    entry.insert("spec".into(), spec.clone());
                    if let Some(note) = body.get("note") {
                        entry.insert("note".into(), string(trim(&text(Some(note), "note", 512)?)));
                    }
                    entry.insert("setAt".into(), number(ctx.now()));
                    entry.insert("setBy".into(), string(principal.identity.id.clone()));
                    if existing.is_some() {
                        tx.put(PRICES, &entry).await?;
                    } else {
                        tx.insert(PRICES, &entry).await?;
                    }
                    let mut metadata = Map::new();
                    metadata.insert("meter".into(), string(key.clone()));
                    metadata.insert("targetTenantId".into(), string(target.id.clone()));
                    metadata.insert("effectiveFrom".into(), string(effective_from));
                    metadata.insert(
                        "model".into(),
                        spec.get("model").cloned().unwrap_or(Value::Null),
                    );
                    self.audit(&tx, &principal, "billing:price", &definer.id, resource_ref, metadata)
                        .await?;
                    let price: BillingPrice = decode(entry)?;
                    Ok(price_view(&price, true, Some(&target.name))?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/listPrices`: a meter's rate card as the tenant may see it: entries for the tenant, its ancestors (list
    /// prices) and tenants below it (newest first), and the entry that prices the tenant's account this period.
    /// Requires iam:billing:read.
    pub async fn list_prices(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ListPricesInput>,
    ) -> IamResult<Reply<billing::ListPricesOutput>> {
        let key = meter_key(input.get("meter"))?;
        let resource = format!("billing/meters/{key}");
        let key = &key;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                &resource,
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let chain = self.ctx.ancestry(&tx, &realm).await?;
                    let Some(meter) = resolve_meter(&tx, &chain, key).await? else {
                        return Err(not_found("Billing meter not found").into());
                    };
                    let mut visible: IndexSet<String> =
                        chain.iter().map(|tenant| tenant.id.clone()).collect();
                    visible.extend(
                        subtree(&self.ctx, &tx, &realm)
                            .await?
                            .into_iter()
                            .map(|tenant| tenant.id),
                    );
                    let show_set_by = self.sees_price_setter(&tx, &principal, &meter).await?;
                    let mut entries: Vec<(String, f64, Value)> = Vec::new();
                    for raw in
                        find(&tx, PRICES, Filter::new().eq("meterId", meter.id.clone())).await?
                    {
                        if !visible.contains(s(&raw, "tenantId")) {
                            continue;
                        }
                        let price: BillingPrice = decode(raw)?;
                        let name = tx
                            .get("tenants", &price.tenant_id)
                            .await?
                            .and_then(|tenant| {
                                tenant
                                    .get("name")
                                    .and_then(Value::as_str)
                                    .map(str::to_owned)
                            });
                        entries.push((
                            price.effective_from.clone(),
                            price.set_at,
                            price_view(&price, show_set_by, name.as_deref())?,
                        ));
                    }
                    entries.sort_by(|a, b| cmp_str(&b.0, &a.0).then_with(|| cmp_f64(b.1, a.1)));
                    let effective = if meter.pricing == "rate-card" {
                        self.effective_price(&tx, &realm, &meter, &self.current_period()?)
                            .await?
                    } else {
                        None
                    };
                    let root_id = chain
                        .last()
                        .map(|tenant| tenant.id.clone())
                        .unwrap_or_default();
                    let mut out = Map::new();
                    out.insert(
                        "meter".into(),
                        self.meter_view(&tx, &realm, &meter, &root_id, &principal)
                            .await?,
                    );
                    out.insert(
                        "entries".into(),
                        Value::Array(entries.into_iter().map(|entry| entry.2).collect()),
                    );
                    if let Some(effective) = &effective {
                        out.insert(
                            "effective".into(),
                            price_view(effective, show_set_by, None)?,
                        );
                    }
                    Ok(Value::Object(out))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/quote`: what `quantity` units of a meter cost the tenant's billing account in a period (default: the
    /// current one), as a period total with tiers and included units applied. Requires iam:billing:read.
    pub async fn quote(
        &self,
        credential: &CredentialInput,
        input: Body<billing::QuoteInput>,
    ) -> IamResult<Reply<billing::QuoteOutput>> {
        let key = meter_key(input.get("meter"))?;
        let resource = format!("billing/meters/{key}");
        let body = &input;
        let key = &key;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                &resource,
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let quantity = match body.get("quantity").and_then(core_js::as_number) {
                        Some(quantity) if quantity.is_finite() && quantity >= 0.0 => quantity,
                        _ => {
                            return Err(invalid("quantity must be a number of at least 0").into());
                        }
                    };
                    let period = self.period_or_current(body.get("period"))?;
                    let chain = self.ctx.ancestry(&tx, &realm).await?;
                    let Some(meter) = resolve_meter(&tx, &chain, key).await? else {
                        return Err(not_found("Billing meter not found").into());
                    };
                    if meter.pricing != "rate-card" {
                        return Err(
                            invalid("Reported meters carry their cost on each event").into()
                        );
                    }
                    let price = self.effective_price(&tx, &realm, &meter, &period).await?;
                    let amount = match &price {
                        Some(price) => price_quantity(&price.spec, quantity)?,
                        None => 0.0,
                    };
                    let mut out = Map::new();
                    out.insert("meter".into(), string(key.clone()));
                    out.insert(
                        "quantity".into(),
                        body.get("quantity").cloned().unwrap_or(Value::Null),
                    );
                    out.insert("period".into(), string(period));
                    out.insert("currency".into(), string(self.settings()?.currency));
                    out.insert("amountMicros".into(), number(amount));
                    out.insert("amount".into(), number(units_of(amount)?));
                    match &price {
                        Some(price) => {
                            let show = self.sees_price_setter(&tx, &principal, &meter).await?;
                            out.insert("price".into(), price_view(price, show, None)?);
                        }
                        None => {
                            out.insert("unpriced".into(), Value::Bool(true));
                        }
                    }
                    Ok(Value::Object(out))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Usage

    /// `billing/record`: records usage of a meter in the tenant, attributed to `identityId` (and their teams and
    /// department at that moment, or `teamId`), with optional `tags`. `idempotencyKey` makes retries safe.
    /// `enforceBudgets` refuses with SPEND_LIMIT_REACHED (402) once an enforced budget covering the usage is spent.
    /// Requires iam:billing:record on `iam/billing/meters/{key}`.
    pub async fn record(
        &self,
        credential: &CredentialInput,
        input: Body<billing::RecordInput>,
    ) -> IamResult<Reply<billing::RecordOutput>> {
        let key = meter_key(input.get("meter"))?;
        let resource = format!("billing/meters/{key}");
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:record",
                &resource,
                false,
                |MutationContext { tx, principal, .. }| async move {
                    let extra = if body.get("enforceBudgets") == Some(&Value::Bool(true)) {
                        json!({ "enforceBudgets": true })
                    } else {
                        json!({})
                    };
                    let receipt: UsageReceipt = self
                        .service
                        .record(&tx, &body.value(), &principal.identity.id, Some(&extra))
                        .await?;
                    Ok(to_json(&receipt)?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/recordMany`: records up to 100 events in one transaction (all or nothing), each in `tenantId` or a
    /// tenant below it. Requires iam:billing:record in `tenantId`.
    pub async fn record_many(
        &self,
        credential: &CredentialInput,
        input: Body<billing::RecordManyInput>,
    ) -> IamResult<Reply<billing::RecordManyOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:record",
                "billing",
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let Some(events) = body
                        .get("events")
                        .and_then(Value::as_array)
                        .filter(|events| !events.is_empty() && events.len() <= 100)
                    else {
                        return Err(invalid("events must list 1-100 usage events").into());
                    };
                    let mut receipts = Vec::with_capacity(events.len());
                    for raw in events {
                        let event = object(Some(raw))?;
                        let tenant_id = match event.get("tenantId") {
                            None => realm.id.clone(),
                            Some(value) => text(Some(value), "tenantId", 256)?,
                        };
                        if tenant_id != realm.id
                            && !self.in_subtree(&tx, &realm, &tenant_id).await?
                        {
                            return Err(invalid(
                                "Every event must be in this tenant or one below it",
                            )
                            .into());
                        }
                        let mut usage = event.clone();
                        usage.insert("tenantId".into(), string(tenant_id));
                        let receipt = self
                            .service
                            .record(&tx, &Value::Object(usage), &principal.identity.id, None)
                            .await?;
                        receipts.push(to_json(&receipt)?);
                    }
                    Ok(json!({ "receipts": receipts }))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/listUsage`: raw usage events recorded in this tenant (not its subtree) for a period (default current),
    /// newest first, optionally for one meter or identity; at most `limit` (1-500, default 100). Requires
    /// iam:billing:read.
    pub async fn list_usage(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ListUsageInput>,
    ) -> IamResult<Reply<billing::ListUsageOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let period = self.period_or_current(body.get("period"))?;
                    let limit = integer(
                        Some(&or_default(body.get("limit"), number(100.0))),
                        "limit",
                        1.0,
                        500.0,
                    )?;
                    let meter = match body.get("meter") {
                        None => None,
                        Some(value) => Some(meter_key(Some(value))?),
                    };
                    let identity_id = match body.get("identityId") {
                        None => None,
                        Some(value) => Some(text(Some(value), "identityId", 256)?),
                    };
                    let mut events: Vec<Record> = find(
                        &tx,
                        USAGE,
                        Filter::new()
                            .eq("tenantId", realm.id.clone())
                            .eq("period", period.clone()),
                    )
                    .await?
                    .into_iter()
                    .filter(|record| {
                        meter
                            .as_deref()
                            .is_none_or(|meter| s(record, "meter") == meter)
                            && identity_id.as_deref().is_none_or(|identity_id| {
                                record.get("identityId").and_then(Value::as_str)
                                    == Some(identity_id)
                                    || record.get("agentId").and_then(Value::as_str)
                                        == Some(identity_id)
                            })
                    })
                    .collect();
                    events.sort_by(|a, b| {
                        cmp_f64(n(b, "occurredAt"), n(a, "occurredAt"))
                            .then_with(|| cmp_str(s(a, "id"), s(b, "id")))
                    });
                    let events: Vec<Value> = events
                        .into_iter()
                        .take(limit as usize)
                        .map(|record| {
                            let unique_key = record
                                .get("uniqueKey")
                                .and_then(Value::as_str)
                                .map(str::to_owned);
                            let mut rest =
                                without(&record, &["rollupId", "expiresAt", "uniqueKey"]);
                            if let Some(key) = unique_key
                                .as_deref()
                                .and_then(|key| key.strip_prefix("idem:"))
                            {
                                rest.insert("idempotencyKey".into(), string(key));
                            }
                            Value::Object(rest)
                        })
                        .collect();
                    Ok(json!({ "tenantId": realm.id, "period": period, "events": events }))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Spend

    /// `billing/spend`: spend of the tenant and every tenant below it in a period (default current), grouped by
    /// `meter` (default), `identity`, `agent`, `team`, `department`, `tenant`, `day` or `tag:{name}`, optionally
    /// filtered. The current period carries a linear `forecast`. Requires iam:billing:read.
    pub async fn spend(
        &self,
        credential: &CredentialInput,
        input: Body<billing::SpendInput>,
    ) -> IamResult<Reply<billing::SpendOutput>> {
        let query = Value::Object(without(&input, &["tenantId"]));
        let query = &query;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let report = self.service.report(&tx, &realm, query, None, None).await?;
                    Ok(to_json(&report)?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/trend`: monthly totals for the last `months` periods (1-24, default 6), with the same filters as
    /// `spend`.
    pub async fn trend(
        &self,
        credential: &CredentialInput,
        input: Body<billing::TrendInput>,
    ) -> IamResult<Reply<billing::TrendOutput>> {
        let query = Value::Object(without(&input, &["tenantId"]));
        let query = &query;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let trend: SpendTrend = self.service.trend(&tx, &realm, query, None).await?;
                    Ok(to_json(&trend)?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/mySpend`: the caller's own spend (their usage and that of the agents they sponsor) in their tenant
    /// and the tenants below it, grouped by `meter` (default), `day`, `agent`, `tenant` or `tag:{name}`, with the
    /// budgets set on them. Any credential of the tenant; needs no permission.
    pub async fn my_spend(
        &self,
        credential: &CredentialInput,
        input: Body<billing::MySpendInput>,
    ) -> IamResult<Reply<billing::MySpendOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let group_by = or_default(input.get("groupBy"), string("meter"));
        let Some(group_by) = group_by
            .as_str()
            .filter(|group_by| {
                ["meter", "day", "agent", "tenant"].contains(group_by)
                    || group_by.starts_with("tag:")
            })
            .map(str::to_owned)
        else {
            return Err(invalid(
                "groupBy must be 'meter', 'day', 'agent', 'tenant' or 'tag:{name}'",
            ));
        };
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let authenticated = &authenticated;
        let tenant_id = &tenant_id;
        let group_by = &group_by;
        let body = &input;
        let result = ctx
            .store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, authenticated)
                    .await?;
                if principal.session.tenant_id != *tenant_id
                    || principal.identity.tenant_id != *tenant_id
                {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Spend is read in the credential\u{2019}s own tenant",
                        403,
                    ));
                }
                let realm = ctx.tenant(&tx, tenant_id).await?;
                let own = self
                    .service
                    .own_identities(&tx, &principal.identity)
                    .await?;
                let mut query = Map::new();
                query.insert("groupBy".into(), string(group_by.clone()));
                if let Some(period) = body.get("period") {
                    query.insert("period".into(), period.clone());
                }
                let filter = |row: &ChargedRow| {
                    row.identity_id.as_ref().is_some_and(|id| own.contains(id))
                        || row.agent_id.as_ref().is_some_and(|id| own.contains(id))
                };
                let report = self
                    .service
                    .report(
                        &tx,
                        &realm,
                        &Value::Object(query),
                        Some(&SpendCache::default()),
                        Some(&filter),
                    )
                    .await?;
                let mut budgets = Vec::new();
                for tenant in ctx.ancestry(&tx, &realm).await? {
                    for raw in find(
                        &tx,
                        BUDGETS,
                        Filter::new()
                            .eq("tenantId", tenant.id.clone())
                            .eq("subjectType", "identity")
                            .eq("subjectId", principal.identity.id.clone()),
                    )
                    .await?
                    {
                        let budget: BillingBudget = decode(raw)?;
                        budgets.push(to_json(
                            &self.service.budget_status(&tx, &budget, None).await?,
                        )?);
                    }
                }
                let mut out = to_map(&report)?;
                out.insert("budgets".into(), Value::Array(budgets));
                Ok(Value::Object(out))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/teamSpend`: a team's spend (with the teams below it), grouped by `identity` (default), `meter`,
    /// `team`, `agent`, `day` or `tag:{name}`. Allowed to the team's maintainers (and those of teams above it) or with
    /// iam:billing:read.
    pub async fn team_spend(
        &self,
        credential: &CredentialInput,
        input: Body<billing::TeamSpendInput>,
    ) -> IamResult<Reply<billing::TeamSpendOutput>> {
        let team_id = text(input.get("teamId"), "teamId", 256)?;
        let mut query = Map::new();
        query.insert("teamId".into(), string(team_id.clone()));
        query.insert(
            "groupBy".into(),
            or_default(input.get("groupBy"), string("identity")),
        );
        if let Some(period) = input.get("period") {
            query.insert("period".into(), period.clone());
        }
        let result = self
            .read_as(
                credential,
                input.get("tenantId"),
                &format!("billing/teams/{team_id}"),
                ReadVia::Team(team_id.clone()),
                Value::Object(query),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/departmentSpend`: a department's spend (with the departments below it), grouped by `identity`
    /// (default), `department`, `team`, `meter`, `day` or `tag:{name}`. Allowed to the department's head (and heads
    /// above it) or with iam:billing:read.
    pub async fn department_spend(
        &self,
        credential: &CredentialInput,
        input: Body<billing::DepartmentSpendInput>,
    ) -> IamResult<Reply<billing::DepartmentSpendOutput>> {
        let department_id = text(input.get("departmentId"), "departmentId", 256)?;
        let mut query = Map::new();
        query.insert("departmentId".into(), string(department_id.clone()));
        query.insert(
            "groupBy".into(),
            or_default(input.get("groupBy"), string("identity")),
        );
        if let Some(period) = input.get("period") {
            query.insert("period".into(), period.clone());
        }
        let result = self
            .read_as(
                credential,
                input.get("tenantId"),
                &format!("billing/departments/{department_id}"),
                ReadVia::Department(department_id.clone()),
                Value::Object(query),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/accounts`: the billing accounts in the tenant's subtree (every organization for the root) with this
    /// period's billable spend, projection, available credit and latest statement. Requires iam:billing:read.
    pub async fn accounts(
        &self,
        credential: &CredentialInput,
        input: Body<billing::AccountsInput>,
    ) -> IamResult<Reply<billing::AccountsOutput>> {
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let ctx = &self.ctx;
                    let period = self.current_period()?;
                    let now = ctx.now();
                    let report: SpendReport = self
                        .service
                        .report(
                            &tx,
                            &realm,
                            &json!({ "period": period, "groupBy": "tenant" }),
                            None,
                            None,
                        )
                        .await?;
                    let total_cost = report
                        .total
                        .get("costMicros")
                        .and_then(core_js::as_number)
                        .unwrap_or_default();
                    let factor = match report
                        .forecast
                        .as_ref()
                        .filter(|forecast| truthy(Some(forecast)))
                    {
                        Some(forecast) if total_cost > 0.0 => Some(
                            forecast
                                .get("costMicros")
                                .and_then(core_js::as_number)
                                .unwrap_or(f64::NAN)
                                / total_cost,
                        ),
                        _ => None,
                    };
                    let mut accounts: indexmap::IndexMap<String, Tenant> =
                        indexmap::IndexMap::new();
                    let top = account_of(ctx, &tx, &realm).await?;
                    if self.in_subtree(&tx, &realm, &top.id).await? {
                        accounts.insert(top.id.clone(), top);
                    }
                    for tenant in subtree(ctx, &tx, &realm).await? {
                        let account = account_of(ctx, &tx, &tenant).await?;
                        if account.parent_id.is_some()
                            && self.in_subtree(&tx, &realm, &account.id).await?
                        {
                            accounts.insert(account.id.clone(), account);
                        }
                    }
                    let mut result: Vec<(f64, String, Value)> = Vec::new();
                    for account in accounts.values() {
                        if account.parent_id.is_none() {
                            continue;
                        }
                        let spend = account_spend(ctx, &tx, account, &period, None).await?;
                        let billable = spend
                            .get("billableMicros")
                            .and_then(core_js::as_number)
                            .unwrap_or_default();
                        let mut statements: Vec<BillingStatement> = Vec::new();
                        for raw in find(
                            &tx,
                            STATEMENTS,
                            Filter::new().eq("tenantId", account.id.clone()),
                        )
                        .await?
                        {
                            if s(&raw, "status") != "draft" {
                                statements.push(decode(raw)?);
                            }
                        }
                        js_sort(&mut statements, |a, b| {
                            let first = if cmp_str(&a.period, &b.period) == Ordering::Less {
                                1.0
                            } else {
                                -1.0
                            };
                            if first != 0.0 {
                                first
                            } else {
                                b.issued_at - a.issued_at
                            }
                        });
                        let mut outstanding = 0.0;
                        for statement in &statements {
                            outstanding += amount_due(statement)?;
                        }
                        let outstanding = round_micros(outstanding)?;
                        let mut credits = 0.0;
                        for raw in find(
                            &tx,
                            CREDITS,
                            Filter::new().eq("tenantId", account.id.clone()),
                        )
                        .await?
                        {
                            let credit: BillingCredit = decode(raw)?;
                            if credit_active(&credit, now) {
                                credits += credit.remaining_micros;
                            }
                        }
                        let mut view = Map::new();
                        view.insert("accountId".into(), string(account.id.clone()));
                        view.insert("name".into(), string(account.name.clone()));
                        view.insert(
                            "hasProfile".into(),
                            Value::Bool(profile_of(&tx, &account.id).await?.is_some()),
                        );
                        view.insert("monthToDateMicros".into(), number(billable));
                        view.insert("monthToDate".into(), number(units_of(billable)?));
                        view.insert(
                            "totalMicros".into(),
                            spend.get("totalMicros").cloned().unwrap_or(Value::Null),
                        );
                        if let Some(factor) = factor {
                            view.insert(
                                "forecastMicros".into(),
                                number(round_micros(billable * factor)?),
                            );
                        }
                        view.insert("creditsMicros".into(), number(round_micros(credits)?));
                        view.insert("outstandingMicros".into(), number(outstanding));
                        if let Some(last) = statements.first() {
                            view.insert(
                                "lastStatement".into(),
                                summary(last, now, Some(&account.name))?,
                            );
                        }
                        result.push((billable, account.name.clone(), Value::Object(view)));
                    }
                    result
                        .sort_by(|a, b| cmp_f64(b.0, a.0).then_with(|| locale_compare(&a.1, &b.1)));
                    Ok(Value::Array(
                        result.into_iter().map(|entry| entry.2).collect(),
                    ))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/anomalies`: spend spikes in the tenant's subtree on `day` (default yesterday): people, teams and
    /// meters that spent at least `factor` (3) times their average over the `baselineDays` (14) before, and at least
    /// `minimum` (10 currency units) more, plus new spending above `minimum`. Requires iam:billing:read.
    pub async fn anomalies(
        &self,
        credential: &CredentialInput,
        input: Body<billing::AnomaliesInput>,
    ) -> IamResult<Reply<billing::AnomaliesOutput>> {
        let options = Value::Object(without(&input, &["tenantId"]));
        let options = &options;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let anomalies: Vec<SpendAnomaly> =
                        self.service.anomalies(&tx, &realm, options).await?;
                    Ok(json!({ "tenantId": realm.id, "anomalies": to_json(&anomalies)? }))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/exportSpend`: a spend report as CSV (the same query as `spend`). Requires iam:billing:read.
    pub async fn export_spend(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ExportSpendInput>,
    ) -> IamResult<Reply<billing::ExportSpendOutput>> {
        let query = Value::Object(without(&input, &["tenantId"]));
        let query = &query;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let report = self.service.report(&tx, &realm, query, None, None).await?;
                    let group_by = report
                        .group_by
                        .as_str()
                        .unwrap_or_default()
                        .replacen(':', "-", 1);
                    let filename = format!(
                        "spend-{}-{}-{group_by}.csv",
                        realm.slug.clone().unwrap_or_else(|| realm.id.clone()),
                        report.period
                    );
                    Ok(json!({
                        "filename": filename,
                        "contentType": "text/csv; charset=utf-8",
                        "body": self.service.spend_csv(&report)?,
                    }))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/exportStatement`: a statement as CSV: its lines, credit and total, then the breakdown by project,
    /// team, department and person.
    pub async fn export_statement(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ExportStatementInput>,
    ) -> IamResult<Reply<billing::ExportStatementOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing/statements",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let raw = self
                        .scoped_statement(&tx, &realm, body.get("statementId"))
                        .await?;
                    let statement: BillingStatement = decode(raw)?;
                    Ok(json!({
                        "filename": format!("{}.csv", statement.number),
                        "contentType": "text/csv; charset=utf-8",
                        "body": self.service.statement_csv(&statement)?,
                    }))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Budgets

    /// `billing/createBudget`: creates a spend budget owned by the tenant. Names are unique per tenant; at most 200.
    /// Requires iam:billing:manage; audited as `billing:budget-create`.
    pub async fn create_budget(
        &self,
        credential: &CredentialInput,
        input: Body<billing::CreateBudgetInput>,
    ) -> IamResult<Reply<billing::CreateBudgetOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/budgets",
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    writable(&realm)?;
                    let fields = self.budget_settings(object(Some(&body.value()))?, None)?;
                    let (subject_type, subject_id) = self
                        .budget_subject(&tx, &realm, body.get("subjectType"), body.get("subjectId"))
                        .await?;
                    let existing =
                        find(&tx, BUDGETS, Filter::new().eq("tenantId", realm.id.clone())).await?;
                    if existing.len() >= MAX_BUDGETS_PER_TENANT {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!("A tenant can have at most {MAX_BUDGETS_PER_TENANT} budgets"),
                            409,
                        )
                        .into());
                    }
                    let name = fields
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let unique_key = format!("name:{}", core_js::to_lower(name));
                    if existing
                        .iter()
                        .any(|budget| s(budget, "uniqueKey") == unique_key)
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A budget with this name already exists",
                            409,
                        )
                        .into());
                    }
                    let now = self.ctx.now();
                    let mut record = Record::new();
                    record.insert("id".into(), string(id()));
                    record.insert("tenantId".into(), string(realm.id.clone()));
                    record.insert("uniqueKey".into(), string(unique_key));
                    spread(&mut record, &Value::Object(fields));
                    record.insert("subjectType".into(), string(subject_type));
                    record.insert("subjectId".into(), string(subject_id));
                    record.insert("createdAt".into(), number(now));
                    record.insert("createdBy".into(), string(principal.identity.id.clone()));
                    record.insert("updatedAt".into(), number(now));
                    record.insert("updatedBy".into(), string(principal.identity.id.clone()));
                    let stored = tx.insert(BUDGETS, &record).await?;
                    let budget: BillingBudget = decode(stored)?;
                    let mut metadata = Map::new();
                    metadata.insert("budgetId".into(), string(budget.id.clone()));
                    metadata.insert("name".into(), string(budget.name.clone()));
                    metadata.insert("subjectType".into(), budget.subject_type.clone());
                    metadata.insert("subjectId".into(), string(budget.subject_id.clone()));
                    metadata.insert("amountMicros".into(), number(budget.amount_micros));
                    metadata.insert("period".into(), budget.period.clone());
                    metadata.insert("enforce".into(), Value::Bool(budget.enforce));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:budget-create",
                        &realm.id,
                        &format!("billing/budgets/{}", budget.id),
                        metadata,
                    )
                    .await?;
                    Ok(self.budget_view(&tx, &budget).await?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/updateBudget`: changes a budget's name, amount, period, meters (`null` for all), thresholds, alerts or
    /// enforcement; its subject stays. Requires iam:billing:manage; audited as `billing:budget-update`.
    pub async fn update_budget(
        &self,
        credential: &CredentialInput,
        input: Body<billing::UpdateBudgetInput>,
    ) -> IamResult<Reply<billing::UpdateBudgetOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/budgets",
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    writable(&realm)?;
                    let mut raw = self
                        .own_budget(&tx, &realm.id, body.get("budgetId"))
                        .await?;
                    let budget: BillingBudget = decode(raw.clone())?;
                    let fields =
                        self.budget_settings(object(Some(&body.value()))?, Some(&budget))?;
                    let name = fields
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let unique_key = format!("name:{}", core_js::to_lower(name));
                    if Some(unique_key.as_str()) != budget.unique_key.as_deref()
                        && !find(
                            &tx,
                            BUDGETS,
                            Filter::new()
                                .eq("tenantId", realm.id.clone())
                                .eq("uniqueKey", unique_key.clone()),
                        )
                        .await?
                        .is_empty()
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A budget with this name already exists",
                            409,
                        )
                        .into());
                    }
                    raw.shift_remove("meters");
                    spread(&mut raw, &Value::Object(fields));
                    raw.insert("uniqueKey".into(), string(unique_key));
                    raw.insert("updatedAt".into(), number(self.ctx.now()));
                    raw.insert("updatedBy".into(), string(principal.identity.id.clone()));
                    let stored = tx.put(BUDGETS, &raw).await?;
                    let next: BillingBudget = decode(stored)?;
                    let mut metadata = Map::new();
                    metadata.insert("budgetId".into(), string(budget.id.clone()));
                    metadata.insert("name".into(), string(next.name.clone()));
                    metadata.insert("amountMicros".into(), number(next.amount_micros));
                    metadata.insert("period".into(), next.period.clone());
                    metadata.insert("enforce".into(), Value::Bool(next.enforce));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:budget-update",
                        &realm.id,
                        &format!("billing/budgets/{}", budget.id),
                        metadata,
                    )
                    .await?;
                    Ok(self.budget_view(&tx, &next).await?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/deleteBudget`: deletes a budget and its alert history. Requires iam:billing:manage; audited as
    /// `billing:budget-delete`.
    pub async fn delete_budget(
        &self,
        credential: &CredentialInput,
        input: Body<billing::DeleteBudgetInput>,
    ) -> IamResult<Reply<billing::DeleteBudgetOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/budgets",
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let budget = self
                        .own_budget(&tx, &realm.id, body.get("budgetId"))
                        .await?;
                    let budget_id = s(&budget, "id").to_owned();
                    for alert in find(
                        &tx,
                        BUDGET_ALERTS,
                        Filter::new()
                            .eq("tenantId", realm.id.clone())
                            .eq("budgetId", budget_id.clone()),
                    )
                    .await?
                    {
                        tx.delete(BUDGET_ALERTS, s(&alert, "id")).await?;
                    }
                    tx.delete(BUDGETS, &budget_id).await?;
                    let mut metadata = Map::new();
                    metadata.insert("budgetId".into(), string(budget_id.clone()));
                    metadata.insert(
                        "name".into(),
                        budget.get("name").cloned().unwrap_or(Value::Null),
                    );
                    self.audit(
                        &tx,
                        &principal,
                        "billing:budget-delete",
                        &realm.id,
                        &format!("billing/budgets/{budget_id}"),
                        metadata,
                    )
                    .await?;
                    Ok(json!({ "success": true }))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/listBudgets`: the tenant's budgets with their spend, projection and thresholds reached this window.
    /// Requires iam:billing:read.
    pub async fn list_budgets(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ListBudgetsInput>,
    ) -> IamResult<Reply<billing::ListBudgetsOutput>> {
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing/budgets",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let mut budgets: Vec<BillingBudget> = Vec::new();
                    for raw in
                        find(&tx, BUDGETS, Filter::new().eq("tenantId", realm.id.clone())).await?
                    {
                        budgets.push(decode(raw)?);
                    }
                    budgets.sort_by(|a, b| locale_compare(&a.name, &b.name));
                    let mut views = Vec::with_capacity(budgets.len());
                    for budget in &budgets {
                        views.push(self.budget_view(&tx, budget).await?);
                    }
                    Ok(Value::Array(views))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/check`: whether the caller's own usage (of `meter`, when given) is within every enforced budget that
    /// covers it. Any credential of the tenant; not audited.
    pub async fn check(
        &self,
        credential: &CredentialInput,
        input: Body<billing::CheckInput>,
    ) -> IamResult<Reply<billing::CheckOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let authenticated = &authenticated;
        let tenant_id = &tenant_id;
        let body = &input;
        let result = ctx
            .store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, authenticated)
                    .await?;
                let realm = ctx.tenant(&tx, tenant_id).await?;
                let chain = ctx.ancestry(&tx, &realm).await?;
                if !chain
                    .iter()
                    .any(|tenant| tenant.id == principal.identity.tenant_id)
                {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Budgets are checked in the credential\u{2019}s own tenant",
                        403,
                    ));
                }
                let mut query = Map::new();
                query.insert("identityId".into(), string(principal.identity.id.clone()));
                if let Some(meter) = body.get("meter") {
                    query.insert("meter".into(), meter.clone());
                }
                let check: SpendCheck = self
                    .service
                    .check(&tx, &realm, &Value::Object(query))
                    .await?;
                to_json(&check)
            })
            .await?;
        Ok(Reply::json(result))
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Credits

    /// `billing/grantCredit`: grants credit to a billing account: statements draw on it, earliest expiry first. Root
    /// administrators only; audited as `billing:credit-grant`.
    pub async fn grant_credit(
        &self,
        credential: &CredentialInput,
        input: Body<billing::GrantCreditInput>,
    ) -> IamResult<Reply<billing::GrantCreditOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/credits",
                true,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let ctx = &self.ctx;
                    writable(&realm)?;
                    if realm.parent_id.is_none() || account_of(ctx, &tx, &realm).await?.id != realm.id {
                        return Err(invalid(
                            "Credit is granted to a billing account (an organization or a tenant with a billing profile)",
                        )
                        .into());
                    }
                    let amount = amount_micros(body.get("amount"), "amount")?;
                    if amount <= 0.0 {
                        return Err(invalid("amount must be above 0").into());
                    }
                    let mut record = Record::new();
                    record.insert("id".into(), string(id()));
                    record.insert("tenantId".into(), string(realm.id.clone()));
                    record.insert("amountMicros".into(), number(amount));
                    record.insert("remainingMicros".into(), number(amount));
                    record.insert(
                        "reason".into(),
                        string(trim(&text(body.get("reason"), "reason", 256)?)),
                    );
                    if let Some(expires_at) = body.get("expiresAt") {
                        record.insert(
                            "expiresAt".into(),
                            number(ctx.binding_expiry(Some(expires_at))?),
                        );
                    }
                    record.insert("grantedAt".into(), number(ctx.now()));
                    record.insert("grantedBy".into(), string(principal.identity.id.clone()));
                    let stored = tx.insert(CREDITS, &record).await?;
                    let credit: BillingCredit = decode(stored)?;
                    let mut metadata = Map::new();
                    metadata.insert("creditId".into(), string(credit.id.clone()));
                    metadata.insert("amountMicros".into(), number(amount));
                    metadata.insert("reason".into(), string(credit.reason.clone()));
                    if let Some(expires_at) = credit.expires_at {
                        metadata.insert("expiresAt".into(), number(expires_at));
                    }
                    self.audit(
                        &tx,
                        &principal,
                        "billing:credit-grant",
                        &realm.id,
                        &format!("billing/credits/{}", credit.id),
                        metadata,
                    )
                    .await?;
                    Ok(credit_view(&credit, ctx.now())?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/revokeCredit`: withdraws what is left of a credit. Root administrators only; audited as
    /// `billing:credit-revoke`.
    pub async fn revoke_credit(
        &self,
        credential: &CredentialInput,
        input: Body<billing::RevokeCreditInput>,
    ) -> IamResult<Reply<billing::RevokeCreditOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/credits",
                true,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let mut raw = self
                        .scoped_record(&tx, CREDITS, body.get("creditId"), "creditId", &realm.id)
                        .await?;
                    let credit: BillingCredit = decode(raw.clone())?;
                    if credit.revoked_at.is_some() {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "The credit is already revoked",
                            409,
                        )
                        .into());
                    }
                    raw.insert("remainingMicros".into(), number(0.0));
                    raw.insert("revokedAt".into(), number(self.ctx.now()));
                    let next: BillingCredit = decode(tx.put(CREDITS, &raw).await?)?;
                    let mut metadata = Map::new();
                    metadata.insert("creditId".into(), string(credit.id.clone()));
                    metadata.insert("forfeitedMicros".into(), number(credit.remaining_micros));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:credit-revoke",
                        &realm.id,
                        &format!("billing/credits/{}", credit.id),
                        metadata,
                    )
                    .await?;
                    Ok(credit_view(&next, self.ctx.now())?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/listCredits`: the credits of the tenant's billing account with the available balance; empty (with
    /// `inherited: true`) when an ancestor pays for the tenant. Requires iam:billing:read.
    pub async fn list_credits(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ListCreditsInput>,
    ) -> IamResult<Reply<billing::ListCreditsOutput>> {
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing/credits",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let account = account_of(&self.ctx, &tx, &realm).await?;
                    let now = self.ctx.now();
                    if account.id != realm.id {
                        return Ok(json!({
                            "accountId": account.id,
                            "inherited": true,
                            "balanceMicros": 0,
                            "balance": 0,
                            "credits": [],
                        }));
                    }
                    let mut credits: Vec<BillingCredit> = Vec::new();
                    for raw in
                        find(&tx, CREDITS, Filter::new().eq("tenantId", realm.id.clone())).await?
                    {
                        credits.push(decode(raw)?);
                    }
                    credits.sort_by(|a, b| {
                        cmp_f64(b.granted_at, a.granted_at).then_with(|| cmp_str(&a.id, &b.id))
                    });
                    let balance = round_micros(
                        credits
                            .iter()
                            .filter(|credit| credit_active(credit, now))
                            .fold(0.0, |sum, credit| sum + credit.remaining_micros),
                    )?;
                    let views = credits
                        .iter()
                        .map(|credit| credit_view(credit, now))
                        .collect::<IamResult<Vec<Value>>>()?;
                    Ok(json!({
                        "accountId": account.id,
                        "inherited": false,
                        "balanceMicros": number(balance),
                        "balance": number(units_of(balance)?),
                        "credits": views,
                    }))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/setTerms`: sets a billing account's contract terms: `discountPercent` off usage, a
    /// `minimumCommitment` per month, and the `taxRatePercent` statements add, labelled `taxLabel`; `null` clears a
    /// term. Root administrators only; audited as `billing:terms`.
    pub async fn set_terms(
        &self,
        credential: &CredentialInput,
        input: Body<billing::SetTermsInput>,
    ) -> IamResult<Reply<billing::SetTermsOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/terms",
                true,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let ctx = &self.ctx;
                    writable(&realm)?;
                    if realm.parent_id.is_none() || account_of(ctx, &tx, &realm).await?.id != realm.id {
                        return Err(invalid(
                            "Terms belong to a billing account (an organization or a tenant with a billing profile)",
                        )
                        .into());
                    }
                    let existing = terms_of(&tx, &realm.id).await?;
                    let percent = |value: Option<&Value>, current: Option<f64>, name: &str| -> IamResult<Option<f64>> {
                        match value {
                            Some(Value::Null) => Ok(None),
                            None => Ok(current),
                            Some(value) => match core_js::as_number(value) {
                                Some(value) if value.is_finite() && (0.0..=100.0).contains(&value) => {
                                    Ok(Some(js_round(value * 1000.0) / 1000.0))
                                }
                                _ => Err(invalid(format!("{name} must be a percentage from 0 to 100"))),
                            },
                        }
                    };
                    let discount_percent = percent(
                        body.get("discountPercent"),
                        existing.as_ref().and_then(|terms| terms.discount_percent),
                        "discountPercent",
                    )?;
                    let tax_rate_percent = percent(
                        body.get("taxRatePercent"),
                        existing.as_ref().and_then(|terms| terms.tax_rate_percent),
                        "taxRatePercent",
                    )?;
                    let minimum_commitment_micros = match body.get("minimumCommitment") {
                        Some(Value::Null) => None,
                        None => existing.as_ref().and_then(|terms| terms.minimum_commitment_micros),
                        Some(value) => Some(amount_micros(Some(value), "minimumCommitment")?),
                    };
                    let tax_label = match body.get("taxLabel") {
                        Some(Value::Null) => None,
                        None => existing.as_ref().and_then(|terms| terms.tax_label.clone()),
                        Some(value) => Some(trim(&text(Some(value), "taxLabel", 32)?)),
                    };
                    let set_at = ctx.now();
                    let mut record = Record::new();
                    record.insert(
                        "id".into(),
                        string(existing.as_ref().map(|terms| terms.id.clone()).unwrap_or_else(id)),
                    );
                    record.insert("tenantId".into(), string(realm.id.clone()));
                    record.insert("uniqueKey".into(), string("terms"));
                    if let Some(percent) = discount_percent {
                        record.insert("discountPercent".into(), number(percent));
                    }
                    if let Some(micros) = minimum_commitment_micros {
                        record.insert("minimumCommitmentMicros".into(), number(micros));
                    }
                    if let Some(percent) = tax_rate_percent {
                        record.insert("taxRatePercent".into(), number(percent));
                    }
                    if let Some(label) = &tax_label {
                        record.insert("taxLabel".into(), string(label.clone()));
                    }
                    record.insert("setAt".into(), number(set_at));
                    record.insert("setBy".into(), string(principal.identity.id.clone()));
                    if existing.is_some() {
                        tx.put(TERMS, &record).await?;
                    } else {
                        tx.insert(TERMS, &record).await?;
                    }
                    let terms: BillingTerms = decode(record)?;
                    let mut metadata = Map::new();
                    metadata.insert(
                        "discountPercent".into(),
                        terms.discount_percent.map(number).unwrap_or(Value::Null),
                    );
                    metadata.insert(
                        "minimumCommitmentMicros".into(),
                        terms.minimum_commitment_micros.map(number).unwrap_or(Value::Null),
                    );
                    metadata.insert(
                        "taxRatePercent".into(),
                        terms.tax_rate_percent.map(number).unwrap_or(Value::Null),
                    );
                    self.audit(&tx, &principal, "billing:terms", &realm.id, "billing/terms", metadata)
                        .await?;
                    Ok(terms_view(&realm.id, Some(&terms), true)?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/getTerms`: the contract terms of the tenant's billing account (empty when none are set; `inherited`
    /// when an ancestor pays for the tenant). Requires iam:billing:read.
    pub async fn get_terms(
        &self,
        credential: &CredentialInput,
        input: Body<billing::GetTermsInput>,
    ) -> IamResult<Reply<billing::GetTermsOutput>> {
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing/terms",
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let account = account_of(&self.ctx, &tx, &realm).await?;
                    if account.id != realm.id {
                        return Ok(json!({ "accountId": account.id, "inherited": true }));
                    }
                    let root_id = self.root_id(&tx, &realm).await?;
                    let terms = terms_of(&tx, &realm.id).await?;
                    Ok(terms_view(
                        &realm.id,
                        terms.as_ref(),
                        principal.identity.tenant_id == root_id,
                    )?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Profiles

    /// `billing/getProfile`: the billing profile of the tenant (or of `targetTenantId`, a tenant below it) and the
    /// account that pays for it. Requires iam:billing:read.
    pub async fn get_profile(
        &self,
        credential: &CredentialInput,
        input: Body<billing::GetProfileInput>,
    ) -> IamResult<Reply<billing::GetProfileOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing/profile",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let target = self
                        .profile_target(&tx, &realm, body.get("targetTenantId"))
                        .await?;
                    let profile = self.profile_record(&tx, &target.id).await?;
                    Ok(self.profile_view(&tx, &target, profile.as_ref()).await?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/setProfile`: creates or updates a billing profile; `null` clears a field. A profile below an
    /// organization makes that tenant its own billing account, which is the parent's decision. Requires
    /// iam:billing:manage; audited as `billing:profile`.
    pub async fn set_profile(
        &self,
        credential: &CredentialInput,
        input: Body<billing::SetProfileInput>,
    ) -> IamResult<Reply<billing::SetProfileOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/profile",
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let ctx = &self.ctx;
                    let target = self.profile_target(&tx, &realm, body.get("targetTenantId")).await?;
                    writable(&target)?;
                    if target.parent_id.is_none() {
                        return Err(invalid("The platform tenant is not billed").into());
                    }
                    let existing = profile_of(&tx, &target.id).await?;
                    if existing.is_none()
                        && target.id == realm.id
                        && ctx.ancestry(&tx, &target).await?.len() > 2
                    {
                        return Err(OperationDenied::new(Some(
                            "A tenant below an organization becomes its own billing account only from its parent (setProfile with targetTenantId)",
                        )));
                    }
                    let optional = |value: Option<&Value>, current: Option<&String>, name: &str, max: usize| -> IamResult<Option<String>> {
                        match value {
                            Some(Value::Null) => Ok(None),
                            None => Ok(current.cloned()),
                            Some(value) => Ok(Some(trim(&text(Some(value), name, max)?))),
                        }
                    };
                    let billing_emails: Vec<String> = match body.get("billingEmails") {
                        None => existing
                            .as_ref()
                            .map(|profile| profile.billing_emails.clone())
                            .unwrap_or_default(),
                        Some(value) => {
                            let Some(items) = value.as_array().filter(|items| items.len() <= 10) else {
                                return Err(invalid("billingEmails must list at most 10 addresses").into());
                            };
                            let addresses = items
                                .iter()
                                .map(|item| email(Some(item)))
                                .collect::<IamResult<Vec<String>>>()?;
                            addresses.into_iter().collect::<IndexSet<String>>().into_iter().collect()
                        }
                    };
                    let current_terms = existing.as_ref().and_then(|profile| profile.payment_terms_days);
                    let payment_terms_days = match body.get("paymentTermsDays") {
                        Some(Value::Null) => None,
                        None => current_terms,
                        Some(value) => Some(integer(Some(value), "paymentTermsDays", 0.0, 365.0)?),
                    };
                    // Longer payment terms are credit the platform extends: billing managers keep the terms they have
                    // or choose terms up to the deployment's default (`billing.paymentTermsDays`); only root
                    // administrators grant more.
                    let default_terms = self.settings()?.payment_terms_days;
                    if let Some(days) = payment_terms_days
                        && Some(days) != current_terms
                        && days > default_terms
                        && !ctx.root_principal(&tx, &principal).await?
                    {
                        return Err(OperationDenied::new(Some(&format!(
                            "Payment terms above {} days are set by root administrators",
                            number_text(default_terms)
                        ))));
                    }
                    let current = existing.as_ref();
                    let fields = [
                        (
                            "companyName",
                            optional(
                                body.get("companyName"),
                                current.and_then(|profile| profile.company_name.as_ref()),
                                "companyName",
                                256,
                            )?,
                        ),
                        (
                            "taxId",
                            optional(
                                body.get("taxId"),
                                current.and_then(|profile| profile.tax_id.as_ref()),
                                "taxId",
                                64,
                            )?,
                        ),
                        (
                            "address",
                            optional(
                                body.get("address"),
                                current.and_then(|profile| profile.address.as_ref()),
                                "address",
                                1024,
                            )?,
                        ),
                        (
                            "purchaseOrder",
                            optional(
                                body.get("purchaseOrder"),
                                current.and_then(|profile| profile.purchase_order.as_ref()),
                                "purchaseOrder",
                                128,
                            )?,
                        ),
                        (
                            "costCenter",
                            optional(
                                body.get("costCenter"),
                                current.and_then(|profile| profile.cost_center.as_ref()),
                                "costCenter",
                                128,
                            )?,
                        ),
                    ];
                    let now = ctx.now();
                    let mut profile = Record::new();
                    profile.insert(
                        "id".into(),
                        string(current.map(|profile| profile.id.clone()).unwrap_or_else(id)),
                    );
                    profile.insert("tenantId".into(), string(target.id.clone()));
                    profile.insert("uniqueKey".into(), string("profile"));
                    profile.insert("billingEmails".into(), json!(billing_emails));
                    for (name, value) in &fields {
                        if let Some(value) = value {
                            profile.insert((*name).into(), string(value.clone()));
                        }
                    }
                    if let Some(days) = payment_terms_days {
                        profile.insert("paymentTermsDays".into(), number(days));
                    }
                    profile.insert(
                        "createdAt".into(),
                        number(current.map(|profile| profile.created_at).unwrap_or(now)),
                    );
                    profile.insert(
                        "createdBy".into(),
                        string(
                            current
                                .map(|profile| profile.created_by.clone())
                                .unwrap_or_else(|| principal.identity.id.clone()),
                        ),
                    );
                    profile.insert("updatedAt".into(), number(now));
                    profile.insert("updatedBy".into(), string(principal.identity.id.clone()));
                    if existing.is_some() {
                        tx.put(PROFILES, &profile).await?;
                    } else {
                        tx.insert(PROFILES, &profile).await?;
                    }
                    let mut metadata = Map::new();
                    metadata.insert("targetTenantId".into(), string(target.id.clone()));
                    metadata.insert("created".into(), Value::Bool(existing.is_none()));
                    metadata.insert("billingEmails".into(), number(billing_emails.len() as f64));
                    if truthy(profile.get("companyName")) {
                        metadata.insert(
                            "companyName".into(),
                            profile.get("companyName").cloned().unwrap_or(Value::Null),
                        );
                    }
                    self.audit(
                        &tx,
                        &principal,
                        "billing:profile",
                        &realm.id,
                        &format!("billing/profile/{}", target.id),
                        metadata,
                    )
                    .await?;
                    Ok(self.profile_view(&tx, &target, Some(&profile)).await?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/deleteProfile`: removes a billing profile (the tenant's own, or `targetTenantId`'s below it).
    /// Requires iam:billing:manage; audited as `billing:profile-delete`.
    pub async fn delete_profile(
        &self,
        credential: &CredentialInput,
        input: Body<billing::DeleteProfileInput>,
    ) -> IamResult<Reply<billing::DeleteProfileOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/profile",
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let target = self.profile_target(&tx, &realm, body.get("targetTenantId")).await?;
                    let Some(existing) = profile_of(&tx, &target.id).await? else {
                        return Err(not_found("This tenant has no billing profile").into());
                    };
                    if target.id == realm.id && self.ctx.ancestry(&tx, &target).await?.len() > 2 {
                        return Err(OperationDenied::new(Some(
                            "Folding a tenant back into its parent\u{2019}s billing account is decided from the parent (targetTenantId)",
                        )));
                    }
                    tx.delete(PROFILES, &existing.id).await?;
                    let mut metadata = Map::new();
                    metadata.insert("targetTenantId".into(), string(target.id.clone()));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:profile-delete",
                        &realm.id,
                        &format!("billing/profile/{}", target.id),
                        metadata,
                    )
                    .await?;
                    Ok(json!({ "success": true }))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Statements

    /// `billing/listStatements`: statements of the billing accounts in the tenant's subtree (all for the root), newest
    /// period first, optionally by `status` or `period`. Requires iam:billing:read.
    pub async fn list_statements(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ListStatementsInput>,
    ) -> IamResult<Reply<billing::ListStatementsOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing/statements",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let period = match body.get("period") {
                        None => None,
                        Some(value) => Some(billing_period(Some(value), None)?),
                    };
                    let now = self.ctx.now();
                    let mut names: indexmap::IndexMap<String, Option<String>> =
                        indexmap::IndexMap::new();
                    let mut result: Vec<(String, f64, Value)> = Vec::new();
                    for raw in self.scope_statements(&tx, &realm).await? {
                        if let Some(status) = body.get("status")
                            && raw.get("status") != Some(status)
                        {
                            continue;
                        }
                        if period
                            .as_deref()
                            .is_some_and(|period| s(&raw, "period") != period)
                        {
                            continue;
                        }
                        let statement: BillingStatement = decode(raw)?;
                        if !names.contains_key(&statement.tenant_id) {
                            let name =
                                tx.get("tenants", &statement.tenant_id)
                                    .await?
                                    .and_then(|tenant| {
                                        tenant
                                            .get("name")
                                            .and_then(Value::as_str)
                                            .map(str::to_owned)
                                    });
                            names.insert(statement.tenant_id.clone(), name);
                        }
                        let name = names.get(&statement.tenant_id).cloned().flatten();
                        result.push((
                            statement.period.clone(),
                            statement.issued_at,
                            summary(&statement, now, name.as_deref())?,
                        ));
                    }
                    result.sort_by(|a, b| cmp_str(&b.0, &a.0).then_with(|| cmp_f64(b.1, a.1)));
                    Ok(Value::Array(
                        result.into_iter().map(|entry| entry.2).collect(),
                    ))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/getStatement`: a statement with its lines, credits, allocation breakdown and bill-to details;
    /// `verified` re-checks its content hash. Requires iam:billing:read.
    pub async fn get_statement(
        &self,
        credential: &CredentialInput,
        input: Body<billing::GetStatementInput>,
    ) -> IamResult<Reply<billing::GetStatementOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing/statements",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let raw = self
                        .scoped_statement(&tx, &realm, body.get("statementId"))
                        .await?;
                    let statement: BillingStatement = decode(raw.clone())?;
                    let verified = statement_hash(&Value::Object(raw.clone()))? == statement.hash;
                    let mut out = raw;
                    out.insert("total".into(), number(units_of(statement.total_micros)?));
                    out.insert(
                        "overdue".into(),
                        Value::Bool(overdue(&statement, self.ctx.now())?),
                    );
                    out.insert("verified".into(), Value::Bool(verified));
                    Ok(Value::Object(out))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/previewStatement`: what the tenant's statement for a period (default the current one, so far) would
    /// hold, without issuing it. Requires iam:billing:read.
    pub async fn preview_statement(
        &self,
        credential: &CredentialInput,
        input: Body<billing::PreviewStatementInput>,
    ) -> IamResult<Reply<billing::PreviewStatementOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing/statements",
                false,
                |MutationContext { tx, tenant: realm, .. }| async move {
                    let period = self.period_or_current(body.get("period"))?;
                    let account = account_of(&self.ctx, &tx, &realm).await?;
                    if account.id != realm.id || realm.parent_id.is_none() {
                        return Err(invalid(
                            "Only a billing account (an organization or a tenant with a profile) has statements",
                        )
                        .into());
                    }
                    let draft: StatementDraft = self
                        .service
                        .draft_statement(&tx, &account, &period, None, None)
                        .await?;
                    Ok(to_json(&draft)?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/closePeriod`: issues statements for a past period (default the previous one) for every billing
    /// account, or only `accountId`'s; `draft` keeps them as drafts. Called on the root tenant; root administrators
    /// only.
    pub async fn close_period(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ClosePeriodInput>,
    ) -> IamResult<Reply<billing::ClosePeriodOutput>> {
        self.run(
            credential,
            input.get("tenantId"),
            "iam:billing:manage",
            "billing/periods",
            true,
            |MutationContext { tenant: realm, .. }| async move {
                if realm.parent_id.is_some() {
                    return Err(invalid("Periods are closed on the platform (root) tenant").into());
                }
                Ok(crate::port::undefined())
            },
        )
        .await?;
        let mut options = Map::new();
        if let Some(period) = input.get("period") {
            options.insert("period".into(), period.clone());
        }
        if let Some(account_id) = input.get("accountId") {
            options.insert("tenantId".into(), account_id.clone());
        }
        if let Some(draft) = input.get("draft") {
            options.insert("draft".into(), draft.clone());
        }
        let result: ClosePeriodResult = self
            .service
            .close_period(Some(&Value::Object(options)))
            .await?;
        Ok(Reply::json(to_json(&result)?))
    }

    /// `billing/markPaid`: marks a finalized (or uncollectible) statement paid: records a `manual` payment of the
    /// amount still due. Root administrators only; audited as `billing:statement-paid`.
    pub async fn mark_paid(
        &self,
        credential: &CredentialInput,
        input: Body<billing::MarkPaidInput>,
    ) -> IamResult<Reply<billing::MarkPaidOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/statements",
                true,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let statement = self
                        .account_statement(&tx, &realm, body.get("statementId"))
                        .await?;
                    let mut payment = Map::new();
                    if let Some(reference) = body.get("reference") {
                        payment.insert("reference".into(), reference.clone());
                    }
                    let result = self
                        .service
                        .record_payment(
                            &tx,
                            &statement,
                            &Value::Object(payment),
                            &principal.identity.id,
                        )
                        .await?;
                    let next: BillingStatement = decode_value(result.get("statement"))?;
                    let mut metadata = Map::new();
                    metadata.insert("number".into(), string(statement.number.clone()));
                    metadata.insert("totalMicros".into(), number(statement.total_micros));
                    if let Some(reference) = next
                        .payment_reference
                        .as_ref()
                        .filter(|reference| !reference.is_empty())
                    {
                        metadata.insert("reference".into(), string(reference.clone()));
                    }
                    self.audit(
                        &tx,
                        &principal,
                        "billing:statement-paid",
                        &statement.tenant_id,
                        &format!("billing/statements/{}", statement.id),
                        metadata,
                    )
                    .await?;
                    Ok(self.named_summary(&tx, &next).await?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/voidStatement`: voids a statement: its credits are restored and its period reopens for the account.
    /// Root administrators only; audited as `billing:statement-void`.
    pub async fn void_statement(
        &self,
        credential: &CredentialInput,
        input: Body<billing::VoidStatementInput>,
    ) -> IamResult<Reply<billing::VoidStatementOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/statements",
                true,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let statement = self
                        .account_statement(&tx, &realm, body.get("statementId"))
                        .await?;
                    let reason = trim(&text(body.get("reason"), "reason", 512)?);
                    let next = self
                        .service
                        .void_statement(&tx, &statement, &principal, &reason)
                        .await?;
                    let mut metadata = Map::new();
                    metadata.insert("number".into(), string(statement.number.clone()));
                    metadata.insert("reason".into(), string(reason));
                    metadata.insert(
                        "restoredCreditMicros".into(),
                        number(statement.credits_micros),
                    );
                    self.audit(
                        &tx,
                        &principal,
                        "billing:statement-void",
                        &statement.tenant_id,
                        &format!("billing/statements/{}", statement.id),
                        metadata,
                    )
                    .await?;
                    Ok(self.named_summary(&tx, &next).await?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Invoicing

    /// `billing/finalizeInvoice`: finalizes a draft invoice: it is recomputed with the latest usage and invoice items,
    /// numbered, and sent. Root administrators only; audited as `billing:statement-finalize`.
    pub async fn finalize_invoice(
        &self,
        credential: &CredentialInput,
        input: Body<billing::FinalizeInvoiceInput>,
    ) -> IamResult<Reply<billing::FinalizeInvoiceOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/statements",
                true,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let statement = self
                        .account_statement(&tx, &realm, body.get("statementId"))
                        .await?;
                    let result = self
                        .service
                        .finalize_draft(&tx, &statement, Some(&principal.identity.id))
                        .await?;
                    let next: BillingStatement = decode_value(result.get("statement"))?;
                    let mut metadata = Map::new();
                    metadata.insert("number".into(), string(next.number.clone()));
                    metadata.insert("period".into(), string(next.period.clone()));
                    metadata.insert("totalMicros".into(), number(next.total_micros));
                    metadata.insert(
                        "recipients".into(),
                        result.get("recipients").cloned().unwrap_or(Value::Null),
                    );
                    self.audit(
                        &tx,
                        &principal,
                        "billing:statement-finalize",
                        &statement.tenant_id,
                        &format!("billing/statements/{}", next.id),
                        metadata,
                    )
                    .await?;
                    Ok(self.named_summary(&tx, &next).await?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/recordPayment`: records a payment against a finalized or uncollectible invoice: `amount` (default the
    /// amount due), `method`, `reference`, and `receivedAt`. Root administrators only; audited as `billing:payment`.
    pub async fn record_payment(
        &self,
        credential: &CredentialInput,
        input: Body<billing::RecordPaymentInput>,
    ) -> IamResult<Reply<billing::RecordPaymentOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/statements",
                true,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let statement = self
                        .account_statement(&tx, &realm, body.get("statementId"))
                        .await?;
                    let result = self
                        .service
                        .record_payment(&tx, &statement, &body.value(), &principal.identity.id)
                        .await?;
                    let next: BillingStatement = decode_value(result.get("statement"))?;
                    let payment = result.get("payment").cloned().unwrap_or(Value::Null);
                    let mut metadata = Map::new();
                    metadata.insert("number".into(), string(next.number.clone()));
                    metadata.insert(
                        "amountMicros".into(),
                        payment.get("amountMicros").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert(
                        "method".into(),
                        payment.get("method").cloned().unwrap_or(Value::Null),
                    );
                    if truthy(payment.get("reference")) {
                        metadata.insert("reference".into(), payment["reference"].clone());
                    }
                    if truthy(payment.get("overpaymentMicros")) {
                        metadata.insert(
                            "overpaymentMicros".into(),
                            payment["overpaymentMicros"].clone(),
                        );
                    }
                    metadata.insert("status".into(), string(next.status.clone()));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:payment",
                        &statement.tenant_id,
                        &format!("billing/statements/{}", next.id),
                        metadata,
                    )
                    .await?;
                    Ok(json!({
                        "statement": self.named_summary(&tx, &next).await?,
                        "payment": payment,
                    }))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/markUncollectible`: writes a finalized invoice off as uncollectible (a later payment still settles
    /// it). Root administrators only; audited as `billing:statement-uncollectible`.
    pub async fn mark_uncollectible(
        &self,
        credential: &CredentialInput,
        input: Body<billing::MarkUncollectibleInput>,
    ) -> IamResult<Reply<billing::MarkUncollectibleOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/statements",
                true,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let statement = self
                        .account_statement(&tx, &realm, body.get("statementId"))
                        .await?;
                    let next = self.service.mark_uncollectible(&tx, &statement).await?;
                    let mut metadata = Map::new();
                    metadata.insert("number".into(), string(next.number.clone()));
                    metadata.insert("amountDueMicros".into(), number(amount_due(&next)?));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:statement-uncollectible",
                        &statement.tenant_id,
                        &format!("billing/statements/{}", next.id),
                        metadata,
                    )
                    .await?;
                    Ok(self.named_summary(&tx, &next).await?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/createCreditNote`: issues a credit note against an invoice for `amount` (default everything not yet
    /// credited) with a `reason` and `memo`. Root administrators only; audited as `billing:credit-note`.
    pub async fn create_credit_note(
        &self,
        credential: &CredentialInput,
        input: Body<billing::CreateCreditNoteInput>,
    ) -> IamResult<Reply<billing::CreateCreditNoteOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/statements",
                true,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let statement = self
                        .account_statement(&tx, &realm, body.get("statementId"))
                        .await?;
                    let result = self
                        .service
                        .create_credit_note(&tx, &statement, &body.value(), &principal.identity.id)
                        .await?;
                    let next: BillingStatement = decode_value(result.get("statement"))?;
                    let note: BillingCreditNote = decode_value(result.get("creditNote"))?;
                    let applied = |key: &str| note.applied.get(key).cloned().unwrap_or(Value::Null);
                    let mut metadata = Map::new();
                    metadata.insert("number".into(), string(note.number.clone()));
                    metadata.insert("statementNumber".into(), string(next.number.clone()));
                    metadata.insert("amountMicros".into(), number(note.amount_micros));
                    metadata.insert("reason".into(), note.reason.clone());
                    metadata.insert("dueMicros".into(), applied("dueMicros"));
                    metadata.insert("creditMicros".into(), applied("creditMicros"));
                    metadata.insert("refundMicros".into(), applied("refundMicros"));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:credit-note",
                        &statement.tenant_id,
                        &format!("billing/statements/{}", next.id),
                        metadata,
                    )
                    .await?;
                    Ok(json!({
                        "statement": self.named_summary(&tx, &next).await?,
                        "creditNote": credit_note_view(&note)?,
                    }))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/listCreditNotes`: credit notes of the billing accounts in the tenant's subtree, or of one
    /// `statementId`. Requires iam:billing:read.
    pub async fn list_credit_notes(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ListCreditNotesInput>,
    ) -> IamResult<Reply<billing::ListCreditNotesOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing/statements",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let raw_notes = match body.get("statementId") {
                        Some(statement_id) => {
                            let statement = self
                                .scoped_statement(&tx, &realm, Some(statement_id))
                                .await?;
                            find(
                                &tx,
                                CREDIT_NOTES,
                                Filter::new()
                                    .eq("tenantId", s(&statement, "tenantId"))
                                    .eq("statementId", s(&statement, "id")),
                            )
                            .await?
                        }
                        None => {
                            let covered = self.covered_accounts(&tx, &realm).await?;
                            find(&tx, CREDIT_NOTES, Filter::new())
                                .await?
                                .into_iter()
                                .filter(|note| {
                                    covered
                                        .as_ref()
                                        .is_none_or(|covered| covered.contains(s(note, "tenantId")))
                                })
                                .collect()
                        }
                    };
                    let mut notes = raw_notes
                        .into_iter()
                        .map(decode::<BillingCreditNote>)
                        .collect::<IamResult<Vec<_>>>()?;
                    notes.sort_by(|a, b| {
                        cmp_f64(b.issued_at, a.issued_at)
                            .then_with(|| cmp_str(&b.number, &a.number))
                    });
                    Ok(Value::Array(
                        notes
                            .iter()
                            .map(credit_note_view)
                            .collect::<IamResult<Vec<_>>>()?,
                    ))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/renderInvoice`: an invoice as a standalone HTML page to print or save as PDF. Requires
    /// iam:billing:read.
    pub async fn render_invoice(
        &self,
        credential: &CredentialInput,
        input: Body<billing::RenderInvoiceInput>,
    ) -> IamResult<Reply<billing::RenderInvoiceOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing/statements",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let raw = self
                        .scoped_statement(&tx, &realm, body.get("statementId"))
                        .await?;
                    let statement: BillingStatement = decode(raw)?;
                    let mut credit_notes = find(
                        &tx,
                        CREDIT_NOTES,
                        Filter::new()
                            .eq("tenantId", statement.tenant_id.clone())
                            .eq("statementId", statement.id.clone()),
                    )
                    .await?;
                    credit_notes.sort_by(|a, b| cmp_str(s(a, "number"), s(b, "number")));
                    let settings = self.settings()?;
                    let mut options = Map::new();
                    if let Some(issuer) = &settings.issuer {
                        options.insert("issuer".into(), to_json(issuer)?);
                    }
                    options.insert(
                        "creditNotes".into(),
                        Value::Array(credit_notes.into_iter().map(Value::Object).collect()),
                    );
                    let filename = if statement.number.is_empty() {
                        format!("draft-{}.html", statement.period)
                    } else {
                        format!("{}.html", statement.number)
                    };
                    Ok(json!({
                        "filename": filename,
                        "contentType": "text/html; charset=utf-8",
                        "body": render_invoice_html(&statement, Some(&Value::Object(options)))?,
                    }))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/listInvoiceItems`: pending (and invoiced) invoice items of the billing accounts in the tenant's
    /// subtree, newest first, optionally by `status`. Requires iam:billing:read.
    pub async fn list_invoice_items(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ListInvoiceItemsInput>,
    ) -> IamResult<Reply<billing::ListInvoiceItemsOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing/invoice-items",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let status = body.get("status");
                    if let Some(status) = status
                        && status.as_str() != Some("pending")
                        && status.as_str() != Some("invoiced")
                    {
                        return Err(invalid("status must be 'pending' or 'invoiced'").into());
                    }
                    let covered = self.covered_accounts(&tx, &realm).await?;
                    let mut filter = Filter::new();
                    if let Some(status) = status.filter(|status| truthy(Some(status))) {
                        filter = filter.eq("status", status.clone());
                    }
                    let mut items = find(&tx, INVOICE_ITEMS, filter)
                        .await?
                        .into_iter()
                        .filter(|item| {
                            covered
                                .as_ref()
                                .is_none_or(|covered| covered.contains(s(item, "tenantId")))
                        })
                        .map(decode::<BillingInvoiceItem>)
                        .collect::<IamResult<Vec<_>>>()?;
                    items.sort_by(|a, b| {
                        cmp_f64(b.created_at, a.created_at).then_with(|| cmp_str(&b.id, &a.id))
                    });
                    Ok(Value::Array(
                        items
                            .iter()
                            .map(invoice_item_view)
                            .collect::<IamResult<Vec<_>>>()?,
                    ))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/createInvoiceItem`: adds a one-off charge (or, with a negative `amount`, a credit) to the billing
    /// account's next invoice, or to the invoice for `period`. Root administrators only; audited as
    /// `billing:invoice-item`.
    pub async fn create_invoice_item(
        &self,
        credential: &CredentialInput,
        input: Body<billing::CreateInvoiceItemInput>,
    ) -> IamResult<Reply<billing::CreateInvoiceItemOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/invoice-items",
                true,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    writable(&realm)?;
                    let account = self.own_account(&tx, &realm).await?;
                    let fields = invoice_item_input(object(Some(&body.value()))?)?;
                    if let Some(period) = fields
                        .get("period")
                        .filter(|period| truthy(Some(period)))
                        .and_then(Value::as_str)
                    {
                        let invoiced = self.service.statement_for(&tx, &account.id, period).await?;
                        if invoiced.is_some_and(|invoiced| invoiced.status != "draft") {
                            return Err(IamError::with_status(
                                "BILLING_PERIOD_CLOSED",
                                format!(
                                    "{period} has already been invoiced; leave period out to bill the next invoice"
                                ),
                                409,
                            )
                            .into());
                        }
                    }
                    let mut record = Record::new();
                    record.insert("id".into(), string(id()));
                    record.insert("tenantId".into(), string(account.id.clone()));
                    spread(&mut record, &fields);
                    record.insert("status".into(), string("pending"));
                    record.insert("source".into(), string("manual"));
                    record.insert("createdAt".into(), number(self.ctx.now()));
                    record.insert("createdBy".into(), string(principal.identity.id.clone()));
                    let item: BillingInvoiceItem = decode(tx.insert(INVOICE_ITEMS, &record).await?)?;
                    let mut metadata = Map::new();
                    metadata.insert("description".into(), string(item.description.clone()));
                    metadata.insert("amountMicros".into(), number(item.amount_micros));
                    if let Some(period) = item.period.as_ref().filter(|period| !period.is_empty()) {
                        metadata.insert("period".into(), string(period.clone()));
                    }
                    self.audit(
                        &tx,
                        &principal,
                        "billing:invoice-item",
                        &realm.id,
                        &format!("billing/invoice-items/{}", item.id),
                        metadata,
                    )
                    .await?;
                    Ok(invoice_item_view(&item)?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/deleteInvoiceItem`: deletes a pending invoice item. Root administrators only; audited as
    /// `billing:invoice-item-delete`.
    pub async fn delete_invoice_item(
        &self,
        credential: &CredentialInput,
        input: Body<billing::DeleteInvoiceItemInput>,
    ) -> IamResult<Reply<billing::DeleteInvoiceItemOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/invoice-items",
                true,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let raw = self
                        .scoped_record(&tx, INVOICE_ITEMS, body.get("itemId"), "itemId", &realm.id)
                        .await?;
                    let item: BillingInvoiceItem = decode(raw)?;
                    if item.status != "pending" {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "The item is on a finalized invoice; issue a credit note instead",
                            409,
                        )
                        .into());
                    }
                    tx.delete(INVOICE_ITEMS, &item.id).await?;
                    let mut metadata = Map::new();
                    metadata.insert("description".into(), string(item.description.clone()));
                    metadata.insert("amountMicros".into(), number(item.amount_micros));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:invoice-item-delete",
                        &realm.id,
                        &format!("billing/invoice-items/{}", item.id),
                        metadata,
                    )
                    .await?;
                    Ok(json!({ "success": true }))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Plans and subscriptions

    /// `billing/listPlans`: the platform's plans. Other tenants see plans that are not archived; root administrators
    /// also see archived plans (`includeArchived`) and subscriber counts. Requires iam:billing:read.
    pub async fn list_plans(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ListPlansInput>,
    ) -> IamResult<Reply<billing::ListPlansOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing/plans",
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let root = self.root_of(&tx, &realm).await?;
                    let admin = realm.parent_id.is_none()
                        && self.ctx.root_principal(&tx, &principal).await?;
                    let mut plans = find(&tx, PLANS, Filter::new().eq("tenantId", root.id.clone()))
                        .await?
                        .into_iter()
                        .map(decode::<BillingPlan>)
                        .collect::<IamResult<Vec<_>>>()?;
                    let now = self.ctx.now();
                    let mut live: Vec<BillingSubscription> = Vec::new();
                    if admin {
                        for raw in find(&tx, SUBSCRIPTIONS, Filter::new()).await? {
                            let subscription: BillingSubscription = decode(raw)?;
                            if subscription_status(&subscription, now)? != "ended" {
                                live.push(subscription);
                            }
                        }
                    }
                    let include_archived = body.get("includeArchived") == Some(&Value::Bool(true));
                    plans.retain(|plan| !plan.archived || (admin && include_archived));
                    plans.sort_by(|a, b| locale_compare(&a.name, &b.name));
                    let views = plans
                        .iter()
                        .map(|plan| {
                            plan_view(
                                plan,
                                admin.then(|| {
                                    live.iter()
                                        .filter(|subscription| subscription.plan_id == plan.id)
                                        .count()
                                }),
                            )
                        })
                        .collect::<IamResult<Vec<_>>>()?;
                    Ok(Value::Array(views))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/createPlan`: defines a plan on the platform (root) tenant. Root administrators only; audited as
    /// `billing:plan`.
    pub async fn create_plan(
        &self,
        credential: &CredentialInput,
        input: Body<billing::CreatePlanInput>,
    ) -> IamResult<Reply<billing::CreatePlanOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/plans",
                true,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    on_root(&realm, "Plans")?;
                    let key = plan_key(body.get("key"))?;
                    let existing =
                        find(&tx, PLANS, Filter::new().eq("tenantId", realm.id.clone())).await?;
                    if existing.iter().any(|plan| s(plan, "key") == key) {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A plan with this key already exists",
                            409,
                        )
                        .into());
                    }
                    if existing.len() as f64 >= MAX_PLANS_PER_TENANT {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!("At most {} plans", number_text(MAX_PLANS_PER_TENANT)),
                            409,
                        )
                        .into());
                    }
                    let fields = plan_settings(object(Some(&body.value()))?, None)?;
                    let now = self.ctx.now();
                    let mut record = Record::new();
                    record.insert("id".into(), string(id()));
                    record.insert("tenantId".into(), string(realm.id.clone()));
                    record.insert("uniqueKey".into(), string(key.clone()));
                    record.insert("key".into(), string(key.clone()));
                    spread(&mut record, &fields);
                    record.insert("createdAt".into(), number(now));
                    record.insert("createdBy".into(), string(principal.identity.id.clone()));
                    record.insert("updatedAt".into(), number(now));
                    record.insert("updatedBy".into(), string(principal.identity.id.clone()));
                    let plan: BillingPlan = decode(tx.insert(PLANS, &record).await?)?;
                    let mut metadata = Map::new();
                    metadata.insert("key".into(), string(key.clone()));
                    metadata.insert("name".into(), string(plan.name.clone()));
                    metadata.insert("items".into(), number(plan.items.len() as f64));
                    metadata.insert("selfServe".into(), Value::Bool(plan.self_serve));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:plan",
                        &realm.id,
                        &format!("billing/plans/{}", plan.id),
                        metadata,
                    )
                    .await?;
                    Ok(plan_view(&plan, Some(0))?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/updatePlan`: changes a plan (by id or key). Changes apply to invoices drawn up afterwards. Root
    /// administrators only; audited as `billing:plan-update`.
    pub async fn update_plan(
        &self,
        credential: &CredentialInput,
        input: Body<billing::UpdatePlanInput>,
    ) -> IamResult<Reply<billing::UpdatePlanOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/plans",
                true,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    on_root(&realm, "Plans")?;
                    let mut raw = self.plan_by_ref(&tx, &realm, body.get("plan")).await?;
                    let plan: BillingPlan = decode(raw.clone())?;
                    let fields = plan_settings(object(Some(&body.value()))?, Some(&plan))?;
                    raw.shift_remove("description");
                    raw.shift_remove("trialDays");
                    spread(&mut raw, &fields);
                    raw.insert("updatedAt".into(), number(self.ctx.now()));
                    raw.insert("updatedBy".into(), string(principal.identity.id.clone()));
                    let next: BillingPlan = decode(tx.put(PLANS, &raw).await?)?;
                    let changed: Vec<Value> = body
                        .keys()
                        .filter(|key| key.as_str() != "tenantId" && key.as_str() != "plan")
                        .map(|key| string(key.clone()))
                        .collect();
                    let mut metadata = Map::new();
                    metadata.insert("key".into(), string(plan.key.clone()));
                    metadata.insert("fields".into(), Value::Array(changed));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:plan-update",
                        &realm.id,
                        &format!("billing/plans/{}", plan.id),
                        metadata,
                    )
                    .await?;
                    Ok(plan_view(&next, None)?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/listSubscriptions`: subscriptions of the billing accounts in the tenant's subtree (ended ones with
    /// `includeEnded`), newest first. Requires iam:billing:read.
    pub async fn list_subscriptions(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ListSubscriptionsInput>,
    ) -> IamResult<Reply<billing::ListSubscriptionsOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing/subscriptions",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let covered = self.covered_accounts(&tx, &realm).await?;
                    let now = self.ctx.now();
                    let include_ended = body.get("includeEnded") == Some(&Value::Bool(true));
                    let mut names: indexmap::IndexMap<String, Option<String>> =
                        indexmap::IndexMap::new();
                    let mut result: Vec<(f64, Value)> = Vec::new();
                    for raw in find(&tx, SUBSCRIPTIONS, Filter::new()).await? {
                        let subscription: BillingSubscription = decode(raw)?;
                        if covered
                            .as_ref()
                            .is_some_and(|covered| !covered.contains(&subscription.tenant_id))
                        {
                            continue;
                        }
                        if !include_ended && subscription_status(&subscription, now)? == "ended" {
                            continue;
                        }
                        if !names.contains_key(&subscription.tenant_id) {
                            let name = tx.get("tenants", &subscription.tenant_id).await?.and_then(
                                |tenant| {
                                    tenant
                                        .get("name")
                                        .and_then(Value::as_str)
                                        .map(str::to_owned)
                                },
                            );
                            names.insert(subscription.tenant_id.clone(), name);
                        }
                        let name = names.get(&subscription.tenant_id).cloned().flatten();
                        result.push((
                            subscription.started_at,
                            subscription_view(&subscription, now, name.as_deref())?,
                        ));
                    }
                    result.sort_by(|a, b| cmp_f64(b.0, a.0));
                    Ok(Value::Array(
                        result.into_iter().map(|entry| entry.1).collect(),
                    ))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/subscribe`: subscribes the billing account to a plan (id or key) with `seats` (default 1). Account
    /// billing managers may subscribe to self-serve plans; root administrators to any plan, and may set `trialDays`.
    /// Audited as `billing:subscription`.
    pub async fn subscribe(
        &self,
        credential: &CredentialInput,
        input: Body<billing::SubscribeInput>,
    ) -> IamResult<Reply<billing::SubscribeOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/subscriptions",
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    writable(&realm)?;
                    let account = self.own_account(&tx, &realm).await?;
                    let plan: BillingPlan =
                        decode(self.plan_by_ref(&tx, &realm, body.get("plan")).await?)?;
                    let admin = self.may_manage(&tx, &principal, &[&plan]).await?;
                    if body.get("trialDays").is_some() && !admin {
                        return Err(OperationDenied::new(Some(
                            "Only root administrators set trial days",
                        )));
                    }
                    let seats = match body.get("seats") {
                        None => 1.0,
                        Some(value) => integer(Some(value), "seats", 0.0, 1_000_000.0)?,
                    };
                    let trial_days = match body.get("trialDays") {
                        None => None,
                        Some(value) => Some(integer(Some(value), "trialDays", 0.0, 365.0)?),
                    };
                    let mut options = Map::new();
                    options.insert("seats".into(), number(seats));
                    if let Some(days) = trial_days {
                        options.insert("trialDays".into(), number(days));
                    }
                    let result = self
                        .service
                        .subscribe(
                            &tx,
                            &account,
                            &plan,
                            &Value::Object(options),
                            &principal.identity.id,
                        )
                        .await?;
                    let subscription: BillingSubscription =
                        decode_value(result.get("subscription"))?;
                    let invoice: Option<BillingStatement> = match result.get("invoice") {
                        Some(invoice) if truthy(Some(invoice)) => {
                            Some(decode_value(Some(invoice))?)
                        }
                        _ => None,
                    };
                    let mut metadata = Map::new();
                    metadata.insert("plan".into(), string(plan.key.clone()));
                    metadata.insert("seats".into(), number(seats));
                    if let Some(at) = subscription.trial_ends_at {
                        metadata.insert("trialEndsAt".into(), number(at));
                    }
                    if let Some(invoice) = &invoice {
                        metadata.insert("invoice".into(), string(invoice.number.clone()));
                        metadata.insert("totalMicros".into(), number(invoice.total_micros));
                    }
                    self.audit(
                        &tx,
                        &principal,
                        "billing:subscription",
                        &realm.id,
                        &format!("billing/subscriptions/{}", subscription.id),
                        metadata,
                    )
                    .await?;
                    let now = self.ctx.now();
                    let mut out = Map::new();
                    out.insert(
                        "subscription".into(),
                        subscription_view(&subscription, now, Some(&account.name))?,
                    );
                    if let Some(invoice) = &invoice {
                        out.insert(
                            "invoice".into(),
                            summary(invoice, now, Some(&account.name))?,
                        );
                    }
                    Ok(Value::Object(out))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// The `{ subscription, invoiceItems }` answer of the subscription changes.
    fn subscription_change(
        &self,
        subscription: &BillingSubscription,
        items: &[BillingInvoiceItem],
        account_name: &str,
    ) -> IamResult<Value> {
        Ok(json!({
            "subscription": subscription_view(subscription, self.ctx.now(), Some(account_name))?,
            "invoiceItems": items.iter().map(invoice_item_view).collect::<IamResult<Vec<_>>>()?,
        }))
    }

    /// `billing/updateSubscription`: changes a subscription's seats; seats already billed in advance for this month
    /// are prorated as invoice items on the next invoice. Audited as `billing:subscription-update`.
    pub async fn update_subscription(
        &self,
        credential: &CredentialInput,
        input: Body<billing::UpdateSubscriptionInput>,
    ) -> IamResult<Reply<billing::UpdateSubscriptionOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/subscriptions",
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let subscription: BillingSubscription = decode(
                        self.scoped_record(
                            &tx,
                            SUBSCRIPTIONS,
                            body.get("subscriptionId"),
                            "subscriptionId",
                            &realm.id,
                        )
                        .await?,
                    )?;
                    if let Some(raw) = tx.get(PLANS, &subscription.plan_id).await? {
                        let plan: BillingPlan = decode(raw)?;
                        self.may_manage(&tx, &principal, &[&plan]).await?;
                    }
                    let seats = integer(body.get("seats"), "seats", 0.0, 1_000_000.0)?;
                    let result = self
                        .service
                        .update_seats(&tx, &subscription, seats, &principal.identity.id)
                        .await?;
                    let next: BillingSubscription = decode_value(result.get("subscription"))?;
                    let items: Vec<BillingInvoiceItem> = match result.get("items") {
                        Some(items) => serde_json::from_value(items.clone()).map_err(|_| {
                            IamError::with_status(
                                "STORAGE_CORRUPT",
                                "A stored record is malformed",
                                500,
                            )
                        })?,
                        None => Vec::new(),
                    };
                    let mut metadata = Map::new();
                    metadata.insert("plan".into(), string(subscription.plan_key.clone()));
                    metadata.insert(
                        "seats".into(),
                        json!({ "before": number(subscription.seats), "after": number(seats) }),
                    );
                    metadata.insert("prorationMicros".into(), number(sum_amounts(&items)?));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:subscription-update",
                        &realm.id,
                        &format!("billing/subscriptions/{}", subscription.id),
                        metadata,
                    )
                    .await?;
                    Ok(self.subscription_change(&next, &items, &realm.name)?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/cancelSubscription`: cancels a subscription at the end of the month (default) or, with
    /// `atPeriodEnd: false`, now. Audited as `billing:subscription-cancel`.
    pub async fn cancel_subscription(
        &self,
        credential: &CredentialInput,
        input: Body<billing::CancelSubscriptionInput>,
    ) -> IamResult<Reply<billing::CancelSubscriptionOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/subscriptions",
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let subscription: BillingSubscription = decode(
                        self.scoped_record(
                            &tx,
                            SUBSCRIPTIONS,
                            body.get("subscriptionId"),
                            "subscriptionId",
                            &realm.id,
                        )
                        .await?,
                    )?;
                    let at_period_end = match body.get("atPeriodEnd") {
                        None => true,
                        Some(Value::Bool(flag)) => *flag,
                        Some(_) => return Err(invalid("atPeriodEnd must be a boolean").into()),
                    };
                    let admin = match tx.get(PLANS, &subscription.plan_id).await? {
                        Some(raw) => {
                            let plan: BillingPlan = decode(raw)?;
                            self.may_manage(&tx, &principal, &[&plan]).await?
                        }
                        None => self.ctx.root_principal(&tx, &principal).await?,
                    };
                    if !at_period_end && !admin {
                        return Err(OperationDenied::new(Some(
                            "Only root administrators cancel a subscription immediately",
                        )));
                    }
                    let result = self
                        .service
                        .cancel_subscription(
                            &tx,
                            &subscription,
                            at_period_end,
                            &principal.identity.id,
                        )
                        .await?;
                    let next: BillingSubscription = decode_value(result.get("subscription"))?;
                    let items: Vec<BillingInvoiceItem> = match result.get("items") {
                        Some(items) => serde_json::from_value(items.clone()).map_err(|_| {
                            IamError::with_status(
                                "STORAGE_CORRUPT",
                                "A stored record is malformed",
                                500,
                            )
                        })?,
                        None => Vec::new(),
                    };
                    let mut metadata = Map::new();
                    metadata.insert("plan".into(), string(subscription.plan_key.clone()));
                    metadata.insert("atPeriodEnd".into(), Value::Bool(at_period_end));
                    metadata.insert(
                        "endsAt".into(),
                        next.ends_at.map(number).unwrap_or(Value::Null),
                    );
                    metadata.insert("prorationMicros".into(), number(sum_amounts(&items)?));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:subscription-cancel",
                        &realm.id,
                        &format!("billing/subscriptions/{}", subscription.id),
                        metadata,
                    )
                    .await?;
                    Ok(self.subscription_change(&next, &items, &realm.name)?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/resumeSubscription`: undoes a cancellation at the end of the month before it takes effect. Audited
    /// as `billing:subscription-resume`.
    pub async fn resume_subscription(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ResumeSubscriptionInput>,
    ) -> IamResult<Reply<billing::ResumeSubscriptionOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/subscriptions",
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let subscription: BillingSubscription = decode(
                        self.scoped_record(
                            &tx,
                            SUBSCRIPTIONS,
                            body.get("subscriptionId"),
                            "subscriptionId",
                            &realm.id,
                        )
                        .await?,
                    )?;
                    if let Some(raw) = tx.get(PLANS, &subscription.plan_id).await? {
                        let plan: BillingPlan = decode(raw)?;
                        self.may_manage(&tx, &principal, &[&plan]).await?;
                    }
                    let next = self.service.resume_subscription(&tx, &subscription).await?;
                    let mut metadata = Map::new();
                    metadata.insert("plan".into(), string(subscription.plan_key.clone()));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:subscription-resume",
                        &realm.id,
                        &format!("billing/subscriptions/{}", subscription.id),
                        metadata,
                    )
                    .await?;
                    Ok(subscription_view(&next, self.ctx.now(), Some(&realm.name))?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/changePlan`: moves a subscription to another plan (id or key) now, keeping its seats and what is left
    /// of its trial. Audited as `billing:subscription-plan-change`.
    pub async fn change_plan(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ChangePlanInput>,
    ) -> IamResult<Reply<billing::ChangePlanOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/subscriptions",
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    writable(&realm)?;
                    let subscription: BillingSubscription = decode(
                        self.scoped_record(
                            &tx,
                            SUBSCRIPTIONS,
                            body.get("subscriptionId"),
                            "subscriptionId",
                            &realm.id,
                        )
                        .await?,
                    )?;
                    let current: Option<BillingPlan> =
                        match tx.get(PLANS, &subscription.plan_id).await? {
                            Some(raw) => Some(decode(raw)?),
                            None => None,
                        };
                    let plan: BillingPlan =
                        decode(self.plan_by_ref(&tx, &realm, body.get("plan")).await?)?;
                    match &current {
                        Some(current) => {
                            self.may_manage(&tx, &principal, &[current, &plan]).await?
                        }
                        None => self.may_manage(&tx, &principal, &[&plan]).await?,
                    };
                    let result = self
                        .service
                        .change_plan(&tx, &subscription, &plan, &principal.identity.id)
                        .await?;
                    let next: BillingSubscription = decode_value(result.get("subscription"))?;
                    let items: Vec<BillingInvoiceItem> = match result.get("items") {
                        Some(items) => serde_json::from_value(items.clone()).map_err(|_| {
                            IamError::with_status(
                                "STORAGE_CORRUPT",
                                "A stored record is malformed",
                                500,
                            )
                        })?,
                        None => Vec::new(),
                    };
                    let mut metadata = Map::new();
                    metadata.insert("from".into(), string(subscription.plan_key.clone()));
                    metadata.insert("to".into(), string(plan.key.clone()));
                    metadata.insert(
                        "previousSubscriptionId".into(),
                        string(subscription.id.clone()),
                    );
                    metadata.insert("prorationMicros".into(), number(sum_amounts(&items)?));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:subscription-plan-change",
                        &realm.id,
                        &format!("billing/subscriptions/{}", next.id),
                        metadata,
                    )
                    .await?;
                    Ok(self.subscription_change(&next, &items, &realm.name)?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Coupons and discounts

    /// `billing/listCoupons`: the platform's coupons, newest first. Called on the root tenant; root administrators
    /// only.
    pub async fn list_coupons(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ListCouponsInput>,
    ) -> IamResult<Reply<billing::ListCouponsOutput>> {
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing/coupons",
                true,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    on_root(&realm, "Coupons")?;
                    let now = self.ctx.now();
                    let mut coupons =
                        find(&tx, COUPONS, Filter::new().eq("tenantId", realm.id.clone()))
                            .await?
                            .into_iter()
                            .map(decode::<BillingCoupon>)
                            .collect::<IamResult<Vec<_>>>()?;
                    coupons.sort_by(|a, b| cmp_f64(b.created_at, a.created_at));
                    Ok(Value::Array(
                        coupons
                            .iter()
                            .map(|coupon| coupon_view(coupon, now))
                            .collect::<IamResult<Vec<_>>>()?,
                    ))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/createCoupon`: creates a coupon on the platform (root) tenant. Root administrators only; audited as
    /// `billing:coupon`.
    pub async fn create_coupon(
        &self,
        credential: &CredentialInput,
        input: Body<billing::CreateCouponInput>,
    ) -> IamResult<Reply<billing::CreateCouponOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/coupons",
                true,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    on_root(&realm, "Coupons")?;
                    let now = self.ctx.now();
                    let fields = coupon_settings(object(Some(&body.value()))?, now)?;
                    let code = fields
                        .get("code")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let unique_key = format!("code:{code}");
                    if !find(
                        &tx,
                        COUPONS,
                        Filter::new()
                            .eq("tenantId", realm.id.clone())
                            .eq("uniqueKey", unique_key.clone()),
                    )
                    .await?
                    .is_empty()
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A coupon with this code already exists",
                            409,
                        )
                        .into());
                    }
                    let mut record = Record::new();
                    record.insert("id".into(), string(id()));
                    record.insert("tenantId".into(), string(realm.id.clone()));
                    record.insert("uniqueKey".into(), string(unique_key));
                    spread(&mut record, &fields);
                    record.insert("redemptions".into(), number(0.0));
                    record.insert("active".into(), Value::Bool(true));
                    record.insert("createdAt".into(), number(now));
                    record.insert("createdBy".into(), string(principal.identity.id.clone()));
                    let coupon: BillingCoupon = decode(tx.insert(COUPONS, &record).await?)?;
                    let mut metadata = Map::new();
                    metadata.insert("code".into(), string(coupon.code.clone()));
                    if let Some(percent) = coupon.percent_off {
                        metadata.insert("percentOff".into(), number(percent));
                    }
                    if let Some(micros) = coupon.amount_off_micros {
                        metadata.insert("amountOffMicros".into(), number(micros));
                    }
                    metadata.insert("duration".into(), string(coupon.duration.clone()));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:coupon",
                        &realm.id,
                        &format!("billing/coupons/{}", coupon.id),
                        metadata,
                    )
                    .await?;
                    Ok(coupon_view(&coupon, now)?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/deactivateCoupon`: stops a coupon (by code) from being redeemed; accounts that redeemed it keep their
    /// discount. Root administrators only; audited as `billing:coupon-deactivate`.
    pub async fn deactivate_coupon(
        &self,
        credential: &CredentialInput,
        input: Body<billing::DeactivateCouponInput>,
    ) -> IamResult<Reply<billing::DeactivateCouponOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/coupons",
                true,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    on_root(&realm, "Coupons")?;
                    let code = coupon_code(body.get("code"))?;
                    let Some(mut raw) = find(
                        &tx,
                        COUPONS,
                        Filter::new()
                            .eq("tenantId", realm.id.clone())
                            .eq("uniqueKey", format!("code:{code}")),
                    )
                    .await?
                    .into_iter()
                    .next() else {
                        return Err(not_found("Coupon not found").into());
                    };
                    raw.insert("active".into(), Value::Bool(false));
                    let next: BillingCoupon = decode(tx.put(COUPONS, &raw).await?)?;
                    let mut metadata = Map::new();
                    metadata.insert("code".into(), string(code));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:coupon-deactivate",
                        &realm.id,
                        &format!("billing/coupons/{}", next.id),
                        metadata,
                    )
                    .await?;
                    Ok(coupon_view(&next, self.ctx.now())?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/redeemCoupon`: redeems a coupon code for the billing account: its discount applies to the account's
    /// invoices for the coupon's duration, after the contract discount. Once per coupon per account. Audited as
    /// `billing:coupon-redeem`.
    pub async fn redeem_coupon(
        &self,
        credential: &CredentialInput,
        input: Body<billing::RedeemCouponInput>,
    ) -> IamResult<Reply<billing::RedeemCouponOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/discounts",
                false,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    writable(&realm)?;
                    let account = self.own_account(&tx, &realm).await?;
                    let code = coupon_code(body.get("code"))?;
                    let root = self.root_of(&tx, &realm).await?;
                    let now = self.ctx.now();
                    let raw = find(
                        &tx,
                        COUPONS,
                        Filter::new()
                            .eq("tenantId", root.id.clone())
                            .eq("uniqueKey", format!("code:{code}")),
                    )
                    .await?
                    .into_iter()
                    .next();
                    let coupon: Option<BillingCoupon> = match &raw {
                        Some(raw) => Some(decode(raw.clone())?),
                        None => None,
                    };
                    if let Some(coupon) = &coupon
                        && !find(
                            &tx,
                            DISCOUNTS,
                            Filter::new()
                                .eq("tenantId", account.id.clone())
                                .eq("uniqueKey", format!("coupon:{}", coupon.id)),
                        )
                        .await?
                        .is_empty()
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "The account has already redeemed this code",
                            409,
                        )
                        .into());
                    }
                    // Unknown, inactive, expired and used-up codes look the same to the account.
                    let (Some(coupon), Some(mut raw)) = (coupon, raw) else {
                        return Err(not_found("This code is not valid").into());
                    };
                    if !coupon_active(&coupon, now) {
                        return Err(not_found("This code is not valid").into());
                    }
                    raw.insert("redemptions".into(), number(coupon.redemptions + 1.0));
                    tx.put(COUPONS, &raw).await?;
                    let mut record = Record::new();
                    record.insert("id".into(), string(id()));
                    record.insert("tenantId".into(), string(account.id.clone()));
                    record.insert("uniqueKey".into(), string(format!("coupon:{}", coupon.id)));
                    record.insert("couponId".into(), string(coupon.id.clone()));
                    record.insert("code".into(), string(coupon.code.clone()));
                    record.insert("name".into(), string(coupon.name.clone()));
                    if let Some(percent) = coupon.percent_off {
                        record.insert("percentOff".into(), number(percent));
                    }
                    if let Some(micros) = coupon.amount_off_micros {
                        record.insert("amountOffMicros".into(), number(micros));
                    }
                    record.insert("duration".into(), string(coupon.duration.clone()));
                    if let Some(months) = coupon.duration_in_months {
                        record.insert("durationInMonths".into(), number(months));
                    }
                    record.insert("appliedInvoices".into(), number(0.0));
                    record.insert("redeemedAt".into(), number(now));
                    record.insert("redeemedBy".into(), string(principal.identity.id.clone()));
                    let discount: BillingDiscount = decode(tx.insert(DISCOUNTS, &record).await?)?;
                    let mut metadata = Map::new();
                    metadata.insert("code".into(), string(code));
                    metadata.insert("couponId".into(), string(coupon.id.clone()));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:coupon-redeem",
                        &realm.id,
                        &format!("billing/discounts/{}", discount.id),
                        metadata,
                    )
                    .await?;
                    let settings = self.settings()?;
                    Ok(discount_view(
                        &discount,
                        &self.current_period()?,
                        &settings.time_zone,
                    )?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/listDiscounts`: discounts (redeemed coupons) of the billing accounts in the tenant's subtree.
    /// Requires iam:billing:read.
    pub async fn list_discounts(
        &self,
        credential: &CredentialInput,
        input: Body<billing::ListDiscountsInput>,
    ) -> IamResult<Reply<billing::ListDiscountsOutput>> {
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:read",
                "billing/discounts",
                false,
                |MutationContext {
                     tx, tenant: realm, ..
                 }| async move {
                    let covered = self.covered_accounts(&tx, &realm).await?;
                    let period = self.current_period()?;
                    let settings = self.settings()?;
                    let mut discounts = find(&tx, DISCOUNTS, Filter::new())
                        .await?
                        .into_iter()
                        .filter(|discount| {
                            covered
                                .as_ref()
                                .is_none_or(|covered| covered.contains(s(discount, "tenantId")))
                        })
                        .map(decode::<BillingDiscount>)
                        .collect::<IamResult<Vec<_>>>()?;
                    discounts.sort_by(|a, b| cmp_f64(b.redeemed_at, a.redeemed_at));
                    Ok(Value::Array(
                        discounts
                            .iter()
                            .map(|discount| discount_view(discount, &period, &settings.time_zone))
                            .collect::<IamResult<Vec<_>>>()?,
                    ))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `billing/removeDiscount`: ends a discount of the billing account now. Root administrators only; audited as
    /// `billing:discount-remove`.
    pub async fn remove_discount(
        &self,
        credential: &CredentialInput,
        input: Body<billing::RemoveDiscountInput>,
    ) -> IamResult<Reply<billing::RemoveDiscountOutput>> {
        let body = &input;
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:billing:manage",
                "billing/discounts",
                true,
                |MutationContext {
                     tx,
                     principal,
                     tenant: realm,
                 }| async move {
                    let mut raw = self
                        .scoped_record(
                            &tx,
                            DISCOUNTS,
                            body.get("discountId"),
                            "discountId",
                            &realm.id,
                        )
                        .await?;
                    let discount: BillingDiscount = decode(raw.clone())?;
                    if discount.ended_at.is_some() {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "The discount has already ended",
                            409,
                        )
                        .into());
                    }
                    raw.insert("endedAt".into(), number(self.ctx.now()));
                    let next: BillingDiscount = decode(tx.put(DISCOUNTS, &raw).await?)?;
                    let mut metadata = Map::new();
                    metadata.insert("code".into(), string(discount.code.clone()));
                    self.audit(
                        &tx,
                        &principal,
                        "billing:discount-remove",
                        &realm.id,
                        &format!("billing/discounts/{}", discount.id),
                        metadata,
                    )
                    .await?;
                    let settings = self.settings()?;
                    Ok(discount_view(
                        &next,
                        &self.current_period()?,
                        &settings.time_zone,
                    )?)
                },
            )
            .await?;
        Ok(Reply::json(result))
    }
}

// -------------------------------------------------------------------------------------------------------------------
// iam.billing

/// `iam.billing`: trusted metering, checks, reports and the scheduler jobs.
pub struct BillingRuntime {
    ctx: Arc<ServerContext>,
    service: Arc<BillingService>,
}

/// `createBillingRuntime(ctx)`.
pub fn create_billing_runtime(ctx: &Arc<ServerContext>) -> IamResult<BillingRuntime> {
    Ok(BillingRuntime {
        ctx: ctx.clone(),
        service: billing_service_of(ctx)?,
    })
}

impl BillingRuntime {
    fn billing_settings(&self) -> IamResult<BillingSettings> {
        let options = crate::options_value::options_value(&self.ctx.options);
        billing_settings(options.get("billing"))
    }

    /// The deployment's billing settings (currency, time zone, ...).
    pub fn settings(&self) -> IamResult<Value> {
        to_json(&self.billing_settings()?)
    }

    /// Records usage without a credential and without an audit event (the hot path for metering).
    pub async fn record(&self, input: &Value) -> IamResult<UsageReceipt> {
        let extra = if input.get("enforceBudgets") == Some(&Value::Bool(true)) {
            json!({ "enforceBudgets": true })
        } else {
            json!({})
        };
        let extra = &extra;
        self.ctx
            .store
            .transaction(move |tx| async move {
                self.service
                    .record(&tx, input, "deployment", Some(extra))
                    .await
            })
            .await
    }

    /// Records up to 1000 events in one transaction. `events` is the value given (`!Array.isArray(events)` is refused
    /// like an empty list).
    pub async fn record_many(&self, events: &Value) -> IamResult<Vec<UsageReceipt>> {
        let Some(events) = events
            .as_array()
            .filter(|events| !events.is_empty() && events.len() <= 1000)
        else {
            return Err(invalid("events must list 1-1000 usage events"));
        };
        self.ctx
            .store
            .transaction(move |tx| async move {
                let mut receipts = Vec::with_capacity(events.len());
                for event in events {
                    receipts.push(self.service.record(&tx, event, "deployment", None).await?);
                }
                Ok(receipts)
            })
            .await
    }

    /// Whether usage by `identityId` in the tenant is within every enforced budget that covers it.
    pub async fn check(&self, input: &Value) -> IamResult<SpendCheck> {
        let ctx = &self.ctx;
        ctx.store
            .transaction(move |tx| async move {
                let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
                let tenant = ctx.tenant(&tx, &tenant_id).await?;
                let mut query = Map::new();
                if let Some(identity_id) = input.get("identityId") {
                    query.insert("identityId".into(), identity_id.clone());
                }
                if let Some(meter) = input.get("meter") {
                    query.insert("meter".into(), meter.clone());
                }
                self.service
                    .check(&tx, &tenant, &Value::Object(query))
                    .await
            })
            .await
    }

    /// A spend report for a tenant's subtree.
    pub async fn spend(&self, input: &Value) -> IamResult<SpendReport> {
        let ctx = &self.ctx;
        let query = match input {
            Value::Object(map) => Value::Object(without(map, &["tenantId"])),
            _ => json!({}),
        };
        let query = &query;
        ctx.store
            .transaction(move |tx| async move {
                let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
                let tenant = ctx.tenant(&tx, &tenant_id).await?;
                self.service.report(&tx, &tenant, query, None, None).await
            })
            .await
    }

    /// Daily seat recording (scheduler job).
    pub async fn record_seats(&self, input: Option<&Value>) -> IamResult<Value> {
        self.service.record_seats(input).await
    }

    /// Budget threshold and forecast alerts (scheduler job).
    pub async fn check_budgets(&self, input: Option<&Value>) -> IamResult<Value> {
        self.service.check_budgets(input).await
    }

    /// Issues statements for the previous (or a given past) period and sweeps old usage events (scheduler job).
    pub async fn close_period(&self, input: Option<&Value>) -> IamResult<ClosePeriodResult> {
        self.service.close_period(input).await
    }

    /// Spend-spike alerts for every billing account for yesterday (scheduler job, daily).
    pub async fn detect_anomalies(&self, input: Option<&Value>) -> IamResult<Value> {
        self.service.detect_anomalies(input).await
    }

    /// Payment reminders for unpaid invoices at `billing.paymentReminderDays` (scheduler job, daily).
    pub async fn send_payment_reminders(&self) -> IamResult<Value> {
        self.service.send_payment_reminders().await
    }

    /// Records a payment from a payment processor (a Stripe webhook, a bank feed) against an invoice by id or number.
    /// `idempotencyKey` (the processor's payment id) makes redelivery safe: a known key returns the invoice unchanged.
    pub async fn record_payment(&self, input: &Value) -> IamResult<Value> {
        let ctx = &self.ctx;
        ctx.store
            .transaction(move |tx| async move {
                let raw = if let Some(statement_id) = input.get("statementId") {
                    tx.get(STATEMENTS, &text(Some(statement_id), "statementId", 256)?)
                        .await?
                } else if let Some(number) = input.get("number") {
                    find(
                        &tx,
                        STATEMENTS,
                        Filter::new().eq("number", text(Some(number), "number", 64)?),
                    )
                    .await?
                    .into_iter()
                    .next()
                } else {
                    return Err(invalid("Give statementId or number"));
                };
                let Some(raw) = raw else {
                    return Err(not_found("Statement not found"));
                };
                let key = match input.get("idempotencyKey") {
                    None => None,
                    Some(value) => Some(text(Some(value), "idempotencyKey", 128)?),
                };
                let statement: BillingStatement = decode(raw.clone())?;
                // The processor's payment id doubles as the payment reference.
                if let Some(key) = &key
                    && statement.payments.as_ref().is_some_and(|payments| {
                        payments
                            .iter()
                            .any(|payment| payment.reference.as_deref() == Some(key.as_str()))
                    })
                {
                    return Ok(json!({ "statement": raw, "duplicate": true }));
                }
                let mut payment = match input {
                    Value::Object(map) => {
                        without(map, &["idempotencyKey", "statementId", "number"])
                    }
                    _ => Map::new(),
                };
                if let Some(key) = &key {
                    payment.insert("reference".into(), string(key.clone()));
                }
                let result = self
                    .service
                    .record_payment(&tx, &statement, &Value::Object(payment), "deployment")
                    .await?;
                let paid = result.get("payment").cloned().unwrap_or(Value::Null);
                let mut metadata = Map::new();
                metadata.insert("number".into(), string(statement.number.clone()));
                metadata.insert(
                    "amountMicros".into(),
                    paid.get("amountMicros").cloned().unwrap_or(Value::Null),
                );
                metadata.insert(
                    "method".into(),
                    paid.get("method").cloned().unwrap_or(Value::Null),
                );
                if truthy(paid.get("reference")) {
                    metadata.insert("reference".into(), paid["reference"].clone());
                }
                metadata.insert(
                    "status".into(),
                    result
                        .get("statement")
                        .and_then(|statement| statement.get("status"))
                        .cloned()
                        .unwrap_or(Value::Null),
                );
                let mut event = Record::new();
                event.insert("id".into(), string(id()));
                event.insert("tenantId".into(), string(statement.tenant_id.clone()));
                event.insert("actorId".into(), string("deployment-operator"));
                event.insert("action".into(), string("billing:payment"));
                event.insert(
                    "resourceId".into(),
                    string(format!("billing/statements/{}", statement.id)),
                );
                event.insert("timestamp".into(), number(ctx.now()));
                event.insert("outcome".into(), string("allow"));
                event.insert("metadata".into(), Value::Object(metadata));
                ctx.events()?.record_audit(&tx, &event).await?;
                let mut out = match result {
                    Value::Object(map) => map,
                    _ => Map::new(),
                };
                out.insert("duplicate".into(), Value::Bool(false));
                Ok(Value::Object(out))
            })
            .await
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        let first = args.first().cloned().unwrap_or(Value::Null);
        let optional = args.first();
        Some(match method {
            "settings" => self.settings(),
            "record" => match self.record(&first).await {
                Ok(receipt) => to_json(&receipt),
                Err(error) => Err(error),
            },
            "recordMany" => match self.record_many(&first).await {
                Ok(receipts) => to_json(&receipts),
                Err(error) => Err(error),
            },
            "check" => match self.check(&first).await {
                Ok(check) => to_json(&check),
                Err(error) => Err(error),
            },
            "spend" => match self.spend(&first).await {
                Ok(report) => to_json(&report),
                Err(error) => Err(error),
            },
            "recordSeats" => self.record_seats(optional).await,
            "checkBudgets" => self.check_budgets(optional).await,
            "closePeriod" => match self.close_period(optional).await {
                Ok(result) => to_json(&result),
                Err(error) => Err(error),
            },
            "detectAnomalies" => self.detect_anomalies(optional).await,
            "sendPaymentReminders" => self.send_payment_reminders().await,
            "recordPayment" => self.record_payment(&first).await,
            _ => return None,
        })
    }
}

// -------------------------------------------------------------------------------------------------------------------
// Interim declarations of the BillingService members this module calls.
//
// `billing-service.ts` is ported by its own unit; the skeleton of `billing_service.rs` declares only the members other
// modules called when it was generated (`hooks`, `spendContext`, `recordPriced`). These are the members of
// `createBillingService(ctx)` that `api/billing.ts` uses, with their TypeScript parameters, answering NOT_IMPLEMENTED
// until that unit lands. When it does, delete this block (its real methods take these names) and adjust call sites
// to the final signatures.

/// `rowFilter` of `report` and `trend`.
pub type RowFilter<'a> = &'a (dyn Fn(&ChargedRow) -> bool + Send + Sync);

impl BillingService {
    /// `record(tx, input, recordedBy, extra = {})`: records one usage event and returns its receipt.
    pub async fn record(
        &self,
        _tx: &Store,
        _input: &Value,
        _recorded_by: &str,
        _extra: Option<&Value>,
    ) -> IamResult<UsageReceipt> {
        Err(not_ported("billing-service.ts record"))
    }

    /// `report(tx, scope, query, cache?, rowFilter?)`: a spend report for a tenant's subtree.
    pub async fn report(
        &self,
        _tx: &Store,
        _scope: &Tenant,
        _query: &Value,
        _cache: Option<&SpendCache>,
        _row_filter: Option<RowFilter<'_>>,
    ) -> IamResult<SpendReport> {
        Err(not_ported("billing-service.ts report"))
    }

    /// `trend(tx, scope, input, rowFilter?)`: monthly totals.
    pub async fn trend(
        &self,
        _tx: &Store,
        _scope: &Tenant,
        _input: &Value,
        _row_filter: Option<RowFilter<'_>>,
    ) -> IamResult<SpendTrend> {
        Err(not_ported("billing-service.ts trend"))
    }

    /// `check(tx, tenant, { identityId?, meter? })`.
    pub async fn check(
        &self,
        _tx: &Store,
        _tenant: &Tenant,
        _input: &Value,
    ) -> IamResult<SpendCheck> {
        Err(not_ported("billing-service.ts check"))
    }

    /// `budgetStatus(tx, budget, cache?)`.
    pub async fn budget_status(
        &self,
        _tx: &Store,
        _budget: &BillingBudget,
        _cache: Option<&SpendCache>,
    ) -> IamResult<BudgetStatus> {
        Err(not_ported("billing-service.ts budgetStatus"))
    }

    /// `checkBudgets(input = {})` (scheduler job).
    pub async fn check_budgets(&self, _input: Option<&Value>) -> IamResult<Value> {
        Err(not_ported("billing-service.ts checkBudgets"))
    }

    /// `draftStatement(tx, account, period, cache?, first?)`.
    pub async fn draft_statement(
        &self,
        _tx: &Store,
        _account: &Tenant,
        _period: &str,
        _cache: Option<&SpendCache>,
        _first: Option<&Value>,
    ) -> IamResult<StatementDraft> {
        Err(not_ported("billing-service.ts draftStatement"))
    }

    /// `statementFor(tx, accountId, period)`: the account's live statement for a period.
    pub async fn statement_for(
        &self,
        _tx: &Store,
        _account_id: &str,
        _period: &str,
    ) -> IamResult<Option<BillingStatement>> {
        Err(not_ported("billing-service.ts statementFor"))
    }

    /// `closePeriod(input = {})`.
    pub async fn close_period(&self, _input: Option<&Value>) -> IamResult<ClosePeriodResult> {
        Err(not_ported("billing-service.ts closePeriod"))
    }

    /// `finalizeDraft(tx, statement, actorId?)`: `{ statement, recipients }`.
    pub async fn finalize_draft(
        &self,
        _tx: &Store,
        _statement: &BillingStatement,
        _actor_id: Option<&str>,
    ) -> IamResult<Value> {
        Err(not_ported("billing-service.ts finalizeDraft"))
    }

    /// `voidStatement(tx, statement, principal, reason)`.
    pub async fn void_statement(
        &self,
        _tx: &Store,
        _statement: &BillingStatement,
        _principal: &AuthenticatedPrincipal,
        _reason: &str,
    ) -> IamResult<BillingStatement> {
        Err(not_ported("billing-service.ts voidStatement"))
    }

    /// `recordPayment(tx, statement, input, actorId)`: `{ statement, payment }`.
    pub async fn record_payment(
        &self,
        _tx: &Store,
        _statement: &BillingStatement,
        _input: &Value,
        _actor_id: &str,
    ) -> IamResult<Value> {
        Err(not_ported("billing-service.ts recordPayment"))
    }

    /// `markUncollectible(tx, statement)`.
    pub async fn mark_uncollectible(
        &self,
        _tx: &Store,
        _statement: &BillingStatement,
    ) -> IamResult<BillingStatement> {
        Err(not_ported("billing-service.ts markUncollectible"))
    }

    /// `createCreditNote(tx, statement, input, actorId)`: `{ statement, creditNote }`.
    pub async fn create_credit_note(
        &self,
        _tx: &Store,
        _statement: &BillingStatement,
        _input: &Value,
        _actor_id: &str,
    ) -> IamResult<Value> {
        Err(not_ported("billing-service.ts createCreditNote"))
    }

    /// `sendPaymentReminders()` (scheduler job).
    pub async fn send_payment_reminders(&self) -> IamResult<Value> {
        Err(not_ported("billing-service.ts sendPaymentReminders"))
    }

    /// `subscribe(tx, account, plan, { seats, trialDays? }, actorId)`: `{ subscription, invoice? }`.
    pub async fn subscribe(
        &self,
        _tx: &Store,
        _account: &Tenant,
        _plan: &BillingPlan,
        _input: &Value,
        _actor_id: &str,
    ) -> IamResult<Value> {
        Err(not_ported("billing-service.ts subscribe"))
    }

    /// `updateSeats(tx, subscription, seats, actorId)`: `{ subscription, items }`.
    pub async fn update_seats(
        &self,
        _tx: &Store,
        _subscription: &BillingSubscription,
        _seats: f64,
        _actor_id: &str,
    ) -> IamResult<Value> {
        Err(not_ported("billing-service.ts updateSeats"))
    }

    /// `cancelSubscription(tx, subscription, atPeriodEnd, actorId)`: `{ subscription, items }`.
    pub async fn cancel_subscription(
        &self,
        _tx: &Store,
        _subscription: &BillingSubscription,
        _at_period_end: bool,
        _actor_id: &str,
    ) -> IamResult<Value> {
        Err(not_ported("billing-service.ts cancelSubscription"))
    }

    /// `resumeSubscription(tx, subscription)`.
    pub async fn resume_subscription(
        &self,
        _tx: &Store,
        _subscription: &BillingSubscription,
    ) -> IamResult<BillingSubscription> {
        Err(not_ported("billing-service.ts resumeSubscription"))
    }

    /// `changePlan(tx, subscription, plan, actorId)`: `{ subscription, items }`.
    pub async fn change_plan(
        &self,
        _tx: &Store,
        _subscription: &BillingSubscription,
        _plan: &BillingPlan,
        _actor_id: &str,
    ) -> IamResult<Value> {
        Err(not_ported("billing-service.ts changePlan"))
    }

    /// `recordSeats(input = {})` (scheduler job).
    pub async fn record_seats(&self, _input: Option<&Value>) -> IamResult<Value> {
        Err(not_ported("billing-service.ts recordSeats"))
    }

    /// `ownIdentities(tx, identity)`: the person and the agents they sponsor.
    pub async fn own_identities(
        &self,
        _tx: &Store,
        _identity: &better_iam_core::Identity,
    ) -> IamResult<IndexSet<String>> {
        Err(not_ported("billing-service.ts ownIdentities"))
    }

    /// `anomalies(tx, scope, input = {})`.
    pub async fn anomalies(
        &self,
        _tx: &Store,
        _scope: &Tenant,
        _input: &Value,
    ) -> IamResult<Vec<SpendAnomaly>> {
        Err(not_ported("billing-service.ts anomalies"))
    }

    /// `detectAnomalies(input = {})` (scheduler job).
    pub async fn detect_anomalies(&self, _input: Option<&Value>) -> IamResult<Value> {
        Err(not_ported("billing-service.ts detectAnomalies"))
    }

    /// `spendCsv(report)`.
    pub fn spend_csv(&self, _report: &SpendReport) -> IamResult<String> {
        Err(not_ported("billing-service.ts spendCsv"))
    }

    /// `statementCsv(statement)`.
    pub fn statement_csv(&self, _statement: &BillingStatement) -> IamResult<String> {
        Err(not_ported("billing-service.ts statementCsv"))
    }
}

#[cfg(test)]
mod tests {
    use super::js_sort;

    #[test]
    fn js_sort_matches_v8_for_an_inconsistent_comparator() {
        // `(a, b) => (a.period < b.period ? 1 : -1)`: V8 reverses a run of equal periods.
        let mut items = vec![("2026-01", 1), ("2026-01", 2), ("2026-01", 3)];
        js_sort(&mut items, |a, b| if a.0 < b.0 { 1.0 } else { -1.0 });
        assert_eq!(items, vec![("2026-01", 3), ("2026-01", 2), ("2026-01", 1)]);
        let mut items = vec![
            ("2026-01", 1),
            ("2026-03", 2),
            ("2026-01", 3),
            ("2026-02", 4),
        ];
        js_sort(&mut items, |a, b| if a.0 < b.0 { 1.0 } else { -1.0 });
        assert_eq!(
            items.iter().map(|item| item.0).collect::<Vec<_>>(),
            vec!["2026-03", "2026-02", "2026-01", "2026-01"]
        );
    }

    #[test]
    fn js_sort_sorts_long_inputs() {
        let mut items: Vec<i64> = (0..300).map(|value| (value * 7919) % 301).collect();
        js_sort(&mut items, |a, b| (*a - *b) as f64);
        let mut sorted = items.clone();
        sorted.sort();
        assert_eq!(items, sorted);
    }
}
