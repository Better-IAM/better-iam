//! Port of `packages/server/src/billing-plans.ts`.
//!
//! Plans and subscriptions: what an account pays every month besides usage. A plan holds recurring fees, per-seat
//! fees and its own prices for meters; a subscription ties a billing account to a plan with a start, an optional
//! trial, a seat count and an end. Fee and seat items are billed in advance (on the invoice closing the month before,
//! or on a first invoice when the subscription starts) or in arrears (on the month's own invoice), prorated to the
//! part of the month the subscription was live and out of its trial. Seat changes and cancellations of
//! advance-billed items create proration invoice items for the next invoice, as Stripe does.

use better_iam_core::{Filter, FindOptions, IamResult, js as core_js};
use indexmap::IndexSet;
use serde_json::{Map, Value, json};

use crate::billing::{
    BillingInvoiceItem, BillingPlan, BillingSubscription, PeriodBounds, PlanItem, amount_micros,
    bounds_of, by_start, cents, js_max, js_min, meter_key, overlap, period_of, price_spec, shift,
};
use crate::context::Store;
use crate::js::{invalid_input, number};
use crate::port::decode;
use crate::utils::id;
use crate::validation::{integer, object, text};

/// `/^[a-z0-9][a-z0-9_-]{0,63}$/`.
fn is_item_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

pub const MAX_PLANS_PER_TENANT: f64 = 100.0;

/// A plan key: 1-64 lowercase letters, digits, `.`, `_` or `-`, starting with a letter.
pub fn plan_key(value: Option<&Value>) -> IamResult<String> {
    match value {
        Some(Value::String(text)) if crate::billing::is_key(text) => Ok(text.clone()),
        _ => Err(invalid_input(
            "plan must be 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter",
        )),
    }
}

/// Validates plan items given in currency units (`amount`, `unitAmount`, a usage item's `price`).
pub fn plan_items(value: Option<&Value>) -> IamResult<Vec<Value>> {
    let items = match value {
        Some(Value::Array(items)) if !items.is_empty() && items.len() <= 20 => items,
        _ => return Err(invalid_input("items must list 1-20 plan items")),
    };
    let mut ids: IndexSet<String> = IndexSet::new();
    let mut meters: IndexSet<String> = IndexSet::new();
    let mut result = Vec::new();
    for raw in items {
        let input = object(Some(raw))?;
        let item_id = match input.get("id") {
            Some(Value::String(item_id)) if is_item_id(item_id) => item_id.clone(),
            _ => {
                return Err(invalid_input(
                    "Each item needs an id of 1-64 lowercase letters, digits, - or _",
                ));
            }
        };
        if ids.contains(&item_id) {
            return Err(invalid_input(format!("Duplicate item id {item_id}")));
        }
        ids.insert(item_id.clone());
        let name_value = crate::js::defined(input.get("name"))
            .cloned()
            .unwrap_or_else(|| Value::String(item_id.clone()));
        let name = core_js::trim(&text(Some(&name_value), "items.name", 128)?).to_owned();
        let billing = crate::js::defined(input.get("billing"))
            .cloned()
            .unwrap_or_else(|| json!("advance"));
        let billing = match billing.as_str() {
            Some(value @ ("advance" | "arrears")) => value.to_owned(),
            _ => {
                return Err(invalid_input(
                    "items.billing must be 'advance' or 'arrears'",
                ));
            }
        };
        let mut item = Map::new();
        item.insert("id".into(), Value::String(item_id));
        match input.get("kind").and_then(Value::as_str) {
            Some("fee") => {
                item.insert("kind".into(), json!("fee"));
                item.insert("name".into(), Value::String(name));
                item.insert(
                    "amountMicros".into(),
                    number(amount_micros(input.get("amount"), "items.amount")?),
                );
                item.insert("billing".into(), Value::String(billing));
            }
            Some("seat") => {
                item.insert("kind".into(), json!("seat"));
                item.insert("name".into(), Value::String(name));
                item.insert(
                    "unitAmountMicros".into(),
                    number(amount_micros(input.get("unitAmount"), "items.unitAmount")?),
                );
                item.insert("billing".into(), Value::String(billing));
                let included = input.get("includedSeats");
                if included.is_some() && included.and_then(core_js::as_number) != Some(0.0) {
                    item.insert(
                        "includedSeats".into(),
                        number(integer(included, "items.includedSeats", 0.0, 1_000_000.0)?),
                    );
                }
            }
            Some("usage") => {
                let meter = meter_key(input.get("meter"))?;
                if meters.contains(&meter) {
                    return Err(invalid_input(format!("Two items price {meter}")));
                }
                meters.insert(meter.clone());
                item.insert("kind".into(), json!("usage"));
                item.insert("name".into(), Value::String(name));
                item.insert("meter".into(), Value::String(meter));
                item.insert("price".into(), price_spec(input.get("price"))?);
            }
            _ => {
                return Err(invalid_input("items.kind must be 'fee', 'seat' or 'usage'"));
            }
        }
        result.push(Value::Object(item));
    }
    Ok(result)
}

/// Validated plan settings; `current` supplies values an update leaves out.
pub fn plan_settings(
    input: &Map<String, Value>,
    current: Option<&crate::billing::BillingPlan>,
) -> IamResult<Value> {
    let name = match input.get("name") {
        None => current.map(|plan| plan.name.clone()),
        value => Some(core_js::trim(&text(value, "name", 128)?).to_owned()),
    };
    let name = match name {
        Some(name) if !name.is_empty() => name,
        _ => return Err(invalid_input("name is required")),
    };
    let items = match input.get("items") {
        None => current.map(|plan| {
            plan.items
                .iter()
                .map(|item| Value::Object(crate::port::encode(item)))
                .collect::<Vec<_>>()
        }),
        value => Some(plan_items(value)?),
    };
    let Some(items) = items else {
        return Err(invalid_input("items are required"));
    };
    let flag = |value: Option<&Value>, fallback: bool, field: &str| -> IamResult<bool> {
        match value {
            None => Ok(fallback),
            Some(Value::Bool(value)) => Ok(*value),
            Some(_) => Err(invalid_input(format!("{field} must be a boolean"))),
        }
    };
    let description = match input.get("description") {
        Some(Value::Null) => None,
        None => current.and_then(|plan| plan.description.clone()),
        value => Some(core_js::trim(&text(value, "description", 512)?).to_owned()),
    };
    let trial_days = match input.get("trialDays") {
        Some(Value::Null) => None,
        None => current.and_then(|plan| plan.trial_days),
        value => Some(integer(value, "trialDays", 1.0, 365.0)?),
    };
    let self_serve = flag(
        input.get("selfServe"),
        current.is_some_and(|plan| plan.self_serve),
        "selfServe",
    )?;
    let archived = flag(
        input.get("archived"),
        current.is_some_and(|plan| plan.archived),
        "archived",
    )?;
    let mut settings = Map::new();
    settings.insert("name".into(), Value::String(name));
    settings.insert("items".into(), Value::Array(items));
    settings.insert("selfServe".into(), Value::Bool(self_serve));
    settings.insert("archived".into(), Value::Bool(archived));
    if let Some(description) = description {
        settings.insert("description".into(), Value::String(description));
    }
    if let Some(trial_days) = trial_days {
        settings.insert("trialDays".into(), number(trial_days));
    }
    Ok(Value::Object(settings))
}

/// `[from, to)`: the part of a month a subscription is billable in.
#[derive(Debug, Clone, Copy)]
struct Window {
    from: f64,
    to: f64,
}

/// The part of `[start, end)` a subscription is billable in: live and past its trial.
fn billable_window(subscription: &BillingSubscription, start: f64, end: f64) -> Option<Window> {
    let from = js_max(
        js_max(start, subscription.started_at),
        subscription.trial_ends_at.unwrap_or(0.0),
    );
    let to = js_min(end, subscription.ends_at.unwrap_or(f64::INFINITY));
    (to > from).then_some(Window { from, to })
}

/// `{ at, seats }` of a seat history entry.
fn seat_entry(entry: &Value) -> (f64, f64) {
    let read = |key: &str| entry.get(key).map(core_js::to_number).unwrap_or(f64::NAN);
    (read("at"), read("seats"))
}

/// Chargeable seats (above the included ones) from the subscription's seat history, weighted by time in `[from, to)`.
fn seat_months(
    subscription: &BillingSubscription,
    item: &PlanItem,
    period: PeriodBounds,
    window: Window,
) -> f64 {
    let history: Vec<(f64, f64)> = if subscription.seat_history.is_empty() {
        vec![(subscription.started_at, subscription.seats)]
    } else {
        subscription.seat_history.iter().map(seat_entry).collect()
    };
    let mut total = 0.0;
    for (index, (at, seats)) in history.iter().enumerate() {
        let next = history
            .get(index + 1)
            .map(|(at, _)| *at)
            .unwrap_or(f64::INFINITY);
        let chargeable = js_max(0.0, seats - item.included_seats.unwrap_or(0.0));
        if chargeable == 0.0 || chargeable.is_nan() {
            continue;
        }
        let from = js_max(window.from, *at);
        let to = js_min(window.to, next);
        if to > from {
            total += chargeable * overlap(period.start, period.end, from, to);
        }
    }
    crate::billing::js_round(total * 10_000.0) / 10_000.0
}

/// One fee or seat line for a subscription item over a month and the part of it that is billable.
fn item_line(
    subscription: &BillingSubscription,
    item: &PlanItem,
    period: PeriodBounds,
    window: Window,
) -> Option<Value> {
    let share = overlap(period.start, period.end, window.from, window.to);
    if share <= 0.0 {
        return None;
    }
    let service_period = json!({ "start": number(period.start), "end": number(period.end) });
    let description = format!("{}: {}", subscription.plan_name, item.name);
    let mut line = Map::new();
    if item.kind == "fee" {
        let amount = item.amount_micros.unwrap_or(f64::NAN);
        line.insert("kind".into(), json!("fee"));
        line.insert("name".into(), json!(item.name));
        line.insert("unit".into(), json!("month"));
        line.insert("quantity".into(), json!(1));
        line.insert("unitAmountMicros".into(), number(amount));
        line.insert("amountMicros".into(), number(cents(amount * share)));
        line.insert("subscriptionId".into(), json!(subscription.id));
        line.insert("planItemId".into(), json!(item.id));
        line.insert("servicePeriod".into(), service_period);
        if share < 1.0 {
            line.insert("proration".into(), number(share));
        }
        line.insert("description".into(), json!(description));
        return Some(Value::Object(line));
    }
    let seats = seat_months(subscription, item, period, window);
    if seats <= 0.0 {
        return None;
    }
    // Seats are shown as seat-months, so the proration is already in the quantity.
    let unit_amount = item.unit_amount_micros.unwrap_or(f64::NAN);
    line.insert("kind".into(), json!("seat"));
    line.insert("name".into(), json!(item.name));
    line.insert("unit".into(), json!("seat-month"));
    line.insert("quantity".into(), number(seats));
    line.insert("unitAmountMicros".into(), number(unit_amount));
    line.insert("amountMicros".into(), number(cents(unit_amount * seats)));
    line.insert("subscriptionId".into(), json!(subscription.id));
    line.insert("planItemId".into(), json!(item.id));
    line.insert("servicePeriod".into(), service_period);
    line.insert("description".into(), json!(description));
    Some(Value::Object(line))
}

/// `item.kind !== 'usage' && item.billing !== 'arrears'`: billed at the start of the month.
fn advance_item(item: &PlanItem) -> bool {
    item.kind != "usage" && item.billing.as_deref() != Some("arrears")
}

/// The fee and seat lines an account's invoice for `period` carries: arrears items for `period` itself, advance
/// items for the month after it, and advance items of `period` that no invoice has billed yet (a trial that ended
/// within the month, a voided subscription invoice). `advance` lists the subscription months the invoice pays for
/// in advance, which are marked billed when it is finalized.
pub async fn subscription_lines(
    tx: &Store,
    account_id: &str,
    period: &str,
    time_zone: &str,
) -> IamResult<Value> {
    let mut lines: Vec<Value> = Vec::new();
    let mut advance: Vec<Value> = Vec::new();
    let here = bounds_of(period, time_zone)?;
    let mut subscriptions: Vec<BillingSubscription> = tx
        .find(
            crate::billing::SUBSCRIPTIONS,
            &Filter::new().eq("tenantId", account_id),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .map(decode)
        .collect::<IamResult<_>>()?;
    subscriptions.sort_by(by_start);
    for subscription in &subscriptions {
        let Some(plan) = tx
            .get(crate::billing::PLANS, &subscription.plan_id)
            .await?
            .map(decode::<BillingPlan>)
            .transpose()?
        else {
            continue;
        };
        if let Some(arrears) = billable_window(subscription, here.start, here.end) {
            for item in &plan.items {
                if item.kind != "usage" && item.billing.as_deref() == Some("arrears") {
                    lines.extend(item_line(subscription, item, here, arrears));
                }
            }
        }
        if !plan.items.iter().any(advance_item) {
            continue;
        }
        for target in [period.to_owned(), shift(period, 1.0)] {
            if subscription.billed_advance.contains(&target) {
                continue;
            }
            let bounds = bounds_of(&target, time_zone)?;
            // Only months the subscription runs in.
            if subscription.started_at >= bounds.end {
                continue;
            }
            if subscription
                .ends_at
                .is_some_and(|ends_at| ends_at <= bounds.start)
            {
                continue;
            }
            if let Some(window) = billable_window(subscription, bounds.start, bounds.end) {
                for item in plan.items.iter().filter(|item| advance_item(item)) {
                    lines.extend(item_line(subscription, item, bounds, window));
                }
            }
            // A month with nothing to bill in advance (a trial) still counts as handled.
            advance.push(json!({ "subscriptionId": subscription.id, "period": target }));
        }
    }
    Ok(json!({ "lines": lines, "advance": advance }))
}

/// The advance lines of a new subscription's first month (from its start, or its trial end, to the month's end).
pub fn first_period_lines(
    subscription: &crate::billing::BillingSubscription,
    plan: &crate::billing::BillingPlan,
    time_zone: &str,
) -> IamResult<Value> {
    let period = period_of(subscription.started_at, time_zone)?;
    let bounds = bounds_of(&period, time_zone)?;
    let mut lines: Vec<Value> = Vec::new();
    if let Some(window) = billable_window(subscription, bounds.start, bounds.end) {
        for item in plan.items.iter().filter(|item| advance_item(item)) {
            lines.extend(item_line(subscription, item, bounds, window));
        }
    }
    Ok(json!({ "period": period, "lines": lines }))
}

/// `${count} seat${count === 1 ? '' : 's'}`.
fn seats_text(count: f64) -> String {
    format!(
        "{} seat{}",
        core_js::number_to_string(count),
        if count == 1.0 { "" } else { "s" }
    )
}

/// Proration invoice items for a change at `at` to advance-billed items of the current month (already paid for): a
/// credit for what the old state no longer uses and a charge for what the new one adds, as Stripe prorates.
///
/// `input` is `{ subscription, plan, at, timeZone, seats?: { before, after }, ending, createdBy }`.
pub fn proration_items(input: &Value) -> IamResult<Vec<crate::billing::BillingInvoiceItem>> {
    let record = |key: &str| match input.get(key) {
        Some(Value::Object(map)) => Ok(map.clone()),
        _ => Err(crate::js::internal_error()),
    };
    let subscription: BillingSubscription = decode(record("subscription")?)?;
    let plan: BillingPlan = decode(record("plan")?)?;
    let at = input.get("at").map(core_js::to_number).unwrap_or(f64::NAN);
    let time_zone = crate::js::js_string(input.get("timeZone"));
    let seats = crate::js::defined(input.get("seats")).map(|seats| {
        let read = |key: &str| crate::js::defined(seats.get(key)).map(core_js::to_number);
        (read("before"), read("after"))
    });
    let ending = crate::js::truthy(input.get("ending"));
    let created_by = crate::js::js_string(input.get("createdBy"));
    let period = period_of(at, &time_zone)?;
    if !subscription.billed_advance.contains(&period) {
        return Ok(Vec::new());
    }
    let bounds = bounds_of(&period, &time_zone)?;
    // Only the part of the month after the change and outside the trial was paid for and changes.
    let from = js_max(at, subscription.trial_ends_at.unwrap_or(0.0));
    let share = overlap(bounds.start, bounds.end, from, bounds.end);
    if share <= 0.0 {
        return Ok(Vec::new());
    }
    let mut items = Vec::new();
    let make = |description: String, amount: f64| BillingInvoiceItem {
        id: id(),
        tenant_id: subscription.tenant_id.clone(),
        unique_key: None,
        description,
        quantity: 1.0,
        unit_amount_micros: amount,
        amount_micros: amount,
        period: Some(period.clone()),
        status: "pending".to_owned(),
        statement_id: None,
        source: "proration".to_owned(),
        subscription_id: Some(subscription.id.clone()),
        metadata: None,
        created_at: at,
        created_by: created_by.clone(),
        extra: Map::new(),
    };
    for item in &plan.items {
        if item.kind == "usage" || item.billing.as_deref() == Some("arrears") {
            continue;
        }
        if item.kind == "fee" && ending {
            let amount = cents(-item.amount_micros.unwrap_or(f64::NAN) * share);
            if amount != 0.0 && !amount.is_nan() {
                items.push(make(
                    format!("Unused time on {}: {}", plan.name, item.name),
                    amount,
                ));
            }
        }
        if item.kind == "seat" {
            let included = item.included_seats.unwrap_or(0.0);
            let before_seats = seats
                .and_then(|(before, _)| before)
                .unwrap_or(subscription.seats);
            let before = js_max(0.0, before_seats - included);
            let after = if ending {
                0.0
            } else {
                let after_seats = seats
                    .and_then(|(_, after)| after)
                    .unwrap_or(subscription.seats);
                js_max(0.0, after_seats - included)
            };
            if before == after {
                continue;
            }
            let amount =
                cents((after - before) * item.unit_amount_micros.unwrap_or(f64::NAN) * share);
            items.push(make(
                if after > before {
                    format!(
                        "{} added seat{} on {} for the rest of the month",
                        core_js::number_to_string(after - before),
                        if after - before == 1.0 { "" } else { "s" },
                        plan.name
                    )
                } else {
                    format!(
                        "Unused time on {} of {}",
                        seats_text(before - after),
                        plan.name
                    )
                },
                amount,
            ));
        }
    }
    Ok(items)
}
