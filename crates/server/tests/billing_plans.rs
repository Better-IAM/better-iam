//! Port of the tests of `billing-plans.ts`: the plan, subscription and proration behavior of
//! tests/billing-invoicing.test.ts ("bills fees, seats and plan prices, prorates seat changes, and bills the next month
//! in advance", "starts trials free of charge ... and bills the rest of the month after") at the level of the module
//! functions (the billing API group and service belong to other port units, so plans and subscriptions are written
//! as the service stores them), with reference vectors computed by the TypeScript implementation
//! (tests/fixtures/billing.json).

mod org_fixture;

use std::sync::LazyLock;

use better_iam_core::{IamStoreExt, js as core_js};
use better_iam_server::billing::{
    self, BillingPlan, BillingSubscription, bounds_of, period_of, shift_period,
};
use better_iam_server::billing_plans::{
    MAX_PLANS_PER_TENANT, first_period_lines, plan_items, plan_key, plan_settings, proration_items,
    subscription_lines,
};
use better_iam_server::port::{decode, encode};
use better_iam_server::utils::id;
use org_fixture::{DAY, Org, run};
use serde_json::{Value, json};

static VECTORS: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("fixtures/billing.json")).expect("billing vectors")
});

fn same(actual: &Value, expected: &Value) {
    assert_eq!(core_js::stringify(actual), core_js::stringify(expected));
}

fn message<T: std::fmt::Debug>(result: Result<T, better_iam_core::IamError>) -> String {
    result.expect_err("expected an error").message
}

fn record<T: serde::de::DeserializeOwned>(value: &Value) -> T {
    decode(value.as_object().unwrap().clone()).unwrap()
}

#[test]
fn first_period_lines_and_prorations_match_typescript() {
    let plans = &VECTORS["plans"];
    let plan: BillingPlan = record(&plans["plan"]);
    let fresh: BillingSubscription = record(&plans["fresh"]);
    same(
        &first_period_lines(&fresh, &plan, "UTC").unwrap(),
        &plans["first"],
    );
    for case in plans["prorations"].as_array().unwrap() {
        let items: Vec<Value> = proration_items(&case["input"])
            .unwrap()
            .iter()
            .map(|item| {
                let mut map = encode(item);
                assert!(!map.shift_remove("id").unwrap().as_str().unwrap().is_empty());
                Value::Object(map)
            })
            .collect();
        same(&Value::Array(items), &case["items"]);
    }
}

#[test]
fn validates_plans_like_typescript() {
    let input = VECTORS["planSettings"]["input"].as_object().unwrap();
    same(
        &plan_settings(input, None).unwrap(),
        &VECTORS["planSettings"]["output"],
    );
    assert_eq!(MAX_PLANS_PER_TENANT, 100.0);
    assert_eq!(plan_key(Some(&json!("pro.2026"))).unwrap(), "pro.2026");
    assert_eq!(
        message(plan_key(Some(&json!("Pro")))),
        "plan must be 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter"
    );
    for (items, expected) in [
        (json!([]), "items must list 1-20 plan items"),
        (
            json!([{ "id": "Base", "kind": "fee", "amount": 1 }]),
            "Each item needs an id of 1-64 lowercase letters, digits, - or _",
        ),
        (
            json!([{ "id": "a", "kind": "fee", "amount": 1 }, { "id": "a", "kind": "fee", "amount": 1 }]),
            "Duplicate item id a",
        ),
        (
            json!([{ "id": "a", "kind": "fee", "amount": 1, "billing": "later" }]),
            "items.billing must be 'advance' or 'arrears'",
        ),
        (
            json!([{ "id": "a", "kind": "tip" }]),
            "items.kind must be 'fee', 'seat' or 'usage'",
        ),
        (
            json!([{ "id": "a", "kind": "fee" }]),
            "items.amount must be an amount from 0 to 1000000000",
        ),
        (
            json!([{ "id": "a", "kind": "seat", "unitAmount": 1, "includedSeats": 1.5 }]),
            "Invalid items.includedSeats",
        ),
        (
            json!([
                { "id": "a", "kind": "usage", "meter": "calls", "price": { "model": "per-unit", "unitAmount": 1 } },
                { "id": "b", "kind": "usage", "meter": "calls", "price": { "model": "per-unit", "unitAmount": 2 } },
            ]),
            "Two items price calls",
        ),
        (
            json!([{ "id": "a", "kind": "usage", "meter": "calls" }]),
            "Expected an object",
        ),
        (
            json!([{ "id": "a", "name": "", "kind": "fee", "amount": 1 }]),
            "Invalid items.name",
        ),
    ] {
        assert_eq!(message(plan_items(Some(&items))), expected, "{items}");
    }
    // An update keeps what it leaves out; null clears the description and the trial.
    let current: BillingPlan = record(&json!({
        "id": "p", "tenantId": "root", "uniqueKey": "pro", "key": "pro", "name": "Pro", "description": "Old",
        "items": [{ "id": "seats", "kind": "seat", "name": "Seats", "unitAmountMicros": 10_000_000, "billing": "advance", "includedSeats": 2 }],
        "trialDays": 14, "selfServe": true, "archived": false, "createdAt": 0, "createdBy": "x", "updatedAt": 0, "updatedBy": "x",
    }));
    same(
        &plan_settings(
            json!({ "description": null, "trialDays": null, "archived": true })
                .as_object()
                .unwrap(),
            Some(&current),
        )
        .unwrap(),
        &json!({
            "name": "Pro",
            "items": [{ "id": "seats", "kind": "seat", "name": "Seats", "unitAmountMicros": 10_000_000, "billing": "advance", "includedSeats": 2 }],
            "selfServe": true,
            "archived": true,
        }),
    );
    assert_eq!(
        message(plan_settings(&serde_json::Map::new(), None)),
        "name is required"
    );
    assert_eq!(
        message(plan_settings(
            json!({ "name": "X" }).as_object().unwrap(),
            None
        )),
        "items are required"
    );
    // Validation order: the description before the flags.
    assert_eq!(
        message(plan_settings(
            json!({ "description": 5, "selfServe": "yes" })
                .as_object()
                .unwrap(),
            Some(&current)
        )),
        "Invalid description"
    );
    assert_eq!(
        message(plan_settings(
            json!({ "selfServe": "yes" }).as_object().unwrap(),
            Some(&current)
        )),
        "selfServe must be a boolean"
    );
    assert_eq!(
        message(plan_settings(
            json!({ "trialDays": 0 }).as_object().unwrap(),
            Some(&current)
        )),
        "Invalid trialDays"
    );
}

/// A plan with an advance fee, advance seats (2 included) and an arrears support fee, as `billing.createPlan`
/// stores it.
async fn plan(org: &Org) -> String {
    let plan_id = id();
    org.insert(
        billing::PLANS,
        json!({
            "id": plan_id, "tenantId": org.root_tenant_id, "uniqueKey": "pro", "key": "pro", "name": "Pro",
            "items": [
                { "id": "base", "kind": "fee", "name": "Base", "amountMicros": 49_000_000, "billing": "advance" },
                { "id": "seats", "kind": "seat", "name": "Seats", "unitAmountMicros": 10_000_000, "billing": "advance", "includedSeats": 2 },
                { "id": "support", "kind": "fee", "name": "Support", "amountMicros": 5_000_000, "billing": "arrears" },
                { "id": "calls", "kind": "usage", "name": "Calls", "meter": "api-calls",
                  "price": { "model": "per-unit", "unitAmountMicros": 1000 } },
            ],
            "selfServe": false, "archived": false, "createdAt": 0, "createdBy": "x", "updatedAt": 0, "updatedBy": "x",
        }),
    )
    .await;
    plan_id
}

async fn subscribe(org: &Org, plan_id: &str, started_at: f64, extra: Value) -> String {
    let subscription_id = id();
    let mut subscription = json!({
        "id": subscription_id, "tenantId": org.tenant_id, "uniqueKey": format!("plan:{plan_id}"), "planId": plan_id,
        "planKey": "pro", "planName": "Pro", "startedAt": started_at, "cancelAtPeriodEnd": false, "seats": 5,
        "seatHistory": [{ "at": started_at, "seats": 5 }], "billedAdvance": [], "createdAt": started_at,
        "createdBy": "x", "updatedAt": started_at,
    });
    for (key, value) in extra.as_object().unwrap() {
        subscription[key] = value.clone();
    }
    org.insert(billing::SUBSCRIPTIONS, subscription).await;
    subscription_id
}

async fn lines(org: &Org, period: &str) -> Value {
    let tenant_id = org.tenant_id.clone();
    let period = period.to_owned();
    org.iam
        .store
        .transaction(|tx| async move { subscription_lines(&tx, &tenant_id, &period, "UTC").await })
        .await
        .unwrap()
}

#[test]
fn bills_fees_seats_in_advance_and_arrears_and_skips_months_already_billed() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let current = period_of(org.now(), "UTC").unwrap();
        let next = shift_period(&current, 1.0).unwrap();
        let bounds = bounds_of(&current, "UTC").unwrap();
        let following = bounds_of(&next, "UTC").unwrap();
        let plan_id = plan(&org).await;
        // Subscribed on the 10th, with the first month billed on its own invoice already.
        let started = bounds.start + 9.0 * DAY;
        let subscription_id = subscribe(
            &org,
            &plan_id,
            started,
            json!({ "billedAdvance": [current] }),
        )
        .await;
        let result = lines(&org, &current).await;
        let share =
            ((bounds.end - started) / (bounds.end - bounds.start) * 10_000.0).round() / 10_000.0;
        let cents = |micros: f64| (micros / 10_000.0).round() * 10_000.0;
        // Support in arrears for this month (prorated), then the next month's fee and seats in advance.
        let lines = result["lines"].as_array().unwrap();
        assert_eq!(
            lines
                .iter()
                .map(|line| line["planItemId"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["support", "base", "seats"]
        );
        assert_eq!(
            lines[0]["amountMicros"].as_f64().unwrap(),
            cents(5_000_000.0 * share)
        );
        assert_eq!(lines[0]["proration"].as_f64().unwrap(), share);
        assert_eq!(
            lines[0]["servicePeriod"]["start"].as_f64().unwrap(),
            bounds.start
        );
        same(
            &lines[1],
            &json!({
                "kind": "fee", "name": "Base", "unit": "month", "quantity": 1, "unitAmountMicros": 49_000_000,
                "amountMicros": 49_000_000, "subscriptionId": subscription_id, "planItemId": "base",
                "servicePeriod": { "start": following.start, "end": following.end }, "description": "Pro: Base",
            }),
        );
        // Five seats, two included: three seat-months.
        assert_eq!(lines[2]["quantity"].as_f64().unwrap(), 3.0);
        assert_eq!(lines[2]["amountMicros"].as_f64().unwrap(), 30_000_000.0);
        assert_eq!(lines[2]["unit"], json!("seat-month"));
        assert!(lines[2].get("proration").is_none());
        same(
            &result["advance"],
            &json!([{ "subscriptionId": subscription_id, "period": next }]),
        );
    });
}

#[test]
fn starts_trials_free_of_charge_and_bills_the_rest_of_the_month_after() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let current = period_of(org.now(), "UTC").unwrap();
        let next = shift_period(&current, 1.0).unwrap();
        let bounds = bounds_of(&current, "UTC").unwrap();
        let following = bounds_of(&next, "UTC").unwrap();
        let plan_id = plan(&org).await;
        // A trial running past the end of this month into the 5th of the next.
        let started = bounds.start + DAY;
        let trial_ends = following.start + 4.0 * DAY;
        let subscription_id = subscribe(
            &org,
            &plan_id,
            started,
            json!({ "trialEndsAt": trial_ends }),
        )
        .await;
        let subscription: BillingSubscription = decode(
            org.get(billing::SUBSCRIPTIONS, &subscription_id)
                .await
                .unwrap(),
        )
        .unwrap();
        let plan: BillingPlan = decode(org.get(billing::PLANS, &plan_id).await.unwrap()).unwrap();
        // Nothing to bill on the first invoice: the whole month is in the trial.
        same(
            &first_period_lines(&subscription, &plan, "UTC").unwrap(),
            &json!({ "period": current, "lines": [] }),
        );
        let result = lines(&org, &current).await;
        // This month's trial bills nothing but counts as handled; the next month bills from the trial end.
        let share = ((following.end - trial_ends) / (following.end - following.start) * 10_000.0)
            .round()
            / 10_000.0;
        let lines_now = result["lines"].as_array().unwrap();
        assert_eq!(
            lines_now
                .iter()
                .map(|line| line["planItemId"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["base", "seats"]
        );
        assert_eq!(lines_now[0]["proration"].as_f64().unwrap(), share);
        assert_eq!(
            lines_now[1]["quantity"].as_f64().unwrap(),
            ((3.0 * share) * 10_000.0_f64).round() / 10_000.0
        );
        same(
            &result["advance"],
            &json!([
                { "subscriptionId": subscription_id, "period": current },
                { "subscriptionId": subscription_id, "period": next },
            ]),
        );
        // A subscription that ended before a month bills nothing in advance for it.
        let ended = subscribe(
            &org,
            &plan_id,
            started,
            json!({ "uniqueKey": "ended", "endsAt": bounds.start + 2.0 * DAY, "billedAdvance": [current] }),
        )
        .await;
        let after = lines(&org, &current).await;
        assert!(
            after["advance"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["subscriptionId"] != json!(ended))
        );
        // Prorations only touch months already billed in advance.
        let input = json!({
            "subscription": org.get(billing::SUBSCRIPTIONS, &subscription_id).await.unwrap(),
            "plan": org.get(billing::PLANS, &plan_id).await.unwrap(),
            "at": bounds.start + 15.0 * DAY,
            "timeZone": "UTC",
            "seats": { "before": 5, "after": 7 },
            "ending": false,
            "createdBy": "me",
        });
        assert!(proration_items(&input).unwrap().is_empty());
        let mut billed = input.clone();
        billed["subscription"]["billedAdvance"] = json!([current]);
        billed["subscription"]["trialEndsAt"] = json!(bounds.start + 2.0 * DAY);
        let items = proration_items(&billed).unwrap();
        assert_eq!(items.len(), 1);
        let rest = ((bounds.end - (bounds.start + 15.0 * DAY)) / (bounds.end - bounds.start)
            * 10_000.0)
            .round()
            / 10_000.0;
        assert_eq!(
            items[0].amount_micros,
            ((2.0 * 10_000_000.0 * rest) / 10_000.0).round() * 10_000.0
        );
        assert_eq!(
            items[0].description,
            "2 added seats on Pro for the rest of the month"
        );
        assert_eq!(
            (
                items[0].status.as_str(),
                items[0].source.as_str(),
                items[0].period.as_deref()
            ),
            ("pending", "proration", Some(current.as_str()))
        );
        assert_eq!(
            items[0].subscription_id.as_deref(),
            Some(subscription_id.as_str())
        );
        assert_eq!(
            encode(&items[0]).keys().collect::<Vec<_>>(),
            vec![
                "id",
                "tenantId",
                "description",
                "quantity",
                "unitAmountMicros",
                "amountMicros",
                "period",
                "status",
                "source",
                "subscriptionId",
                "createdAt",
                "createdBy",
            ]
        );
        let store = org.iam.store.clone();
        let _ = store.get(billing::PLANS, &plan_id).await.unwrap();
    });
}
