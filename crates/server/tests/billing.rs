//! Port of the tests of `billing.ts`: the pricing tests of tests/billing.test.ts ("prices per unit, graduated and
//! volume tiers, packages and included units") and tests/billing-invoicing.test.ts ("breaks tiered prices into
//! sub-lines and applies a price minimum and maximum"), the spend allocation, account, attribution and contract-term
//! scenarios of tests/billing.test.ts and tests/security-billing.test.ts at the level of the module functions (the
//! billing API group and service belong to other port units, so meters, prices, roll-ups, profiles, plans and
//! subscriptions are written as the service stores them), and reference vectors computed by the TypeScript
//! implementation (tests/fixtures/billing.json, from tests/fixtures/generate-billing.mjs).

mod org_fixture;
mod teams_fixture;

use std::sync::LazyLock;

use better_iam_core::{IamStoreExt, Tenant, js as core_js};
use better_iam_server::billing::{
    self, AccountSpend, BillingDiscount, BillingMeter, BillingSettings, BillingTerms,
    InvoiceAmountsInput, SpendCache, account_of, account_spend_of, account_tenants,
    account_terms_of, amount_micros, attribution_for, billing_period, billing_settings,
    budget_thresholds, day_of, directory_for, discount_active, in_department, invoice_amounts,
    invoice_amounts_of, meter_key, meter_settings, meters_for, overlap_share, period_bounds,
    period_of, price_breakdown, price_quantity, price_spec, public_price_spec, resolve_meter,
    rollup_id, scope_spend_of, shift_period, statement_hash, subscription_status, team_share,
    usage_expiry, usage_tags, window_periods,
};
use better_iam_server::port::decode;
use better_iam_server::utils::id;
use org_fixture::{DAY, Org, run};
use serde_json::{Value, json};
use teams_fixture::{add_team_member, create_department, create_team, place};

static VECTORS: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("fixtures/billing.json")).expect("billing vectors")
});

/// JSON equality as `JSON.stringify` writes it: same members in the same order, numbers in JavaScript form.
fn same(actual: &Value, expected: &Value) {
    assert_eq!(core_js::stringify(actual), core_js::stringify(expected));
}

fn message<T: std::fmt::Debug>(result: Result<T, better_iam_core::IamError>) -> String {
    result.expect_err("expected an error").message
}

fn spec(value: Value) -> Value {
    price_spec(Some(&value)).expect("valid price")
}

#[test]
fn prices_per_unit_graduated_and_volume_tiers_packages_and_included_units() {
    let graduated = spec(json!({
        "model": "graduated",
        "tiers": [
            { "upTo": 100, "unitAmount": 1 },
            { "upTo": null, "unitAmount": 0.5, "flatAmount": 10 },
        ],
    }));
    // 100 × $1 + 50 × $0.50 + $10 flat.
    assert_eq!(price_quantity(&graduated, 150.0).unwrap(), 135_000_000.0);
    let volume = spec(json!({
        "model": "volume",
        "tiers": [{ "upTo": 100, "unitAmount": 1 }, { "upTo": null, "unitAmount": 0.5 }],
    }));
    assert_eq!(price_quantity(&volume, 150.0).unwrap(), 75_000_000.0);
    assert_eq!(price_quantity(&volume, 100.0).unwrap(), 100_000_000.0);
    let packaged = spec(json!({ "model": "package", "packageSize": 1000, "packageAmount": 2 }));
    assert_eq!(price_quantity(&packaged, 1001.0).unwrap(), 4_000_000.0);
    let included = spec(json!({
        "model": "per-unit",
        "unitAmount": 0.000002,
        "includedQuantity": 1_000_000,
    }));
    assert_eq!(price_quantity(&included, 3_500_000.0).unwrap(), 5_000_000.0);
    assert_eq!(
        message(price_spec(Some(&json!({
            "model": "graduated",
            "tiers": [{ "upTo": 5, "unitAmount": 1 }],
        })))),
        "Only the last tier has upTo: null"
    );
}

#[test]
fn breaks_tiered_prices_into_sub_lines_and_applies_a_price_minimum_and_maximum() {
    let price = spec(json!({
        "model": "graduated",
        "includedQuantity": 10,
        "tiers": [
            { "upTo": 100, "unitAmount": 1 },
            { "upTo": null, "unitAmount": 0.5, "flatAmount": 10 },
        ],
        "minimumAmount": 20,
        "maximumAmount": 120,
    }));
    // 160 units, 10 free: 100 × $1, then 50 × $0.50 + $10 flat = $135 before the cap.
    same(
        &price_breakdown(&price, 160.0).unwrap(),
        &json!({
            "tiers": [
                { "from": 1, "to": 100, "quantity": 100, "unitAmountMicros": 1_000_000, "amountMicros": 100_000_000 },
                {
                    "from": 101,
                    "to": null,
                    "quantity": 50,
                    "unitAmountMicros": 500_000,
                    "flatAmountMicros": 10_000_000,
                    "amountMicros": 35_000_000,
                },
            ],
            "includedQuantity": 10,
            "rawMicros": 135_000_000,
        }),
    );
    assert_eq!(price_quantity(&price, 160.0).unwrap(), 120_000_000.0);
    // Any usage costs at least the minimum; none costs nothing.
    assert_eq!(price_quantity(&price, 15.0).unwrap(), 20_000_000.0);
    assert_eq!(price_quantity(&price, 0.0).unwrap(), 0.0);
    assert_eq!(
        message(price_spec(Some(&json!({
            "model": "per-unit",
            "unitAmount": 1,
            "minimumAmount": 10,
            "maximumAmount": 5,
        })))),
        "maximumAmount must not be below minimumAmount"
    );
}

#[test]
fn prices_match_the_typescript_vectors() {
    for case in VECTORS["prices"].as_array().unwrap() {
        let price = price_spec(Some(&case["input"])).unwrap();
        same(&price, &case["spec"]);
        same(&public_price_spec(&price).unwrap(), &case["public"]);
        for entry in case["quantities"].as_array().unwrap() {
            let quantity = entry["quantity"].as_f64().unwrap();
            assert_eq!(
                price_quantity(&price, quantity).unwrap(),
                entry["amount"].as_f64().unwrap(),
                "{} × {quantity}",
                case["input"]
            );
            same(
                &price_breakdown(&price, quantity).unwrap(),
                &entry["breakdown"],
            );
        }
    }
}

#[test]
fn validates_prices_keys_periods_and_amounts() {
    assert_eq!(
        message(price_spec(Some(&json!({ "model": "flat" })))),
        "model must be 'per-unit', 'graduated', 'volume' or 'package'"
    );
    assert_eq!(message(price_spec(Some(&json!([])))), "Expected an object");
    assert_eq!(
        message(price_spec(Some(&json!({ "model": "volume", "tiers": [] })))),
        "tiers must list 1-20 tiers"
    );
    assert_eq!(
        message(price_spec(Some(&json!({
            "model": "graduated",
            "tiers": [{ "upTo": 10 }, { "upTo": 5 }, { "upTo": null }],
        })))),
        "Tier upTo values must ascend"
    );
    assert_eq!(
        message(price_spec(Some(
            &json!({ "model": "per-unit", "unitAmount": -1 })
        ))),
        "unitAmount must be an amount from 0 to 1000000000"
    );
    assert_eq!(
        message(price_spec(Some(
            &json!({ "model": "package", "packageSize": 0, "packageAmount": 1 })
        ))),
        "packageSize must be a positive number"
    );
    assert_eq!(
        message(price_spec(Some(
            &json!({ "model": "per-unit", "unitAmount": 1, "includedQuantity": null })
        ))),
        "includedQuantity must be a positive number"
    );
    assert_eq!(
        amount_micros(Some(&json!(1.5)), "amount").unwrap(),
        1_500_000.0
    );
    assert_eq!(
        message(amount_micros(Some(&json!("1")), "budget")),
        "budget must be an amount from 0 to 1000000000"
    );
    assert_eq!(
        meter_key(Some(&json!("api-calls.v2"))).unwrap(),
        "api-calls.v2"
    );
    for bad in [
        json!("Api"),
        json!("1x"),
        json!(""),
        json!(5),
        json!("a".repeat(65)),
    ] {
        assert_eq!(
            message(meter_key(Some(&bad))),
            "meter must be 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter"
        );
    }
    assert_eq!(
        billing_period(Some(&json!("2026-09")), None).unwrap(),
        "2026-09"
    );
    for bad in ["2026-13", "2026-9", "26-09", "2026-00", "2026-09\n"] {
        assert_eq!(
            message(billing_period(Some(&json!(bad)), Some("effectiveFrom"))),
            "effectiveFrom must be a month such as 2026-09"
        );
    }
    assert_eq!(budget_thresholds(None).unwrap(), vec![50.0, 80.0, 100.0]);
    assert_eq!(
        budget_thresholds(Some(&json!([" 80", 50, "50", 1000]))).unwrap(),
        vec![50.0, 80.0, 1000.0]
    );
    assert_eq!(
        message(budget_thresholds(Some(&json!([])))),
        "thresholds must list 1-10 percentages"
    );
    assert_eq!(
        message(budget_thresholds(Some(&json!(["5%"])))),
        "Invalid thresholds"
    );
    assert_eq!(
        message(budget_thresholds(Some(&json!(null)))),
        "thresholds must list 1-10 percentages"
    );
}

#[test]
fn periods_follow_the_billing_time_zone() {
    for case in VECTORS["bounds"].as_array().unwrap() {
        let bounds = period_bounds(
            case["period"].as_str().unwrap(),
            case["tz"].as_str().unwrap(),
        )
        .unwrap();
        same(
            &bounds,
            &json!({ "start": case["start"], "end": case["end"] }),
        );
    }
    for case in VECTORS["days"].as_array().unwrap() {
        let at = case["at"].as_f64().unwrap();
        let tz = case["tz"].as_str().unwrap();
        assert_eq!(period_of(at, tz).unwrap(), case["period"].as_str().unwrap());
        assert_eq!(day_of(at, tz).unwrap(), case["day"].as_str().unwrap());
    }
    assert_eq!(shift_period("2026-01", -1.0).unwrap(), "2025-12");
    assert_eq!(shift_period("2026-12", 1.0).unwrap(), "2027-01");
    assert_eq!(shift_period("2026-05", -17.0).unwrap(), "2024-12");
    assert_eq!(
        window_periods(&json!("quarter"), "2026-05").unwrap(),
        vec!["2026-04", "2026-05", "2026-06"]
    );
    assert_eq!(
        window_periods(&json!("month"), "2026-05").unwrap(),
        vec!["2026-05"]
    );
    let year = window_periods(&json!("year"), "2026-05").unwrap();
    assert_eq!(
        (year.len(), year[0].as_str(), year[11].as_str()),
        (12, "2026-01", "2026-12")
    );
    assert_eq!(
        message(period_bounds("2026-13", "UTC")),
        "period must be a month such as 2026-09"
    );
    assert_eq!(
        period_of(0.0, "Mars/Base").unwrap_err().code,
        "INTERNAL_ERROR"
    );
    let settings = billing_settings(None).unwrap();
    assert_eq!(
        usage_expiry("2026-03", &settings).unwrap(),
        1_775_001_600_000.0 + 400.0 * DAY
    );
    assert_eq!(overlap_share(0.0, 100.0, 25.0, 1000.0).unwrap(), 0.75);
    assert_eq!(overlap_share(0.0, 3.0, 0.0, 1.0).unwrap(), 0.3333);
    assert_eq!(overlap_share(10.0, 10.0, 0.0, 1.0).unwrap(), 0.0);
}

#[test]
fn hashes_and_rollup_ids_match_typescript() {
    for case in VECTORS["rollups"].as_array().unwrap() {
        assert_eq!(
            rollup_id(
                case["tenantId"].as_str().unwrap(),
                case["day"].as_str().unwrap(),
                case["meterId"].as_str().unwrap(),
                &case["attribution"],
            )
            .unwrap(),
            case["id"].as_str().unwrap()
        );
    }
    assert_eq!(
        statement_hash(&VECTORS["hash"]["statement"]).unwrap(),
        VECTORS["hash"]["hash"].as_str().unwrap()
    );
}

#[test]
fn validates_settings_like_typescript() {
    let settings = billing_settings(Some(&json!({
        "paymentReminderDays": [7, -3, 7],
        "issuer": { "name": "X", "extra": 1 },
    })))
    .unwrap();
    assert_eq!(settings.payment_reminder_days, vec![-3.0, 7.0]);
    assert_eq!(settings.issuer.as_ref().unwrap().name, "X");
    assert_eq!(settings.issuer.as_ref().unwrap().extra["extra"], json!(1));
    let defaults = billing_settings(Some(&json!({}))).unwrap();
    assert_eq!(
        (
            defaults.currency.as_str(),
            defaults.time_zone.as_str(),
            defaults.usage_retention_days,
            defaults.team_attribution.as_str(),
            defaults.payment_terms_days,
            defaults.statement_prefix.as_str(),
            defaults.auto_finalize,
        ),
        ("USD", "UTC", 400.0, "split", 30.0, "INV", true)
    );
    assert_eq!(defaults.payment_reminder_days, vec![-3.0, 0.0, 7.0, 14.0]);
    for (options, expected) in [
        (
            json!({ "autoFinalize": "yes" }),
            "billing.autoFinalize must be a boolean",
        ),
        (
            json!({ "issuer": null }),
            "billing.issuer must be an object",
        ),
        (
            json!({ "issuer": {} }),
            "billing.issuer.name must be text of 1-256 characters",
        ),
        (
            json!({ "issuer": { "name": "X", "taxId": " " } }),
            "billing.issuer.taxId must be text of 1-64 characters",
        ),
        (
            json!({ "paymentReminderDays": [400] }),
            "billing.paymentReminderDays must list at most 10 whole days from -60 to 365",
        ),
        (
            json!({ "currency": "usd" }),
            "billing.currency must be an ISO 4217 code such as USD",
        ),
        (
            json!({ "timeZone": "Mars/Base" }),
            "billing.timeZone must be an IANA time zone",
        ),
        (
            json!({ "usageRetentionDays": 0 }),
            "billing.usageRetentionDays must be 1-3650",
        ),
        (
            json!({ "teamAttribution": "even" }),
            "billing.teamAttribution must be 'split', 'primary' or 'full'",
        ),
        (
            json!({ "paymentTermsDays": 1.5 }),
            "billing.paymentTermsDays must be 0-365",
        ),
        (
            json!({ "statementPrefix": "-INV" }),
            "billing.statementPrefix must be 1-16 uppercase letters, digits or hyphens",
        ),
    ] {
        let error = billing_settings(Some(&options)).unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            ("INVALID_CONFIG", expected)
        );
    }
}

#[test]
fn validates_meter_settings_and_tags() {
    same(
        &meter_settings(VECTORS["meterSettings"]["input"].as_object().unwrap(), None).unwrap(),
        &VECTORS["meterSettings"]["output"],
    );
    let current: BillingMeter = decode(
        json!({
            "id": "m", "tenantId": "t", "uniqueKey": "seats", "key": "seats", "name": "Seats", "unit": "seat-day",
            "description": "Seats", "aggregation": "unique", "pricing": "rate-card", "archived": false,
            "createdAt": 0, "createdBy": "x", "updatedAt": 0, "updatedBy": "x",
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();
    same(
        &meter_settings(
            json!({ "archived": true }).as_object().unwrap(),
            Some(&current),
        )
        .unwrap(),
        &json!({
            "name": "Seats", "unit": "seat-day", "aggregation": "unique", "pricing": "rate-card",
            "archived": true, "description": "Seats",
        }),
    );
    for (input, expected) in [
        (
            json!({ "aggregation": "sum" }),
            "A meter’s aggregation cannot change; create a new meter",
        ),
        (
            json!({ "aggregation": null }),
            "A meter’s aggregation cannot change; create a new meter",
        ),
        (
            json!({ "pricing": "reported" }),
            "A meter’s pricing cannot change; create a new meter",
        ),
        (json!({ "archived": 1 }), "archived must be a boolean"),
        (json!({ "name": " " }), "Invalid name"),
    ] {
        assert_eq!(
            message(meter_settings(input.as_object().unwrap(), Some(&current))),
            expected
        );
    }
    assert_eq!(
        message(meter_settings(&serde_json::Map::new(), None)),
        "name is required"
    );
    assert_eq!(
        message(meter_settings(
            json!({ "name": "X", "aggregation": "unique", "pricing": "reported" })
                .as_object()
                .unwrap(),
            None
        )),
        "Reported meters add up their events (aggregation sum)"
    );
    assert_eq!(
        message(meter_settings(
            json!({ "name": "X", "aggregation": "max" })
                .as_object()
                .unwrap(),
            None
        )),
        "aggregation must be 'sum' or 'unique'"
    );
    let tags = usage_tags(Some(&json!({ "project": "apollo", "env.name": "prod" })))
        .unwrap()
        .unwrap();
    assert_eq!(tags.keys().collect::<Vec<_>>(), vec!["env.name", "project"]);
    assert_eq!(usage_tags(Some(&json!({}))).unwrap(), None);
    assert_eq!(usage_tags(None).unwrap(), None);
    assert_eq!(
        message(usage_tags(Some(&json!({ "1x": "a" })))),
        "Invalid tag name 1x"
    );
    assert_eq!(
        message(usage_tags(Some(&json!({ "a": "" })))),
        "Invalid tags.a"
    );
    let many: serde_json::Map<String, Value> = (0..11)
        .map(|index| (format!("k{index}"), json!("v")))
        .collect();
    assert_eq!(
        message(usage_tags(Some(&Value::Object(many)))),
        "tags may hold at most 10 entries"
    );
}

#[test]
fn applies_a_discount_a_minimum_commitment_credit_and_tax() {
    // $50 − 10% = $45; the $100 commitment adds $55; $20 credit leaves $80; 20% VAT: $96.
    let terms: BillingTerms = decode(
        json!({
            "id": "t", "tenantId": "a", "discountPercent": 10, "minimumCommitmentMicros": 100_000_000,
            "taxRatePercent": 20, "taxLabel": "VAT", "setAt": 0, "setBy": "x",
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();
    let mut asked = Vec::new();
    let amounts = invoice_amounts_of(
        &InvoiceAmountsInput {
            subtotal_micros: 50_000_000.0,
            terms: Some(terms),
            commitment: true,
            discounts: Vec::new(),
        },
        |due| {
            asked.push(due);
            due.min(20_000_000.0)
        },
    );
    assert_eq!(asked, vec![100_000_000.0]);
    same(
        &amounts,
        &json!({
            "discount": { "percent": 10, "amountMicros": 5_000_000 },
            "commitment": { "minimumMicros": 100_000_000, "trueUpMicros": 55_000_000 },
            "creditsMicros": 20_000_000,
            "tax": { "label": "VAT", "ratePercent": 20, "amountMicros": 16_000_000 },
            "totalMicros": 96_000_000,
            "carryForwardMicros": 0,
        }),
    );
    // Coupons after the contract discount, as the TypeScript vector computes them.
    let input = &VECTORS["amounts"]["input"];
    let discounts: Vec<BillingDiscount> = input["discounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| decode(item.as_object().unwrap().clone()).unwrap())
        .collect();
    let available = VECTORS["amounts"]["creditAvailable"].as_f64().unwrap();
    same(
        &invoice_amounts_of(
            &InvoiceAmountsInput {
                subtotal_micros: input["subtotalMicros"].as_f64().unwrap(),
                terms: Some(decode(input["terms"].as_object().unwrap().clone()).unwrap()),
                commitment: true,
                discounts,
            },
            |due| due.min(available),
        ),
        &VECTORS["amounts"]["output"],
    );
    // A negative balance is carried forward as credit; JSON input applies no credit.
    same(
        &invoice_amounts(&json!({ "subtotalMicros": -3_000_000, "commitment": false })).unwrap(),
        &VECTORS["amountsNegative"],
    );
}

#[test]
fn reads_subscriptions_discounts_and_invoice_amounts() {
    let subscription: billing::BillingSubscription = decode(
        json!({
            "id": "s", "tenantId": "a", "planId": "p", "planKey": "pro", "planName": "Pro", "startedAt": 0,
            "trialEndsAt": 100, "cancelAtPeriodEnd": false, "seats": 1, "seatHistory": [], "billedAdvance": [],
            "createdAt": 0, "createdBy": "x", "updatedAt": 0,
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();
    assert_eq!(
        subscription_status(&subscription, 50.0).unwrap(),
        "trialing"
    );
    assert_eq!(subscription_status(&subscription, 100.0).unwrap(), "active");
    let ended = billing::BillingSubscription {
        ends_at: Some(200.0),
        ..subscription
    };
    assert_eq!(subscription_status(&ended, 200.0).unwrap(), "ended");
    let discount = |duration: &str, applied: f64| -> BillingDiscount {
        decode(
            json!({
                "id": "d", "tenantId": "a", "couponId": "c", "code": "X", "name": "X", "percentOff": 10,
                "duration": duration, "durationInMonths": 2, "appliedInvoices": applied,
                // 2026-03-10 UTC.
                "redeemedAt": 1_773_100_800_000.0_f64, "redeemedBy": "x",
            })
            .as_object()
            .unwrap()
            .clone(),
        )
        .unwrap()
    };
    assert!(discount_active(&discount("once", 0.0), "2026-09", "UTC").unwrap());
    assert!(!discount_active(&discount("once", 1.0), "2026-03", "UTC").unwrap());
    assert!(discount_active(&discount("repeating", 5.0), "2026-04", "UTC").unwrap());
    assert!(!discount_active(&discount("repeating", 0.0), "2026-05", "UTC").unwrap());
    assert!(!discount_active(&discount("repeating", 0.0), "2026-02", "UTC").unwrap());
    let mut forever = discount("forever", 9.0);
    assert!(discount_active(&forever, "2030-01", "UTC").unwrap());
    forever.ended_at = Some(1.0);
    assert!(!discount_active(&forever, "2030-01", "UTC").unwrap());
    let statement = |extra: Value| -> billing::BillingStatement {
        let mut record = json!({
            "id": "s", "tenantId": "a", "number": "INV-1", "status": "finalized", "issuedAt": 0, "dueAt": 0,
            "hash": "", "period": "2026-03", "currency": "USD", "periodStart": 0, "periodEnd": 1, "lines": [],
            "subtotalMicros": 0, "creditsMicros": 0, "creditsApplied": [], "totalMicros": 10_000_000,
            "breakdown": {}, "billTo": { "name": "A", "emails": [] },
        });
        for (key, value) in extra.as_object().unwrap() {
            record[key] = value.clone();
        }
        decode(record.as_object().unwrap().clone()).unwrap()
    };
    assert_eq!(
        billing::amount_due(&statement(json!({}))).unwrap(),
        10_000_000.0
    );
    assert_eq!(
        billing::amount_due(&statement(
            json!({ "amountPaidMicros": 4_000_000, "creditNotesMicros": 1_000_000 })
        ))
        .unwrap(),
        5_000_000.0
    );
    assert_eq!(
        billing::amount_due(&statement(json!({ "status": "paid" }))).unwrap(),
        0.0
    );
    assert_eq!(
        billing::amount_paid(&statement(json!({ "status": "paid" }))).unwrap(),
        10_000_000.0
    );
    assert_eq!(
        billing::amount_due(&statement(json!({ "status": "void" }))).unwrap(),
        0.0
    );
    assert_eq!(
        billing::amount_due(&statement(json!({ "status": "draft" }))).unwrap(),
        10_000_000.0
    );
    assert_eq!(billing::round_cents(-12_345.0).unwrap(), -10_000.0);
    assert_eq!(billing::round_cents(15_000.0).unwrap(), 20_000.0);
    assert_eq!(billing::round_cents(-15_000.0).unwrap(), -10_000.0);
    assert_eq!(billing::units_of(1_234_567.0).unwrap(), 1.23);
    assert_eq!(billing::round_micros(0.0005).unwrap(), 0.001);
}

// ---------------------------------------------------------------------------------------------------------------
// Spend over the store

const API_CALLS: &str = "api-calls";

/// The current period of the fixture clock and the one before.
fn periods(org: &Org) -> (String, String) {
    let current = period_of(org.now(), "UTC").unwrap();
    let previous = shift_period(&current, -1.0).unwrap();
    (current, previous)
}

async fn tenant(org: &Org, id: &str) -> Tenant {
    decode(org.get("tenants", id).await.expect("tenant")).unwrap()
}

/// A tenant below `parent_id` (as `tenants.create` stores it).
async fn child(org: &Org, parent_id: &str, name: &str, kind: &str) -> String {
    let tenant_id = id();
    org.insert(
        "tenants",
        json!({
            "id": tenant_id, "tenantId": tenant_id, "name": name, "type": kind, "parentId": parent_id,
            "status": "active", "createdAt": org.now(),
        }),
    )
    .await;
    tenant_id
}

/// A meter as `billing.createMeter` stores it.
async fn meter(org: &Org, tenant_id: &str, key: &str, aggregation: &str, pricing: &str) -> String {
    let meter_id = id();
    org.insert(
        billing::METERS,
        json!({
            "id": meter_id, "tenantId": tenant_id, "uniqueKey": key, "key": key, "name": key.replace('-', " "),
            "unit": "request", "aggregation": aggregation, "pricing": pricing, "archived": false,
            "createdAt": org.now(), "createdBy": "x", "updatedAt": org.now(), "updatedBy": "x",
        }),
    )
    .await;
    meter_id
}

/// A rate card entry as `billing.setPrice` stores it (in the tenant it applies to).
async fn price(
    org: &Org,
    on: &str,
    definer: &str,
    meter_id: &str,
    key: &str,
    from: &str,
    input: Value,
) {
    org.insert(
        billing::PRICES,
        json!({
            "id": id(), "tenantId": on, "uniqueKey": format!("{meter_id}:{from}"), "meterId": meter_id,
            "meter": key, "definerId": definer, "effectiveFrom": from, "spec": spec(input),
            "setAt": org.now(), "setBy": "x",
        }),
    )
    .await;
}

/// A daily roll-up as `billing.record` keeps it.
#[allow(clippy::too_many_arguments)]
async fn rollup(
    org: &Org,
    tenant_id: &str,
    meter_id: &str,
    key: &str,
    day: &str,
    identity_id: Option<&str>,
    quantity: f64,
    cost_micros: f64,
) {
    let mut attribution = json!({ "teamIds": [] });
    if let Some(identity_id) = identity_id {
        attribution["identityId"] = json!(identity_id);
    }
    let rollup_id = rollup_id(tenant_id, day, meter_id, &attribution).unwrap();
    let mut record = json!({
        "id": rollup_id, "tenantId": tenant_id, "period": &day[..7], "day": day, "meterId": meter_id, "meter": key,
    });
    if let Some(identity_id) = identity_id {
        record["identityId"] = json!(identity_id);
    }
    record["teamIds"] = json!([]);
    record["quantity"] = json!(quantity);
    record["costMicros"] = json!(cost_micros);
    record["events"] = json!(1);
    record["updatedAt"] = json!(org.now());
    org.insert(billing::ROLLUPS, record).await;
}

async fn spend(org: &Org, account_id: &str, period: &str) -> AccountSpend {
    let ctx = org.iam.ctx.clone();
    let account = tenant(org, account_id).await;
    let period = period.to_owned();
    org.iam
        .store
        .transaction(|tx| async move { account_spend_of(&ctx, &tx, &account, &period, None).await })
        .await
        .unwrap()
}

fn cost_of(spend: &AccountSpend, tenant_id: &str, identity_id: Option<&str>) -> f64 {
    spend
        .rows
        .iter()
        .filter(|row| row.tenant_id == tenant_id && row.identity_id.as_deref() == identity_id)
        .map(|row| row.cost_micros)
        .sum()
}

#[test]
fn prices_the_account_total_once_and_shares_it_out_by_person_meter_and_project() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let (current, previous) = periods(&org);
        let root = org.root_tenant_id.clone();
        // 1000 free calls a month, then $0.01 each up to 10 000, then $0.005.
        let meter_id = meter(&org, &root, API_CALLS, "sum", "rate-card").await;
        price(
            &org,
            &root,
            &root,
            &meter_id,
            API_CALLS,
            &previous,
            json!({
                "model": "graduated",
                "includedQuantity": 1000,
                "tiers": [{ "upTo": 10_000, "unitAmount": 0.01 }, { "upTo": null, "unitAmount": 0.005 }],
            }),
        )
        .await;
        let alice = org.member("alice").await.id;
        let bob = org.member("bob").await.id;
        let apollo = child(&org, &org.tenant_id, "Apollo", "project").await;
        let today = day_of(org.now(), "UTC").unwrap();
        rollup(
            &org,
            &org.tenant_id,
            &meter_id,
            API_CALLS,
            &today,
            Some(&alice),
            3000.0,
            0.0,
        )
        .await;
        rollup(
            &org,
            &org.tenant_id,
            &meter_id,
            API_CALLS,
            &today,
            Some(&bob),
            500.0,
            0.0,
        )
        .await;
        rollup(
            &org, &apollo, &meter_id, API_CALLS, &today, None, 500.0, 0.0,
        )
        .await;
        // 4000 calls, 1000 free: 3000 × $0.01 = $30, shared by quantity (75% / 12.5% / 12.5%).
        let acme = spend(&org, &org.tenant_id, &current).await;
        assert_eq!(
            (acme.total_micros, acme.billable_micros),
            (30_000_000.0, 30_000_000.0)
        );
        assert_eq!(cost_of(&acme, &org.tenant_id, Some(&alice)), 22_500_000.0);
        assert_eq!(cost_of(&acme, &org.tenant_id, Some(&bob)), 3_750_000.0);
        assert_eq!(cost_of(&acme, &apollo, None), 3_750_000.0);
        assert_eq!(acme.charges.len(), 1);
        let charge = &acme.charges[0];
        assert_eq!(
            (
                charge.meter.as_str(),
                charge.quantity,
                charge.amount_micros,
                charge.internal
            ),
            (API_CALLS, 4000.0, 30_000_000.0, false)
        );
        assert_eq!(charge.price.as_ref().unwrap()["source"], json!("rate-card"));
        assert_eq!(charge.price.as_ref().unwrap()["setOn"], json!(root));
        // The project's own view covers only its subtree, priced within Acme's account.
        let ctx = org.iam.ctx.clone();
        let apollo_tenant = tenant(&org, &apollo).await;
        let root_tenant = tenant(&org, &root).await;
        let period = current.clone();
        let (project_view, platform, account) = org
            .iam
            .store
            .transaction(|tx| async move {
                let cache = SpendCache::new();
                let project_view =
                    scope_spend_of(&ctx, &tx, &apollo_tenant, &period, Some(&cache)).await?;
                let platform =
                    scope_spend_of(&ctx, &tx, &root_tenant, &period, Some(&cache)).await?;
                let account = account_of(&ctx, &tx, &apollo_tenant).await?;
                Ok((project_view, platform, account))
            })
            .await
            .unwrap();
        assert_eq!(project_view.rows.len(), 1);
        assert_eq!(project_view.rows[0].cost_micros, 3_750_000.0);
        assert_eq!(account.id, org.tenant_id);
        // The platform sees every organization as an account of its own.
        assert_eq!(
            platform
                .accounts
                .iter()
                .map(|spend| spend.account_id.clone())
                .collect::<Vec<_>>(),
            vec![root.clone(), org.tenant_id.clone()]
        );
        assert_eq!(platform.rows.len(), 3);
        // A negotiated price for Acme wins over the list price from this period on.
        price(
            &org,
            &org.tenant_id,
            &root,
            &meter_id,
            API_CALLS,
            &current,
            json!({ "model": "per-unit", "unitAmount": 0.002 }),
        )
        .await;
        let negotiated = spend(&org, &org.tenant_id, &current).await;
        assert_eq!(negotiated.total_micros, 8_000_000.0);
        assert_eq!(
            negotiated.charges[0].price.as_ref().unwrap()["setOn"],
            json!(org.tenant_id)
        );
        // The month before still has the list price only.
        let before = spend(&org, &org.tenant_id, &previous).await;
        assert!(before.charges.is_empty());
    });
}

#[test]
fn keeps_chargeback_meters_off_statements_and_bills_projects_with_their_own_profile() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let (current, _) = periods(&org);
        let root = org.root_tenant_id.clone();
        let today = day_of(org.now(), "UTC").unwrap();
        // A chargeback meter defined inside Acme, priced by Acme.
        let internal = meter(&org, &org.tenant_id, "gpu-hours", "sum", "rate-card").await;
        price(
            &org,
            &org.tenant_id,
            &org.tenant_id,
            &internal,
            "gpu-hours",
            &current,
            json!({ "model": "per-unit", "unitAmount": 2 }),
        )
        .await;
        // A reported platform meter: every event carries its cost.
        let inference = meter(&org, &root, "inference", "sum", "reported").await;
        let alice = org.member("alice").await.id;
        rollup(
            &org,
            &org.tenant_id,
            &internal,
            "gpu-hours",
            &today,
            Some(&alice),
            3.0,
            0.0,
        )
        .await;
        rollup(
            &org,
            &org.tenant_id,
            &inference,
            "inference",
            &today,
            Some(&alice),
            10.0,
            1_234.567_8,
        )
        .await;
        // A project with a billing profile of its own is its own account.
        let hermes = child(&org, &org.tenant_id, "Hermes", "project").await;
        org.insert(
            billing::PROFILES,
            json!({
                "id": id(), "tenantId": hermes, "uniqueKey": "profile", "billingEmails": [],
                "createdAt": 0, "createdBy": "x", "updatedAt": 0, "updatedBy": "x",
            }),
        )
        .await;
        rollup(
            &org,
            &hermes,
            &inference,
            "inference",
            &today,
            None,
            1.0,
            1_000_000.0,
        )
        .await;
        let acme = spend(&org, &org.tenant_id, &current).await;
        assert_eq!(acme.total_micros, 6_001_234.568);
        assert_eq!(acme.billable_micros, 1_234.568);
        let gpu = acme
            .charges
            .iter()
            .find(|charge| charge.meter == "gpu-hours")
            .unwrap();
        assert!(gpu.internal);
        assert_eq!(gpu.amount_micros, 6_000_000.0);
        let reported = acme
            .charges
            .iter()
            .find(|charge| charge.meter == "inference")
            .unwrap();
        assert_eq!((reported.quantity, reported.price.is_none()), (10.0, true));
        assert!(acme.rows.iter().all(|row| row.tenant_id != hermes));
        let ctx = org.iam.ctx.clone();
        let acme_tenant = tenant(&org, &org.tenant_id).await;
        let hermes_tenant = tenant(&org, &hermes).await;
        let (tenants, account) = org
            .iam
            .store
            .transaction(|tx| async move {
                let tenants = account_tenants(&tx, &acme_tenant, false).await?;
                let account = account_of(&ctx, &tx, &hermes_tenant).await?;
                Ok((tenants, account))
            })
            .await
            .unwrap();
        assert_eq!(tenants.len(), 1);
        assert_eq!(account.id, hermes);
        let hermes_spend = spend(&org, &hermes, &current).await;
        assert_eq!(hermes_spend.billable_micros, 1_000_000.0);
    });
}

#[test]
fn counts_active_users_once_at_the_plan_price_of_their_first_live_day() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let root = org.root_tenant_id.clone();
        let (current, _) = periods(&org);
        let bounds = billing::bounds_of(&current, "UTC").unwrap();
        let active = meter(&org, &root, "active-users", "unique", "rate-card").await;
        price(
            &org,
            &root,
            &root,
            &active,
            "active-users",
            &current,
            json!({ "model": "per-unit", "unitAmount": 5 }),
        )
        .await;
        let plan_id = id();
        org.insert(
            billing::PLANS,
            json!({
                "id": plan_id, "tenantId": root, "uniqueKey": "team", "key": "team", "name": "Team",
                "items": [{ "id": "users", "kind": "usage", "name": "Users", "meter": "active-users",
                    "price": spec(json!({ "model": "per-unit", "unitAmount": 3 })) }],
                "selfServe": true, "archived": false, "createdAt": 0, "createdBy": "x", "updatedAt": 0, "updatedBy": "x",
            }),
        )
        .await;
        // Subscribed from the 11th of the month on.
        let started = bounds.start + 10.0 * DAY;
        org.insert(
            billing::SUBSCRIPTIONS,
            json!({
                "id": id(), "tenantId": org.tenant_id, "uniqueKey": format!("plan:{plan_id}"), "planId": plan_id,
                "planKey": "team", "planName": "Team", "startedAt": started, "cancelAtPeriodEnd": false, "seats": 0,
                "seatHistory": [], "billedAdvance": [], "createdAt": 0, "createdBy": "x", "updatedAt": 0,
            }),
        )
        .await;
        let alice = org.member("alice").await.id;
        let bob = org.member("bob").await.id;
        let early = day_of(bounds.start + DAY, "UTC").unwrap();
        let late = day_of(started + DAY, "UTC").unwrap();
        rollup(
            &org,
            &org.tenant_id,
            &active,
            "active-users",
            &early,
            Some(&alice),
            1.0,
            0.0,
        )
        .await;
        rollup(
            &org,
            &org.tenant_id,
            &active,
            "active-users",
            &late,
            Some(&alice),
            3.0,
            0.0,
        )
        .await;
        rollup(
            &org,
            &org.tenant_id,
            &active,
            "active-users",
            &early,
            Some(&bob),
            1.0,
            0.0,
        )
        .await;
        let acme = spend(&org, &org.tenant_id, &current).await;
        // Alice counts once, at the plan's $3 (her first window); Bob only used it before the plan: $5.
        assert_eq!(acme.total_micros, 8_000_000.0);
        let plan_part = acme
            .charges
            .iter()
            .find(|charge| {
                charge
                    .price
                    .as_ref()
                    .is_some_and(|price| price["source"] == json!("plan"))
            })
            .unwrap();
        assert_eq!(
            (plan_part.quantity, plan_part.amount_micros),
            (1.0, 3_000_000.0)
        );
        assert_eq!(plan_part.price.as_ref().unwrap()["planKey"], json!("team"));
        assert_eq!(cost_of(&acme, &org.tenant_id, Some(&alice)), 3_000_000.0);
        let mut alice_rows: Vec<f64> = acme
            .rows
            .iter()
            .filter(|row| row.identity_id.as_deref() == Some(alice.as_str()))
            .map(|row| row.cost_micros)
            .collect();
        // Spread over her rows by quantity (1 and 3).
        alice_rows.sort_by(f64::total_cmp);
        assert_eq!(alice_rows, vec![750_000.0, 2_250_000.0]);
        assert_eq!(cost_of(&acme, &org.tenant_id, Some(&bob)), 5_000_000.0);
    });
}

#[test]
fn resolves_meters_terms_and_attribution_along_the_tenant_chain() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let root = org.root_tenant_id.clone();
        let platform_meter = meter(&org, &root, "api-calls", "sum", "rate-card").await;
        meter(&org, &org.tenant_id, "api-calls", "sum", "rate-card").await;
        meter(&org, &org.tenant_id, "gpu-hours", "sum", "rate-card").await;
        let apollo = child(&org, &org.tenant_id, "Apollo", "project").await;
        org.insert(
            billing::TERMS,
            json!({
                "id": id(), "tenantId": org.tenant_id, "uniqueKey": "terms", "discountPercent": 10,
                "minimumCommitmentMicros": 100_000_000, "taxRatePercent": 20, "setAt": 0, "setBy": "x",
            }),
        )
        .await;
        let alice = org.member("alice").await;
        let carol = org.member("carol").await;
        let platform = create_team(&org, "Platform", "platform", None, &[]).await;
        let api = create_team(&org, "API", "api", Some(&platform.id), &[]).await;
        let web = create_team(&org, "Web", "web", None, &[]).await;
        add_team_member(&org, &api.id, &alice.id, "member", None).await;
        org.advance(1000.0);
        add_team_member(&org, &web.id, &alice.id, "member", None).await;
        let engineering = create_department(&org, "Engineering", None).await;
        let backend = create_department(&org, "Backend", Some(&engineering)).await;
        place(&org, &backend, &alice.id).await;
        let ctx = org.iam.ctx.clone();
        let acme = tenant(&org, &org.tenant_id).await;
        let apollo_tenant = tenant(&org, &apollo).await;
        let tenant_id = org.tenant_id.clone();
        let (alice_id, carol_id, api_id, platform_id) = (
            alice.id.clone(),
            carol.id.clone(),
            api.id.clone(),
            platform.id.clone(),
        );
        let (backend_id, engineering_id) = (backend.clone(), engineering.clone());
        org.iam
            .store
            .transaction(|tx| async move {
                let chain = ctx.ancestry(&tx, &apollo_tenant).await?;
                // The ancestor nearest the root owns a shared key.
                let found = resolve_meter(&tx, &chain, "api-calls").await?.unwrap();
                assert_eq!(found.id, platform_meter);
                assert!(resolve_meter(&tx, &chain, "unknown").await?.is_none());
                let meters = meters_for(&tx, &chain).await?;
                assert_eq!(meters.keys().collect::<Vec<_>>(), vec!["api-calls", "gpu-hours"]);
                assert_eq!(meters["api-calls"].tenant_id, ctx.ancestry(&tx, &acme).await?[1].id);
                // A carved-out account keeps the discount and tax, but not the commitment.
                let own = account_terms_of(&ctx, &tx, &acme).await?.unwrap();
                assert_eq!(own.minimum_commitment_micros, Some(100_000_000.0));
                let inherited = account_terms_of(&ctx, &tx, &apollo_tenant).await?.unwrap();
                assert_eq!(
                    (inherited.discount_percent, inherited.minimum_commitment_micros, inherited.tax_rate_percent),
                    (Some(10.0), None, Some(20.0))
                );
                let settings: BillingSettings = billing_settings(None)?;
                // Alice's teams split her cost; her department comes from her placement.
                let attribution =
                    attribution_for(&ctx, &tx, &chain, &json!({ "identityId": alice_id }), &settings).await?;
                assert_eq!(attribution["identityId"], json!(alice_id));
                assert_eq!(attribution["teamIds"].as_array().unwrap().len(), 2);
                assert_eq!(attribution["departmentId"], json!(backend_id));
                assert_eq!(
                    attribution.as_object().unwrap().keys().collect::<Vec<_>>(),
                    vec!["teamIds", "identityId", "departmentId"]
                );
                let primary = BillingSettings {
                    team_attribution: "primary".into(),
                    ..settings.clone()
                };
                let first =
                    attribution_for(&ctx, &tx, &chain, &json!({ "identityId": alice_id }), &primary).await?;
                assert_eq!(first["teamIds"], json!([api_id]));
                // A named team replaces the person's own teams.
                let named = attribution_for(
                    &ctx,
                    &tx,
                    &chain,
                    &json!({ "identityId": carol_id, "teamId": platform_id, "agentId": "agent-1" }),
                    &settings,
                )
                .await?;
                assert_eq!(
                    named,
                    json!({ "teamIds": [platform_id], "identityId": carol_id, "agentId": "agent-1" })
                );
                let anonymous = attribution_for(&ctx, &tx, &chain, &json!({}), &settings).await?;
                assert_eq!(anonymous, json!({ "teamIds": [] }));
                let missing =
                    attribution_for(&ctx, &tx, &chain, &json!({ "identityId": "nobody" }), &settings).await;
                assert_eq!(missing.unwrap_err().code, "NOT_FOUND");
                let bad_team =
                    attribution_for(&ctx, &tx, &chain, &json!({ "teamId": "nope" }), &settings).await;
                assert_eq!(bad_team.unwrap_err().message, "Team not found");
                let invalid =
                    attribution_for(&ctx, &tx, &chain, &json!({ "identityId": null }), &settings).await;
                assert_eq!(invalid.unwrap_err().message, "Invalid identityId");
                // Team and department roll-ups over a directory.
                let directory = directory_for(&tx, &json!([tenant_id, tenant_id])).await?;
                assert_eq!(directory.teams.len(), 3);
                assert_eq!(directory.departments.len(), 2);
                let row: billing::ChargedRow = decode(
                    json!({
                        "tenantId": tenant_id, "period": "2026-03", "day": "2026-03-01", "meterId": "m",
                        "meter": "api-calls", "teamIds": attribution["teamIds"], "departmentId": backend_id,
                        "quantity": 1, "costMicros": 10, "events": 1, "internal": false,
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                )?;
                assert_eq!(team_share(&row, &platform_id, &directory, &settings, false)?, 0.0);
                assert_eq!(team_share(&row, &platform_id, &directory, &settings, true)?, 0.5);
                let full = BillingSettings {
                    team_attribution: "full".into(),
                    ..settings.clone()
                };
                assert_eq!(team_share(&row, &api_id, &directory, &full, false)?, 1.0);
                assert!(in_department(&row, &engineering_id, &directory, true)?);
                assert!(!in_department(&row, &engineering_id, &directory, false)?);
                assert!(in_department(&row, &backend_id, &directory, false)?);
                Ok(())
            })
            .await
            .unwrap();
    });
}

#[test]
fn caches_account_spend_within_one_call() {
    run(|| async {
        let org = Org::new(|_| {}).await;
        let (current, _) = periods(&org);
        let root = org.root_tenant_id.clone();
        let meter_id = meter(&org, &root, API_CALLS, "sum", "rate-card").await;
        price(
            &org,
            &root,
            &root,
            &meter_id,
            API_CALLS,
            &current,
            json!({ "model": "per-unit", "unitAmount": 1 }),
        )
        .await;
        let today = day_of(org.now(), "UTC").unwrap();
        rollup(
            &org,
            &org.tenant_id,
            &meter_id,
            API_CALLS,
            &today,
            None,
            2.0,
            0.0,
        )
        .await;
        let ctx = org.iam.ctx.clone();
        let acme = tenant(&org, &org.tenant_id).await;
        let store = org.iam.store.clone();
        let tenant_id = org.tenant_id.clone();
        org.iam
            .store
            .transaction(|tx| async move {
                let cache = SpendCache::new();
                let first = account_spend_of(&ctx, &tx, &acme, &current, Some(&cache)).await?;
                assert_eq!(first.total_micros, 2_000_000.0);
                // Usage recorded later in the call is not seen through the cache.
                let today = day_of(ctx.now(), "UTC")?;
                let mut record = serde_json::Map::new();
                record.insert("id".into(), json!(id()));
                record.insert("tenantId".into(), json!(tenant_id));
                record.insert("period".into(), json!(current));
                record.insert("day".into(), json!(today));
                record.insert("meterId".into(), json!(meter_id));
                record.insert("meter".into(), json!(API_CALLS));
                record.insert("teamIds".into(), json!([]));
                record.insert("quantity".into(), json!(5));
                record.insert("costMicros".into(), json!(0));
                record.insert("events".into(), json!(1));
                record.insert("updatedAt".into(), json!(0));
                tx.insert(billing::ROLLUPS, &record).await?;
                let cached =
                    account_spend_of(&ctx, &tx, &acme, &current, Some(&cache.clone())).await?;
                assert_eq!(cached.total_micros, 2_000_000.0);
                let fresh = account_spend_of(&ctx, &tx, &acme, &current, None).await?;
                assert_eq!(fresh.total_micros, 7_000_000.0);
                let _ = store;
                Ok(())
            })
            .await
            .unwrap();
    });
}

#[test]
fn names_the_collections_the_module_owns() {
    assert_eq!(
        billing::BILLING_COLLECTIONS["meters"],
        json!(billing::METERS)
    );
    assert_eq!(
        billing::BILLING_COLLECTIONS["subscriptions"],
        json!(billing::SUBSCRIPTIONS)
    );
    assert_eq!(billing::BILLING_COLLECTIONS.as_object().unwrap().len(), 16);
    assert_eq!(billing::MAX_METERS_PER_TENANT, 100.0);
}
