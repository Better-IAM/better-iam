//! Port of the tests of `billing-invoices.ts`: the invoice item, coupon and credit note validation and the printable
//! invoice of tests/billing-invoicing.test.ts ("drafts invoices with items, finalizes them, and takes payments and
//! credit notes", "applies coupons after the contract discount ...") at the level of the module functions (the
//! billing API group and service belong to other port units), with the HTML compared byte for byte with what the
//! TypeScript implementation renders (tests/fixtures/billing.json).

use std::sync::LazyLock;

use better_iam_core::js as core_js;
use better_iam_server::billing::BillingStatement;
use better_iam_server::billing_invoices::{
    coupon_code, coupon_settings, credit_note_reason, invoice_item_input, render_invoice_html,
    signed_amount_micros,
};
use better_iam_server::port::decode;
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

#[test]
fn renders_invoices_like_typescript() {
    for case in VECTORS["html"].as_array().unwrap() {
        let statement: BillingStatement =
            decode(case["statement"].as_object().unwrap().clone()).unwrap();
        let html = render_invoice_html(&statement, Some(&case["options"])).unwrap();
        let expected = case["html"].as_str().unwrap();
        if html != expected {
            let at = html
                .chars()
                .zip(expected.chars())
                .position(|(a, b)| a != b)
                .unwrap_or(0);
            let from = at.saturating_sub(80);
            panic!(
                "{} differs at {at}:\n rust: {}\n   ts: {}",
                statement.currency,
                html.chars().skip(from).take(200).collect::<String>(),
                expected.chars().skip(from).take(200).collect::<String>()
            );
        }
    }
    // Without options the issuer is the product.
    let statement: BillingStatement =
        decode(VECTORS["html"][1]["statement"].as_object().unwrap().clone()).unwrap();
    let html = render_invoice_html(&statement, None).unwrap();
    assert!(html.contains("<strong>Better IAM</strong>"));
    assert!(html.contains("<title>Draft invoice · 2026-03</title>"));
    assert!(html.contains("<span class=\"badge\">Draft</span>"));
    // A finalized invoice past its due date is overdue.
    let mut overdue = statement.clone();
    overdue.status = "finalized".into();
    overdue.number = "INV-1".into();
    overdue.due_at = 0.0;
    assert!(
        render_invoice_html(&overdue, None)
            .unwrap()
            .contains("<span class=\"badge\">Overdue</span>")
    );
}

#[test]
fn validates_invoice_items() {
    let input = VECTORS["item"]["input"].as_object().unwrap();
    same(
        &invoice_item_input(input).unwrap(),
        &VECTORS["item"]["output"],
    );
    same(
        &invoice_item_input(
            json!({ "description": "Setup", "amount": 100 })
                .as_object()
                .unwrap(),
        )
        .unwrap(),
        &json!({ "description": "Setup", "quantity": 1, "unitAmountMicros": 100_000_000, "amountMicros": 100_000_000 }),
    );
    for (input, expected) in [
        (json!({ "amount": 1 }), "Invalid description"),
        (
            json!({ "description": "x" }),
            "amount must be an amount from -1000000000 to 1000000000",
        ),
        (
            json!({ "description": "x", "amount": 2e9 }),
            "amount must be an amount from -1000000000 to 1000000000",
        ),
        (
            json!({ "description": "x", "amount": 1, "quantity": 0 }),
            "quantity must be a positive number",
        ),
        (
            json!({ "description": "x", "amount": 1, "quantity": null }),
            "quantity must be a positive number",
        ),
        (
            json!({ "description": "x", "amount": 1, "period": "2026-1" }),
            "period must be a month such as 2026-09",
        ),
        (
            json!({ "description": "x", "amount": 1, "metadata": [] }),
            "Expected an object",
        ),
        (
            json!({ "description": "x", "amount": 1, "metadata": { "k": 1 } }),
            "Invalid metadata.k",
        ),
    ] {
        assert_eq!(
            message(invoice_item_input(input.as_object().unwrap())),
            expected,
            "{input}"
        );
    }
    let many: serde_json::Map<String, Value> = (0..21)
        .map(|index| (format!("k{index}"), json!("v")))
        .collect();
    assert_eq!(
        message(invoice_item_input(
            json!({ "description": "x", "amount": 1, "metadata": many })
                .as_object()
                .unwrap()
        )),
        "metadata may hold at most 20 entries"
    );
    assert_eq!(
        signed_amount_micros(Some(&json!(-0.5)), "amount").unwrap(),
        -500_000.0
    );
}

#[test]
fn validates_coupons_and_credit_note_reasons() {
    let input = VECTORS["coupon"]["input"].as_object().unwrap();
    let now = VECTORS["coupon"]["now"].as_f64().unwrap();
    same(
        &coupon_settings(input, now).unwrap(),
        &VECTORS["coupon"]["output"],
    );
    same(
        &coupon_settings(
            json!({ "code": "welcome", "name": " Welcome ", "amountOff": 25, "duration": "forever", "redeemBy": 2000 })
                .as_object()
                .unwrap(),
            1000.0,
        )
        .unwrap(),
        &json!({ "code": "WELCOME", "name": "Welcome", "duration": "forever", "amountOffMicros": 25_000_000, "redeemBy": 2000 }),
    );
    assert_eq!(coupon_code(Some(&json!(" ab_1 "))).unwrap(), "AB_1");
    for bad in [json!("ab"), json!("-abc"), json!(7), json!("a b c")] {
        assert_eq!(
            message(coupon_code(Some(&bad))),
            "code must be 3-32 letters, digits, - or _"
        );
    }
    for (input, expected) in [
        (
            json!({ "code": "ABC" }),
            "Give either percentOff or amountOff",
        ),
        (
            json!({ "code": "ABC", "percentOff": 10, "amountOff": 1 }),
            "Give either percentOff or amountOff",
        ),
        (
            json!({ "code": "ABC", "percentOff": 0 }),
            "percentOff must be above 0 and at most 100",
        ),
        (
            json!({ "code": "ABC", "amountOff": -1 }),
            "amountOff must be above 0",
        ),
        (
            json!({ "code": "ABC", "percentOff": 5, "duration": "weekly" }),
            "duration must be 'once', 'repeating' or 'forever'",
        ),
        (
            json!({ "code": "ABC", "percentOff": 5, "duration": "repeating" }),
            "Invalid durationInMonths",
        ),
        (
            json!({ "code": "ABC", "percentOff": 5, "durationInMonths": 2 }),
            "durationInMonths is only for repeating coupons",
        ),
        (
            json!({ "code": "ABC", "percentOff": 5, "maxRedemptions": 0 }),
            "Invalid maxRedemptions",
        ),
        (
            json!({ "code": "ABC", "percentOff": 5, "redeemBy": 1000 }),
            "Invalid redeemBy",
        ),
    ] {
        assert_eq!(
            message(coupon_settings(input.as_object().unwrap(), 1000.0)),
            expected,
            "{input}"
        );
    }
    assert_eq!(credit_note_reason(None).unwrap(), json!("other"));
    assert_eq!(
        credit_note_reason(Some(&json!(null))).unwrap(),
        json!("other")
    );
    assert_eq!(
        credit_note_reason(Some(&json!("duplicate"))).unwrap(),
        json!("duplicate")
    );
    assert_eq!(
        message(credit_note_reason(Some(&json!("refund")))),
        "reason must be one of duplicate, fraudulent, order_change, product_unsatisfactory, other"
    );
}
