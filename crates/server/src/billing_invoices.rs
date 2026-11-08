//! Port of `packages/server/src/billing-invoices.ts`.
//!
//! Invoicing helpers without storage: validation of invoice items, coupons and credit notes, and the printable
//! invoice (HTML a browser can save as PDF, like a hosted invoice page). The transactional side lives in
//! billing_service.rs.

use better_iam_core::{IamResult, js as core_js};
use serde_json::{Map, Value, json};

use crate::billing::{
    BillingCreditNote, BillingStatement, InvoiceIssuer, StatementLine, billing_period, cents,
    due_of, js_round, micros, paid_of, units,
};
use crate::js::{invalid_input, number};
use crate::validation::{integer, object, text};

/// An amount in currency units that may be negative (a credit item), as micros.
pub fn signed_amount_micros(value: Option<&Value>, name: &str) -> IamResult<f64> {
    match value.and_then(core_js::as_number) {
        Some(value) if value.is_finite() && value.abs() <= 1e9 => Ok(micros(value * 1_000_000.0)),
        _ => Err(invalid_input(format!(
            "{name} must be an amount from -1000000000 to 1000000000"
        ))),
    }
}

/// Validated invoice item input: description, unit amount (currency units, negative for a credit), quantity,
/// period.
pub fn invoice_item_input(input: &Map<String, Value>) -> IamResult<Value> {
    let description =
        core_js::trim(&text(input.get("description"), "description", 256)?).to_owned();
    let unit_amount_micros = signed_amount_micros(input.get("amount"), "amount")?;
    let quantity = match input.get("quantity") {
        None => 1.0,
        Some(value) => match core_js::as_number(value) {
            Some(quantity) if quantity.is_finite() && quantity > 0.0 && quantity <= 1e9 => quantity,
            _ => return Err(invalid_input("quantity must be a positive number")),
        },
    };
    let period = match input.get("period") {
        None => None,
        value => Some(billing_period(value, None)?),
    };
    let mut metadata: Option<Map<String, Value>> = None;
    if let Some(value) = input.get("metadata") {
        let entries = core_js::entries(object(Some(value))?);
        if entries.len() > 20 {
            return Err(invalid_input("metadata may hold at most 20 entries"));
        }
        let mut result = Map::new();
        for (key, raw) in entries {
            let key = text(Some(&Value::String(key.clone())), "metadata key", 64)?;
            let value = text(Some(raw), &format!("metadata.{key}"), 256)?;
            result.insert(key, Value::String(value));
        }
        metadata = Some(result);
    }
    let mut item = Map::new();
    item.insert("description".into(), Value::String(description));
    item.insert("quantity".into(), number(quantity));
    item.insert("unitAmountMicros".into(), number(unit_amount_micros));
    item.insert(
        "amountMicros".into(),
        number(cents(unit_amount_micros * quantity)),
    );
    if let Some(period) = period.filter(|period| !period.is_empty()) {
        item.insert("period".into(), Value::String(period));
    }
    if let Some(metadata) = metadata {
        item.insert("metadata".into(), Value::Object(metadata));
    }
    Ok(Value::Object(item))
}

/// `/^[A-Z0-9][A-Z0-9_-]{2,31}$/`.
fn is_coupon_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    (3..=32).contains(&bytes.len())
        && (bytes[0].is_ascii_uppercase() || bytes[0].is_ascii_digit())
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

/// A coupon code: 3-32 letters, digits, `-` or `_` (stored in upper case).
pub fn coupon_code(value: Option<&Value>) -> IamResult<String> {
    let code = match value {
        Some(Value::String(text)) => core_js::trim(text).to_uppercase(),
        _ => String::new(),
    };
    if !is_coupon_code(&code) {
        return Err(invalid_input("code must be 3-32 letters, digits, - or _"));
    }
    Ok(code)
}

/// Validated coupon settings: `percentOff` or `amountOff`, a duration, and redemption limits.
pub fn coupon_settings(input: &Map<String, Value>, now: f64) -> IamResult<Value> {
    let code = coupon_code(input.get("code"))?;
    let name = match input.get("name") {
        None => code.clone(),
        value => core_js::trim(&text(value, "name", 128)?).to_owned(),
    };
    let has_percent = crate::js::defined(input.get("percentOff")).is_some();
    let has_amount = crate::js::defined(input.get("amountOff")).is_some();
    if has_percent == has_amount {
        return Err(invalid_input("Give either percentOff or amountOff"));
    }
    let mut percent_off = None;
    if has_percent {
        match input.get("percentOff").and_then(core_js::as_number) {
            Some(value) if value.is_finite() && value > 0.0 && value <= 100.0 => {
                percent_off = Some(js_round(value * 1000.0) / 1000.0);
            }
            _ => {
                return Err(invalid_input("percentOff must be above 0 and at most 100"));
            }
        }
    }
    let mut amount_off_micros = None;
    if has_amount {
        let micros = signed_amount_micros(input.get("amountOff"), "amountOff")?;
        if micros <= 0.0 {
            return Err(invalid_input("amountOff must be above 0"));
        }
        amount_off_micros = Some(micros);
    }
    let duration = crate::js::defined(input.get("duration"))
        .cloned()
        .unwrap_or_else(|| json!("once"));
    let duration = match duration.as_str() {
        Some(value @ ("once" | "repeating" | "forever")) => value.to_owned(),
        _ => {
            return Err(invalid_input(
                "duration must be 'once', 'repeating' or 'forever'",
            ));
        }
    };
    let duration_in_months = if duration == "repeating" {
        Some(integer(
            input.get("durationInMonths"),
            "durationInMonths",
            1.0,
            120.0,
        )?)
    } else {
        None
    };
    if duration != "repeating" && input.get("durationInMonths").is_some() {
        return Err(invalid_input(
            "durationInMonths is only for repeating coupons",
        ));
    }
    let max_redemptions = match input.get("maxRedemptions") {
        None => None,
        value => Some(integer(value, "maxRedemptions", 1.0, 1_000_000.0)?),
    };
    let redeem_by = match input.get("redeemBy") {
        None => None,
        value => Some(integer(
            value,
            "redeemBy",
            now + 1.0,
            core_js::MAX_SAFE_INTEGER,
        )?),
    };
    let mut settings = Map::new();
    settings.insert("code".into(), Value::String(code));
    settings.insert("name".into(), Value::String(name));
    settings.insert("duration".into(), Value::String(duration));
    if let Some(percent_off) = percent_off {
        settings.insert("percentOff".into(), number(percent_off));
    }
    if let Some(amount_off_micros) = amount_off_micros {
        settings.insert("amountOffMicros".into(), number(amount_off_micros));
    }
    if let Some(duration_in_months) = duration_in_months {
        settings.insert("durationInMonths".into(), number(duration_in_months));
    }
    if let Some(max_redemptions) = max_redemptions {
        settings.insert("maxRedemptions".into(), number(max_redemptions));
    }
    if let Some(redeem_by) = redeem_by {
        settings.insert("redeemBy".into(), number(redeem_by));
    }
    Ok(Value::Object(settings))
}

const CREDIT_NOTE_REASONS: [&str; 5] = [
    "duplicate",
    "fraudulent",
    "order_change",
    "product_unsatisfactory",
    "other",
];

/// A credit note reason (Stripe's list).
pub fn credit_note_reason(value: Option<&Value>) -> IamResult<crate::billing::CreditNoteReason> {
    let reason = crate::js::defined(value)
        .cloned()
        .unwrap_or_else(|| json!("other"));
    match reason.as_str() {
        Some(text) if CREDIT_NOTE_REASONS.contains(&text) => Ok(reason),
        _ => Err(invalid_input(format!(
            "reason must be one of {}",
            CREDIT_NOTE_REASONS.join(", ")
        ))),
    }
}

/// `value.replace(/[&<>"']/g, ...)`.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// The shortest decimal digits of a finite, non-negative number and the position of its decimal point
/// (`value = 0.d1d2d3... × 10^point`), as ICU reads a double before rounding it.
fn shortest_digits(value: f64) -> (Vec<u8>, i32) {
    if value == 0.0 {
        return (vec![0], 1);
    }
    let text = format!("{value:e}");
    let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let digits: Vec<u8> = mantissa
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect();
    (digits, exponent + 1)
}

/// Digits of `value` rounded half away from zero to `fraction` decimals: the integer part and the fraction part.
fn round_decimal(value: f64, fraction: usize) -> (String, String) {
    let (digits, point) = shortest_digits(value);
    // Digits of value × 10^fraction before the cut, as a big decimal string.
    let keep = point + fraction as i32;
    let mut kept: Vec<u8> = if keep <= 0 {
        Vec::new()
    } else {
        (0..keep as usize)
            .map(|index| digits.get(index).copied().unwrap_or(0))
            .collect()
    };
    let next = if keep < 0 {
        0
    } else {
        digits.get(keep as usize).copied().unwrap_or(0)
    };
    if next >= 5 {
        let mut index = kept.len();
        loop {
            if index == 0 {
                kept.insert(0, 1);
                break;
            }
            index -= 1;
            if kept[index] == 9 {
                kept[index] = 0;
            } else {
                kept[index] += 1;
                break;
            }
        }
    }
    while kept.len() < fraction + 1 {
        kept.insert(0, 0);
    }
    let split = kept.len() - fraction;
    let integer: String = kept[..split]
        .iter()
        .map(|digit| char::from(b'0' + digit))
        .collect();
    let integer = integer.trim_start_matches('0');
    let integer = if integer.is_empty() { "0" } else { integer };
    let fraction_text: String = kept[split..]
        .iter()
        .map(|digit| char::from(b'0' + digit))
        .collect();
    (integer.to_owned(), fraction_text)
}

/// `1234567` → `1,234,567`.
fn group(integer: &str) -> String {
    let mut out = String::new();
    for (index, character) in integer.chars().enumerate() {
        if index > 0 && (integer.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(character);
    }
    out
}

/// `Intl.NumberFormat('en-US', ...)` of a number with grouping, `minimum` to `maximum` fraction digits, without the
/// sign.
fn decimal_text(value: f64, minimum: usize, maximum: usize) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return "∞".to_owned();
    }
    let (integer, mut fraction) = round_decimal(value.abs(), maximum);
    while fraction.len() > minimum && fraction.ends_with('0') {
        fraction.pop();
    }
    if fraction.is_empty() {
        group(&integer)
    } else {
        format!("{}.{fraction}", group(&integer))
    }
}

/// The en-US currency symbols that are not the ISO code (CLDR `en`).
fn currency_symbol(code: &str) -> &str {
    match code {
        "AUD" => "A$",
        "BRL" => "R$",
        "CAD" => "CA$",
        "CNY" => "CN¥",
        "EUR" => "€",
        "GBP" => "£",
        "HKD" => "HK$",
        "ILS" => "₪",
        "INR" => "₹",
        "JPY" => "¥",
        "KRW" => "₩",
        "MXN" => "MX$",
        "NZD" => "NZ$",
        "PHP" => "₱",
        "TWD" => "NT$",
        "USD" => "$",
        "VND" => "₫",
        "XAF" => "FCFA",
        "XCD" => "EC$",
        "XOF" => "F\u{202F}CFA",
        "XPF" => "CFPF",
        "XXX" => "¤",
        other => other,
    }
}

/// `value.toFixed(digits)`.
fn to_fixed(value: f64, digits: usize) -> String {
    if !value.is_finite() {
        return core_js::number_to_string(value);
    }
    let exact = format!("{:.*}", digits + 40, value.abs());
    let (integer, rest) = exact.split_once('.').unwrap_or((&exact, ""));
    let mut kept: Vec<u8> = integer
        .bytes()
        .chain(rest.bytes().take(digits))
        .map(|b| b - b'0')
        .collect();
    if rest.as_bytes().get(digits).is_some_and(|b| *b >= b'5') {
        let mut index = kept.len();
        loop {
            if index == 0 {
                kept.insert(0, 1);
                break;
            }
            index -= 1;
            if kept[index] == 9 {
                kept[index] = 0;
            } else {
                kept[index] += 1;
                break;
            }
        }
    }
    let split = kept.len() - digits;
    let text: String = kept.iter().map(|digit| char::from(b'0' + digit)).collect();
    let body = if digits == 0 {
        text
    } else {
        format!("{}.{}", &text[..split], &text[split..])
    };
    if value < 0.0 && kept.iter().any(|digit| *digit != 0) {
        format!("-{body}")
    } else {
        body
    }
}

/// Money for invoices: cents, or six decimals for fractions of a cent (per-token and per-call prices).
fn formatter(currency: &str) -> impl Fn(f64) -> String + '_ {
    move |micros: f64| {
        let digits = if micros != 0.0 && micros.abs() < 10_000.0 {
            6
        } else {
            2
        };
        let amount = if digits == 2 {
            units(micros)
        } else {
            micros / 1_000_000.0
        };
        // Intl accepts any well-formed code (three ASCII letters, any case) and throws a RangeError otherwise.
        if currency.len() != 3 || !currency.bytes().all(|b| b.is_ascii_alphabetic()) {
            return format!("{currency} {}", to_fixed(amount, digits));
        }
        let code = currency.to_ascii_uppercase();
        let symbol = currency_symbol(&code);
        let number = decimal_text(amount, digits, digits);
        // ICU inserts a no-break space between a symbol that ends in a letter and the digits.
        let spacing = symbol
            .chars()
            .last()
            .is_some_and(|last| last.is_alphanumeric());
        let sign = if amount.is_sign_negative() && !amount.is_nan() {
            "-"
        } else {
            ""
        };
        format!(
            "{sign}{symbol}{}{number}",
            if spacing { "\u{a0}" } else { "" }
        )
    }
}

/// `new Date(at).toISOString().slice(0, 10)`.
fn day(at: f64) -> IamResult<String> {
    core_js::iso_string(at)
        .map(|text| text[..10].to_owned())
        .ok_or_else(crate::js::internal_error)
}

/// `value.toLocaleString('en-US', { maximumFractionDigits: 4 })`.
fn quantity_text(value: f64) -> String {
    let text = decimal_text(value, 0, 4);
    if value.is_sign_negative() && !value.is_nan() {
        format!("-{text}")
    } else {
        text
    }
}

fn line_rows(line: &StatementLine, money: &dyn Fn(f64) -> String) -> IamResult<String> {
    let tiers = line.tiers.as_deref().unwrap_or(&[]);
    let tier_number =
        |tier: &Value, key: &str| tier.get(key).map(core_js::to_number).unwrap_or(f64::NAN);
    let unit = match line.unit_amount_micros {
        Some(amount) => money(amount),
        None if tiers.len() == 1 => money(tier_number(&tiers[0], "unitAmountMicros")),
        None => String::new(),
    };
    let mut details: Vec<String> = Vec::new();
    if let Some(service) = &line.service_period {
        let start = service
            .get("start")
            .map(core_js::to_number)
            .unwrap_or(f64::NAN);
        let end = service
            .get("end")
            .map(core_js::to_number)
            .unwrap_or(f64::NAN);
        details.push(format!("{} to {}", day(start)?, day(end - 1.0)?));
    }
    if let Some(proration) = line.proration {
        details.push(format!(
            "{}% of the month",
            core_js::number_to_string(js_round(proration * 1000.0) / 10.0)
        ));
    }
    if let Some(included) = line
        .included_quantity
        .filter(|value| *value != 0.0 && !value.is_nan())
    {
        details.push(format!("{} included", quantity_text(included)));
    }
    if line
        .price
        .as_ref()
        .and_then(|price| price.get("source"))
        .and_then(Value::as_str)
        == Some("plan")
    {
        details.push("plan price".to_owned());
    }
    if let Some(adjusted) = line.adjusted_from_micros {
        details.push(format!("adjusted from {}", money(adjusted)));
    }
    let main = format!(
        "<tr><td>{}{}</td><td class=\"num\">{} {}</td><td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
        escape(&line.name),
        if details.is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"muted\">{}</div>",
                escape(&details.join(" · "))
            )
        },
        escape(&quantity_text(line.quantity)),
        escape(&line.unit),
        escape(&unit),
        escape(&money(line.amount_micros))
    );
    let mut sub_lines = String::new();
    if tiers.len() > 1 {
        for tier in tiers {
            let from = tier_number(tier, "from");
            let to = tier.get("to");
            let range = match to {
                Some(Value::Null) => format!("Units {} and above", quantity_text(from)),
                other => format!(
                    "Units {}–{}",
                    quantity_text(from),
                    quantity_text(other.map(core_js::to_number).unwrap_or(f64::NAN))
                ),
            };
            let flat = tier
                .get("flatAmountMicros")
                .map(core_js::to_number)
                .filter(|flat| *flat != 0.0 && !flat.is_nan());
            sub_lines.push_str(&format!(
                "<tr class=\"tier\"><td>{}{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
                escape(&range),
                flat.map(|flat| format!(
                    "<div class=\"muted\">{}</div>",
                    escape(&format!("plus {} flat", money(flat)))
                ))
                .unwrap_or_default(),
                escape(&quantity_text(tier_number(tier, "quantity"))),
                escape(&money(tier_number(tier, "unitAmountMicros"))),
                escape(&money(tier_number(tier, "amountMicros")))
            ));
        }
    }
    Ok(main + &sub_lines)
}

/// A string member of a JSON object.
fn member_text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// `block(lines)`: the truthy lines, escaped, with line breaks as `<br>`.
fn block(lines: &[Option<String>]) -> String {
    lines
        .iter()
        .flatten()
        .filter(|line| !line.is_empty())
        .map(|line| escape(line).replace('\n', "<br>"))
        .collect::<Vec<_>>()
        .join("<br>")
}

/// The invoice as a standalone HTML page (print it or save it as PDF): issuer, bill-to, number and dates, lines
/// with tier sub-lines and service periods, discounts, commitment, credit, tax, payments, credit notes, and amount
/// due.
///
/// `options` is `{ issuer?, appName?, creditNotes? }`.
pub fn render_invoice_html(
    statement: &crate::billing::BillingStatement,
    options: Option<&Value>,
) -> IamResult<String> {
    let options = options.cloned().unwrap_or_else(|| json!({}));
    let issuer: InvoiceIssuer = match crate::js::defined(options.get("issuer")) {
        Some(Value::Object(map)) => crate::port::decode(map.clone())?,
        Some(_) => return Err(crate::js::internal_error()),
        None => InvoiceIssuer {
            name: member_text(&options, "appName")
                .unwrap_or("Better IAM")
                .to_owned(),
            address: None,
            tax_id: None,
            email: None,
            url: None,
            payment_instructions: None,
            extra: Map::new(),
        },
    };
    let credit_notes: Vec<BillingCreditNote> = match crate::js::defined(options.get("creditNotes"))
    {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Object(map) => crate::port::decode(map.clone()),
                _ => Err(crate::js::internal_error()),
            })
            .collect::<IamResult<_>>()?,
        _ => Vec::new(),
    };
    render(statement, &issuer, &credit_notes)
}

fn render(
    statement: &BillingStatement,
    issuer: &InvoiceIssuer,
    credit_notes: &[BillingCreditNote],
) -> IamResult<String> {
    let money_fn = formatter(&statement.currency);
    let money: &dyn Fn(f64) -> String = &money_fn;
    let title = if statement.status == "draft" {
        format!("Draft invoice · {}", statement.period)
    } else {
        format!("Invoice {}", statement.number)
    };
    let read =
        |value: &Value, key: &str| value.get(key).map(core_js::to_number).unwrap_or(f64::NAN);
    let mut totals: Vec<(String, String, bool)> =
        vec![("Subtotal".into(), money(statement.subtotal_micros), false)];
    if let Some(discount) = statement.discount.as_ref().filter(|d| !d.is_null()) {
        totals.push((
            format!(
                "Discount ({}%)",
                crate::js::js_string(discount.get("percent"))
            ),
            money(-read(discount, "amountMicros")),
            false,
        ));
    }
    if let Some(commitment) = statement.commitment.as_ref().filter(|c| !c.is_null())
        && read(commitment, "trueUpMicros") > 0.0
    {
        totals.push((
            format!(
                "Minimum commitment ({}) true-up",
                money(read(commitment, "minimumMicros"))
            ),
            money(read(commitment, "trueUpMicros")),
            false,
        ));
    }
    for coupon in statement.coupons.as_deref().unwrap_or(&[]) {
        let name = crate::js::js_string(coupon.get("name"));
        let code = crate::js::js_string(coupon.get("code"));
        totals.push((
            if name == code {
                code
            } else {
                format!("{name} ({code})")
            },
            money(-read(coupon, "amountMicros")),
            false,
        ));
    }
    if statement.credits_micros != 0.0 && !statement.credits_micros.is_nan() {
        totals.push((
            "Credit applied".into(),
            money(-statement.credits_micros),
            false,
        ));
    }
    if let Some(tax) = statement.tax.as_ref().filter(|t| !t.is_null()) {
        totals.push((
            format!(
                "{} ({}%)",
                crate::js::js_string(tax.get("label")),
                crate::js::js_string(tax.get("ratePercent"))
            ),
            money(read(tax, "amountMicros")),
            false,
        ));
    }
    totals.push(("Total".into(), money(statement.total_micros), true));
    let paid = paid_of(statement);
    if paid != 0.0 && !paid.is_nan() {
        totals.push(("Paid".into(), money(-paid), false));
    }
    if let Some(notes) = statement
        .credit_notes_micros
        .filter(|notes| *notes != 0.0 && !notes.is_nan())
    {
        totals.push(("Credit notes".into(), money(-notes), false));
    }
    totals.push(("Amount due".into(), money(due_of(statement)), true));
    let bill_to = &statement.bill_to;
    let status = if statement.status == "finalized" {
        if statement.due_at < crate::utils::date_now() {
            "Overdue".to_owned()
        } else {
            "Open".to_owned()
        }
    } else {
        let mut characters = statement.status.chars();
        let first = characters.next().ok_or_else(crate::js::internal_error)?;
        format!("{}{}", first.to_uppercase(), characters.as_str())
    };
    let bill_to_text = |key: &str| member_text(bill_to, key).map(str::to_owned);
    let emails = bill_to
        .get("emails")
        .and_then(Value::as_array)
        .map(|emails| {
            emails
                .iter()
                .map(|email| crate::js::js_string(Some(email)))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let mut lines_html: Vec<String> = Vec::new();
    for line in &statement.lines {
        lines_html.push(line_rows(line, money)?);
    }
    let totals_html: String = totals
        .iter()
        .map(|(label, value, strong)| {
            format!(
                "<tr{}><td>{}</td><td class=\"num\">{}</td></tr>",
                if *strong { " class=\"strong\"" } else { "" },
                escape(label),
                escape(value)
            )
        })
        .collect();
    let payments = statement.payments.as_deref().unwrap_or(&[]);
    let payments_html = if payments.is_empty() {
        String::new()
    } else {
        let mut rows = String::new();
        for payment in payments {
            rows.push_str(&format!(
                "<tr><td>{}</td><td>{}{}</td><td class=\"num\">{}</td></tr>",
                escape(&day(payment.received_at)?),
                escape(&payment.method),
                payment
                    .reference
                    .as_deref()
                    .filter(|reference| !reference.is_empty())
                    .map(|reference| format!(" · {}", escape(reference)))
                    .unwrap_or_default(),
                escape(&money(payment.amount_micros))
            ));
        }
        format!("<h3>Payments</h3><table><tbody>{rows}</tbody></table>")
    };
    let notes_html = if credit_notes.is_empty() {
        String::new()
    } else {
        let rows: String = credit_notes
            .iter()
            .map(|note| {
                format!(
                    "<tr><td>{}</td><td>{}{}</td><td class=\"num\">{}</td></tr>",
                    escape(&note.number),
                    escape(&crate::js::js_string(Some(&note.reason)).replacen('_', " ", 1)),
                    note.memo
                        .as_deref()
                        .filter(|memo| !memo.is_empty())
                        .map(|memo| format!(" · {}", escape(memo)))
                        .unwrap_or_default(),
                    escape(&money(note.amount_micros))
                )
            })
            .collect();
        format!("<h3>Credit notes</h3><table><tbody>{rows}</tbody></table>")
    };
    let instructions = issuer
        .payment_instructions
        .as_deref()
        .filter(|text| !text.is_empty())
        .map(|text| format!("<div class=\"notes\">{}</div>", escape(text)))
        .unwrap_or_default();
    let hash = if statement.hash.is_empty() {
        String::new()
    } else {
        format!(
            "<p class=\"muted\">Content hash {}</p>",
            escape(&statement.hash)
        )
    };
    let issuer_block = block(&[
        issuer.address.clone(),
        issuer
            .tax_id
            .as_deref()
            .filter(|tax_id| !tax_id.is_empty())
            .map(|tax_id| format!("Tax ID {tax_id}")),
        issuer.email.clone(),
        issuer.url.clone(),
    ]);
    let bill_to_block = block(&[
        bill_to_text("address"),
        bill_to_text("taxId")
            .filter(|value| !value.is_empty())
            .map(|value| format!("Tax ID {value}")),
        bill_to_text("purchaseOrder")
            .filter(|value| !value.is_empty())
            .map(|value| format!("PO {value}")),
        bill_to_text("costCenter")
            .filter(|value| !value.is_empty())
            .map(|value| format!("Cost center {value}")),
        Some(emails).filter(|emails| !emails.is_empty()),
    ]);
    let bill_to_name = match bill_to.get("companyName") {
        Some(value) if !value.is_null() => crate::js::js_string(Some(value)),
        _ => crate::js::js_string(bill_to.get("name")),
    };
    Ok(format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{title}</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>
body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111;margin:0;background:#f5f6f8}}
main{{max-width:800px;margin:24px auto;background:#fff;padding:40px;border-radius:8px}}
h1{{font-size:22px;margin:0}}header{{display:flex;justify-content:space-between;gap:24px;margin-bottom:32px}}
.muted{{color:#666;font-size:12px}}.parties{{display:flex;justify-content:space-between;gap:24px;margin-bottom:24px;font-size:14px}}
table{{width:100%;border-collapse:collapse;font-size:14px}}th{{text-align:left;border-bottom:1px solid #ddd;padding:8px 4px;font-weight:600}}
td{{padding:8px 4px;border-bottom:1px solid #f0f0f0;vertical-align:top}}.num{{text-align:right;white-space:nowrap}}
tr.tier td{{color:#555;font-size:12px;padding-left:20px}}.totals{{margin-left:auto;width:320px;margin-top:16px}}
.totals td{{border:none;padding:4px}}.totals .strong td{{font-weight:700;border-top:1px solid #ddd}}
.badge{{display:inline-block;padding:2px 8px;border-radius:999px;background:#eef;font-size:12px}}
.notes{{margin-top:24px;font-size:13px;white-space:pre-wrap}}@media print{{body{{background:#fff}}main{{margin:0;box-shadow:none}}}}
</style></head><body><main>
<header><div><h1>{title}</h1><div class="muted">{dates}</div></div><div><span class="badge">{status}</span></div></header>
<section class="parties"><div><strong>{issuer_name}</strong><br>{issuer_block}</div>
<div><span class="muted">Bill to</span><br><strong>{bill_to_name}</strong><br>{bill_to_block}</div></section>
<table><thead><tr><th>Description</th><th class="num">Quantity</th><th class="num">Unit price</th><th class="num">Amount</th></tr></thead><tbody>
{lines}
</tbody></table>
<table class="totals"><tbody>{totals_html}</tbody></table>
{payments_html}
{notes_html}
{instructions}
{hash}
</main></body></html>"#,
        title = escape(&title),
        dates = escape(&format!(
            "{} · issued {} · due {}",
            statement.period,
            day(statement.issued_at)?,
            day(statement.due_at)?
        )),
        status = escape(&status),
        issuer_name = escape(&issuer.name),
        bill_to_name = escape(&bill_to_name),
        lines = lines_html.join("\n"),
    ))
}
