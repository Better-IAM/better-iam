//! JavaScript semantics the TypeScript implementation relies on, reproduced exactly (Rust-only module).
//!
//! The TypeScript code base stores records as `JSON.stringify` output, compares strings by UTF-16 code units, counts
//! string lengths in UTF-16 code units, and iterates objects in JavaScript property order (array-index keys first, in
//! ascending numeric order, then the other keys in insertion order). Everything that must agree byte for byte with the
//! TypeScript implementation (stored record text, SQL parameters, hashes, signatures) goes through this module.
//!
//! JSON values are `serde_json::Value` with the `preserve_order` feature, so object members keep insertion order like
//! a JavaScript object built by `JSON.parse`. Numbers are JavaScript doubles: integers read beyond 2^53 are rounded to
//! the nearest double, exactly as `JSON.parse` does.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;

use serde_json::{Map, Number, Value};

/// `Number.MAX_SAFE_INTEGER`.
pub const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// The value of a JSON number as a JavaScript double.
pub fn number_value(number: &Number) -> f64 {
    number.as_f64().unwrap_or(f64::NAN)
}

/// The value of a JSON value as a JavaScript number, when it is one (`typeof value === 'number'`).
pub fn as_number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => Some(number_value(number)),
        _ => None,
    }
}

/// A JSON number from a JavaScript double; integral doubles within the safe range become JSON integers so that
/// `serde_json` comparisons and `as_i64`/`as_u64` work as callers expect. Non-finite numbers have no JSON form.
pub fn number(value: f64) -> Option<Value> {
    if !value.is_finite() {
        return None;
    }
    if value.fract() == 0.0
        && value.abs() <= MAX_SAFE_INTEGER
        && !(value == 0.0 && value.is_sign_negative())
    {
        if value >= 0.0 {
            return Some(Value::Number(Number::from(value as u64)));
        }
        return Some(Value::Number(Number::from(value as i64)));
    }
    Number::from_f64(value).map(Value::Number)
}

/// `Number.isSafeInteger(value)`.
pub fn is_safe_integer(value: f64) -> bool {
    value.is_finite() && value.fract() == 0.0 && value.abs() <= MAX_SAFE_INTEGER
}

/// `String(value)` for a finite or non-finite JavaScript number (`Number.prototype.toString()`), which is also what
/// `JSON.stringify` writes for finite numbers.
pub fn number_to_string(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_owned();
    }
    if value == 0.0 {
        return "0".to_owned();
    }
    let mut buffer = ryu_js::Buffer::new();
    buffer.format_finite(value).to_owned()
}

/// The length of a string in UTF-16 code units (`string.length`).
pub fn utf16_len(value: &str) -> usize {
    value.chars().map(char::len_utf16).sum()
}

/// String comparison by UTF-16 code units: JavaScript's `<`, `>` and the default `Array.prototype.sort` order.
pub fn cmp_utf16(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

/// `WhiteSpace` and `LineTerminator` as `String.prototype.trim` removes them.
pub fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

/// `String.prototype.trim`.
pub fn trim(value: &str) -> &str {
    value.trim_matches(is_js_whitespace)
}

/// `/\s/` (JavaScript's whitespace class, the same set `trim` removes).
pub fn has_js_whitespace(value: &str) -> bool {
    value.chars().any(is_js_whitespace)
}

/// `String.prototype.toLowerCase` (Unicode default case conversion, including the final-sigma rule).
pub fn to_lower(value: &str) -> String {
    value.to_lowercase()
}

/// True for a canonical array index (`"0"` to `"4294967294"`): JavaScript orders such property keys first.
pub fn is_array_index(key: &str) -> bool {
    let bytes = key.as_bytes();
    if bytes.is_empty() || bytes.len() > 10 || !bytes.iter().all(u8::is_ascii_digit) {
        return false;
    }
    if bytes.len() > 1 && bytes[0] == b'0' {
        return false;
    }
    key.parse::<u64>().is_ok_and(|index| index < 4_294_967_295)
}

/// The members of an object in JavaScript property order: array-index keys ascending, then the rest in insertion
/// order (`Object.keys`, `Object.entries`, `for...in`, `JSON.stringify`).
pub fn entries(map: &Map<String, Value>) -> Vec<(&String, &Value)> {
    if !map.keys().any(|key| is_array_index(key)) {
        return map.iter().collect();
    }
    let mut indexes: Vec<(u64, (&String, &Value))> = Vec::new();
    let mut rest = Vec::new();
    for entry in map.iter() {
        if is_array_index(entry.0) {
            indexes.push((entry.0.parse().unwrap_or(0), entry));
        } else {
            rest.push(entry);
        }
    }
    indexes.sort_by_key(|(index, _)| *index);
    indexes
        .into_iter()
        .map(|(_, entry)| entry)
        .chain(rest)
        .collect()
}

/// The keys of an object in JavaScript property order (`Object.keys`).
pub fn keys(map: &Map<String, Value>) -> Vec<&String> {
    entries(map).into_iter().map(|(key, _)| key).collect()
}

/// Appends a string as `JSON.stringify` quotes it.
pub fn quote_into(value: &str, out: &mut String) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `JSON.stringify(string)`.
pub fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    quote_into(value, &mut out);
    out
}

/// `JSON.stringify(value)` for a JSON value: no whitespace, numbers in ECMAScript form, members in JavaScript
/// property order.
pub fn stringify(value: &Value) -> String {
    let mut out = String::new();
    stringify_into(value, &mut out);
    out
}

/// Appends `JSON.stringify(value)`.
pub fn stringify_into(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number_to_string(number_value(number))),
        Value::String(text) => quote_into(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                stringify_into(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (index, (key, item)) in entries(map).into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                quote_into(key, out);
                out.push(':');
                stringify_into(item, out);
            }
            out.push('}');
        }
    }
}

/// `JSON.stringify(value)` for an object.
pub fn stringify_object(map: &Map<String, Value>) -> String {
    let mut out = String::new();
    out.push('{');
    for (index, (key, item)) in entries(map).into_iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        quote_into(key, &mut out);
        out.push(':');
        stringify_into(item, &mut out);
    }
    out.push('}');
    out
}

/// `JSON.parse(text)`. Rust strings cannot hold unpaired UTF-16 surrogates, which `JSON.stringify` writes as
/// `\udXXX` escapes; such escapes read as U+FFFD (the only lossy case, and only for text written by another
/// implementation). [`parse_reporting`] also says which strings that happened to.
pub fn parse(text: &str) -> Result<Value, serde_json::Error> {
    parse_reporting(text).map(|(value, _)| value)
}

/// [`parse`], also returning the strings (as read, with U+FFFD in place of each unpaired surrogate) that held an
/// unpaired surrogate escape, so a caller that must refuse text that is not well-formed UTF-16 (`isWellFormed`, or
/// a lone-surrogate test) can still tell them from a literal U+FFFD. The set is empty when the text had none.
pub fn parse_reporting(text: &str) -> Result<(Value, HashSet<String>), serde_json::Error> {
    match serde_json::from_str(text) {
        Ok(value) => Ok((value, HashSet::new())),
        Err(error) => match replace_lone_surrogates(text) {
            Some((repaired, ill_formed)) => {
                serde_json::from_str(&repaired).map(|value| (value, ill_formed))
            }
            None => Err(error),
        },
    }
}

tokio::task_local! {
    static ILL_FORMED: Arc<HashSet<String>>;
}

/// Runs `future` with the strings [`parse_reporting`] found ill-formed in the request it serves, for
/// [`was_ill_formed`] to consult anywhere in that call chain (on the same task).
pub async fn with_ill_formed<F: Future>(ill_formed: HashSet<String>, future: F) -> F::Output {
    ILL_FORMED.scope(Arc::new(ill_formed), future).await
}

/// Whether `value` stands for a string of the request being served that held an unpaired surrogate before parsing
/// replaced it with U+FFFD (a string that is not well-formed UTF-16 in TypeScript). Only a string containing U+FFFD
/// can be one; outside a [`with_ill_formed`] scope nothing is.
pub fn was_ill_formed(value: &str) -> bool {
    value.contains('\u{fffd}')
        && ILL_FORMED
            .try_with(|set| set.contains(value))
            .unwrap_or(false)
}

fn hex4(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 4 {
        return None;
    }
    let text = std::str::from_utf8(&bytes[..4]).ok()?;
    u32::from_str_radix(text, 16).ok()
}

/// Rewrites unpaired surrogate escapes inside JSON strings as `�`, with the strings that held one (decoded
/// after the rewrite); None when there were none.
fn replace_lone_surrogates(text: &str) -> Option<(String, HashSet<String>)> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut ill_formed = HashSet::new();
    let mut changed = false;
    let mut in_string = false;
    // Where the current string literal begins in `out` (text from `start` on is copied verbatim), and whether it
    // was rewritten.
    let mut literal_start = 0;
    let mut literal_changed = false;
    let mut index = 0;
    let mut start = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if !in_string {
            if byte == b'"' {
                in_string = true;
                literal_start = out.len() + (index - start);
                literal_changed = false;
            }
            index += 1;
            continue;
        }
        match byte {
            b'"' => {
                in_string = false;
                index += 1;
                if literal_changed {
                    out.push_str(&text[start..index]);
                    start = index;
                    if let Ok(decoded) = serde_json::from_str::<String>(&out[literal_start..]) {
                        ill_formed.insert(decoded);
                    }
                }
            }
            b'\\' if index + 1 < bytes.len() && bytes[index + 1] == b'u' => {
                let Some(code) = hex4(&bytes[index + 2..]) else {
                    index += 2;
                    continue;
                };
                if (0xD800..=0xDBFF).contains(&code) {
                    let paired = bytes.len() >= index + 12
                        && bytes[index + 6] == b'\\'
                        && bytes[index + 7] == b'u'
                        && hex4(&bytes[index + 8..])
                            .is_some_and(|low| (0xDC00..=0xDFFF).contains(&low));
                    if paired {
                        index += 12;
                        continue;
                    }
                } else if !(0xDC00..=0xDFFF).contains(&code) {
                    index += 6;
                    continue;
                }
                out.push_str(&text[start..index]);
                out.push_str("\\ufffd");
                changed = true;
                literal_changed = true;
                index += 6;
                start = index;
            }
            b'\\' => index += 2,
            _ => index += 1,
        }
    }
    if !changed {
        return None;
    }
    out.push_str(&text[start..]);
    Some((out, ill_formed))
}

/// JavaScript `===` between two JSON values: primitives by value (numbers as doubles, so `0 === -0`), objects and
/// arrays never (distinct references).
pub fn strict_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => number_value(a) == number_value(b),
        (Value::String(a), Value::String(b)) => a == b,
        _ => false,
    }
}

/// Deep JSON equality: numbers as doubles, object member order ignored, array order kept.
pub fn deep_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| deep_equal(x, y))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, item)| b.get(key).is_some_and(|other| deep_equal(item, other)))
        }
        _ => strict_equal(left, right),
    }
}

/// `typeof value` for a JSON value.
pub fn type_of(value: &Value) -> &'static str {
    match value {
        Value::Null | Value::Array(_) | Value::Object(_) => "object",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
    }
}

/// `Array.prototype.includes` (SameValueZero) for a JSON array and a primitive.
pub fn includes(items: &[Value], wanted: &Value) -> bool {
    items.iter().any(|item| strict_equal(item, wanted))
}

/// `new Date(ms).toISOString()`; None outside the representable range (the JavaScript call throws).
pub fn iso_string(ms: f64) -> Option<String> {
    if !ms.is_finite() || ms.abs() > 8.64e15 {
        return None;
    }
    let ms = ms.trunc() as i64;
    let days = ms.div_euclid(86_400_000);
    let rest = ms.rem_euclid(86_400_000);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second, milli) = (
        rest / 3_600_000,
        (rest / 60_000) % 60,
        (rest / 1000) % 60,
        rest % 1000,
    );
    let year_text = if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else if year < 0 {
        format!("-{:06}", -year)
    } else {
        format!("+{year:06}")
    };
    Some(format!(
        "{year_text}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milli:03}Z"
    ))
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The proleptic Gregorian date of a day count since 1970-01-01.
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Days in a month of the proleptic Gregorian calendar.
pub fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

/// A replacement wall clock (`Date.now()` under a fake clock), in epoch milliseconds; see [`set_wall_clock`].
pub type WallClock = std::sync::Arc<dyn Fn() -> f64 + Send + Sync>;

static WALL_CLOCK: std::sync::RwLock<Option<WallClock>> = std::sync::RwLock::new(None);

/// The current time in epoch milliseconds (`Date.now()`): the clock installed with [`set_wall_clock`], else the
/// system clock. Every crate reads real time through here, so one override (the conformance server's clock
/// endpoint, or a test) moves time for all of them, as replacing `Date.now` does in JavaScript.
pub fn now_ms() -> f64 {
    let clock = WALL_CLOCK
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    match clock {
        Some(clock) => clock(),
        None => system_now_ms(),
    }
}

/// The system clock in epoch milliseconds, ignoring any [`set_wall_clock`] override.
pub fn system_now_ms() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as f64)
        .unwrap_or(0.0)
}

/// Replaces the process wall clock read by [`now_ms`]; `None` returns to the system clock. A clock must not call
/// [`now_ms`] itself (use [`system_now_ms`]).
pub fn set_wall_clock(clock: Option<WallClock>) {
    *WALL_CLOCK
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = clock;
}

/// A JavaScript `TypeError`: a programming error the TypeScript function throws (not an `IamError`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct TypeError(pub String);

/// `Number(value)` for a JSON value (`ToNumber`).
pub fn to_number(value: &Value) -> f64 {
    match value {
        Value::Null => 0.0,
        Value::Bool(flag) => f64::from(u8::from(*flag)),
        Value::Number(number) => number_value(number),
        Value::String(text) => string_to_number(text),
        Value::Array(items) => match items.as_slice() {
            [] => 0.0,
            [item] => match item {
                Value::Array(_) => to_number(item),
                Value::Object(_) => f64::NAN,
                Value::Null => 0.0,
                Value::String(text) => string_to_number(text),
                other => string_to_number(&stringify(other)),
            },
            _ => f64::NAN,
        },
        Value::Object(_) => f64::NAN,
    }
}

/// `StringToNumber`: decimal literals (with `Infinity`), `0x`/`0o`/`0b` integers, whitespace trimmed, empty is 0.
pub fn string_to_number(text: &str) -> f64 {
    let text = trim(text);
    if text.is_empty() {
        return 0.0;
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ] {
        if let Some(digits) = text.strip_prefix(prefix) {
            if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                return f64::NAN;
            }
            return digits.chars().fold(0.0, |sum, c| {
                sum * f64::from(radix) + f64::from(c.to_digit(radix).unwrap_or(0))
            });
        }
    }
    let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
    if unsigned == "Infinity" {
        return if text.starts_with('-') {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        };
    }
    let valid = !unsigned.is_empty()
        && unsigned
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-'))
        && unsigned
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit() || c == '.');
    if !valid {
        return f64::NAN;
    }
    text.parse::<f64>().unwrap_or(f64::NAN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn numbers_print_like_javascript() {
        assert_eq!(number_to_string(1e21), "1e+21");
        assert_eq!(number_to_string(0.1 + 0.2), "0.30000000000000004");
        assert_eq!(number_to_string(-0.0), "0");
        assert_eq!(number_to_string(5e-324), "5e-324");
        assert_eq!(number_to_string(2f64.powi(64)), "18446744073709552000");
        assert_eq!(number_to_string(100.0), "100");
    }

    #[test]
    fn stringify_orders_index_keys_first() {
        let value: Value =
            serde_json::from_str(r#"{"b":1,"2":2,"a":[1.5,"\u0001"],"1":true}"#).unwrap();
        assert_eq!(
            stringify(&value),
            r#"{"1":true,"2":2,"b":1,"a":[1.5,"\u0001"]}"#
        );
        assert_eq!(stringify(&json!(1.0)), "1");
    }

    #[test]
    fn parses_lone_surrogates_lossily() {
        assert_eq!(
            parse(r#"{"a":"x\ud800"}"#).unwrap(),
            json!({"a": "x\u{fffd}"})
        );
        assert_eq!(parse(r#"["😀"]"#).unwrap(), json!(["😀"]));
    }

    #[test]
    fn reports_the_strings_that_held_lone_surrogates() {
        let (value, ill_formed) = parse_reporting(
            r#"{"a":"key-\ud800","b":["key-\udc00x","�","ok😀"],"c\ud800":"x\\ud800"}"#,
        )
        .unwrap();
        assert_eq!(
            value,
            json!({"a": "key-\u{fffd}", "b": ["key-\u{fffd}x", "\u{fffd}", "ok😀"], "c\u{fffd}": "x\\ud800"})
        );
        let mut found: Vec<&str> = ill_formed.iter().map(String::as_str).collect();
        found.sort_unstable();
        assert_eq!(found, ["c\u{fffd}", "key-\u{fffd}", "key-\u{fffd}x"]);
        // A literal U+FFFD (escaped or not) is well-formed text.
        assert!(parse_reporting(r#"["�","�"]"#).unwrap().1.is_empty());
    }

    #[tokio::test]
    async fn ill_formed_strings_are_known_only_inside_their_scope() {
        let (_, ill_formed) = parse_reporting(r#"["key-\ud800"]"#).unwrap();
        assert!(!was_ill_formed("key-\u{fffd}"));
        with_ill_formed(ill_formed, async {
            assert!(was_ill_formed("key-\u{fffd}"));
            assert!(!was_ill_formed("other-\u{fffd}"));
        })
        .await;
    }

    #[test]
    fn iso_strings() {
        assert_eq!(
            iso_string(1_767_225_600_000.0).unwrap(),
            "2026-01-01T00:00:00.000Z"
        );
        assert_eq!(iso_string(0.0).unwrap(), "1970-01-01T00:00:00.000Z");
    }
}
