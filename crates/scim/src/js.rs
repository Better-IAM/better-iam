//! JavaScript semantics the TypeScript SCIM package relies on (Rust-only helpers): `String(value)`, truthiness,
//! `encodeURIComponent` / `decodeURIComponent`, relational comparison, `localeCompare`, and a few record helpers.

use std::cmp::Ordering;
use std::sync::LazyLock;

use better_iam_core::{IamError, js as core_js};
use icu_collator::{CollatorBorrowed, options::CollatorOptions};
use serde_json::{Map, Value};

/// `String(value)` for a JSON value (`undefined` for None).
pub fn js_string(value: Option<&Value>) -> String {
    match value {
        None => "undefined".to_owned(),
        Some(Value::Null) => "null".to_owned(),
        Some(Value::Bool(flag)) => flag.to_string(),
        Some(Value::Number(number)) => core_js::number_to_string(core_js::number_value(number)),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Null => String::new(),
                other => js_string(Some(other)),
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::Object(_)) => "[object Object]".to_owned(),
    }
}

/// JavaScript truthiness of a JSON value (None is `undefined`).
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => {
            let value = core_js::number_value(number);
            value != 0.0 && !value.is_nan()
        }
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(_)) | Some(Value::Object(_)) => true,
    }
}

/// `value ?? fallback`: None for an absent member or JSON null.
pub fn nullish(value: Option<&Value>) -> Option<&Value> {
    value.filter(|value| !value.is_null())
}

/// A plain JSON object (`!!value && typeof value === 'object' && !Array.isArray(value)`).
pub fn as_object(value: Option<&Value>) -> Option<&Map<String, Value>> {
    match value {
        Some(Value::Object(map)) => Some(map),
        _ => None,
    }
}

/// `encodeURIComponent(value)`.
pub fn encode_uri_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
        {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `decodeURIComponent(value)`; None where JavaScript throws a URIError (a malformed escape or invalid UTF-8).
pub fn decode_uri_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = value.get(index + 1..index + 3)?;
            if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return None;
            }
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

static COLLATOR: LazyLock<CollatorBorrowed<'static>> = LazyLock::new(|| {
    CollatorBorrowed::try_new(Default::default(), CollatorOptions::default())
        .expect("the root collation is compiled in")
});

/// `a.localeCompare(b)` without locales: ICU root collation.
pub fn locale_compare(a: &str, b: &str) -> Ordering {
    COLLATOR.compare(a, b)
}

/// The first `count` UTF-16 code units of a string (`value.slice(0, count)`), never splitting a character.
pub fn utf16_prefix(value: &str, count: usize) -> &str {
    let mut units = 0;
    for (index, c) in value.char_indices() {
        units += c.len_utf16();
        if units > count {
            return &value[..index];
        }
    }
    value
}

/// `ToPrimitive` then `ToNumber` / string, for the abstract relational comparison.
enum Primitive {
    Text(String),
    Number(f64),
}

fn primitive(value: &Value) -> Primitive {
    match value {
        Value::String(text) => Primitive::Text(text.clone()),
        Value::Number(number) => Primitive::Number(core_js::number_value(number)),
        Value::Bool(flag) => Primitive::Number(if *flag { 1.0 } else { 0.0 }),
        Value::Null => Primitive::Number(0.0),
        other => Primitive::Text(js_string(Some(other))),
    }
}

/// JavaScript `left < right` between two defined, non-null JSON values.
pub fn less_than(left: &Value, right: &Value) -> bool {
    match (primitive(left), primitive(right)) {
        (Primitive::Text(a), Primitive::Text(b)) => core_js::cmp_utf16(&a, &b) == Ordering::Less,
        (a, b) => {
            let number = |value: Primitive| match value {
                Primitive::Number(number) => number,
                Primitive::Text(text) => core_js::string_to_number(&text),
            };
            number(a) < number(b)
        }
    }
}

/// `new IamError(code, message)` (status 400).
pub fn error(code: &str, message: impl Into<String>) -> IamError {
    IamError::new(code, message)
}

/// What TypeScript answers for an exception that is not an `IamError` (`INTERNAL_ERROR` 500): the Rust port reports
/// every failure as an `IamError`, so this code and status mark the unexpected ones.
pub fn unexpected(message: impl Into<String>) -> IamError {
    IamError::with_status("INTERNAL_ERROR", message, 500)
}

/// Whether an error stands for a JavaScript exception that is not an `IamError` (see [`unexpected`]).
pub fn is_unexpected(error: &IamError) -> bool {
    error.code == "INTERNAL_ERROR" && error.status == 500
}

/// A JSON number from a JavaScript double (`null` for non-finite numbers, as `JSON.stringify` writes them).
pub fn number(value: f64) -> Value {
    core_js::number(value).unwrap_or(Value::Null)
}

/// `Date.now()` (the wall clock the conformance server controls).
pub fn date_now() -> f64 {
    core_js::now_ms()
}

/// `crypto.randomUUID()`.
pub fn random_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// `randomBytes(count)`.
pub fn random_bytes(count: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; count];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// `new Date(ms).toISOString()`; a RangeError (an unexpected failure) outside the representable range.
pub fn iso_string(ms: Option<&Value>) -> Result<String, IamError> {
    let value = match ms {
        Some(Value::Number(number)) => core_js::number_value(number),
        Some(Value::Null) => 0.0,
        Some(Value::Bool(flag)) => {
            if *flag {
                1.0
            } else {
                0.0
            }
        }
        Some(Value::String(text)) => core_js::string_to_number(text),
        _ => f64::NAN,
    };
    core_js::iso_string(value).ok_or_else(|| unexpected("Invalid time value"))
}
