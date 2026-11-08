//! JavaScript semantics the server's validators rely on when they read untrusted values (Rust-only module).
//!
//! The TypeScript validators read options and request bodies as plain JavaScript values: `value?.member`, `??`,
//! truthiness, `typeof`, `String(value)`. Those reads are reproduced here over `serde_json::Value`, where an absent
//! member (`undefined`) is `None` and `null` is `Some(Value::Null)`. Everything else that must agree with JavaScript
//! (number formatting, UTF-16 lengths, property order) lives in `better_iam_core::js`.

use better_iam_core::{IamError, js as core_js};
use serde_json::{Map, Value};

pub use core_js::{
    MAX_SAFE_INTEGER, as_number, cmp_utf16, entries, has_js_whitespace, includes, is_js_whitespace,
    is_safe_integer, number_to_string, stringify, to_number, trim, type_of, utf16_len,
};

/// The member name the options model uses for a JavaScript function (a callback has no JSON form). JSON input never
/// produces it: the standalone configuration reader turns `{"$scripted": true}` markers into it.
const FUNCTION_KEY: &str = "\u{1}better-iam:function";

/// The value standing for a function in the options model (`typeof value === 'function'`).
pub fn function_marker() -> Value {
    let mut map = Map::new();
    map.insert(FUNCTION_KEY.to_owned(), Value::Bool(true));
    Value::Object(map)
}

/// `typeof value === 'function'` in the options model.
pub fn is_function(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Object(map)) if map.len() == 1 && map.contains_key(FUNCTION_KEY))
}

/// `typeof value` in the options model, where functions are [`function_marker`]s and `undefined` is `None`.
pub fn type_name(value: Option<&Value>) -> &'static str {
    match value {
        None => "undefined",
        Some(_) if is_function(value) => "function",
        Some(value) => type_of(value),
    }
}

/// `value?.[key]` for a JSON value: the member of an object; `None` (undefined) for anything else.
pub fn member<'a>(value: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    match value {
        Some(Value::Object(map)) => map.get(key),
        _ => None,
    }
}

/// `value ?? undefined`: `None` for `null` and `undefined`.
pub fn defined(value: Option<&Value>) -> Option<&Value> {
    match value {
        None | Some(Value::Null) => None,
        other => other,
    }
}

/// `value === null || value === undefined`.
pub fn nullish(value: Option<&Value>) -> bool {
    defined(value).is_none()
}

/// JavaScript truthiness.
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => {
            let value = core_js::number_value(number);
            value != 0.0 && !value.is_nan()
        }
        Some(Value::String(text)) => !text.is_empty(),
        Some(_) => true,
    }
}

/// `value !== null && typeof value === 'object' && !Array.isArray(value)` (functions excluded).
pub fn is_object(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Object(_))) && !is_function(value)
}

/// `String(value)` for a JSON value.
pub fn js_string(value: Option<&Value>) -> String {
    match value {
        None => "undefined".to_owned(),
        Some(Value::Null) => "null".to_owned(),
        Some(Value::Bool(flag)) => flag.to_string(),
        Some(Value::Number(number)) => number_to_string(core_js::number_value(number)),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Null => String::new(),
                other => js_string(Some(other)),
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(other) if is_function(Some(other)) => "function () { [native code] }".to_owned(),
        Some(Value::Object(_)) => "[object Object]".to_owned(),
    }
}

/// `/[\u0000-\u001f]/.test(value)`.
pub fn has_control(value: &str) -> bool {
    value.chars().any(|c| (c as u32) < 0x20)
}

/// A JavaScript exception that is not an `IamError` (a `TypeError` from reading a member of `undefined`, a plain
/// `Error` a module throws). The HTTP layer and the conformance server answer every such exception as
/// `INTERNAL_ERROR` 500 "Internal server error", which is what [`ThrownError::into_iam`] gives.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{name}: {message}")]
pub struct ThrownError {
    pub name: String,
    pub message: String,
}

impl ThrownError {
    pub fn new(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            message: message.into(),
        }
    }

    /// `new Error(message)`.
    pub fn error(message: impl Into<String>) -> Self {
        Self::new("Error", message)
    }

    /// `new TypeError(message)`.
    pub fn type_error(message: impl Into<String>) -> Self {
        Self::new("TypeError", message)
    }

    /// The `IamError` the server answers for it.
    pub fn into_iam(self) -> IamError {
        internal_error()
    }
}

impl From<ThrownError> for IamError {
    fn from(error: ThrownError) -> Self {
        error.into_iam()
    }
}

/// `INTERNAL_ERROR` 500 "Internal server error": what TypeScript answers for an exception that is not an `IamError`.
pub fn internal_error() -> IamError {
    IamError::with_status("INTERNAL_ERROR", "Internal server error", 500)
}

/// A thrown JavaScript exception that is not an `IamError` (an `Error` named `name` with `message`): `INTERNAL_ERROR`
/// 500 carrying the exception's own message, which code that reads `error.message` reports (an archive failure). The
/// HTTP layer and the conformance error shape still answer "Internal server error" for it.
pub fn thrown_error(name: impl Into<String>, message: impl Into<String>) -> IamError {
    IamError::with_status("INTERNAL_ERROR", message, 500).with_details(
        better_iam_core::IamErrorDetails {
            thrown: Some(name.into()),
            ..Default::default()
        },
    )
}

/// The exception name of an error that stands for a thrown non-`IamError` (see [`thrown_error`]).
pub fn thrown_name(error: &IamError) -> Option<&str> {
    error
        .details
        .as_deref()
        .and_then(|details| details.thrown.as_deref())
}

/// `new IamError('INVALID_INPUT', message)`.
pub fn invalid_input(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// `new IamError('INVALID_CONFIG', message)`.
pub fn invalid_config(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_CONFIG", message)
}

/// `Object.keys(value)` of an object in JavaScript property order.
pub fn keys(map: &Map<String, Value>) -> Vec<&String> {
    core_js::keys(map)
}

/// A JavaScript number as a JSON value (`null` for non-finite numbers, as `JSON.stringify` writes them).
pub fn number(value: f64) -> Value {
    core_js::number(value).unwrap_or(Value::Null)
}

/// `#[serde(serialize_with = "crate::js::serialize_number")]`: writes an `f64` field as [`number`] does, so an
/// integral double serializes as a JSON integer (`600`, not `600.0`), exactly like a JavaScript number.
pub fn serialize_number<S: serde::Serializer>(
    value: &f64,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serde::Serialize::serialize(&number(*value), serializer)
}

/// `JSON.parse(text)`; a syntax error is an exception the server answers as INTERNAL_ERROR.
pub fn parse_json(text: &str) -> Result<Value, IamError> {
    core_js::parse(text).map_err(|_| internal_error())
}

/// Sorts strings as `Array.prototype.sort()` does without a comparator (UTF-16 code unit order, stable).
pub fn sort_strings(items: &mut [String]) {
    items.sort_by(|a, b| cmp_utf16(a, b));
}

/// Removes duplicates keeping the first occurrence (`[...new Set(items)]`).
pub fn unique(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = indexmap::IndexSet::new();
    for item in items {
        seen.insert(item);
    }
    seen.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn strings_and_truthiness_follow_javascript() {
        assert_eq!(js_string(Some(&json!([1, null, "a"]))), "1,,a");
        assert_eq!(js_string(Some(&json!(2.0))), "2");
        assert_eq!(js_string(Some(&json!({}))), "[object Object]");
        assert!(!truthy(Some(&json!(0))));
        assert!(!truthy(Some(&json!(""))));
        assert!(truthy(Some(&json!([]))));
        assert!(is_function(Some(&function_marker())));
        assert_eq!(type_name(Some(&function_marker())), "function");
        assert!(!is_object(Some(&function_marker())));
    }
}
