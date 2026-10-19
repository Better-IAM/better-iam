//! Port of `packages/server/src/validation.ts`: the input validators every module shares.
//!
//! Values are untrusted JSON; `None` is `undefined` (which every validator treats like `null`).

use better_iam_core::{IamResult, js as core_js};
use serde_json::{Map, Value};

use crate::js::{has_control, invalid_input, utf16_len};

/// `text(value, name, max = 256)`: a non-blank string of at most `max` UTF-16 code units without control characters.
pub fn text(value: Option<&Value>, name: &str, max: usize) -> IamResult<String> {
    match value {
        Some(Value::String(text))
            if !core_js::trim(text).is_empty() && utf16_len(text) <= max && !has_control(text) =>
        {
            Ok(text.clone())
        }
        _ => Err(invalid_input(format!("Invalid {name}"))),
    }
}

/// [`text`] with the default limit of 256.
pub fn text256(value: Option<&Value>, name: &str) -> IamResult<String> {
    text(value, name, 256)
}

/// [`text`] for a value that is already a string.
pub fn text_str(value: &str, name: &str, max: usize) -> IamResult<String> {
    text(Some(&Value::String(value.to_owned())), name, max)
}

/// `/^[^\s@]+@[^\s@]+\.[^\s@]+$/`.
fn email_shape(value: &str) -> bool {
    let ok = |c: char| c != '@' && !core_js::is_js_whitespace(c);
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    if local.is_empty() || !local.chars().all(ok) || !domain.chars().all(ok) {
        return false;
    }
    // `[^\s@]+\.[^\s@]+`: some dot with at least one character on each side.
    domain
        .char_indices()
        .any(|(index, c)| c == '.' && index > 0 && index + 1 < domain.len())
}

/// `email(value)`: trimmed and lowercased, `user@domain.tld` shaped.
pub fn email(value: Option<&Value>) -> IamResult<String> {
    let result = core_js::to_lower(core_js::trim(&text(value, "email", 254)?));
    if !email_shape(&result) {
        return Err(invalid_input("Invalid email"));
    }
    Ok(result)
}

/// `object(value)`: a non-array object.
pub fn object(value: Option<&Value>) -> IamResult<&Map<String, Value>> {
    match value {
        Some(Value::Object(map)) if !crate::js::is_function(value) => Ok(map),
        _ => Err(invalid_input("Expected an object")),
    }
}

/// `integer(value, name, min, max)`: a safe integer within `[min, max]`.
pub fn integer(value: Option<&Value>, name: &str, min: f64, max: f64) -> IamResult<f64> {
    match value.and_then(core_js::as_number) {
        Some(number) if core_js::is_safe_integer(number) && number >= min && number <= max => {
            Ok(number)
        }
        _ => Err(invalid_input(format!("Invalid {name}"))),
    }
}

/// [`integer`] for a JavaScript number.
pub fn integer_number(value: f64, name: &str, min: f64, max: f64) -> IamResult<f64> {
    if core_js::is_safe_integer(value) && value >= min && value <= max {
        Ok(value)
    } else {
        Err(invalid_input(format!("Invalid {name}")))
    }
}

/// `strings(value, name)`: an array of at most 100 [`text`] values.
pub fn strings(value: Option<&Value>, name: &str) -> IamResult<Vec<String>> {
    match value {
        Some(Value::Array(items)) if items.len() <= 100 => items
            .iter()
            .map(|item| text(Some(item), name, 256))
            .collect(),
        _ => Err(invalid_input(format!("Invalid {name}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn message(result: IamResult<impl std::fmt::Debug>) -> String {
        let error = result.unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT");
        assert_eq!(error.status, 400);
        error.message
    }

    #[test]
    fn text_rules() {
        assert_eq!(text(Some(&json!("ok")), "name", 256).unwrap(), "ok");
        assert_eq!(
            message(text(Some(&json!("  ")), "name", 256)),
            "Invalid name"
        );
        assert_eq!(
            message(text(Some(&json!("a\nb")), "name", 256)),
            "Invalid name"
        );
        assert_eq!(message(text(Some(&json!(5)), "name", 256)), "Invalid name");
        assert_eq!(message(text(None, "name", 256)), "Invalid name");
        // UTF-16 length: one astral character counts twice.
        assert!(text(Some(&json!("😀")), "x", 1).is_err());
        assert!(text(Some(&json!("😀")), "x", 2).is_ok());
    }

    #[test]
    fn email_rules() {
        assert_eq!(
            email(Some(&json!("  Ada@Example.COM "))).unwrap(),
            "ada@example.com"
        );
        assert_eq!(message(email(Some(&json!("a@b")))), "Invalid email");
        assert_eq!(message(email(Some(&json!("a@.b")))), "Invalid email");
        assert_eq!(message(email(Some(&json!("a@b.")))), "Invalid email");
        assert_eq!(message(email(Some(&json!("a b@c.d")))), "Invalid email");
        assert!(email(Some(&json!("a@b.c.d"))).is_ok());
        assert!(email(Some(&json!("a@b..c"))).is_ok());
    }

    #[test]
    fn integers_objects_and_strings() {
        assert_eq!(integer(Some(&json!(5)), "n", 1.0, 10.0).unwrap(), 5.0);
        assert_eq!(
            message(integer(Some(&json!(5.5)), "n", 1.0, 10.0)),
            "Invalid n"
        );
        assert_eq!(
            message(integer(Some(&json!("5")), "n", 1.0, 10.0)),
            "Invalid n"
        );
        assert_eq!(
            message(integer(Some(&json!(11)), "n", 1.0, 10.0)),
            "Invalid n"
        );
        assert_eq!(message(object(Some(&json!([])))), "Expected an object");
        assert_eq!(message(object(Some(&json!(null)))), "Expected an object");
        assert_eq!(
            strings(Some(&json!(["a", "b"])), "list").unwrap(),
            vec!["a", "b"]
        );
        let many: Vec<Value> = (0..101).map(|i| json!(format!("v{i}"))).collect();
        assert_eq!(
            message(strings(Some(&Value::Array(many)), "list")),
            "Invalid list"
        );
    }
}
