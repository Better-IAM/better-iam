//! Input validation shared by the authentication flows (`validation.ts`).

use better_iam_core::{IamError, IamResult, Identity, Session, js};
use serde_json::Value;

use crate::types::{SafeIdentity, SafeSession};

/// `text(value, field, max)`: a nonempty string of at most `max` UTF-16 code units.
pub fn text(value: Option<&Value>, field: &str, max: usize) -> IamResult<String> {
    match value {
        Some(Value::String(text)) => text_str(text, field, max).map(str::to_owned),
        _ => Err(text_error(field, max)),
    }
}

fn text_error(field: &str, max: usize) -> IamError {
    IamError::new(
        "INVALID_INPUT",
        format!("{field} must be a nonempty string of at most {max} characters"),
    )
}

/// [`text`] for a value already known to be a string.
pub fn text_str<'a>(value: &'a str, field: &str, max: usize) -> IamResult<&'a str> {
    let length = js::utf16_len(value);
    if length == 0 || length > max {
        return Err(text_error(field, max));
    }
    Ok(value)
}

/// `controlCharacters`: control characters (C0, DEL, C1) and Unicode line/paragraph separators.
pub fn is_control_character(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{2028}' | '\u{2029}')
}

/// `value.replace(controlCharacters, ' ')`.
pub fn replace_control_characters(value: &str) -> String {
    value
        .chars()
        .map(|c| if is_control_character(c) { ' ' } else { c })
        .collect()
}

/// `displayName(value, max)`: control and line-separator characters become spaces, so a name can never break an
/// email header or forge a line in a message.
pub fn display_name(value: Option<&Value>, max: usize) -> IamResult<String> {
    let name = text(value, "name", max)?;
    let cleaned = replace_control_characters(&name);
    text_str(js::trim(&cleaned), "name", max).map(str::to_owned)
}

/// [`display_name`] of a string.
pub fn display_name_str(value: &str, max: usize) -> IamResult<String> {
    display_name(Some(&Value::String(value.to_owned())), max)
}

fn email_shape(value: &str) -> bool {
    // /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    let bad = |c: char| c == '@' || js::is_js_whitespace(c);
    if local.is_empty() || local.chars().any(bad) || domain.chars().any(bad) {
        return false;
    }
    let chars: Vec<char> = domain.chars().collect();
    chars
        .iter()
        .enumerate()
        .any(|(index, c)| *c == '.' && index >= 1 && index + 1 < chars.len())
}

/// `email(value)`: trimmed, lower-cased, and shaped like an address.
pub fn email(value: Option<&Value>) -> IamResult<String> {
    let raw = text(value, "email", 254)?;
    let normalized = js::to_lower(js::trim(&raw));
    if !email_shape(&normalized) {
        return Err(IamError::new("INVALID_INPUT", "Invalid email"));
    }
    Ok(normalized)
}

/// [`email`] of a string.
pub fn email_str(value: &str) -> IamResult<String> {
    email(Some(&Value::String(value.to_owned())))
}

/// `phone(value)`: E.164.
pub fn phone(value: Option<&Value>) -> IamResult<String> {
    let normalized = text(value, "phone", 16)?;
    let bytes = normalized.as_bytes();
    let valid = bytes.len() >= 8
        && bytes.len() <= 16
        && bytes[0] == b'+'
        && (b'1'..=b'9').contains(&bytes[1])
        && bytes[2..].iter().all(u8::is_ascii_digit);
    if !valid {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Phone must use E.164 format",
        ));
    }
    Ok(normalized)
}

/// [`phone`] of a string.
pub fn phone_str(value: &str) -> IamResult<String> {
    phone(Some(&Value::String(value.to_owned())))
}

/// `password(value)`: at most 1024 characters and at least 12.
pub fn password(value: Option<&Value>) -> IamResult<String> {
    let result = text(value, "password", 1024)?;
    if js::utf16_len(&result) < 12 {
        return Err(IamError::new(
            "WEAK_PASSWORD",
            "Password must contain at least 12 characters",
        ));
    }
    Ok(result)
}

/// `publicIdentity(identity)`: the identity without its password hash.
pub fn public_identity(identity: &Identity) -> SafeIdentity {
    SafeIdentity(identity.clone())
}

/// `publicSession(session)`: a session without its secret-derived fields (`tokenHash`, and `uniqueKey`, which
/// holds the same hash).
pub fn public_session(session: &Session) -> SafeSession {
    SafeSession(session.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validates_emails_like_the_typescript_pattern() {
        assert_eq!(
            email(Some(&json!(" Ada@Example.COM "))).unwrap(),
            "ada@example.com"
        );
        for bad in [
            "a@b",
            "a@.com",
            "a@com.",
            "@x.com",
            "a b@x.com",
            "a@b@c.com",
        ] {
            assert!(email(Some(&json!(bad))).is_err(), "{bad}");
        }
        assert!(email(Some(&json!("a@b.c.d"))).is_ok());
        assert!(email(Some(&json!(42))).is_err());
    }

    #[test]
    fn validates_phones() {
        assert!(phone(Some(&json!("+15551234567"))).is_ok());
        assert!(phone(Some(&json!("+0555123456"))).is_err());
        assert!(phone(Some(&json!("+12345"))).is_err());
    }
}
