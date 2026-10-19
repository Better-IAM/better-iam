//! Helpers shared by the modules of this crate (Rust-only): Node's base64 codecs, JavaScript truthiness and string
//! conversion, typed record conversion, and the error a TypeScript `TypeError` becomes.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use better_iam_core::{Filter, FindOptions, IamError, IamResult, IamStore, Record, js};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

/// `Buffer.from(bytes).toString('base64url')`.
pub fn base64url(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// `Buffer.from(bytes).toString('base64')` without the padding (`.split('=')[0]`).
pub fn base64_unpadded(bytes: impl AsRef<[u8]>) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

/// `Buffer.from(bytes).toString('base64')`.
pub fn base64_padded(bytes: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `Buffer.from(text, 'base64')` / `Buffer.from(text, 'base64url')`: Node accepts both alphabets in either mode,
/// skips characters outside them, stops at the first `=`, and drops a trailing partial sextet group.
pub fn node_base64_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for c in text.chars() {
        let value = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            '=' => break,
            _ => continue,
        };
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    out
}

/// JavaScript truthiness of a JSON value (`undefined` is None).
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => {
            let n = js::number_value(number);
            n != 0.0 && !n.is_nan()
        }
        Some(Value::String(text)) => !text.is_empty(),
        Some(_) => true,
    }
}

/// `String(value)` for a JSON value.
pub fn js_string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => js::number_to_string(js::number_value(number)),
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Null => String::new(),
                other => js_string(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_owned(),
    }
}

/// `input[key]` of a JSON body: None when the member is absent or the body is not an object.
pub fn prop<'a>(input: &'a Value, key: &str) -> Option<&'a Value> {
    input.as_object().and_then(|map| map.get(key))
}

/// The string value of `input[key]`, when it is a string.
pub fn prop_str<'a>(input: &'a Value, key: &str) -> Option<&'a str> {
    prop(input, key).and_then(Value::as_str)
}

/// What the HTTP layer answers for an exception that is not an `IamError` (a TypeScript `TypeError` or a library
/// error): `INTERNAL_ERROR`, 500, "Internal server error".
pub fn internal_error() -> IamError {
    IamError::with_status("INTERNAL_ERROR", "Internal server error", 500)
}

/// A JSON number from a JavaScript double (`null` for the non-finite values `JSON.stringify` writes as null).
pub fn num(value: f64) -> Value {
    js::number(value).unwrap_or(Value::Null)
}

/// A typed record from a stored JSON object.
pub fn from_record<T: DeserializeOwned>(record: Record) -> IamResult<T> {
    serde_json::from_value(Value::Object(record)).map_err(|_| {
        IamError::with_status("STORAGE_CORRUPT", "Record does not match its type", 500)
    })
}

/// The JSON object of a typed record.
pub fn to_record<T: Serialize>(value: &T) -> Record {
    match serde_json::to_value(value) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    }
}

/// Typed storage access over the object-safe store contract.
pub async fn get<T: DeserializeOwned>(
    store: &dyn IamStore,
    collection: &str,
    id: &str,
) -> IamResult<Option<T>> {
    match store.get(collection, id).await? {
        Some(record) => from_record(record).map(Some),
        None => Ok(None),
    }
}

/// `store.find(collection, filter)` deserialized.
pub async fn find<T: DeserializeOwned>(
    store: &dyn IamStore,
    collection: &str,
    filter: &Filter,
) -> IamResult<Vec<T>> {
    store
        .find(collection, filter, &FindOptions::default())
        .await?
        .into_iter()
        .map(from_record)
        .collect()
}

/// `store.insert(collection, record)` of a typed record.
pub async fn insert<T: Serialize>(
    store: &dyn IamStore,
    collection: &str,
    value: &T,
) -> IamResult<Record> {
    store.insert(collection, &to_record(value)).await
}

/// `store.put(collection, record)` of a typed record.
pub async fn put<T: Serialize>(
    store: &dyn IamStore,
    collection: &str,
    value: &T,
) -> IamResult<Record> {
    store.put(collection, &to_record(value)).await
}

/// A shared store handle.
pub type Store = Arc<dyn IamStore>;

/// JavaScript `a < b` for strings (UTF-16 code unit order).
pub fn js_less(left: &str, right: &str) -> bool {
    js::cmp_utf16(left, right) == std::cmp::Ordering::Less
}

/// `(a.x - b.x) || (a.id < b.id ? -1 : 1)` comparators reduce to this ordering.
pub fn by_number_then_id(left: (f64, &str), right: (f64, &str)) -> std::cmp::Ordering {
    let delta = left.0 - right.0;
    if delta != 0.0 && !delta.is_nan() {
        return if delta < 0.0 {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        };
    }
    if js_less(left.1, right.1) {
        std::cmp::Ordering::Less
    } else {
        std::cmp::Ordering::Greater
    }
}

/// Lower-case hexadecimal.
pub fn hex(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// `encodeURIComponent(value)`.
pub fn encode_uri_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let c = *byte as char;
        if c.is_ascii_alphanumeric() || "-_.!~*'()".contains(c) {
            out.push(c);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_like_node() {
        let cases = [
            ("ab$cd", "69b71d"),
            ("ab cd", "69b71d"),
            ("abc=", "69b7"),
            ("ab=cd", "69"),
            ("a", ""),
            ("ab+/", "69bfbf"),
            ("ab-_", "69bfbf"),
            ("abcde", "69b71d"),
            ("==ab", ""),
            ("abé", "69"),
        ];
        for (input, expected) in cases {
            assert_eq!(hex(node_base64_decode(input)), expected, "{input}");
        }
    }

    #[test]
    fn encodes_uri_components() {
        assert_eq!(
            encode_uri_component("ünï code@example.com"),
            "%C3%BCn%C3%AF%20code%40example.com"
        );
        assert_eq!(encode_uri_component("Better IAM"), "Better%20IAM");
    }
}
