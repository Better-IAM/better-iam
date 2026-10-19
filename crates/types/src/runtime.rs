//! Support code for the generated types (hand-written, not generated).
//!
//! - [`to_json_string`] / [`to_value`]: serialize a value exactly as the TypeScript server's `JSON.stringify` would
//!   (numbers in JavaScript form, `1` rather than `1.0`).
//! - [`present`] and [`nullable`]: field adapters that keep an absent member, an explicit `null` and a value apart.
//! - [`Shape`] and [`untagged`]: how an untagged union (TypeScript `A | B` without a discriminator serde can use)
//!   picks its variant: the first one whose JSON shape (kind, constants, required and allowed members) the value
//!   matches, then, failing that, the first one that decodes at all.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// Serializes `value` to a `serde_json::Value`.
pub fn to_value<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Value> {
    serde_json::to_value(value)
}

/// Serializes `value` to JSON text byte-identical to `JSON.stringify` of the same value in the TypeScript
/// implementation (numbers formatted the JavaScript way; members in declaration order).
pub fn to_json_string<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
    Ok(better_iam_core::js::stringify(&serde_json::to_value(
        value,
    )?))
}

/// JSON kinds, as bit flags for [`Shape::kinds`] and [`Member::kinds`].
pub mod kind {
    pub const NULL: u8 = 1;
    pub const BOOL: u8 = 2;
    pub const NUMBER: u8 = 4;
    pub const STRING: u8 = 8;
    pub const ARRAY: u8 = 16;
    pub const OBJECT: u8 = 32;
    pub const ANY: u8 = NULL | BOOL | NUMBER | STRING | ARRAY | OBJECT;
}

/// The JSON kind of `value` (one of the [`kind`] flags).
pub fn kind_of(value: &Value) -> u8 {
    match value {
        Value::Null => kind::NULL,
        Value::Bool(_) => kind::BOOL,
        Value::Number(_) => kind::NUMBER,
        Value::String(_) => kind::STRING,
        Value::Array(_) => kind::ARRAY,
        Value::Object(_) => kind::OBJECT,
    }
}

/// A constant a schema allows.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Const {
    Null,
    Bool(bool),
    Number(f64),
    Str(&'static str),
}

impl Const {
    /// Whether `value` is this constant (numbers compare as JavaScript doubles).
    pub fn matches(&self, value: &Value) -> bool {
        match (self, value) {
            (Const::Null, Value::Null) => true,
            (Const::Bool(expected), Value::Bool(actual)) => expected == actual,
            (Const::Number(expected), Value::Number(actual)) => actual.as_f64() == Some(*expected),
            (Const::Str(expected), Value::String(actual)) => expected == actual,
            _ => false,
        }
    }
}

/// One declared member of an object [`Shape`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Member {
    pub name: &'static str,
    pub required: bool,
    /// The JSON kinds the member may have.
    pub kinds: u8,
    /// When not empty, the only values the member may have.
    pub consts: &'static [Const],
}

impl Member {
    pub const fn new(
        name: &'static str,
        required: bool,
        kinds: u8,
        consts: &'static [Const],
    ) -> Self {
        Member {
            name,
            required,
            kinds,
            consts,
        }
    }
}

/// The JSON shape of one variant of an untagged union.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Shape {
    /// The JSON kinds the value may have.
    pub kinds: u8,
    /// When not empty, the only values allowed.
    pub consts: &'static [Const],
    /// For objects: the declared members.
    pub members: &'static [Member],
    /// For objects: whether members other than `members` are refused.
    pub closed: bool,
}

impl Shape {
    pub const fn new(
        kinds: u8,
        consts: &'static [Const],
        members: &'static [Member],
        closed: bool,
    ) -> Self {
        Shape {
            kinds,
            consts,
            members,
            closed,
        }
    }

    /// Whether `value` has this shape: its kind is allowed, it is one of the constants (when listed), and an object
    /// has every required member, only allowed kinds and constants in its declared members, and no other members
    /// when the shape is closed.
    pub fn matches(&self, value: &Value) -> bool {
        if self.kinds & kind_of(value) == 0 {
            return false;
        }
        if !self.consts.is_empty() && !self.consts.iter().any(|constant| constant.matches(value)) {
            return false;
        }
        let Value::Object(map) = value else {
            return true;
        };
        if self.kinds & kind::OBJECT == 0 {
            return true;
        }
        for member in self.members {
            match map.get(member.name) {
                None => {
                    if member.required {
                        return false;
                    }
                }
                Some(item) => {
                    if member.kinds & kind_of(item) == 0 {
                        return false;
                    }
                    if !member.consts.is_empty()
                        && !member.consts.iter().any(|constant| constant.matches(item))
                    {
                        return false;
                    }
                }
            }
        }
        !self.closed
            || map
                .keys()
                .all(|key| self.members.iter().any(|member| member.name == key))
    }
}

/// One variant of an untagged union: its shape and how to decode it.
pub struct Variant<T: 'static> {
    pub shape: Shape,
    pub decode: fn(Value) -> serde_json::Result<T>,
}

/// Decodes an untagged union: the first variant whose shape matches and that decodes, otherwise the first variant
/// that decodes, otherwise serde's untagged error.
pub fn untagged<'de, D, T>(
    deserializer: D,
    name: &str,
    variants: &[Variant<T>],
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: 'static,
{
    let value = Value::deserialize(deserializer)?;
    from_untagged(value, name, variants).map_err(D::Error::custom)
}

/// [`untagged`] on a `serde_json::Value`.
pub fn from_untagged<T: 'static>(
    value: Value,
    name: &str,
    variants: &[Variant<T>],
) -> Result<T, String> {
    let mut tried = vec![false; variants.len()];
    for (index, variant) in variants.iter().enumerate() {
        if variant.shape.matches(&value) {
            tried[index] = true;
            if let Ok(decoded) = (variant.decode)(value.clone()) {
                return Ok(decoded);
            }
        }
    }
    for (index, variant) in variants.iter().enumerate() {
        if tried[index] {
            continue;
        }
        if let Ok(decoded) = (variant.decode)(value.clone()) {
            return Ok(decoded);
        }
    }
    Err(format!(
        "data did not match any variant of untagged enum {name}"
    ))
}

/// Field adapter for members of any JSON type (`unknown`): `None` is an absent member and `Some(Value::Null)` an
/// explicit `null`. Used with `#[serde(default, skip_serializing_if = "Option::is_none", with = "...")]`.
pub mod present {
    use super::*;

    pub fn serialize<S: Serializer>(
        value: &Option<Value>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => value.serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Value>, D::Error> {
        Value::deserialize(deserializer).map(Some)
    }
}

/// Field adapter for optional members that may also be `null`: `None` is an absent member, `Some(None)` an explicit
/// `null` and `Some(Some(value))` a value. Used with
/// `#[serde(default, skip_serializing_if = "Option::is_none", with = "...")]`.
pub mod nullable {
    use super::*;

    pub fn serialize<T: Serialize, S: Serializer>(
        value: &Option<Option<T>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(inner) => inner.serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Option<T>>, D::Error> {
        Option::<T>::deserialize(deserializer).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shapes_check_kind_constants_and_members() {
        const SHAPE: Shape = Shape {
            kinds: kind::OBJECT,
            consts: &[],
            members: &[
                Member {
                    name: "kind",
                    required: true,
                    kinds: kind::STRING,
                    consts: &[Const::Str("a")],
                },
                Member {
                    name: "n",
                    required: false,
                    kinds: kind::NUMBER,
                    consts: &[],
                },
            ],
            closed: true,
        };
        assert!(SHAPE.matches(&json!({ "kind": "a" })));
        assert!(SHAPE.matches(&json!({ "kind": "a", "n": 1 })));
        assert!(!SHAPE.matches(&json!({ "kind": "b" })));
        assert!(!SHAPE.matches(&json!({ "n": 1 })));
        assert!(!SHAPE.matches(&json!({ "kind": "a", "n": "1" })));
        assert!(!SHAPE.matches(&json!({ "kind": "a", "other": true })));
        assert!(!SHAPE.matches(&json!("a")));
        assert!(Const::Number(1.0).matches(&json!(1)));
    }

    #[test]
    fn js_number_formatting() {
        assert_eq!(
            to_json_string(&json!({ "a": 1.0, "b": [2.5, 1e21] })).unwrap(),
            r#"{"a":1,"b":[2.5,1e+21]}"#
        );
    }
}
