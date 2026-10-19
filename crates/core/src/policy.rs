//! Policy documents: validation, glob and variable matching, conditions, and evaluation (`policy.ts`).
//!
//! Grants form a union; every boundary is an independent intersection. A boundary never grants access. Glob matching
//! is anchored; only `*` and `?` are operators. Policy variables (`${principal.id}`) substitute trusted context values
//! that always match literally.

use std::cell::Cell;
use std::fmt;

use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::js;
use crate::{IamError, IamResult};

/// The evaluation context: principal, request, tenant and resource keys (`Record<string, unknown>`).
pub type Context = Map<String, Value>;

macro_rules! operators {
    ($($name:ident),* $(,)?) => {
        /// A condition operator (`ConditionOperator`).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum ConditionOperator { $($name),* }

        impl ConditionOperator {
            /// Every operator, in the TypeScript declaration order.
            pub const ALL: &'static [ConditionOperator] = &[$(ConditionOperator::$name),*];

            pub fn as_str(self) -> &'static str {
                match self { $(ConditionOperator::$name => stringify!($name)),* }
            }

            pub fn parse(name: &str) -> Option<Self> {
                match name { $(stringify!($name) => Some(ConditionOperator::$name),)* _ => None }
            }
        }
    };
}

operators!(
    StringEquals,
    StringNotEquals,
    StringEqualsIgnoreCase,
    StringNotEqualsIgnoreCase,
    StringLike,
    StringNotLike,
    StringLikeIgnoreCase,
    Bool,
    NumericEquals,
    NumericNotEquals,
    NumericLessThan,
    NumericLessThanEquals,
    NumericGreaterThan,
    NumericGreaterThanEquals,
    DateBefore,
    DateAfter,
    IpAddress,
    NotIpAddress,
    ArrayContains,
    ArrayContainsAll,
    Exists,
);

impl fmt::Display for ConditionOperator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for ConditionOperator {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ConditionOperator {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        ConditionOperator::parse(&name)
            .ok_or_else(|| serde::de::Error::custom("Unknown condition operator"))
    }
}

/// Negated operators succeed only when the actual value differs from every listed value.
fn negated(operator: ConditionOperator) -> bool {
    use ConditionOperator::*;
    matches!(
        operator,
        StringNotEquals
            | StringNotEqualsIgnoreCase
            | StringNotLike
            | NumericNotEquals
            | NotIpAddress
    )
}

/// Operators that require every listed value (the negated ones and `ArrayContainsAll`).
fn every_value(operator: ConditionOperator) -> bool {
    negated(operator) || operator == ConditionOperator::ArrayContainsAll
}

/// `PolicyStatement.effect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

/// Conditions of a statement: operator → attribute → expected value (a string, number or boolean, or a list of
/// them).
pub type Conditions = IndexMap<ConditionOperator, IndexMap<String, Value>>;

/// `PolicyStatement`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyStatement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub effect: Effect,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Conditions>,
}

/// A validated policy document (`PolicyDocument`, version 1). Deserializing one runs [`validate_policy`], so a
/// document read from JSON is always valid.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyDocument {
    pub statements: Vec<PolicyStatement>,
}

#[derive(Serialize, Deserialize)]
struct RawDocument {
    version: u8,
    statements: Vec<PolicyStatement>,
}

impl PolicyDocument {
    /// A version 1 document of these statements.
    pub fn new(statements: Vec<PolicyStatement>) -> Self {
        Self { statements }
    }

    /// Validates untrusted JSON ([`validate_policy`]) and reads it.
    pub fn from_value(value: &Value) -> IamResult<Self> {
        validate_policy(value)?;
        let mut raw: RawDocument = serde_json::from_value(value.clone())
            .map_err(|_| IamError::new("INVALID_POLICY", "Policy must be a plain object"))?;
        // Attributes are evaluated in JavaScript property order (integer-like keys first).
        for statement in &mut raw.statements {
            for attributes in statement
                .conditions
                .iter_mut()
                .flat_map(|conditions| conditions.values_mut())
            {
                if attributes.keys().any(|key| js::is_array_index(key)) {
                    let map: Map<String, Value> = std::mem::take(attributes).into_iter().collect();
                    *attributes = js::entries(&map)
                        .into_iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect();
                }
            }
        }
        Ok(Self {
            statements: raw.statements,
        })
    }

    /// The document as JSON (`{ version: 1, statements }`).
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("version".into(), Value::from(1));
        map.insert(
            "statements".into(),
            serde_json::to_value(&self.statements).unwrap_or_else(|_| Value::Array(Vec::new())),
        );
        Value::Object(map)
    }
}

impl Serialize for PolicyDocument {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        RawDocument {
            version: 1,
            statements: self.statements.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PolicyDocument {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        PolicyDocument::from_value(&value).map_err(|error| serde::de::Error::custom(error.message))
    }
}

/// `EvaluationInput`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EvaluationInput {
    pub action: String,
    pub resource: String,
    pub context: Option<Context>,
    pub grants: Vec<PolicyDocument>,
    pub boundaries: Option<Vec<PolicyDocument>>,
}

/// `Decision`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub allowed: bool,
    pub reason: String,
    pub matched: Vec<String>,
}

const UNSAFE_KEYS: [&str; 3] = ["__proto__", "prototype", "constructor"];

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_POLICY", message)
}

/// `nonempty(value, max)`: 1 to `max` UTF-16 code units without C0 controls or DEL.
fn nonempty(value: &Value, max: usize) -> bool {
    match value {
        Value::String(text) => nonempty_str(text, max),
        _ => false,
    }
}

fn nonempty_str(text: &str, max: usize) -> bool {
    let length = js::utf16_len(text);
    length > 0 && length <= max && !text.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}')
}

fn only_keys(value: &Map<String, Value>, allowed: &[&str]) -> IamResult<()> {
    if value.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid("Unknown policy field"));
    }
    Ok(())
}

const VARIABLE_MARKER: &str = "${";

/// The variable reference at `index` (`/\$\{([A-Za-z_][A-Za-z0-9_.:-]{0,127})\}/y`): its name and total length.
pub(crate) fn variable_at(text: &str, index: usize) -> Option<(&str, usize)> {
    let bytes = text.as_bytes();
    if !text[index..].starts_with(VARIABLE_MARKER) {
        return None;
    }
    let start = index + 2;
    let first = *bytes.get(start)?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let mut end = start + 1;
    while end < bytes.len() && end - start < 128 {
        let byte = bytes[end];
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-') {
            end += 1;
        } else {
            break;
        }
    }
    if bytes.get(end) != Some(&b'}') {
        return None;
    }
    Some((&text[start..end], end + 1 - index))
}

/// A glob token: a star, a single-character wildcard, or a literal character.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Token {
    Star,
    Any,
    Char(char),
}

pub(crate) fn glob_tokens(pattern: &str, into: &mut Vec<Token>) {
    for c in pattern.chars() {
        into.push(match c {
            '*' => Token::Star,
            '?' => Token::Any,
            c => Token::Char(c),
        });
    }
}

/// `String(value)` of a context value that can substitute a variable (string, number or boolean).
pub(crate) fn substitution(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(js::number_to_string(js::number_value(number))),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// Splits a pattern into wildcard and literal tokens, substituting variables from context. None when a variable is
/// unresolved.
fn tokenize(pattern: &str, context: Option<&Context>) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut cursor = 0;
    let mut search = 0;
    while let Some(found) = pattern[search..].find(VARIABLE_MARKER) {
        let index = search + found;
        let Some((name, length)) = variable_at(pattern, index) else {
            // A malformed reference is rejected by validation; at evaluation it is treated as literal text.
            search = index + VARIABLE_MARKER.len();
            continue;
        };
        glob_tokens(&pattern[cursor..index], &mut tokens);
        let value = substitution(context.and_then(|context| context.get(name)))?;
        tokens.extend(value.chars().map(Token::Char));
        cursor = index + length;
        search = cursor;
    }
    glob_tokens(&pattern[cursor..], &mut tokens);
    Some(tokens)
}

thread_local! {
    /// Work left in the running evaluation, in characters examined (roughly).
    static WORK_LEFT: Cell<f64> = const { Cell::new(f64::INFINITY) };
}

const EVALUATION_WORK: f64 = 4_000_000.0;

/// Too much matching work for one evaluation.
#[derive(Debug)]
struct EvaluationLimit;

fn spend(units: usize) -> Result<(), EvaluationLimit> {
    WORK_LEFT.with(|left| {
        let next = left.get() - units as f64;
        left.set(next);
        if next < 0.0 {
            Err(EvaluationLimit)
        } else {
            Ok(())
        }
    })
}

fn match_tokens(tokens: &[Token], value: &str) -> Result<bool, EvaluationLimit> {
    // Greedy wildcard matching avoids catastrophic regular-expression backtracking.
    let chars: Vec<char> = value.chars().collect();
    spend(chars.len() + tokens.len())?;
    let (mut p, mut v, mut star, mut retry) = (0usize, 0usize, None::<usize>, 0usize);
    while v < chars.len() {
        spend(1)?;
        match tokens.get(p) {
            Some(Token::Any) => {
                p += 1;
                v += 1;
            }
            Some(Token::Char(c)) if *c == chars[v] => {
                p += 1;
                v += 1;
            }
            Some(Token::Star) => {
                star = Some(p);
                p += 1;
                retry = v;
            }
            _ => match star {
                Some(star) => {
                    p = star + 1;
                    retry += 1;
                    v = retry;
                }
                None => return Ok(false),
            },
        }
    }
    while tokens.get(p) == Some(&Token::Star) {
        p += 1;
    }
    Ok(p == tokens.len())
}

/// Every `${...}` in a value must be a well-formed variable reference (`validPolicyVariables`).
pub fn valid_policy_variables(value: &str) -> bool {
    let mut index = value.find(VARIABLE_MARKER);
    while let Some(at) = index {
        let Some((_, length)) = variable_at(value, at) else {
            return false;
        };
        index = value[at + length..]
            .find(VARIABLE_MARKER)
            .map(|next| at + length + next);
    }
    true
}

/// Resolves the variables of a string condition value (`resolvePolicyValue`). None when any variable is unresolved.
pub fn resolve_policy_value(value: &str, context: Option<&Context>) -> Option<String> {
    if !value.contains(VARIABLE_MARKER) {
        return Some(value.to_owned());
    }
    let tokens = tokenize(value, context)?;
    Some(
        tokens
            .into_iter()
            .map(|token| match token {
                Token::Star => '*',
                Token::Any => '?',
                Token::Char(c) => c,
            })
            .collect(),
    )
}

fn astral(text: &str) -> bool {
    text.chars().any(|c| (c as u32) > 0xFFFF)
}

fn try_match_pattern(
    pattern: &str,
    value: &str,
    context: Option<&Context>,
) -> Result<bool, EvaluationLimit> {
    if pattern.contains(VARIABLE_MARKER) {
        return match tokenize(pattern, context) {
            Some(tokens) => match_tokens(&tokens, value),
            None => Ok(false),
        };
    }
    // `?` is one character (code point) on every path; astral characters take the token path.
    if pattern.contains('?') || astral(pattern) || astral(value) {
        let mut tokens = Vec::new();
        glob_tokens(pattern, &mut tokens);
        return match_tokens(&tokens, value);
    }
    match_stars(pattern, value)
}

/// Glob matching (`matchPattern`): anchored; only `*` and `?` are operators. Variables resolve from context.
pub fn match_pattern(pattern: &str, value: &str, context: Option<&Context>) -> bool {
    try_match_pattern(pattern, value, context).unwrap_or(false)
}

/// A glob whose only operator is `*` (`matchStars`).
fn match_stars(pattern: &str, value: &str) -> Result<bool, EvaluationLimit> {
    spend(js::utf16_len(pattern) + js::utf16_len(value))?;
    let pieces: Vec<&str> = pattern.split('*').collect();
    if pieces.len() == 1 {
        return Ok(pattern == value);
    }
    let first = pieces[0];
    let last = pieces[pieces.len() - 1];
    if value.len() < first.len() + last.len() || !value.starts_with(first) || !value.ends_with(last)
    {
        return Ok(false);
    }
    let end = value.len() - last.len();
    let mut cursor = first.len();
    for piece in &pieces[1..pieces.len() - 1] {
        if piece.is_empty() {
            continue;
        }
        let Some(found) = value[cursor..].find(piece) else {
            return Ok(false);
        };
        let at = cursor + found;
        if at + piece.len() > end {
            return Ok(false);
        }
        cursor = at + piece.len();
    }
    Ok(true)
}

/// An IP address: its bit width and value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Address {
    bits: u32,
    value: u128,
}

fn decimal_octet(part: &str) -> bool {
    let bytes = part.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 3
        && bytes.iter().all(u8::is_ascii_digit)
        && (bytes[0] != b'0' || bytes.len() == 1)
}

fn ipv4(value: &str) -> Option<Address> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4
        || parts
            .iter()
            .any(|part| !decimal_octet(part) || part.parse::<u32>().unwrap_or(256) > 255)
    {
        return None;
    }
    let value = parts.iter().fold(0u128, |result, part| {
        (result << 8) | part.parse::<u128>().unwrap_or(0)
    });
    Some(Address { bits: 32, value })
}

fn hex_group(part: &str) -> bool {
    (1..=4).contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn ip(value: &str) -> Option<Address> {
    if value.contains(['%', '/', '[', ']']) {
        return None;
    }
    if !value.contains(':') {
        return ipv4(value);
    }
    let mut normalized = value.to_owned();
    if normalized.contains('.') {
        let boundary = normalized.rfind(':')?;
        let suffix = ipv4(&normalized[boundary + 1..])?;
        normalized = format!(
            "{}{:x}:{:x}",
            &normalized[..boundary + 1],
            suffix.value >> 16,
            suffix.value & 65535
        );
    }
    let halves: Vec<&str> = normalized.split("::").collect();
    if halves.len() > 2 {
        return None;
    }
    let left: Vec<&str> = if halves[0].is_empty() {
        Vec::new()
    } else {
        halves[0].split(':').collect()
    };
    let right: Vec<&str> = if halves.len() == 2 && !halves[1].is_empty() {
        halves[1].split(':').collect()
    } else {
        Vec::new()
    };
    if left.iter().chain(right.iter()).any(|part| !hex_group(part)) {
        return None;
    }
    let total = left.len() + right.len();
    if (halves.len() == 1 && total != 8) || (halves.len() == 2 && total >= 8) {
        return None;
    }
    let mut parts: Vec<&str> = left;
    if halves.len() == 2 {
        parts.extend(std::iter::repeat_n("0", 8 - total));
        parts.extend(right);
    }
    let value = parts.iter().fold(0u128, |result, part| {
        (result << 16) | u128::from_str_radix(part, 16).unwrap_or(0)
    });
    Some(Address { bits: 128, value })
}

fn cidr(value: &str) -> Option<(Address, u32)> {
    let parts: Vec<&str> = value.split('/').collect();
    if parts.len() > 2 {
        return None;
    }
    let address = ip(parts[0])?;
    if parts.len() == 2 && !decimal_octet(parts[1]) {
        return None;
    }
    let prefix = if parts.len() == 2 {
        parts[1].parse().ok()?
    } else {
        address.bits
    };
    (prefix <= address.bits).then_some((address, prefix))
}

/// The IPv4 address carried by an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`), if it is one.
fn mapped_ipv4(address: Address) -> Option<Address> {
    (address.bits == 128 && address.value >> 32 == 0xffff).then_some(Address {
        bits: 32,
        value: address.value & 0xffff_ffff,
    })
}

fn in_network(actual: &str, expected: &str) -> bool {
    let (Some(mut address), Some((mut base, mut prefix))) = (ip(actual), cidr(expected)) else {
        return false;
    };
    // Across families the IPv4-mapped form stands for its IPv4 address, on either side.
    if address.bits != base.bits {
        let unmapped = mapped_ipv4(address);
        let mapped_network = if prefix >= 96 {
            mapped_ipv4(base)
        } else {
            None
        };
        if let Some(unmapped) = unmapped {
            address = unmapped;
        } else if let Some(mapped) = mapped_network {
            base = mapped;
            prefix -= 96;
        } else {
            return false;
        }
    }
    let shift = address.bits - prefix;
    address.value.checked_shr(shift).unwrap_or(0) == base.value.checked_shr(shift).unwrap_or(0)
}

/// True for an IPv4/IPv6 address or CIDR block, as accepted by the `IpAddress` operator (`isIpRange`).
pub fn is_ip_range(value: &str) -> bool {
    cidr(value).is_some()
}

/// True when `address` lies inside `network` (`ipMatches`), IPv4-mapped IPv6 addresses matching their IPv4 form.
pub fn ip_matches(address: &str, network: &str) -> bool {
    in_network(address, network)
}

/// The key a per-address counter uses for a client (`ipCounterKey`): an IPv4 address as itself, an IPv6 address as
/// its /64. None when the value is not an IP address.
pub fn ip_counter_key(address: &str) -> Option<String> {
    let parsed = ip(js::trim(address))?;
    let v4 = if parsed.bits == 32 {
        Some(parsed)
    } else {
        mapped_ipv4(parsed)
    };
    if let Some(v4) = v4 {
        return Some(
            [24, 16, 8, 0]
                .iter()
                .map(|shift| ((v4.value >> shift) & 255).to_string())
                .collect::<Vec<_>>()
                .join("."),
        );
    }
    let groups: Vec<String> = [112, 96, 80, 64]
        .iter()
        .map(|shift| format!("{:x}", (parsed.value >> shift) & 0xffff))
        .collect();
    Some(format!("{}::/64", groups.join(":")))
}

fn two_digits(bytes: &[u8], at: usize) -> Option<i64> {
    let (a, b) = (*bytes.get(at)?, *bytes.get(at + 1)?);
    (a.is_ascii_digit() && b.is_ascii_digit())
        .then(|| i64::from(a - b'0') * 10 + i64::from(b - b'0'))
}

/// An ISO 8601 timestamp as epoch milliseconds, with the engine's validation (`timestamp`): the
/// `YYYY-MM-DDTHH:MM:SS(.sss)?(Z|±HH:MM)` form, `Date.parse`, and no normalized calendar dates (February 31).
pub fn parse_timestamp(value: &str) -> Option<f64> {
    let bytes = value.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let year = {
        let digits = bytes.get(0..4)?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        digits
            .iter()
            .fold(0i64, |year, digit| year * 10 + i64::from(digit - b'0'))
    };
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let month = two_digits(bytes, 5)?;
    let day = two_digits(bytes, 8)?;
    let hour = two_digits(bytes, 11)?;
    let minute = two_digits(bytes, 14)?;
    let second = two_digits(bytes, 17)?;
    let mut at = 19;
    let mut millis = 0i64;
    if bytes.get(at) == Some(&b'.') {
        let start = at + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_digit() && end - start < 3 {
            end += 1;
        }
        if end == start {
            return None;
        }
        let digits = &bytes[start..end];
        millis = digits
            .iter()
            .fold(0i64, |sum, digit| sum * 10 + i64::from(digit - b'0'));
        millis *= 10i64.pow(3 - digits.len() as u32);
        at = end;
    }
    let offset_minutes = match bytes.get(at)? {
        b'Z' if at + 1 == bytes.len() => 0,
        sign @ (b'+' | b'-') if at + 6 == bytes.len() && bytes[at + 3] == b':' => {
            let (hours, minutes) = (two_digits(bytes, at + 1)?, two_digits(bytes, at + 4)?);
            // Date.parse refuses offsets beyond 23:59.
            if hours > 23 || minutes > 59 {
                return None;
            }
            let total = hours * 60 + minutes;
            if *sign == b'+' { total } else { -total }
        }
        _ => return None,
    };
    // Date.parse refuses out-of-range fields (24:00:00 is the end of the day); the checks below are the engine's.
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || minute > 59
        || second > 59
        || hour > 24
    {
        return None;
    }
    if hour == 24 && (minute != 0 || second != 0 || millis != 0) {
        return None;
    }
    let days = js::days_in_month(if year == 0 { 400 } else { year }, month);
    if day > days || hour > 23 {
        return None;
    }
    let date = js::days_from_civil(year, month, day) * 86_400_000
        + hour * 3_600_000
        + minute * 60_000
        + second * 1000
        + millis
        - offset_minutes * 60_000;
    Some(date as f64)
}

fn valid_value(operator: ConditionOperator, value: &Value) -> bool {
    use ConditionOperator::*;
    match operator {
        Bool | Exists => value.is_boolean(),
        NumericEquals
        | NumericNotEquals
        | NumericLessThan
        | NumericLessThanEquals
        | NumericGreaterThan
        | NumericGreaterThanEquals => value.is_number(),
        DateBefore | DateAfter => value.as_str().and_then(parse_timestamp).is_some(),
        IpAddress | NotIpAddress => value.as_str().is_some_and(|text| cidr(text).is_some()),
        StringEquals
        | StringNotEquals
        | StringEqualsIgnoreCase
        | StringNotEqualsIgnoreCase
        | StringLike
        | StringNotLike
        | StringLikeIgnoreCase => value
            .as_str()
            .is_some_and(|text| js::utf16_len(text) <= 2048),
        ArrayContains | ArrayContainsAll => match value {
            Value::String(text) => js::utf16_len(text) <= 2048,
            Value::Number(_) | Value::Bool(_) => true,
            _ => false,
        },
    }
}

/// Validate untrusted documents before storage and again before evaluation (`validatePolicy`).
pub fn validate_policy(value: &Value) -> IamResult<()> {
    let Value::Object(document) = value else {
        return Err(invalid("Policy must be a plain object"));
    };
    only_keys(document, &["version", "statements"])?;
    let statements = match (
        document.get("version").and_then(js::as_number),
        document.get("statements"),
    ) {
        (Some(version), Some(Value::Array(statements)))
            if version == 1.0 && statements.len() <= 128 =>
        {
            statements
        }
        _ => {
            return Err(invalid(
                "Expected policy version 1 and at most 128 statements",
            ));
        }
    };
    let mut sids = std::collections::HashSet::new();
    for statement in statements {
        let Value::Object(statement) = statement else {
            return Err(invalid("Statement must be a plain object"));
        };
        only_keys(
            statement,
            &["sid", "effect", "actions", "resources", "conditions"],
        )?;
        match statement.get("effect").and_then(Value::as_str) {
            Some("allow" | "deny") => {}
            _ => return Err(invalid("Statement effect must be allow or deny")),
        }
        if let Some(sid) = statement.get("sid") {
            let text = sid.as_str().filter(|_| nonempty(sid, 128));
            match text {
                Some(text) if !sids.contains(text) => {
                    sids.insert(text.to_owned());
                }
                _ => return Err(invalid("Statement IDs must be nonempty and unique")),
            }
        }
        for field in ["actions", "resources"] {
            let items = match statement.get(field) {
                Some(Value::Array(items))
                    if !items.is_empty()
                        && items.len() <= 128
                        && items.iter().all(|item| nonempty(item, 512)) =>
                {
                    items
                }
                _ => {
                    return Err(invalid(format!(
                        "{field} must contain 1–128 nonempty patterns"
                    )));
                }
            };
            let texts = items.iter().filter_map(Value::as_str);
            if field == "actions" {
                if texts.clone().any(|item| item.contains(VARIABLE_MARKER)) {
                    return Err(invalid("Policy variables are not allowed in actions"));
                }
            } else {
                for item in texts {
                    if !valid_policy_variables(item) {
                        return Err(invalid(format!(
                            "Malformed policy variable in resource pattern {item}"
                        )));
                    }
                    if item
                        .split('/')
                        .next()
                        .unwrap_or_default()
                        .contains(VARIABLE_MARKER)
                    {
                        return Err(invalid(
                            "Policy variables may only appear after the resource type",
                        ));
                    }
                }
            }
        }
        if let Some(conditions) = statement.get("conditions") {
            let conditions = match conditions {
                Value::Object(conditions) if !conditions.is_empty() => conditions,
                _ => return Err(invalid("Conditions must be a nonempty operator map")),
            };
            for (name, entries) in js::entries(conditions) {
                let operator = ConditionOperator::parse(name);
                let entries = match (operator, entries) {
                    (Some(_), Value::Object(entries))
                        if !entries.is_empty() && entries.len() <= 64 =>
                    {
                        entries
                    }
                    _ => return Err(invalid("Unknown operator or invalid condition attributes")),
                };
                let operator = operator.unwrap_or(ConditionOperator::Exists);
                for (key, expected) in js::entries(entries) {
                    if !nonempty_str(key, 128) || UNSAFE_KEYS.contains(&key.as_str()) {
                        return Err(invalid("Invalid condition attribute"));
                    }
                    let values: Vec<&Value> = match expected {
                        Value::Array(items) => items.iter().collect(),
                        single => vec![single],
                    };
                    if values.is_empty()
                        || values.len() > 64
                        || !values.iter().all(|item| valid_value(operator, item))
                    {
                        return Err(invalid(format!("Invalid value for condition {name}")));
                    }
                    if values.iter().any(|item| {
                        item.as_str()
                            .is_some_and(|text| !valid_policy_variables(text))
                    }) {
                        return Err(invalid(format!(
                            "Malformed policy variable in condition {name}"
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Typed document builder (`definePolicy`): validates and returns a detached document.
pub fn define_policy(document: &Value) -> IamResult<PolicyDocument> {
    PolicyDocument::from_value(document)
}

fn finite(value: &Value) -> Option<f64> {
    js::as_number(value)
}

/// A scalar member test for array context values; string members honour policy variables.
fn member(
    actual: &[Value],
    expected: &Value,
    context: Option<&Context>,
) -> Result<bool, EvaluationLimit> {
    let wanted = match expected {
        Value::String(text) => resolve_policy_value(text, context).map(Value::String),
        other => Some(other.clone()),
    };
    spend(actual.len())?;
    Ok(wanted.is_some_and(|wanted| js::includes(actual, &wanted)))
}

/// Case-insensitive matching lowers variable values too.
fn lower_case_context(context: Option<&Context>) -> Option<Context> {
    context.map(|context| {
        context
            .iter()
            .map(|(key, value)| {
                let value = match value {
                    Value::String(text) => Value::String(js::to_lower(text)),
                    other => other.clone(),
                };
                (key.clone(), value)
            })
            .collect()
    })
}

/// The positive comparison for an operator.
fn compare(
    operator: ConditionOperator,
    actual: &Value,
    expected: &Value,
    context: Option<&Context>,
) -> Result<bool, EvaluationLimit> {
    use ConditionOperator::*;
    Ok(match operator {
        Exists => js::strict_equal(actual, expected),
        StringEquals | StringNotEquals => match (actual, expected) {
            (Value::String(actual), Value::String(expected)) => {
                resolve_policy_value(expected, context).is_some_and(|resolved| *actual == resolved)
            }
            _ => false,
        },
        StringEqualsIgnoreCase | StringNotEqualsIgnoreCase => {
            let resolved = expected
                .as_str()
                .and_then(|expected| resolve_policy_value(expected, context));
            match (actual, resolved) {
                (Value::String(actual), Some(resolved)) => {
                    js::to_lower(actual) == js::to_lower(&resolved)
                }
                _ => false,
            }
        }
        StringLike | StringNotLike => match (actual, expected) {
            (Value::String(actual), Value::String(expected)) => {
                try_match_pattern(expected, actual, context)?
            }
            _ => false,
        },
        StringLikeIgnoreCase => match (actual, expected) {
            (Value::String(actual), Value::String(expected)) => {
                let lowered = lower_case_context(context);
                try_match_pattern(
                    &js::to_lower(expected),
                    &js::to_lower(actual),
                    lowered.as_ref(),
                )?
            }
            _ => false,
        },
        Bool => actual.is_boolean() && js::strict_equal(actual, expected),
        NumericEquals | NumericNotEquals => {
            finite(actual).is_some() && js::strict_equal(actual, expected)
        }
        NumericLessThan | NumericLessThanEquals | NumericGreaterThan | NumericGreaterThanEquals => {
            match (finite(actual), js::as_number(expected)) {
                (Some(actual), Some(expected)) => match operator {
                    NumericLessThan => actual < expected,
                    NumericLessThanEquals => actual <= expected,
                    NumericGreaterThan => actual > expected,
                    _ => actual >= expected,
                },
                _ => false,
            }
        }
        DateBefore | DateAfter => {
            match (
                actual.as_str().and_then(parse_timestamp),
                expected.as_str().and_then(parse_timestamp),
            ) {
                (Some(left), Some(right)) => {
                    if operator == DateBefore {
                        left < right
                    } else {
                        left > right
                    }
                }
                _ => false,
            }
        }
        IpAddress | NotIpAddress => match (actual, expected) {
            (Value::String(actual), Value::String(expected)) => in_network(actual, expected),
            _ => false,
        },
        ArrayContains | ArrayContainsAll => match actual {
            Value::Array(items) => member(items, expected, context)?,
            _ => false,
        },
    })
}

/// A negated operator only negates a comparison that could have succeeded: the actual value must have the
/// operator's type.
fn well_typed(operator: ConditionOperator, actual: &Value) -> bool {
    match operator {
        ConditionOperator::NumericNotEquals => finite(actual).is_some(),
        ConditionOperator::NotIpAddress => actual.as_str().is_some_and(|text| ip(text).is_some()),
        _ => actual.is_string(),
    }
}

fn matches(
    statement: &PolicyStatement,
    action: &str,
    resource: &str,
    context: Option<&Context>,
) -> Result<bool, EvaluationLimit> {
    let mut action_matched = false;
    for pattern in &statement.actions {
        if try_match_pattern(pattern, action, None)? {
            action_matched = true;
            break;
        }
    }
    if !action_matched {
        return Ok(false);
    }
    let mut resource_matched = false;
    for pattern in &statement.resources {
        if try_match_pattern(pattern, resource, context)? {
            resource_matched = true;
            break;
        }
    }
    if !resource_matched {
        return Ok(false);
    }
    let Some(conditions) = &statement.conditions else {
        return Ok(true);
    };
    for (operator, attributes) in conditions {
        let operator = *operator;
        for (key, expected) in attributes {
            let present = context.and_then(|context| context.get(key));
            // Missing or wrongly typed values never satisfy a condition, including negated ones.
            if operator != ConditionOperator::Exists && present.is_none() {
                return Ok(false);
            }
            let exists_value = Value::Bool(present.is_some());
            let actual = if operator == ConditionOperator::Exists {
                &exists_value
            } else {
                present.unwrap_or(&Value::Null)
            };
            if negated(operator) && !well_typed(operator, actual) {
                return Ok(false);
            }
            let values: Vec<&Value> = match expected {
                Value::Array(items) => items.iter().collect(),
                single => vec![single],
            };
            let test = |item: &Value| -> Result<bool, EvaluationLimit> {
                spend(1 + actual.as_str().map(js::utf16_len).unwrap_or(0))?;
                let outcome = compare(operator, actual, item, context)?;
                Ok(if negated(operator) { !outcome } else { outcome })
            };
            let satisfied = if every_value(operator) {
                let mut all = true;
                for item in values {
                    if !test(item)? {
                        all = false;
                        break;
                    }
                }
                all
            } else {
                let mut any = false;
                for item in values {
                    if test(item)? {
                        any = true;
                        break;
                    }
                }
                any
            };
            if !satisfied {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn invalid_request() -> IamError {
    IamError::new("INVALID_REQUEST", "Invalid policy evaluation request")
}

/// Grants form a union; every boundary is an independent intersection (`evaluatePolicy`). A boundary never grants
/// access. Callers must establish trusted context and tenant scope.
pub fn evaluate_policy(input: &EvaluationInput) -> IamResult<Decision> {
    if !nonempty_str(&input.action, 512) || !nonempty_str(&input.resource, 2048) {
        return Err(invalid_request());
    }
    let boundaries: &[PolicyDocument] = input.boundaries.as_deref().unwrap_or(&[]);
    for document in input.grants.iter().chain(boundaries) {
        validate_policy(&document.to_value())?;
    }
    Ok(run_evaluation(
        &input.action,
        &input.resource,
        input.context.as_ref(),
        &input.grants,
        boundaries,
    ))
}

/// [`evaluate_policy`] on untrusted JSON input (`{ action, resource, context?, grants, boundaries? }`), with the
/// TypeScript function's checks in the same order.
pub fn evaluate_policy_json(input: &Value) -> IamResult<Decision> {
    let Value::Object(input) = input else {
        return Err(invalid_request());
    };
    let action = input
        .get("action")
        .filter(|value| nonempty(value, 512))
        .and_then(Value::as_str);
    let resource = input
        .get("resource")
        .filter(|value| nonempty(value, 2048))
        .and_then(Value::as_str);
    let grants = input.get("grants").and_then(Value::as_array);
    let boundaries = match input.get("boundaries") {
        None => Some(None),
        Some(Value::Array(items)) => Some(Some(items)),
        Some(_) => None,
    };
    let context = match input.get("context") {
        None => Some(None),
        Some(Value::Object(context)) => Some(Some(context)),
        Some(_) => None,
    };
    let (Some(action), Some(resource), Some(grants), Some(boundaries), Some(context)) =
        (action, resource, grants, boundaries, context)
    else {
        return Err(invalid_request());
    };
    let empty = Vec::new();
    let boundary_values = boundaries.unwrap_or(&empty);
    for document in grants.iter().chain(boundary_values) {
        validate_policy(document)?;
    }
    let parse = |items: &Vec<Value>| {
        items
            .iter()
            .map(PolicyDocument::from_value)
            .collect::<IamResult<Vec<_>>>()
    };
    let grants = parse(grants)?;
    let boundaries = parse(boundary_values)?;
    Ok(run_evaluation(
        action,
        resource,
        context,
        &grants,
        &boundaries,
    ))
}

fn run_evaluation(
    action: &str,
    resource: &str,
    context: Option<&Context>,
    grants: &[PolicyDocument],
    boundaries: &[PolicyDocument],
) -> Decision {
    let mut matched = Vec::new();
    let mut granted = false;
    let mut boundary_allows = vec![false; boundaries.len()];
    let mut denied = false;
    let outer = WORK_LEFT.with(|left| left.replace(EVALUATION_WORK));
    let outcome = (|| -> Result<(), EvaluationLimit> {
        for (kind, policies) in [("grant", grants), ("boundary", boundaries)] {
            for (policy_index, document) in policies.iter().enumerate() {
                for (statement_index, statement) in document.statements.iter().enumerate() {
                    if !matches(statement, action, resource, context)? {
                        continue;
                    }
                    let label = statement
                        .sid
                        .clone()
                        .unwrap_or_else(|| statement_index.to_string());
                    matched.push(format!("{kind}:{policy_index}:{label}"));
                    if statement.effect == Effect::Deny {
                        denied = true;
                    } else if kind == "grant" {
                        granted = true;
                    } else {
                        boundary_allows[policy_index] = true;
                    }
                }
            }
        }
        Ok(())
    })();
    WORK_LEFT.with(|left| left.set(outer));
    let decision = |allowed: bool, reason: &str, matched: Vec<String>| Decision {
        allowed,
        reason: reason.to_owned(),
        matched,
    };
    if outcome.is_err() {
        // Too much matching work refuses, like a deny: nothing is granted on a partial evaluation.
        return decision(false, "evaluation-limit", matched);
    }
    if denied {
        return decision(false, "explicit-deny", matched);
    }
    if !granted {
        return decision(false, "no-grant", matched);
    }
    if boundary_allows.iter().any(|allowed| !allowed) {
        return decision(false, "boundary-deny", matched);
    }
    decision(true, "allowed", matched)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn timestamps_follow_date_parse() {
        assert_eq!(
            parse_timestamp("2024-01-01T00:00:00+23:59"),
            Some(1_703_980_860_000.0)
        );
        assert_eq!(parse_timestamp("2024-01-01T00:00:00+24:00"), None);
        assert_eq!(parse_timestamp("2024-02-30T00:00:00Z"), None);
        assert_eq!(
            parse_timestamp("0000-01-01T00:00:00Z"),
            Some(-62_167_219_200_000.0)
        );
        assert_eq!(
            parse_timestamp("2024-01-01T00:00:00.12Z"),
            Some(1_704_067_200_120.0)
        );
    }

    #[test]
    fn evaluates_a_grant() {
        let decision = evaluate_policy_json(&json!({
            "action": "docs:read",
            "resource": "doc/1",
            "grants": [{"version": 1, "statements": [{"effect": "allow", "actions": ["docs:*"], "resources": ["doc/*"]}]}]
        }))
        .unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.matched, vec!["grant:0:0"]);
    }
}
