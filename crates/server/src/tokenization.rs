//! Port of `packages/server/src/tokenization.ts`.
//!
//! Data protection by tokenization (like Skyflow, VGS or Google DLP de-identification): sensitive values (card
//! numbers, national identifiers, email addresses, phone numbers, free text) are replaced by tokens that are safe
//! to store and pass around. The values themselves are encrypted under a tenant KMS key, and turning a token back
//! into its value is decided by policy per profile and purpose. The API lives in api/protection.rs.
//!
//! Strings: JavaScript measures lengths in UTF-16 code units and iterates `[...value]` by code point; both are kept
//! here (`utf16_len`, `chars()`). A Rust string cannot hold an unpaired surrogate (the JSON decoder refuses one), so
//! the `LONE_SURROGATE` checks of the TypeScript cannot fail here.

use std::sync::LazyLock;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_iam_core::{IamError, IamResult, js as core_js};
use hmac::{Hmac, Mac};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::js::{internal_error, invalid_input, js_string, utf16_len};
use crate::validation::text;

/// `'card' | 'ssn' | 'email' | 'phone' | 'generic'`, as stored on a profile.
pub type DataType = Value;

pub const MAX_BATCH: f64 = 100.0;

pub const MAX_PROFILES_PER_TENANT: f64 = 100.0;

const MAX_GENERIC_LENGTH: usize = 4096;

/// `'last4' | 'first6last4' | 'email' | 'full'`, as stored on a profile.
pub type MaskStyle = Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileSummary {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(rename = "dataType")]
    pub data_type: crate::tokenization::DataType,
    #[serde(rename = "format")]
    pub format: crate::tokenization::TokenFormat,
    #[serde(rename = "deterministic")]
    pub deterministic: bool,
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "mask")]
    pub mask: crate::tokenization::MaskStyle,
    #[serde(
        rename = "retentionDays",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub retention_days: Option<f64>,
    /// Tokens the profile holds.
    #[serde(rename = "tokens")]
    pub tokens: f64,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtectedToken {
    /// `token:{profileId}:{SHA-256 of the token}`: a token names one value in its profile.
    #[serde(rename = "uniqueKey")]
    pub unique_key: String,
    #[serde(rename = "profileId")]
    pub profile_id: String,
    #[serde(rename = "token")]
    pub token: String,
    /// Keyed HMAC of the normalized value under the profile's lookup key, stored for every profile: deterministic
    /// profiles find the token they already issued by it, and erasure by value finds every token of a value.
    #[serde(rename = "fingerprint")]
    pub fingerprint: String,
    /// The batch's data key, wrapped under the profile's KMS key.
    #[serde(rename = "wrapped")]
    pub wrapped: String,
    /// iv | tag | ciphertext of the normalized value (AES-256-GCM, bound to tenant, profile and token).
    #[serde(rename = "sealed")]
    pub sealed: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtectionProfile {
    /// `name:{name}`: profiles are named in policies (`iam/protection/{name}`).
    #[serde(rename = "uniqueKey")]
    pub unique_key: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(rename = "dataType")]
    pub data_type: crate::tokenization::DataType,
    #[serde(rename = "format")]
    pub format: crate::tokenization::TokenFormat,
    /// The same value always gets the same token, so tokens can be joined and counted.
    #[serde(rename = "deterministic")]
    pub deterministic: bool,
    /// The tenant AES key that wraps each batch's data key and the lookup key.
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "mask")]
    pub mask: crate::tokenization::MaskStyle,
    /// Tokens older than this are deleted by `iam.protection.sweep()`.
    #[serde(
        rename = "retentionDays",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub retention_days: Option<f64>,
    /// The HMAC key behind value fingerprints, wrapped under the profile's KMS key like a batch data key: disabling or
    /// deleting that key stops lookups too, and stored fingerprints cannot be tested against guesses without it.
    #[serde(rename = "lookupKeyWrapped")]
    pub lookup_key_wrapped: String,
    /// Tokens the profile holds, kept by every write so nothing counts them by scanning.
    #[serde(rename = "tokens")]
    pub tokens: f64,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `'random' | 'format-preserving'`, as stored on a profile.
pub type TokenFormat = Value;

/// `protectionActions`: the actions of the protection API.
pub fn protection_actions() -> IamResult<Value> {
    Ok(json!({
        "read": "iam:protection:read",
        "manage": "iam:protection:manage",
        "tokenize": "iam:protection:tokenize",
        "detokenize": "iam:protection:detokenize",
        "mask": "iam:protection:mask",
        "delete": "iam:protection:delete",
    }))
}

pub const DATA_TYPES: &[&str] = &["card", "ssn", "email", "phone", "generic"];

pub fn profile_name(value: Option<&Value>) -> IamResult<String> {
    static PATTERN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9-]{0,63}$").expect("profile name pattern"));
    let name = text(value, "profile", 64)?;
    if !PATTERN.is_match(&name) {
        return Err(invalid_input(
            "Profile names are lowercase letters, digits and hyphens, starting with a letter",
        ));
    }
    Ok(name)
}

pub fn summarize_profile(
    profile: &crate::tokenization::ProtectionProfile,
) -> IamResult<crate::tokenization::ProfileSummary> {
    Ok(ProfileSummary {
        id: profile.id.clone(),
        tenant_id: profile.tenant_id.clone(),
        name: profile.name.clone(),
        description: profile.description.clone(),
        data_type: profile.data_type.clone(),
        format: profile.format.clone(),
        deterministic: profile.deterministic,
        key_id: profile.key_id.clone(),
        mask: profile.mask.clone(),
        retention_days: profile.retention_days,
        tokens: profile.tokens,
        created_at: profile.created_at,
        created_by: profile.created_by.clone(),
        updated_at: profile.updated_at,
        extra: Map::new(),
    })
}

/// The mask a data type gets when none is named.
pub static DEFAULT_MASK: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
    || json!({"card":"last4","ssn":"last4","email":"email","phone":"last4","generic":"full"}),
);

/// The masks each data type may use: a style meant for one kind of value can reveal most of another.
fn mask_styles(data_type: &str) -> Option<&'static [&'static str]> {
    match data_type {
        "card" => Some(&["last4", "first6last4", "full"]),
        "ssn" => Some(&["last4", "full"]),
        "email" => Some(&["email", "full"]),
        "phone" => Some(&["last4", "full"]),
        "generic" => Some(&["full", "last4"]),
        _ => None,
    }
}

/// The data type as the string a profile stores (`maskStyles[type]` of an unknown type is a TypeError).
fn type_name(data_type: &DataType) -> IamResult<&str> {
    match data_type.as_str() {
        Some(name) if DATA_TYPES.contains(&name) => Ok(name),
        _ => Err(internal_error()),
    }
}

pub fn mask_style(
    r#type: &crate::tokenization::DataType,
    value: Option<&Value>,
    name: Option<&str>,
) -> IamResult<crate::tokenization::MaskStyle> {
    let data_type = type_name(r#type)?;
    let styles = mask_styles(data_type).ok_or_else(internal_error)?;
    let name = name.unwrap_or("mask");
    match value {
        Some(Value::String(style)) if styles.contains(&style.as_str()) => {
            Ok(Value::String(style.clone()))
        }
        _ => Err(invalid_input(format!(
            "{name} must be one of {} for {data_type} values",
            styles.join(", ")
        ))),
    }
}

/// Format-preserving `ssn` and `phone` tokens keep the last four digits, leaving few random ones (10,000 tokens per
/// last four of a social security number): issuing a new token on every call would use them up, so these profiles
/// are deterministic.
pub fn needs_deterministic(
    r#type: &crate::tokenization::DataType,
    format: &crate::tokenization::TokenFormat,
) -> IamResult<bool> {
    Ok(format.as_str() == Some("format-preserving")
        && matches!(r#type.as_str(), Some("ssn") | Some("phone")))
}

// ---------------------------------------------------------------------------------------------------------------
// Values

fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0u32;
    for (index, character) in digits.chars().rev().enumerate() {
        let mut digit = character.to_digit(10).unwrap_or(0);
        if index % 2 == 1 {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
    }
    sum.is_multiple_of(10)
}

/// Control characters other than tab and line feed, DEL and the C1 range included.
fn is_control(character: char) -> bool {
    matches!(character as u32, 0x00..=0x08 | 0x0b..=0x1f | 0x7f..=0x9f)
}

/// Bidirectional formatting controls, which make text display as something other than what it is.
fn is_bidi(character: char) -> bool {
    matches!(
        character as u32,
        0x061c | 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069
    )
}

/// `value.replace(/[{class}]/g, '')` for a class of JavaScript whitespace plus the given characters.
fn strip(value: &str, also: &[char]) -> String {
    value
        .chars()
        .filter(|character| !core_js::is_js_whitespace(*character) && !also.contains(character))
        .collect()
}

fn all_ascii_digits(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_digit())
}

/// `/^[^\s@<>()[\],;:"\\]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/`.
fn email_shape(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    let local_ok = |character: char| {
        !core_js::is_js_whitespace(character)
            && !matches!(
                character,
                '@' | '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';' | ':' | '"' | '\\'
            )
    };
    if local.is_empty() || !local.chars().all(local_ok) {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

/// Validates and normalizes a value for its data type: card numbers to their digits (12 to 19, Luhn-valid), US
/// social security numbers to `NNN-NN-NNNN`, email addresses to NFC lowercase, phone numbers to `+digits` or digits
/// (7 to 15, compared as written, so give them in E.164), and anything else to NFC (up to 4096 characters of
/// well-formed text without control or bidirectional formatting characters; tab and line feed are allowed).
pub fn normalize_value(
    r#type: &crate::tokenization::DataType,
    value: Option<&Value>,
) -> IamResult<String> {
    let Some(Value::String(value)) = value else {
        return Err(invalid_input("Every value must be a string"));
    };
    let invalid = |what: &str| invalid_input(format!("Not a valid {what}"));
    match r#type.as_str() {
        Some("card") => {
            let digits = strip(value, &['-']);
            let length = digits.len();
            if !(12..=19).contains(&length) || !all_ascii_digits(&digits) || !luhn_valid(&digits) {
                return Err(invalid("card number"));
            }
            Ok(digits)
        }
        Some("ssn") => {
            let digits = strip(value, &['-']);
            if digits.len() != 9 || !all_ascii_digits(&digits) {
                return Err(invalid("social security number"));
            }
            Ok(format!(
                "{}-{}-{}",
                &digits[..3],
                &digits[3..5],
                &digits[5..]
            ))
        }
        Some("email") => {
            let email = core_js::to_lower(&core_js::trim(value).nfc().collect::<String>());
            if utf16_len(&email) > 254
                || email.chars().any(is_control)
                || email.chars().any(is_bidi)
                || !email_shape(&email)
            {
                return Err(invalid("email address"));
            }
            Ok(email)
        }
        Some("phone") => {
            let compact = strip(value, &['(', ')', '.', '-']);
            let digits = compact.strip_prefix('+').unwrap_or(&compact);
            if !(7..=15).contains(&digits.len()) || !all_ascii_digits(digits) {
                return Err(invalid("phone number"));
            }
            Ok(compact)
        }
        Some("generic") => {
            let refuse = || {
                invalid_input(format!(
                    "Values are 1 to {MAX_GENERIC_LENGTH} characters of well-formed text without control or bidirectional formatting characters"
                ))
            };
            if value.chars().any(is_control) || value.chars().any(is_bidi) {
                return Err(refuse());
            }
            let normalized: String = value.nfc().collect();
            if normalized.is_empty() || utf16_len(&normalized) > MAX_GENERIC_LENGTH {
                return Err(refuse());
            }
            Ok(normalized)
        }
        // The switch has no case for it: TypeScript returns undefined, which no caller can use.
        _ => Err(internal_error()),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Tokens

const BASE62: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";

/// `randomInt(max)`: a uniform integer in `[0, max)` from the system's CSPRNG.
fn random_int(max: usize) -> usize {
    let max = max as u64;
    // Rejection sampling over 64 bits, as Node's randomInt does over 48: no modulo bias.
    let limit = u64::MAX - (u64::MAX % max);
    loop {
        let bytes = better_iam_auth::crypto::random_bytes(8);
        let draw = u64::from_le_bytes(bytes.try_into().expect("8 random bytes"));
        if draw < limit {
            return (draw % max) as usize;
        }
    }
}

fn pick(alphabet: &str, length: usize) -> String {
    let characters: Vec<char> = alphabet.chars().collect();
    (0..length)
        .map(|_| characters[random_int(characters.len())])
        .collect()
}

fn digits(length: usize) -> String {
    pick(DIGITS, length)
}

/// Letters and digits of any script: what masks hide and format-preserving tokens replace.
static MASKABLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\p{L}\p{M}\p{N}]").expect("maskable pattern"));
static LETTER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\p{L}\p{M}]").expect("letter pattern"));
static CAPITAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\p{Lu}\p{Lt}]").expect("capital pattern"));
static NUMBER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\p{N}").expect("number pattern"));

fn char_matches(pattern: &Regex, character: char) -> bool {
    let mut buffer = [0u8; 4];
    pattern.is_match(character.encode_utf8(&mut buffer))
}

fn maskable(character: char) -> bool {
    char_matches(&MASKABLE, character)
}

/// Group digits that no SSN or ITIN has with a 9XX area (ITIN groups are 50-65, 70-88, 90-92 and 94-99).
static SSN_TOKEN_GROUPS: LazyLock<Vec<String>> = LazyLock::new(|| {
    (0..100u32)
        .filter(|group| {
            (1..=49).contains(group) || (66..=69).contains(group) || *group == 89 || *group == 93
        })
        .map(|group| format!("{group:02}"))
        .collect()
});

/// The last `count` UTF-16 code units of `value` (`value.slice(-count)`); `value` is ASCII where this is used.
fn last(value: &str, count: usize) -> &str {
    &value[value.len().saturating_sub(count)..]
}

fn format_preserving(data_type: &str, value: &str) -> IamResult<String> {
    Ok(match data_type {
        "card" => digits(value.len().saturating_sub(4)) + last(value, 4),
        "ssn" => format!(
            "9{}-{}-{}",
            digits(2),
            SSN_TOKEN_GROUPS[random_int(SSN_TOKEN_GROUPS.len())],
            last(value, 4)
        ),
        "email" => {
            let domain = match value.rfind('@') {
                Some(at) => &value[at + 1..],
                None => value,
            };
            format!("{}@{domain}", pick(&format!("{LOWER}{DIGITS}"), 16))
        }
        "phone" => {
            let plus = if value.starts_with('+') { "+" } else { "" };
            let body = &value[plus.len()..];
            format!(
                "{plus}{}{}",
                digits(body.len().saturating_sub(4)),
                last(body, 4)
            )
        }
        "generic" => value
            .chars()
            .map(|character| {
                if char_matches(&CAPITAL, character) {
                    pick(UPPER, 1)
                } else if char_matches(&LETTER, character) {
                    pick(LOWER, 1)
                } else if char_matches(&NUMBER, character) {
                    digits(1)
                } else {
                    character.to_string()
                }
            })
            .collect(),
        _ => return Err(internal_error()),
    })
}

/// A new token for a normalized value; never the value itself. Random tokens are `tok_` and 22 base62 characters
/// (131 bits). Format-preserving tokens keep what systems validate or display: - card: the same length and last
/// four digits, but failing the Luhn check, so a token is never a card number; - ssn: `9XX-`, group digits outside
/// the ITIN ranges and the last four digits, so a token is never an SSN or ITIN; - email: a random local part at
/// the same domain; - phone: the same length, leading `+` and last four digits; - generic: the same length in
/// characters, each letter (of any script) replaced by an ASCII letter (capitals by capitals), each digit by a
/// digit, the rest kept.
pub fn new_token(
    r#type: &crate::tokenization::DataType,
    format: &crate::tokenization::TokenFormat,
    value: &str,
) -> IamResult<String> {
    if format.as_str() == Some("random") {
        return Ok(format!("tok_{}", pick(BASE62, 22)));
    }
    let data_type = r#type.as_str().unwrap_or_default();
    loop {
        let candidate = format_preserving(data_type, value)?;
        if candidate != value && (data_type != "card" || !luhn_valid(&candidate)) {
            return Ok(candidate);
        }
    }
}

/// Format-preserving generic tokens need enough random positions to be unguessable and unique.
pub fn format_preserving_space(
    r#type: &crate::tokenization::DataType,
    value: &str,
) -> IamResult<bool> {
    if r#type.as_str() != Some("generic") {
        return Ok(true);
    }
    Ok(value
        .chars()
        .filter(|character| maskable(*character))
        .count()
        >= 12)
}

/// Where a token is unique: its profile, by hash (a format-preserving token can be long).
pub fn token_key(profile_id: &str, token: &str) -> IamResult<String> {
    Ok(format!(
        "token:{profile_id}:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
    ))
}

/// A masked form of a normalized value, for display. A mask never shows more than half of a value's letters and
/// digits, except the first six and last four digits of a card number of 15 or more digits (what PCI DSS allows
/// showing); on a shorter card number `first6last4` shows the last four only. Letters and digits of every script
/// are hidden.
pub fn mask_value(
    r#type: &crate::tokenization::DataType,
    style: &crate::tokenization::MaskStyle,
    value: &str,
) -> IamResult<String> {
    let characters: Vec<char> = value.chars().collect();
    let total = characters.iter().filter(|c| maskable(**c)).count();
    let half = total / 2;
    let hide = |mut keep_start: usize, mut keep_end: usize, capped: bool| -> String {
        if capped && keep_start + keep_end > half {
            keep_start = 0;
            keep_end = keep_end.min(half);
        }
        let mut seen = 0usize;
        characters
            .iter()
            .map(|character| {
                if !maskable(*character) {
                    return *character;
                }
                let position = seen;
                seen += 1;
                if position < keep_start || position + keep_end >= total {
                    *character
                } else {
                    '*'
                }
            })
            .collect()
    };
    match style.as_str() {
        Some("last4") => Ok(hide(0, 4, true)),
        Some("first6last4") => Ok(if r#type.as_str() == Some("card") && total >= 15 {
            hide(6, 4, false)
        } else {
            hide(0, 4, true)
        }),
        Some("email") => {
            let at = value.rfind('@');
            let Some(at) = at.filter(|at| *at >= 1) else {
                return Ok(hide(0, 0, true));
            };
            let local: Vec<char> = value[..at].chars().collect();
            // The first character only when most of the local part stays hidden.
            let first = if local.len() >= 4 {
                local[0].to_string()
            } else {
                "*".to_owned()
            };
            Ok(format!("{first}***@{}", &value[at + 1..]))
        }
        Some("full") => Ok(hide(0, 0, true)),
        // The switch has no case for it: TypeScript returns undefined.
        _ => Err(internal_error()),
    }
}

pub fn fingerprint(key: &[u8], value: &str) -> IamResult<String> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| internal_error())?;
    mac.update(value.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

/// The encryption context of a profile's lookup key (batch data keys are bound to `{ protection }` alone).
pub fn lookup_context(profile_id: &str) -> IamResult<Value> {
    Ok(json!({ "protection": profile_id, "use": "lookup" }))
}

fn aad(tenant_id: &str, profile_id: &str, token: &str) -> Vec<u8> {
    format!("protection:{tenant_id}:{profile_id}:{token}").into_bytes()
}

pub fn seal_value(
    data_key: &[u8],
    tenant_id: &str,
    profile_id: &str,
    token: &str,
    value: &str,
) -> IamResult<String> {
    // `createCipheriv` refuses a key that is not 32 bytes (a plain Error).
    let cipher = Aes256Gcm::new_from_slice(data_key).map_err(|_| internal_error())?;
    let iv = better_iam_auth::crypto::random_bytes(12);
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: value.as_bytes(),
                aad: &aad(tenant_id, profile_id, token),
            },
        )
        .map_err(|_| internal_error())?;
    // aes-gcm appends the tag; the stored form is iv | tag | ciphertext.
    let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
    let mut out = Vec::with_capacity(12 + sealed.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(tag);
    out.extend_from_slice(ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(out))
}

/// Opens a stored value; a record that fails authentication was altered in storage.
pub fn open_value(data_key: &[u8], record: &Value) -> IamResult<String> {
    let unavailable = || {
        IamError::with_status(
            "KEY_MATERIAL_UNAVAILABLE",
            "A stored value cannot be opened",
            500,
        )
    };
    let Some(sealed) = record.get("sealed").and_then(Value::as_str) else {
        return Err(unavailable());
    };
    let bytes = better_iam_auth::util::node_base64_decode(sealed);
    if bytes.len() < 28 {
        return Err(unavailable());
    }
    let cipher = Aes256Gcm::new_from_slice(data_key).map_err(|_| unavailable())?;
    let mut payload = bytes[28..].to_vec();
    payload.extend_from_slice(&bytes[12..28]);
    let aad = aad(
        &js_string(record.get("tenantId")),
        &js_string(record.get("profileId")),
        &js_string(record.get("token")),
    );
    let opened = cipher
        .decrypt(
            Nonce::from_slice(&bytes[..12]),
            Payload {
                msg: &payload,
                aad: &aad,
            },
        )
        .map_err(|_| unavailable())?;
    Ok(String::from_utf8_lossy(&opened).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(value: &str) -> Value {
        Value::String(value.to_owned())
    }

    #[test]
    fn masks_and_tokens_keep_their_shapes() {
        assert_eq!(
            mask_value(&s("card"), &s("first6last4"), "4111111111111111").unwrap(),
            "411111******1111"
        );
        assert_eq!(
            mask_value(&s("email"), &s("email"), "alice@example.com").unwrap(),
            "a***@example.com"
        );
        assert_eq!(
            mask_value(&s("ssn"), &s("last4"), "123-45-6789").unwrap(),
            "***-**-6789"
        );
        let token = new_token(&s("card"), &s("format-preserving"), "4111111111111111").unwrap();
        assert_eq!(token.len(), 16);
        assert!(token.ends_with("1111") && !luhn_valid(&token));
        let random = new_token(&s("card"), &s("random"), "4111111111111111").unwrap();
        assert!(random.starts_with("tok_") && random.len() == 26);
    }

    #[test]
    fn sealed_values_open_with_the_same_binding() {
        let key = better_iam_auth::crypto::random_bytes(32);
        let sealed = seal_value(&key, "t", "p", "tok", "secret").unwrap();
        let record = json!({ "tenantId": "t", "profileId": "p", "token": "tok", "sealed": sealed });
        assert_eq!(open_value(&key, &record).unwrap(), "secret");
        let moved =
            json!({ "tenantId": "t", "profileId": "p", "token": "other", "sealed": sealed });
        assert_eq!(
            open_value(&key, &moved).unwrap_err().code,
            "KEY_MATERIAL_UNAVAILABLE"
        );
    }
}
