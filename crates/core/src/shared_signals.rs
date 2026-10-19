//! Shared Signals (OpenID SSF 1.0 with CAEP and RISC) (`shared-signals.ts`): event-type URIs, subject identifiers
//! (RFC 9493, the SSF `complex` format and the legacy RISC `subject`), and a reader for the claims of a Security Event
//! Token (RFC 8417) whose signature, issuer, audience and `typ` the caller has already verified. No cryptography and no
//! I/O.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::jcs::canonicalize_json;
use crate::js;

const CAEP: &str = "https://schemas.openid.net/secevent/caep/event-type/";
const RISC: &str = "https://schemas.openid.net/secevent/risc/event-type/";
const SSF: &str = "https://schemas.openid.net/secevent/ssf/event-type/";
const SSE: &str = "https://schemas.openid.net/secevent/sse/event-type/";

/// The security events a receiver understands, by name (`SignalEventType`); `unknown` for every other URI.
pub const SIGNAL_EVENT_TYPES: [(&str, &str, &str); 16] = [
    ("session-revoked", CAEP, "session-revoked"),
    ("credential-change", CAEP, "credential-change"),
    ("token-claims-change", CAEP, "token-claims-change"),
    ("assurance-level-change", CAEP, "assurance-level-change"),
    ("device-compliance-change", CAEP, "device-compliance-change"),
    ("risk-level-change", CAEP, "risk-level-change"),
    ("account-disabled", RISC, "account-disabled"),
    ("account-enabled", RISC, "account-enabled"),
    ("account-purged", RISC, "account-purged"),
    (
        "account-credential-change-required",
        RISC,
        "account-credential-change-required",
    ),
    ("credential-compromise", RISC, "credential-compromise"),
    ("identifier-changed", RISC, "identifier-changed"),
    ("identifier-recycled", RISC, "identifier-recycled"),
    ("sessions-revoked", RISC, "sessions-revoked"),
    ("verification", SSF, "verification"),
    ("stream-updated", SSF, "stream-updated"),
];

/// The event-type URI of each known security event (`signalEventUris`).
pub fn signal_event_uris() -> Vec<(&'static str, String)> {
    SIGNAL_EVENT_TYPES
        .iter()
        .map(|(name, base, suffix)| (*name, format!("{base}{suffix}")))
        .collect()
}

/// The event type an event-type URI names (exact match), or `unknown` (`signalEventType`).
pub fn signal_event_type(uri: &str) -> &'static str {
    for (name, base, suffix) in SIGNAL_EVENT_TYPES {
        if uri.strip_prefix(base) == Some(suffix) {
            return name;
        }
    }
    // Before SSF 1.0 the control events lived under the RISC namespace and, briefly, under the SSE drafts'.
    for base in [RISC, SSE] {
        match uri.strip_prefix(base) {
            Some("verification") => return "verification",
            Some("stream-updated") => return "stream-updated",
            _ => {}
        }
    }
    "unknown"
}

/// The members of a `complex` subject, in order.
pub const COMPLEX_MEMBERS: [&str; 7] = [
    "user",
    "session",
    "device",
    "tenant",
    "group",
    "application",
    "org_unit",
];

/// A subject identifier (`SubjectIdentifier`): RFC 9493 section 3 plus the SSF 1.0 `complex` format.
#[derive(Debug, Clone, PartialEq)]
pub enum SubjectIdentifier {
    IssSub {
        iss: String,
        sub: String,
    },
    Email {
        email: String,
    },
    Opaque {
        id: String,
    },
    Account {
        uri: String,
    },
    PhoneNumber {
        phone_number: String,
    },
    Did {
        url: String,
    },
    Uri {
        uri: String,
    },
    Aliases {
        identifiers: Vec<SubjectIdentifier>,
    },
    /// Members by name (`user`, `session`, ...), in [`COMPLEX_MEMBERS`] order.
    Complex {
        members: Vec<(&'static str, SubjectIdentifier)>,
    },
}

impl SubjectIdentifier {
    /// The `format` member.
    pub fn format(&self) -> &'static str {
        match self {
            SubjectIdentifier::IssSub { .. } => "iss_sub",
            SubjectIdentifier::Email { .. } => "email",
            SubjectIdentifier::Opaque { .. } => "opaque",
            SubjectIdentifier::Account { .. } => "account",
            SubjectIdentifier::PhoneNumber { .. } => "phone_number",
            SubjectIdentifier::Did { .. } => "did",
            SubjectIdentifier::Uri { .. } => "uri",
            SubjectIdentifier::Aliases { .. } => "aliases",
            SubjectIdentifier::Complex { .. } => "complex",
        }
    }

    /// The identifier as JSON, members in the order the TypeScript reader writes them.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("format".into(), Value::String(self.format().into()));
        let mut put = |key: &str, value: &str| {
            map.insert(key.into(), Value::String(value.into()));
        };
        match self {
            SubjectIdentifier::IssSub { iss, sub } => {
                put("iss", iss);
                put("sub", sub);
            }
            SubjectIdentifier::Email { email } => put("email", email),
            SubjectIdentifier::Opaque { id } => put("id", id),
            SubjectIdentifier::Account { uri } | SubjectIdentifier::Uri { uri } => put("uri", uri),
            SubjectIdentifier::PhoneNumber { phone_number } => put("phone_number", phone_number),
            SubjectIdentifier::Did { url } => put("url", url),
            SubjectIdentifier::Aliases { identifiers } => {
                map.insert(
                    "identifiers".into(),
                    Value::Array(identifiers.iter().map(Self::to_value).collect()),
                );
            }
            SubjectIdentifier::Complex { members } => {
                for (name, identifier) in members {
                    map.insert((*name).into(), identifier.to_value());
                }
            }
        }
        Value::Object(map)
    }

    /// The `iss_sub` parts, when it is one.
    pub fn iss_sub(&self) -> Option<(&str, &str)> {
        match self {
            SubjectIdentifier::IssSub { iss, sub } => Some((iss, sub)),
            _ => None,
        }
    }
}

impl Serialize for SubjectIdentifier {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_value().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SubjectIdentifier {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        parse_subject_identifier(&value)
            .ok_or_else(|| serde::de::Error::custom("Invalid subject identifier"))
    }
}

const MAX_STRING: usize = 512;
const MAX_ALIASES: usize = 10;
const MAX_SUBJECT_DEPTH: usize = 3;
const MAX_AUDIENCES: usize = 20;
const MAX_EVENT_DEPTH: usize = 10;
const MAX_SECONDS: f64 = 1e11;

/// A string of 1 to 512 characters with no control characters (C0, DEL or C1).
fn text(value: Option<&Value>) -> Option<&str> {
    let text = value?.as_str()?;
    let length = js::utf16_len(text);
    (length > 0
        && length <= MAX_STRING
        && !text
            .chars()
            .any(|c| (c as u32) < 0x20 || (0x7f..=0x9f).contains(&(c as u32))))
    .then_some(text)
}

fn email_address(value: Option<&Value>) -> Option<&str> {
    let text = text(value)?;
    email_text(text).then_some(text)
}

fn email_text(text: &str) -> bool {
    if js::has_js_whitespace(text) {
        return false;
    }
    match text.rfind('@') {
        Some(at) => at > 0 && at + 1 < text.len(),
        None => false,
    }
}

fn account_uri(value: Option<&Value>) -> Option<&str> {
    let text = text(value)?;
    let ok = text.len() >= 5
        && text.is_char_boundary(5)
        && text[..5].eq_ignore_ascii_case("acct:")
        && js::utf16_len(&text[5..]) <= MAX_STRING
        && !text[5..].is_empty()
        && !text[5..]
            .chars()
            .any(|c| (c as u32) < 0x20 || (0x7f..=0x9f).contains(&(c as u32)))
        && email_text(&text[5..]);
    ok.then_some(text)
}

fn non_space(text: &str) -> bool {
    !text.is_empty() && !js::has_js_whitespace(text)
}

fn did_url(value: Option<&Value>) -> Option<&str> {
    let text = text(value)?;
    let rest = text.strip_prefix("did:")?;
    let colon = rest.find(':')?;
    let (method, tail) = (&rest[..colon], &rest[colon + 1..]);
    (!method.is_empty()
        && method
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && non_space(tail))
    .then_some(text)
}

fn generic_uri(value: Option<&Value>) -> Option<&str> {
    let text = text(value)?;
    let bytes = text.as_bytes();
    if !bytes.first()?.is_ascii_alphabetic() {
        return None;
    }
    let end = bytes
        .iter()
        .position(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-')))?;
    (bytes[end] == b':' && non_space(&text[end + 1..])).then_some(text)
}

#[derive(Clone, Copy)]
struct SubjectScope {
    depth: usize,
    in_aliases: bool,
    in_complex: bool,
}

fn read_subject(value: &Value, scope: SubjectScope) -> Option<SubjectIdentifier> {
    if scope.depth > MAX_SUBJECT_DEPTH {
        return None;
    }
    let subject = value.as_object()?;
    let own = |key: &str| subject.get(key);
    match own("format")?.as_str()? {
        "iss_sub" => Some(SubjectIdentifier::IssSub {
            iss: text(own("iss"))?.into(),
            sub: text(own("sub"))?.into(),
        }),
        "email" => Some(SubjectIdentifier::Email {
            email: email_address(own("email"))?.into(),
        }),
        "opaque" => Some(SubjectIdentifier::Opaque {
            id: text(own("id"))?.into(),
        }),
        "account" => Some(SubjectIdentifier::Account {
            uri: account_uri(own("uri"))?.into(),
        }),
        "phone_number" => Some(SubjectIdentifier::PhoneNumber {
            phone_number: text(own("phone_number"))?.into(),
        }),
        "did" => Some(SubjectIdentifier::Did {
            url: did_url(own("url"))?.into(),
        }),
        "uri" => Some(SubjectIdentifier::Uri {
            uri: generic_uri(own("uri"))?.into(),
        }),
        "aliases" => {
            // RFC 9493 section 3.2.8: an alias list never nests another, directly or through a complex subject.
            if scope.in_aliases {
                return None;
            }
            let listed = own("identifiers")?.as_array()?;
            if listed.is_empty() || listed.len() > MAX_ALIASES {
                return None;
            }
            let inner = SubjectScope {
                depth: scope.depth + 1,
                in_aliases: true,
                ..scope
            };
            let identifiers = listed
                .iter()
                .map(|entry| read_subject(entry, inner))
                .collect::<Option<Vec<_>>>()?;
            Some(SubjectIdentifier::Aliases { identifiers })
        }
        "complex" => {
            // Each member names one part of the subject; a complex part is not one.
            if scope.in_complex {
                return None;
            }
            let inner = SubjectScope {
                depth: scope.depth + 1,
                in_complex: true,
                ..scope
            };
            let mut members = Vec::new();
            for member in COMPLEX_MEMBERS {
                let Some(entry) = own(member) else { continue };
                members.push((member, read_subject(entry, inner)?));
            }
            (!members.is_empty()).then_some(SubjectIdentifier::Complex { members })
        }
        _ => None,
    }
}

/// Reads an RFC 9493 subject identifier (or an SSF `complex` one) strictly (`parseSubjectIdentifier`). Members a
/// format does not define are left out of the result. None for anything else.
pub fn parse_subject_identifier(value: &Value) -> Option<SubjectIdentifier> {
    read_subject(
        value,
        SubjectScope {
            depth: 1,
            in_aliases: false,
            in_complex: false,
        },
    )
}

/// Reads the subject of a legacy RISC event (`legacyRiscSubject`).
pub fn legacy_risc_subject(value: Option<&Value>) -> Option<SubjectIdentifier> {
    let subject = value?.as_object()?;
    let (iss, sub, email, phone) = (
        subject.get("iss"),
        subject.get("sub"),
        subject.get("email"),
        subject.get("phone"),
    );
    match subject.get("subject_type")?.as_str()? {
        "iss-sub" | "iss_sub" => Some(SubjectIdentifier::IssSub {
            iss: text(iss)?.into(),
            sub: text(sub)?.into(),
        }),
        "email" => Some(SubjectIdentifier::Email {
            email: email_address(email)?.into(),
        }),
        "phone" => Some(SubjectIdentifier::PhoneNumber {
            phone_number: text(phone)?.into(),
        }),
        "id_token_claims" | "id-token-claims" => {
            let mut identifiers = Vec::new();
            if iss.is_some() || sub.is_some() {
                identifiers.push(SubjectIdentifier::IssSub {
                    iss: text(iss)?.into(),
                    sub: text(sub)?.into(),
                });
            }
            if email.is_some() {
                identifiers.push(SubjectIdentifier::Email {
                    email: email_address(email)?.into(),
                });
            }
            if phone.is_some() {
                identifiers.push(SubjectIdentifier::PhoneNumber {
                    phone_number: text(phone)?.into(),
                });
            }
            if identifiers.len() < 2 {
                return identifiers.into_iter().next();
            }
            Some(SubjectIdentifier::Aliases { identifiers })
        }
        _ => None,
    }
}

/// Why a SET's claims were refused (`SignalFormatError.reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignalFormatReason {
    Events,
    Subject,
    Nonce,
    Claims,
    Size,
}

impl SignalFormatReason {
    pub fn as_str(self) -> &'static str {
        match self {
            SignalFormatReason::Events => "events",
            SignalFormatReason::Subject => "subject",
            SignalFormatReason::Nonce => "nonce",
            SignalFormatReason::Claims => "claims",
            SignalFormatReason::Size => "size",
        }
    }
}

/// Why a SET's claims were refused (`SignalFormatError`): the receiver answers `invalid_request` for each.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct SignalFormatError {
    pub reason: SignalFormatReason,
    pub message: String,
}

fn refuse(reason: SignalFormatReason, message: impl Into<String>) -> SignalFormatError {
    SignalFormatError {
        reason,
        message: message.into(),
    }
}

/// The claims of a verified Security Event Token, normalized (`SecurityEventClaims`).
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityEventClaims {
    pub iss: String,
    pub aud: Vec<String>,
    pub iat: f64,
    pub jti: String,
    pub txn: Option<String>,
    pub event_uri: String,
    pub event_type: &'static str,
    pub event: Map<String, Value>,
    pub subject: Option<SubjectIdentifier>,
    pub event_timestamp: Option<f64>,
}

impl SecurityEventClaims {
    /// The claims as the TypeScript object.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("iss".into(), Value::String(self.iss.clone()));
        map.insert(
            "aud".into(),
            Value::Array(self.aud.iter().cloned().map(Value::String).collect()),
        );
        map.insert("iat".into(), js::number(self.iat).unwrap_or(Value::Null));
        map.insert("jti".into(), Value::String(self.jti.clone()));
        if let Some(txn) = &self.txn {
            map.insert("txn".into(), Value::String(txn.clone()));
        }
        map.insert("eventUri".into(), Value::String(self.event_uri.clone()));
        map.insert("eventType".into(), Value::String(self.event_type.into()));
        map.insert("event".into(), Value::Object(self.event.clone()));
        if let Some(subject) = &self.subject {
            map.insert("subject".into(), subject.to_value());
        }
        if let Some(timestamp) = self.event_timestamp {
            map.insert(
                "eventTimestamp".into(),
                js::number(timestamp).unwrap_or(Value::Null),
            );
        }
        Value::Object(map)
    }
}

fn string_claim(
    claims: &Map<String, Value>,
    name: &str,
    required: bool,
) -> Result<Option<String>, SignalFormatError> {
    let Some(value) = claims.get(name) else {
        if required {
            return Err(refuse(
                SignalFormatReason::Claims,
                format!("The security event token has no {name} claim"),
            ));
        }
        return Ok(None);
    };
    let invalid = || {
        refuse(
            SignalFormatReason::Claims,
            format!("The security event token's {name} claim is invalid"),
        )
    };
    let Some(text_value) = value.as_str().filter(|text| !text.is_empty()) else {
        return Err(invalid());
    };
    if js::utf16_len(text_value) > MAX_STRING {
        return Err(refuse(
            SignalFormatReason::Size,
            format!("The security event token's {name} claim is too long"),
        ));
    }
    if text(Some(value)).is_none() {
        return Err(invalid());
    }
    Ok(Some(text_value.to_owned()))
}

/// A NumericDate (seconds), or None when absent; refuses anything but a positive finite number.
fn numeric_date(value: Option<&Value>, name: &str) -> Result<Option<f64>, SignalFormatError> {
    let Some(value) = value else { return Ok(None) };
    match js::as_number(value) {
        Some(seconds) if seconds > 0.0 && seconds <= MAX_SECONDS => Ok(Some(seconds)),
        _ => Err(refuse(
            SignalFormatReason::Claims,
            format!("The security event token's {name} is invalid"),
        )),
    }
}

fn audiences(value: Option<&Value>) -> Result<Vec<String>, SignalFormatError> {
    let Some(value) = value else {
        return Err(refuse(
            SignalFormatReason::Claims,
            "The security event token has no aud claim",
        ));
    };
    let invalid = || {
        refuse(
            SignalFormatReason::Claims,
            "The security event token's aud claim is invalid",
        )
    };
    let listed: Vec<&Value> = match value {
        Value::String(_) => vec![value],
        Value::Array(items) => items.iter().collect(),
        _ => return Err(invalid()),
    };
    if listed.is_empty() {
        return Err(invalid());
    }
    if listed.len() > MAX_AUDIENCES {
        return Err(refuse(
            SignalFormatReason::Size,
            "The security event token names too many audiences",
        ));
    }
    let mut unique: Vec<String> = Vec::new();
    for audience in listed {
        if audience
            .as_str()
            .is_some_and(|text| js::utf16_len(text) > MAX_STRING)
        {
            return Err(refuse(
                SignalFormatReason::Size,
                "An audience of the security event token is too long",
            ));
        }
        let Some(text) = text(Some(audience)) else {
            return Err(invalid());
        };
        if !unique.iter().any(|existing| existing == text) {
            unique.push(text.to_owned());
        }
    }
    Ok(unique)
}

/// True when objects and arrays inside `value` go deeper than `MAX_EVENT_DEPTH` levels.
fn nested_too_deep(value: &Value, depth: usize) -> bool {
    match value {
        Value::Array(items) => {
            depth > MAX_EVENT_DEPTH || items.iter().any(|item| nested_too_deep(item, depth + 1))
        }
        Value::Object(map) => {
            depth > MAX_EVENT_DEPTH || map.values().any(|item| nested_too_deep(item, depth + 1))
        }
        _ => false,
    }
}

fn without_trailing_slash(issuer: &str) -> &str {
    issuer.trim_end_matches('/')
}

/// Reads the claims of a Security Event Token after its signature, issuer, audience and `typ` were verified
/// (`readSecurityEvent`).
pub fn read_security_event(payload: &Value) -> Result<SecurityEventClaims, SignalFormatError> {
    let Value::Object(claims) = payload else {
        return Err(refuse(
            SignalFormatReason::Claims,
            "The security event token has no claims",
        ));
    };
    if claims.contains_key("nonce") {
        return Err(refuse(
            SignalFormatReason::Nonce,
            "A security event token must not carry a nonce",
        ));
    }
    let iss = string_claim(claims, "iss", true)?.unwrap_or_default();
    let jti = string_claim(claims, "jti", true)?.unwrap_or_default();
    let txn = string_claim(claims, "txn", false)?;
    let Some(iat) = numeric_date(claims.get("iat"), "iat claim")? else {
        return Err(refuse(
            SignalFormatReason::Claims,
            "The security event token has no iat claim",
        ));
    };
    let aud = audiences(claims.get("aud"))?;

    let Some(events) = claims.get("events").and_then(Value::as_object) else {
        return Err(refuse(
            SignalFormatReason::Events,
            "The security event token has no events claim",
        ));
    };
    let uris = js::keys(events);
    if uris.len() != 1 {
        return Err(refuse(
            SignalFormatReason::Events,
            format!(
                "A security event token carries exactly one event, not {}",
                uris.len()
            ),
        ));
    }
    let event_uri = uris[0].clone();
    if js::utf16_len(&event_uri) > MAX_STRING {
        return Err(refuse(
            SignalFormatReason::Size,
            "The event type of the security event token is too long",
        ));
    }
    if text(Some(&Value::String(event_uri.clone()))).is_none() {
        return Err(refuse(
            SignalFormatReason::Events,
            "The event type of the security event token is invalid",
        ));
    }
    let Some(payload_event) = events.get(&event_uri).and_then(Value::as_object) else {
        return Err(refuse(
            SignalFormatReason::Events,
            "The event of the security event token is not an object",
        ));
    };
    if nested_too_deep(&Value::Object(payload_event.clone()), 1) {
        return Err(refuse(
            SignalFormatReason::Size,
            "The event of the security event token is nested too deeply",
        ));
    }
    let legacy_subject = payload_event.get("subject");
    let event: Map<String, Value> = js::entries(payload_event)
        .into_iter()
        .filter(|(key, _)| key.as_str() != "subject")
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    let mut subject = None;
    if let Some(sub_id) = claims.get("sub_id") {
        subject = Some(parse_subject_identifier(sub_id).ok_or_else(|| {
            refuse(
                SignalFormatReason::Subject,
                "The sub_id claim is not a valid subject identifier",
            )
        })?);
    }
    if payload_event.contains_key("subject") {
        let legacy = legacy_subject.filter(|value| value.is_object());
        let parsed = match legacy {
            Some(legacy)
                if legacy
                    .as_object()
                    .is_some_and(|map| map.contains_key("format")) =>
            {
                parse_subject_identifier(legacy)
            }
            other => legacy_risc_subject(other),
        };
        let Some(parsed) = parsed else {
            return Err(refuse(
                SignalFormatReason::Subject,
                "The subject of the event is not a valid subject identifier",
            ));
        };
        if let Some(existing) = &subject
            && canonicalize_json(&existing.to_value()) != canonicalize_json(&parsed.to_value())
        {
            return Err(refuse(
                SignalFormatReason::Subject,
                "The sub_id claim and the event name different subjects",
            ));
        }
        if subject.is_none() {
            subject = Some(parsed);
        }
    }
    if let Some(sub) = claims.get("sub") {
        if sub
            .as_str()
            .is_some_and(|text| js::utf16_len(text) > MAX_STRING)
        {
            return Err(refuse(
                SignalFormatReason::Size,
                "The security event token's sub claim is too long",
            ));
        }
        let Some(sub) = text(Some(sub)) else {
            return Err(refuse(
                SignalFormatReason::Claims,
                "The security event token's sub claim is invalid",
            ));
        };
        let issuer = without_trailing_slash(&iss);
        let contradicts = user_subjects(subject.as_ref()).iter().any(|identifier| {
            identifier
                .iss_sub()
                .is_some_and(|(identifier_iss, identifier_sub)| {
                    without_trailing_slash(identifier_iss) == issuer && identifier_sub != sub
                })
        });
        if contradicts {
            return Err(refuse(
                SignalFormatReason::Subject,
                "The sub and sub_id claims name different subjects",
            ));
        }
    }

    let event_seconds = numeric_date(event.get("event_timestamp"), "event_timestamp")?;
    let toe = numeric_date(claims.get("toe"), "toe claim")?;
    let seconds = event_seconds.or(toe);
    Ok(SecurityEventClaims {
        iss,
        aud,
        iat,
        jti,
        txn,
        event_type: signal_event_type(&event_uri),
        event_uri,
        event,
        subject,
        event_timestamp: seconds.map(|seconds| (seconds * 1000.0).round()),
    })
}

/// The identifiers in a subject that may name a person, without repeats (`userSubjects`).
pub fn user_subjects(subject: Option<&SubjectIdentifier>) -> Vec<SubjectIdentifier> {
    fn visit(
        identifier: &SubjectIdentifier,
        found: &mut Vec<SubjectIdentifier>,
        seen: &mut Vec<String>,
    ) {
        match identifier {
            SubjectIdentifier::Aliases { identifiers } => {
                for entry in identifiers {
                    visit(entry, found, seen);
                }
            }
            SubjectIdentifier::Complex { members } => {
                if let Some((_, user)) = members.iter().find(|(name, _)| *name == "user") {
                    visit(user, found, seen);
                }
            }
            SubjectIdentifier::IssSub { .. }
            | SubjectIdentifier::Email { .. }
            | SubjectIdentifier::Opaque { .. }
            | SubjectIdentifier::Account { .. }
            | SubjectIdentifier::PhoneNumber { .. } => {
                let key = canonicalize_json(&identifier.to_value());
                if !seen.contains(&key) {
                    seen.push(key);
                    found.push(identifier.clone());
                }
            }
            SubjectIdentifier::Did { .. } | SubjectIdentifier::Uri { .. } => {}
        }
    }
    let mut found = Vec::new();
    let mut seen = Vec::new();
    if let Some(subject) = subject {
        visit(subject, &mut found, &mut seen);
    }
    found
}
