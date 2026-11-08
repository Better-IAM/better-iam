//! Port of `packages/scim/src/attributes.ts`: which attributes the service drops instead of applying.

use serde_json::Value;

use crate::types::{ENTERPRISE_SCHEMA, GROUP_SCHEMA, ObjectValue, ResourceType, USER_SCHEMA};

/// Read-only attributes (RFC 7643 §3.1, §4): a client may send them back, and RFC 7644 §3.3/§3.5.1 says to ignore
/// them.
fn read_only(kind: ResourceType) -> &'static [&'static str] {
    match kind {
        ResourceType::Users => &["id", "meta", "groups"],
        ResourceType::Groups => &["id", "meta"],
    }
}

/// Core User attributes RFC 7643 §4.1 defines that this service provider does not store. Identity providers send
/// several of them by default (Entra ID: `addresses`, `phoneNumbers`, `preferredLanguage`; Okta: `locale`,
/// `nickName`, `password` with password sync), so with `unsupportedAttributes: 'ignore'` they are accepted and
/// dropped.
const UNSUPPORTED_USER: [&str; 14] = [
    "nickname",
    "profileurl",
    "usertype",
    "preferredlanguage",
    "locale",
    "timezone",
    "password",
    "phonenumbers",
    "ims",
    "photos",
    "addresses",
    "entitlements",
    "roles",
    "x509certificates",
];

/// `ignoredAttribute(path, type, lenient, readOnly)`: whether an attribute (a top-level name such as `addresses`, or
/// a PATCH path such as `phoneNumbers[type eq "work"].value` or `urn:…:core:2.0:User:preferredLanguage`) is dropped
/// instead of applied: read-only attributes are (unless `read_only` is false: a PATCH path that targets one is a
/// `mutability` error, RFC 7644 §3.5.2, while a POST/PUT body or a pathless PATCH value that carries one is not,
/// §3.5.1); with `lenient`, so are core attributes this service does not store and anything in an extension schema
/// other than the enterprise User extension. Everything else is validated as before, so a typo in a supported
/// attribute (or an attribute no schema defines, such as `badge` in the enterprise extension) is still an error.
pub fn ignored_attribute(
    path: &str,
    kind: ResourceType,
    lenient: bool,
    read_only_ignored: bool,
) -> bool {
    let head = path.split('[').next().unwrap_or_default();
    let mut lower = head.to_lowercase();
    let prefixes = [USER_SCHEMA, GROUP_SCHEMA].map(|schema| format!("{}:", schema.to_lowercase()));
    if let Some(prefix) = prefixes
        .iter()
        .find(|prefix| lower.starts_with(prefix.as_str()))
    {
        lower = lower[prefix.len()..].to_owned();
    }
    let enterprise = ENTERPRISE_SCHEMA.to_lowercase();
    if lower == enterprise || lower.starts_with(&format!("{enterprise}:")) {
        return false;
    }
    if lower.starts_with("urn:") {
        return lenient;
    }
    let name = lower.split('.').next().unwrap_or_default();
    if read_only(kind).contains(&name) {
        return read_only_ignored;
    }
    lenient && kind == ResourceType::Users && UNSUPPORTED_USER.contains(&name)
}

/// `withoutIgnored(data, type, lenient)`: a copy of a POST/PUT body without the attributes `ignored_attribute` drops
/// (and, when lenient, foreign schema URNs).
pub fn without_ignored(data: &ObjectValue, kind: ResourceType, lenient: bool) -> ObjectValue {
    let mut kept = ObjectValue::new();
    for (key, value) in data {
        if key == "schemas" || !ignored_attribute(key, kind, lenient, true) {
            kept.insert(key.clone(), value.clone());
        }
    }
    if lenient && let Some(Value::Array(schemas)) = kept.get("schemas") {
        let known: &[&str] = match kind {
            ResourceType::Users => &[USER_SCHEMA, ENTERPRISE_SCHEMA],
            ResourceType::Groups => &[GROUP_SCHEMA],
        };
        // Extension schemas this service does not implement are listed by the IdP but their attributes were dropped
        // above.
        let filtered: Vec<Value> = schemas
            .iter()
            .filter(|schema| {
                !matches!(schema, Value::String(text) if text.starts_with("urn:") && !known.contains(&text.as_str()))
            })
            .cloned()
            .collect();
        kept.insert("schemas".into(), Value::Array(filtered));
    }
    kept
}
