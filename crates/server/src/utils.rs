//! Port of `packages/server/src/utils.ts`: identifiers, tokens, hashes and record helpers, plus the wall clock.

use std::cmp::Ordering;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_iam_core::{Identity, PolicyDocument, Record, js as core_js};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// `id()`: a random UUID (`crypto.randomUUID()`).
pub fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// `token()`: 32 random bytes as base64url.
pub fn token() -> String {
    URL_SAFE_NO_PAD.encode(better_iam_auth::crypto::random_bytes(32))
}

/// `hash(value)`: SHA-256 hex.
pub fn hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// `sameHash(a, b)`: constant-time comparison of two token hashes (for equal lengths).
pub fn same_hash(a: &str, b: &str) -> bool {
    let (first, second) = (a.as_bytes(), b.as_bytes());
    first.len() == second.len() && bool::from(first.ct_eq(second))
}

/// [`same_hash`] for stored values, read fail-closed: anything but two strings never matches.
pub fn same_hash_value(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (Some(Value::String(a)), Some(Value::String(b))) => same_hash(a, b),
        _ => false,
    }
}

/// `all`: the unrestricted policy used for root authorities, owner roles, and default ceilings.
pub fn all_value() -> Value {
    json!({ "version": 1, "statements": [{ "effect": "allow", "actions": ["*"], "resources": ["*"] }] })
}

/// [`all_value`] as a typed document.
pub fn all() -> PolicyDocument {
    serde_json::from_value(all_value()).expect("the unrestricted policy is valid")
}

/// `publicIdentity(identity)`: the identity without its password hash.
pub fn public_identity(identity: &Identity) -> Record {
    let mut record = match serde_json::to_value(identity) {
        Ok(Value::Object(map)) => map,
        _ => Record::new(),
    };
    record.remove("passwordHash");
    record
}

/// [`public_identity`] for a stored identity record.
pub fn public_identity_record(identity: &Record) -> Record {
    let mut record = identity.clone();
    record.remove("passwordHash");
    record
}

fn id_order(a: &str, b: &str) -> Ordering {
    core_js::cmp_utf16(a, b)
}

/// `byNewest`: deterministic newest-first ordering for records that carry a creation timestamp (`createdAt`
/// descending, then id ascending).
pub fn by_newest(a_created: f64, a_id: &str, b_created: f64, b_id: &str) -> Ordering {
    let difference = b_created - a_created;
    if difference != 0.0 && !difference.is_nan() {
        return if difference > 0.0 {
            Ordering::Greater
        } else {
            Ordering::Less
        };
    }
    id_order(a_id, b_id)
}

/// [`by_newest`] over records (`createdAt` read as a number; anything else compares as NaN).
pub fn by_newest_records(a: &Record, b: &Record) -> Ordering {
    let created = |record: &Record| {
        record
            .get("createdAt")
            .and_then(core_js::as_number)
            .unwrap_or(f64::NAN)
    };
    let id = |record: &Record| {
        record
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    by_newest(created(a), &id(a), created(b), &id(b))
}

/// `byId`.
pub fn by_id(a: &str, b: &str) -> Ordering {
    id_order(a, b)
}

/// The wall clock reader of a process (`Date.now()`); see [`date_now`].
pub type WallClock = core_js::WallClock;

/// `Date.now()`: the wall clock in epoch milliseconds. TypeScript modules that read real time directly (tenant
/// `createdAt`, audit event timestamps) read it here; [`set_wall_clock`] puts it under control (the conformance
/// server's clock endpoint). It is the core crate's clock, so the override reaches core and auth too.
pub fn date_now() -> f64 {
    core_js::now_ms()
}

/// Replaces the process wall clock ([`date_now`] and `better_iam_core::js::now_ms`); `None` returns to real time.
pub fn set_wall_clock(clock: Option<WallClock>) {
    core_js::set_wall_clock(clock);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_tokens_and_ids() {
        assert_eq!(
            hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(token().len(), 43);
        assert_ne!(token(), token());
        assert_eq!(id().len(), 36);
        assert!(same_hash("abc", "abc"));
        assert!(!same_hash("abc", "abd"));
        assert!(!same_hash("abc", "abcd"));
        assert!(!same_hash_value(Some(&json!(1)), Some(&json!(1))));
    }

    #[test]
    fn newest_first() {
        assert_eq!(by_newest(2.0, "a", 1.0, "b"), Ordering::Less);
        assert_eq!(by_newest(1.0, "b", 1.0, "a"), Ordering::Greater);
        assert_eq!(by_newest(f64::NAN, "a", 1.0, "b"), Ordering::Less);
    }
}
