//! Port of `packages/server/src/session-kinds.ts`: session kinds and the rules shared by every code path that
//! branches on them.
//!
//! Long-lived credentials (`user`, `api-key`) act in their identity's own right; temporary ones (`role`,
//! `session-token`, `delegated`) derive from a source and never pass recent-authentication, ownership or self-service
//! checks. Unknown kinds fail closed everywhere.

use better_iam_core::{IamError, IamResult, SessionKind, js as core_js};
use serde_json::Value;

/// The temporary kinds: derived from a source credential, bounded by it, and never usable for self-service.
pub const TEMPORARY_SESSION_KINDS: [SessionKind; 3] = [
    SessionKind::Role,
    SessionKind::SessionToken,
    SessionKind::Delegated,
];

/// Whether a kind is one of [`TEMPORARY_SESSION_KINDS`] (`temporarySessionKinds.has(kind)`).
pub fn is_temporary_kind(kind: SessionKind) -> bool {
    TEMPORARY_SESSION_KINDS.contains(&kind)
}

/// [`is_temporary_kind`] for a stored kind string; unknown kinds are not temporary (they fail closed elsewhere).
pub fn is_temporary_kind_name(kind: &str) -> bool {
    matches!(kind, "role" | "session-token" | "delegated")
}

/// `actsInOwnRight(session)`: a user session or an API key, as self-service actions require. False for temporary
/// and unknown kinds.
pub fn acts_in_own_right(kind: SessionKind) -> bool {
    matches!(kind, SessionKind::User | SessionKind::ApiKey)
}

/// [`acts_in_own_right`] for a stored kind string.
pub fn acts_in_own_right_name(kind: &str) -> bool {
    matches!(kind, "user" | "api-key")
}

/// `revokedByWatermark(createdAt, ...watermarks)`: true when the session was created strictly before a finite
/// numeric watermark. Missing watermarks are ignored.
pub fn revoked_by_watermark(created_at: f64, watermarks: &[Option<f64>]) -> bool {
    watermarks
        .iter()
        .flatten()
        .any(|watermark| watermark.is_finite() && created_at < *watermark)
}

/// [`revoked_by_watermark`] for stored watermark values (anything but a number is ignored).
pub fn revoked_by_watermark_values(created_at: f64, watermarks: &[Option<&Value>]) -> bool {
    let numbers: Vec<Option<f64>> = watermarks
        .iter()
        .map(|value| value.and_then(core_js::as_number))
        .collect();
    revoked_by_watermark(created_at, &numbers)
}

/// `nextWatermark(current, before, now)`: `max(current ?? 0, before ?? now + 1)`, so a watermark only ever moves
/// forward and never lies in the future. INVALID_INPUT when `before` is not a safe integer >= 0 or is > now + 1.
pub fn next_watermark(current: Option<f64>, before: Option<&Value>, now: f64) -> IamResult<f64> {
    let before = match before {
        None => None,
        Some(value) => match core_js::as_number(value) {
            Some(number)
                if core_js::is_safe_integer(number) && number >= 0.0 && number <= now + 1.0 =>
            {
                Some(number)
            }
            _ => {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "before must be a time no later than now",
                ));
            }
        },
    };
    let current = current.unwrap_or(0.0);
    let candidate = before.unwrap_or(now + 1.0);
    // Math.max: NaN wins.
    Ok(if current.is_nan() || candidate.is_nan() {
        f64::NAN
    } else {
        current.max(candidate)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn kinds() {
        assert!(acts_in_own_right(SessionKind::User));
        assert!(acts_in_own_right(SessionKind::ApiKey));
        assert!(!acts_in_own_right(SessionKind::Role));
        assert!(is_temporary_kind(SessionKind::Delegated));
        assert!(!is_temporary_kind_name("unknown"));
        assert!(!acts_in_own_right_name("unknown"));
    }

    #[test]
    fn watermarks() {
        assert!(revoked_by_watermark(5.0, &[None, Some(6.0)]));
        assert!(!revoked_by_watermark(6.0, &[Some(6.0)]));
        assert!(!revoked_by_watermark(5.0, &[Some(f64::INFINITY)]));
        assert_eq!(next_watermark(None, None, 100.0).unwrap(), 101.0);
        assert_eq!(next_watermark(Some(500.0), None, 100.0).unwrap(), 500.0);
        assert_eq!(
            next_watermark(Some(5.0), Some(&json!(50)), 100.0).unwrap(),
            50.0
        );
        let error = next_watermark(None, Some(&json!(102)), 100.0).unwrap_err();
        assert_eq!(error.message, "before must be a time no later than now");
        assert!(next_watermark(None, Some(&json!("1")), 100.0).is_err());
        assert!(next_watermark(None, Some(&json!(-1)), 100.0).is_err());
    }
}
