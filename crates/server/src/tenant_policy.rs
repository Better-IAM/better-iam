//! Port of `packages/server/src/tenant-policy.ts`: tenant authentication policies and plan limits.

use better_iam_core::{AUTH_METHODS, IamResult, TenantAuthPolicy, TenantLimits, is_ip_range};
use serde_json::Value;

use crate::js::{invalid_input, keys, unique};
use crate::validation::{integer, object, strings};

const AUTH_POLICY_KEYS: [&str; 18] = [
    "requireMfa",
    "allowedMethods",
    "sessionLifetimeMs",
    "sessionIdleTimeoutMs",
    "maxAttempts",
    "minPasswordLength",
    "maxSessions",
    "allowImpersonation",
    "trustedDeviceDays",
    "passwordHistory",
    "passwordMaxAgeDays",
    "passwordMinClasses",
    "passwordRejectPersonalInfo",
    "notifyNewSignIn",
    "allowedIpRanges",
    "mfaEmailCodes",
    "requireMfaForOwners",
    "bindSessionsToIp",
];
const THIRTY_DAYS: f64 = 30.0 * 24.0 * 60.0 * 60_000.0;

fn flag(input: &serde_json::Map<String, Value>, key: &str) -> IamResult<Option<bool>> {
    match input.get(key) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(invalid_input(format!("{key} must be a boolean"))),
    }
}

/// `tenantAuthPolicy(value)`: validates a tenant authentication policy; every field is optional but must be
/// well-formed.
pub fn tenant_auth_policy(value: Option<&Value>) -> IamResult<TenantAuthPolicy> {
    let input = object(value)?;
    let mut policy = TenantAuthPolicy::default();
    for key in keys(input) {
        if !AUTH_POLICY_KEYS.contains(&key.as_str()) {
            return Err(invalid_input(format!(
                "Unknown authentication policy field {key}"
            )));
        }
    }
    policy.require_mfa = flag(input, "requireMfa")?;
    if let Some(methods) = input.get("allowedMethods") {
        let methods = unique(strings(Some(methods), "allowedMethods")?);
        let parsed: Vec<_> = methods
            .iter()
            .map(|method| {
                AUTH_METHODS
                    .iter()
                    .copied()
                    .find(|known| known.as_str() == method)
            })
            .collect();
        if methods.is_empty() || parsed.iter().any(Option::is_none) {
            let names: Vec<&str> = AUTH_METHODS.iter().map(|method| method.as_str()).collect();
            return Err(invalid_input(format!(
                "allowedMethods must list one or more of {}",
                names.join(", ")
            )));
        }
        policy.allowed_methods = Some(parsed.into_iter().flatten().collect());
    }
    if let Some(value) = input.get("sessionLifetimeMs") {
        policy.session_lifetime_ms = Some(integer(
            Some(value),
            "sessionLifetimeMs",
            60_000.0,
            THIRTY_DAYS,
        )?);
    }
    if let Some(value) = input.get("sessionIdleTimeoutMs") {
        policy.session_idle_timeout_ms = Some(integer(
            Some(value),
            "sessionIdleTimeoutMs",
            60_000.0,
            THIRTY_DAYS,
        )?);
    }
    if let (Some(lifetime), Some(idle)) =
        (policy.session_lifetime_ms, policy.session_idle_timeout_ms)
        && idle > lifetime
    {
        return Err(invalid_input(
            "sessionIdleTimeoutMs cannot exceed sessionLifetimeMs",
        ));
    }
    if let Some(value) = input.get("maxAttempts") {
        policy.max_attempts = Some(integer(Some(value), "maxAttempts", 1.0, 100_000.0)?);
    }
    if let Some(value) = input.get("minPasswordLength") {
        policy.min_password_length = Some(integer(Some(value), "minPasswordLength", 12.0, 128.0)?);
    }
    if let Some(value) = input.get("maxSessions") {
        policy.max_sessions = Some(integer(Some(value), "maxSessions", 1.0, 100.0)?);
    }
    policy.allow_impersonation = flag(input, "allowImpersonation")?;
    if let Some(value) = input.get("trustedDeviceDays") {
        policy.trusted_device_days = Some(integer(Some(value), "trustedDeviceDays", 0.0, 365.0)?);
    }
    if let Some(value) = input.get("passwordHistory") {
        policy.password_history = Some(integer(Some(value), "passwordHistory", 1.0, 24.0)?);
    }
    if let Some(value) = input.get("passwordMaxAgeDays") {
        policy.password_max_age_days =
            Some(integer(Some(value), "passwordMaxAgeDays", 1.0, 3650.0)?);
    }
    if let Some(value) = input.get("passwordMinClasses") {
        policy.password_min_classes = Some(integer(Some(value), "passwordMinClasses", 2.0, 4.0)?);
    }
    policy.password_reject_personal_info = flag(input, "passwordRejectPersonalInfo")?;
    policy.notify_new_sign_in = flag(input, "notifyNewSignIn")?;
    if let Some(value) = input.get("allowedIpRanges") {
        let ranges = unique(strings(Some(value), "allowedIpRanges")?);
        if ranges.is_empty() || ranges.iter().any(|range| !is_ip_range(range)) {
            return Err(invalid_input(
                "allowedIpRanges must list one or more IPv4/IPv6 addresses or CIDR blocks",
            ));
        }
        policy.allowed_ip_ranges = Some(ranges);
    }
    policy.mfa_email_codes = flag(input, "mfaEmailCodes")?;
    policy.require_mfa_for_owners = flag(input, "requireMfaForOwners")?;
    policy.bind_sessions_to_ip = flag(input, "bindSessionsToIp")?;
    Ok(policy)
}

/// The plan limit keys, in TypeScript order.
pub const LIMIT_KEYS: [&str; 8] = [
    "identities",
    "serviceAccounts",
    "agents",
    "groups",
    "roles",
    "policies",
    "resources",
    "webhooks",
];

/// `tenantLimits(value)`: known keys only, each a non-negative integer up to one billion.
pub fn tenant_limits(value: Option<&Value>) -> IamResult<TenantLimits> {
    let input = object(value)?;
    for key in keys(input) {
        if !LIMIT_KEYS.contains(&key.as_str()) {
            return Err(invalid_input(format!("Unknown limit {key}")));
        }
    }
    let mut limits = TenantLimits::default();
    for key in LIMIT_KEYS {
        let Some(value) = input.get(key) else {
            continue;
        };
        let number = integer(Some(value), key, 0.0, 1_000_000_000.0)?;
        *limit_slot(&mut limits, key) = Some(number);
    }
    Ok(limits)
}

/// The member of a [`TenantLimits`] for a limit key.
pub fn limit_slot<'a>(limits: &'a mut TenantLimits, key: &str) -> &'a mut Option<f64> {
    match key {
        "identities" => &mut limits.identities,
        "serviceAccounts" => &mut limits.service_accounts,
        "agents" => &mut limits.agents,
        "groups" => &mut limits.groups,
        "roles" => &mut limits.roles,
        "policies" => &mut limits.policies,
        "resources" => &mut limits.resources,
        _ => &mut limits.webhooks,
    }
}

/// The value of a limit key in a [`TenantLimits`].
pub fn limit_value(limits: &TenantLimits, key: &str) -> Option<f64> {
    match key {
        "identities" => limits.identities,
        "serviceAccounts" => limits.service_accounts,
        "agents" => limits.agents,
        "groups" => limits.groups,
        "roles" => limits.roles,
        "policies" => limits.policies,
        "resources" => limits.resources,
        "webhooks" => limits.webhooks,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn error(value: Value) -> String {
        tenant_auth_policy(Some(&value)).unwrap_err().message
    }

    #[test]
    fn auth_policy_validation() {
        let policy = tenant_auth_policy(Some(&json!({
            "requireMfa": true,
            "allowedMethods": ["password", "passkey", "password"],
            "sessionLifetimeMs": 3_600_000,
            "allowedIpRanges": ["10.0.0.0/8"],
        })))
        .unwrap();
        assert_eq!(policy.require_mfa, Some(true));
        assert_eq!(policy.allowed_methods.as_ref().unwrap().len(), 2);
        assert_eq!(
            error(json!({ "nope": 1 })),
            "Unknown authentication policy field nope"
        );
        assert_eq!(
            error(json!({ "requireMfa": 1 })),
            "requireMfa must be a boolean"
        );
        assert_eq!(
            error(json!({ "allowedMethods": ["sms"] })),
            "allowedMethods must list one or more of password, passwordless-email, passwordless-sms, passkey, federated"
        );
        assert_eq!(
            error(json!({ "allowedMethods": [] })),
            "allowedMethods must list one or more of password, passwordless-email, passwordless-sms, passkey, federated"
        );
        assert_eq!(
            error(json!({ "sessionLifetimeMs": 60_000, "sessionIdleTimeoutMs": 120_000 })),
            "sessionIdleTimeoutMs cannot exceed sessionLifetimeMs"
        );
        assert_eq!(
            error(json!({ "minPasswordLength": 8 })),
            "Invalid minPasswordLength"
        );
        assert_eq!(
            error(json!({ "allowedIpRanges": ["nope"] })),
            "allowedIpRanges must list one or more IPv4/IPv6 addresses or CIDR blocks"
        );
        assert_eq!(error(json!([])), "Expected an object");
    }

    #[test]
    fn limits_validation() {
        let limits = tenant_limits(Some(&json!({ "roles": 5, "groups": 0 }))).unwrap();
        assert_eq!(limits.roles, Some(5.0));
        assert_eq!(limits.groups, Some(0.0));
        assert_eq!(
            tenant_limits(Some(&json!({ "seats": 5 })))
                .unwrap_err()
                .message,
            "Unknown limit seats"
        );
        assert_eq!(
            tenant_limits(Some(&json!({ "roles": -1 })))
                .unwrap_err()
                .message,
            "Invalid roles"
        );
    }
}
