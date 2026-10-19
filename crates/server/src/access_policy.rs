//! Port of `packages/server/src/access-policy.ts`: tenant access policies (just-in-time activation floors) and the
//! activation rules of one binding.

use better_iam_core::{IamResult, TenantAccessPolicy};
use serde_json::Value;

use crate::js::{invalid_input, keys};
use crate::models::Binding;
use crate::validation::{integer, object};

/// `defaultActivationMs`: one hour.
pub const DEFAULT_ACTIVATION_MS: f64 = 3_600_000.0;
/// `maxActivationMs`: seven days.
pub const MAX_ACTIVATION_MS: f64 = 7.0 * 86_400_000.0;
/// `defaultApprovalLifetimeMs`: one day.
pub const DEFAULT_APPROVAL_LIFETIME_MS: f64 = 24.0 * 3_600_000.0;

const ACCESS_POLICY_KEYS: [&str; 5] = [
    "maxActivationMs",
    "requireJustification",
    "requireMfa",
    "requireApproval",
    "approvalLifetimeMs",
];

/// `tenantAccessPolicy(value)`: unknown keys and non-boolean flags are refused, `false` flags are dropped.
pub fn tenant_access_policy(value: Option<&Value>) -> IamResult<TenantAccessPolicy> {
    let input = object(value)?;
    for key in keys(input) {
        if !ACCESS_POLICY_KEYS.contains(&key.as_str()) {
            return Err(invalid_input(format!("Unknown access policy field {key}")));
        }
    }
    let mut policy = TenantAccessPolicy::default();
    if let Some(value) = input.get("maxActivationMs") {
        policy.max_activation_ms = Some(integer(
            Some(value),
            "maxActivationMs",
            60_000.0,
            MAX_ACTIVATION_MS,
        )?);
    }
    if let Some(value) = input.get("approvalLifetimeMs") {
        policy.approval_lifetime_ms = Some(integer(
            Some(value),
            "approvalLifetimeMs",
            5.0 * 60_000.0,
            30.0 * 86_400_000.0,
        )?);
    }
    for flag in ["requireJustification", "requireMfa", "requireApproval"] {
        let Some(value) = input.get(flag) else {
            continue;
        };
        let Value::Bool(set) = value else {
            return Err(invalid_input(format!("{flag} must be boolean")));
        };
        if *set {
            match flag {
                "requireJustification" => policy.require_justification = Some(true),
                "requireMfa" => policy.require_mfa = Some(true),
                _ => policy.require_approval = Some(true),
            }
        }
    }
    Ok(policy)
}

/// `ActivationRules`: what governs activating one binding.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ActivationRules {
    pub require_justification: bool,
    pub require_mfa: bool,
    pub require_approval: bool,
    pub max_activation_ms: f64,
    pub approval_lifetime_ms: f64,
}

/// `activationRules(binding, policy = {})`: the binding's own settings tightened by the tenant's policy.
pub fn activation_rules(binding: &Binding, policy: Option<&TenantAccessPolicy>) -> ActivationRules {
    let default = TenantAccessPolicy::default();
    let policy = policy.unwrap_or(&default);
    let binding_max = binding.max_activation_ms.unwrap_or(DEFAULT_ACTIVATION_MS);
    ActivationRules {
        require_justification: binding.require_justification == Some(true)
            || policy.require_justification == Some(true),
        require_mfa: binding.require_mfa == Some(true) || policy.require_mfa == Some(true),
        require_approval: binding.require_approval == Some(true)
            || policy.require_approval == Some(true),
        max_activation_ms: match policy.max_activation_ms {
            // Math.min: NaN wins.
            Some(max) if max.is_nan() || binding_max.is_nan() => f64::NAN,
            Some(max) => binding_max.min(max),
            None => binding_max,
        },
        approval_lifetime_ms: policy
            .approval_lifetime_ms
            .unwrap_or(DEFAULT_APPROVAL_LIFETIME_MS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn access_policy_validation() {
        let policy = tenant_access_policy(Some(&json!({
            "maxActivationMs": 120_000, "requireMfa": true, "requireApproval": false
        })))
        .unwrap();
        assert_eq!(policy.max_activation_ms, Some(120_000.0));
        assert_eq!(policy.require_mfa, Some(true));
        assert_eq!(policy.require_approval, None);
        assert_eq!(
            tenant_access_policy(Some(&json!({ "x": 1 })))
                .unwrap_err()
                .message,
            "Unknown access policy field x"
        );
        assert_eq!(
            tenant_access_policy(Some(&json!({ "requireMfa": "yes" })))
                .unwrap_err()
                .message,
            "requireMfa must be boolean"
        );
        assert_eq!(
            tenant_access_policy(Some(&json!({ "maxActivationMs": 1 })))
                .unwrap_err()
                .message,
            "Invalid maxActivationMs"
        );
    }

    #[test]
    fn rules_tighten() {
        let binding: Binding = serde_json::from_value(json!({
            "id": "b", "tenantId": "t", "subjectType": "identity", "subjectId": "i", "roleId": "r",
            "authorityId": "a", "maxActivationMs": 7_200_000, "requireMfa": true
        }))
        .unwrap();
        let rules = activation_rules(&binding, None);
        assert_eq!(rules.max_activation_ms, 7_200_000.0);
        assert!(rules.require_mfa);
        assert_eq!(rules.approval_lifetime_ms, DEFAULT_APPROVAL_LIFETIME_MS);
        let policy = TenantAccessPolicy {
            max_activation_ms: Some(600_000.0),
            require_approval: Some(true),
            ..TenantAccessPolicy::default()
        };
        let rules = activation_rules(&binding, Some(&policy));
        assert_eq!(rules.max_activation_ms, 600_000.0);
        assert!(rules.require_approval);
    }
}
