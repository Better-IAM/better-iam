//! Port of `packages/server/src/context-keys.ts`: the registry of context keys the server derives for every
//! decision.
//!
//! Decisions assign them, policy lint knows their types, the catalog reserves their names as identity attributes,
//! and package rules refuse the ones that describe a session. Lower-precedence context (resolveContext, plugins,
//! identity attributes) can never supply them: [`is_server_owned_key`] names every key that is removed before the
//! server assigns its own values. Maps keep the TypeScript insertion order.

use std::sync::LazyLock;

use indexmap::{IndexMap, IndexSet};

/// What a context key holds. `identifier` strings are never timestamps; `timestamp` values are ISO-8601 strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContextKeyType {
    Identifier,
    Timestamp,
    String,
    Number,
    Boolean,
    List,
}

impl ContextKeyType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Identifier => "identifier",
            Self::Timestamp => "timestamp",
            Self::String => "string",
            Self::Number => "number",
            Self::Boolean => "boolean",
            Self::List => "list",
        }
    }
}

use ContextKeyType::{Boolean, Identifier, List, Number, String as Str, Timestamp};

const PRINCIPAL_SERVER_KEYS: &[(&str, ContextKeyType)] = &[
    ("principal.id", Identifier),
    ("principal.tenantId", Identifier),
    ("principal.mfa", Boolean),
    ("principal.kind", Identifier),
    ("principal.owner", Boolean),
    ("principal.rootAdmin", Boolean),
    // 'user' | 'role' | 'api-key' | 'session-token' | 'delegated'.
    ("principal.sessionKind", Identifier),
    ("principal.authMethod", Identifier),
    ("principal.impersonated", Boolean),
    ("principal.impersonatorId", Identifier),
    ("principal.groups", List),
    ("principal.roles", List),
    ("principal.agreements", List),
    ("principal.pendingAgreements", Number),
    // Onboarding flows the person completed (names) and required ones still open.
    ("principal.onboarding", List),
    ("principal.pendingOnboarding", Number),
    // Teams the person belongs to (team IDs, with the teams above them) and their department with the ones above it.
    ("principal.teams", List),
    ("principal.departments", List),
    ("principal.departmentId", Identifier),
    // Spend (billing-service.ts): whether an enforced budget covering the principal is spent, and the spent budgets' names.
    ("principal.spendExceeded", Boolean),
    ("principal.budgetsExceeded", List),
    // Privacy (privacy.ts): keys of the consent and legitimate-interest purposes that may be processed for the person now.
    ("principal.consents", List),
    // Threat detection (threats.ts): the identity's effective risk level and score.
    ("principal.riskLevel", Identifier),
    ("principal.riskScore", Number),
    // License management (licenses.ts): keys of the license products the person holds an active seat for.
    ("principal.licenses", List),
    // B2B guest collaboration (guests.ts).
    ("principal.guest", Boolean),
    ("principal.guestSponsorId", Identifier),
    ("principal.homeTenantId", Identifier),
    // Session-aware keys: 'simulation' is the session id of simulated principals.
    ("principal.sessionId", Identifier),
    ("principal.tokenIssueTime", Timestamp),
    ("principal.authTime", Timestamp),
    ("principal.mfaTime", Timestamp),
    ("principal.sessionTagKeys", List),
    ("principal.sourceTenantId", Identifier),
    ("principal.sessionName", Identifier),
    ("principal.sourceIdentity", Identifier),
    ("principal.webIdentityProvider", Identifier),
    ("principal.webIdentitySubject", Str),
    // AI agents (agents.ts).
    ("principal.delegated", Boolean),
    ("principal.delegationId", Identifier),
    ("principal.agentId", Identifier),
    ("principal.agentSponsorId", Identifier),
    ("principal.agentModel", Str),
    ("principal.agentProvider", Str),
    // Delegated sessions: the agents from the person's own delegate to the acting one (longer after hand-offs).
    ("principal.delegationChain", List),
    ("request.time", Timestamp),
    // The client address the server saw; never set for simulated principals or without a client scope.
    ("request.sourceIp", Identifier),
    // Device posture (devices.ts).
    ("request.deviceAssurance", Identifier),
    ("request.deviceManaged", Boolean),
    ("request.deviceCompliant", Boolean),
    ("request.deviceId", Identifier),
    ("request.devicePlatform", Identifier),
    // Security clearances (clearances.ts), only with `options.clearances`.
    ("principal.clearanceLevel", Identifier),
    ("principal.clearanceRank", Number),
    ("principal.clearanceStatus", Identifier),
    ("principal.clearanceCompartments", List),
    ("principal.clearanceCitizenship", List),
];

/// Every `principal.*` and `request.*` key the server derives, with its type. Optional members
/// ([`OPTIONAL_PRINCIPAL_SERVER_KEYS`]) are absent when their source is absent; the rest are always present.
pub static PRINCIPAL_SERVER_KEYS_MAP: LazyLock<IndexMap<&'static str, ContextKeyType>> =
    LazyLock::new(|| PRINCIPAL_SERVER_KEYS.iter().copied().collect());

/// `principalServerKeys`.
pub fn principal_server_keys() -> &'static IndexMap<&'static str, ContextKeyType> {
    &PRINCIPAL_SERVER_KEYS_MAP
}

/// `resource.*` keys the server derives from a resource's classification label (only with `options.clearances`).
pub static RESOURCE_SERVER_KEYS: LazyLock<IndexMap<&'static str, ContextKeyType>> =
    LazyLock::new(|| {
        [
            ("resource.classification", Identifier),
            ("resource.classificationRank", Number),
            ("resource.compartments", List),
            ("resource.noforn", Boolean),
            ("resource.releasableTo", List),
        ]
        .into_iter()
        .collect()
    });

/// Resource server keys missing from some decisions: an unlabeled resource has no classification level.
pub const OPTIONAL_RESOURCE_SERVER_KEYS: [&str; 1] = ["resource.classification"];

/// The keys only the server sets once the deployment enables clearances (`options.clearances`).
pub static CLEARANCE_SERVER_KEYS: LazyLock<IndexSet<&'static str>> = LazyLock::new(|| {
    let mut keys: IndexSet<&'static str> = [
        "principal.clearanceLevel",
        "principal.clearanceRank",
        "principal.clearanceStatus",
        "principal.clearanceCompartments",
        "principal.clearanceCitizenship",
    ]
    .into_iter()
    .collect();
    keys.extend(RESOURCE_SERVER_KEYS.keys().copied());
    keys
});

/// `tenant.*` keys the server derives about the decision's tenant.
pub static TENANT_SERVER_KEYS: LazyLock<IndexMap<&'static str, ContextKeyType>> =
    LazyLock::new(|| [("tenant.features", List)].into_iter().collect());

/// Server keys missing from some decisions (every operator except Exists is then false).
pub const OPTIONAL_PRINCIPAL_SERVER_KEYS: [&str; 21] = [
    "principal.authMethod",
    "principal.impersonatorId",
    "principal.mfaTime",
    "principal.sourceTenantId",
    "principal.sessionName",
    "principal.sourceIdentity",
    "principal.webIdentityProvider",
    "principal.webIdentitySubject",
    "principal.delegationId",
    "principal.agentId",
    "principal.agentSponsorId",
    "principal.agentModel",
    "principal.agentProvider",
    "principal.delegationChain",
    "principal.departmentId",
    // Only for guests (guests.ts), and the home tenant only for tenant-sourced ones.
    "principal.guestSponsorId",
    "principal.homeTenantId",
    "request.sourceIp",
    // Only when the request carries a verified device proof (devices.ts).
    "request.deviceId",
    "request.devicePlatform",
    // Only while the session holds a clearance (clearances.ts).
    "principal.clearanceLevel",
];

/// Session tags appear as `principal.sessionTags.<key>` (optional strings), one key per tag.
pub const SESSION_TAG_PREFIX: &str = "principal.sessionTags.";

/// `tagKeyPattern`: a letter, then letters, digits or underscores, at most 64 characters (case-sensitive).
pub fn is_tag_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphabetic())
        && key.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Bare principal names the session keys occupy; identity attributes may not use them.
pub const RESERVED_SESSION_PRINCIPAL_NAMES: [&str; 18] = [
    "sessionId",
    "tokenIssueTime",
    "authTime",
    "mfaTime",
    "sourceTenantId",
    "sessionName",
    "sourceIdentity",
    "sessionTags",
    "sessionTagKeys",
    "webIdentityProvider",
    "webIdentitySubject",
    "delegated",
    "delegationId",
    "agentId",
    "agentSponsorId",
    "agentModel",
    "agentProvider",
    "delegationChain",
];

/// The session-derived principal keys as policies name them (`principal.<name>`, without `sessionTags`). Rules
/// evaluated without a session (package rules) refuse them.
pub static SESSION_SCOPED_PRINCIPAL_KEYS: LazyLock<Vec<String>> = LazyLock::new(|| {
    RESERVED_SESSION_PRINCIPAL_NAMES
        .iter()
        .filter(|name| **name != "sessionTags")
        .map(|name| format!("principal.{name}"))
        .collect()
});

/// `isServerOwnedKey(key, clearances = true)`: a registry member or any `principal.sessionTags.` key. The clearance
/// keys count only when `clearances` is true (the deployment sets `options.clearances`).
pub fn is_server_owned_key(key: &str, clearances: bool) -> bool {
    if !clearances && CLEARANCE_SERVER_KEYS.contains(key) {
        return false;
    }
    principal_server_keys().contains_key(key)
        || TENANT_SERVER_KEYS.contains_key(key)
        || RESOURCE_SERVER_KEYS.contains_key(key)
        || key.starts_with(SESSION_TAG_PREFIX)
}

/// `sessionTagName(key)`: `principal.sessionTags.<key>`, or None when the key is not valid.
pub fn session_tag_name(key: &str) -> Option<String> {
    is_tag_key(key).then(|| format!("{SESSION_TAG_PREFIX}{key}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contents() {
        assert_eq!(principal_server_keys().len(), 57);
        assert!(principal_server_keys().keys().all(|key| !key.is_empty()));
        assert_eq!(
            principal_server_keys().get("principal.tokenIssueTime"),
            Some(&Timestamp)
        );
        assert_eq!(CLEARANCE_SERVER_KEYS.len(), 10);
        assert!(is_server_owned_key("principal.sessionTags.team", true));
        assert!(is_server_owned_key("principal.clearanceRank", true));
        assert!(!is_server_owned_key("principal.clearanceRank", false));
        assert!(is_server_owned_key("tenant.features", false));
        assert!(!is_server_owned_key("principal.department", true));
        assert_eq!(SESSION_SCOPED_PRINCIPAL_KEYS.len(), 17);
        assert_eq!(
            session_tag_name("team_1").unwrap(),
            "principal.sessionTags.team_1"
        );
        assert!(session_tag_name("1team").is_none());
        assert!(session_tag_name(&"a".repeat(65)).is_none());
        assert!(session_tag_name(&"a".repeat(64)).is_some());
    }
}
