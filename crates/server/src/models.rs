//! Port of `packages/server/src/models.ts`: the records the server stores.
//!
//! Every record serializes with the TypeScript member names (camelCase), leaves unset optional members out, and
//! keeps members it does not declare in `extra`, so a record written by the TypeScript server (or a newer version)
//! survives a Rust read-modify-write. Numbers are JavaScript numbers (`f64`); string unions are `String`s, so values
//! a newer implementation writes are carried along instead of failing to decode.

use better_iam_core::{AttributeType, Conditions, PolicyDocument};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

macro_rules! record {
    (
        $(#[$meta:meta])*
        pub struct $name:ident {
            $(
                $(#[$fmeta:meta])*
                $field:ident : $ty:ty
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            pub id: String,
            pub tenant_id: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub unique_key: Option<String>,
            $(
                $(#[$fmeta])*
                pub $field: $ty,
            )*
            /// Members this type does not declare.
            #[serde(flatten)]
            pub extra: Map<String, Value>,
        }
    };
}

record! {
    /// `Role`.
    pub struct Role {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        policy_ids: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        document: Option<PolicyDocument>,
        protected: bool,
        /// Roles whose grants this role includes (role hierarchy).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        inherits: Option<Vec<String>>,
        /// Role sessions created before this time (epoch milliseconds) are refused (`roles.revokeSessions`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sessions_revoked_before: Option<f64>,
    }
}

/// `AccessWindow`: a recurring time window in a named time zone during which a binding applies. `from`/`to` are
/// `HH:MM` (24-hour); a window whose `to` is not after `from` wraps past midnight; `days` are 0 (Sunday) to 6 and
/// default to every day.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessWindow {
    pub from: String,
    pub to: String,
    pub time_zone: String,
    /// Members in the order `accessWindow` writes them: `days` last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days: Option<Vec<f64>>,
}

record! {
    /// `Policy`.
    pub struct Policy {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        document: PolicyDocument,
        version: f64,
    }
}

record! {
    /// `GrantAuthority`. Root-issued authorities also carry `rootIssued: true` (in `extra`).
    pub struct GrantAuthority {
        identity_id: String,
        ceiling: PolicyDocument,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_authority_id: Option<String>,
        revoked: bool,
    }
}

record! {
    /// `Binding`: `expiresAt` makes the grant temporary; an eligible binding grants nothing until its subject
    /// activates it.
    pub struct Binding {
        /// `'identity' | 'group'`.
        subject_type: String,
        subject_id: String,
        role_id: String,
        authority_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        starts_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        access_request_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        eligible: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_activation_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        require_justification: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        require_mfa: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        require_approval: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approver_group_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        manager_approval: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        window: Option<AccessWindow>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        package_assignment_id: Option<String>,
    }
}

record! {
    /// `BindingActivation`: uniqueKey is `{bindingId}:{identityId}`.
    pub struct BindingActivation {
        binding_id: String,
        identity_id: String,
        role_id: String,
        activated_at: f64,
        expires_at: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        justification: Option<String>,
        session_id: String,
        /// `'pending' | 'active' | 'denied'`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        requested_duration_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decided_by: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decided_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    }
}

/// `AccessRequestStatus` values.
pub const ACCESS_REQUEST_STATUSES: [&str; 5] =
    ["pending", "approved", "denied", "cancelled", "expired"];

record! {
    /// `AccessRequest`: a request for temporary or standing role bindings.
    pub struct AccessRequest {
        requester_id: String,
        role_ids: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        justification: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_seconds: Option<f64>,
        status: String,
        created_at: f64,
        expires_at: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reviewer_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reviewed_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        binding_ids: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant_expires_at: Option<f64>,
    }
}

record! {
    /// `Webhook`: the signing secret is sealed at rest and returned only when created or rotated.
    pub struct Webhook {
        url: String,
        events: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        active: bool,
        /// `'tenant' | 'subtree'`.
        scope: String,
        /// `('allow' | 'deny')[]`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        outcomes: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resources: Option<Vec<String>>,
        secret_sealed: String,
        created_at: f64,
        updated_at: f64,
        created_by: String,
    }
}

record! {
    /// `Group`.
    pub struct Group {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        team_id: Option<String>,
    }
}

record! {
    /// `GroupMember`.
    pub struct GroupMember {
        group_id: String,
        identity_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        package_assignment_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        team_id: Option<String>,
    }
}

/// `AutoAssignRule.approved`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovedChanges {
    pub grants: f64,
    pub removals: f64,
    pub until: f64,
}

/// `PackageRuleConditions`: exactly a policy statement's `conditions` block.
pub type PackageRuleConditions = Conditions;

/// `AutoAssignRule`: the birthright rule of an access package.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoAssignRule {
    pub include: Vec<PackageRuleConditions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<PackageRuleConditions>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_grants: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_removals: Option<f64>,
    pub owner_id: String,
    pub authority_id: String,
    pub revision: f64,
    pub updated_at: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved: Option<ApprovedChanges>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

record! {
    /// `AccessPackage`: roles and groups granted together for a shared period.
    pub struct AccessPackage {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        role_ids: Vec<String>,
        group_ids: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_duration_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        require_justification: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        requestable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approver_group_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        manager_approval: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auto_assign: Option<AutoAssignRule>,
        created_at: f64,
        updated_at: f64,
    }
}

record! {
    /// `PackageRuleIssue`: a problem the package-rule reconciler met.
    pub struct PackageRuleIssue {
        package_id: String,
        /// `'failed' | 'suspended' | 'braked'`.
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identity_id: Option<String>,
        code: String,
        message: String,
        revision: f64,
        since: f64,
    }
}

record! {
    /// `ExpiryReminderMark`: uniqueKey `{kind}:{id}:{expiresAt}`.
    pub struct ExpiryReminderMark {
        identity_id: String,
        expires_at: f64,
    }
}

/// `PackageRequestStatus` values.
pub const PACKAGE_REQUEST_STATUSES: [&str; 5] =
    ["pending", "approved", "denied", "cancelled", "expired"];

record! {
    /// `PackageRequest`.
    pub struct PackageRequest {
        package_id: String,
        identity_id: String,
        status: String,
        requested_at: f64,
        expires_at: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        desired_expires_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        justification: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decided_by: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decided_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        assignment_id: Option<String>,
    }
}

record! {
    /// `PackageAssignment`: uniqueKey `{packageId}:{identityId}`.
    pub struct PackageAssignment {
        package_id: String,
        identity_id: String,
        assigned_by: String,
        assigned_at: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        justification: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule_revision: Option<f64>,
        binding_ids: Vec<String>,
        membership_ids: Vec<String>,
    }
}

/// `TrustConditions`: a statement's `conditions` block over `token.<claim>` keys.
pub type TrustConditions = Conditions;

/// `SourceIdentityMode` values.
pub const SOURCE_IDENTITY_MODES: [&str; 3] = ["forbidden", "optional", "required"];

record! {
    /// `Trust`: permission to assume a role of this tenant (identity or web-identity trust).
    pub struct Trust {
        /// `'identity' | 'web-identity'`; absent on legacy records, which are identity trusts.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<String>,
        source_tenant_id: String,
        source_identity_id: String,
        role_id: String,
        require_mfa: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        external_id_hash: Option<String>,
        revoked: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ceiling: Option<PolicyDocument>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_session_seconds: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pass_source_attributes: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_tag_keys: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_identity_mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sessions_revoked_before: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        conditions: Option<TrustConditions>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tag_claims: Option<IndexMap<String, String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_identity_claim: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authority_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        created_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        created_by: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        updated_at: Option<f64>,
    }
}

/// `PublicTrust`: a trust as the API returns it (never the external ID hash).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicTrust {
    pub id: String,
    pub tenant_id: String,
    /// `'identity'` for legacy records.
    pub kind: String,
    pub source_tenant_id: String,
    pub source_identity_id: String,
    pub role_id: String,
    pub require_mfa: bool,
    pub requires_external_id: bool,
    pub revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceiling: Option<PolicyDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_session_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass_source_attributes: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_tag_keys: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_identity_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions_revoked_before: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<TrustConditions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_claims: Option<IndexMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_identity_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<f64>,
}

/// `WebIdentityAlgorithm` values: JWS algorithms an OIDC provider's tokens may use.
pub const WEB_IDENTITY_ALGORITHMS: [&str; 9] = [
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA",
];

/// `PublicJwk`: a public JSON Web Key (RFC 7517).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicJwk {
    pub kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `{ keys: PublicJwk[] }`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicJwks {
    pub keys: Vec<PublicJwk>,
}

record! {
    /// `OidcProvider`: an external OpenID Connect issuer (collection 'oidcProviders', uniqueKey `issuer:{issuer}`).
    pub struct OidcProvider {
        name: String,
        issuer: String,
        audiences: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        jwks_uri: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        jwks: Option<PublicJwks>,
        algorithms: Vec<String>,
        max_token_lifetime_seconds: f64,
        clock_tolerance_seconds: f64,
        /// `'single-use' | 'off'`.
        replay_protection: String,
        enabled: bool,
        authority_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sessions_revoked_before: Option<f64>,
        created_at: f64,
        created_by: String,
        updated_at: f64,
    }
}

/// `PublicOidcProvider`: an OIDC provider as the API returns it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicOidcProvider {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub issuer: String,
    pub audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<PublicJwks>,
    pub algorithms: Vec<String>,
    pub max_token_lifetime_seconds: f64,
    pub clock_tolerance_seconds: f64,
    pub replay_protection: String,
    pub enabled: bool,
    pub authority_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions_revoked_before: Option<f64>,
    pub created_at: f64,
    pub created_by: String,
    pub updated_at: f64,
}

record! {
    /// `WebIdentityReplay`: a redeemed web-identity token (collection 'webIdentityReplays').
    pub struct WebIdentityReplay {
        provider_id: String,
        expires_at: f64,
    }
}

record! {
    /// `OwnerInvitation`. The TypeScript server also writes `creatorId` (in `extra`).
    pub struct OwnerInvitation {
        token_hash: String,
        email: String,
        created_at: f64,
        expires_at: f64,
        authority_id: String,
        consumed: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revoked: Option<bool>,
    }
}

record! {
    /// `MemberInvitation`: `authorityId` is present only when the invitation carries roles or groups.
    pub struct MemberInvitation {
        token_hash: String,
        email: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        role_ids: Vec<String>,
        group_ids: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authority_id: Option<String>,
        inviter_id: String,
        created_at: f64,
        expires_at: f64,
        consumed: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revoked: Option<bool>,
    }
}

record! {
    /// `IdentityLink`.
    pub struct IdentityLink {
        left_id: String,
        right_id: String,
        revoked: bool,
    }
}

record! {
    /// `PrincipalBoundary`.
    pub struct PrincipalBoundary {
        identity_id: String,
        document: PolicyDocument,
    }
}

record! {
    /// `ActionDefinition`.
    pub struct ActionDefinition {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resource_type: Option<String>,
    }
}

record! {
    /// `ResourceTypeRecord`: a tenant-defined resource type; its actions are namespaced under the type name.
    pub struct ResourceTypeRecord {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        attributes: IndexMap<String, AttributeType>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relations: Option<Vec<String>>,
        created_at: f64,
    }
}

record! {
    /// `Relationship`: uniqueKey `{type}/{resourceId}#{relation}@{subjectType}:{subjectId}`.
    pub struct Relationship {
        #[serde(rename = "type")]
        kind: String,
        resource_id: String,
        relation: String,
        /// `'identity' | 'group'`.
        subject_type: String,
        subject_id: String,
        created_at: f64,
        created_by: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<f64>,
    }
}

record! {
    /// `ResourceRecord`: a managed resource registered with IAM; uniqueKey `{type}/{resourceId}`.
    pub struct ResourceRecord {
        #[serde(rename = "type")]
        kind: String,
        resource_id: String,
        attributes: Map<String, Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner_id: Option<String>,
        created_at: f64,
        updated_at: f64,
    }
}

record! {
    /// `TenantAlias`: the record id is the alias itself, so the primary key enforces uniqueness across tenants.
    pub struct TenantAlias {
        created_at: f64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn records_round_trip_unknown_members() {
        let value = json!({
            "id": "b1", "tenantId": "t1", "subjectType": "identity", "subjectId": "i1", "roleId": "r1",
            "authorityId": "a1", "window": { "from": "09:00", "to": "17:00", "timeZone": "UTC" }, "future": [1]
        });
        let binding: Binding = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(binding.window.as_ref().unwrap().time_zone, "UTC");
        assert_eq!(binding.extra.get("future"), Some(&json!([1])));
        let back = serde_json::to_value(&binding).unwrap();
        assert!(better_iam_core::js::deep_equal(&back, &value));
        let resource: ResourceRecord = serde_json::from_value(json!({
            "id": "r", "tenantId": "t", "type": "doc", "resourceId": "d1", "attributes": {}, "createdAt": 1, "updatedAt": 2
        }))
        .unwrap();
        assert_eq!(resource.kind, "doc");
    }
}
