//! The shared record and configuration types of `packages/core/src/index.ts` (tenants, identities, sessions, audit
//! events, outbox messages, the permission catalog configuration) and the plugin contracts.
//!
//! Records serialize with the TypeScript member names (camelCase) and leave unset optional members out. Members a
//! type does not declare are kept in `extra`, so a record written by a newer implementation survives a round trip.

use std::sync::Arc;

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::policy::PolicyDocument;
use crate::{IamResult, IamStore};

/// `TenantStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TenantStatus {
    Pending,
    Active,
    Suspended,
    Deleted,
}

/// How a user session was established (`AuthMethod`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMethod {
    Password,
    PasswordlessEmail,
    PasswordlessSms,
    Passkey,
    Federated,
    /// A session an administrator opened on a member's behalf (`identities.impersonate`); never a sign-in method.
    Impersonation,
}

impl AuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMethod::Password => "password",
            AuthMethod::PasswordlessEmail => "passwordless-email",
            AuthMethod::PasswordlessSms => "passwordless-sms",
            AuthMethod::Passkey => "passkey",
            AuthMethod::Federated => "federated",
            AuthMethod::Impersonation => "impersonation",
        }
    }
}

/// The sign-in methods a tenant policy can allow or restrict (`authMethods`); impersonation is an administrative
/// action, not a sign-in.
pub const AUTH_METHODS: [AuthMethod; 5] = [
    AuthMethod::Password,
    AuthMethod::PasswordlessEmail,
    AuthMethod::PasswordlessSms,
    AuthMethod::Passkey,
    AuthMethod::Federated,
];

macro_rules! optional_fields {
    ($(#[$meta:meta])* pub struct $name:ident { $($(#[$fmeta:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            $(
                $(#[$fmeta])*
                #[serde(default, skip_serializing_if = "Option::is_none")]
                pub $field: Option<$ty>,
            )*
            /// Members this type does not declare.
            #[serde(flatten)]
            pub extra: Map<String, Value>,
        }
    };
}

optional_fields! {
    /// Per-tenant authentication rules layered under the deployment's configuration; never looser than it
    /// (`TenantAuthPolicy`).
    pub struct TenantAuthPolicy {
        require_mfa: bool,
        allowed_methods: Vec<AuthMethod>,
        session_lifetime_ms: f64,
        session_idle_timeout_ms: f64,
        max_attempts: f64,
        min_password_length: f64,
        max_sessions: f64,
        allow_impersonation: bool,
        trusted_device_days: f64,
        password_history: f64,
        password_max_age_days: f64,
        password_min_classes: f64,
        password_reject_personal_info: bool,
        notify_new_sign_in: bool,
        allowed_ip_ranges: Vec<String>,
        mfa_email_codes: bool,
        require_mfa_for_owners: bool,
        bind_sessions_to_ip: bool,
    }
}

optional_fields! {
    /// Floors for just-in-time activation across a tenant (`TenantAccessPolicy`).
    pub struct TenantAccessPolicy {
        max_activation_ms: f64,
        require_justification: bool,
        require_mfa: bool,
        require_approval: bool,
        approval_lifetime_ms: f64,
    }
}

optional_fields! {
    /// Plan limits a platform administrator sets on a tenant (`TenantLimits`).
    pub struct TenantLimits {
        identities: f64,
        service_accounts: f64,
        agents: f64,
        groups: f64,
        roles: f64,
        policies: f64,
        resources: f64,
        webhooks: f64,
    }
}

/// `Tenant`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tenant {
    pub id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub parent_id: Option<String>,
    pub status: TenantStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary: Option<PolicyDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_policy: Option<TenantAuthPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_policy: Option<TenantAccessPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<TenantLimits>,
    pub created_at: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<f64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Who suspended an agent, when, and why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentSuspension {
    pub by: String,
    pub at: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The account profile of an AI agent (`AgentProfile`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentProfile {
    pub sponsor_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_delegated_session_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary: Option<PolicyDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_audiences: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspended: Option<AgentSuspension>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The marker of a guest (`GuestProfile`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestProfile {
    pub sponsor_id: String,
    pub since: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_domain: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `Identity.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityKind {
    User,
    Service,
    Agent,
}

/// `Identity.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityStatus {
    Active,
    Disabled,
    Deleted,
}

/// `Identity`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    pub kind: IdentityKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest: Option<GuestProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Map<String, Value>>,
    pub status: IdentityStatus,
    pub email_verified: bool,
    pub root_admin: bool,
    pub owner: bool,
    pub created_at: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_changed_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unproven_password: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_email: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

optional_fields! {
    /// Client details recorded on a session for device lists; never used for authorization (`SessionClientInfo`).
    pub struct SessionClientInfo {
        ip: String,
        user_agent: String,
        label: String,
    }
}

/// Sign-in bookkeeping kept per person (`SignInRecord`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_client: Option<SessionClientInfo>,
    pub failed_attempts: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failed_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failed_client: Option<SessionClientInfo>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The kinds of stored session (`SessionKind`). Code that branches on the kind must fail closed for kinds it does
/// not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionKind {
    User,
    Role,
    ApiKey,
    SessionToken,
    Delegated,
}

impl SessionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionKind::User => "user",
            SessionKind::Role => "role",
            SessionKind::ApiKey => "api-key",
            SessionKind::SessionToken => "session-token",
            SessionKind::Delegated => "delegated",
        }
    }
}

/// Web-identity role sessions: the OIDC provider and the verified external subject behind the session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebIdentity {
    pub provider_id: String,
    pub issuer: String,
    pub subject: String,
}

/// `Session`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    pub identity_id: String,
    pub token_hash: String,
    pub created_at: f64,
    pub expires_at: f64,
    pub last_seen_at: f64,
    pub authenticated_at: f64,
    pub mfa: bool,
    pub kind: SessionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa_authenticated_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_authority_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_tags: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_policy: Option<PolicyDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_identity: Option<WebIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<AuthMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<SessionClientInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonator_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonator_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_identity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_authority_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_sign_in: Option<SignInRecord>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The session an audited action ran under (`AuditSessionContext`): an allowlist projection of the session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditSessionContext {
    pub session_id: String,
    pub kind: SessionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_identity_provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_identity_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_id: Option<String>,
}

/// Produced by verified credential resolution (`AuthenticatedPrincipal`). Server services never accept this from
/// JSON.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticatedPrincipal {
    pub identity: Identity,
    pub session: Session,
    /// The unverified device proof the request carried (`x-better-iam-device`).
    pub device_proof: Option<String>,
}

/// `AuditEvent.outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    Allow,
    Deny,
}

/// `AuditEvent`. The audit chain functions work on [`crate::Record`]s so that every stored member is hashed; this
/// type is the typed view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    pub actor_id: String,
    pub action: String,
    pub resource_id: String,
    pub timestamp: f64,
    pub outcome: AuditOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_override: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_actor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonator_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_context: Option<AuditSessionContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `OutboxMessage.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboxKind {
    Email,
    Sms,
    Webhook,
}

/// `OutboxMessage`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboxMessage {
    pub id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    pub kind: OutboxKind,
    pub to: String,
    pub template: String,
    pub payload: Map<String, Value>,
    pub created_at: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<f64>,
    pub attempts: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `CredentialInput`: request headers (name, value) and/or a bearer token.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CredentialInput {
    pub headers: Option<Vec<(String, String)>>,
    pub token: Option<String>,
}

/// `ResourceRef`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceRef {
    pub tenant_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

/// `TenantType`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantType {
    pub allowed_children: Vec<String>,
}

/// `HierarchyConfig`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HierarchyConfig {
    pub types: indexmap::IndexMap<String, TenantType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<f64>,
}

/// `AttributeType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttributeType {
    String,
    Number,
    Boolean,
}

/// `ResourceTypeDefinition`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceTypeDefinition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<indexmap::IndexMap<String, AttributeType>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relations: Option<Vec<String>>,
}

/// `PermissionsConfig.mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionsMode {
    Catalog,
    TenantDefined,
}

/// `PermissionsConfig`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<PermissionsMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_types: Option<indexmap::IndexMap<String, ResourceTypeDefinition>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_attributes: Option<indexmap::IndexMap<String, AttributeType>>,
}

/// `PluginDelivery.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginDeliveryKind {
    Email,
    Sms,
}

/// A delivery a plugin handler may queue in its transaction (`PluginDelivery`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginDelivery {
    pub kind: PluginDeliveryKind,
    pub to: String,
    pub template: String,
    pub payload: indexmap::IndexMap<String, String>,
}

/// Queues an outbox delivery in the endpoint's transaction and returns the message ID.
pub type DeliverFn =
    Arc<dyn Fn(PluginDelivery) -> BoxFuture<'static, IamResult<String>> + Send + Sync>;

/// `PluginEndpointContext`.
#[derive(Clone)]
pub struct PluginEndpointContext {
    pub store: Arc<dyn IamStore>,
    pub principal: AuthenticatedPrincipal,
    pub tenant_id: String,
    pub deliver: DeliverFn,
}

/// `PluginEndpoint` (method is always `POST`).
#[async_trait::async_trait]
pub trait PluginEndpoint: Send + Sync {
    fn path(&self) -> &str;
    fn action(&self) -> &str;
    /// Validation must reject unknown/invalid fields before calling handler.
    fn validate(&self, input: &Value) -> IamResult<Map<String, Value>>;
    /// The record the endpoint acts on, from the validated input (for example `project/{projectId}`); None
    /// authorizes on the tenant itself.
    fn resource(&self, _input: &Map<String, Value>) -> Option<String> {
        None
    }
    async fn handler(
        &self,
        context: PluginEndpointContext,
        input: Map<String, Value>,
    ) -> IamResult<Value>;
}

/// `OperationHookInput`.
#[derive(Clone)]
pub struct OperationHookInput {
    pub store: Arc<dyn IamStore>,
    pub principal: AuthenticatedPrincipal,
    pub tenant_id: String,
    pub action: String,
    pub resource_id: String,
}

/// `PluginHooks`: both run inside the operation's transaction; returning an error aborts it.
#[async_trait::async_trait]
pub trait PluginHooks: Send + Sync {
    /// Runs after authorization and before the mutation.
    async fn before_operation(&self, _input: &OperationHookInput) -> IamResult<()> {
        Ok(())
    }
    /// Runs after the mutation, before its audit record.
    async fn after_operation(&self, _input: &OperationHookInput, _result: &Value) -> IamResult<()> {
        Ok(())
    }
}

/// `IamPlugin.afterAudit`: runs after commit for every recorded audit event.
#[async_trait::async_trait]
pub trait AfterAuditHook: Send + Sync {
    async fn after_audit(&self, event: &crate::Record) -> IamResult<()>;
}

/// `IamPlugin`. Optional TypeScript members are default methods.
#[async_trait::async_trait]
pub trait IamPlugin: Send + Sync {
    fn id(&self) -> &str;
    fn actions(&self) -> Vec<String> {
        Vec::new()
    }
    /// Platform resource types contributed by the plugin, validated like `permissions.resourceTypes`.
    fn resource_types(&self) -> indexmap::IndexMap<String, ResourceTypeDefinition> {
        indexmap::IndexMap::new()
    }
    fn endpoints(&self) -> Vec<Arc<dyn PluginEndpoint>> {
        Vec::new()
    }
    fn hooks(&self) -> Option<Arc<dyn PluginHooks>> {
        None
    }
    fn validate_config(&self) -> IamResult<()> {
        Ok(())
    }
    async fn migrate(&self, _store: &dyn IamStore) -> IamResult<()> {
        Ok(())
    }
    /// Adds trusted, server-derived keys to the policy evaluation context; never trust browser input here.
    async fn resolve_context(
        &self,
        _principal: &AuthenticatedPrincipal,
    ) -> IamResult<Map<String, Value>> {
        Ok(Map::new())
    }
    /// `afterAudit`: an optional hook (TypeScript's `plugin.afterAudit?`). Its presence matters: the server records an
    /// `auditHooks` row for post-commit dispatch only when some plugin has one (or `events.onEvent`/subscribers exist).
    fn after_audit(&self) -> Option<Arc<dyn AfterAuditHook>> {
        None
    }
    /// Remove plugin-owned records before the server deletes purged tenants in the same transaction.
    async fn purge(&self, _store: &dyn IamStore, _tenant_ids: &[String]) -> IamResult<()> {
        Ok(())
    }
}
