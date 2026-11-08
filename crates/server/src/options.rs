//! Port of `packages/server/src/options.ts`: every option type of `BetterIamOptions` and `resolveConfig`, the
//! validation that turns options into the [`ServerConfig`].
//!
//! Options mirror `BetterIamOptions` field for field; JavaScript callbacks are `Arc` closures or traits with the same
//! names. Validation reads the options as a model value ([`crate::options_value::options_value`]): the
//! JSON-representable members spelled as in TypeScript, callbacks as function markers. That is what lets the
//! standalone JSON configuration ([`crate::standalone_config`]) and in-process Rust options be refused with identical
//! `INVALID_CONFIG` (and, where TypeScript throws them, `INVALID_INPUT`) codes and messages, in the same order,
//! including values a Rust type could not hold (a string where a number belongs): the configuration reader keeps the
//! JSON it read as the options' model.
//!
//! Option types of modules that are not ported yet (audit archiving, access usage, inference, A2A, billing, SSH,
//! verifiable credentials, vault, domains) are declared here as well, with the TypeScript module named; those
//! modules validate them when they are ported.

use std::sync::Arc;

use better_iam_auth::{DeliveryError, PasswordPolicyOptions, RateLimitOptions, RequireMfaFn};
use better_iam_core::{
    AuthenticatedPrincipal, ClassificationLabel, CredentialInput, HierarchyConfig, IamError,
    IamPlugin, IamResult, IamStore, PermissionsConfig, Record, ResourceRef, SessionClientInfo,
    TenantAuthPolicy, TenantLimits, TenantType,
};
use futures::future::BoxFuture;
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use url::Url;

use crate::hosts::{
    HostConfigContext, HostOptions, RegionOptions, ResolvedHostConfig, ResolvedRegionConfig,
    resolve_host_config, resolve_region_config, url_hostname, url_origin,
};
use crate::js::{
    self, defined, internal_error, invalid_config, is_function, is_object, js_string, member,
    number_to_string, type_name, utf16_len,
};
use crate::observe::ObservabilityOptions;
use crate::tenant_policy::{tenant_auth_policy, tenant_limits};
use crate::validation::{integer, text256};
use crate::web_identity::{IssuerRules, web_identity_issuer};

/// `boolean | Options`: an option that is switched on with `true` or configured with an object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Toggle<T> {
    Flag(bool),
    Options(T),
}

impl<T> Toggle<T> {
    /// The options object, when one was given.
    pub fn options(&self) -> Option<&T> {
        match self {
            Self::Options(options) => Some(options),
            Self::Flag(_) => None,
        }
    }

    /// Truthiness of the option (`true` or an object).
    pub fn enabled(&self) -> bool {
        !matches!(self, Self::Flag(false))
    }
}

/// `WebhookEvent`: the JSON body delivered to a webhook endpoint ([`crate::events::webhook_body`] builds it in this
/// member order).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub tenant_id: String,
    pub actor_id: String,
    pub resource_id: String,
    /// `'allow' | 'deny'`.
    pub outcome: String,
    pub timestamp: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_actor_id: Option<String>,
    /// Set when an administrator acted through an impersonation session; `actorId` is the member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonator_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_override: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_context: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// `WebhookDelivery`: a signed delivery handed to `events.deliverWebhook` when the default HTTP transport is
/// replaced. `headers` keep the TypeScript order (content-type, user-agent, x-better-iam-event, -delivery,
/// -webhook, -timestamp, -signature).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookDelivery {
    pub id: String,
    pub tenant_id: String,
    pub webhook_id: String,
    pub url: String,
    pub event: String,
    pub body: String,
    pub headers: IndexMap<String, String>,
}

/// `events.onEvent(event)`: called after commit for every audit event (a stored audit event record), from the
/// dispatcher; at-least-once.
pub type OnEventFn = Arc<dyn Fn(Record) -> BoxFuture<'static, IamResult<()>> + Send + Sync>;
/// `events.deliverWebhook(delivery)`: replaces the built-in HTTPS POST transport.
pub type DeliverWebhookFn =
    Arc<dyn Fn(WebhookDelivery) -> BoxFuture<'static, Result<(), DeliveryError>> + Send + Sync>;

/// `EventOptions`.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventOptions {
    #[serde(skip)]
    pub on_event: Option<OnEventFn>,
    #[serde(skip)]
    pub deliver_webhook: Option<DeliverWebhookFn>,
    /// Timeout for the built-in transport (default 10 seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_timeout_ms: Option<f64>,
    /// Lets webhook endpoints reach private and reserved addresses. Off by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_private_networks: Option<bool>,
}

/// `AccessRequestOptions`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessRequestOptions {
    /// How long a pending request stays open (default 7 days).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime_ms: Option<f64>,
    /// Longest temporary grant a request may ask for (default 90 days).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<f64>,
}

/// The request head a [`ClientInfoFn`] sees (method, URI, headers).
pub type RequestHead = http::request::Parts;

/// `http.clientInfo(request)`: derives the client details recorded on sessions issued by a request.
pub type ClientInfoFn = Arc<dyn Fn(&RequestHead) -> Option<SessionClientInfo> + Send + Sync>;

/// `HttpOptions`.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpOptions {
    #[serde(skip)]
    pub client_info: Option<ClientInfoFn>,
    /// `SameSite` of the session and device cookies: `lax` (default) or `strict`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_same_site: Option<String>,
    /// Whether session cookies outlive the browser by default (default true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_cookies: Option<bool>,
}

/// A buffered HTTP request as protocol mounts see it.
pub type HttpRequest = http::Request<bytes::Bytes>;
/// A buffered HTTP response.
pub type HttpResponse = http::Response<bytes::Bytes>;

/// `ProtocolMount`: a protocol handler (OAuth/OIDC, SAML, SCIM, verifiable credentials, Shared Signals) mounted in
/// front of the IAM routes. `handle` answers the request, or returns None to pass it on.
#[async_trait::async_trait]
pub trait ProtocolMount: Send + Sync {
    async fn handle(&self, request: &HttpRequest) -> IamResult<Option<HttpResponse>>;
}

/// The resource of an authorization request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceTarget {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

/// `AuthorizationRequest`.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationRequest {
    pub credential: CredentialInput,
    pub tenant_id: String,
    pub action: String,
    pub resource: ResourceTarget,
}

/// `AuthorizationCheck`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationCheck {
    pub action: String,
    pub resource: ResourceTarget,
}

/// `BatchAuthorizationRequest`.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchAuthorizationRequest {
    pub credential: CredentialInput,
    pub tenant_id: String,
    pub checks: Vec<AuthorizationCheck>,
}

/// `AccessibleResourcesRequest`: which registered resources of a managed type may the caller act on.
#[derive(Debug, Clone, PartialEq)]
pub struct AccessibleResourcesRequest {
    pub credential: CredentialInput,
    pub tenant_id: String,
    pub action: String,
    pub kind: String,
    pub limit: Option<f64>,
    pub offset: Option<f64>,
}

/// `ResolvedResource`: a resource reference with its trusted attributes and, with security clearances, its
/// effective classification label (`Some(Value::Null)`: looked up and unlabeled; `None`: no classification member).
/// A resolver may return a label, validated later against the tenant's scheme, so it is kept as JSON.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResolvedResource {
    pub tenant_id: String,
    pub kind: String,
    pub id: String,
    pub attributes: Option<Map<String, Value>>,
    pub classification: Option<Value>,
}

impl ResolvedResource {
    /// The resource of a reference, without attributes.
    pub fn of(reference: &ResourceRef) -> Self {
        Self {
            tenant_id: reference.tenant_id.clone(),
            kind: reference.kind.clone(),
            id: reference.id.clone(),
            attributes: None,
            classification: None,
        }
    }

    /// The reference part.
    pub fn reference(&self) -> ResourceRef {
        ResourceRef {
            tenant_id: self.tenant_id.clone(),
            kind: self.kind.clone(),
            id: self.id.clone(),
        }
    }

    /// The JSON form (`{ tenantId, type, id, attributes?, classification? }`).
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("tenantId".into(), Value::String(self.tenant_id.clone()));
        map.insert("type".into(), Value::String(self.kind.clone()));
        map.insert("id".into(), Value::String(self.id.clone()));
        if let Some(attributes) = &self.attributes {
            map.insert("attributes".into(), Value::Object(attributes.clone()));
        }
        if let Some(classification) = &self.classification {
            map.insert("classification".into(), classification.clone());
        }
        Value::Object(map)
    }

    /// Reads the JSON form a resolver returns (`classification` is kept as given; the clearances module validates it).
    pub fn from_value(value: &Value) -> Option<Self> {
        let map = value.as_object()?;
        Some(Self {
            tenant_id: map.get("tenantId")?.as_str()?.to_owned(),
            kind: map.get("type")?.as_str()?.to_owned(),
            id: map.get("id")?.as_str()?.to_owned(),
            attributes: map.get("attributes").and_then(Value::as_object).cloned(),
            classification: map.get("classification").cloned(),
        })
    }

    /// A label as the classification member.
    pub fn label(label: &ClassificationLabel) -> Value {
        serde_json::to_value(label).unwrap_or(Value::Null)
    }
}

/// `resolveResource(reference)`: ownership and attributes from trusted storage.
pub type ResolveResourceFn =
    Arc<dyn Fn(ResourceRef) -> BoxFuture<'static, IamResult<ResolvedResource>> + Send + Sync>;
/// `resolveContext(principal)`: application context keys for a principal.
pub type ResolveContextFn = Arc<
    dyn Fn(AuthenticatedPrincipal) -> BoxFuture<'static, IamResult<Map<String, Value>>>
        + Send
        + Sync,
>;

/// A JSON Web Key as JSON (RFC 7517).
pub type Jwk = Map<String, Value>;

/// `SessionTokenSigningOptions`: signing keys for session JWTs (`format: 'jwt'`), separate from `secret`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionTokenSigningOptions {
    pub signing_keys: Vec<Jwk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_keys: Option<Vec<Jwk>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audiences: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lifetime_seconds: Option<f64>,
}

/// `fetchJson(url)`: replaces the built-in guarded fetch of discovery documents and JWKS.
pub type FetchJsonFn = Arc<dyn Fn(Url) -> BoxFuture<'static, IamResult<Value>> + Send + Sync>;

/// `StsWebIdentityOptions`: AssumeRoleWithWebIdentity.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StsWebIdentityOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_issuers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_cache_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetch_timeout_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_jwks_bytes: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_exchanges_per_window: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_sessions_per_trust: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_private_networks: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_insecure_localhost: Option<bool>,
    #[serde(skip)]
    pub fetch_json: Option<FetchJsonFn>,
}

/// `StsOptions`: temporary credentials.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StsOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_role_session_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_session_token_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_session_tokens_per_identity: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<SessionTokenSigningOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_identity: Option<StsWebIdentityOptions>,
}

/// `ResolvedStsConfig.webIdentity`.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedWebIdentityConfig {
    pub enabled: bool,
    pub allowed_issuers: Option<Vec<String>>,
    pub jwks_cache_seconds: f64,
    pub fetch_timeout_ms: f64,
    pub max_jwks_bytes: f64,
    pub max_exchanges_per_window: f64,
    pub max_sessions_per_trust: f64,
    pub allow_private_networks: bool,
    pub allow_insecure_localhost: bool,
}

/// `ResolvedStsConfig`: validated STS settings with defaults applied (`jwt` is validated by the token signer).
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedStsConfig {
    pub max_role_session_seconds: f64,
    pub max_session_token_seconds: f64,
    pub max_session_tokens_per_identity: f64,
    pub web_identity: ResolvedWebIdentityConfig,
}

/// `ClearanceOptions`: its presence enables security clearances.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClearanceOptions {
    /// Whether root administrators are bound by classification labels too (default true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_to_root: Option<bool>,
}

/// `ResolvedClearanceConfig`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedClearanceConfig {
    pub applies_to_root: bool,
}

/// `SignalsOptions`: the Shared Signals receiver.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalsOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_private_networks: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_insecure_localhost: Option<bool>,
    /// Where transmitters push: `{pushPath}/{sourceId}` (default `{basePath}/signals/push`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_path: Option<String>,
}

/// `ResolvedSignalsConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSignalsConfig {
    pub allow_private_networks: bool,
    pub allow_insecure_localhost: bool,
    pub push_path: String,
}

/// `BetterIamOptions.onboarding`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnboardingOptions {
    /// `'invitation' | 'linked'`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation_lifetime_ms: Option<f64>,
}

/// `BetterIamOptions.tenantDefaults`: plan limits and authentication policy for tenants created through
/// `tenants.create`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantDefaults {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<TenantLimits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_policy: Option<TenantAuthPolicy>,
}

/// `passkeys` of [`ServerAuthOptions`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerPasskeyOptions {
    pub rp_id: String,
    pub rp_name: Option<String>,
}

/// `BetterIamOptions.authentication`: `AuthOptions` without `store`, `secret`, `previousSecrets`, `baseURL` and
/// `trustedOrigins`, which the server supplies (it also replaces `onAudit` and `deliverWebhook`).
#[derive(Clone, Default)]
pub struct ServerAuthOptions {
    pub app_name: Option<String>,
    pub sign_up_enabled: Option<bool>,
    pub require_email_verification: Option<bool>,
    pub email_password: Option<bool>,
    pub passwordless_email: Option<bool>,
    pub passwordless_sms: Option<bool>,
    pub send_email: Option<better_iam_auth::DeliveryFn>,
    pub send_sms: Option<better_iam_auth::DeliveryFn>,
    /// Ignored: the server always delivers webhooks itself.
    pub deliver_webhook: Option<better_iam_auth::DeliveryFn>,
    pub max_delivery_attempts: Option<f64>,
    pub session_lifetime_ms: Option<f64>,
    pub session_idle_timeout_ms: Option<f64>,
    pub recent_authentication_ms: Option<f64>,
    pub trusted_device_lifetime_ms: Option<f64>,
    pub sign_in_notifications: Option<bool>,
    pub mfa_email_codes: Option<bool>,
    pub failed_sign_in_alerts: Option<f64>,
    pub rate_limits: Option<RateLimitOptions>,
    pub require_mfa: Option<RequireMfaFn>,
    pub passkeys: Option<ServerPasskeyOptions>,
    /// Ignored: the server always records authentication events itself.
    pub on_audit: Option<better_iam_auth::OnAuditFn>,
    /// Inject time for deterministic integration tests.
    pub now: Option<better_iam_auth::NowFn>,
    pub password_policy: Option<PasswordPolicyOptions>,
}

/// `AuditArchiveBatch` (audit-archive.ts).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditArchiveBatch {
    pub tenant_id: String,
    pub from_sequence: f64,
    pub to_sequence: f64,
    pub previous_hash: String,
    pub last_hash: String,
    /// Events in chain order (stored audit event records).
    pub events: Vec<Record>,
}

/// `auditArchive.write(batch)`.
pub type AuditArchiveWriteFn =
    Arc<dyn Fn(AuditArchiveBatch) -> BoxFuture<'static, IamResult<()>> + Send + Sync>;

/// `AuditArchiveOptions` (audit-archive.ts).
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditArchiveOptions {
    #[serde(skip)]
    pub write: Option<AuditArchiveWriteFn>,
    /// Events per batch (default 1000, 1-10000).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_size: Option<f64>,
    /// How long one run may hold a tenant (default 10 minutes, 1 minute to 1 hour).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_ms: Option<f64>,
}

/// `AccessUsageOptions` (usage.ts).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessUsageOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flush_interval_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_buffered: Option<f64>,
}

/// `InferenceOptions` (inference.ts).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InferenceOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_custom_base_urls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_retention_days: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_insecure_localhost: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_private_networks: Option<bool>,
}

/// `A2aOptions` (a2a.ts).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aOptions {
    pub signing_keys: Vec<Jwk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_keys: Option<Vec<Jwk>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card_lifetime_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

/// `InvoiceIssuer` (billing.ts).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvoiceIssuer {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tax_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_instructions: Option<String>,
}

/// `BillingOptions` (billing.ts).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BillingOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_retention_days: Option<f64>,
    /// `'split' | 'primary' | 'full'`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_attribution: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_terms_days: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<InvoiceIssuer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_reminder_days: Option<Vec<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_finalize: Option<bool>,
}

/// `SshOptions` (ssh.ts).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_user_certificate_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_certificate_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_skew_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_hosts_per_certificate: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_retention_days: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_token_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuance_limit: Option<f64>,
}

/// `VerifiableCredentialOptions` (vc.ts).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiableCredentialOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lifetime_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_list_size: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_lifetime_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_list_lifetime_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_list_ttl_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_retention_days: Option<f64>,
}

/// `VaultRotator` (vault.ts): applies a rotated value to the system it unlocks. Inputs are the TypeScript
/// `RotatorInput` as JSON.
#[async_trait::async_trait]
pub trait VaultRotator: Send + Sync {
    async fn rotate(&self, input: Value) -> IamResult<()>;
}

/// `VaultEngine` (vault.ts): a dynamic secret engine. Inputs and results are the TypeScript `EngineIssueInput`,
/// `EngineLeaseInput` and `EngineIssued` as JSON.
#[async_trait::async_trait]
pub trait VaultEngine: Send + Sync {
    async fn issue(&self, input: Value) -> IamResult<Value>;
    /// Whether `revoke` is implemented (optional in TypeScript).
    fn has_revoke(&self) -> bool {
        false
    }
    async fn revoke(&self, _input: Value) -> IamResult<()> {
        Ok(())
    }
    /// Whether `renew` is implemented (optional in TypeScript).
    fn has_renew(&self) -> bool {
        false
    }
    async fn renew(&self, _input: Value) -> IamResult<()> {
        Ok(())
    }
}

/// `VaultOptions` (vault.ts).
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultOptions {
    #[serde(skip)]
    pub rotators: Option<IndexMap<String, Arc<dyn VaultRotator>>>,
    #[serde(skip)]
    pub engines: Option<IndexMap<String, Arc<dyn VaultEngine>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_value_bytes: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_secrets_per_tenant: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_retention_days: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_timeout_ms: Option<f64>,
}

/// `domains.resolveTxt(hostname)`: TXT lookup.
pub type ResolveTxtFn =
    Arc<dyn Fn(String) -> BoxFuture<'static, IamResult<Vec<Vec<String>>>> + Send + Sync>;

/// `DomainOptions` (api/domains.ts).
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainOptions {
    #[serde(skip)]
    pub resolve_txt: Option<ResolveTxtFn>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_domains: Option<Vec<String>>,
}

/// `BetterIamOptions`.
#[derive(Clone, Default)]
pub struct BetterIamOptions {
    pub database: Option<Arc<dyn IamStore>>,
    pub secret: String,
    /// Deployment secrets being rotated out (at most five).
    pub previous_secrets: Option<Vec<String>>,
    pub base_url: String,
    pub base_path: Option<String>,
    pub trusted_origins: Option<Vec<String>>,
    pub authentication: Option<ServerAuthOptions>,
    pub hierarchy: Option<HierarchyConfig>,
    pub permissions: Option<PermissionsConfig>,
    pub onboarding: Option<OnboardingOptions>,
    pub plugins: Option<Vec<Arc<dyn IamPlugin>>>,
    pub events: Option<EventOptions>,
    pub audit_archive: Option<AuditArchiveOptions>,
    pub access_requests: Option<AccessRequestOptions>,
    pub observability: Option<ObservabilityOptions>,
    pub access_usage: Option<Toggle<AccessUsageOptions>>,
    pub inference: Option<Toggle<InferenceOptions>>,
    pub a2a: Option<A2aOptions>,
    pub billing: Option<BillingOptions>,
    pub ssh: Option<Toggle<SshOptions>>,
    pub verifiable_credentials: Option<Toggle<VerifiableCredentialOptions>>,
    pub clearances: Option<ClearanceOptions>,
    pub vault: Option<VaultOptions>,
    pub http: Option<HttpOptions>,
    pub tenant_defaults: Option<TenantDefaults>,
    pub domains: Option<DomainOptions>,
    pub hosts: Option<HostOptions>,
    pub regions: Option<RegionOptions>,
    pub resolve_resource: Option<ResolveResourceFn>,
    pub resolve_context: Option<ResolveContextFn>,
    pub protocols: Option<Vec<Arc<dyn ProtocolMount>>>,
    pub sts: Option<StsOptions>,
    pub signals: Option<SignalsOptions>,
    /// The options as the TypeScript validators see them, when they were read from JSON
    /// ([`crate::standalone_config`]); otherwise derived from the typed members.
    pub(crate) model: Option<Arc<Value>>,
    /// Members of a JSON configuration whose value has no typed form (validation reports them).
    pub(crate) undecodable: Vec<(String, String)>,
}

impl BetterIamOptions {
    /// The required options; everything else takes its default.
    pub fn new(
        database: Arc<dyn IamStore>,
        secret: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            database: Some(database),
            secret: secret.into(),
            base_url: base_url.into(),
            ..Self::default()
        }
    }

    /// Options given as their model value: the JSON TypeScript's validators would receive as `options` (callbacks as
    /// [`crate::js::function_marker`]s). Validation reads the model; the typed members stay unset, so this is for
    /// checking configurations (the conformance suite, `better-iam doctor`), not for running a server.
    pub fn from_model(database: Arc<dyn IamStore>, model: Value) -> Self {
        let get = |key: &str| {
            model
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        };
        Self {
            database: Some(database),
            secret: get("secret"),
            base_url: get("baseURL"),
            model: Some(Arc::new(model)),
            ..Self::default()
        }
    }

    /// Members of a JSON configuration that passed the TypeScript validation but have no typed Rust form; the
    /// composition root calls this after every validator ran ([`check_decoded`]).
    pub fn undecodable(&self) -> &[(String, String)] {
        &self.undecodable
    }

    /// The JSON configuration these options were read from, if any.
    pub fn model(&self) -> Option<&Value> {
        self.model.as_deref()
    }
}

/// Refuses options read from JSON whose members passed validation but cannot be represented by the Rust types
/// (`INVALID_CONFIG`, `Invalid better-iam.json: <member>: <reason>`). TypeScript would carry such values along; the
/// composition root runs this after every module validated its options.
pub fn check_decoded(options: &BetterIamOptions) -> IamResult<()> {
    match options.undecodable.first() {
        Some((member, reason)) => Err(invalid_config(format!(
            "Invalid better-iam.json: {member}: {reason}"
        ))),
        None => Ok(()),
    }
}

/// `ServerConfig`: validated, defaulted configuration derived once from the options.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub base_url: Url,
    pub base_path: String,
    /// `new Set([baseURL.origin, ...trustedOrigins])`.
    pub trusted_origins: IndexSet<String>,
    pub hierarchy: HierarchyConfig,
    pub max_depth: f64,
    pub tenant_defined: bool,
    pub strict_resource_types: bool,
    pub linked_onboarding: bool,
    /// `onboarding.invitationLifetimeMs ?? 86400000`, unvalidated as in TypeScript (NaN for a non-number).
    pub invitation_lifetime_ms: f64,
    pub access_request_lifetime_ms: f64,
    pub access_request_max_duration_seconds: f64,
    pub webhook_timeout_ms: f64,
    pub tenant_defaults: TenantDefaults,
    pub sts: ResolvedStsConfig,
    /// Organization sign-in addresses (`hosts` option), compiled.
    pub hosts: ResolvedHostConfig,
    /// Region settings (`regions` option); None for single-region deployments.
    pub regions: Option<ResolvedRegionConfig>,
    /// Shared Signals receiver settings (`signals` option).
    pub signals: ResolvedSignalsConfig,
    /// Security clearance settings (`clearances` option); None when the module is off.
    pub clearances: Option<ResolvedClearanceConfig>,
}

impl ServerConfig {
    /// `config.baseURL.origin`.
    pub fn origin(&self) -> String {
        url_origin(&self.base_url)
    }

    /// `config.baseURL.protocol === 'https:'`.
    pub fn https(&self) -> bool {
        self.base_url.scheme() == "https"
    }
}

/// `defaultHierarchy`.
pub fn default_hierarchy() -> HierarchyConfig {
    let mut types = IndexMap::new();
    types.insert(
        "root".to_owned(),
        TenantType {
            allowed_children: vec!["organization".to_owned()],
        },
    );
    types.insert(
        "organization".to_owned(),
        TenantType {
            allowed_children: vec!["project".to_owned()],
        },
    );
    types.insert(
        "project".to_owned(),
        TenantType {
            allowed_children: Vec::new(),
        },
    );
    HierarchyConfig {
        types,
        max_depth: Some(8.0),
    }
}

fn default_hierarchy_value() -> Value {
    serde_json::to_value(default_hierarchy()).expect("serializable")
}

/// Iterates `for (const child of value)`: arrays by item, strings by code point; anything else throws a TypeError.
fn iterate(value: Option<&Value>) -> IamResult<Vec<Value>> {
    match value {
        Some(Value::Array(items)) => Ok(items.clone()),
        Some(Value::String(text)) => Ok(text.chars().map(|c| Value::String(c.into())).collect()),
        _ => Err(internal_error()),
    }
}

/// Spreads `[...value]` (arrays and strings), TypeError otherwise.
fn spread(value: Option<&Value>) -> IamResult<Vec<Value>> {
    iterate(value)
}

/// `resolveConfig(options)`.
pub fn resolve_config(options: &BetterIamOptions) -> IamResult<ServerConfig> {
    if options.database.is_none() {
        return Err(invalid_config("database is required"));
    }
    let model = crate::options_value::options_value(options);
    let root = Some(&*model);
    let get = |key: &str| member(root, key);
    // new URL(options.baseURL), whose TypeError for anything that is not an absolute URL becomes INVALID_CONFIG.
    let base_url = Url::parse(&js_string(get("baseURL")))
        .map_err(|_| invalid_config("baseURL must be an absolute URL"))?;
    if base_url.scheme() != "https"
        && !["localhost", "127.0.0.1", "[::1]"].contains(&url_hostname(&base_url).as_str())
    {
        return Err(invalid_config("HTTPS is required outside localhost"));
    }
    let base_path_value = defined(get("basePath"))
        .cloned()
        .unwrap_or_else(|| Value::String("/api/iam".into()));
    let base_path_text = js_string(Some(&base_path_value));
    if !valid_path(&base_path_text) {
        return Err(invalid_config("Invalid basePath"));
    }
    let Value::String(base_path) = base_path_value else {
        // `basePath.endsWith` of a non-string.
        return Err(internal_error());
    };
    if base_path.ends_with('/') {
        return Err(invalid_config("Invalid basePath"));
    }
    let default_hierarchy = default_hierarchy_value();
    let hierarchy_value = defined(get("hierarchy")).unwrap_or(&default_hierarchy);
    let max_depth_value = defined(member(Some(hierarchy_value), "maxDepth"))
        .cloned()
        .unwrap_or_else(|| Value::from(8));
    let max_depth = integer(Some(&max_depth_value), "maxDepth", 1.0, 100.0)?;
    let types = match hierarchy_value {
        Value::Object(map) => match map.get("types") {
            None | Some(Value::Null) => return Err(internal_error()),
            Some(types) => types,
        },
        // A primitive hierarchy has no `types` member: reading `.root` of undefined throws.
        _ => return Err(internal_error()),
    };
    if !js::truthy(member(Some(types), "root")) {
        return Err(invalid_config("Hierarchy must define root"));
    }
    if let Value::Object(type_map) = types {
        for (name, kind) in js::entries(type_map) {
            text256(Some(&Value::String(name.clone())), "tenant type")?;
            // `type.allowedChildren` of null throws, and anything but an object has no iterable `allowedChildren`.
            if !matches!(kind, Value::Object(_)) {
                return Err(internal_error());
            }
            for child in iterate(member(Some(kind), "allowedChildren"))? {
                let key = js_string(Some(&child));
                if !js::truthy(type_map.get(&key)) || child == Value::String("root".into()) {
                    return Err(invalid_config("Invalid allowed child type"));
                }
            }
        }
    }
    let hierarchy: HierarchyConfig =
        serde_json::from_value(hierarchy_value.clone()).map_err(|_| internal_error())?;
    let mut tenant_defaults = TenantDefaults::default();
    let defaults = get("tenantDefaults");
    let wrap = |error: IamError| invalid_config(format!("tenantDefaults: {}", error.message));
    if let Some(limits) = member(defaults, "limits") {
        tenant_defaults.limits = Some(tenant_limits(Some(limits)).map_err(wrap)?);
    }
    if let Some(policy) = member(defaults, "authPolicy") {
        tenant_defaults.auth_policy = Some(tenant_auth_policy(Some(policy)).map_err(wrap)?);
    }
    let clearances = resolve_clearance_config(get("clearances"))?;
    let regions = resolve_region_config(
        get("regions"),
        options
            .regions
            .as_ref()
            .and_then(|regions| regions.locate.clone()),
    )?;
    let rp_id = member(member(get("authentication"), "passkeys"), "rpID");
    let rp_id = js::truthy(rp_id).then(|| js_string(rp_id));
    let hosts = resolve_host_config(
        get("hosts"),
        &HostConfigContext {
            base_url: &base_url,
            regions: regions.as_ref(),
            passkey_rp_id: rp_id.as_deref(),
        },
    )?;
    let origin = url_origin(&base_url);
    let mut trusted_origins = IndexSet::new();
    trusted_origins.insert(origin.clone());
    if let Some(extra) = defined(get("trustedOrigins")) {
        for item in spread(Some(extra))? {
            if let Value::String(item) = item {
                trusted_origins.insert(item);
            }
        }
    }
    let permissions = get("permissions");
    let onboarding = get("onboarding");
    let access_requests = get("accessRequests");
    let number_or = |value: Option<&Value>, fallback: f64| {
        defined(value)
            .cloned()
            .unwrap_or_else(|| js::number(fallback))
    };
    let invitation_lifetime_ms = match defined(member(onboarding, "invitationLifetimeMs")) {
        None => 86_400_000.0,
        Some(value) => js::as_number(value).unwrap_or(f64::NAN),
    };
    let access_request_lifetime_ms = integer(
        Some(&number_or(
            member(access_requests, "lifetimeMs"),
            7.0 * 86_400_000.0,
        )),
        "accessRequests.lifetimeMs",
        60_000.0,
        365.0 * 86_400_000.0,
    )?;
    let access_request_max_duration_seconds = integer(
        Some(&number_or(
            member(access_requests, "maxDurationSeconds"),
            90.0 * 86_400.0,
        )),
        "accessRequests.maxDurationSeconds",
        60.0,
        10.0 * 365.0 * 86_400.0,
    )?;
    let webhook_timeout_ms = integer(
        Some(&number_or(
            member(get("events"), "webhookTimeoutMs"),
            10_000.0,
        )),
        "events.webhookTimeoutMs",
        1_000.0,
        120_000.0,
    )?;
    let sts_value = get("sts");
    let self_issuer = match defined(member(member(sts_value, "jwt"), "issuer")) {
        Some(issuer) => js_string(Some(issuer)),
        None => format!("{origin}{base_path}"),
    };
    let sts = resolve_sts_config(sts_value, &self_issuer)?;
    let signals = resolve_signals_config(get("signals"), &base_path)?;
    Ok(ServerConfig {
        hosts,
        regions,
        tenant_defaults,
        base_url,
        base_path,
        trusted_origins,
        hierarchy,
        max_depth,
        tenant_defined: member(permissions, "mode")
            == Some(&Value::String("tenant-defined".into())),
        strict_resource_types: member(permissions, "resourceTypes").is_some(),
        linked_onboarding: member(onboarding, "mode") == Some(&Value::String("linked".into())),
        invitation_lifetime_ms,
        access_request_lifetime_ms,
        access_request_max_duration_seconds,
        webhook_timeout_ms,
        sts,
        signals,
        clearances,
    })
}

/// `/^\/[\w/-]+$/`.
fn valid_path(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next() == Some('/')
        && value.len() > 1
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '/' || c == '-')
}

/// `resolveClearanceConfig(options)`: an object, or absent to leave the module off.
pub fn resolve_clearance_config(
    options: Option<&Value>,
) -> IamResult<Option<ResolvedClearanceConfig>> {
    let Some(value) = options else {
        return Ok(None);
    };
    let Value::Object(map) = value else {
        return Err(invalid_config("clearances must be an object"));
    };
    if is_function(options) {
        return Err(invalid_config("clearances must be an object"));
    }
    for key in js::keys(map) {
        if key != "appliesToRoot" {
            return Err(invalid_config(format!(
                "clearances.{key} is not a known setting"
            )));
        }
    }
    let applies = map.get("appliesToRoot");
    if applies.is_some() && !matches!(applies, Some(Value::Bool(_))) {
        return Err(invalid_config("clearances.appliesToRoot must be a boolean"));
    }
    Ok(Some(ResolvedClearanceConfig {
        applies_to_root: applies != Some(&Value::Bool(false)),
    }))
}

/// `typeof value === 'object'` and not null (arrays included, functions excluded).
fn object_like(value: &Value) -> bool {
    matches!(value, Value::Array(_) | Value::Object(_)) && !is_function(Some(value))
}

/// `resolveSignalsConfig(options, basePath)`.
pub fn resolve_signals_config(
    options: Option<&Value>,
    base_path: &str,
) -> IamResult<ResolvedSignalsConfig> {
    let invalid = |field: &str, detail: &str| invalid_config(format!("signals.{field} {detail}"));
    if let Some(value) = options
        && !object_like(value)
    {
        return Err(invalid_config("signals must be an object"));
    }
    let flag = |field: &str| -> IamResult<bool> {
        match member(options, field) {
            None => Ok(false),
            Some(Value::Bool(value)) => Ok(*value),
            Some(_) => Err(invalid(field, "must be a boolean")),
        }
    };
    let push_path = match defined(member(options, "pushPath")) {
        None => format!("{base_path}/signals/push"),
        Some(value) => match value {
            Value::String(path) => path.clone(),
            _ => {
                return Err(invalid(
                    "pushPath",
                    "must be an absolute path such as /api/iam/signals/push",
                ));
            }
        },
    };
    if utf16_len(&push_path) > 256
        || !valid_path(&push_path)
        || push_path.ends_with('/')
        || push_path.contains("//")
    {
        return Err(invalid(
            "pushPath",
            "must be an absolute path such as /api/iam/signals/push",
        ));
    }
    Ok(ResolvedSignalsConfig {
        allow_private_networks: flag("allowPrivateNetworks")?,
        allow_insecure_localhost: flag("allowInsecureLocalhost")?,
        push_path,
    })
}

/// `resolveStsConfig(options, selfIssuer)`: validates `options.sts` (except `jwt`) and applies the defaults.
pub fn resolve_sts_config(
    options: Option<&Value>,
    self_issuer: &str,
) -> IamResult<ResolvedStsConfig> {
    let invalid = |field: &str, detail: &str| invalid_config(format!("sts.{field} {detail}"));
    if let Some(value) = options
        && !object_like(value)
    {
        return Err(invalid("options", "must be an object"));
    }
    let number = |value: Option<&Value>, fallback: f64, field: &str, min: f64, max: f64| {
        let value = defined(value)
            .cloned()
            .unwrap_or_else(|| js::number(fallback));
        integer(Some(&value), field, min, max).map_err(|_| {
            invalid(
                field,
                &format!(
                    "must be an integer from {} to {}",
                    number_to_string(min),
                    number_to_string(max)
                ),
            )
        })
    };
    let flag = |value: Option<&Value>, field: &str| -> IamResult<bool> {
        match value {
            None => Ok(false),
            Some(Value::Bool(value)) => Ok(*value),
            Some(_) => Err(invalid(field, "must be a boolean")),
        }
    };
    let web = member(options, "webIdentity");
    if let Some(value) = web
        && !object_like(value)
    {
        return Err(invalid("webIdentity", "must be an object"));
    }
    let fetch_json = member(web, "fetchJson");
    if fetch_json.is_some() && type_name(fetch_json) != "function" {
        return Err(invalid("webIdentity.fetchJson", "must be a function"));
    }
    let allow_insecure_localhost = flag(
        member(web, "allowInsecureLocalhost"),
        "webIdentity.allowInsecureLocalhost",
    )?;
    let mut allowed_issuers = None;
    if let Some(list) = member(web, "allowedIssuers") {
        let Value::Array(items) = list else {
            return Err(invalid(
                "webIdentity.allowedIssuers",
                "must be an array of at most 100 issuers",
            ));
        };
        if items.len() > 100 {
            return Err(invalid(
                "webIdentity.allowedIssuers",
                "must be an array of at most 100 issuers",
            ));
        }
        let rules = IssuerRules {
            allow_insecure_localhost,
            self_issuer: Some(self_issuer),
            allowed_issuers: None,
        };
        let mut issuers = Vec::new();
        for item in items {
            match web_identity_issuer(Some(item), &rules) {
                Ok(issuer) => issuers.push(issuer),
                Err(error) => {
                    return Err(invalid(
                        "webIdentity.allowedIssuers",
                        &format!("contains an invalid issuer: {}", error.message),
                    ));
                }
            }
        }
        allowed_issuers = Some(js::unique(issuers));
    }
    Ok(ResolvedStsConfig {
        max_role_session_seconds: number(
            member(options, "maxRoleSessionSeconds"),
            3600.0,
            "maxRoleSessionSeconds",
            900.0,
            43200.0,
        )?,
        max_session_token_seconds: number(
            member(options, "maxSessionTokenSeconds"),
            43200.0,
            "maxSessionTokenSeconds",
            900.0,
            129_600.0,
        )?,
        max_session_tokens_per_identity: number(
            member(options, "maxSessionTokensPerIdentity"),
            50.0,
            "maxSessionTokensPerIdentity",
            1.0,
            1000.0,
        )?,
        web_identity: ResolvedWebIdentityConfig {
            enabled: flag(member(web, "enabled"), "webIdentity.enabled")?,
            allowed_issuers,
            jwks_cache_seconds: number(
                member(web, "jwksCacheSeconds"),
                600.0,
                "webIdentity.jwksCacheSeconds",
                60.0,
                3600.0,
            )?,
            fetch_timeout_ms: number(
                member(web, "fetchTimeoutMs"),
                5000.0,
                "webIdentity.fetchTimeoutMs",
                500.0,
                10_000.0,
            )?,
            max_jwks_bytes: number(
                member(web, "maxJwksBytes"),
                65536.0,
                "webIdentity.maxJwksBytes",
                1024.0,
                1_048_576.0,
            )?,
            max_exchanges_per_window: number(
                member(web, "maxExchangesPerWindow"),
                600.0,
                "webIdentity.maxExchangesPerWindow",
                1.0,
                100_000.0,
            )?,
            max_sessions_per_trust: number(
                member(web, "maxSessionsPerTrust"),
                1000.0,
                "webIdentity.maxSessionsPerTrust",
                1.0,
                100_000.0,
            )?,
            allow_private_networks: flag(
                member(web, "allowPrivateNetworks"),
                "webIdentity.allowPrivateNetworks",
            )?,
            allow_insecure_localhost,
        },
    })
}

/// Whether a value counts as an options object in the model (`is_object`), re-exported for the module validators.
pub fn is_options_object(value: Option<&Value>) -> bool {
    is_object(value)
}
