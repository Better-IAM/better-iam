//! Options, results, and the records private to the authentication service (`types.ts`).
//!
//! Record types serialize with the TypeScript member names and keep members they do not declare in `extra`, so a
//! record written by the TypeScript service survives a Rust read-modify-write unchanged.

use std::ops::Deref;
use std::sync::Arc;

use async_trait::async_trait;
use better_iam_core::{
    IamError, IamResult, IamStore, Identity, Record, Session, SessionClientInfo, SignInRecord,
    Tenant,
};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::password_policy::PasswordPolicyOptions;
use crate::util::to_record;

/// A queued email, SMS, or webhook delivery handed to a delivery callback (`DeliveryMessage`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryMessage {
    pub id: String,
    pub tenant_id: String,
    pub to: String,
    pub template: String,
    pub payload: Map<String, Value>,
    /// The organization's sign-in URL (its own subdomain, custom hostname, or regional address), added by the server
    /// when organization addresses or regions are configured, so the links in the message can point there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in_url: Option<String>,
}

impl DeliveryMessage {
    /// A string member of the payload.
    pub fn payload_str(&self, key: &str) -> Option<&str> {
        self.payload.get(key).and_then(Value::as_str)
    }
}

/// What a delivery callback failed with. The outbox records `"{name}: {message}"` (an `Error` in TypeScript) or the
/// bare text (anything else that was thrown), cut to 256 characters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.recorded())]
pub struct DeliveryError {
    pub name: Option<String>,
    pub message: String,
}

impl DeliveryError {
    /// An `Error` named `name` (`Error`, `TypeError`, ...).
    pub fn new(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            message: message.into(),
        }
    }

    /// A plain `Error`.
    pub fn error(message: impl Into<String>) -> Self {
        Self::new("Error", message)
    }

    /// A thrown value that is not an `Error` (`String(value)`).
    pub fn thrown(value: impl Into<String>) -> Self {
        Self {
            name: None,
            message: value.into(),
        }
    }

    /// The text the outbox records before truncation.
    pub fn recorded(&self) -> String {
        match &self.name {
            Some(name) => format!("{name}: {}", self.message),
            None => self.message.clone(),
        }
    }
}

impl From<IamError> for DeliveryError {
    fn from(error: IamError) -> Self {
        Self::new("IamError", error.message)
    }
}

/// A delivery callback (`sendEmail`, `sendSms`, `deliverWebhook`). Callbacks must deduplicate by `message.id`.
pub type DeliveryFn =
    Arc<dyn Fn(DeliveryMessage) -> BoxFuture<'static, Result<(), DeliveryError>> + Send + Sync>;

/// Wraps an async closure as a [`DeliveryFn`].
pub fn delivery_fn<F, Fut>(callback: F) -> DeliveryFn
where
    F: Fn(DeliveryMessage) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), DeliveryError>> + Send + 'static,
{
    Arc::new(move |message| Box::pin(callback(message)))
}

/// `RateLimiter.consume` input.
#[derive(Debug, Clone, PartialEq)]
pub struct ConsumeInput {
    pub key: String,
    pub tenant_id: String,
    pub limit: f64,
    pub window_ms: f64,
    pub now: f64,
}

/// `RateLimiter.reset` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetInput {
    pub key: String,
    pub tenant_id: String,
}

/// A durable attempt counter (`RateLimiter`). The default limiter stores counters in the IAM database; supply one
/// backed by Redis or similar for multi-instance deployments.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// True when the attempt is permitted. Implementations must count the attempt even when the caller later fails.
    async fn consume(&self, input: ConsumeInput) -> IamResult<bool>;
    /// Whether [`RateLimiter::reset`] is implemented (`reset` is optional in TypeScript).
    fn supports_reset(&self) -> bool {
        false
    }
    /// Clears one counter so an administrator can unlock an account.
    async fn reset(&self, _input: ResetInput) -> IamResult<()> {
        Ok(())
    }
}

/// `RateLimitOptions`.
#[derive(Clone, Default)]
pub struct RateLimitOptions {
    /// Attempts per window for ordinary flows such as password sign-in (default 10).
    pub attempts: Option<f64>,
    /// Attempts per window for sensitive flows such as MFA, recovery, and delivery requests (default 5).
    pub sensitive_attempts: Option<f64>,
    /// Rolling window length (default 15 minutes).
    pub window_ms: Option<f64>,
    /// Attempts per window from one client IP across every authentication flow of a tenant (0, the default,
    /// disables it).
    pub ip_attempts: Option<f64>,
    pub limiter: Option<Arc<dyn RateLimiter>>,
}

/// `requireMfa(tenant, identity)`.
pub type RequireMfaFn =
    Arc<dyn Fn(Tenant, Identity) -> BoxFuture<'static, IamResult<bool>> + Send + Sync>;
/// `onAudit(tx, event)`: runs inside the transaction that records an authentication audit event.
pub type OnAuditFn =
    Arc<dyn Fn(Arc<dyn IamStore>, Record) -> BoxFuture<'static, IamResult<()>> + Send + Sync>;
/// `now()`: epoch milliseconds.
pub type NowFn = Arc<dyn Fn() -> f64 + Send + Sync>;

/// `passkeys` option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyOptions {
    pub rp_id: String,
    pub rp_name: Option<String>,
}

/// `AuthOptions`. Numbers are JavaScript numbers (`f64`) so the same validation applies.
#[derive(Clone)]
pub struct AuthOptions {
    pub store: Arc<dyn IamStore>,
    pub secret: String,
    /// Secrets being rotated out: values sealed with them and challenge links issued under them keep working until
    /// re-sealed or expired. New values always use `secret`.
    pub previous_secrets: Option<Vec<String>>,
    pub base_url: String,
    pub trusted_origins: Option<Vec<String>>,
    pub app_name: Option<String>,
    pub sign_up_enabled: Option<bool>,
    pub require_email_verification: Option<bool>,
    pub email_password: Option<bool>,
    pub passwordless_email: Option<bool>,
    pub passwordless_sms: Option<bool>,
    pub send_email: Option<DeliveryFn>,
    pub send_sms: Option<DeliveryFn>,
    /// Delivers webhook outbox messages; `to` is the webhook ID and the payload carries `url` and the JSON `body`.
    pub deliver_webhook: Option<DeliveryFn>,
    /// Outbox messages are abandoned after this many failed attempts (default 25).
    pub max_delivery_attempts: Option<f64>,
    pub session_lifetime_ms: Option<f64>,
    pub session_idle_timeout_ms: Option<f64>,
    pub recent_authentication_ms: Option<f64>,
    /// How long "remember this device" lets a browser skip MFA (default 30 days, at most 365; 0 disables it).
    pub trusted_device_lifetime_ms: Option<f64>,
    /// Queue a `new-sign-in` email when a session starts from a client none of the person's live sessions or
    /// remembered devices has used.
    pub sign_in_notifications: Option<bool>,
    /// Let people without an authenticator satisfy an MFA requirement with an emailed one-time code.
    pub mfa_email_codes: Option<bool>,
    /// Email a `sign-in-failures` alert once this many attempts have failed since the last sign-in (0 disables).
    pub failed_sign_in_alerts: Option<f64>,
    pub rate_limits: Option<RateLimitOptions>,
    pub require_mfa: Option<RequireMfaFn>,
    pub passkeys: Option<PasskeyOptions>,
    pub on_audit: Option<OnAuditFn>,
    /// Inject time for deterministic integration tests.
    pub now: Option<NowFn>,
    /// Deployment-wide password screening.
    pub password_policy: Option<PasswordPolicyOptions>,
}

impl AuthOptions {
    /// The required options; everything else takes its default.
    pub fn new(
        store: Arc<dyn IamStore>,
        secret: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            store,
            secret: secret.into(),
            previous_secrets: None,
            base_url: base_url.into(),
            trusted_origins: None,
            app_name: None,
            sign_up_enabled: None,
            require_email_verification: None,
            email_password: None,
            passwordless_email: None,
            passwordless_sms: None,
            send_email: None,
            send_sms: None,
            deliver_webhook: None,
            max_delivery_attempts: None,
            session_lifetime_ms: None,
            session_idle_timeout_ms: None,
            recent_authentication_ms: None,
            trusted_device_lifetime_ms: None,
            sign_in_notifications: None,
            mfa_email_codes: None,
            failed_sign_in_alerts: None,
            rate_limits: None,
            require_mfa: None,
            passkeys: None,
            on_audit: None,
            now: None,
            password_policy: None,
        }
    }
}

/// An identity without its password hash (`SafeIdentity`).
#[derive(Debug, Clone, PartialEq)]
pub struct SafeIdentity(pub(crate) Identity);

impl SafeIdentity {
    pub fn new(identity: &Identity) -> Self {
        let mut safe = identity.clone();
        safe.password_hash = None;
        Self(safe)
    }

    pub fn into_inner(self) -> Identity {
        self.0
    }
}

impl Deref for SafeIdentity {
    type Target = Identity;
    fn deref(&self) -> &Identity {
        &self.0
    }
}

impl Serialize for SafeIdentity {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = to_record(&self.0);
        map.remove("passwordHash");
        map.serialize(serializer)
    }
}

/// A session without its secret-derived fields, `tokenHash` and `uniqueKey` (`SafeSession`).
#[derive(Debug, Clone, PartialEq)]
pub struct SafeSession(pub(crate) Session);

impl SafeSession {
    pub fn new(session: &Session) -> Self {
        let mut safe = session.clone();
        safe.token_hash = String::new();
        safe.unique_key = None;
        Self(safe)
    }

    pub fn into_inner(self) -> Session {
        self.0
    }
}

impl Deref for SafeSession {
    type Target = Session;
    fn deref(&self) -> &Session {
        &self.0
    }
}

impl Serialize for SafeSession {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = to_record(&self.0);
        map.remove("tokenHash");
        map.remove("uniqueKey");
        map.serialize(serializer)
    }
}

/// `SessionResult`: the bearer token, returned once (only its hash is stored), and the new session.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SessionResult {
    pub token: String,
    pub session: SafeSession,
}

/// `MfaRequired`: the first factor passed; a second factor must complete the sign-in.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaRequired {
    /// Always true.
    pub mfa_required: bool,
    pub challenge: String,
    /// No second factor is set up: enroll an authenticator or, when offered, use an emailed code.
    pub enrollment_required: bool,
    /// Whether an authenticator app is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_enrolled: Option<bool>,
    /// `requestMfaCode` may email a one-time code for this challenge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_code_available: Option<bool>,
    /// A registered passkey may satisfy this challenge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passkey_available: Option<bool>,
}

/// `SignInResult = SessionResult | MfaRequired`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum SignInResult {
    Session(SessionResult),
    MfaRequired(MfaRequired),
}

impl SignInResult {
    /// The session, when no second factor was needed.
    pub fn session(&self) -> Option<&SessionResult> {
        match self {
            Self::Session(session) => Some(session),
            Self::MfaRequired(_) => None,
        }
    }

    /// The MFA challenge, when a second factor is needed.
    pub fn mfa(&self) -> Option<&MfaRequired> {
        match self {
            Self::MfaRequired(mfa) => Some(mfa),
            Self::Session(_) => None,
        }
    }
}

/// `MfaCredential = CredentialInput | { tenantId, challenge }`.
#[derive(Debug, Clone, PartialEq)]
pub enum MfaCredential {
    Credential(better_iam_core::CredentialInput),
    Challenge {
        tenant_id: String,
        challenge: String,
    },
}

/// A remembered browser that may satisfy the MFA requirement until it expires or is revoked (`TrustedDevice`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedDevice {
    pub id: String,
    pub tenant_id: String,
    pub identity_id: String,
    pub token_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    pub created_at: f64,
    pub expires_at: f64,
    pub last_used_at: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<SessionClientInfo>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A trusted device without `tokenHash` and `uniqueKey` (`SafeTrustedDevice`).
#[derive(Debug, Clone, PartialEq)]
pub struct SafeTrustedDevice(pub(crate) TrustedDevice);

impl SafeTrustedDevice {
    pub fn new(device: &TrustedDevice) -> Self {
        let mut safe = device.clone();
        safe.token_hash = String::new();
        safe.unique_key = None;
        Self(safe)
    }
}

impl Deref for SafeTrustedDevice {
    type Target = TrustedDevice;
    fn deref(&self) -> &TrustedDevice {
        &self.0
    }
}

impl Serialize for SafeTrustedDevice {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = to_record(&self.0);
        map.remove("tokenHash");
        map.remove("uniqueKey");
        map.serialize(serializer)
    }
}

/// A session plus, when the caller asked to remember the device and the policy allows it, the device token
/// (`MfaSessionResult`).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaSessionResult {
    pub token: String,
    pub session: SafeSession,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_expires_at: Option<f64>,
}

impl MfaSessionResult {
    pub fn from_session(session: SessionResult, device: Option<RememberedDevice>) -> Self {
        let (device_token, device_expires_at) = match device {
            Some(device) => (Some(device.device_token), Some(device.device_expires_at)),
            None => (None, None),
        };
        Self {
            token: session.token,
            session: session.session,
            device_token,
            device_expires_at,
        }
    }
}

/// What `rememberDevice` returns.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RememberedDevice {
    pub device_token: String,
    pub device_expires_at: f64,
}

/// Per-person sign-in bookkeeping (`authSignIns`, one record per identity, `id` = identity ID) (`SignInLedger`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInLedger {
    pub id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    pub identity_id: String,
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

impl SignInLedger {
    /// The public part of a sign-in ledger, as stamped on a new session (`signInSummary`).
    pub fn summary(&self) -> SignInRecord {
        SignInRecord {
            failed_attempts: self.failed_attempts,
            last_at: self.last_at,
            last_client: self.last_client.clone(),
            last_failed_at: self.last_failed_at,
            last_failed_client: self.last_failed_client.clone(),
            extra: Map::new(),
        }
    }
}

/// What a failed attempt presented wrongly; recorded on `auth:signin:fail` events (`SignInFailureReason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInFailureReason {
    Password,
    Mfa,
    RecoveryCode,
}

impl SignInFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Mfa => "mfa",
            Self::RecoveryCode => "recovery-code",
        }
    }
}

/// A network refused across a tenant's sign-in flows and live sessions (`authBlocks`) (`NetworkBlock`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkBlock {
    pub id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    pub network: String,
    pub reason: String,
    pub created_at: f64,
    pub created_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<bool>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A single-use, purpose-bound challenge (`Challenge`, collection `authChallenges`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    pub id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    pub identity_id: String,
    pub purpose: String,
    pub token_hash: String,
    pub payload: Map<String, Value>,
    pub expires_at: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Challenge {
    /// A string member of the payload (`challenge.payload[key]`).
    pub fn payload_str(&self, key: &str) -> Option<&str> {
        self.payload.get(key).and_then(Value::as_str)
    }
}

/// An authenticator enrollment (`MfaRecord`, collection `authMfa`, `id` = identity ID).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaRecord {
    pub id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    pub identity_id: String,
    pub encrypted_secret: String,
    pub recovery_hashes: Vec<String>,
    pub enabled: bool,
    pub last_used_step: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_expires_at: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_credential: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A registered WebAuthn credential (`PasskeyRecord`, collection `authPasskeys`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRecord {
    pub id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    pub identity_id: String,
    pub credential_id: String,
    pub public_key: String,
    pub counter: f64,
    /// The transports the browser reported at registration (`AuthenticatorTransportFuture[]`), kept as given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transports: Option<Value>,
    /// A label the person chose or the default derived from the authenticator's transports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
    /// Last successful sign-in or MFA assertion with this passkey.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    /// `singleDevice` or `multiDevice` (from the registration).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backed_up: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aaguid: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What `listPasskeys` returns: everything but the key material (`SafePasskey`).
#[derive(Debug, Clone, PartialEq)]
pub struct SafePasskey(pub(crate) PasskeyRecord);

impl Deref for SafePasskey {
    type Target = PasskeyRecord;
    fn deref(&self) -> &PasskeyRecord {
        &self.0
    }
}

impl Serialize for SafePasskey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = to_record(&self.0);
        map.remove("publicKey");
        map.remove("counter");
        map.remove("uniqueKey");
        map.serialize(serializer)
    }
}

/// A rate-limit counter (`RateRecord`, collection `authRateLimits`, `id` = the hashed key).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateRecord {
    pub id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    pub count: f64,
    pub reset_at: f64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A previous password hash, kept (newest 24 per identity) so `passwordHistory` can refuse reuse
/// (`PasswordHistoryRecord`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistoryRecord {
    pub id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    pub identity_id: String,
    pub hash: String,
    pub created_at: f64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
