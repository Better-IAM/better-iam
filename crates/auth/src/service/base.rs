//! Configuration, storage primitives, and the session core shared by every authentication feature
//! (`service/base.ts`, class `AuthBase`).

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex};

use better_iam_core::boxed;
use better_iam_core::{
    AuthMethod, AuthenticatedPrincipal, CredentialInput, Filter, IamError, IamResult, IamStoreExt,
    Identity, IdentityKind, IdentityStatus, OutboxKind, Session, SessionClientInfo, SessionKind,
    Tenant, TenantStatus, append_audit_event, ip_counter_key, ip_matches, is_ip_range, js,
    task_scope,
};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use tokio::sync::OnceCell;

use super::{AuthService, AuthState};
use crate::crypto::{
    CredentialTokenType, hash_token, new_credential_token, new_id, new_token,
    parse_credential_token,
};
use crate::outbox::{
    DispatchResult, EnqueueInput, OutboxContext, dispatch_outbox, enqueue_delivery,
};
use crate::password_policy::{
    PasswordCheckContext, PasswordIdentity, PersonalInfo, assert_password_rules,
};
use crate::passwords;
use crate::rate_limit::resolve_rate_limits;
use crate::types::{
    AuthOptions, Challenge, ConsumeInput, DeliveryFn, MfaRecord, MfaRequired, NetworkBlock,
    PasswordHistoryRecord, RememberedDevice, ResetInput, SessionResult, SignInFailureReason,
    SignInLedger, SignInResult, TrustedDevice,
};
use crate::util::{Store, by_number_then_id, find, from_record, get, hex, insert, num, put};
use crate::validation::{display_name, email, password, public_session, text, text_str};

/// Previous password hashes kept per identity; `passwordHistory` policies may use up to this many.
const PASSWORD_HISTORY_LIMIT: usize = 24;
/// How long a tenant's network block list is reused before storage is read again.
const BLOCK_CACHE_MS: f64 = 5_000.0;
const DAY_MS: f64 = 24.0 * 60.0 * 60_000.0;

/// The address a request arrived on, as the HTTP layer resolved it (`RequestHost`): `origin` is the request's
/// trusted `Origin` (an organization's own address counts), and `tenant_id` the organization that address belongs
/// to, if any.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestHost {
    pub origin: Option<String>,
    pub tenant_id: Option<String>,
}

/// The rate-limit tier of an attempt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RateTier {
    #[default]
    Default,
    Sensitive,
    /// Anonymous, credential-free starts (passkey discovery): ten times the ordinary allowance.
    Generous,
}

/// `limitAttempt` options.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct LimitAttemptOptions {
    pub tier: Option<RateTier>,
    pub limit: Option<f64>,
    /// With `limit`: false skips the network steps when the same attempt already ran them.
    pub count_client: Option<bool>,
}

/// What `resetRateLimits` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ResetRateLimitsResult {
    pub supported: bool,
    pub cleared: usize,
}

/// A tenant's session limits (`sessionLimits`).
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionLimits {
    pub lifetime_ms: f64,
    pub idle_timeout_ms: f64,
}

/// `createIdentity` input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateIdentityInput {
    pub tenant_id: String,
    pub email: String,
    pub name: String,
    pub password: Option<String>,
    pub owner: Option<bool>,
    pub root_admin: Option<bool>,
    pub email_verified: Option<bool>,
}

/// `createIdentity` input as untrusted JSON values (`password` absent means no password).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CreateIdentityRaw<'a> {
    pub tenant_id: Option<&'a Value>,
    pub email: Option<&'a Value>,
    pub name: Option<&'a Value>,
    pub password: Option<&'a Value>,
    pub owner: bool,
    pub root_admin: bool,
    pub email_verified: bool,
}

/// `issueSession` options.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IssueSessionOptions {
    pub mfa: Option<bool>,
    pub authenticated_at: Option<f64>,
    pub method: Option<AuthMethod>,
    pub trusted_device_id: Option<String>,
    /// When the second factor behind `mfa` was verified, for sessions that carry an earlier ceremony forward.
    pub mfa_authenticated_at: Option<f64>,
}

/// A bound session presented from another network; `authenticate` records it after the refusal rolled back.
#[derive(Debug, Clone)]
pub(crate) struct SessionNetworkMismatch {
    pub session: Session,
}

pub(crate) type MismatchSink = Arc<Mutex<Option<SessionNetworkMismatch>>>;

fn config(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_CONFIG", message)
}

fn utf16(value: &str) -> usize {
    js::utf16_len(value)
}

/// `new URL(value)` for configuration values: an INVALID_CONFIG error (a TypeError in TypeScript) when it fails.
fn parse_url(value: &str) -> IamResult<url::Url> {
    url::Url::parse(value).map_err(|_| config("Invalid URL"))
}

/// `url.hostname` as WHATWG serializes it (IPv6 in brackets).
pub(crate) fn url_hostname(url: &url::Url) -> String {
    match url.host() {
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        Some(url::Host::Ipv4(address)) => address.to_string(),
        Some(url::Host::Domain(domain)) => domain.to_owned(),
        None => String::new(),
    }
}

/// The `Headers` view of a credential: names case-insensitive, repeated values joined with ", ".
pub(crate) fn header(input: &CredentialInput, name: &str) -> Option<String> {
    let headers = input.headers.as_ref()?;
    let values: Vec<&str> = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

fn token_shape(token: &str) -> bool {
    let length = token.len();
    (32..=512).contains(&length)
        && token
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// `Math.min(a, b ?? Infinity)`.
fn min_opt(value: f64, other: Option<f64>) -> f64 {
    match other {
        Some(other) => js_min(value, other),
        None => value,
    }
}

/// `Math.min`: NaN when either is NaN.
fn js_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

/// The client details of a session for fingerprinting.
fn fingerprint(client: Option<&SessionClientInfo>) -> Option<String> {
    let client = client?;
    let user_agent = client
        .user_agent
        .as_deref()
        .filter(|value| !value.is_empty());
    let ip = client.ip.as_deref().filter(|value| !value.is_empty());
    if user_agent.is_none() && ip.is_none() {
        return None;
    }
    Some(format!(
        "{}|{}",
        client.user_agent.clone().unwrap_or_default(),
        client.ip.clone().unwrap_or_default()
    ))
}

/// `client && (client.ip || client.userAgent || client.label)`.
fn client_has_details(client: &SessionClientInfo) -> bool {
    [&client.ip, &client.user_agent, &client.label]
        .iter()
        .any(|value| value.as_deref().is_some_and(|value| !value.is_empty()))
}

impl AuthService {
    /// `new AuthService(options)`: validates the configuration.
    pub fn new(options: AuthOptions) -> IamResult<Self> {
        if utf16(&options.secret) < 32 {
            return Err(config("secret must have at least 32 characters"));
        }
        let previous = options.previous_secrets.clone().unwrap_or_default();
        let distinct: HashSet<&String> = previous.iter().collect();
        if previous.len() > 5
            || previous
                .iter()
                .any(|value| utf16(value) < 32 || *value == options.secret)
            || distinct.len() != previous.len()
        {
            return Err(config(
                "previousSecrets must list at most 5 distinct secrets of at least 32 characters, other than secret",
            ));
        }
        let mut secrets = vec![options.secret.clone()];
        secrets.extend(previous);
        let limits = resolve_rate_limits(options.rate_limits.as_ref(), options.store.clone())?;
        let max_attempts = options.max_delivery_attempts.unwrap_or(25.0);
        if !js::is_safe_integer(max_attempts) || !(1.0..=1_000.0).contains(&max_attempts) {
            return Err(config(
                "maxDeliveryAttempts must be an integer between 1 and 1000",
            ));
        }
        let url = parse_url(&options.base_url)?;
        let cookie_name = if url.scheme() == "https" {
            "__Host-better-iam.session"
        } else {
            "better-iam.session"
        }
        .to_owned();
        let hostname = url_hostname(&url);
        if !["http", "https"].contains(&url.scheme())
            || (url.scheme() != "https"
                && !["localhost", "127.0.0.1", "[::1]"].contains(&hostname.as_str()))
        {
            return Err(config(
                "baseURL must use HTTPS, except loopback development",
            ));
        }
        let require_email_verification = options
            .require_email_verification
            .unwrap_or(options.sign_up_enabled.unwrap_or(false));
        if (require_email_verification || options.passwordless_email == Some(true))
            && options.send_email.is_none()
        {
            return Err(config("Enabled email features require sendEmail"));
        }
        if options.passwordless_sms == Some(true) && options.send_sms.is_none() {
            return Err(config("Enabled SMS features require sendSms"));
        }
        let mut origins = vec![url.origin().ascii_serialization()];
        for origin in options.trusted_origins.clone().unwrap_or_default() {
            if parse_url(&origin)?.origin().ascii_serialization() != origin {
                return Err(config("Trusted origins must be exact origins"));
            }
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        }
        let now = options.now.clone().unwrap_or_else(|| Arc::new(js::now_ms));
        let session_lifetime = options.session_lifetime_ms.unwrap_or(7.0 * DAY_MS);
        let idle_lifetime = options
            .session_idle_timeout_ms
            .unwrap_or_else(|| js_min(session_lifetime, DAY_MS));
        let recent_lifetime = options.recent_authentication_ms.unwrap_or(5.0 * 60_000.0);
        if !js::is_safe_integer(session_lifetime)
            || session_lifetime < 60_000.0
            || session_lifetime > 30.0 * DAY_MS
        {
            return Err(config(
                "Session lifetime must be between one minute and thirty days",
            ));
        }
        if !js::is_safe_integer(idle_lifetime)
            || idle_lifetime < 60_000.0
            || idle_lifetime > session_lifetime
        {
            return Err(config(
                "Session idle timeout must be between one minute and the absolute session lifetime",
            ));
        }
        if !js::is_safe_integer(recent_lifetime)
            || recent_lifetime < 1_000.0
            || recent_lifetime > 15.0 * 60_000.0
        {
            return Err(config(
                "Recent authentication lifetime must be between one second and fifteen minutes",
            ));
        }
        let device_lifetime = options.trusted_device_lifetime_ms.unwrap_or(30.0 * DAY_MS);
        if !js::is_safe_integer(device_lifetime)
            || device_lifetime < 0.0
            || (device_lifetime > 0.0 && device_lifetime < 60_000.0)
            || device_lifetime > 365.0 * DAY_MS
        {
            return Err(config(
                "Trusted device lifetime must be 0 (disabled) or between one minute and one year",
            ));
        }
        let failed_alert_threshold = options.failed_sign_in_alerts.unwrap_or(0.0);
        if !js::is_safe_integer(failed_alert_threshold)
            || !(0.0..=1_000.0).contains(&failed_alert_threshold)
        {
            return Err(config(
                "failedSignInAlerts must be 0 (disabled) or an integer between 1 and 1000",
            ));
        }
        if failed_alert_threshold > 0.0 && options.send_email.is_none() {
            return Err(config("failedSignInAlerts requires sendEmail"));
        }
        let app_name = options
            .app_name
            .clone()
            .unwrap_or_else(|| "Better IAM".to_owned());
        if let Some(passkeys) = &options.passkeys {
            let mut matching = true;
            for origin in &origins {
                let hostname = url_hostname(&parse_url(origin)?);
                if hostname != passkeys.rp_id
                    && !hostname.ends_with(&format!(".{}", passkeys.rp_id))
                {
                    matching = false;
                }
            }
            if passkeys.rp_id.is_empty() || !matching {
                return Err(config("Passkey RP ID must match each trusted origin"));
            }
        }
        let deliver = (
            options.send_email.clone(),
            options.send_sms.clone(),
            options.deliver_webhook.clone(),
        );
        let outbox = OutboxContext {
            store: options.store.clone(),
            secret: options.secret.clone(),
            secrets: Some(secrets.clone()),
            now: now.clone(),
            max_attempts,
            deliverer: Arc::new(move |kind| match kind {
                OutboxKind::Email => deliver.0.clone(),
                OutboxKind::Sms => deliver.1.clone(),
                OutboxKind::Webhook => deliver.2.clone(),
            }),
        };
        let service = Self {
            state: Arc::new(AuthState {
                options,
                now,
                origins,
                session_lifetime,
                idle_lifetime,
                cookie_name,
                recent_lifetime,
                device_lifetime,
                failed_alert_threshold,
                app_name,
                require_email_verification,
                dummy_password_hash: OnceCell::new(),
                limits,
                outbox,
                client_scope: task_scope::new_key(),
                host_scope: task_scope::new_key(),
                block_cache: Mutex::new(HashMap::new()),
                bookkeeping: Mutex::new(Vec::new()),
                secrets,
            }),
        };
        // The decoy hash unknown accounts are checked against is computed up front, as the TypeScript constructor
        // starts it, so the first sign-in does not pay for it inside its transaction.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let warm = service.clone();
            handle.spawn(async move {
                let _ = warm.dummy_hash().await;
            });
        }
        Ok(service)
    }

    /// The current time (`this.now()`).
    pub fn now(&self) -> f64 {
        (self.state.now)()
    }

    /// The session cookie name (`__Host-better-iam.session` on HTTPS deployments).
    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    /// The deployment's trusted origins.
    pub fn origins(&self) -> &[String] {
        &self.origins
    }

    /// The application name used in messages and authenticator labels.
    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    /// Whether sign-in requires a verified email.
    pub fn requires_email_verification(&self) -> bool {
        self.require_email_verification
    }

    /// The rate-limit window, which `RATE_LIMITED` refusals carry as `retryAfterMs`.
    pub fn rate_limit_window_ms(&self) -> f64 {
        self.limits.window_ms
    }

    pub(crate) fn store(&self) -> &Store {
        &self.options.store
    }

    pub(crate) async fn dummy_hash(&self) -> IamResult<String> {
        self.dummy_password_hash
            .get_or_try_init(|| async { passwords::hash(&new_token()).await })
            .await
            .cloned()
    }

    /// `withClient(client, fn)`: runs `future` so that every session it issues records `client` (IP, user agent,
    /// label); values are trimmed and bounded.
    pub async fn with_client<F: Future>(
        &self,
        client: Option<SessionClientInfo>,
        future: F,
    ) -> F::Output {
        let Some(client) = client else {
            return future.await;
        };
        let clean = |value: &Option<String>, max: usize| -> Option<String> {
            let value = value.as_deref()?;
            if js::trim(value).is_empty() {
                return None;
            }
            let stripped: String = value
                .chars()
                .filter(|c| !matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'))
                .collect();
            let trimmed = crate::outbox::truncate_utf16(js::trim(&stripped), max);
            (!trimmed.is_empty()).then_some(trimmed)
        };
        let info = SessionClientInfo {
            ip: clean(&client.ip, 64),
            user_agent: clean(&client.user_agent, 512),
            label: clean(&client.label, 128),
            extra: Map::new(),
        };
        if info.ip.is_none() && info.user_agent.is_none() && info.label.is_none() {
            return future.await;
        }
        task_scope::run(self.client_scope, Arc::new(info), future).await
    }

    /// `currentClient()`: the client details of the current request (set by `with_client`), if any.
    pub fn current_client(&self) -> Option<SessionClientInfo> {
        task_scope::current::<SessionClientInfo>(self.client_scope).map(|client| (*client).clone())
    }

    fn client_ip(&self) -> Option<String> {
        self.current_client().and_then(|client| client.ip)
    }

    /// `withRequestHost(host, fn)`: runs `future` for a request that arrived on `host`: credentials of another
    /// organization are refused on an organization's own address (`HOST_MISMATCH`), and passkey ceremonies accept
    /// that address's origin.
    pub async fn with_request_host<F: Future>(
        &self,
        host: Option<RequestHost>,
        future: F,
    ) -> F::Output {
        match host {
            Some(host)
                if host
                    .origin
                    .as_deref()
                    .is_some_and(|origin| !origin.is_empty())
                    || host
                        .tenant_id
                        .as_deref()
                        .is_some_and(|tenant| !tenant.is_empty()) =>
            {
                task_scope::run(self.host_scope, Arc::new(host), future).await
            }
            _ => future.await,
        }
    }

    /// `requestHost()`: the address of the current request (set by `with_request_host`), if any.
    pub fn request_host(&self) -> Option<RequestHost> {
        task_scope::current::<RequestHost>(self.host_scope).map(|host| (*host).clone())
    }

    /// `assertRequestHost(tenantId)`: refuses a credential of another organization on an organization's own address.
    pub fn assert_request_host(&self, tenant_id: &str) -> IamResult<()> {
        if let Some(pinned) = self
            .request_host()
            .and_then(|host| host.tenant_id)
            .filter(|t| !t.is_empty())
            && pinned != tenant_id
        {
            return Err(IamError::with_status(
                "HOST_MISMATCH",
                "This address belongs to another organization",
                403,
            ));
        }
        Ok(())
    }

    /// Origins a WebAuthn response may come from: the deployment's, plus the current request's organization address.
    pub(crate) fn expected_origins(&self) -> Vec<String> {
        match self
            .request_host()
            .and_then(|host| host.origin)
            .filter(|origin| !origin.is_empty())
        {
            Some(origin) if !self.origins.contains(&origin) => {
                let mut origins = self.origins.clone();
                origins.push(origin);
                origins
            }
            _ => self.origins.clone(),
        }
    }

    /// `assertTenantActive(tx, tenantId)`: validates every ancestor; tenant identifiers are never inferred from email.
    pub async fn assert_tenant_active(&self, tx: &Store, tenant_id: &str) -> IamResult<()> {
        let mut current = Some(text_str(tenant_id, "tenantId", 512)?.to_owned());
        let mut seen = HashSet::new();
        while let Some(id) = current.filter(|id| !id.is_empty()) {
            if !seen.insert(id.clone()) {
                return Err(IamError::with_status(
                    "INVALID_TENANT_TREE",
                    "Invalid tenant hierarchy",
                    403,
                ));
            }
            let tenant: Option<Tenant> = get(tx.as_ref(), "tenants", &id).await?;
            match tenant {
                Some(tenant) if tenant.status == TenantStatus::Active => current = tenant.parent_id,
                _ => {
                    return Err(IamError::with_status(
                        "TENANT_UNAVAILABLE",
                        "Tenant is not active",
                        403,
                    ));
                }
            }
        }
        Ok(())
    }

    /// `rate(tenantId, subject, tier)`: counts an attempt against the configured limiter before any credential is
    /// examined: first against the client IP when one is recorded and `rateLimits.ipAttempts` is set, then against
    /// the subject.
    pub(crate) async fn rate(
        &self,
        tenant_id: &str,
        subject: &str,
        tier: RateTier,
    ) -> IamResult<()> {
        self.rate_client(tenant_id).await?;
        self.rate_subject(tenant_id, subject, tier).await
    }

    /// `limitAttempt(tenantId, subject, options)`: counts an attempt for a server flow outside the sign-in paths.
    /// Without `limit` it is exactly `rate(tenantId, subject, tier)`; with `limit` it applies the network blocks and
    /// per-IP counter, then a dedicated per-subject budget. Call it outside any transaction.
    pub async fn limit_attempt(
        &self,
        tenant_id: &str,
        subject: &str,
        options: LimitAttemptOptions,
    ) -> IamResult<()> {
        let Some(limit) = options.limit else {
            return self
                .rate(tenant_id, subject, options.tier.unwrap_or_default())
                .await;
        };
        if !js::is_safe_integer(limit) || limit < 1.0 {
            return Err(IamError::new(
                "INVALID_INPUT",
                "limit must be a positive integer",
            ));
        }
        if options.count_client != Some(false) {
            self.rate_client(tenant_id).await?;
        }
        self.consume(
            hash_token(&format!("{tenant_id}:{subject}")),
            tenant_id,
            limit,
        )
        .await
    }

    /// The network steps `rate` performs before a subject's counter: network blocks, then the per-IP counter.
    async fn rate_client(&self, tenant_id: &str) -> IamResult<()> {
        let ip = self.client_ip();
        // A blocked network is refused before any credential is examined or any counter moves.
        self.assert_network_not_blocked(self.store(), tenant_id, ip.as_deref())
            .await?;
        if let Some(ip) = ip.filter(|ip| !ip.is_empty())
            && self.limits.ip_attempts > 0.0
        {
            // IPv6 clients are counted per /64 and an IPv4-mapped address as its IPv4 form.
            let network = ip_counter_key(&ip).unwrap_or(ip);
            self.consume(
                hash_token(&format!("{tenant_id}:ip:{network}")),
                tenant_id,
                self.limits.ip_attempts,
            )
            .await?;
        }
        Ok(())
    }

    /// `rateChallengeIdentity`: counts a second-factor attempt against the person a challenge names (subject
    /// `{subject}:{identityId}`), on top of the flow's per-challenge counter. The challenge is read outside any
    /// transaction; an unknown or expired challenge counts nothing more here.
    pub(crate) async fn rate_challenge_identity(
        &self,
        tenant_id: &str,
        token: &str,
        purpose: &str,
        subject: &str,
    ) -> IamResult<()> {
        let identity_id = self
            .read_challenge(
                self.store(),
                tenant_id,
                token,
                purpose,
                ChallengeMatch::default(),
            )
            .await
            .ok()
            .map(|challenge| challenge.identity_id);
        if let Some(identity_id) = identity_id.filter(|id| !id.is_empty()) {
            self.rate_subject(
                tenant_id,
                &format!("{subject}:{identity_id}"),
                RateTier::Sensitive,
            )
            .await?;
        }
        Ok(())
    }

    /// One subject's counter, without the network checks `rate` performs first.
    async fn rate_subject(&self, tenant_id: &str, subject: &str, tier: RateTier) -> IamResult<()> {
        let key = hash_token(&format!("{tenant_id}:{subject}"));
        let mut limit = match tier {
            RateTier::Sensitive => self.limits.sensitive_attempts,
            RateTier::Generous => self.limits.attempts * 10.0,
            RateTier::Default => self.limits.attempts,
        };
        // A tenant policy can only tighten the deployment's limit; an unknown tenant keeps the default.
        if let Ok(Some(tenant)) = get::<Tenant>(self.store().as_ref(), "tenants", tenant_id).await
            && let Some(cap) = tenant.auth_policy.and_then(|policy| policy.max_attempts)
        {
            limit = js_min(limit, cap);
        }
        self.consume(key, tenant_id, limit).await
    }

    async fn consume(&self, key: String, tenant_id: &str, limit: f64) -> IamResult<()> {
        let permitted = self
            .limits
            .limiter
            .consume(ConsumeInput {
                key,
                tenant_id: tenant_id.to_owned(),
                limit,
                window_ms: self.limits.window_ms,
                now: self.now(),
            })
            .await?;
        if !permitted {
            // Clients and the HTTP layer read `retryAfterMs` (the window length; see `rate_limit_window_ms`).
            return Err(IamError::with_status(
                "RATE_LIMITED",
                "Too many attempts; try again later",
                429,
            )
            .with_details(better_iam_core::IamErrorDetails {
                retry_after_ms: Some(self.limits.window_ms),
                ..Default::default()
            }));
        }
        Ok(())
    }

    /// `setPassword(tx, tenant, identity, value)`: validates and sets `identity.passwordHash` (the caller persists
    /// the identity): the deployment minimum, the tenant's password rules, the deployment screen, and — for an
    /// existing password — the tenant's `passwordHistory`. The replaced hash joins the identity's history.
    pub async fn set_password(
        &self,
        tx: &Store,
        tenant: Option<&Tenant>,
        identity: &mut Identity,
        value: Option<&Value>,
    ) -> IamResult<()> {
        let plain = password(value)?;
        let policy = tenant.and_then(|tenant| tenant.auth_policy.as_ref());
        let screening = self.options.password_policy.as_ref();
        assert_password_rules(
            &plain,
            policy,
            screening,
            Some(PersonalInfo {
                email: identity.email.as_deref(),
                name: Some(&identity.name),
            }),
        )?;
        if let Some(check) = screening.and_then(|screening| screening.check.clone()) {
            let custom = check(
                plain.clone(),
                PasswordCheckContext {
                    tenant_id: identity.tenant_id.clone(),
                    identity: Some(PasswordIdentity {
                        id: identity.id.clone(),
                        email: identity.email.clone(),
                        name: identity.name.clone(),
                    }),
                },
            )
            .await?;
            if let Some(message) = custom.filter(|message| !message.is_empty()) {
                return Err(IamError::new("WEAK_PASSWORD", message));
            }
        }
        if let Some(is_breached) = screening.and_then(|screening| screening.is_breached.clone())
            && is_breached(plain.clone()).await?
        {
            return Err(IamError::new(
                "BREACHED_PASSWORD",
                "This password appears in a known data breach; choose a different one",
            ));
        }
        let current_hash = identity
            .password_hash
            .clone()
            .filter(|hash| !hash.is_empty());
        let mut history: Vec<PasswordHistoryRecord> = if current_hash.is_some() {
            find(
                tx.as_ref(),
                "passwordHistory",
                &Filter::new().eq("identityId", identity.id.clone()),
            )
            .await?
        } else {
            Vec::new()
        };
        // Newest first (`b.createdAt - a.createdAt`, stable for ties).
        history.sort_by(|a, b| {
            b.created_at
                .partial_cmp(&a.created_at)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let depth = policy
            .and_then(|policy| policy.password_history)
            .unwrap_or(0.0);
        if let Some(current) = current_hash.clone().filter(|_| depth > 0.0) {
            let mut recent = vec![current];
            let take = (depth - 1.0).max(0.0) as usize;
            recent.extend(history.iter().take(take).map(|row| row.hash.clone()));
            for hash in recent {
                if passwords::verify(&hash, &plain).await? {
                    return Err(IamError::new(
                        "PASSWORD_REUSED",
                        format!(
                            "Password must differ from your last {} password{}",
                            js::number_to_string(depth),
                            if depth == 1.0 { "" } else { "s" }
                        ),
                    ));
                }
            }
        }
        let now = self.now();
        if let Some(previous) = current_hash.clone() {
            let newest = history.first().map_or(0.0, |row| row.created_at);
            insert(
                tx.as_ref(),
                "passwordHistory",
                &PasswordHistoryRecord {
                    id: new_id("pwh"),
                    tenant_id: identity.tenant_id.clone(),
                    unique_key: None,
                    identity_id: identity.id.clone(),
                    hash: previous,
                    // Strictly increasing per identity, so history order survives changes within one clock tick.
                    created_at: now.max(newest + 1.0),
                    extra: Map::new(),
                },
            )
            .await?;
            for stale in history.iter().skip(PASSWORD_HISTORY_LIMIT - 1) {
                tx.delete("passwordHistory", &stale.id).await?;
            }
        }
        identity.password_hash = Some(passwords::hash(&plain).await?);
        identity.password_changed_at = Some(now);
        Ok(())
    }

    /// `passwordExpiresAt(tenant, identity)`: when the identity's password expires under its tenant's
    /// `passwordMaxAgeDays`, if it does.
    pub fn password_expires_at(&self, tenant: Option<&Tenant>, identity: &Identity) -> Option<f64> {
        let days = tenant
            .and_then(|tenant| tenant.auth_policy.as_ref())
            .and_then(|policy| policy.password_max_age_days)
            .filter(|days| *days != 0.0 && !days.is_nan())?;
        identity
            .password_hash
            .as_deref()
            .filter(|hash| !hash.is_empty())?;
        Some(identity.password_changed_at.unwrap_or(identity.created_at) + days * DAY_MS)
    }

    /// Refuses a correct but expired password; the person recovers through password reset.
    pub(crate) async fn assert_password_current(
        &self,
        tx: &Store,
        identity: &Identity,
    ) -> IamResult<()> {
        let tenant: Option<Tenant> = get(tx.as_ref(), "tenants", &identity.tenant_id).await?;
        if let Some(expires_at) = self.password_expires_at(tenant.as_ref(), identity)
            && expires_at <= self.now()
        {
            return Err(IamError::with_status(
                "PASSWORD_EXPIRED",
                "Your password has expired; reset it to continue",
                403,
            ));
        }
        Ok(())
    }

    /// `resetRateLimits(identity)`: clears the rate-limit counters an identity's sign-in and recovery flows use, so an
    /// administrator can unlock an account. `supported` is false when the limiter cannot reset counters.
    pub async fn reset_rate_limits(&self, identity: &Identity) -> IamResult<ResetRateLimitsResult> {
        let limiter = &self.limits.limiter;
        if !limiter.supports_reset() {
            return Ok(ResetRateLimitsResult {
                supported: false,
                cleared: 0,
            });
        }
        let id = &identity.id;
        let mut subjects: Vec<String> = [
            "mfa-enroll",
            "password-change",
            "reauth",
            "email-change",
            "phone-verify",
            "phone-code",
            "mfa-verify",
            "mfa-recovery",
            "mfa-code-send",
            "passkey-mfa-begin",
            "passkey-mfa-verify",
        ]
        .iter()
        .map(|subject| format!("{subject}:{id}"))
        .collect();
        for destination in [&identity.email, &identity.phone].into_iter().flatten() {
            if destination.is_empty() {
                continue;
            }
            for subject in [
                "signup",
                "signin",
                "verify-email",
                "password-reset",
                "passwordless-start",
                "passwordless-finish",
                "passkey",
            ] {
                subjects.push(format!("{subject}:{destination}"));
            }
        }
        for subject in &subjects {
            limiter
                .reset(ResetInput {
                    key: hash_token(&format!("{}:{subject}", identity.tenant_id)),
                    tenant_id: identity.tenant_id.clone(),
                })
                .await?;
        }
        Ok(ResetRateLimitsResult {
            supported: true,
            cleared: subjects.len(),
        })
    }

    /// True once an identity's `expiresAt` has passed: it is refused everywhere, before the purge worker disables it.
    pub fn identity_expired(&self, identity: &Identity) -> bool {
        identity.expires_at.is_some_and(|at| at <= self.now())
    }

    /// `user(tx, identityId, tenantId)`: an active, unexpired human identity in an active tenant tree.
    pub async fn user(
        &self,
        tx: &Store,
        identity_id: &str,
        tenant_id: Option<&str>,
    ) -> IamResult<Identity> {
        let identity: Option<Identity> = get(tx.as_ref(), "identities", identity_id).await?;
        let invalid = || IamError::with_status("UNAUTHENTICATED", "Invalid authentication", 401);
        let identity = identity.ok_or_else(invalid)?;
        if identity.kind != IdentityKind::User
            || identity.status != IdentityStatus::Active
            || self.identity_expired(&identity)
            || tenant_id.is_some_and(|tenant| !tenant.is_empty() && identity.tenant_id != tenant)
        {
            return Err(invalid());
        }
        self.assert_tenant_active(tx, &identity.tenant_id).await?;
        Ok(identity)
    }

    /// `mfaRequired(tx, identity)`: root administrators, enrolled people, and members of tenants that require MFA.
    pub async fn mfa_required(&self, tx: &Store, identity: &Identity) -> IamResult<bool> {
        let mfa: Option<MfaRecord> = get(tx.as_ref(), "authMfa", &identity.id).await?;
        let tenant: Option<Tenant> = get(tx.as_ref(), "tenants", &identity.tenant_id).await?;
        if identity.root_admin || mfa.is_some_and(|mfa| mfa.enabled) {
            return Ok(true);
        }
        match tenant {
            Some(tenant) => self.tenant_requires_mfa(&tenant, identity).await,
            None => Ok(false),
        }
    }

    /// `tenantRequiresMfa(tenant, identity)`: the configured callback or the tenant's own policy.
    pub async fn tenant_requires_mfa(
        &self,
        tenant: &Tenant,
        identity: &Identity,
    ) -> IamResult<bool> {
        let policy = tenant.auth_policy.as_ref();
        if policy.and_then(|policy| policy.require_mfa) == Some(true)
            || (policy.and_then(|policy| policy.require_mfa_for_owners) == Some(true)
                && identity.owner)
        {
            return Ok(true);
        }
        match &self.options.require_mfa {
            Some(callback) => callback(tenant.clone(), identity.clone()).await,
            None => Ok(false),
        }
    }

    /// `sessionLimits(tenant)`: its policy can shorten, never extend, the deployment's lifetimes.
    pub fn session_limits(&self, tenant: Option<&Tenant>) -> SessionLimits {
        let policy = tenant.and_then(|tenant| tenant.auth_policy.as_ref());
        let lifetime_ms = min_opt(
            self.session_lifetime,
            policy.and_then(|policy| policy.session_lifetime_ms),
        );
        let idle_timeout_ms = min_opt(
            js_min(lifetime_ms, self.idle_lifetime),
            policy.and_then(|policy| policy.session_idle_timeout_ms),
        );
        SessionLimits {
            lifetime_ms,
            idle_timeout_ms,
        }
    }

    /// `methodAllowed(tx, tenantId, method)`: rejects a sign-in method the tenant's policy excludes; called before any
    /// credential is examined so failures never reveal validity.
    pub(crate) async fn method_allowed(
        &self,
        tx: &Store,
        tenant_id: &str,
        method: AuthMethod,
    ) -> IamResult<()> {
        let tenant: Option<Tenant> = get(tx.as_ref(), "tenants", tenant_id).await?;
        if let Some(allowed) = tenant
            .and_then(|tenant| tenant.auth_policy)
            .and_then(|policy| policy.allowed_methods)
            && !allowed.contains(&method)
        {
            return Err(IamError::with_status(
                "METHOD_NOT_ALLOWED",
                "This sign-in method is not permitted for this organization",
                403,
            ));
        }
        Ok(())
    }

    /// `audit(tx, identity, action, session, metadata)`: records an authentication event; when `session` is an
    /// impersonation session the administrator is attributed. `metadata` carries small facts (never secrets).
    pub async fn audit(
        &self,
        tx: &Store,
        identity: &Identity,
        action: &str,
        session: Option<&Session>,
        metadata: Option<Map<String, Value>>,
    ) -> IamResult<()> {
        let mut event = better_iam_core::record(json!({
            "id": new_id("audit"),
            "tenantId": identity.tenant_id,
            "actorId": identity.id,
            "action": action,
            "resourceId": identity.id,
            "timestamp": num(self.now()),
            "outcome": "allow",
        }));
        if let Some(impersonator) = session
            .and_then(|session| session.impersonator_id.clone())
            .filter(|id| !id.is_empty())
        {
            event.insert("impersonatorId".to_owned(), Value::String(impersonator));
        }
        if let Some(metadata) = metadata.filter(|metadata| !metadata.is_empty()) {
            event.insert("metadata".to_owned(), Value::Object(metadata));
        }
        let stored = append_audit_event(tx.as_ref(), &event).await?;
        if let Some(on_audit) = &self.options.on_audit {
            on_audit(tx.clone(), stored).await?;
        }
        Ok(())
    }

    /// `clientMetadata()`: the recorded client of the current request as audit metadata (IP and user agent only).
    pub(crate) fn client_metadata(&self) -> Map<String, Value> {
        let mut metadata = Map::new();
        if let Some(client) = self.current_client() {
            if let Some(ip) = client.ip.filter(|ip| !ip.is_empty()) {
                metadata.insert("ip".to_owned(), Value::String(ip));
            }
            if let Some(user_agent) = client.user_agent.filter(|value| !value.is_empty()) {
                metadata.insert("userAgent".to_owned(), Value::String(user_agent));
            }
        }
        metadata
    }

    /// `digestChallenge(tenantId, token, secret)`: hex HMAC-SHA256(secret, `{tenantId}:{token}`).
    pub fn digest_challenge(&self, tenant_id: &str, token: &str, secret: Option<&str>) -> String {
        digest_challenge(secret.unwrap_or(&self.options.secret), tenant_id, token)
    }

    /// `challenge(tx, identity, purpose, payload, lifetimeMs, token, sessionId)`: stores a single-use, purpose-bound
    /// challenge and returns the plaintext token to deliver.
    #[allow(clippy::too_many_arguments)]
    pub async fn challenge(
        &self,
        tx: &Store,
        identity: &Identity,
        purpose: &str,
        payload: Map<String, Value>,
        lifetime_ms: Option<f64>,
        token: Option<String>,
        session_id: Option<String>,
    ) -> IamResult<String> {
        let token = token.unwrap_or_else(new_token);
        let token_hash = self.digest_challenge(&identity.tenant_id, &token, None);
        insert(
            tx.as_ref(),
            "authChallenges",
            &Challenge {
                id: new_id("ch"),
                tenant_id: identity.tenant_id.clone(),
                unique_key: None,
                identity_id: identity.id.clone(),
                purpose: purpose.to_owned(),
                token_hash,
                payload,
                expires_at: self.now() + lifetime_ms.unwrap_or(10.0 * 60_000.0),
                session_id,
                extra: Map::new(),
            },
        )
        .await?;
        Ok(token)
    }

    /// `readChallenge(tx, tenantId, token, purpose, match)`: the live challenge behind a token, trying the digests of
    /// every secret (links issued before a rotation carry digests under a previous secret).
    pub async fn read_challenge(
        &self,
        tx: &Store,
        tenant_id: &str,
        token: &str,
        purpose: &str,
        matching: ChallengeMatch<'_>,
    ) -> IamResult<Challenge> {
        text_str(tenant_id, "tenantId", 512)?;
        text_str(token, "token", 512)?;
        let mut item: Option<Challenge> = None;
        for secret in &self.secrets {
            let candidates: Vec<Challenge> = find(
                tx.as_ref(),
                "authChallenges",
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq(
                        "tokenHash",
                        self.digest_challenge(tenant_id, token, Some(secret)),
                    )
                    .eq("purpose", purpose),
            )
            .await?;
            item = candidates.into_iter().find(|entry| {
                matching
                    .identity_id
                    .filter(|id| !id.is_empty())
                    .is_none_or(|id| entry.identity_id == id)
                    && matching
                        .destination
                        .filter(|destination| !destination.is_empty())
                        .is_none_or(|destination| {
                            entry.payload_str("destination") == Some(destination)
                        })
            });
            if item.is_some() {
                break;
            }
        }
        match item {
            Some(item) if item.expires_at > self.now() => Ok(item),
            _ => Err(IamError::with_status(
                "INVALID_CHALLENGE",
                "Challenge is invalid or expired",
                401,
            )),
        }
    }

    /// `enqueue(tx, identity, kind, to, template, payload)`.
    pub(crate) async fn enqueue(
        &self,
        tx: &Store,
        identity: &Identity,
        kind: OutboxKind,
        to: &str,
        template: &str,
        payload: Map<String, Value>,
    ) -> IamResult<()> {
        self.enqueue_delivery(
            tx,
            EnqueueInput {
                tenant_id: identity.tenant_id.clone(),
                kind,
                to: to.to_owned(),
                template: template.to_owned(),
                payload,
                reference: None,
            },
        )
        .await?;
        Ok(())
    }

    /// The delivery callback of a message kind, if configured.
    pub fn deliverer(&self, kind: OutboxKind) -> Option<DeliveryFn> {
        (self.outbox.deliverer)(kind)
    }

    /// `enqueueDelivery(tx, input)`: internal server integrations enqueue callbacks in the same transaction as
    /// provisioning. Returns the message ID.
    pub async fn enqueue_delivery(&self, tx: &Store, input: EnqueueInput) -> IamResult<String> {
        enqueue_delivery(&self.outbox, tx.as_ref(), input).await
    }

    /// `dispatchOutbox(limit)`: at-least-once delivery with backoff (default limit 100).
    pub async fn dispatch_outbox(&self, limit: Option<f64>) -> IamResult<DispatchResult> {
        dispatch_outbox(&self.outbox, limit.unwrap_or(100.0)).await
    }

    /// The outbox context (for server integrations that dispatch with their own limits).
    pub fn outbox_context(&self) -> &OutboxContext {
        &self.outbox
    }

    /// `createIdentity(tx, input)`: the internal provisioning primitive every path that creates a person ends in. It
    /// does not grant application permissions.
    pub async fn create_identity(
        &self,
        tx: &Store,
        input: CreateIdentityInput,
    ) -> IamResult<Identity> {
        let tenant_id = Value::String(input.tenant_id);
        let email = Value::String(input.email);
        let name = Value::String(input.name);
        let password = input.password.map(Value::String);
        self.create_identity_raw(
            tx,
            CreateIdentityRaw {
                tenant_id: Some(&tenant_id),
                email: Some(&email),
                name: Some(&name),
                password: password.as_ref(),
                owner: input.owner.unwrap_or(false),
                root_admin: input.root_admin.unwrap_or(false),
                email_verified: input.email_verified.unwrap_or(false),
            },
        )
        .await
    }

    /// [`AuthService::create_identity`] for untrusted values (a request's `name` and `password`), validated as the
    /// TypeScript function validates them.
    pub async fn create_identity_raw(
        &self,
        tx: &Store,
        input: CreateIdentityRaw<'_>,
    ) -> IamResult<Identity> {
        let tenant_id = text(input.tenant_id, "tenantId", 512)?;
        let normalized = email(input.email)?;
        let tenant: Option<Tenant> = get(tx.as_ref(), "tenants", &tenant_id).await?;
        let tenant = tenant.ok_or_else(|| {
            IamError::with_status("TENANT_NOT_FOUND", "Tenant does not exist", 404)
        })?;
        let existing = tx
            .find(
                "identities",
                &Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("email", normalized.clone()),
                &Default::default(),
            )
            .await?;
        if !existing.is_empty() {
            return Err(IamError::with_status(
                "IDENTITY_EXISTS",
                "An identity with this email already exists in this tenant",
                409,
            ));
        }
        if let Some(limit) = tenant.limits.as_ref().and_then(|limits| limits.identities) {
            let members = tx
                .find(
                    "identities",
                    &Filter::new()
                        .eq("tenantId", tenant_id.clone())
                        .eq("kind", "user"),
                    &Default::default(),
                )
                .await?
                .into_iter()
                .filter(|item| item.get("status").and_then(Value::as_str) != Some("deleted"))
                .count();
            if members as f64 >= limit {
                return Err(IamError::with_status(
                    "LIMIT_EXCEEDED",
                    format!(
                        "This tenant has reached its member limit ({})",
                        js::number_to_string(limit)
                    ),
                    409,
                ));
            }
        }
        let mut identity: Identity = from_record(better_iam_core::record(json!({
            "id": new_id("usr"),
            "tenantId": tenant_id,
            "uniqueKey": format!("email:{normalized}"),
            "kind": "user",
            "email": normalized,
            "name": display_name(input.name, 256)?,
            "status": "active",
            "emailVerified": input.email_verified,
            "rootAdmin": input.root_admin,
            "owner": input.owner,
            "createdAt": num(self.now()),
        })))?;
        if let Some(plain) = input.password {
            self.set_password(tx, Some(&tenant), &mut identity, Some(plain))
                .await?;
        }
        insert(tx.as_ref(), "identities", &identity).await?;
        self.audit(tx, &identity, "auth:identity:create", None, None)
            .await?;
        Ok(identity)
    }

    /// `deviceLifetimeFor(tenant)`: how long this tenant remembers a device: the deployment ceiling, shortened by
    /// policy; 0 when either disables it.
    pub fn device_lifetime_for(&self, tenant: Option<&Tenant>) -> f64 {
        let days = tenant
            .and_then(|tenant| tenant.auth_policy.as_ref())
            .and_then(|policy| policy.trusted_device_days);
        if self.device_lifetime == 0.0 || days == Some(0.0) {
            return 0.0;
        }
        min_opt(self.device_lifetime, days.map(|days| days * DAY_MS))
    }

    /// `rememberDevice(tx, identity)`: remembers the current client for an identity that just completed MFA. Returns
    /// the device token to hand to the client, or None when the deployment, the tenant, or the identity (root
    /// administrators) rules it out.
    pub async fn remember_device(
        &self,
        tx: &Store,
        identity: &Identity,
    ) -> IamResult<Option<RememberedDevice>> {
        if identity.root_admin {
            return Ok(None);
        }
        let tenant: Option<Tenant> = get(tx.as_ref(), "tenants", &identity.tenant_id).await?;
        let lifetime = self.device_lifetime_for(tenant.as_ref());
        if lifetime == 0.0 {
            return Ok(None);
        }
        let now = self.now();
        let token = new_token();
        let device = TrustedDevice {
            id: new_id("dev"),
            tenant_id: identity.tenant_id.clone(),
            identity_id: identity.id.clone(),
            token_hash: hash_token(&token),
            unique_key: Some(hash_token(&token)),
            created_at: now,
            expires_at: now + lifetime,
            last_used_at: now,
            client: self.current_client(),
            extra: Map::new(),
        };
        insert(tx.as_ref(), "authDevices", &device).await?;
        self.audit(tx, identity, "auth:device:trust", None, None)
            .await?;
        Ok(Some(RememberedDevice {
            device_token: token,
            device_expires_at: device.expires_at,
        }))
    }

    /// `trustedDevice(tx, identity, deviceToken)`: the live trusted device behind a token for this identity, touched
    /// on use; None when it cannot vouch.
    pub(crate) async fn trusted_device(
        &self,
        tx: &Store,
        identity: &Identity,
        device_token: &str,
    ) -> IamResult<Option<TrustedDevice>> {
        if identity.root_admin || !token_shape(device_token) {
            return Ok(None);
        }
        let tenant: Option<Tenant> = get(tx.as_ref(), "tenants", &identity.tenant_id).await?;
        let lifetime = self.device_lifetime_for(tenant.as_ref());
        if lifetime == 0.0 {
            return Ok(None);
        }
        let device: Option<TrustedDevice> = find::<TrustedDevice>(
            tx.as_ref(),
            "authDevices",
            &Filter::new().eq("tokenHash", hash_token(device_token)),
        )
        .await?
        .into_iter()
        .next();
        let Some(mut device) = device else {
            return Ok(None);
        };
        // The current policy also bounds devices remembered under a longer one.
        if device.identity_id != identity.id
            || device.tenant_id != identity.tenant_id
            || device.expires_at <= self.now()
            || self.now() - device.created_at >= lifetime
        {
            return Ok(None);
        }
        device.last_used_at = self.now();
        put(tx.as_ref(), "authDevices", &device).await?;
        Ok(Some(device))
    }

    /// `issueSession(tx, identity, options)`: the caller must already have verified the authentication ceremony.
    pub async fn issue_session(
        &self,
        tx: &Store,
        identity: &Identity,
        options: IssueSessionOptions,
    ) -> IamResult<SessionResult> {
        let active = boxed(|| self.user(tx, &identity.id, Some(&identity.tenant_id))).await?;
        if self.require_email_verification && !active.email_verified {
            return Err(IamError::with_status(
                "EMAIL_UNVERIFIED",
                "Verify your email before signing in",
                403,
            ));
        }
        if boxed(|| self.mfa_required(tx, &active)).await? && options.mfa != Some(true) {
            return Err(IamError::with_status(
                "MFA_REQUIRED",
                "Multi-factor authentication is required",
                403,
            ));
        }
        let tenant: Option<Tenant> =
            boxed(|| get(tx.as_ref(), "tenants", &active.tenant_id)).await?;
        let client = self.current_client();
        let ip = client.as_ref().and_then(|client| client.ip.clone());
        self.assert_ip_allowed(tenant.as_ref(), ip.as_deref())?;
        boxed(|| self.assert_network_not_blocked(tx, &active.tenant_id, ip.as_deref())).await?;
        let now = self.now();
        let token = new_credential_token(CredentialTokenType::Ses);
        let mfa = options.mfa.unwrap_or(false);
        let mut session: Session = from_record(better_iam_core::record(json!({
            "id": new_id("ses"),
            "tenantId": active.tenant_id,
            "identityId": active.id,
            "kind": "user",
            "tokenHash": hash_token(&token),
            "uniqueKey": hash_token(&token),
            "createdAt": num(now),
            "lastSeenAt": num(now),
            "expiresAt": num(now + self.session_limits(tenant.as_ref()).lifetime_ms),
            "authenticatedAt": num(options.authenticated_at.unwrap_or(now)),
            "mfa": mfa,
        })))?;
        session.method = options.method;
        session.trusted_device_id = options
            .trusted_device_id
            .clone()
            .filter(|id| !id.is_empty());
        // principal.mfaTime: only a first-hand factor counts, never a remembered device.
        if session.mfa && session.trusted_device_id.is_none() {
            let mfa_at = options
                .mfa_authenticated_at
                .or(if options.authenticated_at.is_none() {
                    Some(now)
                } else {
                    None
                });
            session.mfa_authenticated_at = mfa_at;
        }
        session.client = client.clone();
        // The previous sign-in, and the attempts that failed since, travel on the session for a "last sign-in"
        // notice; the ledger then restarts from this session.
        let ledger: Option<SignInLedger> =
            boxed(|| get(tx.as_ref(), "authSignIns", &active.id)).await?;
        if let Some(ledger) = &ledger {
            session.previous_sign_in = Some(ledger.summary());
        }
        boxed(|| insert(tx.as_ref(), "sessions", &session)).await?;
        let next = SignInLedger {
            id: active.id.clone(),
            tenant_id: active.tenant_id.clone(),
            unique_key: None,
            identity_id: active.id.clone(),
            last_at: Some(now),
            last_client: client.clone().filter(client_has_details),
            failed_attempts: 0.0,
            last_failed_at: None,
            last_failed_client: None,
            extra: Map::new(),
        };
        if ledger.is_some() {
            boxed(|| put(tx.as_ref(), "authSignIns", &next)).await?;
        } else {
            boxed(|| insert(tx.as_ref(), "authSignIns", &next)).await?;
        }
        // A tenant may cap concurrent sessions per person; the oldest live sessions make room for the new one.
        if let Some(max_sessions) = tenant
            .as_ref()
            .and_then(|tenant| tenant.auth_policy.as_ref())
            .and_then(|policy| policy.max_sessions)
        {
            let mut live: Vec<Session> = boxed(|| async {
                find::<Session>(
                    tx.as_ref(),
                    "sessions",
                    &Filter::new()
                        .eq("tenantId", active.tenant_id.clone())
                        .eq("identityId", active.id.clone())
                        .eq("kind", "user"),
                )
                .await
            })
            .await?
            .into_iter()
            .filter(|item| {
                item.expires_at > now && item.impersonator_id.as_deref().is_none_or(str::is_empty)
            })
            .collect();
            live.sort_by(|a, b| by_number_then_id((a.created_at, &a.id), (b.created_at, &b.id)));
            let excess = (live.len() as f64 - max_sessions).max(0.0);
            for stale in live.iter().take(excess as usize) {
                boxed(|| self.end_session(tx, &stale.id)).await?;
            }
        }
        let mut metadata = Map::new();
        if let Some(method) = options.method {
            metadata.insert(
                "method".to_owned(),
                Value::String(method.as_str().to_owned()),
            );
        }
        metadata.extend(self.client_metadata());
        boxed(|| self.audit(tx, &active, "auth:session:create", None, Some(metadata))).await?;
        if session.trusted_device_id.is_none() {
            boxed(|| self.notify_new_sign_in(tx, &active, tenant.as_ref(), &session)).await?;
        }
        Ok(SessionResult {
            token,
            session: public_session(&session),
        })
    }

    /// `recordSignInFailure(identity, reason, at)`: counts an attempt that named a known, active person with a wrong
    /// password, factor, or recovery code, in its own transaction; never fails (the credential error is what the
    /// caller reports).
    pub async fn record_sign_in_failure(
        &self,
        identity: &Identity,
        reason: SignInFailureReason,
        at: Option<f64>,
    ) {
        if identity.kind != IdentityKind::User || identity.status != IdentityStatus::Active {
            return;
        }
        let at = at.unwrap_or_else(|| self.now());
        let identity = identity.clone();
        let _ = self
            .store()
            .transaction(|tx| async move {
                let now = at;
                let client = self.current_client();
                let existing: Option<SignInLedger> =
                    get(tx.as_ref(), "authSignIns", &identity.id).await?;
                let ledger = SignInLedger {
                    id: identity.id.clone(),
                    tenant_id: identity.tenant_id.clone(),
                    unique_key: None,
                    identity_id: identity.id.clone(),
                    last_at: existing.as_ref().and_then(|existing| existing.last_at),
                    last_client: existing
                        .as_ref()
                        .and_then(|existing| existing.last_client.clone()),
                    failed_attempts: existing
                        .as_ref()
                        .map_or(0.0, |existing| existing.failed_attempts)
                        + 1.0,
                    last_failed_at: Some(now),
                    last_failed_client: client.clone().filter(client_has_details),
                    extra: Map::new(),
                };
                if existing.is_some() {
                    put(tx.as_ref(), "authSignIns", &ledger).await?;
                } else {
                    insert(tx.as_ref(), "authSignIns", &ledger).await?;
                }
                let mut metadata = Map::new();
                metadata.insert(
                    "reason".to_owned(),
                    Value::String(reason.as_str().to_owned()),
                );
                metadata.extend(self.client_metadata());
                self.audit(&tx, &identity, "auth:signin:fail", None, Some(metadata))
                    .await?;
                // One alert per streak: exactly when the threshold is reached, and the streak ends with a sign-in.
                if self.failed_alert_threshold > 0.0
                    && ledger.failed_attempts == self.failed_alert_threshold
                    && identity
                        .email
                        .as_deref()
                        .is_some_and(|email| !email.is_empty())
                    && identity.email_verified
                    && self.options.send_email.is_some()
                {
                    let mut payload = Map::new();
                    payload.insert(
                        "attempts".to_owned(),
                        Value::String(js::number_to_string(ledger.failed_attempts)),
                    );
                    payload.insert(
                        "time".to_owned(),
                        Value::String(js::iso_string(now).ok_or_else(crate::util::internal_error)?),
                    );
                    payload.extend(self.client_metadata());
                    let email = identity.email.clone().unwrap_or_default();
                    self.enqueue(
                        &tx,
                        &identity,
                        OutboxKind::Email,
                        &email,
                        "sign-in-failures",
                        payload,
                    )
                    .await?;
                }
                Ok(())
            })
            .await;
    }

    /// `deferSignInFailure(identity, reason)`: records a refused attempt without delaying the refusal. The write
    /// starts once the refusal has been answered (a separate task); `settle_bookkeeping` awaits it.
    pub(crate) fn defer_sign_in_failure(&self, identity: Identity, reason: SignInFailureReason) {
        let at = self.now();
        let service = self.clone();
        let client = self.current_client();
        let task = async move {
            tokio::task::yield_now().await;
            let record = service.record_sign_in_failure(&identity, reason, Some(at));
            match client {
                Some(client) => service.with_client(Some(client), record).await,
                None => record.await,
            }
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let join = handle.spawn(task);
        let mut pending = self
            .bookkeeping
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pending.retain(|handle| !handle.is_finished());
        pending.push(join);
    }

    /// `settleBookkeeping()`: resolves once the failed-attempt bookkeeping of refusals already answered has been
    /// written. Tests that read the sign-in ledger right after a refusal await this first; a graceful shutdown can
    /// await it so those records are not lost.
    pub async fn settle_bookkeeping(&self) {
        loop {
            let pending: Vec<_> = {
                let mut pending = self
                    .bookkeeping
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                std::mem::take(&mut *pending)
            };
            if pending.is_empty() {
                return;
            }
            for handle in pending {
                let _ = handle.await;
            }
        }
    }

    /// `notifyNewSignIn`: emails the person about a session from a client that no live session or remembered device
    /// of theirs has used.
    pub(crate) async fn notify_new_sign_in(
        &self,
        tx: &Store,
        identity: &Identity,
        tenant: Option<&Tenant>,
        session: &Session,
    ) -> IamResult<()> {
        let enabled = tenant
            .and_then(|tenant| tenant.auth_policy.as_ref())
            .and_then(|policy| policy.notify_new_sign_in)
            .or(self.options.sign_in_notifications)
            .unwrap_or(false);
        let Some(email) = identity.email.clone().filter(|email| !email.is_empty()) else {
            return Ok(());
        };
        if !enabled || self.options.send_email.is_none() {
            return Ok(());
        }
        let Some(current) = fingerprint(session.client.as_ref()) else {
            return Ok(());
        };
        let now = self.now();
        let scope = Filter::new()
            .eq("identityId", identity.id.clone())
            .eq("tenantId", identity.tenant_id.clone());
        let known_session =
            find::<Session>(tx.as_ref(), "sessions", &scope.clone().eq("kind", "user"))
                .await?
                .iter()
                .any(|other| {
                    other.id != session.id
                        && other.expires_at > now
                        && fingerprint(other.client.as_ref()).as_deref() == Some(current.as_str())
                });
        let known_device = !known_session
            && find::<TrustedDevice>(tx.as_ref(), "authDevices", &scope)
                .await?
                .iter()
                .any(|device| {
                    device.expires_at > now
                        && fingerprint(device.client.as_ref()).as_deref() == Some(current.as_str())
                });
        if known_session || known_device {
            return Ok(());
        }
        let mut payload = Map::new();
        payload.insert("sessionId".to_owned(), Value::String(session.id.clone()));
        payload.insert(
            "time".to_owned(),
            Value::String(js::iso_string(now).ok_or_else(crate::util::internal_error)?),
        );
        payload.insert(
            "method".to_owned(),
            Value::String(
                session
                    .method
                    .map_or("unknown", AuthMethod::as_str)
                    .to_owned(),
            ),
        );
        if let Some(client) = &session.client {
            for (key, value) in [
                ("userAgent", &client.user_agent),
                ("ip", &client.ip),
                ("label", &client.label),
            ] {
                if let Some(value) = value.clone().filter(|value| !value.is_empty()) {
                    payload.insert(key.to_owned(), Value::String(value));
                }
            }
        }
        self.enqueue(
            tx,
            identity,
            OutboxKind::Email,
            &email,
            "new-sign-in",
            payload,
        )
        .await
    }

    /// `issueImpersonationSession(tx, actor, target, durationMs)`: opens a session as `target` on behalf of `actor`
    /// ("view as"). The server authorizes and audits the request; here the tenant must allow impersonation, the
    /// actor must hold an ordinary session of their own, and the new session inherits the actor's MFA state and
    /// expires with the actor's session.
    pub async fn issue_impersonation_session(
        &self,
        tx: &Store,
        actor: &AuthenticatedPrincipal,
        target: &Identity,
        duration_ms: f64,
    ) -> IamResult<SessionResult> {
        if actor.session.kind != SessionKind::User
            || actor
                .session
                .impersonator_id
                .as_deref()
                .is_some_and(|id| !id.is_empty())
        {
            return Err(IamError::with_status(
                "IMPERSONATION_RESTRICTED",
                "Only a person acting through their own session can impersonate",
                403,
            ));
        }
        let active = self.user(tx, &target.id, Some(&target.tenant_id)).await?;
        let tenant: Option<Tenant> = get(tx.as_ref(), "tenants", &active.tenant_id).await?;
        let client = self.current_client();
        let ip = client.as_ref().and_then(|client| client.ip.clone());
        self.assert_ip_allowed(tenant.as_ref(), ip.as_deref())?;
        self.assert_network_not_blocked(tx, &active.tenant_id, ip.as_deref())
            .await?;
        if tenant
            .as_ref()
            .and_then(|tenant| tenant.auth_policy.as_ref())
            .and_then(|policy| policy.allow_impersonation)
            != Some(true)
        {
            return Err(IamError::with_status(
                "FEATURE_DISABLED",
                "Impersonation is not enabled for this organization",
                403,
            ));
        }
        if self.mfa_required(tx, &active).await? && !actor.session.mfa {
            return Err(IamError::with_status(
                "MFA_REQUIRED",
                "Complete multi-factor authentication before impersonating a member who requires it",
                403,
            ));
        }
        let now = self.now();
        // Impersonation inherits the actor's MFA flag but never a first-hand factor time (no principal.mfaTime).
        let token = new_credential_token(CredentialTokenType::Ses);
        let mut session: Session = from_record(better_iam_core::record(json!({
            "id": new_id("ses"),
            "tenantId": active.tenant_id,
            "identityId": active.id,
            "kind": "user",
            "tokenHash": hash_token(&token),
            "uniqueKey": hash_token(&token),
            "createdAt": num(now),
            "lastSeenAt": num(now),
            "expiresAt": num(js_min(actor.session.expires_at, now + duration_ms)),
            "authenticatedAt": num(now),
            "mfa": actor.session.mfa,
            "method": "impersonation",
            "impersonatorId": actor.identity.id,
            "impersonatorSessionId": actor.session.id,
        })))?;
        session.client = client;
        insert(tx.as_ref(), "sessions", &session).await?;
        self.audit(tx, &active, "auth:session:create", Some(&session), None)
            .await?;
        Ok(SessionResult {
            token,
            session: public_session(&session),
        })
    }

    /// `endSession(tx, sessionId)`: removes a session together with any impersonation sessions an administrator
    /// opened through it.
    pub async fn end_session(&self, tx: &Store, session_id: &str) -> IamResult<()> {
        tx.delete("sessions", session_id).await?;
        let dependents = tx
            .find(
                "sessions",
                &Filter::new().eq("impersonatorSessionId", session_id),
                &Default::default(),
            )
            .await?;
        for dependent in dependents {
            tx.delete("sessions", better_iam_core::record_id(&dependent))
                .await?;
        }
        Ok(())
    }

    /// `assertImpersonationSource(tx, session)`: an impersonation session lives only while the administrator's own
    /// session and identity do, while the member's tenant still allows impersonation, and while the member may still
    /// be impersonated; otherwise it is refused (and removed on sight).
    pub async fn assert_impersonation_source(
        &self,
        tx: &Store,
        session: &Session,
    ) -> IamResult<()> {
        let Some(impersonator_id) = session.impersonator_id.clone().filter(|id| !id.is_empty())
        else {
            return Ok(());
        };
        let source: Option<Session> = match session
            .impersonator_session_id
            .as_deref()
            .filter(|id| !id.is_empty())
        {
            Some(id) => get(tx.as_ref(), "sessions", id).await?,
            None => None,
        };
        let actor: Option<Identity> = get(tx.as_ref(), "identities", &impersonator_id).await?;
        let member: Option<Identity> = get(tx.as_ref(), "identities", &session.identity_id).await?;
        let member_tenant: Option<Tenant> = get(tx.as_ref(), "tenants", &session.tenant_id).await?;
        let source_tenant: Option<Tenant> = match &source {
            Some(source) => get(tx.as_ref(), "tenants", &source.tenant_id).await?,
            None => None,
        };
        let last_active = source
            .as_ref()
            .map_or(0.0, |source| source.last_seen_at)
            .max(session.last_seen_at);
        let now = self.now();
        let ended = match (&source, &actor, &member) {
            (Some(source), Some(actor), Some(member)) => {
                source.kind != SessionKind::User
                    || source.identity_id != impersonator_id
                    || source.expires_at <= now
                    || now - last_active
                        >= self.session_limits(source_tenant.as_ref()).idle_timeout_ms
                    || actor.status != IdentityStatus::Active
                    || self.identity_expired(actor)
                    || member_tenant
                        .as_ref()
                        .and_then(|tenant| tenant.auth_policy.as_ref())
                        .and_then(|policy| policy.allow_impersonation)
                        != Some(true)
                    || member.owner
                    || member.root_admin
            }
            _ => true,
        };
        if ended {
            tx.delete("sessions", &session.id).await?;
            return Err(IamError::with_status(
                "UNAUTHENTICATED",
                "Impersonation has ended",
                401,
            ));
        }
        Ok(())
    }

    /// `passkeyFactor(tx, identity)`: whether the person has a registered passkey that can serve as their second
    /// factor on this deployment.
    pub(crate) async fn passkey_factor(&self, tx: &Store, identity: &Identity) -> IamResult<bool> {
        if self.options.passkeys.is_none() {
            return Ok(false);
        }
        Ok(!tx
            .find(
                "authPasskeys",
                &Filter::new()
                    .eq("tenantId", identity.tenant_id.clone())
                    .eq("identityId", identity.id.clone()),
                &Default::default(),
            )
            .await?
            .is_empty())
    }

    /// `completeAuthentication(tx, identity, method, deviceToken)`: callers have verified the first factor (or a
    /// federated assertion). `method` is recorded on the session, carried through the MFA challenge, and checked
    /// against the tenant's allowed methods. A valid `deviceToken` satisfies the MFA requirement.
    pub async fn complete_authentication(
        &self,
        tx: &Store,
        identity: &Identity,
        method: Option<AuthMethod>,
        device_token: Option<&str>,
    ) -> IamResult<SignInResult> {
        let active = boxed(|| self.user(tx, &identity.id, Some(&identity.tenant_id))).await?;
        if let Some(method) = method {
            boxed(|| self.method_allowed(tx, &active.tenant_id, method)).await?;
        }
        if boxed(|| self.mfa_required(tx, &active)).await? {
            let device = match device_token.filter(|token| !token.is_empty()) {
                Some(token) => boxed(|| self.trusted_device(tx, &active, token)).await?,
                None => None,
            };
            if let Some(device) = device {
                return boxed(|| {
                    self.issue_session(
                        tx,
                        &active,
                        IssueSessionOptions {
                            mfa: Some(true),
                            method,
                            trusted_device_id: Some(device.id),
                            ..Default::default()
                        },
                    )
                })
                .await
                .map(SignInResult::Session);
            }
            let mfa: Option<MfaRecord> = boxed(|| get(tx.as_ref(), "authMfa", &active.id)).await?;
            let enabled = mfa.is_some_and(|mfa| mfa.enabled);
            // Emailed one-time codes stand in for an authenticator only when nothing is enrolled and policy allows it.
            let tenant: Option<Tenant> =
                boxed(|| get(tx.as_ref(), "tenants", &active.tenant_id)).await?;
            let email_codes = !enabled
                && !active.root_admin
                && active
                    .email
                    .as_deref()
                    .is_some_and(|email| !email.is_empty())
                && active.email_verified
                && self.options.send_email.is_some()
                && tenant
                    .as_ref()
                    .and_then(|tenant| tenant.auth_policy.as_ref())
                    .and_then(|policy| policy.mfa_email_codes)
                    .or(self.options.mfa_email_codes)
                    .unwrap_or(false);
            let passkeys = boxed(|| self.passkey_factor(tx, &active)).await?;
            let mut payload = Map::new();
            if let Some(method) = method {
                payload.insert(
                    "method".to_owned(),
                    Value::String(method.as_str().to_owned()),
                );
            }
            if email_codes {
                payload.insert("emailCodes".to_owned(), Value::String("1".to_owned()));
            }
            let challenge = boxed(|| {
                self.challenge(
                    tx,
                    &active,
                    "mfa-login",
                    payload,
                    Some(5.0 * 60_000.0),
                    None,
                    None,
                )
            })
            .await?;
            return Ok(SignInResult::MfaRequired(MfaRequired {
                mfa_required: true,
                challenge,
                // A registered passkey is a second factor: the login challenge cannot enroll an authenticator over it.
                enrollment_required: !enabled && !passkeys,
                authenticator_enrolled: Some(enabled),
                email_code_available: email_codes.then_some(true),
                passkey_available: passkeys.then_some(true),
            }));
        }
        boxed(|| {
            self.issue_session(
                tx,
                &active,
                IssueSessionOptions {
                    method,
                    ..Default::default()
                },
            )
        })
        .await
        .map(SignInResult::Session)
    }

    /// `authenticate(input)`: resolves a bearer token or session cookie to its verified identity and session.
    pub async fn authenticate(&self, input: &CredentialInput) -> IamResult<AuthenticatedPrincipal> {
        let mut token = input.token.clone();
        if token.is_none() {
            match header(input, "authorization").filter(|value| !value.is_empty()) {
                Some(authorization) => {
                    let valid = authorization.len() > 7
                        && authorization.is_char_boundary(7)
                        && authorization[..7].eq_ignore_ascii_case("bearer ")
                        && authorization[7..]
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
                    if !valid {
                        return Err(IamError::with_status(
                            "UNAUTHENTICATED",
                            "Invalid credentials",
                            401,
                        ));
                    }
                    token = Some(authorization[7..].to_owned());
                }
                None => {
                    let prefix = format!("{}=", self.cookie_name);
                    token = header(input, "cookie").and_then(|cookie| {
                        cookie
                            .split(';')
                            .map(js::trim)
                            .find(|part| part.starts_with(&prefix))
                            .map(|part| part[prefix.len()..].to_owned())
                    });
                }
            }
        }
        let token = match token {
            Some(token) if token_shape(&token) => token,
            _ => {
                return Err(IamError::with_status(
                    "UNAUTHENTICATED",
                    "Invalid or missing credentials",
                    401,
                ));
            }
        };
        // A prefixed token with a bad shape or checksum is refused before any storage read.
        if token.starts_with("biam_") && parse_credential_token(&token).is_none() {
            return Err(IamError::with_status(
                "UNAUTHENTICATED",
                "Invalid or missing credentials",
                401,
            ));
        }
        let sink: MismatchSink = Arc::new(Mutex::new(None));
        let result = {
            let sink = sink.clone();
            let token = token.clone();
            self.store()
                .transaction(|tx| async move {
                    let session: Option<Session> = boxed(|| async {
                        find::<Session>(
                            tx.as_ref(),
                            "sessions",
                            &Filter::new().eq("tokenHash", hash_token(&token)),
                        )
                        .await
                    })
                    .await?
                    .into_iter()
                    .next();
                    boxed(|| self.validate_stored_session(&tx, session, Some(&sink))).await
                })
                .await
        };
        let principal = match result {
            Ok(principal) => principal,
            Err(error) => {
                let mismatch = sink
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take();
                if let Some(mismatch) = mismatch
                    && error.code == "SESSION_NETWORK_MISMATCH"
                {
                    boxed(|| self.record_session_mismatch(&mismatch)).await;
                }
                return Err(error);
            }
        };
        self.assert_request_host(&principal.session.tenant_id)?;
        Ok(principal)
    }

    /// `recordSessionMismatch`: notes in the person's trail that their bound session was presented from another
    /// network (`auth:session:mismatch`, with both addresses), in its own transaction; never fails.
    pub(crate) async fn record_session_mismatch(&self, mismatch: &SessionNetworkMismatch) {
        let mismatch = mismatch.clone();
        let _ = self
            .store()
            .transaction(|tx| async move {
                let identity: Option<Identity> =
                    get(tx.as_ref(), "identities", &mismatch.session.identity_id).await?;
                let Some(identity) = identity else {
                    return Ok(());
                };
                let mut metadata = Map::new();
                metadata.insert(
                    "sessionId".to_owned(),
                    Value::String(mismatch.session.id.clone()),
                );
                metadata.insert(
                    "sessionIp".to_owned(),
                    Value::String(
                        mismatch
                            .session
                            .client
                            .as_ref()
                            .and_then(|client| client.ip.clone())
                            .unwrap_or_default(),
                    ),
                );
                metadata.extend(self.client_metadata());
                self.audit(
                    &tx,
                    &identity,
                    "auth:session:mismatch",
                    None,
                    Some(metadata),
                )
                .await
            })
            .await;
    }

    /// `validateStoredSession(tx, session)`.
    pub(crate) async fn validate_stored_session(
        &self,
        tx: &Store,
        session: Option<Session>,
        mismatch: Option<&MismatchSink>,
    ) -> IamResult<AuthenticatedPrincipal> {
        let invalid =
            || IamError::with_status("UNAUTHENTICATED", "Invalid or expired credentials", 401);
        let mut session = match session {
            Some(session)
                if session.kind == SessionKind::User && session.expires_at > self.now() =>
            {
                session
            }
            _ => return Err(invalid()),
        };
        let tenant: Option<Tenant> =
            boxed(|| get(tx.as_ref(), "tenants", &session.tenant_id)).await?;
        let SessionLimits {
            lifetime_ms,
            idle_timeout_ms,
        } = self.session_limits(tenant.as_ref());
        // Both limits are judged against the tenant's current policy.
        if self.now() - session.last_seen_at >= idle_timeout_ms
            || self.now() - session.created_at >= lifetime_ms
        {
            return Err(invalid());
        }
        let identity =
            boxed(|| self.user(tx, &session.identity_id, Some(&session.tenant_id))).await?;
        if self.require_email_verification && !identity.email_verified {
            return Err(IamError::with_status(
                "EMAIL_UNVERIFIED",
                "Verify your email before signing in",
                403,
            ));
        }
        if boxed(|| self.mfa_required(tx, &identity)).await? && !session.mfa {
            return Err(IamError::with_status(
                "MFA_REQUIRED",
                "Multi-factor authentication is required",
                403,
            ));
        }
        boxed(|| self.assert_impersonation_source(tx, &session)).await?;
        // A session issued from a network the tenant no longer allows, or has since blocked, stops working.
        let session_ip = session.client.as_ref().and_then(|client| client.ip.clone());
        self.assert_ip_allowed(tenant.as_ref(), session_ip.as_deref())?;
        boxed(|| self.assert_network_not_blocked(tx, &session.tenant_id, session_ip.as_deref()))
            .await?;
        // The address presenting the cookie now is judged against network blocks too.
        let presented = self.client_ip().filter(|ip| !ip.is_empty());
        if let Some(presented) = &presented
            && Some(presented) != session_ip.as_ref()
        {
            boxed(|| self.assert_network_not_blocked(tx, &session.tenant_id, Some(presented)))
                .await?;
        }
        // Opt-in per tenant: the session works only from the network it was issued from.
        if tenant
            .as_ref()
            .and_then(|tenant| tenant.auth_policy.as_ref())
            .and_then(|policy| policy.bind_sessions_to_ip)
            == Some(true)
            && let (Some(original), Some(presented)) =
                (session_ip.as_ref().filter(|ip| !ip.is_empty()), &presented)
            && presented != original
        {
            if let Some(sink) = mismatch {
                *sink.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
                    Some(SessionNetworkMismatch {
                        session: session.clone(),
                    });
            }
            return Err(IamError::with_status(
                "SESSION_NETWORK_MISMATCH",
                "This session can only be used from the network it was signed in from",
                401,
            ));
        }
        // A touch at most every tenth of the idle window (at most once a minute).
        if self.now() - session.last_seen_at >= js_min(60_000.0, (idle_timeout_ms / 10.0).floor()) {
            session.last_seen_at = self.now();
            boxed(|| put(tx.as_ref(), "sessions", &session)).await?;
        }
        Ok(AuthenticatedPrincipal {
            identity,
            session,
            device_proof: None,
        })
    }

    /// `networkBlocks(reader, tenantId)`: the blocks that apply to a tenant, its own and the platform-wide ones, read
    /// through `reader` and cached briefly.
    pub(crate) async fn network_blocks(
        &self,
        reader: &Store,
        tenant_id: &str,
    ) -> IamResult<Vec<NetworkBlock>> {
        let now = self.now();
        {
            let cache = self
                .block_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some((at, blocks)) = cache.get(tenant_id)
                && now >= *at
                && now - at < BLOCK_CACHE_MS
            {
                return Ok(blocks.clone());
            }
        }
        let own: Vec<NetworkBlock> = find(
            reader.as_ref(),
            "authBlocks",
            &Filter::new().eq("tenantId", tenant_id),
        )
        .await?;
        let platform: Vec<NetworkBlock> = find(
            reader.as_ref(),
            "authBlocks",
            &Filter::new().eq("platform", true),
        )
        .await?;
        let mut blocks = own;
        blocks.extend(
            platform
                .into_iter()
                .filter(|block| block.tenant_id != tenant_id),
        );
        let mut cache = self
            .block_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if cache.len() >= 10_000 {
            cache.clear();
        }
        cache.insert(tenant_id.to_owned(), (now, blocks.clone()));
        Ok(blocks)
    }

    /// `invalidateNetworkBlocks()`: forgets the cached block lists so a change applies at once in this process.
    pub fn invalidate_network_blocks(&self) {
        self.block_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    /// `blockedNetwork(reader, tenantId, ip)`: the live block covering an IP for a tenant, if any; unknown IPs are
    /// never blocked.
    pub async fn blocked_network(
        &self,
        reader: &Store,
        tenant_id: &str,
        ip: Option<&str>,
    ) -> IamResult<Option<NetworkBlock>> {
        let Some(ip) = ip.filter(|ip| !ip.is_empty()) else {
            return Ok(None);
        };
        let now = self.now();
        Ok(self
            .network_blocks(reader, tenant_id)
            .await?
            .into_iter()
            .find(|block| {
                block.expires_at.is_none_or(|at| at > now)
                    && is_ip_range(&block.network)
                    && ip_matches(ip, &block.network)
            }))
    }

    /// `assertNetworkNotBlocked(reader, tenantId, ip)`: refuses a recorded client IP that a live block of the tenant
    /// or the platform covers (`IP_BLOCKED`).
    pub async fn assert_network_not_blocked(
        &self,
        reader: &Store,
        tenant_id: &str,
        ip: Option<&str>,
    ) -> IamResult<()> {
        if self.blocked_network(reader, tenant_id, ip).await?.is_some() {
            return Err(IamError::with_status(
                "IP_BLOCKED",
                "Sign-in from this network is blocked",
                403,
            ));
        }
        Ok(())
    }

    /// `assertIpAllowed(tenant, ip)`: refuses a recorded client IP outside the tenant's `allowedIpRanges`; unknown
    /// IPs are not judged.
    pub fn assert_ip_allowed(&self, tenant: Option<&Tenant>, ip: Option<&str>) -> IamResult<()> {
        let ranges = tenant
            .and_then(|tenant| tenant.auth_policy.as_ref())
            .and_then(|policy| policy.allowed_ip_ranges.as_ref());
        let (Some(ranges), Some(ip)) = (
            ranges.filter(|ranges| !ranges.is_empty()),
            ip.filter(|ip| !ip.is_empty()),
        ) else {
            return Ok(());
        };
        if !ranges.iter().any(|range| ip_matches(ip, range)) {
            return Err(IamError::with_status(
                "IP_NOT_ALLOWED",
                "Sign-in from this network is not permitted for this organization",
                403,
            ));
        }
        Ok(())
    }

    /// `validateSessionId(sessionId)`: internal protocol integrations only: revalidate the IAM session attached to a
    /// stored OAuth grant.
    pub async fn validate_session_id(&self, session_id: &str) -> IamResult<AuthenticatedPrincipal> {
        text_str(session_id, "sessionId", 512)?;
        let session_id = session_id.to_owned();
        self.store()
            .transaction(|tx| async move {
                let session: Option<Session> = get(tx.as_ref(), "sessions", &session_id).await?;
                self.validate_stored_session(&tx, session, None).await
            })
            .await
    }

    /// `requireRecent(principal)`: sensitive operations need a fresh authentication; an impersonated session never
    /// qualifies, and neither does a temporary credential, which carries its source's authentication time forward.
    pub fn require_recent(&self, principal: &AuthenticatedPrincipal) -> IamResult<()> {
        let session = &principal.session;
        if session
            .impersonator_id
            .as_deref()
            .is_some_and(|id| !id.is_empty())
        {
            return Err(IamError::with_status(
                "IMPERSONATION_RESTRICTED",
                "This operation is unavailable while impersonating a member",
                403,
            ));
        }
        if (session.kind != SessionKind::User && session.kind != SessionKind::ApiKey)
            || session.source_session_id.is_some()
        {
            return Err(IamError::with_status(
                "RECENT_AUTH_REQUIRED",
                "Temporary credentials cannot perform this operation; use a signed-in session",
                403,
            ));
        }
        let now = self.now();
        if now - session.authenticated_at > self.recent_lifetime || session.authenticated_at > now {
            return Err(IamError::with_status(
                "RECENT_AUTH_REQUIRED",
                "Reauthenticate to perform this operation",
                403,
            ));
        }
        Ok(())
    }

    /// `revokeIdentity(tx, identityId)`: revokes every session, pending challenge, and remembered device of an
    /// identity.
    pub async fn revoke_identity(&self, tx: &Store, identity_id: &str) -> IamResult<()> {
        let filter = Filter::new().eq("identityId", identity_id);
        for session in tx.find("sessions", &filter, &Default::default()).await? {
            self.end_session(tx, better_iam_core::record_id(&session))
                .await?;
        }
        for device in tx.find("authDevices", &filter, &Default::default()).await? {
            tx.delete("authDevices", better_iam_core::record_id(&device))
                .await?;
        }
        for challenge in tx
            .find("authChallenges", &filter, &Default::default())
            .await?
        {
            tx.delete("authChallenges", better_iam_core::record_id(&challenge))
                .await?;
        }
        Ok(())
    }
}

/// What `readChallenge` additionally requires of a challenge.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChallengeMatch<'a> {
    pub identity_id: Option<&'a str>,
    pub destination: Option<&'a str>,
}

/// `digestChallenge`: hex HMAC-SHA256(secret, `{tenantId}:{token}`).
pub fn digest_challenge(secret: &str, tenant_id: &str, token: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(format!("{tenant_id}:{token}").as_bytes());
    hex(mac.finalize().into_bytes())
}
