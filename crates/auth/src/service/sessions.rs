//! Password sign-up and sign-in, plus session listing and revocation (`service/sessions.ts`, class `SessionAuth`).

use std::sync::Mutex;

use better_iam_core::boxed;
use better_iam_core::{
    AuthMethod, CredentialInput, Filter, IamError, IamResult, IamStoreExt, Identity, IdentityKind,
    IdentityStatus, OutboxKind, Record, Session, Tenant, js,
};
use serde::Serialize;
use serde_json::{Map, Value};

use super::AuthService;
use super::base::{CreateIdentityRaw, RateTier};
use crate::passwords;
use crate::types::{
    SafeIdentity, SafeSession, SafeTrustedDevice, SignInFailureReason, SignInResult, TrustedDevice,
};
use crate::util::{by_number_then_id, find, get, js_less, prop, put};
use crate::validation::{email, public_identity, public_session, text};

/// `{ success: true }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Success {
    pub success: bool,
}

impl Success {
    pub const TRUE: Success = Success { success: true };
}

/// What `signUp` returns.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignUpResult {
    pub identity: SafeIdentity,
    pub verification_required: bool,
}

/// One entry of `listSecurityEvents`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEvent {
    pub id: String,
    pub action: String,
    pub timestamp: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonator_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Map<String, Value>>,
}

/// `{ revoked }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Revoked {
    pub revoked: usize,
}

/// The limits `getSession` reports.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionLimitsInfo {
    pub lifetime_ms: f64,
    pub idle_timeout_ms: f64,
    /// When the session lapses if nothing touches it again (this call just did).
    pub idle_expires_at: f64,
    /// The server's clock when it answered, so clients can correct for their own clock skew.
    pub now: f64,
}

/// What `getSession` returns.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SessionInfo {
    pub identity: SafeIdentity,
    pub session: SafeSession,
    pub limits: SessionLimitsInfo,
}

/// One entry of `listSessions`: the session, and whether it is the one making the call.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListedSession {
    #[serde(flatten)]
    pub session: SafeSession,
    pub current: bool,
}

/// `input.key === undefined ? undefined : text(input.key, field, max)`.
pub(crate) fn optional_text(
    input: &Value,
    key: &str,
    field: &str,
    max: usize,
) -> IamResult<Option<String>> {
    match prop(input, key) {
        None => Ok(None),
        Some(value) => text(Some(value), field, max).map(Some),
    }
}

impl AuthService {
    /// `signUp(input)`: self-registration with a password (`{ tenantId, email, name, password }`).
    pub async fn sign_up(&self, input: &Value) -> IamResult<SignUpResult> {
        if self.options.sign_up_enabled != Some(true) || self.options.email_password == Some(false)
        {
            return Err(IamError::with_status(
                "FEATURE_DISABLED",
                "Self registration is disabled",
                403,
            ));
        }
        let tenant_id = text(prop(input, "tenantId"), "tenantId", 512)?;
        let normalized = email(prop(input, "email"))?;
        self.rate(
            &tenant_id,
            &format!("signup:{normalized}"),
            RateTier::Sensitive,
        )
        .await?;
        self.store()
            .transaction(|tx| async move {
                self.assert_tenant_active(&tx, &tenant_id).await?;
                let tenant: Option<Tenant> = get(tx.as_ref(), "tenants", &tenant_id).await?;
                if tenant
                    .and_then(|tenant| tenant.parent_id)
                    .is_none_or(|parent| parent.is_empty())
                {
                    return Err(IamError::with_status(
                        "FORBIDDEN",
                        "Root identity provisioning requires an administrator",
                        403,
                    ));
                }
                let mut identity = self
                    .create_identity_raw(
                        &tx,
                        CreateIdentityRaw {
                            tenant_id: Some(&Value::String(tenant_id.clone())),
                            email: Some(&Value::String(normalized.clone())),
                            name: prop(input, "name"),
                            password: prop(input, "password"),
                            owner: false,
                            root_admin: false,
                            email_verified: false,
                        },
                    )
                    .await?;
                // Nobody has proven this address yet: see Identity.unprovenPassword (finishPasswordless acts on it).
                identity.unproven_password = Some(true);
                put(tx.as_ref(), "identities", &identity).await?;
                if self.require_email_verification {
                    let mut payload = Map::new();
                    payload.insert("email".to_owned(), Value::String(normalized.clone()));
                    let token = self
                        .challenge(
                            &tx,
                            &identity,
                            "verify-email",
                            payload,
                            Some(24.0 * 60.0 * 60_000.0),
                            None,
                            None,
                        )
                        .await?;
                    let mut delivery = Map::new();
                    delivery.insert("token".to_owned(), Value::String(token));
                    self.enqueue(
                        &tx,
                        &identity,
                        OutboxKind::Email,
                        &normalized,
                        "verify-email",
                        delivery,
                    )
                    .await?;
                }
                Ok(SignUpResult {
                    identity: public_identity(&identity),
                    verification_required: self.require_email_verification,
                })
            })
            .await
    }

    /// `signIn(input)`: `{ tenantId, email, password, deviceToken? }`; `deviceToken` (from "remember this device")
    /// lets a browser that completed MFA before skip the second factor.
    pub async fn sign_in(&self, input: &Value) -> IamResult<SignInResult> {
        if self.options.email_password == Some(false) {
            return Err(IamError::with_status(
                "FEATURE_DISABLED",
                "Password authentication is disabled",
                403,
            ));
        }
        let tenant_id = text(prop(input, "tenantId"), "tenantId", 512)?;
        let normalized = email(prop(input, "email"))?;
        let password = text(prop(input, "password"), "password", 1024)?;
        let device_token = optional_text(input, "deviceToken", "deviceToken", 512)?;
        self.rate(
            &tenant_id,
            &format!("signin:{normalized}"),
            RateTier::Default,
        )
        .await?;
        // A wrong password for a real, active account is counted after the refused transaction rolled back, without
        // holding the refusal (an unknown address writes nothing, so waiting would reveal which accounts exist).
        let failed: Mutex<Option<Identity>> = Mutex::new(None);
        let result = self
            .store()
            .transaction(|tx| {
                let failed = &failed;
                let password = password.clone();
                async move {
                    self.assert_tenant_active(&tx, &tenant_id).await?;
                    self.method_allowed(&tx, &tenant_id, AuthMethod::Password)
                        .await?;
                    let identity: Option<Identity> = find::<Identity>(
                        tx.as_ref(),
                        "identities",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("email", normalized.clone()),
                    )
                    .await?
                    .into_iter()
                    .next();
                    // Unknown and passwordless-only accounts perform the same password-hash operation.
                    let digest = match identity
                        .as_ref()
                        .and_then(|identity| identity.password_hash.clone())
                    {
                        Some(hash) => hash,
                        None => self.dummy_hash().await?,
                    };
                    let valid = passwords::verify(&digest, &password).await?;
                    // An expired identity is refused like a disabled one (and, like it, leaves no failure record).
                    let usable = identity.as_ref().is_some_and(|identity| {
                        identity.status == IdentityStatus::Active
                            && !self.identity_expired(identity)
                    });
                    let identity = match identity {
                        Some(identity) if valid && usable => identity,
                        other => {
                            if let Some(identity) = other
                                && !valid
                                && identity.kind == IdentityKind::User
                                && usable
                            {
                                *failed
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                                    Some(identity);
                            }
                            return Err(IamError::with_status(
                                "INVALID_CREDENTIALS",
                                "Invalid email or password",
                                401,
                            ));
                        }
                    };
                    if self.require_email_verification && !identity.email_verified {
                        return Err(IamError::with_status(
                            "EMAIL_UNVERIFIED",
                            "Verify your email before signing in",
                            403,
                        ));
                    }
                    self.assert_password_current(&tx, &identity).await?;
                    self.complete_authentication(
                        &tx,
                        &identity,
                        Some(AuthMethod::Password),
                        device_token.as_deref(),
                    )
                    .await
                }
            })
            .await;
        if result.is_err()
            && let Some(identity) = failed
                .into_inner()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            self.defer_sign_in_failure(identity, SignInFailureReason::Password);
        }
        result
    }

    /// `listSecurityEvents(credentials, { limit })`: the caller's own authentication trail, newest first: the
    /// `auth:*` audit events recorded for their identity in this tenant, with the administrator named when one acted
    /// through impersonation and the event's `metadata`.
    pub async fn list_security_events(
        &self,
        credentials: &CredentialInput,
        input: &Value,
    ) -> IamResult<Vec<SecurityEvent>> {
        let limit = match prop(input, "limit") {
            None | Some(Value::Null) => 50.0,
            Some(Value::Number(number)) => js::number_value(number),
            Some(_) => f64::NAN,
        };
        if !js::is_safe_integer(limit) || !(1.0..=200.0).contains(&limit) {
            return Err(IamError::new(
                "INVALID_INPUT",
                "limit must be an integer between 1 and 200",
            ));
        }
        let principal = boxed(|| self.authenticate(credentials)).await?;
        let mut events: Vec<Record> = boxed(|| async {
            self.store()
                .find(
                    "audit",
                    &Filter::new()
                        .eq("tenantId", principal.identity.tenant_id.clone())
                        .eq("actorId", principal.identity.id.clone()),
                    &Default::default(),
                )
                .await
        })
        .await?
        .into_iter()
        .filter(|event| {
            event
                .get("action")
                .and_then(Value::as_str)
                .is_some_and(|action| action.starts_with("auth:"))
        })
        .collect();
        let timestamp = |event: &Record| {
            event
                .get("timestamp")
                .and_then(js::as_number)
                .unwrap_or(f64::NAN)
        };
        let id = |event: &Record| {
            event
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        };
        events.sort_by(|a, b| {
            let delta = timestamp(b) - timestamp(a);
            if delta != 0.0 && !delta.is_nan() {
                return if delta < 0.0 {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                };
            }
            if js_less(&id(a), &id(b)) {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Less
            }
        });
        Ok(events
            .into_iter()
            .take(limit as usize)
            .map(|event| SecurityEvent {
                id: id(&event),
                action: event
                    .get("action")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                timestamp: timestamp(&event),
                impersonator_id: event
                    .get("impersonatorId")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned),
                sequence: event.get("sequence").and_then(js::as_number),
                metadata: event.get("metadata").and_then(Value::as_object).cloned(),
            })
            .collect())
    }

    /// `listTrustedDevices(credentials)`: remembered devices of the caller in this tenant, newest first, without their
    /// tokens.
    pub async fn list_trusted_devices(
        &self,
        credentials: &CredentialInput,
    ) -> IamResult<Vec<SafeTrustedDevice>> {
        let principal = self.authenticate(credentials).await?;
        let now = self.now();
        let mut devices: Vec<TrustedDevice> = find::<TrustedDevice>(
            self.store().as_ref(),
            "authDevices",
            &Filter::new()
                .eq("identityId", principal.identity.id.clone())
                .eq("tenantId", principal.identity.tenant_id.clone()),
        )
        .await?
        .into_iter()
        .filter(|device| device.expires_at > now)
        .collect();
        devices.sort_by(|a, b| by_number_then_id((b.last_used_at, &a.id), (a.last_used_at, &b.id)));
        Ok(devices.iter().map(SafeTrustedDevice::new).collect())
    }

    /// `revokeTrustedDevice(credentials, { deviceId })`: forgets one remembered device; the next sign-in from it asks
    /// for MFA again. Requires recent authentication.
    pub async fn revoke_trusted_device(
        &self,
        credentials: &CredentialInput,
        input: &Value,
    ) -> IamResult<Success> {
        self.store()
            .transaction(|tx| async move {
                let principal = self.authenticate(credentials).await?;
                self.require_recent(&principal)?;
                let device_id = text(prop(input, "deviceId"), "deviceId", 512)?;
                let device: Option<TrustedDevice> =
                    get(tx.as_ref(), "authDevices", &device_id).await?;
                let device = match device {
                    Some(device)
                        if device.identity_id == principal.identity.id
                            && device.tenant_id == principal.identity.tenant_id =>
                    {
                        device
                    }
                    _ => return Err(IamError::with_status("NOT_FOUND", "Device not found", 404)),
                };
                tx.delete("authDevices", &device.id).await?;
                self.audit(&tx, &principal.identity, "auth:device:revoke", None, None)
                    .await?;
                Ok(Success::TRUE)
            })
            .await
    }

    /// `revokeTrustedDevices(credentials)`: forgets every remembered device of the caller. Requires recent
    /// authentication.
    pub async fn revoke_trusted_devices(
        &self,
        credentials: &CredentialInput,
    ) -> IamResult<Revoked> {
        self.store()
            .transaction(|tx| async move {
                let principal = self.authenticate(credentials).await?;
                self.require_recent(&principal)?;
                let devices = tx
                    .find(
                        "authDevices",
                        &Filter::new()
                            .eq("identityId", principal.identity.id.clone())
                            .eq("tenantId", principal.identity.tenant_id.clone()),
                        &Default::default(),
                    )
                    .await?;
                for device in &devices {
                    tx.delete("authDevices", better_iam_core::record_id(device))
                        .await?;
                }
                if !devices.is_empty() {
                    self.audit(&tx, &principal.identity, "auth:device:revoke", None, None)
                        .await?;
                }
                Ok(Revoked {
                    revoked: devices.len(),
                })
            })
            .await
    }

    /// `getSession(credentials)`: the caller's identity and session, plus the limits in force for their tenant.
    pub async fn get_session(&self, credentials: &CredentialInput) -> IamResult<SessionInfo> {
        let principal = self.authenticate(credentials).await?;
        let tenant: Option<Tenant> = get(
            self.store().as_ref(),
            "tenants",
            &principal.identity.tenant_id,
        )
        .await?;
        let limits = self.session_limits(tenant.as_ref());
        let idle = principal.session.last_seen_at + limits.idle_timeout_ms;
        let idle_expires_at = if idle.is_nan() || principal.session.expires_at.is_nan() {
            f64::NAN
        } else {
            idle.min(principal.session.expires_at)
        };
        Ok(SessionInfo {
            identity: public_identity(&principal.identity),
            session: public_session(&principal.session),
            limits: SessionLimitsInfo {
                lifetime_ms: limits.lifetime_ms,
                idle_timeout_ms: limits.idle_timeout_ms,
                idle_expires_at,
                now: self.now(),
            },
        })
    }

    /// `listSessions(credentials)`: the caller's live sessions; `current` marks the one making this call.
    pub async fn list_sessions(
        &self,
        credentials: &CredentialInput,
    ) -> IamResult<Vec<ListedSession>> {
        let principal = self.authenticate(credentials).await?;
        let now = self.now();
        Ok(find::<Session>(
            self.store().as_ref(),
            "sessions",
            &Filter::new()
                .eq("identityId", principal.identity.id.clone())
                .eq("tenantId", principal.identity.tenant_id.clone()),
        )
        .await?
        .into_iter()
        .filter(|session| session.expires_at > now)
        .map(|session| ListedSession {
            current: session.id == principal.session.id,
            session: public_session(&session),
        })
        .collect())
    }

    /// `revokeSession(credentials, { sessionId })`.
    pub async fn revoke_session(
        &self,
        credentials: &CredentialInput,
        input: &Value,
    ) -> IamResult<Success> {
        self.store()
            .transaction(|tx| async move {
                let principal = self.authenticate(credentials).await?;
                self.require_recent(&principal)?;
                let session_id = text(prop(input, "sessionId"), "sessionId", 512)?;
                let session: Option<Session> = get(tx.as_ref(), "sessions", &session_id).await?;
                let session = match session {
                    Some(session)
                        if session.identity_id == principal.identity.id
                            && session.tenant_id == principal.identity.tenant_id =>
                    {
                        session
                    }
                    _ => return Err(IamError::with_status("NOT_FOUND", "Session not found", 404)),
                };
                self.end_session(&tx, &session.id).await?;
                self.audit(&tx, &principal.identity, "auth:session:revoke", None, None)
                    .await?;
                Ok(Success::TRUE)
            })
            .await
    }

    /// `revokeOtherSessions(credentials)`: ends every other user session of the caller's identity in this tenant
    /// ("sign out everywhere else").
    pub async fn revoke_other_sessions(&self, credentials: &CredentialInput) -> IamResult<Revoked> {
        self.store()
            .transaction(|tx| async move {
                let principal = self.authenticate(credentials).await?;
                self.require_recent(&principal)?;
                let mut revoked = 0;
                let sessions = tx
                    .find(
                        "sessions",
                        &Filter::new()
                            .eq("identityId", principal.identity.id.clone())
                            .eq("tenantId", principal.identity.tenant_id.clone())
                            .eq("kind", "user"),
                        &Default::default(),
                    )
                    .await?;
                for session in sessions {
                    let id = better_iam_core::record_id(&session);
                    if id != principal.session.id {
                        self.end_session(&tx, id).await?;
                        revoked += 1;
                    }
                }
                self.audit(
                    &tx,
                    &principal.identity,
                    "auth:session:revoke-others",
                    None,
                    None,
                )
                .await?;
                Ok(Revoked { revoked })
            })
            .await
    }

    /// `signOut(credentials)`.
    pub async fn sign_out(&self, credentials: &CredentialInput) -> IamResult<Success> {
        self.store()
            .transaction(|tx| async move {
                let principal = self.authenticate(credentials).await?;
                self.end_session(&tx, &principal.session.id).await?;
                self.audit(
                    &tx,
                    &principal.identity,
                    "auth:session:revoke",
                    Some(&principal.session),
                    None,
                )
                .await?;
                Ok(Success::TRUE)
            })
            .await
    }
}
