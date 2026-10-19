//! TOTP enrollment, verification, recovery codes, emailed one-time codes, and disabling where the tenant allows it
//! (`service/mfa.ts`, class `MfaAuth`).

use std::sync::Mutex;

use better_iam_core::{
    AuthMethod, AuthenticatedPrincipal, CredentialInput, Filter, IamError, IamResult, IamStoreExt,
    Identity, IdentityKind, OutboxKind, Tenant, js,
};
use serde::Serialize;
use serde_json::{Map, Value};
use subtle::ConstantTimeEq;

use super::AuthService;
use super::account::six_digit_code;
use super::base::{ChallengeMatch, IssueSessionOptions, RateTier};
use super::sessions::Success;
use crate::crypto::{decrypt_secret, encrypt_secret, hash_token, random_bytes};
use crate::totp;
use crate::types::{
    Challenge, MfaCredential, MfaRecord, MfaSessionResult, SafeSession, SessionResult,
    SignInFailureReason, TrustedDevice,
};
use crate::util::{Store, find, get, hex, insert, num, prop, put};
use crate::validation::text;

/// Who is changing MFA enrollment: a restricted login challenge (first factor passed) or a recently authenticated
/// session.
pub(crate) struct MfaActor {
    pub identity: Identity,
    pub principal: Option<AuthenticatedPrincipal>,
    pub login_challenge: Option<Challenge>,
}

/// What `beginMfa` returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MfaEnrollment {
    pub secret: String,
    pub uri: String,
}

/// `confirmMfa` input.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfirmMfaInput {
    pub credential: MfaCredential,
    pub code: String,
    pub remember_device: bool,
}

/// What `confirmMfa` returns: the new session, the device token when asked for, and the recovery codes.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmedMfa {
    pub token: String,
    pub session: SafeSession,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_expires_at: Option<f64>,
    pub recovery_codes: Vec<String>,
}

/// What `requestMfaCode` returns.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaCodeSent {
    pub success: bool,
    pub expires_at: f64,
}

/// What `mfaStatus` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaStatus {
    pub enabled: bool,
    pub recovery_codes_remaining: usize,
    pub passkeys: usize,
    pub trusted_devices: usize,
    pub session_mfa: bool,
}

/// `{ recoveryCodes }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCodes {
    pub recovery_codes: Vec<String>,
}

/// `{ verifiedAt }`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepUpVerified {
    pub verified_at: f64,
}

/// Ten recovery codes (24 hex characters each).
fn new_recovery_codes() -> Vec<String> {
    (0..10).map(|_| hex(random_bytes(12))).collect()
}

fn method_of(value: Option<&str>) -> Option<AuthMethod> {
    value.and_then(|method| serde_json::from_value(Value::String(method.to_owned())).ok())
}

/// `/^\d{6}$/`.
fn six_digits(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|c| c.is_ascii_digit())
}

/// The core of `checkTotp` for an opened secret: accepts a six-digit code of the current step or a neighbouring one
/// (window 1) whose step is later than `last_used_step`, and returns that step.
pub fn check_totp_code(secret: &str, code: &str, now: f64, last_used_step: f64) -> IamResult<f64> {
    if !six_digits(code) {
        return Err(IamError::with_status(
            "INVALID_MFA",
            "Invalid MFA code",
            401,
        ));
    }
    let delta = totp::check_delta(code, secret, now, 1);
    let step = (now / 30_000.0).floor() + delta.unwrap_or(0) as f64;
    if delta.is_none() || step <= last_used_step {
        return Err(IamError::with_status(
            "INVALID_MFA",
            "Invalid or previously used MFA code",
            401,
        ));
    }
    Ok(step)
}

impl AuthService {
    /// `mfaCodeDigest(challenge, code, secret)`: the stored form of an emailed MFA code, keyed with the deployment
    /// secret and bound to its login challenge.
    pub(crate) fn mfa_code_digest(
        &self,
        challenge: &Challenge,
        code: &str,
        secret: Option<&str>,
    ) -> String {
        self.digest_challenge(
            &challenge.tenant_id,
            &format!("mfa-code:{}:{code}", challenge.id),
            secret,
        )
    }

    /// `mfaActor(tx, credential)`: enrollment may start from a restricted login challenge or from a recently
    /// authenticated session.
    pub(crate) async fn mfa_actor(
        &self,
        tx: &Store,
        credential: &MfaCredential,
    ) -> IamResult<MfaActor> {
        match credential {
            MfaCredential::Challenge {
                tenant_id,
                challenge,
            } => {
                let login = self
                    .read_challenge(
                        tx,
                        tenant_id,
                        challenge,
                        "mfa-login",
                        ChallengeMatch::default(),
                    )
                    .await?;
                let identity = self.user(tx, &login.identity_id, Some(tenant_id)).await?;
                // A password alone must not add a factor over an existing one.
                let mfa: Option<MfaRecord> = get(tx.as_ref(), "authMfa", &identity.id).await?;
                if mfa.is_some_and(|mfa| mfa.enabled) || self.passkey_factor(tx, &identity).await? {
                    return Err(IamError::with_status(
                        "MFA_REQUIRED",
                        "Use an existing MFA factor before changing enrollment",
                        403,
                    ));
                }
                Ok(MfaActor {
                    identity,
                    principal: None,
                    login_challenge: Some(login),
                })
            }
            MfaCredential::Credential(credential) => {
                let principal = self.authenticate(credential).await?;
                self.require_recent(&principal)?;
                Ok(MfaActor {
                    identity: principal.identity.clone(),
                    principal: Some(principal),
                    login_challenge: None,
                })
            }
        }
    }

    /// `beginMfa(credential)`: a fresh authenticator secret (160 bits) and its `otpauth://` URI.
    pub async fn begin_mfa(&self, credential: &MfaCredential) -> IamResult<MfaEnrollment> {
        self.store()
            .transaction(|tx| async move {
                let actor = self.mfa_actor(&tx, credential).await?;
                let existing: Option<MfaRecord> =
                    get(tx.as_ref(), "authMfa", &actor.identity.id).await?;
                if existing.as_ref().is_some_and(|existing| existing.enabled) {
                    return Err(IamError::with_status(
                        "MFA_ALREADY_ENABLED",
                        "MFA is already enabled",
                        409,
                    ));
                }
                // 160 bits, as RFC 4226 recommends.
                let secret = totp::generate_secret(20);
                let credential_id = actor
                    .principal
                    .as_ref()
                    .map(|principal| principal.session.id.clone())
                    .or_else(|| actor.login_challenge.as_ref().map(|login| login.id.clone()))
                    .unwrap_or_default();
                let record = MfaRecord {
                    id: actor.identity.id.clone(),
                    tenant_id: actor.identity.tenant_id.clone(),
                    unique_key: None,
                    identity_id: actor.identity.id.clone(),
                    encrypted_secret: encrypt_secret(
                        &secret,
                        &self.options.secret,
                        &format!("mfa:{}", actor.identity.id),
                    ),
                    recovery_hashes: Vec::new(),
                    enabled: false,
                    last_used_step: -1.0,
                    enrollment_expires_at: Some(num(self.now() + 10.0 * 60_000.0)),
                    enrollment_credential: Some(Value::String(credential_id)),
                    extra: Map::new(),
                };
                if existing.is_some() {
                    put(tx.as_ref(), "authMfa", &record).await?;
                } else {
                    insert(tx.as_ref(), "authMfa", &record).await?;
                }
                let account = actor
                    .identity
                    .email
                    .clone()
                    .unwrap_or_else(|| actor.identity.id.clone());
                Ok(MfaEnrollment {
                    uri: totp::keyuri(&account, &self.app_name, &secret),
                    secret,
                })
            })
            .await
    }

    /// `checkTotp(record, code)`: accepts a code once per time step; the step is recorded so a captured code cannot
    /// be replayed.
    pub(crate) fn check_totp(&self, record: &MfaRecord, code: &str) -> IamResult<f64> {
        if !six_digits(code) {
            return Err(IamError::with_status(
                "INVALID_MFA",
                "Invalid MFA code",
                401,
            ));
        }
        let secret = decrypt_secret(
            &record.encrypted_secret,
            &self.secrets,
            &format!("mfa:{}", record.identity_id),
        )?;
        check_totp_code(&secret, code, self.now(), record.last_used_step)
    }

    /// `verifyStepUpCode(tx, identity, code)`: verifies a first-hand TOTP code for an MFA step-up on an existing
    /// credential, inside the caller's transaction. Only an enrolled authenticator counts; the code's time step is
    /// recorded. MFA_NOT_ENROLLED (403) without an enabled authenticator, INVALID_MFA (401) for a wrong or used code.
    pub async fn verify_step_up_code(
        &self,
        tx: &Store,
        identity: &Identity,
        code: &str,
    ) -> IamResult<StepUpVerified> {
        let record: Option<MfaRecord> = if identity.kind == IdentityKind::User {
            get(tx.as_ref(), "authMfa", &identity.id).await?
        } else {
            None
        };
        let mut record = match record {
            Some(record) if record.enabled && record.tenant_id == identity.tenant_id => record,
            _ => {
                return Err(IamError::with_status(
                    "MFA_NOT_ENROLLED",
                    "MFA is not enrolled",
                    403,
                ));
            }
        };
        record.last_used_step = self.check_totp(&record, code)?;
        put(tx.as_ref(), "authMfa", &record).await?;
        self.audit(tx, identity, "auth:mfa:step-up", None, None)
            .await?;
        Ok(StepUpVerified {
            verified_at: self.now(),
        })
    }

    /// `confirmMfa({ credential, code, rememberDevice })`: enables the authenticator, returns a new session and the
    /// recovery codes; `rememberDevice` returns a device token (when the tenant allows it).
    pub async fn confirm_mfa(&self, input: &ConfirmMfaInput) -> IamResult<ConfirmedMfa> {
        let actor = self
            .store()
            .transaction(|tx| async move { self.mfa_actor(&tx, &input.credential).await })
            .await?;
        self.rate(
            &actor.identity.tenant_id,
            &format!("mfa-enroll:{}", actor.identity.id),
            RateTier::Sensitive,
        )
        .await?;
        self.store()
            .transaction(|tx| async move {
                let verified = self.mfa_actor(&tx, &input.credential).await?;
                let record: Option<MfaRecord> =
                    get(tx.as_ref(), "authMfa", &verified.identity.id).await?;
                let expected = verified
                    .principal
                    .as_ref()
                    .map(|principal| principal.session.id.clone())
                    .or_else(|| {
                        verified
                            .login_challenge
                            .as_ref()
                            .map(|login| login.id.clone())
                    });
                let mut record = match record {
                    Some(record)
                        if !record.enabled
                            && record
                                .enrollment_expires_at
                                .as_ref()
                                .and_then(js::as_number)
                                .is_some_and(|at| at > self.now())
                            && record
                                .enrollment_credential
                                .as_ref()
                                .and_then(Value::as_str)
                                == expected.as_deref() =>
                    {
                        record
                    }
                    _ => {
                        return Err(IamError::with_status(
                            "INVALID_CHALLENGE",
                            "MFA enrollment is invalid or expired",
                            401,
                        ));
                    }
                };
                record.last_used_step = self.check_totp(&record, &input.code)?;
                record.enabled = true;
                let recovery_codes = new_recovery_codes();
                record.recovery_hashes =
                    recovery_codes.iter().map(|code| hash_token(code)).collect();
                put(tx.as_ref(), "authMfa", &record).await?;
                self.revoke_identity(&tx, &verified.identity.id).await?;
                self.audit(&tx, &verified.identity, "auth:mfa:enable", None, None)
                    .await?;
                let method = match &verified.login_challenge {
                    Some(login) => method_of(login.payload_str("method")),
                    None => None,
                }
                .or_else(|| {
                    verified
                        .principal
                        .as_ref()
                        .and_then(|principal| principal.session.method)
                });
                let session = self
                    .issue_session(
                        &tx,
                        &verified.identity,
                        IssueSessionOptions {
                            mfa: Some(true),
                            method,
                            ..Default::default()
                        },
                    )
                    .await?;
                let device = if input.remember_device {
                    self.remember_device(&tx, &verified.identity).await?
                } else {
                    None
                };
                let (device_token, device_expires_at) = match device {
                    Some(device) => (Some(device.device_token), Some(device.device_expires_at)),
                    None => (None, None),
                };
                Ok(ConfirmedMfa {
                    token: session.token,
                    session: session.session,
                    device_token,
                    device_expires_at,
                    recovery_codes,
                })
            })
            .await
    }

    /// `verifyMfa({ tenantId, challenge, code, rememberDevice? })`: completes a sign-in with the authenticator code,
    /// or with a code emailed for this very challenge when nothing is enrolled.
    pub async fn verify_mfa(&self, input: &Value) -> IamResult<MfaSessionResult> {
        let code = text(prop(input, "code"), "code", 6)?;
        let tenant_id = text(prop(input, "tenantId"), "tenantId", 512)?;
        let token = text(prop(input, "challenge"), "challenge", 512)?;
        let remember = prop(input, "rememberDevice") == Some(&Value::Bool(true));
        self.rate(
            &tenant_id,
            &format!("mfa:{}", hash_token(&token)),
            RateTier::Sensitive,
        )
        .await?;
        // Also per person: each correct password mints a new challenge with a fresh per-challenge budget.
        self.rate_challenge_identity(&tenant_id, &token, "mfa-login", "mfa-verify")
            .await?;
        // A wrong code for a real login challenge counts as a failed attempt once the refusal rolled back.
        let attempted: Mutex<Option<Identity>> = Mutex::new(None);
        let result = self
            .store()
            .transaction(|tx| {
                let attempted = &attempted;
                async move {
                    let challenge = self
                        .read_challenge(
                            &tx,
                            &tenant_id,
                            &token,
                            "mfa-login",
                            ChallengeMatch::default(),
                        )
                        .await?;
                    let identity = self
                        .user(&tx, &challenge.identity_id, Some(&tenant_id))
                        .await?;
                    *attempted
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(identity.clone());
                    let record: Option<MfaRecord> =
                        get(tx.as_ref(), "authMfa", &identity.id).await?;
                    match record {
                        Some(mut record) if record.enabled => {
                            record.last_used_step = self.check_totp(&record, &code)?;
                            put(tx.as_ref(), "authMfa", &record).await?;
                        }
                        _ => {
                            // No authenticator: only a code emailed for this very challenge can satisfy it.
                            let expected = challenge
                                .payload_str("codeHash")
                                .filter(|hash| !hash.is_empty());
                            let valid_until = challenge
                                .payload
                                .get("codeExpiresAt")
                                .map_or(f64::NAN, js::to_number);
                            let matches = expected.is_some_and(|expected| {
                                self.secrets.iter().any(|secret| {
                                    let provided =
                                        self.mfa_code_digest(&challenge, &code, Some(secret));
                                    expected.len() == provided.len()
                                        && bool::from(
                                            expected.as_bytes().ct_eq(provided.as_bytes()),
                                        )
                                })
                            });
                            if expected.is_none()
                                || valid_until.partial_cmp(&self.now())
                                    != Some(std::cmp::Ordering::Greater)
                                || !matches
                            {
                                return Err(if expected.is_some() {
                                    IamError::with_status(
                                        "INVALID_MFA",
                                        "Invalid or expired code",
                                        401,
                                    )
                                } else {
                                    IamError::with_status(
                                        "MFA_NOT_ENROLLED",
                                        "MFA is not enrolled",
                                        403,
                                    )
                                });
                            }
                        }
                    }
                    tx.delete("authChallenges", &challenge.id).await?;
                    let session = self
                        .issue_session(
                            &tx,
                            &identity,
                            IssueSessionOptions {
                                mfa: Some(true),
                                method: method_of(challenge.payload_str("method")),
                                ..Default::default()
                            },
                        )
                        .await?;
                    let device = if remember {
                        self.remember_device(&tx, &identity).await?
                    } else {
                        None
                    };
                    Ok(MfaSessionResult::from_session(session, device))
                }
            })
            .await;
        if let Err(error) = &result
            && error.code == "INVALID_MFA"
            && let Some(identity) = attempted
                .into_inner()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            self.defer_sign_in_failure(identity, SignInFailureReason::Mfa);
        }
        result
    }

    /// `requestMfaCode({ tenantId, challenge })`: emails a six-digit one-time code for a login challenge whose
    /// sign-in offered `emailCodeAvailable`; `verifyMfa` then accepts it once, within ten minutes and before the
    /// challenge itself expires. Requesting again replaces the code.
    pub async fn request_mfa_code(&self, input: &Value) -> IamResult<MfaCodeSent> {
        let tenant_id = text(prop(input, "tenantId"), "tenantId", 512)?;
        let token = text(prop(input, "challenge"), "challenge", 512)?;
        self.rate(
            &tenant_id,
            &format!("mfa-code:{}", hash_token(&token)),
            RateTier::Sensitive,
        )
        .await?;
        // Per person too, so repeated sign-ins cannot queue unbounded code emails to the account's inbox.
        self.rate_challenge_identity(&tenant_id, &token, "mfa-login", "mfa-code-send")
            .await?;
        self.store()
            .transaction(|tx| async move {
                let mut challenge = self
                    .read_challenge(
                        &tx,
                        &tenant_id,
                        &token,
                        "mfa-login",
                        ChallengeMatch::default(),
                    )
                    .await?;
                if challenge.payload_str("emailCodes") != Some("1") {
                    return Err(IamError::with_status(
                        "FEATURE_DISABLED",
                        "Emailed codes are not available for this sign-in",
                        403,
                    ));
                }
                let identity = self
                    .user(&tx, &challenge.identity_id, Some(&tenant_id))
                    .await?;
                let address = match identity.email.clone().filter(|email| !email.is_empty()) {
                    Some(address) if identity.email_verified => address,
                    _ => {
                        return Err(IamError::with_status(
                            "FEATURE_DISABLED",
                            "A verified email address is required",
                            403,
                        ));
                    }
                };
                let code = six_digit_code();
                let limit = self.now() + 10.0 * 60_000.0;
                let expires_at = if challenge.expires_at.is_nan() {
                    f64::NAN
                } else {
                    challenge.expires_at.min(limit)
                };
                let digest = self.mfa_code_digest(&challenge, &code, None);
                challenge
                    .payload
                    .insert("codeHash".to_owned(), Value::String(digest));
                challenge.payload.insert(
                    "codeExpiresAt".to_owned(),
                    Value::String(js::number_to_string(expires_at)),
                );
                put(tx.as_ref(), "authChallenges", &challenge).await?;
                let mut payload = Map::new();
                payload.insert("code".to_owned(), Value::String(code));
                self.enqueue(
                    &tx,
                    &identity,
                    OutboxKind::Email,
                    &address,
                    "mfa-code",
                    payload,
                )
                .await?;
                Ok(MfaCodeSent {
                    success: true,
                    expires_at,
                })
            })
            .await
    }

    /// `recoverMfa({ tenantId, challenge, code })`: completes a sign-in with a recovery code, which is used up.
    pub async fn recover_mfa(&self, input: &Value) -> IamResult<SessionResult> {
        let code = text(prop(input, "code"), "code", 128)?;
        let tenant_id = text(prop(input, "tenantId"), "tenantId", 512)?;
        let token = text(prop(input, "challenge"), "challenge", 512)?;
        self.rate(
            &tenant_id,
            &format!("mfa-recover:{}", hash_token(&token)),
            RateTier::Sensitive,
        )
        .await?;
        self.rate_challenge_identity(&tenant_id, &token, "mfa-login", "mfa-recovery")
            .await?;
        let attempted: Mutex<Option<Identity>> = Mutex::new(None);
        let result = self
            .store()
            .transaction(|tx| {
                let attempted = &attempted;
                async move {
                    let challenge = self
                        .read_challenge(
                            &tx,
                            &tenant_id,
                            &token,
                            "mfa-login",
                            ChallengeMatch::default(),
                        )
                        .await?;
                    let identity = self
                        .user(&tx, &challenge.identity_id, Some(&tenant_id))
                        .await?;
                    *attempted
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(identity.clone());
                    let record: Option<MfaRecord> =
                        get(tx.as_ref(), "authMfa", &identity.id).await?;
                    let code_hash = hash_token(&code);
                    let index = record.as_ref().and_then(|record| {
                        record.recovery_hashes.iter().position(|value| {
                            value.len() == code_hash.len()
                                && bool::from(value.as_bytes().ct_eq(code_hash.as_bytes()))
                        })
                    });
                    let (mut record, index) = match (record, index) {
                        (Some(record), Some(index)) if record.enabled => (record, index),
                        _ => {
                            return Err(IamError::with_status(
                                "INVALID_MFA",
                                "Invalid recovery code",
                                401,
                            ));
                        }
                    };
                    record.recovery_hashes.remove(index);
                    put(tx.as_ref(), "authMfa", &record).await?;
                    tx.delete("authChallenges", &challenge.id).await?;
                    self.audit(&tx, &identity, "auth:mfa:recover", None, None)
                        .await?;
                    self.issue_session(
                        &tx,
                        &identity,
                        IssueSessionOptions {
                            mfa: Some(true),
                            method: method_of(challenge.payload_str("method")),
                            ..Default::default()
                        },
                    )
                    .await
                }
            })
            .await;
        if let Err(error) = &result
            && error.code == "INVALID_MFA"
            && let Some(identity) = attempted
                .into_inner()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            self.defer_sign_in_failure(identity, SignInFailureReason::RecoveryCode);
        }
        result
    }

    /// `mfaStatus(credentials)`: what the caller has set up: authenticator state, unused recovery codes, passkeys, and
    /// remembered devices.
    pub async fn mfa_status(&self, credentials: &CredentialInput) -> IamResult<MfaStatus> {
        let principal = self.authenticate(credentials).await?;
        let scope = Filter::new()
            .eq("tenantId", principal.identity.tenant_id.clone())
            .eq("identityId", principal.identity.id.clone());
        let record: Option<MfaRecord> =
            get(self.store().as_ref(), "authMfa", &principal.identity.id).await?;
        let enabled = record.as_ref().is_some_and(|record| record.enabled);
        let passkeys = self
            .store()
            .find("authPasskeys", &scope, &Default::default())
            .await?
            .len();
        let now = self.now();
        let trusted_devices = find::<TrustedDevice>(self.store().as_ref(), "authDevices", &scope)
            .await?
            .iter()
            .filter(|device| device.expires_at > now)
            .count();
        Ok(MfaStatus {
            enabled,
            recovery_codes_remaining: if enabled {
                record.map_or(0, |record| record.recovery_hashes.len())
            } else {
                0
            },
            passkeys,
            trusted_devices,
            session_mfa: principal.session.mfa,
        })
    }

    /// `regenerateRecoveryCodes(credentials)`: replaces the recovery codes.
    pub async fn regenerate_recovery_codes(
        &self,
        credentials: &CredentialInput,
    ) -> IamResult<RecoveryCodes> {
        self.store()
            .transaction(|tx| async move {
                let principal = self.authenticate(credentials).await?;
                self.require_recent(&principal)?;
                if !principal.session.mfa {
                    return Err(IamError::with_status(
                        "MFA_REQUIRED",
                        "Multi-factor authentication is required",
                        403,
                    ));
                }
                let record: Option<MfaRecord> =
                    get(tx.as_ref(), "authMfa", &principal.identity.id).await?;
                let mut record = match record {
                    Some(record) if record.enabled => record,
                    _ => {
                        return Err(IamError::with_status(
                            "MFA_NOT_ENROLLED",
                            "MFA is not enrolled",
                            403,
                        ));
                    }
                };
                let recovery_codes = new_recovery_codes();
                record.recovery_hashes =
                    recovery_codes.iter().map(|code| hash_token(code)).collect();
                put(tx.as_ref(), "authMfa", &record).await?;
                self.audit(
                    &tx,
                    &principal.identity,
                    "auth:mfa:recovery-codes",
                    None,
                    None,
                )
                .await?;
                Ok(RecoveryCodes { recovery_codes })
            })
            .await
    }

    /// `disableMfa(credentials)`: removes the authenticator where neither the person nor the tenant requires MFA.
    pub async fn disable_mfa(&self, credentials: &CredentialInput) -> IamResult<Success> {
        self.store()
            .transaction(|tx| async move {
                let principal = self.authenticate(credentials).await?;
                self.require_recent(&principal)?;
                if !principal.session.mfa {
                    return Err(IamError::with_status(
                        "MFA_REQUIRED",
                        "Multi-factor authentication is required",
                        403,
                    ));
                }
                let tenant: Option<Tenant> =
                    get(tx.as_ref(), "tenants", &principal.identity.tenant_id).await?;
                let required = principal.identity.root_admin
                    || match &tenant {
                        Some(tenant) => {
                            self.tenant_requires_mfa(tenant, &principal.identity)
                                .await?
                        }
                        None => return Err(crate::util::internal_error()),
                    };
                if required {
                    return Err(IamError::with_status(
                        "MFA_REQUIRED",
                        "MFA is required by this tenant",
                        403,
                    ));
                }
                tx.delete("authMfa", &principal.identity.id).await?;
                self.revoke_identity(&tx, &principal.identity.id).await?;
                self.audit(&tx, &principal.identity, "auth:mfa:disable", None, None)
                    .await?;
                Ok(Success::TRUE)
            })
            .await
    }
}
