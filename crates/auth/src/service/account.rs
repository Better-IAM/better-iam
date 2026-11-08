//! Email verification, password recovery and change, reauthentication, and email/phone changes
//! (`service/account.ts`, class `AccountAuth`).

use std::sync::Mutex;

use better_iam_core::boxed;
use better_iam_core::{
    AuthMethod, CredentialInput, Filter, IamError, IamResult, IamStoreExt, Identity, IdentityKind,
    IdentityStatus, OutboxKind, Session, Tenant,
};
use rand::Rng;
use serde_json::{Map, Value};

use super::AuthService;
use super::base::{ChallengeMatch, RateTier};
use super::sessions::Success;
use crate::crypto::hash_token;
use crate::passwords;
use crate::types::{Challenge, SignInFailureReason, SignInResult};
use crate::util::{Store, find, get, prop, put};
use crate::validation::{email, password, phone, text};

/// `randomInt(0, 1_000_000).toString().padStart(6, '0')`: a six-digit one-time code.
pub(crate) fn six_digit_code() -> String {
    format!("{:06}", rand::rngs::OsRng.gen_range(0..1_000_000u32))
}

fn single(key: &str, value: impl Into<String>) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert(key.to_owned(), Value::String(value.into()));
    map
}

/// The active people with this address in this tenant (`{ tenantId, email, status: 'active', kind: 'user' }`).
async fn active_person(tx: &Store, tenant_id: &str, address: &str) -> IamResult<Option<Identity>> {
    Ok(find::<Identity>(
        tx.as_ref(),
        "identities",
        &Filter::new()
            .eq("tenantId", tenant_id)
            .eq("email", address)
            .eq("status", "active")
            .eq("kind", "user"),
    )
    .await?
    .into_iter()
    .next())
}

impl AuthService {
    /// `requestEmailVerification({ tenantId, email })`.
    pub async fn request_email_verification(&self, input: &Value) -> IamResult<Success> {
        let tenant_id = text(prop(input, "tenantId"), "tenantId", 512)?;
        let normalized = email(prop(input, "email"))?;
        if self.options.send_email.is_none() {
            return Err(IamError::new(
                "FEATURE_DISABLED",
                "Email delivery is not configured",
            ));
        }
        self.rate(
            &tenant_id,
            &format!("verify-email:{normalized}"),
            RateTier::Sensitive,
        )
        .await?;
        self.store()
            .transaction(|tx| async move {
                self.assert_tenant_active(&tx, &tenant_id).await?;
                if let Some(identity) = active_person(&tx, &tenant_id, &normalized).await?
                    && !identity.email_verified
                {
                    let token = self
                        .challenge(
                            &tx,
                            &identity,
                            "verify-email",
                            single("email", normalized.clone()),
                            Some(24.0 * 60.0 * 60_000.0),
                            None,
                            None,
                        )
                        .await?;
                    self.enqueue(
                        &tx,
                        &identity,
                        OutboxKind::Email,
                        &normalized,
                        "verify-email",
                        single("token", token),
                    )
                    .await?;
                }
                Ok(Success::TRUE)
            })
            .await
    }

    /// `verifyEmail({ tenantId, token })`.
    pub async fn verify_email(&self, input: &Value) -> IamResult<Success> {
        let tenant_id = text(prop(input, "tenantId"), "tenantId", 512)?;
        let token = text(prop(input, "token"), "token", 512)?;
        self.rate(
            &tenant_id,
            &format!("verify-token:{}", hash_token(&token)),
            RateTier::Default,
        )
        .await?;
        self.store()
            .transaction(|tx| async move {
                let challenge = self
                    .read_challenge(
                        &tx,
                        &tenant_id,
                        &token,
                        "verify-email",
                        ChallengeMatch::default(),
                    )
                    .await?;
                let mut identity = self
                    .user(&tx, &challenge.identity_id, Some(&tenant_id))
                    .await?;
                // The link proves control of the address it was mailed to, and only that one.
                assert_same_address(&challenge, &identity)?;
                identity.email_verified = true;
                // The address owner completed the sign-up themselves, so the password they chose stands.
                identity.unproven_password = None;
                put(tx.as_ref(), "identities", &identity).await?;
                tx.delete("authChallenges", &challenge.id).await?;
                self.audit(&tx, &identity, "auth:email:verify", None, None)
                    .await?;
                Ok(Success::TRUE)
            })
            .await
    }

    /// `requestPasswordReset({ tenantId, email })`.
    pub async fn request_password_reset(&self, input: &Value) -> IamResult<Success> {
        let tenant_id = text(prop(input, "tenantId"), "tenantId", 512)?;
        let normalized = email(prop(input, "email"))?;
        if self.options.send_email.is_none() || self.options.email_password == Some(false) {
            return Err(IamError::new(
                "FEATURE_DISABLED",
                "Password recovery is unavailable",
            ));
        }
        self.rate(
            &tenant_id,
            &format!("password-reset:{normalized}"),
            RateTier::Sensitive,
        )
        .await?;
        self.store()
            .transaction(|tx| async move {
                self.assert_tenant_active(&tx, &tenant_id).await?;
                if let Some(identity) = active_person(&tx, &tenant_id, &normalized).await?
                    && identity.email_verified
                {
                    let token = self
                        .challenge(
                            &tx,
                            &identity,
                            "password-reset",
                            single("email", normalized.clone()),
                            None,
                            None,
                            None,
                        )
                        .await?;
                    self.enqueue(
                        &tx,
                        &identity,
                        OutboxKind::Email,
                        &normalized,
                        "password-reset",
                        single("token", token),
                    )
                    .await?;
                }
                Ok(Success::TRUE)
            })
            .await
    }

    /// `issuePasswordReset(tx, identity)`: queues a password-reset email for an identity on an administrator's
    /// behalf, verified or not.
    pub async fn issue_password_reset(&self, tx: &Store, identity: &Identity) -> IamResult<()> {
        if self.options.send_email.is_none() || self.options.email_password == Some(false) {
            return Err(IamError::new(
                "FEATURE_DISABLED",
                "Password recovery is unavailable",
            ));
        }
        let address = identity.email.clone().filter(|email| !email.is_empty());
        let address = match address {
            Some(address)
                if identity.kind == IdentityKind::User
                    && identity.status == IdentityStatus::Active =>
            {
                address
            }
            _ => {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "Only active people with an email can reset a password",
                ));
            }
        };
        let token = self
            .challenge(
                tx,
                identity,
                "password-reset",
                single("email", address.clone()),
                None,
                None,
                None,
            )
            .await?;
        self.enqueue(
            tx,
            identity,
            OutboxKind::Email,
            &address,
            "password-reset",
            single("token", token),
        )
        .await
    }

    /// `resetPassword({ tenantId, token, password })`: recovery never creates a session or removes MFA.
    pub async fn reset_password(&self, input: &Value) -> IamResult<Success> {
        if self.options.email_password == Some(false) {
            return Err(IamError::with_status(
                "FEATURE_DISABLED",
                "Password authentication is disabled",
                403,
            ));
        }
        let new_password = password(prop(input, "password"))?;
        let tenant_id = text(prop(input, "tenantId"), "tenantId", 512)?;
        let token = text(prop(input, "token"), "token", 512)?;
        self.rate(
            &tenant_id,
            &format!("reset-token:{}", hash_token(&token)),
            RateTier::Default,
        )
        .await?;
        self.store()
            .transaction(|tx| async move {
                let challenge = self
                    .read_challenge(
                        &tx,
                        &tenant_id,
                        &token,
                        "password-reset",
                        ChallengeMatch::default(),
                    )
                    .await?;
                let mut identity = self
                    .user(&tx, &challenge.identity_id, Some(&tenant_id))
                    .await?;
                assert_same_address(&challenge, &identity)?;
                // A password chosen through the mailed link is the address owner's.
                identity.unproven_password = None;
                let tenant: Option<Tenant> =
                    get(tx.as_ref(), "tenants", &identity.tenant_id).await?;
                self.set_password(
                    &tx,
                    tenant.as_ref(),
                    &mut identity,
                    Some(&Value::String(new_password)),
                )
                .await?;
                put(tx.as_ref(), "identities", &identity).await?;
                self.revoke_identity(&tx, &identity.id).await?;
                self.audit(&tx, &identity, "auth:password:reset", None, None)
                    .await?;
                Ok(Success::TRUE)
            })
            .await
    }

    /// `changePassword(credentials, { currentPassword, password })`.
    pub async fn change_password(
        &self,
        credentials: &CredentialInput,
        input: &Value,
    ) -> IamResult<Success> {
        let new_password = password(prop(input, "password"))?;
        let current = text(prop(input, "currentPassword"), "currentPassword", 1024)?;
        let initial = self.authenticate(credentials).await?;
        self.rate(
            &initial.identity.tenant_id,
            &format!("password-change:{}", initial.identity.id),
            RateTier::Default,
        )
        .await?;
        // A wrong current password is a failed attempt on the account like one at sign-in.
        let failed: Mutex<Option<Identity>> = Mutex::new(None);
        let result = self
            .store()
            .transaction(|tx| {
                let failed = &failed;
                async move {
                    let mut principal = self.authenticate(credentials).await?;
                    self.require_recent(&principal)?;
                    let valid = match principal
                        .identity
                        .password_hash
                        .clone()
                        .filter(|hash| !hash.is_empty())
                    {
                        Some(hash) => passwords::verify(&hash, &current).await?,
                        None => false,
                    };
                    if !valid {
                        *failed
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                            Some(principal.identity.clone());
                        return Err(IamError::with_status(
                            "INVALID_CREDENTIALS",
                            "Invalid current password",
                            401,
                        ));
                    }
                    let tenant: Option<Tenant> =
                        get(tx.as_ref(), "tenants", &principal.identity.tenant_id).await?;
                    self.set_password(
                        &tx,
                        tenant.as_ref(),
                        &mut principal.identity,
                        Some(&Value::String(new_password)),
                    )
                    .await?;
                    put(tx.as_ref(), "identities", &principal.identity).await?;
                    self.revoke_identity(&tx, &principal.identity.id).await?;
                    self.audit(&tx, &principal.identity, "auth:password:change", None, None)
                        .await?;
                    Ok(Success::TRUE)
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

    /// `reauthenticate(credentials, { password })`: re-runs the password (and MFA) ceremony for an existing session
    /// so sensitive operations can require recent authentication.
    pub async fn reauthenticate(
        &self,
        credentials: &CredentialInput,
        input: &Value,
    ) -> IamResult<SignInResult> {
        if self.options.email_password == Some(false) {
            return Err(IamError::with_status(
                "FEATURE_DISABLED",
                "Password authentication is disabled",
                403,
            ));
        }
        let password = text(prop(input, "password"), "password", 1024)?;
        let initial = boxed(|| self.authenticate(credentials)).await?;
        if initial
            .session
            .impersonator_id
            .as_deref()
            .is_some_and(|id| !id.is_empty())
        {
            return Err(IamError::with_status(
                "IMPERSONATION_RESTRICTED",
                "An impersonated session cannot be re-authenticated",
                403,
            ));
        }
        boxed(|| async {
            self.rate(
                &initial.identity.tenant_id,
                &format!("reauth:{}", initial.identity.id),
                RateTier::Default,
            )
            .await
        })
        .await?;
        // Reauthentication is a sign-in, so a wrong password here is recorded like one at sign-in.
        let failed: Mutex<Option<Identity>> = Mutex::new(None);
        let result = self
            .store()
            .transaction(|tx| {
                let failed = &failed;
                async move {
                    let principal = boxed(|| self.authenticate(credentials)).await?;
                    boxed(|| {
                        self.method_allowed(
                            &tx,
                            &principal.identity.tenant_id,
                            AuthMethod::Password,
                        )
                    })
                    .await?;
                    let valid = match principal
                        .identity
                        .password_hash
                        .clone()
                        .filter(|hash| !hash.is_empty())
                    {
                        Some(hash) => boxed(|| passwords::verify(&hash, &password)).await?,
                        None => false,
                    };
                    if !valid {
                        *failed
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                            Some(principal.identity.clone());
                        return Err(IamError::with_status(
                            "INVALID_CREDENTIALS",
                            "Invalid password",
                            401,
                        ));
                    }
                    // As at sign-in: an expired password is refused once verified.
                    boxed(|| self.assert_password_current(&tx, &principal.identity)).await?;
                    boxed(|| {
                        self.complete_authentication(
                            &tx,
                            &principal.identity,
                            Some(AuthMethod::Password),
                            None,
                        )
                    })
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

    /// `requestEmailChange(credentials, { email })`.
    pub async fn request_email_change(
        &self,
        credentials: &CredentialInput,
        input: &Value,
    ) -> IamResult<Success> {
        let normalized = email(prop(input, "email"))?;
        let initial = self.authenticate(credentials).await?;
        self.rate(
            &initial.identity.tenant_id,
            &format!("email-change:{}", initial.identity.id),
            RateTier::Sensitive,
        )
        .await?;
        self.store()
            .transaction(|tx| async move {
                let principal = self.authenticate(credentials).await?;
                self.require_recent(&principal)?;
                // A guest's address is the one their invitation proved and the cross-tenant settings admitted.
                if principal.identity.guest.is_some() {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "A guest’s email address cannot change: ask the organization to invite the new address",
                    ));
                }
                let token = self
                    .challenge(
                        &tx,
                        &principal.identity,
                        "email-change",
                        single("email", normalized.clone()),
                        Some(10.0 * 60_000.0),
                        None,
                        Some(principal.session.id.clone()),
                    )
                    .await?;
                self.enqueue(
                    &tx,
                    &principal.identity,
                    OutboxKind::Email,
                    &normalized,
                    "email-change",
                    single("token", token),
                )
                .await?;
                Ok(Success::TRUE)
            })
            .await
    }

    /// `confirmEmailChange({ tenantId, token })`.
    pub async fn confirm_email_change(&self, input: &Value) -> IamResult<Success> {
        let tenant_id = text(prop(input, "tenantId"), "tenantId", 512)?;
        let token = text(prop(input, "token"), "token", 512)?;
        self.rate(
            &tenant_id,
            &format!("email-change-token:{}", hash_token(&token)),
            RateTier::Default,
        )
        .await?;
        self.store()
            .transaction(|tx| async move {
                let challenge = self
                    .read_challenge(
                        &tx,
                        &tenant_id,
                        &token,
                        "email-change",
                        ChallengeMatch::default(),
                    )
                    .await?;
                let mut identity = self
                    .user(&tx, &challenge.identity_id, Some(&tenant_id))
                    .await?;
                let session: Option<Session> =
                    match challenge.session_id.as_deref().filter(|id| !id.is_empty()) {
                        Some(id) => get(tx.as_ref(), "sessions", id).await?,
                        None => None,
                    };
                if session.is_none_or(|session| session.expires_at <= self.now()) {
                    return Err(IamError::with_status(
                        "UNAUTHENTICATED",
                        "Original session is no longer valid",
                        401,
                    ));
                }
                let normalized = email(challenge.payload.get("email"))?;
                let taken = find::<Identity>(
                    tx.as_ref(),
                    "identities",
                    &Filter::new()
                        .eq("tenantId", tenant_id.clone())
                        .eq("email", normalized.clone()),
                )
                .await?
                .iter()
                .any(|item| item.id != identity.id);
                if taken {
                    return Err(IamError::with_status(
                        "IDENTITY_EXISTS",
                        "Email is already in use in this tenant",
                        409,
                    ));
                }
                identity.email = Some(normalized.clone());
                identity.email_verified = true;
                identity.unique_key = Some(format!("email:{normalized}"));
                put(tx.as_ref(), "identities", &identity).await?;
                self.revoke_identity(&tx, &identity.id).await?;
                self.audit(&tx, &identity, "auth:email:change", None, None)
                    .await?;
                Ok(Success::TRUE)
            })
            .await
    }

    /// `startPhoneVerification(credentials, { phone })`.
    pub async fn start_phone_verification(
        &self,
        credentials: &CredentialInput,
        input: &Value,
    ) -> IamResult<Success> {
        let normalized = phone(prop(input, "phone"))?;
        let initial = self.authenticate(credentials).await?;
        self.rate(
            &initial.identity.tenant_id,
            &format!("phone-verify:{}", initial.identity.id),
            RateTier::Sensitive,
        )
        .await?;
        self.store()
            .transaction(|tx| async move {
                let principal = self.authenticate(credentials).await?;
                self.require_recent(&principal)?;
                let token = six_digit_code();
                self.challenge(
                    &tx,
                    &principal.identity,
                    "phone-verify",
                    single("phone", normalized.clone()),
                    Some(5.0 * 60_000.0),
                    Some(token.clone()),
                    Some(principal.session.id.clone()),
                )
                .await?;
                self.enqueue(
                    &tx,
                    &principal.identity,
                    OutboxKind::Sms,
                    &normalized,
                    "phone-verify",
                    single("token", token),
                )
                .await?;
                Ok(Success::TRUE)
            })
            .await
    }

    /// `confirmPhoneVerification(credentials, { phone, code })`.
    pub async fn confirm_phone_verification(
        &self,
        credentials: &CredentialInput,
        input: &Value,
    ) -> IamResult<Success> {
        let normalized = phone(prop(input, "phone"))?;
        let code = text(prop(input, "code"), "code", 6)?;
        let initial = boxed(|| self.authenticate(credentials)).await?;
        boxed(|| async {
            self.rate(
                &initial.identity.tenant_id,
                &format!("phone-code:{}", initial.identity.id),
                RateTier::Sensitive,
            )
            .await
        })
        .await?;
        self.store()
            .transaction(|tx| async move {
                let mut principal = boxed(|| self.authenticate(credentials)).await?;
                self.require_recent(&principal)?;
                let challenge = boxed(|| {
                    self.read_challenge(
                        &tx,
                        &principal.identity.tenant_id,
                        &code,
                        "phone-verify",
                        ChallengeMatch {
                            identity_id: Some(&principal.identity.id),
                            destination: None,
                        },
                    )
                })
                .await?;
                if challenge.identity_id != principal.identity.id
                    || challenge.session_id.as_deref() != Some(principal.session.id.as_str())
                    || challenge.payload_str("phone") != Some(normalized.as_str())
                {
                    return Err(IamError::with_status(
                        "INVALID_CHALLENGE",
                        "Invalid verification code",
                        401,
                    ));
                }
                let existing = boxed(|| async {
                    find::<Identity>(
                        tx.as_ref(),
                        "identities",
                        &Filter::new()
                            .eq("tenantId", principal.identity.tenant_id.clone())
                            .eq("phone", normalized.clone())
                            .eq("phoneVerified", true),
                    )
                    .await
                })
                .await?;
                if existing
                    .iter()
                    .any(|identity| identity.id != principal.identity.id)
                {
                    return Err(IamError::with_status(
                        "PHONE_EXISTS",
                        "Phone is already verified by another identity",
                        409,
                    ));
                }
                principal.identity.phone = Some(normalized.clone());
                principal.identity.phone_verified = Some(true);
                boxed(|| put(tx.as_ref(), "identities", &principal.identity)).await?;
                boxed(|| tx.delete("authChallenges", &challenge.id)).await?;
                boxed(|| self.audit(&tx, &principal.identity, "auth:phone:verify", None, None))
                    .await?;
                Ok(Success::TRUE)
            })
            .await
    }
}

/// `assertSameAddress(challenge, identity)`: refuses a mailed link once the identity's address is no longer the one
/// it was sent to.
pub(crate) fn assert_same_address(challenge: &Challenge, identity: &Identity) -> IamResult<()> {
    match identity.email.as_deref().filter(|email| !email.is_empty()) {
        Some(address) if challenge.payload_str("email") == Some(address) => Ok(()),
        _ => Err(IamError::with_status(
            "INVALID_CHALLENGE",
            "Email has changed",
            401,
        )),
    }
}
