//! Magic links and one-time codes over email or SMS (`service/passwordless.ts`, class `PasswordlessAuth`).
//! Passwordless sign-in never links accounts by matching email.

use better_iam_core::{AuthMethod, Filter, IamError, IamResult, IamStoreExt, Identity, OutboxKind};
use serde_json::{Map, Value};

use super::AuthService;
use super::account::six_digit_code;
use super::base::{ChallengeMatch, RateTier};
use super::sessions::{Success, optional_text};
use crate::crypto::new_token;
use crate::types::{Challenge, SignInResult};
use crate::util::{find, internal_error, prop, prop_str, put};
use crate::validation::{email, phone, text};

impl AuthService {
    /// `startPasswordless({ tenantId, destination, channel, kind })`: `channel` is `email` or `sms`, `kind` is
    /// `magic-link` or `code` (SMS needs a code).
    pub async fn start_passwordless(&self, input: &Value) -> IamResult<Success> {
        let channel =
            prop_str(input, "channel").filter(|channel| ["email", "sms"].contains(channel));
        let kind = prop_str(input, "kind").filter(|kind| ["magic-link", "code"].contains(kind));
        let (Some(channel), Some(kind)) = (channel, kind) else {
            return Err(IamError::new(
                "INVALID_INPUT",
                "Invalid passwordless method",
            ));
        };
        if channel == "sms" && kind != "code" {
            return Err(IamError::new(
                "INVALID_INPUT",
                "SMS authentication requires a code",
            ));
        }
        let enabled = if channel == "email" {
            self.options.passwordless_email
        } else {
            self.options.passwordless_sms
        };
        if enabled != Some(true) {
            return Err(IamError::new(
                "FEATURE_DISABLED",
                "Passwordless method is disabled",
            ));
        }
        let tenant_id = text(prop(input, "tenantId"), "tenantId", 512)?;
        let destination = if channel == "email" {
            email(prop(input, "destination"))?
        } else {
            phone(prop(input, "destination"))?
        };
        self.rate(
            &tenant_id,
            &format!("passwordless-start:{destination}"),
            RateTier::Sensitive,
        )
        .await?;
        let method = if channel == "email" {
            AuthMethod::PasswordlessEmail
        } else {
            AuthMethod::PasswordlessSms
        };
        self.store()
            .transaction(|tx| async move {
                self.assert_tenant_active(&tx, &tenant_id).await?;
                self.method_allowed(&tx, &tenant_id, method).await?;
                let mut filter = Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("kind", "user")
                    .eq("status", "active");
                filter = if channel == "email" {
                    filter.eq("email", destination.clone())
                } else {
                    filter
                        .eq("phone", destination.clone())
                        .eq("phoneVerified", true)
                };
                let identity: Option<Identity> =
                    find::<Identity>(tx.as_ref(), "identities", &filter)
                        .await?
                        .into_iter()
                        .next();
                if let Some(identity) = identity {
                    // Only the newest code or link for a destination stays valid.
                    let earlier: Vec<Challenge> = find(
                        tx.as_ref(),
                        "authChallenges",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("identityId", identity.id.clone())
                            .eq("purpose", "passwordless"),
                    )
                    .await?;
                    for earlier in earlier {
                        if earlier.payload_str("destination") == Some(destination.as_str()) {
                            tx.delete("authChallenges", &earlier.id).await?;
                        }
                    }
                    let token = if kind == "code" {
                        six_digit_code()
                    } else {
                        new_token()
                    };
                    let mut payload = Map::new();
                    payload.insert("destination".to_owned(), Value::String(destination.clone()));
                    payload.insert("channel".to_owned(), Value::String(channel.to_owned()));
                    self.challenge(
                        &tx,
                        &identity,
                        "passwordless",
                        payload,
                        Some(5.0 * 60_000.0),
                        Some(token.clone()),
                        None,
                    )
                    .await?;
                    let mut delivery = Map::new();
                    delivery.insert("token".to_owned(), Value::String(token));
                    let kind_of = if channel == "email" {
                        OutboxKind::Email
                    } else {
                        OutboxKind::Sms
                    };
                    self.enqueue(&tx, &identity, kind_of, &destination, kind, delivery)
                        .await?;
                }
                Ok(Success::TRUE)
            })
            .await
    }

    /// `finishPasswordless({ tenantId, destination, token, deviceToken? })`.
    pub async fn finish_passwordless(&self, input: &Value) -> IamResult<SignInResult> {
        let tenant_id = text(prop(input, "tenantId"), "tenantId", 512)?;
        let device_token = optional_text(input, "deviceToken", "deviceToken", 512)?;
        let destination = match prop(input, "destination") {
            Some(Value::String(value)) if value.starts_with('+') => {
                phone(prop(input, "destination"))?
            }
            None | Some(Value::Null) | Some(Value::String(_)) => email(prop(input, "destination"))?,
            // `input.destination?.startsWith` is not a function for other values.
            Some(_) => return Err(internal_error()),
        };
        self.rate(
            &tenant_id,
            &format!("passwordless-finish:{destination}"),
            RateTier::Sensitive,
        )
        .await?;
        self.store()
            .transaction(|tx| async move {
                let sms = destination.starts_with('+');
                self.method_allowed(
                    &tx,
                    &tenant_id,
                    if sms {
                        AuthMethod::PasswordlessSms
                    } else {
                        AuthMethod::PasswordlessEmail
                    },
                )
                .await?;
                let token = text(prop(input, "token"), "token", 512)?;
                let challenge = self
                    .read_challenge(
                        &tx,
                        &tenant_id,
                        &token,
                        "passwordless",
                        ChallengeMatch {
                            identity_id: None,
                            destination: Some(&destination),
                        },
                    )
                    .await?;
                let email_channel = challenge.payload_str("channel") == Some("email");
                let enabled = if email_channel {
                    self.options.passwordless_email
                } else {
                    self.options.passwordless_sms
                };
                if enabled != Some(true) {
                    return Err(IamError::new(
                        "FEATURE_DISABLED",
                        "Passwordless method is disabled",
                    ));
                }
                if challenge.payload_str("destination") != Some(destination.as_str()) {
                    return Err(IamError::with_status(
                        "INVALID_CHALLENGE",
                        "Invalid verification code",
                        401,
                    ));
                }
                let mut identity = self
                    .user(&tx, &challenge.identity_id, Some(&tenant_id))
                    .await?;
                let mut squatted = false;
                if email_channel {
                    if identity.email.as_deref() != Some(destination.as_str()) {
                        return Err(IamError::with_status(
                            "INVALID_CHALLENGE",
                            "Email has changed",
                            401,
                        ));
                    }
                    squatted = !identity.email_verified && identity.unproven_password == Some(true);
                    identity.email_verified = true;
                    identity.unproven_password = None;
                } else if identity.phone.as_deref() != Some(destination.as_str())
                    || identity.phone_verified != Some(true)
                {
                    return Err(IamError::with_status(
                        "INVALID_CHALLENGE",
                        "Phone has changed",
                        401,
                    ));
                }
                tx.delete("authChallenges", &challenge.id).await?;
                if squatted {
                    // The first proof that someone controls this address, on an account whose password was chosen at
                    // self sign-up before anyone proved it: that password, and the sessions and remembered devices it
                    // produced, go. The owner sets a password through reset.
                    self.revoke_identity(&tx, &identity.id).await?;
                    if identity
                        .password_hash
                        .as_deref()
                        .is_some_and(|hash| !hash.is_empty())
                    {
                        identity.password_hash = None;
                        self.audit(&tx, &identity, "auth:password:clear", None, None)
                            .await?;
                    }
                }
                if email_channel {
                    put(tx.as_ref(), "identities", &identity).await?;
                }
                self.complete_authentication(
                    &tx,
                    &identity,
                    Some(if email_channel {
                        AuthMethod::PasswordlessEmail
                    } else {
                        AuthMethod::PasswordlessSms
                    }),
                    device_token.as_deref(),
                )
                .await
            })
            .await
    }
}
