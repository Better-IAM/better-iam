//! WebAuthn passkeys: registration from a recently authenticated session, passwordless sign-in that satisfies MFA,
//! and passkeys as a second factor (`service/passkeys.ts`, class `PasskeyAuth`).

use std::collections::HashSet;

use better_iam_core::boxed;
use better_iam_core::{
    AuthMethod, CredentialInput, Filter, IamError, IamResult, IamStoreExt, Identity,
    ip_counter_key, js,
};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::Sha256;

use super::AuthService;
use super::base::{ChallengeMatch, IssueSessionOptions, RateTier, url_hostname};
use super::sessions::Success;
use crate::crypto::{hash_token, new_id, new_token};
use crate::types::{Challenge, MfaSessionResult, PasskeyRecord, SafePasskey, SessionResult};
use crate::util::{
    base64url, find, get, insert, internal_error, node_base64_decode, prop, put, truthy,
};
use crate::validation::{email, text};
use crate::webauthn::{
    self, CredentialDescriptor, RegistrationOptionsInput, StoredCredential,
    generate_authentication_options, generate_registration_options,
};

const PASSKEY_NAME_LIMIT: usize = 64;

/// What the `begin*` passkey ceremonies return: the challenge to finish with and the options for the browser.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCeremony {
    pub challenge_id: String,
    pub options: Value,
}

/// What `finishPasskeyRegistration` returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasskeyRegistered {
    pub id: String,
    pub name: String,
}

/// `defaultPasskeyName(transports)`: a readable default label from what the authenticator reported about itself.
/// A value `new Set(...)` cannot iterate is the TypeError the TypeScript function throws.
pub fn default_passkey_name(transports: Option<&Value>) -> IamResult<String> {
    let set: HashSet<String> = match transports {
        None | Some(Value::Null) => HashSet::new(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        Some(Value::String(text)) => text.chars().map(String::from).collect(),
        Some(_) => return Err(internal_error()),
    };
    let has = |name: &str| set.contains(name);
    Ok(if has("internal") {
        "This device"
    } else if has("hybrid") {
        "Phone"
    } else if has("usb") || has("nfc") || has("ble") {
        "Security key"
    } else {
        "Passkey"
    }
    .to_owned())
}

/// `passkeyName(value, fallback)`.
fn passkey_name(
    value: Option<&Value>,
    fallback: impl FnOnce() -> IamResult<String>,
) -> IamResult<String> {
    match value {
        None => fallback(),
        Some(value) => {
            let name = text(Some(value), "name", PASSKEY_NAME_LIMIT)?;
            let trimmed = js::trim(&name);
            if trimmed.is_empty() {
                return Err(IamError::new("INVALID_INPUT", "name must not be empty"));
            }
            Ok(trimmed.to_owned())
        }
    }
}

/// `publicPasskey(record)`: everything but the key material, with the default name filled in.
pub fn public_passkey(record: &PasskeyRecord) -> IamResult<SafePasskey> {
    let mut safe = record.clone();
    if safe.name.is_none() {
        safe.name = Some(default_passkey_name(record.transports.as_ref())?);
    }
    Ok(SafePasskey(safe))
}

/// The configuration the ceremonies use.
struct PasskeyConfig {
    rp_id: String,
    rp_name: String,
}

/// `!input.response || typeof input.response !== 'object' || typeof input.response.id !== 'string' ||
/// !input.response.response`.
fn assertion_present(input: &Value) -> IamResult<&Value> {
    let response = prop(input, "response");
    match response {
        Some(response @ (Value::Object(_) | Value::Array(_)))
            if response.get("id").is_some_and(Value::is_string)
                && truthy(response.get("response")) =>
        {
            Ok(response)
        }
        _ => Err(IamError::new(
            "INVALID_INPUT",
            "A passkey authentication response is required",
        )),
    }
}

fn descriptor(key: &PasskeyRecord) -> CredentialDescriptor {
    CredentialDescriptor {
        id: key.credential_id.clone(),
        transports: key.transports.clone(),
    }
}

fn single(key: &str, value: impl Into<String>) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert(key.to_owned(), Value::String(value.into()));
    map
}

/// The challenge string the options carry.
fn options_challenge(options: &Value) -> String {
    options
        .get("challenge")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

impl AuthService {
    /// `passkeys()`: the relying party; refuses an organization address outside the RP ID up front.
    fn passkey_config(&self) -> IamResult<PasskeyConfig> {
        let passkeys = self
            .options
            .passkeys
            .as_ref()
            .ok_or_else(|| IamError::new("FEATURE_DISABLED", "Passkeys are not configured"))?;
        if let Some(origin) = self
            .request_host()
            .and_then(|host| host.origin)
            .filter(|origin| !origin.is_empty())
        {
            let url = url::Url::parse(&origin).map_err(|_| internal_error())?;
            let hostname = url_hostname(&url);
            if hostname != passkeys.rp_id && !hostname.ends_with(&format!(".{}", passkeys.rp_id)) {
                return Err(IamError::new(
                    "FEATURE_DISABLED",
                    "Passkeys are not available at this address",
                ));
            }
        }
        Ok(PasskeyConfig {
            rp_id: passkeys.rp_id.clone(),
            rp_name: passkeys
                .rp_name
                .clone()
                .unwrap_or_else(|| self.app_name.clone()),
        })
    }

    async fn identity_passkeys(
        &self,
        tx: &crate::util::Store,
        identity: &Identity,
    ) -> IamResult<Vec<PasskeyRecord>> {
        find(
            tx.as_ref(),
            "authPasskeys",
            &Filter::new()
                .eq("tenantId", identity.tenant_id.clone())
                .eq("identityId", identity.id.clone()),
        )
        .await
    }

    /// `beginPasskeyRegistration(credentials)`.
    pub async fn begin_passkey_registration(
        &self,
        credentials: &CredentialInput,
    ) -> IamResult<PasskeyCeremony> {
        let config = self.passkey_config()?;
        self.store()
            .transaction(|tx| async move {
                let principal = self.authenticate(credentials).await?;
                self.require_recent(&principal)?;
                let existing = self.identity_passkeys(&tx, &principal.identity).await?;
                let options = generate_registration_options(
                    &RegistrationOptionsInput {
                        rp_name: config.rp_name.clone(),
                        rp_id: config.rp_id.clone(),
                        user_name: principal
                            .identity
                            .email
                            .clone()
                            .unwrap_or_else(|| principal.identity.id.clone()),
                        user_id: principal.identity.id.as_bytes().to_vec(),
                        user_display_name: principal.identity.name.clone(),
                        exclude_credentials: existing.iter().map(descriptor).collect(),
                    },
                    None,
                )
                .map_err(|_| internal_error())?;
                let challenge_id = self
                    .challenge(
                        &tx,
                        &principal.identity,
                        "passkey-register",
                        single("challenge", options_challenge(&options)),
                        Some(5.0 * 60_000.0),
                        None,
                        Some(principal.session.id.clone()),
                    )
                    .await?;
                Ok(PasskeyCeremony {
                    challenge_id,
                    options,
                })
            })
            .await
    }

    /// `finishPasskeyRegistration(credentials, { challengeId, response, name? })`: `name` labels the passkey for the
    /// person's own list (at most 64 characters); the default names the device kind.
    pub async fn finish_passkey_registration(
        &self,
        credentials: &CredentialInput,
        input: &Value,
    ) -> IamResult<PasskeyRegistered> {
        let config = self.passkey_config()?;
        self.store()
            .transaction(|tx| async move {
                let principal = boxed(|| self.authenticate(credentials)).await?;
                self.require_recent(&principal)?;
                let token = text(prop(input, "challengeId"), "token", 512)?;
                let challenge = boxed(|| {
                    self.read_challenge(
                        &tx,
                        &principal.identity.tenant_id,
                        &token,
                        "passkey-register",
                        ChallengeMatch::default(),
                    )
                })
                .await?;
                if challenge.identity_id != principal.identity.id
                    || challenge.session_id.as_deref() != Some(principal.session.id.as_str())
                {
                    return Err(IamError::with_status(
                        "INVALID_CHALLENGE",
                        "Invalid passkey challenge",
                        401,
                    ));
                }
                let response = prop(input, "response").cloned().unwrap_or(Value::Null);
                let result = boxed(|| async {
                    webauthn::verify_registration_response(
                        &response,
                        challenge.payload_str("challenge").unwrap_or_default(),
                        &self.expected_origins(),
                        &config.rp_id,
                        true,
                    )
                    .await
                })
                .await
                .map_err(|_| {
                    IamError::with_status(
                        "INVALID_PASSKEY",
                        "Passkey registration verification failed",
                        401,
                    )
                })?;
                let info = match result.info {
                    Some(info) if result.verified => info,
                    _ => {
                        return Err(IamError::with_status(
                            "INVALID_PASSKEY",
                            "Passkey verification failed",
                            401,
                        ));
                    }
                };
                let id = new_id("pk");
                // A credential is globally unique for this RP, including across tenant accounts.
                let taken = boxed(|| async {
                    tx.find(
                        "authPasskeys",
                        &Filter::new().eq("credentialId", info.credential_id.clone()),
                        &Default::default(),
                    )
                    .await
                })
                .await?;
                if !taken.is_empty() {
                    return Err(IamError::with_status(
                        "PASSKEY_EXISTS",
                        "Passkey is already registered",
                        409,
                    ));
                }
                let name = passkey_name(prop(input, "name"), || {
                    default_passkey_name(info.transports.as_ref())
                })?;
                let record = PasskeyRecord {
                    id: id.clone(),
                    tenant_id: principal.identity.tenant_id.clone(),
                    unique_key: Some(info.credential_id.clone()),
                    identity_id: principal.identity.id.clone(),
                    credential_id: info.credential_id.clone(),
                    public_key: base64url(&info.public_key),
                    counter: f64::from(info.counter),
                    transports: info.transports.clone().filter(|value| !value.is_null()),
                    name: Some(name.clone()),
                    created_at: Some(self.now()),
                    last_used_at: None,
                    device_type: Some(info.device_type.to_owned()),
                    backed_up: Some(info.backed_up),
                    aaguid: (!info.aaguid.is_empty()
                        && info.aaguid != "00000000-0000-0000-0000-000000000000")
                        .then(|| info.aaguid.clone()),
                    extra: Map::new(),
                };
                boxed(|| insert(tx.as_ref(), "authPasskeys", &record)).await?;
                boxed(|| tx.delete("authChallenges", &challenge.id)).await?;
                boxed(|| {
                    self.audit(
                        &tx,
                        &principal.identity,
                        "auth:passkey:create",
                        None,
                        Some(single("name", name.clone())),
                    )
                })
                .await?;
                Ok(PasskeyRegistered { id, name })
            })
            .await
    }

    /// `beginPasskeyAuthentication({ tenantId, email? })`: with `email`, the options name that person's credentials;
    /// without it, the authenticator offers whatever discoverable credential it holds (the browser's passkey picker
    /// or autofill) and `finishPasskeyAuthentication` finds the account from the credential itself.
    pub async fn begin_passkey_authentication(&self, input: &Value) -> IamResult<PasskeyCeremony> {
        let config = self.passkey_config()?;
        let tenant_id = text(prop(input, "tenantId"), "tenantId", 512)?;
        if prop(input, "email").is_none() {
            // Discovery names nobody, so the counter is per address (an IPv6 /64 as one).
            let ip = self
                .current_client()
                .and_then(|client| client.ip)
                .filter(|ip| !ip.is_empty());
            let subject = match ip {
                Some(ip) => ip_counter_key(&ip).unwrap_or(ip),
                None => "unknown".to_owned(),
            };
            self.rate(
                &tenant_id,
                &format!("passkey-discover:{subject}"),
                RateTier::Generous,
            )
            .await?;
            return self
                .store()
                .transaction(|tx| async move {
                    self.assert_tenant_active(&tx, &tenant_id).await?;
                    self.method_allowed(&tx, &tenant_id, AuthMethod::Passkey)
                        .await?;
                    let options = generate_authentication_options(&config.rp_id, None, None)
                        .map_err(|_| internal_error())?;
                    let token = new_token();
                    let mut payload = single("challenge", options_challenge(&options));
                    payload.insert("discovery".to_owned(), Value::String("1".to_owned()));
                    insert(
                        tx.as_ref(),
                        "authChallenges",
                        &Challenge {
                            id: new_id("ch"),
                            tenant_id: tenant_id.clone(),
                            unique_key: None,
                            identity_id: String::new(),
                            purpose: "passkey-authenticate".to_owned(),
                            token_hash: self.digest_challenge(&tenant_id, &token, None),
                            payload,
                            expires_at: self.now() + 5.0 * 60_000.0,
                            session_id: None,
                            extra: Map::new(),
                        },
                    )
                    .await?;
                    Ok(PasskeyCeremony {
                        challenge_id: token,
                        options,
                    })
                })
                .await;
        }
        let normalized = email(prop(input, "email"))?;
        self.rate(
            &tenant_id,
            &format!("passkey:{normalized}"),
            RateTier::Default,
        )
        .await?;
        self.store()
            .transaction(|tx| async move {
                self.assert_tenant_active(&tx, &tenant_id).await?;
                self.method_allowed(&tx, &tenant_id, AuthMethod::Passkey)
                    .await?;
                let identity: Option<Identity> = find::<Identity>(
                    tx.as_ref(),
                    "identities",
                    &Filter::new()
                        .eq("tenantId", tenant_id.clone())
                        .eq("email", normalized.clone())
                        .eq("status", "active")
                        .eq("kind", "user"),
                )
                .await?
                .into_iter()
                .next();
                let keys = match &identity {
                    Some(identity) => self.identity_passkeys(&tx, identity).await?,
                    None => Vec::new(),
                };
                let identity = match identity {
                    Some(identity) if !keys.is_empty() => identity,
                    _ => {
                        // Answered like an account with a passkey, so these options never reveal who has an account
                        // (or a passkey): a decoy credential id that is stable per address, and a challenge id that
                        // finishes nowhere.
                        let mut mac =
                            Hmac::<Sha256>::new_from_slice(self.options.secret.as_bytes())
                                .expect("any key length");
                        mac.update(format!("passkey-decoy:{tenant_id}:{normalized}").as_bytes());
                        let decoy = base64url(mac.finalize().into_bytes());
                        let options = generate_authentication_options(
                            &config.rp_id,
                            Some(&[CredentialDescriptor {
                                id: decoy,
                                transports: None,
                            }]),
                            None,
                        )
                        .map_err(|_| internal_error())?;
                        return Ok(PasskeyCeremony {
                            challenge_id: new_token(),
                            options,
                        });
                    }
                };
                let descriptors: Vec<CredentialDescriptor> = keys.iter().map(descriptor).collect();
                let options =
                    generate_authentication_options(&config.rp_id, Some(&descriptors), None)
                        .map_err(|_| internal_error())?;
                let challenge_id = self
                    .challenge(
                        &tx,
                        &identity,
                        "passkey-authenticate",
                        single("challenge", options_challenge(&options)),
                        Some(5.0 * 60_000.0),
                        None,
                        None,
                    )
                    .await?;
                Ok(PasskeyCeremony {
                    challenge_id,
                    options,
                })
            })
            .await
    }

    /// Verifies an assertion against a stored passkey; the TypeScript library's failures are INVALID_PASSKEY.
    fn verify_assertion(
        &self,
        config: &PasskeyConfig,
        challenge: &Challenge,
        response: &Value,
        key: &PasskeyRecord,
    ) -> IamResult<webauthn::AuthenticationVerification> {
        let result = webauthn::verify_authentication_response(
            response,
            challenge.payload_str("challenge").unwrap_or_default(),
            &self.expected_origins(),
            &config.rp_id,
            true,
            &StoredCredential {
                id: key.credential_id.clone(),
                public_key: node_base64_decode(&key.public_key),
                counter: key.counter,
            },
        )
        .map_err(|_| {
            IamError::with_status(
                "INVALID_PASSKEY",
                "Passkey authentication verification failed",
                401,
            )
        })?;
        if !result.verified || !result.user_verified {
            return Err(IamError::with_status(
                "INVALID_PASSKEY",
                "Passkey verification failed",
                401,
            ));
        }
        Ok(result)
    }

    /// `finishPasskeyAuthentication({ tenantId, challengeId, response })`: a passkey sign-in, which satisfies MFA.
    pub async fn finish_passkey_authentication(&self, input: &Value) -> IamResult<SessionResult> {
        let config = self.passkey_config()?;
        let response = assertion_present(input)?;
        let tenant_id = text(prop(input, "tenantId"), "tenantId", 512)?;
        let challenge_id = text(prop(input, "challengeId"), "challengeId", 512)?;
        self.rate(
            &tenant_id,
            &format!("passkey-finish:{}", hash_token(&challenge_id)),
            RateTier::Sensitive,
        )
        .await?;
        let config = &config;
        self.store()
            .transaction(|tx| async move {
                self.method_allowed(&tx, &tenant_id, AuthMethod::Passkey)
                    .await?;
                let challenge = self
                    .read_challenge(
                        &tx,
                        &tenant_id,
                        &challenge_id,
                        "passkey-authenticate",
                        ChallengeMatch::default(),
                    )
                    .await?;
                let credential_id = response
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                // A discovery challenge names nobody: the presented credential identifies the account.
                let discovery = challenge.payload_str("discovery") == Some("1");
                let discovered: Option<PasskeyRecord> = if discovery {
                    find::<PasskeyRecord>(
                        tx.as_ref(),
                        "authPasskeys",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("credentialId", credential_id),
                    )
                    .await?
                    .into_iter()
                    .next()
                } else {
                    None
                };
                if discovery && discovered.is_none() {
                    return Err(IamError::with_status(
                        "INVALID_PASSKEY",
                        "Passkey is not registered for this organization",
                        401,
                    ));
                }
                let identity_id = discovered
                    .as_ref()
                    .map_or(challenge.identity_id.clone(), |key| key.identity_id.clone());
                let identity = self.user(&tx, &identity_id, Some(&tenant_id)).await?;
                let user_handle = response
                    .get("response")
                    .and_then(|inner| inner.get("userHandle"));
                if truthy(user_handle)
                    && user_handle.and_then(Value::as_str)
                        != Some(base64url(identity.id.as_bytes()).as_str())
                {
                    return Err(IamError::with_status(
                        "INVALID_PASSKEY",
                        "Passkey user handle does not match this identity",
                        401,
                    ));
                }
                let key = match discovered {
                    Some(key) => Some(key),
                    None => find::<PasskeyRecord>(
                        tx.as_ref(),
                        "authPasskeys",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("identityId", identity.id.clone())
                            .eq("credentialId", credential_id),
                    )
                    .await?
                    .into_iter()
                    .next(),
                };
                let mut key = key.ok_or_else(|| {
                    IamError::with_status(
                        "INVALID_PASSKEY",
                        "Passkey does not belong to this tenant identity",
                        401,
                    )
                })?;
                let result = self.verify_assertion(config, &challenge, response, &key)?;
                key.counter = f64::from(result.new_counter);
                key.last_used_at = Some(self.now());
                put(tx.as_ref(), "authPasskeys", &key).await?;
                tx.delete("authChallenges", &challenge.id).await?;
                self.issue_session(
                    &tx,
                    &identity,
                    IssueSessionOptions {
                        mfa: Some(true),
                        method: Some(AuthMethod::Passkey),
                        ..Default::default()
                    },
                )
                .await
            })
            .await
    }

    /// `beginPasskeyMfa({ tenantId, challenge })`: passkey as the second factor, after a sign-in returned
    /// `mfaRequired` with `passkeyAvailable`.
    pub async fn begin_passkey_mfa(&self, input: &Value) -> IamResult<PasskeyCeremony> {
        let config = self.passkey_config()?;
        let tenant_id = text(prop(input, "tenantId"), "tenantId", 512)?;
        let token = text(prop(input, "challenge"), "challenge", 512)?;
        self.rate(
            &tenant_id,
            &format!("passkey-mfa:{}", hash_token(&token)),
            RateTier::Sensitive,
        )
        .await?;
        self.rate_challenge_identity(&tenant_id, &token, "mfa-login", "passkey-mfa-begin")
            .await?;
        self.store()
            .transaction(|tx| async move {
                let login = self
                    .read_challenge(
                        &tx,
                        &tenant_id,
                        &token,
                        "mfa-login",
                        ChallengeMatch::default(),
                    )
                    .await?;
                let identity = self.user(&tx, &login.identity_id, Some(&tenant_id)).await?;
                let keys = self.identity_passkeys(&tx, &identity).await?;
                if keys.is_empty() {
                    return Err(IamError::with_status(
                        "FEATURE_DISABLED",
                        "No passkey is registered for this account",
                        403,
                    ));
                }
                let descriptors: Vec<CredentialDescriptor> = keys.iter().map(descriptor).collect();
                let options =
                    generate_authentication_options(&config.rp_id, Some(&descriptors), None)
                        .map_err(|_| internal_error())?;
                let mut payload = single("challenge", options_challenge(&options));
                payload.insert(
                    "loginChallengeId".to_owned(),
                    Value::String(login.id.clone()),
                );
                let challenge_id = self
                    .challenge(
                        &tx,
                        &identity,
                        "passkey-mfa",
                        payload,
                        Some(5.0 * 60_000.0),
                        None,
                        None,
                    )
                    .await?;
                Ok(PasskeyCeremony {
                    challenge_id,
                    options,
                })
            })
            .await
    }

    /// `finishPasskeyMfa({ tenantId, challengeId, response, rememberDevice? })`.
    pub async fn finish_passkey_mfa(&self, input: &Value) -> IamResult<MfaSessionResult> {
        let config = self.passkey_config()?;
        let response = assertion_present(input)?;
        let tenant_id = text(prop(input, "tenantId"), "tenantId", 512)?;
        let token = text(prop(input, "challengeId"), "challengeId", 512)?;
        let remember = prop(input, "rememberDevice") == Some(&Value::Bool(true));
        boxed(|| async {
            self.rate(
                &tenant_id,
                &format!("passkey-mfa-finish:{}", hash_token(&token)),
                RateTier::Sensitive,
            )
            .await
        })
        .await?;
        boxed(|| {
            self.rate_challenge_identity(&tenant_id, &token, "passkey-mfa", "passkey-mfa-verify")
        })
        .await?;
        let config = &config;
        self.store()
            .transaction(|tx| async move {
                let challenge = boxed(|| {
                    self.read_challenge(
                        &tx,
                        &tenant_id,
                        &token,
                        "passkey-mfa",
                        ChallengeMatch::default(),
                    )
                })
                .await?;
                let identity =
                    boxed(|| self.user(&tx, &challenge.identity_id, Some(&tenant_id))).await?;
                // The login challenge this assertion completes must still be open and belong to the same person.
                let login: Option<Challenge> = match challenge.payload_str("loginChallengeId") {
                    Some(id) => boxed(|| get(tx.as_ref(), "authChallenges", id)).await?,
                    None => None,
                };
                let login = match login {
                    Some(login)
                        if login.purpose == "mfa-login"
                            && login.identity_id == identity.id
                            && login.expires_at > self.now() =>
                    {
                        login
                    }
                    _ => {
                        return Err(IamError::with_status(
                            "INVALID_CHALLENGE",
                            "Sign-in challenge is invalid or expired",
                            401,
                        ));
                    }
                };
                let credential_id = response
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let key: Option<PasskeyRecord> = boxed(|| async {
                    find::<PasskeyRecord>(
                        tx.as_ref(),
                        "authPasskeys",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("identityId", identity.id.clone())
                            .eq("credentialId", credential_id),
                    )
                    .await
                })
                .await?
                .into_iter()
                .next();
                let mut key = key.ok_or_else(|| {
                    IamError::with_status(
                        "INVALID_PASSKEY",
                        "Passkey does not belong to this account",
                        401,
                    )
                })?;
                let result = self.verify_assertion(config, &challenge, response, &key)?;
                key.counter = f64::from(result.new_counter);
                key.last_used_at = Some(self.now());
                boxed(|| put(tx.as_ref(), "authPasskeys", &key)).await?;
                boxed(|| tx.delete("authChallenges", &challenge.id)).await?;
                boxed(|| tx.delete("authChallenges", &login.id)).await?;
                let method = login.payload_str("method").and_then(|method| {
                    serde_json::from_value::<AuthMethod>(Value::String(method.to_owned())).ok()
                });
                let session = boxed(|| {
                    self.issue_session(
                        &tx,
                        &identity,
                        IssueSessionOptions {
                            mfa: Some(true),
                            method,
                            ..Default::default()
                        },
                    )
                })
                .await?;
                let device = if remember {
                    boxed(|| self.remember_device(&tx, &identity)).await?
                } else {
                    None
                };
                Ok(MfaSessionResult::from_session(session, device))
            })
            .await
    }

    /// `listPasskeys(credentials)`: the caller's passkeys, newest first.
    pub async fn list_passkeys(
        &self,
        credentials: &CredentialInput,
    ) -> IamResult<Vec<SafePasskey>> {
        let principal = boxed(|| self.authenticate(credentials)).await?;
        let mut keys = boxed(|| self.identity_passkeys(self.store(), &principal.identity)).await?;
        keys.sort_by(|a, b| {
            crate::util::by_number_then_id(
                (b.created_at.unwrap_or(0.0), &a.id),
                (a.created_at.unwrap_or(0.0), &b.id),
            )
        });
        keys.iter().map(public_passkey).collect()
    }

    /// `renamePasskey(credentials, { id, name })`: relabels one of the caller's passkeys (at most 64 characters).
    pub async fn rename_passkey(
        &self,
        credentials: &CredentialInput,
        input: &Value,
    ) -> IamResult<SafePasskey> {
        self.store()
            .transaction(|tx| async move {
                let principal = self.authenticate(credentials).await?;
                let id = text(prop(input, "id"), "id", 512)?;
                let passkey: Option<PasskeyRecord> = get(tx.as_ref(), "authPasskeys", &id).await?;
                let mut passkey = match passkey {
                    Some(passkey)
                        if passkey.identity_id == principal.identity.id
                            && passkey.tenant_id == principal.identity.tenant_id =>
                    {
                        passkey
                    }
                    _ => return Err(IamError::with_status("NOT_FOUND", "Passkey not found", 404)),
                };
                let name = passkey_name(prop(input, "name"), || {
                    default_passkey_name(passkey.transports.as_ref())
                })?;
                passkey.name = Some(name.clone());
                put(tx.as_ref(), "authPasskeys", &passkey).await?;
                self.audit(
                    &tx,
                    &principal.identity,
                    "auth:passkey:rename",
                    Some(&principal.session),
                    Some(single("name", name)),
                )
                .await?;
                public_passkey(&passkey)
            })
            .await
    }

    /// `deletePasskey(credentials, { id })`: another login method must remain before the last passkey goes.
    pub async fn delete_passkey(
        &self,
        credentials: &CredentialInput,
        input: &Value,
    ) -> IamResult<Success> {
        self.store()
            .transaction(|tx| async move {
                let principal = self.authenticate(credentials).await?;
                self.require_recent(&principal)?;
                let id = text(prop(input, "id"), "id", 512)?;
                let passkey: Option<PasskeyRecord> = get(tx.as_ref(), "authPasskeys", &id).await?;
                let passkey = match passkey {
                    Some(passkey)
                        if passkey.identity_id == principal.identity.id
                            && passkey.tenant_id == principal.identity.tenant_id =>
                    {
                        passkey
                    }
                    _ => return Err(IamError::with_status("NOT_FOUND", "Passkey not found", 404)),
                };
                let keys = self.identity_passkeys(&tx, &principal.identity).await?;
                let identity = &principal.identity;
                let alternative = identity
                    .password_hash
                    .as_deref()
                    .is_some_and(|hash| !hash.is_empty())
                    || (self.options.passwordless_email == Some(true) && identity.email_verified)
                    || (self.options.passwordless_sms == Some(true)
                        && identity.phone_verified == Some(true));
                if keys.len() == 1 && !alternative {
                    return Err(IamError::with_status(
                        "LAST_AUTHENTICATOR",
                        "Configure another login method before removing the last passkey",
                        409,
                    ));
                }
                tx.delete("authPasskeys", &passkey.id).await?;
                self.revoke_identity(&tx, &principal.identity.id).await?;
                self.audit(&tx, &principal.identity, "auth:passkey:delete", None, None)
                    .await?;
                Ok(Success::TRUE)
            })
            .await
    }
}
