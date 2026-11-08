//! Delegation tokens for services outside Better IAM: an agent acting for a person gets one from
//! `delegations.issueToken` and presents it (typically as a bearer token); the service checks it here, offline, with
//! the issuing deployment's public keys (the same JWKS as its agent cards). The token says who the person is
//! (`person_id`), which agent acts for them (`agent_id`, and `chain` when the work was handed on between agents),
//! which organization, and which scopes of the delegation it carries. The service still decides what that person may
//! do (delegation-tokens.ts).

use std::sync::{Arc, Mutex};

use better_iam_core::{
    DELEGATION_TOKEN_TYPE, DelegationTokenExpectations, DelegationTokenRead,
    DelegationTokenRejection, DelegationTokenSummary, js, read_delegation_token_claims,
};
use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cards::{
    AgentCardErrorReason, Clock, TrustedKeys, fetch_jwks, from_base64_url, pick_key,
    verify_signature,
};
use crate::error::A2aError;
use crate::transport::{DEFAULT_FETCH, Fetch, decode_utf8};

/// Why [`verify_delegation_token`] refused a token (`DelegationTokenErrorReason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DelegationTokenErrorReason {
    Malformed,
    Issuer,
    Audience,
    Tenant,
    Expired,
    NotYetValid,
    Lifetime,
    Type,
    UntrustedKey,
    Signature,
    Replay,
    Fetch,
}

impl DelegationTokenErrorReason {
    /// The TypeScript string (`not-yet-valid`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            DelegationTokenErrorReason::Malformed => "malformed",
            DelegationTokenErrorReason::Issuer => "issuer",
            DelegationTokenErrorReason::Audience => "audience",
            DelegationTokenErrorReason::Tenant => "tenant",
            DelegationTokenErrorReason::Expired => "expired",
            DelegationTokenErrorReason::NotYetValid => "not-yet-valid",
            DelegationTokenErrorReason::Lifetime => "lifetime",
            DelegationTokenErrorReason::Type => "type",
            DelegationTokenErrorReason::UntrustedKey => "untrusted-key",
            DelegationTokenErrorReason::Signature => "signature",
            DelegationTokenErrorReason::Replay => "replay",
            DelegationTokenErrorReason::Fetch => "fetch",
        }
    }
}

impl From<DelegationTokenRejection> for DelegationTokenErrorReason {
    fn from(rejection: DelegationTokenRejection) -> Self {
        match rejection {
            DelegationTokenRejection::Malformed => DelegationTokenErrorReason::Malformed,
            DelegationTokenRejection::Issuer => DelegationTokenErrorReason::Issuer,
            DelegationTokenRejection::Audience => DelegationTokenErrorReason::Audience,
            DelegationTokenRejection::Tenant => DelegationTokenErrorReason::Tenant,
            DelegationTokenRejection::Expired => DelegationTokenErrorReason::Expired,
            DelegationTokenRejection::NotYetValid => DelegationTokenErrorReason::NotYetValid,
            DelegationTokenRejection::Lifetime => DelegationTokenErrorReason::Lifetime,
        }
    }
}

/// Why [`verify_delegation_token`] refused a token (`DelegationTokenError`): `reason` is `malformed`, `type`,
/// `issuer`, `untrusted-key`, `signature`, `audience`, `tenant`, `expired`, `not-yet-valid`, `lifetime`, `replay` or
/// `fetch`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct DelegationTokenError {
    pub reason: DelegationTokenErrorReason,
    pub message: String,
}

impl DelegationTokenError {
    pub fn new(reason: DelegationTokenErrorReason, message: impl Into<String>) -> Self {
        DelegationTokenError {
            reason,
            message: message.into(),
        }
    }

    /// `error.name`.
    pub fn name(&self) -> &'static str {
        "DelegationTokenError"
    }
}

fn refused(reason: DelegationTokenErrorReason, message: impl Into<String>) -> A2aError {
    A2aError::DelegationToken(DelegationTokenError::new(reason, message))
}

/// Records a verified token's id until it expires (`replay`); answers false when the id was seen before.
pub type ReplayCheck =
    Arc<dyn Fn(String, f64) -> BoxFuture<'static, Result<bool, A2aError>> + Send + Sync>;

/// `VerifyDelegationTokenOptions`.
#[derive(Clone, Default)]
pub struct VerifyDelegationTokenOptions {
    /// The audience your service answers to: the token's `aud` must be exactly this.
    pub audience: String,
    /// The Better IAM deployments you trust, by issuer (their `a2a` issuer): each one's JWKS URL (`a2a.jwksUrl`) or
    /// its JWKS. A token is checked only with the keys of the issuer it names.
    pub trusted_issuers: IndexMap<String, TrustedKeys>,
    /// Accept only tokens of this organization (tenant id).
    pub tenant_id: Option<String>,
    /// Records a verified token's id until it expires; answer false when the id was seen before to refuse the
    /// replay. Without it a token may be used again until it expires (at most an hour, usually five minutes).
    pub replay: Option<ReplayCheck>,
    /// Allowed clock difference in seconds (default 30).
    pub clock_tolerance_seconds: Option<f64>,
    /// How long fetched key sets are kept, in seconds (default 300).
    pub jwks_cache_seconds: Option<f64>,
    pub now: Option<Clock>,
    pub fetch: Option<Arc<dyn Fetch>>,
}

/// `decodeJson(part)`: the JSON a base64url part holds, or None.
fn decode_json(part: &str) -> Option<Value> {
    let bytes = from_base64_url(part).ok()?;
    js::parse(&decode_utf8(&bytes)).ok()
}

/// `String(value)` of a claim (`undefined` when absent).
fn js_string(value: Option<&Value>) -> String {
    match value {
        None => "undefined".to_owned(),
        Some(value) => better_iam_auth::util::js_string(value),
    }
}

/// Verifies a delegation token: a compact JWT of type `biam-delegation+jwt`, signed (EdDSA or ES256) by a key of the
/// trusted issuer it names, for exactly `audience` (and `tenant_id`), current, and issued for at most an hour.
/// Returns who acts for whom; fails with a `DelegationTokenError` otherwise. Revocation reaches a token only when it
/// expires, so keep lifetimes short, or verify inside the deployment with `iam.a2a.verify_delegation_token(token,
/// { live: true })` (`verifyDelegationToken`).
pub async fn verify_delegation_token(
    token: &str,
    options: &VerifyDelegationTokenOptions,
) -> Result<DelegationTokenSummary, A2aError> {
    if options.audience.is_empty() {
        return Err(A2aError::type_error(
            "verifyDelegationToken needs audience and trustedIssuers",
        ));
    }
    if js::utf16_len(token) > 16_384 {
        return Err(refused(
            DelegationTokenErrorReason::Malformed,
            "Not a delegation token",
        ));
    }
    let parts: Vec<&str> = token.split('.').collect();
    let compact = parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        });
    if !compact {
        return Err(refused(
            DelegationTokenErrorReason::Malformed,
            "Not a compact JWT",
        ));
    }
    let (protected_header, payload, signature_part) = (parts[0], parts[1], parts[2]);
    let header = decode_json(protected_header);
    let claims = decode_json(payload);
    let (Some(Value::Object(header)), Some(Value::Object(claims))) = (header, claims) else {
        return Err(refused(
            DelegationTokenErrorReason::Malformed,
            "The token is not a JWT",
        ));
    };
    if header.get("typ").and_then(Value::as_str) != Some(DELEGATION_TOKEN_TYPE) {
        return Err(refused(
            DelegationTokenErrorReason::Type,
            "The token is not a delegation token",
        ));
    }
    let alg = match header.get("alg").and_then(Value::as_str) {
        Some(alg @ ("EdDSA" | "ES256")) => Some(alg),
        _ => None,
    };
    let kid = header.get("kid").and_then(Value::as_str);
    let (Some(alg), Some(kid)) = (alg, kid) else {
        return Err(refused(
            DelegationTokenErrorReason::Malformed,
            "The token header is not acceptable",
        ));
    };
    if header.contains_key("crit") || header.contains_key("b64") {
        return Err(refused(
            DelegationTokenErrorReason::Malformed,
            "The token header is not acceptable",
        ));
    }
    // The issuer is read before the signature is checked only to pick its keys; the signature then binds the two.
    let issuer = match claims.get("iss") {
        Some(Value::String(issuer)) if options.trusted_issuers.contains_key(issuer) => {
            issuer.clone()
        }
        other => {
            return Err(refused(
                DelegationTokenErrorReason::Issuer,
                format!("The token was issued by {}", js_string(other)),
            ));
        }
    };
    let source = &options.trusted_issuers[&issuer];
    let now = match &options.now {
        Some(now) => now(),
        None => js::now_ms(),
    };
    let fetcher = options
        .fetch
        .clone()
        .unwrap_or_else(|| DEFAULT_FETCH.clone());
    let looked_up: Result<Option<Value>, Option<A2aError>> = async {
        match source {
            TrustedKeys::Url(url) => {
                let cache_seconds = options.jwks_cache_seconds.unwrap_or(300.0);
                let first = fetch_jwks(url, &fetcher, now, cache_seconds, false)
                    .await
                    .map_err(Some)?;
                if let Some(key) = pick_key(&first, kid, alg).map_err(|()| None)? {
                    return Ok(Some(key.clone()));
                }
                let second = fetch_jwks(url, &fetcher, now, cache_seconds, true)
                    .await
                    .map_err(Some)?;
                Ok(pick_key(&second, kid, alg).map_err(|()| None)?.cloned())
            }
            TrustedKeys::Jwks(jwks) => Ok(pick_key(jwks, kid, alg).map_err(|()| None)?.cloned()),
        }
    }
    .await;
    let jwk = match looked_up {
        Ok(jwk) => jwk,
        Err(Some(A2aError::Card(error))) if error.reason != AgentCardErrorReason::Fetch => {
            return Err(refused(
                DelegationTokenErrorReason::UntrustedKey,
                error.message,
            ));
        }
        Err(_) => {
            return Err(refused(
                DelegationTokenErrorReason::Fetch,
                format!("Could not fetch the keys of {issuer}"),
            ));
        }
    };
    let Some(jwk) = jwk else {
        return Err(refused(
            DelegationTokenErrorReason::UntrustedKey,
            "The token is not signed with a trusted key",
        ));
    };
    let Ok(signature) = from_base64_url(signature_part) else {
        return Err(refused(
            DelegationTokenErrorReason::Malformed,
            "The token signature is not base64url",
        ));
    };
    let signing_input = format!("{protected_header}.{payload}");
    if !verify_signature(&jwk, alg, signing_input.as_bytes(), &signature) {
        return Err(refused(
            DelegationTokenErrorReason::Signature,
            "The token signature does not verify",
        ));
    }
    let read = read_delegation_token_claims(
        &Value::Object(claims),
        &DelegationTokenExpectations {
            issuer: vec![issuer],
            audience: options.audience.clone(),
            tenant_id: options.tenant_id.clone(),
            now,
            clock_tolerance_seconds: options.clock_tolerance_seconds,
        },
    )?;
    let token = match read {
        DelegationTokenRead::Token(token) => *token,
        DelegationTokenRead::Rejected { rejected, message } => {
            return Err(refused(rejected.into(), message));
        }
    };
    if let Some(replay) = &options.replay
        && !replay(token.token_id.clone(), token.expires_at).await?
    {
        return Err(refused(
            DelegationTokenErrorReason::Replay,
            "The token was used before",
        ));
    }
    Ok(token)
}

/// A token Better IAM issued: `{ token, expiresAt }` of `delegations.issueToken`.
#[derive(Debug, Clone, PartialEq)]
pub struct IssuedDelegationToken {
    pub token: String,
    pub expires_at: f64,
}

/// Gets a new token for an audience and scopes, for example with `iam.api.delegations.issue_token`.
pub type DelegationTokenIssuer = Arc<
    dyn Fn(
            String,
            Option<Vec<String>>,
        ) -> BoxFuture<'static, Result<IssuedDelegationToken, A2aError>>
        + Send
        + Sync,
>;

/// `DelegationTokenCacheOptions`.
#[derive(Clone)]
pub struct DelegationTokenCacheOptions {
    /// Gets a new token.
    pub issue: DelegationTokenIssuer,
    /// Get a new token once less than this share of its lifetime is left (default 0.2), or 15 seconds.
    pub refresh_share: Option<f64>,
    pub now: Option<Clock>,
}

struct CachedToken {
    token: String,
    issued_at: f64,
    expires_at: f64,
}

type SharedToken = Shared<BoxFuture<'static, Result<String, A2aError>>>;

struct TokenCacheState {
    options: DelegationTokenCacheOptions,
    tokens: Mutex<IndexMap<String, CachedToken>>,
    pending: Mutex<IndexMap<String, SharedToken>>,
}

/// For the agent side ([`create_delegation_token_cache`]): [`DelegationTokenCache::token`] yields a current
/// delegation token for an audience (and scopes), issuing one on first use and again when it nears its end, so an
/// agent calling a service repeatedly does not ask for a token on every call. Concurrent calls for the same audience
/// share one request.
#[derive(Clone)]
pub struct DelegationTokenCache {
    state: Arc<TokenCacheState>,
}

/// `createDelegationTokenCache(options)`.
pub fn create_delegation_token_cache(options: DelegationTokenCacheOptions) -> DelegationTokenCache {
    DelegationTokenCache {
        state: Arc::new(TokenCacheState {
            options,
            tokens: Mutex::new(IndexMap::new()),
            pending: Mutex::new(IndexMap::new()),
        }),
    }
}

impl DelegationTokenCache {
    /// A current token for `audience` and `scopes`.
    pub async fn token(
        &self,
        audience: &str,
        scopes: Option<&[String]>,
    ) -> Result<String, A2aError> {
        let state = &self.state;
        let mut sorted: Option<Vec<String>> = scopes.map(<[String]>::to_vec);
        if let Some(sorted) = &mut sorted {
            sorted.sort_by(|left, right| js::cmp_utf16(left, right));
        }
        let key = js::stringify(&Value::Array(vec![
            Value::String(audience.to_owned()),
            match &sorted {
                Some(sorted) => Value::Array(sorted.iter().cloned().map(Value::String).collect()),
                None => Value::Null,
            },
        ]));
        let at = match &state.options.now {
            Some(now) => now(),
            None => js::now_ms(),
        };
        let share = state.options.refresh_share.unwrap_or(0.2);
        let run = {
            let tokens = state
                .tokens
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(current) = tokens.get(&key) {
                let left = current.expires_at - at;
                if left > f64::max(15_000.0, (current.expires_at - current.issued_at) * share) {
                    return Ok(current.token.clone());
                }
            }
            drop(tokens);
            let mut pending = state
                .pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(running) = pending.get(&key) {
                running.clone()
            } else {
                let task_state = self.state.clone();
                let task_key = key.clone();
                let audience = audience.to_owned();
                let scopes = scopes.map(<[String]>::to_vec);
                let run = async move {
                    let result = (task_state.options.issue)(audience, scopes).await;
                    let outcome = match result {
                        Ok(issued) => {
                            let mut tokens = task_state
                                .tokens
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            tokens.insert(
                                task_key.clone(),
                                CachedToken {
                                    token: issued.token.clone(),
                                    issued_at: at,
                                    expires_at: issued.expires_at,
                                },
                            );
                            if tokens.len() > 256 {
                                tokens.shift_remove_index(0);
                            }
                            Ok(issued.token)
                        }
                        Err(error) => Err(error),
                    };
                    task_state
                        .pending
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .shift_remove(&task_key);
                    outcome
                }
                .boxed()
                .shared();
                pending.insert(key, run.clone());
                run
            }
        };
        run.await
    }
}
