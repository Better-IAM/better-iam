//! Port of `packages/server/src/api/sts.ts`: the `sts` group: temporary credentials (GetSessionToken,
//! GetCallerIdentity) plus the public web-identity exchange. Every method takes the caller's credential first; tokens
//! are returned once, in the response body, and never set a cookie.

use std::collections::HashMap;
use std::sync::Arc;

use better_iam_auth::service::{LimitAttemptOptions, RateTier};
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, Identity, Record, Session, SessionKind,
};
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply};
use crate::client_info::client_from_headers;
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, OperationFailure};
use crate::session_kinds::acts_in_own_right;
use crate::temporary_credentials::{
    audience_value, caller_identity, credential_format, duration_within, mint_credential,
    session_name_value, session_token_duration_bounds, temporary_credential,
};
use crate::utils::id;
use crate::web_identity_exchange::{WebIdentityStsApi, create_web_identity_sts_api};
use better_iam_types::api::sts;

fn chaining_disabled() -> IamError {
    IamError::with_status(
        "CREDENTIAL_CHAINING_DISABLED",
        "Temporary credentials cannot mint session tokens",
        400,
    )
}

/// `TokenStanding`: how a stored session token stands for the per-identity cap: `Live` (usable, counts), `Dead` (can
/// never be used again, so it is deleted) or `Suspended` (refused for now for a reason that can be lifted, such as a
/// network block or a tenant's MFA requirement; neither counted nor deleted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenStanding {
    Live,
    Dead,
    Suspended,
}

fn truthy_text(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|text| !text.is_empty())
}

/// `tokenStanding(ctx, tx, identity, token, now, sources)`: judges a session token of `identity` as `principals`
/// would, without its per-use network checks: the token must be unexpired and consistent with a stored source (a user
/// session or API key of the same identity and tenant, never an impersonation, which it does not outlive and whose
/// authority it carries), and the source must still pass re-validation. A source refused as `UNAUTHENTICATED`
/// (signed out, expired, idled out, key authority revoked) never comes back, so its tokens are dead. Source verdicts
/// are cached per source in `sources`.
async fn token_standing(
    ctx: &ServerContext,
    tx: &Store,
    identity: &Identity,
    token: &Session,
    now: f64,
    sources: &mut HashMap<String, TokenStanding>,
) -> IamResult<TokenStanding> {
    let Some(source_id) = token
        .source_session_id
        .as_deref()
        .filter(|_| token.expires_at > now)
    else {
        return Ok(TokenStanding::Dead);
    };
    let source: Option<Session> = match tx.get("sessions", source_id).await? {
        Some(record) => Some(crate::port::decode(record)?),
        None => None,
    };
    let Some(source) = source.filter(|source| {
        matches!(source.kind, SessionKind::User | SessionKind::ApiKey)
            && !truthy_text(&source.impersonator_id)
            && source.identity_id == identity.id
            && source.tenant_id == token.tenant_id
            && token.tenant_id == identity.tenant_id
            && source.expires_at > now
            && token.expires_at <= source.expires_at
            && token.credential_authority_id == source.credential_authority_id
    }) else {
        return Ok(TokenStanding::Dead);
    };
    if let Some(cached) = sources.get(&source.id) {
        return Ok(*cached);
    }
    let principal = AuthenticatedPrincipal {
        identity: identity.clone(),
        session: source.clone(),
        device_proof: None,
    };
    let standing = match ctx.principals()?.current_principal(tx, &principal).await {
        Ok(_) => TokenStanding::Live,
        // Exceptions that are not IamErrors in TypeScript propagate.
        Err(error) if error.code == "INTERNAL_ERROR" => return Err(error),
        Err(error) if error.code == "UNAUTHENTICATED" => TokenStanding::Dead,
        Err(_) => TokenStanding::Suspended,
    };
    sources.insert(source.id.clone(), standing);
    Ok(standing)
}

/// The `sts` API group (`createStsApi(ctx)`): one method per route `sts/{method}`.
pub struct StsApi {
    ctx: Arc<ServerContext>,
    web_identity: WebIdentityStsApi,
}

/// `createStsApi(ctx)`.
pub fn create_sts_api(ctx: &Arc<ServerContext>) -> IamResult<StsApi> {
    Ok(StsApi {
        ctx: ctx.clone(),
        web_identity: create_web_identity_sts_api(ctx)?,
    })
}

impl StsApi {
    /// `sts/assumeRoleWithWebIdentity` (public: no credential): see
    /// [`WebIdentityStsApi::assume_role_with_web_identity`].
    pub async fn assume_role_with_web_identity(
        &self,
        input: Body<sts::AssumeRoleWithWebIdentityInput>,
    ) -> IamResult<Reply<sts::AssumeRoleWithWebIdentityOutput>> {
        let input = Value::Object(input.raw().clone());
        let credential = self
            .web_identity
            .assume_role_with_web_identity(&input)
            .await?;
        Ok(Reply::json(credential))
    }

    /// `sts/getCallerIdentity`: who the presented credential acts as, for every session kind (user, impersonation,
    /// API key, role session, session token, session JWT). The credential is re-validated like any other use, so this
    /// doubles as the online revocation check for holders of a session JWT. Needs no permission and writes no audit
    /// event; the result is an allowlist projection that never carries hashes, policies or authority ids.
    pub async fn get_caller_identity(
        &self,
        credential: &CredentialInput,
        input: Body<sts::GetCallerIdentityInput>,
    ) -> IamResult<Reply<sts::GetCallerIdentityOutput>> {
        let _ = input;
        let ctx = &self.ctx;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let principals = ctx.principals()?.clone();
        let principal = ctx
            .store
            .transaction(
                |tx| async move { principals.current_principal(&tx, &authenticated).await },
            )
            .await?;
        let identity = caller_identity(&principal)?;
        let value = serde_json::to_value(&identity).map_err(|_| crate::js::internal_error())?;
        Ok(Reply::json(value))
    }

    /// `sts/getSessionToken`: a temporary credential of kind 'session-token' (`biam_sts_…`, or a session JWT with
    /// `format: 'jwt'`) for the caller's own identity, minted from a user session (not impersonated) or an API key.
    /// Needs `iam:session-tokens:create` on `iam/{identityId}` in the identity's tenant. The token acts with the
    /// identity's grants, bounded by `input.policy` and by the source's own policy (API-key scopes, kept as
    /// `sourcePolicy`) and authority; it expires with its source at the latest, ends when the source ends, and cannot
    /// pass recent-authentication, ownership, root or self-service checks.
    ///
    /// With `mfaCode` (user sources whose identity has TOTP enabled only), a first-hand code is verified and the token
    /// carries a fresh MFA time; the attempt counts against the sensitive rate limit first. Without it, the source's
    /// MFA state is copied (API keys: never MFA). Live tokens per identity are capped
    /// (`sts.maxSessionTokensPerIdentity`): tokens that can never be used again are deleted at issuance, and tokens
    /// whose source is refused for a liftable reason do not count while it lasts. Audited as the operation plus a
    /// `session-token:issued` event naming the new session.
    ///
    /// The issuing client is recorded on the token. Callers that pass the incoming request's headers as the credential
    /// (with no client scope set) get the client derived from those headers, exactly as behind the HTTP handler.
    pub async fn get_session_token(
        &self,
        credential: &CredentialInput,
        input: Body<sts::GetSessionTokenInput>,
    ) -> IamResult<Reply<sts::GetSessionTokenOutput>> {
        let ctx = &self.ctx;
        let request = input.raw().clone();
        let issued = if ctx.auth.current_client().is_none() && credential.headers.is_some() {
            let client = client_from_headers(
                ctx.options.http.as_ref(),
                credential.headers.as_deref(),
                ctx.config.base_url.as_str(),
            );
            ctx.auth
                .with_client(client, self.issue_session_token(credential, &request))
                .await?
        } else {
            self.issue_session_token(credential, &request).await?
        };
        Ok(Reply::json(issued))
    }

    /// `issueSessionToken(credential, input)`: GetSessionToken inside the caller's client scope.
    async fn issue_session_token(
        &self,
        credential: &CredentialInput,
        request: &Map<String, Value>,
    ) -> IamResult<Value> {
        let ctx = &self.ctx;
        let source = ctx.principals()?.authenticate(credential).await?;
        if truthy_text(&source.session.impersonator_id) {
            return Err(IamError::with_status(
                "IMPERSONATION_RESTRICTED",
                "Session tokens cannot be minted while impersonating a member",
                403,
            ));
        }
        if !acts_in_own_right(source.session.kind) {
            return Err(chaining_disabled());
        }
        let mfa_code = request.get("mfaCode").cloned();
        if let Some(code) = &mfa_code {
            if source.session.kind != SessionKind::User {
                return Err(IamError::with_status(
                    "MFA_NOT_ENROLLED",
                    "Only a signed-in person can verify MFA",
                    403,
                ));
            }
            // Counted before anything else is examined and outside any transaction, so a refusal cannot roll it back.
            ctx.auth
                .limit_attempt(
                    &source.identity.tenant_id,
                    &format!("step-up:{}", source.identity.id),
                    LimitAttemptOptions {
                        tier: Some(RateTier::Sensitive),
                        ..LimitAttemptOptions::default()
                    },
                )
                .await?;
            if !code.is_string() {
                return Err(IamError::new("INVALID_INPUT", "mfaCode must be a string"));
            }
        }
        let mfa_code: Option<String> = mfa_code.and_then(|code| code.as_str().map(str::to_owned));
        // Input shapes are refused before the operation; the policy is validated against the catalog inside it.
        let session_name = session_name_value(request.get("sessionName"))?;
        let format = credential_format(request.get("format"))?;
        let audience = audience_value(request.get("audience"), &format)?;
        let format_value = serde_json::to_value(&format).unwrap_or(Value::Null);
        if format_value == "jwt" && ctx.session_tokens().is_none() {
            return Err(IamError::with_status(
                "FEATURE_DISABLED",
                "Session JWTs are not enabled on this deployment (sts.jwt)",
                403,
            ));
        }
        let bounds = session_token_duration_bounds(ctx, &format)?;
        let duration_seconds = duration_within(request.get("durationSeconds"), &bounds)?;
        let policy = request.get("policy").cloned();
        if policy.as_ref().is_some_and(|policy| !policy.is_object()) {
            return Err(IamError::new(
                "INVALID_INPUT",
                "policy must be a policy document",
            ));
        }
        let identity_id = source.identity.id.clone();
        let tenant_id = source.identity.tenant_id.clone();
        let source_session_id = source.session.id.clone();
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                // The re-validated principal must still be the credential examined above, acting in its own right.
                if principal.identity.id != identity_id
                    || principal.session.id != source_session_id
                    || truthy_text(&principal.session.impersonator_id)
                {
                    return Err(OperationFailure::from(IamError::with_status(
                        "UNAUTHENTICATED",
                        "Credential revoked",
                        401,
                    )));
                }
                if !acts_in_own_right(principal.session.kind) {
                    return Err(chaining_disabled().into());
                }
                if let Some(policy) = &policy {
                    ctx.catalog
                        .validate(tx.as_ref(), &tenant_id, policy)
                        .await?;
                }
                let step_up = match &mfa_code {
                    Some(code) => Some(
                        ctx.auth
                            .verify_step_up_code(&tx, &principal.identity, code)
                            .await?,
                    ),
                    None => None,
                };
                // The injected clock, like user sessions, so validation and issuance agree under a test clock.
                let now = ctx.now();
                // Only tokens that can still be used hold a place under the cap, and dead ones are deleted here, so the
                // cap bounds the stored rows too.
                let mut live = 0usize;
                let mut sources: HashMap<String, TokenStanding> = HashMap::new();
                let tokens = tx
                    .find(
                        "sessions",
                        &Filter::new()
                            .eq("identityId", identity_id.clone())
                            .eq("kind", "session-token"),
                        &FindOptions::default(),
                    )
                    .await?;
                for record in tokens {
                    let session: Session = crate::port::decode(record)?;
                    if session.kind != SessionKind::SessionToken
                        || session.identity_id != identity_id
                    {
                        continue;
                    }
                    let standing =
                        token_standing(ctx, &tx, &principal.identity, &session, now, &mut sources)
                            .await?;
                    match standing {
                        TokenStanding::Dead => tx.delete("sessions", &session.id).await?,
                        TokenStanding::Live => live += 1,
                        TokenStanding::Suspended => {}
                    }
                }
                if live as f64 >= ctx.config.sts.max_session_tokens_per_identity {
                    return Err(IamError::with_status(
                        "LIMIT_EXCEEDED",
                        "This identity holds the maximum number of live session tokens",
                        409,
                    )
                    .into());
                }
                let source_session = &principal.session;
                // API keys never carry MFA; a person's session passes its own MFA state on unless a code was verified
                // now.
                let source_mfa = source_session.kind == SessionKind::User && source_session.mfa;
                let mut draft = Record::new();
                draft.insert("id".into(), Value::String(id()));
                draft.insert("tenantId".into(), Value::String(tenant_id.clone()));
                draft.insert("identityId".into(), Value::String(identity_id.clone()));
                draft.insert("kind".into(), Value::from("session-token"));
                draft.insert(
                    "sourceSessionId".into(),
                    Value::String(source_session.id.clone()),
                );
                draft.insert("tokenHash".into(), Value::from(""));
                draft.insert("createdAt".into(), crate::js::number(now));
                draft.insert("lastSeenAt".into(), crate::js::number(now));
                draft.insert(
                    "authenticatedAt".into(),
                    crate::js::number(source_session.authenticated_at),
                );
                draft.insert(
                    "expiresAt".into(),
                    crate::js::number(
                        source_session
                            .expires_at
                            .min(now + duration_seconds * 1000.0),
                    ),
                );
                draft.insert("mfa".into(), Value::Bool(step_up.is_some() || source_mfa));
                if step_up.is_some() {
                    draft.insert("mfaAuthenticatedAt".into(), crate::js::number(now));
                } else if source_mfa && let Some(at) = source_session.mfa_authenticated_at {
                    draft.insert("mfaAuthenticatedAt".into(), crate::js::number(at));
                }
                if let Some(policy) = &policy {
                    draft.insert("policy".into(), policy.clone());
                }
                if let Some(source_policy) = &source_session.policy {
                    draft.insert("sourcePolicy".into(), source_policy.to_value());
                }
                if let Some(authority) = &source_session.credential_authority_id {
                    draft.insert(
                        "credentialAuthorityId".into(),
                        Value::String(authority.clone()),
                    );
                }
                if let Some(name) = &session_name {
                    draft.insert("sessionName".into(), Value::String(name.clone()));
                }
                // The issuing address: the tenant's allowlist judges it on every use, network blocks judge it and the
                // presenting address.
                if let Some(client) = ctx.auth.current_client() {
                    let client = crate::port::encode(&client);
                    if !client.is_empty() {
                        draft.insert("client".into(), Value::Object(client));
                    }
                }
                let mut mint = Map::new();
                mint.insert(
                    "identity".into(),
                    Value::Object(crate::port::encode(&principal.identity)),
                );
                mint.insert("draft".into(), Value::Object(draft));
                mint.insert("format".into(), format_value.clone());
                if let Some(audience) = &audience {
                    mint.insert("audience".into(), json!(audience));
                }
                let minted = mint_credential(ctx, &tx, &Value::Object(mint)).await?;
                let token = minted
                    .get("token")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let session: Session =
                    serde_json::from_value(minted.get("session").cloned().unwrap_or(Value::Null))
                        .map_err(|_| crate::js::internal_error())?;
                let mut metadata = Map::new();
                metadata.insert("sessionId".into(), Value::String(session.id.clone()));
                metadata.insert(
                    "sourceSessionKind".into(),
                    Value::from(source_session.kind.as_str()),
                );
                metadata.insert(
                    "durationSeconds".into(),
                    crate::js::number(duration_seconds),
                );
                metadata.insert("format".into(), format_value.clone());
                metadata.insert("mfaStepUp".into(), Value::Bool(step_up.is_some()));
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "session-token:issued",
                        &tenant_id,
                        &identity_id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                let credential = temporary_credential(&token, &session, now)?;
                Ok(serde_json::to_value(&credential).map_err(|_| crate::js::internal_error())?)
            })
        });
        let tenant_value = Value::String(source.identity.tenant_id.clone());
        ctx.operations()?
            .operation(
                credential,
                Some(&tenant_value),
                "iam:session-tokens:create",
                &source.identity.id,
                mutation,
                false,
            )
            .await
    }
}
