//! Port of `packages/server/src/principals.ts`: credential resolution. User sessions go through the auth service; API
//! keys, role sessions, session tokens, delegated sessions and IAM-signed session JWTs are resolved here. Every
//! credential is backed by a stored session row, re-read and re-validated (`currentPrincipal`) before it is used.

use std::sync::{Arc, Mutex, Weak};

use async_trait::async_trait;
use better_iam_auth::parse_credential_token;
use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError, IamResult, IamStoreExt,
    Identity, IdentityKind, IdentityStatus, Session, SessionKind, Tenant, TenantStatus,
    js as core_js,
};
use serde_json::{Map, Value};

use crate::agents::{assert_agent_usable, machine_identity};
use crate::client_info::client_from_headers;
use crate::context::{ServerContext, Store};
use crate::contracts::PrincipalService;
use crate::delegations::check_delegated_session;
use crate::devices::{device_proof_of, with_request_device};
use crate::flows::trust_requires_mfa;
use crate::models::{OidcProvider, Role, Trust};
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::port::decode;
use crate::session_kinds::revoked_by_watermark;
use crate::session_tokens::{SessionTokenClaims, looks_like_jwt};
use crate::utils::{hash, same_hash};
use crate::validation::text_str;
use better_iam_core::AuditOutcome;

/// The kinds a session token may be minted from; temporary kinds never are (no chaining).
const SESSION_TOKEN_SOURCE_KINDS: [SessionKind; 2] = [SessionKind::User, SessionKind::ApiKey];
/// The kinds a classic role session may be assumed from; a session-token source is re-validated down to its root.
const ROLE_SOURCE_KINDS: [SessionKind; 3] = [
    SessionKind::User,
    SessionKind::ApiKey,
    SessionKind::SessionToken,
];

/// `headers.get(name)` over a credential's headers: every value of the name, joined with ", ".
pub fn credential_header(input: &CredentialInput, name: &str) -> Option<String> {
    let values: Vec<&str> = input
        .headers
        .iter()
        .flatten()
        .filter(|(key, _)| key.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim_matches([' ', '\t', '\n', '\r']))
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

/// `/^Bearer (\S{1,4096})$/i`: the bearer value of an Authorization header.
pub fn bearer_value(header: &str) -> Option<&str> {
    let scheme = header.get(..7)?;
    if !scheme.eq_ignore_ascii_case("bearer ") {
        return None;
    }
    let value = &header[7..];
    let length = core_js::utf16_len(value);
    ((1..=4096).contains(&length) && !value.chars().any(core_js::is_js_whitespace)).then_some(value)
}

/// `credentialValue(input)`: `input.token`, else the bearer header, else '' (the auth service reads cookies).
fn credential_value(input: &CredentialInput) -> IamResult<String> {
    if let Some(token) = input.token.as_deref().filter(|token| !token.is_empty()) {
        return text_str(token, "token", 4096);
    }
    Ok(credential_header(input, "authorization")
        .as_deref()
        .and_then(bearer_value)
        .unwrap_or_default()
        .to_owned())
}

/// `/^[A-Za-z0-9_-]{32,512}$/`: the shape of every opaque token (legacy unprefixed ones included).
fn opaque_token(value: &str) -> bool {
    (32..=512).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn invalid_credentials() -> IamError {
    IamError::with_status("UNAUTHENTICATED", "Invalid credentials", 401)
}
fn expired_or_revoked() -> IamError {
    IamError::with_status("UNAUTHENTICATED", "Credential expired or revoked", 401)
}
fn role_revoked() -> IamError {
    IamError::with_status("UNAUTHENTICATED", "Role credential revoked", 401)
}

/// What `SessionTokenNetworkMismatch` carries besides its error: ids only, never the rows.
#[derive(Debug, Clone)]
struct NetworkMismatch {
    session_id: String,
    identity_id: String,
    session_ip: String,
}

/// `new SessionTokenNetworkMismatch(session)`: a bound session presented from another network. `authenticate`
/// records it as `auth:session:mismatch` after the refusal rolled back; the details travel in the task-local slot of
/// the `authenticate` call in progress (TypeScript reads them from the error instance).
fn network_mismatch(session: &Session) -> IamError {
    let mismatch = NetworkMismatch {
        session_id: session.id.clone(),
        identity_id: session.identity_id.clone(),
        session_ip: session
            .client
            .as_ref()
            .and_then(|client| client.ip.clone())
            .unwrap_or_default(),
    };
    let _ = MISMATCH.try_with(|slot| {
        *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(mismatch);
    });
    IamError::with_status(
        "SESSION_NETWORK_MISMATCH",
        "This session can only be used from the network it was signed in from",
        401,
    )
}

tokio::task_local! {
    static MISMATCH: Arc<Mutex<Option<NetworkMismatch>>>;
}

/// `boundToJwt(session, claims)`: whether a stored row is the one a verified session JWT names.
fn bound_to_jwt(session: &Session, claims: &SessionTokenClaims) -> bool {
    session.format.as_deref() == Some("jwt")
        && session.kind.as_str() == claims.kind
        && session.identity_id == claims.sub
        && session.tenant_id == claims.tid
}

async fn get<T: serde::de::DeserializeOwned>(
    tx: &Store,
    collection: &str,
    id: &str,
) -> IamResult<Option<T>> {
    match tx.get(collection, id).await? {
        Some(record) => Ok(Some(decode(record)?)),
        None => Ok(None),
    }
}

fn client_ip(ctx: &ServerContext) -> Option<String> {
    ctx.auth.current_client().and_then(|client| client.ip)
}

fn session_ip(session: &Session) -> Option<&str> {
    session
        .client
        .as_ref()
        .and_then(|client| client.ip.as_deref())
        .filter(|ip| !ip.is_empty())
}

fn binds_to_ip(tenant: &Tenant) -> bool {
    tenant
        .auth_policy
        .as_ref()
        .and_then(|policy| policy.bind_sessions_to_ip)
        .unwrap_or(false)
}

/// `createPrincipals(ctx)`: the principal service ([`PrincipalService`]).
pub fn create_principals(ctx: &Arc<ServerContext>) -> Arc<Principals> {
    Arc::new(Principals {
        ctx: Arc::downgrade(ctx),
    })
}

/// The principal service of one server context.
pub struct Principals {
    ctx: Weak<ServerContext>,
}

impl Principals {
    fn context(&self) -> IamResult<Arc<ServerContext>> {
        self.ctx.upgrade().ok_or_else(crate::js::internal_error)
    }

    /// `resolveStored(sessionId, tokenHash, bound?, deviceProof?)`: the path every non-user credential shares once
    /// its row is known.
    async fn resolve_stored(
        &self,
        ctx: &Arc<ServerContext>,
        session_id: &str,
        token_hash: &str,
        claims: Option<&SessionTokenClaims>,
        device_proof: Option<String>,
    ) -> IamResult<AuthenticatedPrincipal> {
        ctx.store
            .transaction(|tx| async move {
                let raw = tx.get("sessions", session_id).await?;
                let Some(mut raw) = raw else {
                    return Err(expired_or_revoked());
                };
                let session: Session = decode(raw.clone())?;
                if session.expires_at <= ctx.now()
                    || !same_hash(&session.token_hash, token_hash)
                    || claims.is_some_and(|claims| !bound_to_jwt(&session, claims))
                {
                    return Err(expired_or_revoked());
                }
                let identity: Option<Identity> =
                    get(&tx, "identities", &session.identity_id).await?;
                let Some(identity) =
                    identity.filter(|identity| identity.status == IdentityStatus::Active)
                else {
                    return Err(IamError::with_status(
                        "UNAUTHENTICATED",
                        "Identity disabled",
                        401,
                    ));
                };
                if ctx.identity_expired(&identity) {
                    return Err(IamError::with_status(
                        "UNAUTHENTICATED",
                        "Identity expired",
                        401,
                    ));
                }
                // API keys record when they were last used (at most once a minute) so unused keys can be found.
                let now = ctx.now();
                let current = if session.kind == SessionKind::ApiKey
                    && now - session.last_seen_at >= 60_000.0
                {
                    raw.insert("lastSeenAt".into(), crate::js::number(now));
                    decode(tx.put("sessions", &raw).await?)?
                } else {
                    session
                };
                // The request's device proof goes along: a role session's source decides its assumption again here.
                self.current_principal(
                    &tx,
                    &AuthenticatedPrincipal {
                        identity,
                        session: current,
                        device_proof,
                    },
                )
                .await
            })
            .await
    }

    /// `resolveJwt(value, deviceProof?)`: hybrid session JWTs.
    async fn resolve_jwt(
        &self,
        ctx: &Arc<ServerContext>,
        value: &str,
        device_proof: Option<String>,
    ) -> IamResult<AuthenticatedPrincipal> {
        let Some(signer) = ctx.session_tokens() else {
            return Err(invalid_credentials());
        };
        let issuer = signer.issuer().to_owned();
        let claims = signer
            .verify(value, Some(&issuer))
            .await
            .map_err(|_| invalid_credentials())?;
        let token_hash = hash(value);
        let candidate: Option<Session> = get(&ctx.store, "sessions", &claims.sid).await?;
        let Some(candidate) = candidate.filter(|candidate| {
            bound_to_jwt(candidate, &claims) && same_hash(&candidate.token_hash, &token_hash)
        }) else {
            return Err(expired_or_revoked());
        };
        self.resolve_stored(ctx, &candidate.id, &token_hash, Some(&claims), device_proof)
            .await
    }

    async fn resolve_credential(
        &self,
        ctx: &Arc<ServerContext>,
        input: &CredentialInput,
    ) -> IamResult<AuthenticatedPrincipal> {
        let provided = credential_value(input)?;
        if provided.is_empty() {
            return ctx.auth.authenticate(input).await;
        }
        let device_proof = device_proof_of(input.headers.as_deref());
        if looks_like_jwt(&provided) {
            return self.resolve_jwt(ctx, &provided, device_proof).await;
        }
        // Prefixed tokens route by type; the stored kind stays authoritative and a mismatch never falls back.
        let mut expected: Option<&'static str> = None;
        if provided.starts_with("biam_") {
            let Some(parsed) = parse_credential_token(&provided) else {
                return Err(invalid_credentials());
            };
            if parsed.kind() == "user" {
                return ctx.auth.authenticate(input).await;
            }
            expected = Some(parsed.kind());
        } else if !opaque_token(&provided) {
            // Refused there, unread.
            return ctx.auth.authenticate(input).await;
        }
        let token_hash = hash(&provided);
        let candidate: Option<Session> = ctx
            .store
            .find(
                "sessions",
                &Filter::new().eq("tokenHash", token_hash.clone()),
                &FindOptions::default(),
            )
            .await?
            .into_iter()
            .next()
            .map(decode)
            .transpose()?;
        match expected {
            Some(expected) => {
                if !candidate
                    .as_ref()
                    .is_some_and(|candidate| candidate.kind.as_str() == expected)
                {
                    return Err(invalid_credentials());
                }
            }
            None => {
                if candidate
                    .as_ref()
                    .is_none_or(|candidate| candidate.kind == SessionKind::User)
                {
                    return ctx.auth.authenticate(input).await;
                }
            }
        }
        let candidate = candidate.ok_or_else(invalid_credentials)?;
        self.resolve_stored(ctx, &candidate.id, &token_hash, None, device_proof)
            .await
    }

    /// `checkSessionToken(tx, identity, session)`: a session token lives only as long as its source.
    async fn check_session_token(
        &self,
        tx: &Store,
        identity: &Identity,
        session: &Session,
    ) -> IamResult<()> {
        let source: Option<Session> = match &session.source_session_id {
            Some(id) => get(tx, "sessions", id).await?,
            None => None,
        };
        let revoked = || IamError::with_status("UNAUTHENTICATED", "Session token revoked", 401);
        let Some(source) = source else {
            return Err(revoked());
        };
        if !SESSION_TOKEN_SOURCE_KINDS.contains(&source.kind)
            || source
                .impersonator_id
                .as_deref()
                .is_some_and(|id| !id.is_empty())
            || source.identity_id != identity.id
            || source.tenant_id != session.tenant_id
            || session.tenant_id != identity.tenant_id
            || session.expires_at > source.expires_at
            || session.credential_authority_id != source.credential_authority_id
        {
            return Err(revoked());
        }
        self.current_principal(
            tx,
            &AuthenticatedPrincipal {
                identity: identity.clone(),
                session: source,
                device_proof: None,
            },
        )
        .await?;
        Ok(())
    }

    /// `checkRoleSession(tx, identity, session, request)`.
    async fn check_role_session(
        &self,
        ctx: &Arc<ServerContext>,
        tx: &Store,
        identity: &Identity,
        session: &Session,
        request: &AuthenticatedPrincipal,
    ) -> IamResult<()> {
        let trust: Option<Trust> = match &session.trust_id {
            Some(id) => get(tx, "trusts", id).await?,
            None => None,
        };
        let role: Option<Role> = match &session.role_id {
            Some(id) => get(tx, "roles", id).await?,
            None => None,
        };
        let (Some(trust), Some(role)) = (trust, role) else {
            return Err(role_revoked());
        };
        if trust.revoked
            || trust.tenant_id != session.tenant_id
            || role.tenant_id != session.tenant_id
            || trust.role_id != role.id
            || session.original_identity_id.as_deref() != Some(identity.id.as_str())
            || revoked_by_watermark(
                session.created_at,
                &[trust.sessions_revoked_before, role.sessions_revoked_before],
            )
        {
            return Err(role_revoked());
        }
        if session.web_identity.is_some() {
            self.check_web_identity_session(ctx, tx, identity, session, &trust, &role)
                .await
        } else {
            self.check_classic_role_session(ctx, tx, identity, session, &trust, &role, request)
                .await
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn check_classic_role_session(
        &self,
        ctx: &Arc<ServerContext>,
        tx: &Store,
        identity: &Identity,
        session: &Session,
        trust: &Trust,
        role: &Role,
        request: &AuthenticatedPrincipal,
    ) -> IamResult<()> {
        let source: Option<Session> = match &session.source_session_id {
            Some(id) => get(tx, "sessions", id).await?,
            None => None,
        };
        let consistent = trust.kind.as_deref().unwrap_or("identity") == "identity"
            && trust.source_identity_id == identity.id
            && trust.source_tenant_id == identity.tenant_id
            && session.source_tenant_id.as_deref() == Some(identity.tenant_id.as_str())
            && source.as_ref().is_some_and(|source| {
                ROLE_SOURCE_KINDS.contains(&source.kind)
                    && source.identity_id == identity.id
                    && source.tenant_id == identity.tenant_id
                    // Read fail-closed: any stored value but `false` requires a source session that carries MFA.
                    && !(trust_requires_mfa(trust) && !source.mfa)
            });
        let (true, Some(source)) = (consistent, source) else {
            return Err(role_revoked());
        };
        // The re-decision sees the device this request proves (bound to the role session), as the assumption saw the
        // device of the request that made it.
        let verified_source = with_request_device(
            self.current_principal(
                tx,
                &AuthenticatedPrincipal {
                    identity: identity.clone(),
                    session: source,
                    device_proof: None,
                },
            )
            .await?,
            request,
        );
        for authority_id in session.source_authority_ids.iter().flatten() {
            if ctx.authority_chain(tx, authority_id).await?.is_none() {
                return Err(IamError::with_status(
                    "UNAUTHENTICATED",
                    "Source authority revoked",
                    401,
                ));
            }
        }
        if !self.role_authority_live(ctx, tx, role).await? {
            return Err(IamError::with_status(
                "UNAUTHENTICATED",
                "Role authority revoked",
                401,
            ));
        }
        let decision = ctx
            .decisions()?
            .decide(
                tx,
                &verified_source,
                &AuthorizationRequest {
                    credential: CredentialInput::default(),
                    tenant_id: identity.tenant_id.clone(),
                    action: "iam:roles:assume".into(),
                    resource: ResourceTarget {
                        kind: "iam".into(),
                        id: role.id.clone(),
                    },
                },
                false,
            )
            .await?;
        if !decision.allowed {
            return Err(IamError::with_status(
                "UNAUTHENTICATED",
                "Assumption permission revoked",
                401,
            ));
        }
        Ok(())
    }

    /// `typeof role.authorityId === 'string' && await ctx.authorityChain(tx, role.authorityId)`.
    async fn role_authority_live(
        &self,
        ctx: &Arc<ServerContext>,
        tx: &Store,
        role: &Role,
    ) -> IamResult<bool> {
        match role.extra.get("authorityId").and_then(Value::as_str) {
            Some(authority_id) => Ok(ctx.authority_chain(tx, authority_id).await?.is_some()),
            None => Ok(false),
        }
    }

    /// `checkWebIdentitySession(tx, identity, session, trust, role)`.
    async fn check_web_identity_session(
        &self,
        ctx: &Arc<ServerContext>,
        tx: &Store,
        identity: &Identity,
        session: &Session,
        trust: &Trust,
        role: &Role,
    ) -> IamResult<()> {
        let Some(web) = &session.web_identity else {
            return Err(role_revoked());
        };
        let provider: Option<OidcProvider> = get(tx, "oidcProviders", &web.provider_id).await?;
        let Some(provider) = provider else {
            return Err(role_revoked());
        };
        let trust_authority = trust.authority_id.as_deref();
        if !ctx.config.sts.web_identity.enabled
            || trust.kind.as_deref() != Some("web-identity")
            || trust.provider_id.as_deref() != Some(web.provider_id.as_str())
            || trust.source_identity_id != identity.id
            || trust.source_tenant_id != session.tenant_id
            || identity.kind != IdentityKind::Service
            || identity.tenant_id != session.tenant_id
            || session.source_session_id.is_some()
            || provider.tenant_id != session.tenant_id
            || !provider.enabled
            || provider.issuer != web.issuer
            || revoked_by_watermark(session.created_at, &[provider.sessions_revoked_before])
            || trust_authority.is_none()
            || session.credential_authority_id.as_deref() != trust_authority
        {
            return Err(role_revoked());
        }
        if ctx
            .authority_chain(tx, &provider.authority_id)
            .await?
            .is_none()
            || ctx
                .authority_chain(tx, trust_authority.unwrap_or_default())
                .await?
                .is_none()
        {
            return Err(role_revoked());
        }
        if !self.role_authority_live(ctx, tx, role).await? {
            return Err(IamError::with_status(
                "UNAUTHENTICATED",
                "Role authority revoked",
                401,
            ));
        }
        Ok(())
    }

    /// `resolveRecorded(input)`: `resolveCredential`, noting in the identity's trail when a bound session token was
    /// presented from another network (`auth:session:mismatch`), in its own transaction once the refusal rolled back.
    async fn resolve_recorded(
        &self,
        ctx: &Arc<ServerContext>,
        input: &CredentialInput,
    ) -> IamResult<AuthenticatedPrincipal> {
        let slot: Arc<Mutex<Option<NetworkMismatch>>> = Arc::default();
        let result = MISMATCH
            .scope(slot.clone(), self.resolve_credential(ctx, input))
            .await;
        let Err(error) = result else {
            return result;
        };
        let mismatch = slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(mismatch) = mismatch.filter(|_| error.code == "SESSION_NETWORK_MISMATCH") {
            let client = ctx.auth.current_client();
            let recorded = ctx
                .store
                .transaction(|tx| async move {
                    let identity: Option<Identity> =
                        get(&tx, "identities", &mismatch.identity_id).await?;
                    let session: Option<Session> =
                        get(&tx, "sessions", &mismatch.session_id).await?;
                    let (Some(identity), Some(session)) = (identity, session) else {
                        return Ok(());
                    };
                    let mut metadata = Map::new();
                    metadata.insert(
                        "sessionId".into(),
                        Value::String(mismatch.session_id.clone()),
                    );
                    metadata.insert(
                        "sessionIp".into(),
                        Value::String(mismatch.session_ip.clone()),
                    );
                    if let Some(ip) = client
                        .as_ref()
                        .and_then(|client| client.ip.clone())
                        .filter(|ip| !ip.is_empty())
                    {
                        metadata.insert("ip".into(), Value::String(ip));
                    }
                    if let Some(agent) = client
                        .as_ref()
                        .and_then(|client| client.user_agent.clone())
                        .filter(|agent| !agent.is_empty())
                    {
                        metadata.insert("userAgent".into(), Value::String(agent));
                    }
                    let tenant_id = identity.tenant_id.clone();
                    let identity_id = identity.id.clone();
                    ctx.events()?
                        .audit(
                            &tx,
                            &AuthenticatedPrincipal {
                                identity,
                                session,
                                device_proof: None,
                            },
                            "auth:session:mismatch",
                            &tenant_id,
                            &identity_id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await
                })
                .await;
            // Bookkeeping never masks the refusal.
            let _ = recorded;
        }
        Err(error)
    }

    /// The tenant record of an id, or NOT_FOUND as `ctx.tenant` reports it.
    async fn tenant_chain_inactive(
        ctx: &Arc<ServerContext>,
        tx: &Store,
        tenant: &Tenant,
    ) -> IamResult<bool> {
        Ok(ctx
            .ancestry(tx, tenant)
            .await?
            .iter()
            .any(|item| item.status != TenantStatus::Active))
    }
}

#[async_trait]
impl PrincipalService for Principals {
    async fn authenticate(&self, input: &CredentialInput) -> IamResult<AuthenticatedPrincipal> {
        let ctx = self.context()?;
        // Framework integrations pass the incoming request's headers as the credential and set no client scope. The
        // client is derived from those headers (`http.clientInfo`) so session binding and network checks judge the
        // presenting address as they do behind the HTTP handler.
        let principal = if ctx.auth.current_client().is_none() && input.headers.is_some() {
            let client = client_from_headers(
                ctx.options.http.as_ref(),
                input.headers.as_deref(),
                ctx.config.base_url.as_str(),
            );
            ctx.auth
                .with_client(client, self.resolve_recorded(&ctx, input))
                .await?
        } else {
            self.resolve_recorded(&ctx, input).await?
        };
        // On an organization's own address (`hosts`), only that organization's credentials are accepted.
        ctx.auth.assert_request_host(&principal.session.tenant_id)?;
        // A device proof travels with the principal unverified; decisions verify it (devices.ts).
        Ok(match device_proof_of(input.headers.as_deref()) {
            None => principal,
            Some(proof) => AuthenticatedPrincipal {
                device_proof: Some(proof),
                ..principal
            },
        })
    }

    async fn current_principal(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
    ) -> IamResult<AuthenticatedPrincipal> {
        let ctx = self.context()?;
        let identity: Option<Identity> = get(tx, "identities", &principal.identity.id).await?;
        let session: Option<Session> = get(tx, "sessions", &principal.session.id).await?;
        let now = ctx.now();
        let revoked = || IamError::with_status("UNAUTHENTICATED", "Credential revoked", 401);
        let (Some(identity), Some(session)) = (identity, session) else {
            return Err(revoked());
        };
        if identity.status != IdentityStatus::Active
            || session.expires_at <= now
            || session.identity_id != identity.id
            || session.token_hash != principal.session.token_hash
        {
            return Err(revoked());
        }
        if ctx.identity_expired(&identity) {
            return Err(IamError::with_status(
                "UNAUTHENTICATED",
                "Identity expired",
                401,
            ));
        }
        let realm = ctx.tenant(tx, &identity.tenant_id).await?;
        // `||` short-circuits: the session's tenant is read (and may be NOT_FOUND) only when the realm chain is active.
        if Self::tenant_chain_inactive(&ctx, tx, &realm).await?
            || Self::tenant_chain_inactive(&ctx, tx, &ctx.tenant(tx, &session.tenant_id).await?)
                .await?
        {
            return Err(IamError::with_status(
                "TENANT_INACTIVE",
                "Tenant inactive",
                403,
            ));
        }
        match session.kind {
            SessionKind::User => {
                let limits = ctx.auth.session_limits(Some(&realm));
                if identity.kind != IdentityKind::User
                    || identity.tenant_id != session.tenant_id
                    || now - session.last_seen_at >= limits.idle_timeout_ms
                    || now - session.created_at >= limits.lifetime_ms
                {
                    return Err(IamError::with_status(
                        "UNAUTHENTICATED",
                        "User session expired",
                        401,
                    ));
                }
                if !session.mfa && ctx.auth.mfa_required(tx, &identity).await? {
                    return Err(IamError::with_status(
                        "MFA_REQUIRED",
                        "Multi-factor authentication is required",
                        403,
                    ));
                }
                ctx.auth.assert_impersonation_source(tx, &session).await?;
                // The recorded address is judged as the auth service judges it, so a role session sourced from this
                // one ends as soon as this session's network is blocked or no longer allowed.
                ctx.auth
                    .assert_ip_allowed(Some(&realm), session_ip(&session))?;
                ctx.auth
                    .assert_network_not_blocked(tx, &session.tenant_id, session_ip(&session))
                    .await?;
                // The address presenting the credential now is judged too.
                let presented = client_ip(&ctx);
                let presented = presented.as_deref().filter(|ip| !ip.is_empty());
                ctx.auth
                    .assert_network_not_blocked(tx, &session.tenant_id, presented)
                    .await?;
                if binds_to_ip(&realm)
                    && let (Some(recorded), Some(presented)) = (session_ip(&session), presented)
                    && presented != recorded
                {
                    return Err(network_mismatch(&session));
                }
            }
            SessionKind::ApiKey => {
                let authority_live = match &session.credential_authority_id {
                    Some(authority_id) => ctx.authority_chain(tx, authority_id).await?.is_some(),
                    None => false,
                };
                if !machine_identity(&identity)
                    || identity.tenant_id != session.tenant_id
                    || !authority_live
                {
                    return Err(IamError::with_status(
                        "UNAUTHENTICATED",
                        "Service credential revoked",
                        401,
                    ));
                }
                // An agent's key works only while the agent and its sponsor are in good standing (agents.ts).
                if identity.kind == IdentityKind::Agent {
                    assert_agent_usable(&ctx, tx, &identity).await?;
                }
            }
            SessionKind::SessionToken => self.check_session_token(tx, &identity, &session).await?,
            SessionKind::Role => {
                self.check_role_session(&ctx, tx, &identity, &session, principal)
                    .await?
            }
            SessionKind::Delegated => {
                check_delegated_session(&ctx, tx, &identity, &session, self).await?
            }
        }
        if session.kind != SessionKind::User {
            // API keys, assumed roles and session tokens have no sign-in of their own to refuse, so they are judged
            // against the address presenting them now (and any address recorded on them).
            let target = if session.kind == SessionKind::Role {
                Some(ctx.tenant(tx, &session.tenant_id).await?)
            } else {
                None
            };
            if session.kind == SessionKind::SessionToken {
                let home = ctx.tenant(tx, &session.tenant_id).await?;
                ctx.auth
                    .assert_ip_allowed(Some(&home), session_ip(&session))?;
                // With `bindSessionsToIp`, a session token works only from the network it was issued from.
                if binds_to_ip(&home) {
                    let presented = client_ip(&ctx);
                    if let (Some(recorded), Some(presented)) = (
                        session_ip(&session),
                        presented.as_deref().filter(|ip| !ip.is_empty()),
                    ) && presented != recorded
                    {
                        return Err(network_mismatch(&session));
                    }
                }
            }
            let mut addresses: Vec<Option<String>> = Vec::new();
            for ip in [client_ip(&ctx), session_ip(&session).map(str::to_owned)] {
                if !addresses.contains(&ip) {
                    addresses.push(ip);
                }
            }
            for ip in addresses {
                let ip = ip.as_deref().filter(|ip| !ip.is_empty());
                if let Some(target) = &target {
                    ctx.auth.assert_ip_allowed(Some(target), ip)?;
                }
                ctx.auth
                    .assert_network_not_blocked(tx, &session.tenant_id, ip)
                    .await?;
            }
        }
        // The request's device proof (still unverified) stays with the principal for decisions (devices.ts).
        Ok(AuthenticatedPrincipal {
            identity,
            session,
            device_proof: principal.device_proof.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_values() {
        assert_eq!(bearer_value("Bearer abc"), Some("abc"));
        assert_eq!(bearer_value("bearer abc"), Some("abc"));
        assert_eq!(bearer_value("Bearer  abc"), None);
        assert_eq!(bearer_value("Bearer "), None);
        assert_eq!(bearer_value("Basic abc"), None);
        assert_eq!(bearer_value("Bearer a b"), None);
        assert!(opaque_token(&"a".repeat(32)));
        assert!(!opaque_token(&"a".repeat(31)));
        assert!(!opaque_token(&format!("{}!", "a".repeat(40))));
    }
}
