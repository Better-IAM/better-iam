//! Port of `packages/server/src/web-identity-exchange.ts`: AssumeRoleWithWebIdentity, the public exchange of a
//! verified external OIDC token (GitHub Actions, GitLab, Kubernetes, cloud workload identity) for a role session under
//! a web-identity trust (`sts/assumeRoleWithWebIdentity`, listed in `publicApiMethods`), plus the administrators' dry
//! run (`trust.evaluateWebIdentity`).
//!
//! The external token is the only credential, so the exchange is built against enumeration: the feature flag and the
//! input shape are checked first, the per-trust rate limit is consumed before anything is looked up, and every failure
//! that depends on stored state or on the token is the same WEB_IDENTITY_REJECTED (403). Only once a verified token has
//! matched the trust do specific errors surface (rate and network refusals, the per-trust session cap, duration,
//! policy, format and audience problems). Denials are audited best-effort, and only once the trust has resolved in its
//! tenant; claims are recorded only when the signature verified, and the raw token is never stored or recorded.

use std::sync::{Arc, LazyLock};

use better_iam_auth::service::LimitAttemptOptions;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, Filter, FindOptions, IamError, IamResult, IamStoreExt,
    Identity, Record, Tenant, TenantStatus,
};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::js::utf16_len;
use crate::temporary_credentials::{
    audience_value, credential_format, duration_within, mint_credential, role_duration_bounds,
    session_tags_value, temporary_credential,
};
use crate::utils::id;
use crate::validation::text;
use crate::web_identity::{
    VerifiedWebIdentity, WebIdentityFailure, match_web_identity_conditions,
    web_identity_conditions, web_identity_replay_id,
};

/// `trust.evaluateWebIdentity`: what the exchange would conclude about a token, without issuing anything.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebIdentityEvaluation {
    /// Whether the signature, issuer, audience and time claims verified against the provider.
    #[serde(rename = "verified")]
    pub verified: bool,
    /// The verified registered claims; `aud` is the provider audience the token was accepted for.
    #[serde(rename = "claims", default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Value>,
    /// The trust conditions; `failed` lists each unmet entry as `Operator:key`.
    #[serde(
        rename = "conditions",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub conditions: Option<Value>,
    /// The session tags the trust's `tagClaims` would map.
    #[serde(
        rename = "sessionTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_tags: Option<IndexMap<String, String>>,
    /// The source identity the trust's `sourceIdentityClaim` would map.
    #[serde(
        rename = "sourceIdentity",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_identity: Option<String>,
    /// Set when the exchange would refuse the token (`WebIdentityRejectionReason`).
    #[serde(rename = "reason", default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl WebIdentityEvaluation {
    fn refused(reason: &str) -> Self {
        Self {
            verified: false,
            claims: None,
            conditions: None,
            session_tags: None,
            source_identity: None,
            reason: Some(reason.to_owned()),
            extra: Map::new(),
        }
    }
}

const MAX_TOKEN_LENGTH: usize = 8192;
static TOKEN_SHAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$").expect("valid regex")
});
/// `sessionNamePattern` of temporary-credentials.ts (`/^[\w+=,.@-]{2,64}$/`).
static SESSION_NAME_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_+=,.@-]{2,64}$").expect("valid regex"));
/// The replay record outlives the provider's acceptance window; an unusable stored tolerance counts as the maximum.
const MAX_CLOCK_TOLERANCE_SECONDS: f64 = 120.0;
const AUDIT_ACTION: &str = "role:assumed-with-web-identity";

fn invalid(message: &str) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

fn feature_disabled() -> IamError {
    IamError::with_status(
        "FEATURE_DISABLED",
        "Web identity federation is not enabled",
        403,
    )
}

fn rejected() -> IamError {
    IamError::with_status(
        "WEB_IDENTITY_REJECTED",
        "The web identity token was not accepted",
        403,
    )
}

/// `new Rejection(reason)`: a refusal that depends on stored state or on the token; it always surfaces as
/// `rejected()`. It travels as an error (rolling the issuance back) under a code of its own.
const REJECTION_CODE: &str = "\u{0}WEB_IDENTITY_REJECTION";

fn rejection(reason: &str) -> IamError {
    IamError::with_status(REJECTION_CODE, reason, 403)
}

fn rejection_reason(error: &IamError) -> Option<String> {
    (error.code == REJECTION_CODE).then(|| error.message.clone())
}

fn member<'a>(record: &'a Record, name: &str) -> Option<&'a Value> {
    record.get(name)
}

fn string_member<'a>(record: &'a Record, name: &str) -> Option<&'a str> {
    record.get(name).and_then(Value::as_str)
}

/// `a === b` for two possibly-undefined members.
fn same(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => better_iam_core::js::strict_equal(left, right),
        _ => false,
    }
}

/// `liveTrust(trust, tenantId)`: a live web-identity trust of the tenant (read fail-closed).
fn live_trust(trust: Option<&Record>, tenant_id: Option<&Value>) -> bool {
    let Some(trust) = trust else {
        return false;
    };
    same(member(trust, "tenantId"), tenant_id)
        && string_member(trust, "kind") == Some("web-identity")
        && member(trust, "revoked") == Some(&Value::Bool(false))
        && member(trust, "providerId").is_some_and(Value::is_string)
        && member(trust, "roleId").is_some_and(Value::is_string)
        && member(trust, "sourceIdentityId").is_some_and(Value::is_string)
}

/// `liveProvider(provider, tenantId)`: an enabled provider of the tenant (read fail-closed).
fn live_provider(provider: Option<&Record>, tenant_id: Option<&Value>) -> bool {
    let Some(provider) = provider else {
        return false;
    };
    same(member(provider, "tenantId"), tenant_id)
        && member(provider, "enabled") == Some(&Value::Bool(true))
}

/// `issuerAllowed(ctx, provider)`: whether `sts.webIdentity.allowedIssuers` (when set) still admits the provider's
/// issuer.
fn issuer_allowed(ctx: &ServerContext, provider: &Record) -> bool {
    match &ctx.config.sts.web_identity.allowed_issuers {
        None => true,
        Some(allowed) => string_member(provider, "issuer")
            .is_some_and(|issuer| allowed.iter().any(|a| a == issuer)),
    }
}

/// `verificationSettings(provider)`: the provider settings a verification depends on, as JSON. Issuance compares
/// them between the record the token was verified against and the one re-read in the transaction.
fn verification_settings(provider: &Record) -> String {
    let or_null = |name: &str| match provider.get(name) {
        None => Value::Null,
        Some(value) => value.clone(),
    };
    better_iam_core::js::stringify(&Value::Array(vec![
        or_null("issuer"),
        or_null("audiences"),
        or_null("algorithms"),
        or_null("jwks"),
        or_null("jwksUri"),
        or_null("maxTokenLifetimeSeconds"),
        or_null("clockToleranceSeconds"),
    ]))
}

/// `value.slice(0, max)` in UTF-16 code units.
fn slice_utf16(value: &str, max: usize) -> String {
    let mut units = 0;
    let mut out = String::new();
    for c in value.chars() {
        units += c.len_utf16();
        if units > max {
            break;
        }
        out.push(c);
    }
    out
}

/// `Inspection`.
struct Inspection {
    evaluation: WebIdentityEvaluation,
    /// Present once the token verified.
    verified: Option<VerifiedWebIdentity>,
    session_tags: Option<IndexMap<String, String>>,
    source_identity: Option<String>,
}

/// `inspect(ctx, trust, provider, token)`: verifies a token against a provider and matches it against a trust: the
/// signature and claims, the trust's claim conditions (re-validated, so a malformed or unpinned stored block matches
/// nothing), then the claim mappings.
async fn inspect(
    ctx: &ServerContext,
    trust: &Record,
    provider: &Record,
    token: Option<&Value>,
) -> IamResult<Inspection> {
    let Some(verifier) = ctx.web_identity() else {
        return Err(feature_disabled());
    };
    let refused = |reason: &str| Inspection {
        evaluation: WebIdentityEvaluation::refused(reason),
        verified: None,
        session_tags: None,
        source_identity: None,
    };
    // The deployment's issuer pin holds for providers registered before it was narrowed, too.
    if !issuer_allowed(ctx, provider) {
        return Ok(refused("issuer"));
    }
    let Some(Value::String(token)) = token else {
        return Ok(refused("malformed"));
    };
    let verified = match verifier
        .verify(&Value::Object(provider.clone()), token)
        .await
    {
        Ok(value) => serde_json::from_value::<VerifiedWebIdentity>(value).ok(),
        Err(error) => {
            // Anything but a typed refusal (a malformed stored provider, say) refuses the token all the same.
            let reason = WebIdentityFailure::from_error(&error)
                .map_or_else(|| "malformed".to_owned(), |failure| failure.reason);
            return Ok(refused(&reason));
        }
    };
    let Some(verified) = verified else {
        return Ok(refused("malformed"));
    };
    Ok(match_trust(trust, verified))
}

/// `matchTrust(trust, verified)`: matches a verified token against a trust: its claim conditions, then its claim
/// mappings. Only string claims that make a valid tag become tags; a `sourceIdentityClaim` that is missing or not a
/// valid source identity refuses the token.
fn match_trust(trust: &Record, verified: VerifiedWebIdentity) -> Inspection {
    let mut claims = Map::new();
    claims.insert("iss".into(), Value::String(verified.issuer.clone()));
    claims.insert("sub".into(), Value::String(verified.subject.clone()));
    claims.insert("aud".into(), Value::String(verified.audience.clone()));
    claims.insert("iat".into(), crate::js::number(verified.issued_at));
    claims.insert("exp".into(), crate::js::number(verified.expires_at));
    if let Some(jti) = &verified.jti {
        claims.insert("jti".into(), Value::String(jti.clone()));
    }
    let trust_id = string_member(trust, "id").unwrap_or_default();
    let conditions = web_identity_conditions(member(trust, "conditions"))
        .and_then(|conditions| {
            match_web_identity_conditions(&conditions, &verified.context, trust_id)
        })
        .unwrap_or_else(|_| json!({ "matched": false, "failed": ["conditions"] }));
    let matched = conditions.get("matched") == Some(&Value::Bool(true));
    let claim = |name: Option<&Value>| match name {
        Some(Value::String(name)) => verified.context.get(name).cloned(),
        _ => None,
    };
    let mut session_tags: IndexMap<String, String> = IndexMap::new();
    if let Some(Value::Object(mapping)) = member(trust, "tagClaims") {
        for (key, name) in better_iam_core::js::entries(mapping) {
            let Some(Value::String(value)) = claim(Some(name)) else {
                continue;
            };
            let mut candidate = Map::new();
            for (tag, existing) in &session_tags {
                candidate.insert(tag.clone(), Value::String(existing.clone()));
            }
            candidate.insert(key.clone(), Value::String(value.clone()));
            if session_tags_value(Some(&Value::Object(candidate))).is_ok() {
                session_tags.insert(key.clone(), value);
            }
        }
    }
    let tags = (!session_tags.is_empty()).then_some(session_tags);
    let mut source_identity = None;
    let mut source_identity_refused = false;
    if let Some(name) = member(trust, "sourceIdentityClaim") {
        match claim(Some(name)) {
            Some(Value::String(value)) if SESSION_NAME_PATTERN.is_match(&value) => {
                source_identity = Some(value);
            }
            _ => source_identity_refused = true,
        }
    }
    let reason = if !matched {
        Some("conditions".to_owned())
    } else if source_identity_refused {
        Some("source-identity".to_owned())
    } else {
        None
    };
    Inspection {
        evaluation: WebIdentityEvaluation {
            verified: true,
            claims: Some(Value::Object(claims)),
            conditions: Some(conditions),
            session_tags: tags.clone(),
            source_identity: source_identity.clone(),
            reason,
            extra: Map::new(),
        },
        verified: Some(verified),
        session_tags: tags,
        source_identity,
    }
}

/// What backs a live trust's sessions.
struct Backing {
    role: Record,
    account: Identity,
}

/// `sessionBacking(ctx, tx, trust, provider)`: the role (present, unprotected, under a live authority), the service
/// account (active, unexpired, in the tenant) and the authorities of the trust's and the provider's creators, read
/// fail-closed. The role and the account, or the first refusal in the order issuance checks them.
async fn session_backing(
    ctx: &ServerContext,
    tx: &Store,
    trust: &Record,
    provider: &Record,
) -> IamResult<Result<Backing, &'static str>> {
    let tenant_id = member(trust, "tenantId");
    let role = tx
        .get("roles", string_member(trust, "roleId").unwrap_or_default())
        .await?;
    let role = match role {
        Some(role)
            if same(member(&role, "tenantId"), tenant_id)
                && !crate::js::truthy(member(&role, "protected"))
                && member(&role, "authorityId").is_some_and(Value::is_string) =>
        {
            role
        }
        _ => return Ok(Err("role")),
    };
    if ctx
        .authority_chain(tx, string_member(&role, "authorityId").unwrap_or_default())
        .await?
        .is_none()
    {
        return Ok(Err("role"));
    }
    let account = tx
        .get(
            "identities",
            string_member(trust, "sourceIdentityId").unwrap_or_default(),
        )
        .await?;
    let account = match account {
        Some(account)
            if string_member(&account, "kind") == Some("service")
                && string_member(&account, "status") == Some("active")
                && same(member(&account, "tenantId"), tenant_id)
                && same(member(trust, "sourceTenantId"), tenant_id) =>
        {
            account
        }
        _ => return Ok(Err("service-account")),
    };
    let expired = matches!(member(&account, "expiresAt"), Some(Value::Number(expires))
        if better_iam_core::js::number_value(expires) <= ctx.now());
    if expired {
        return Ok(Err("service-account"));
    }
    let account: Identity = crate::port::decode(account)?;
    // Sessions are bounded by the authorities of the trust's and the provider's creators.
    let live_authority =
        |record: &Record| member(record, "authorityId").is_some_and(Value::is_string);
    if !live_authority(trust)
        || ctx
            .authority_chain(tx, string_member(trust, "authorityId").unwrap_or_default())
            .await?
            .is_none()
        || !live_authority(provider)
        || ctx
            .authority_chain(
                tx,
                string_member(provider, "authorityId").unwrap_or_default(),
            )
            .await?
            .is_none()
    {
        return Ok(Err("authority"));
    }
    Ok(Ok(Backing { role, account }))
}

/// `evaluateWebIdentity(ctx, { trust, provider, token })`: the dry run behind `trust.evaluateWebIdentity`:
/// verification, trust conditions and claim mappings for a token, with no replay record and no issuance. The caller
/// has authorized the read and loaded the trust and its provider. Stored state that would refuse the exchange is
/// reported too, in the exchange's order: a revoked trust or a disabled provider comes before the token's own
/// problems, and the role, service account and authorities after them.
pub async fn evaluate_web_identity(
    ctx: &Arc<ServerContext>,
    input: &Value,
) -> IamResult<crate::web_identity_exchange::WebIdentityEvaluation> {
    let empty = Record::new();
    let trust = input
        .get("trust")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let provider = input
        .get("provider")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let Inspection { mut evaluation, .. } =
        inspect(ctx, trust, provider, input.get("token")).await?;
    let tenant_id = member(trust, "tenantId");
    if !live_trust(Some(trust), tenant_id) {
        evaluation.reason = Some("trust".to_owned());
    } else if !live_provider(Some(provider), tenant_id)
        || !same(member(trust, "providerId"), member(provider, "id"))
    {
        evaluation.reason = Some("provider".to_owned());
    } else if evaluation.reason.is_none() {
        let backing = ctx
            .store
            .transaction(|tx| {
                let ctx = ctx.clone();
                let (trust, provider) = (trust.clone(), provider.clone());
                async move { Ok(session_backing(&ctx, &tx, &trust, &provider).await?.err()) }
            })
            .await?;
        if let Some(reason) = backing {
            evaluation.reason = Some(reason.to_owned());
        }
    }
    Ok(evaluation)
}

/// The public side of the `sts` group: `assumeRoleWithWebIdentity`. Pre-wired into `createStsApi` by spreading.
pub struct WebIdentityStsApi {
    ctx: Arc<ServerContext>,
}

/// `createWebIdentityStsApi(ctx)`.
pub fn create_web_identity_sts_api(ctx: &Arc<ServerContext>) -> IamResult<WebIdentityStsApi> {
    Ok(WebIdentityStsApi { ctx: ctx.clone() })
}

/// What the issuance transaction receives.
struct IssueRequest {
    tenant_id: String,
    trust_id: String,
    token: String,
    session_name: String,
    duration_seconds: Option<Value>,
    policy: Option<Value>,
    format: crate::temporary_credentials::CredentialFormat,
    audience: Option<Vec<String>>,
}

impl WebIdentityStsApi {
    /// `recordDenial(trust, reason, verified)`: records a refusal in its own transaction; bookkeeping never masks the
    /// refusal itself.
    async fn record_denial(
        &self,
        trust: &Record,
        reason: &str,
        verified: Option<&VerifiedWebIdentity>,
    ) {
        let ctx = &self.ctx;
        let mut metadata = Map::new();
        metadata.insert(
            "trustId".into(),
            member(trust, "id").cloned().unwrap_or(Value::Null),
        );
        metadata.insert(
            "providerId".into(),
            match member(trust, "providerId") {
                Some(Value::String(provider)) => Value::String(provider.clone()),
                _ => Value::Null,
            },
        );
        metadata.insert("reason".into(), Value::String(reason.to_owned()));
        // Claims are recorded only once the signature verified; unverified input never reaches the audit log.
        if let Some(verified) = verified {
            metadata.insert(
                "issuer".into(),
                Value::String(slice_utf16(&verified.issuer, 256)),
            );
            metadata.insert(
                "subject".into(),
                Value::String(slice_utf16(&verified.subject, 256)),
            );
        }
        let mut event = Record::new();
        event.insert("id".into(), Value::String(id()));
        event.insert(
            "tenantId".into(),
            member(trust, "tenantId").cloned().unwrap_or(Value::Null),
        );
        // The trust's anchoring service account, the identity a session would have acted as.
        event.insert(
            "actorId".into(),
            member(trust, "sourceIdentityId")
                .cloned()
                .unwrap_or(Value::Null),
        );
        event.insert("action".into(), Value::from(AUDIT_ACTION));
        event.insert(
            "resourceId".into(),
            member(trust, "roleId").cloned().unwrap_or(Value::Null),
        );
        event.insert("outcome".into(), Value::from("deny"));
        event.insert("rootOverride".into(), Value::Bool(false));
        event.insert("timestamp".into(), crate::js::number(ctx.now()));
        event.insert("metadata".into(), Value::Object(metadata));
        let Ok(events) = ctx.events() else {
            return;
        };
        let events = events.clone();
        // Best-effort.
        let _ = ctx
            .store
            .transaction(|tx| async move { events.record_audit(&tx, &event).await })
            .await;
    }

    /// `issue(tx, request, verifiedWith, verified)`: the issuance transaction; every stored-state check is repeated
    /// here, next to the replay record and the row.
    async fn issue(
        &self,
        tx: &Store,
        request: &IssueRequest,
        verified_with: &Record,
        verified: &VerifiedWebIdentity,
    ) -> IamResult<Value> {
        let ctx = &self.ctx;
        let settings = &ctx.config.sts.web_identity;
        let tenant_value = Value::String(request.tenant_id.clone());
        let tenant_id = &request.tenant_id;
        let trust = tx.get("trusts", &request.trust_id).await?;
        let trust = match trust {
            Some(trust)
                if live_trust(Some(&trust), Some(&tenant_value))
                    && same(member(&trust, "providerId"), member(verified_with, "id")) =>
            {
                trust
            }
            _ => return Err(rejection("trust")),
        };
        // The token was verified and matched outside this transaction: the provider settings it was verified against
        // must still be the live ones, and the live trust must still admit it (with its current mappings).
        let provider = tx
            .get(
                "oidcProviders",
                string_member(verified_with, "id").unwrap_or_default(),
            )
            .await?;
        let provider = match provider {
            Some(provider)
                if live_provider(Some(&provider), Some(&tenant_value))
                    && string_member(&provider, "issuer") == Some(verified.issuer.as_str())
                    && issuer_allowed(ctx, &provider)
                    && verification_settings(&provider) == verification_settings(verified_with) =>
            {
                provider
            }
            _ => return Err(rejection("provider")),
        };
        let inspection = match_trust(&trust, verified.clone());
        if let Some(reason) = &inspection.evaluation.reason {
            return Err(rejection(reason));
        }
        let Backing { role, account } = match session_backing(ctx, tx, &trust, &provider).await? {
            Ok(backing) => backing,
            Err(reason) => return Err(rejection(reason)),
        };
        let target = match tx.get("tenants", tenant_id).await {
            Ok(Some(record)) => match crate::port::decode::<Tenant>(record) {
                Ok(target) => match ctx.ancestry(tx, &target).await {
                    Ok(chain) if chain.iter().all(|item| item.status == TenantStatus::Active) => {
                        Some(target)
                    }
                    _ => None,
                },
                Err(_) => None,
            },
            _ => None,
        };
        let Some(target) = target else {
            return Err(rejection("tenant"));
        };

        // From here on the token matched a live trust, so specific refusals may surface.
        let ip = ctx.auth.current_client().and_then(|client| client.ip);
        ctx.auth.assert_ip_allowed(Some(&target), ip.as_deref())?;
        ctx.auth
            .assert_network_not_blocked(tx, tenant_id, ip.as_deref())
            .await?;
        // The injected clock, like user sessions, so validation and issuance agree under a test clock.
        let now = ctx.now();
        let trust_id = member(&trust, "id").cloned().unwrap_or(Value::Null);
        let role_id = string_member(&trust, "roleId")
            .unwrap_or_default()
            .to_owned();
        let live = tx
            .find(
                "sessions",
                &Filter::new().eq("roleId", role_id.clone()),
                &FindOptions::default(),
            )
            .await?
            .into_iter()
            .filter(|session| {
                string_member(session, "kind") == Some("role")
                    && same(member(session, "trustId"), Some(&trust_id))
                    && string_member(session, "tenantId") == Some(tenant_id.as_str())
                    && member(session, "expiresAt")
                        .and_then(crate::js::as_number)
                        .is_some_and(|expires| expires > now)
            })
            .count();
        if live as f64 >= settings.max_sessions_per_trust {
            return Err(IamError::with_status(
                "LIMIT_EXCEEDED",
                "This trust holds the maximum number of live role sessions",
                409,
            ));
        }
        if let Some(policy) = &request.policy {
            ctx.catalog.validate(tx.as_ref(), tenant_id, policy).await?;
        }
        let bounds = role_duration_bounds(ctx, &Value::Object(trust.clone()), &request.format)?;
        let duration_seconds = duration_within(request.duration_seconds.as_ref(), &bounds)?;
        // Single use unless the provider opts out; recorded in this transaction, so a failed issuance does not burn it.
        if string_member(&provider, "replayProtection") != Some("off") {
            let provider_id = string_member(&provider, "id").unwrap_or_default();
            let replay_id =
                web_identity_replay_id(provider_id, verified.jti.as_deref(), &request.token)?;
            if tx.get("webIdentityReplays", &replay_id).await?.is_some() {
                return Err(rejection("replay"));
            }
            // Kept for the largest tolerance any provider may be given, not this provider's current one: raising its
            // clockToleranceSeconds later must not reopen a window in which an already redeemed token is accepted
            // again.
            let mut replay = Record::new();
            replay.insert("id".into(), Value::String(replay_id));
            replay.insert(
                "tenantId".into(),
                member(&provider, "tenantId")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
            replay.insert("providerId".into(), Value::String(provider_id.to_owned()));
            replay.insert(
                "expiresAt".into(),
                crate::js::number(
                    verified.expires_at * 1000.0 + MAX_CLOCK_TOLERANCE_SECONDS * 1000.0,
                ),
            );
            tx.insert("webIdentityReplays", &replay).await?;
        }
        let provider_id = member(&provider, "id").cloned().unwrap_or(Value::Null);
        let web_identity = json!({
            "providerId": provider_id,
            "issuer": verified.issuer,
            "subject": verified.subject,
        });
        let mut draft = Record::new();
        draft.insert("id".into(), Value::String(id()));
        draft.insert("tenantId".into(), Value::String(tenant_id.clone()));
        draft.insert("identityId".into(), Value::String(account.id.clone()));
        draft.insert(
            "originalIdentityId".into(),
            Value::String(account.id.clone()),
        );
        draft.insert(
            "roleId".into(),
            member(&role, "id").cloned().unwrap_or(Value::Null),
        );
        draft.insert("trustId".into(), trust_id.clone());
        draft.insert("kind".into(), Value::from("role"));
        draft.insert("tokenHash".into(), Value::from(""));
        draft.insert("createdAt".into(), crate::js::number(now));
        draft.insert("lastSeenAt".into(), crate::js::number(now));
        // The exchange is the authentication; external tokens never attest MFA.
        draft.insert("authenticatedAt".into(), crate::js::number(now));
        draft.insert(
            "expiresAt".into(),
            crate::js::number(now + duration_seconds * 1000.0),
        );
        draft.insert("mfa".into(), Value::Bool(false));
        if let Some(authority) = member(&trust, "authorityId") {
            draft.insert("credentialAuthorityId".into(), authority.clone());
        }
        draft.insert("webIdentity".into(), web_identity.clone());
        draft.insert(
            "sessionName".into(),
            Value::String(request.session_name.clone()),
        );
        if let Some(policy) = &request.policy {
            draft.insert("policy".into(), policy.clone());
        }
        if let Some(tags) = &inspection.session_tags {
            draft.insert(
                "sessionTags".into(),
                serde_json::to_value(tags).unwrap_or(Value::Null),
            );
        }
        if let Some(source_identity) = &inspection.source_identity {
            draft.insert(
                "sourceIdentity".into(),
                Value::String(source_identity.clone()),
            );
        }
        // The presenting address: the tenant's allowlist and network blocks judge it on every use.
        if let Some(client) = ctx.auth.current_client() {
            let client = crate::port::encode(&client);
            if !client.is_empty() {
                draft.insert("client".into(), Value::Object(client));
            }
        }
        let format = serde_json::to_value(&request.format).unwrap_or(Value::Null);
        let mut mint = Map::new();
        mint.insert(
            "identity".into(),
            Value::Object(crate::port::encode(&account)),
        );
        mint.insert("draft".into(), Value::Object(draft));
        mint.insert("format".into(), format.clone());
        if let Some(audience) = &request.audience {
            mint.insert("audience".into(), json!(audience));
        }
        let minted = mint_credential(ctx, tx, &Value::Object(mint)).await?;
        let token = minted
            .get("token")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let session: better_iam_core::Session =
            serde_json::from_value(minted.get("session").cloned().unwrap_or(Value::Null))
                .map_err(|_| crate::js::internal_error())?;
        let mut tag_keys: Vec<String> = inspection
            .session_tags
            .as_ref()
            .map(|tags| tags.keys().cloned().collect())
            .unwrap_or_default();
        crate::js::sort_strings(&mut tag_keys);
        let mut metadata = Map::new();
        metadata.insert("trustId".into(), trust_id);
        metadata.insert("providerId".into(), provider_id);
        metadata.insert(
            "issuer".into(),
            Value::String(slice_utf16(&verified.issuer, 256)),
        );
        metadata.insert(
            "subject".into(),
            Value::String(slice_utf16(&verified.subject, 256)),
        );
        metadata.insert(
            "durationSeconds".into(),
            crate::js::number(duration_seconds),
        );
        metadata.insert("format".into(), format);
        metadata.insert("tagKeys".into(), json!(tag_keys));
        let principal = AuthenticatedPrincipal {
            identity: account.clone(),
            session: session.clone(),
            device_proof: None,
        };
        ctx.events()?
            .audit(
                tx,
                &principal,
                AUDIT_ACTION,
                tenant_id,
                string_member(&role, "id").unwrap_or_default(),
                AuditOutcome::Allow,
                false,
                Some(metadata),
            )
            .await?;
        let credential = temporary_credential(&token, &session, now)?;
        let mut result = match serde_json::to_value(&credential) {
            Ok(Value::Object(map)) => map,
            _ => return Err(crate::js::internal_error()),
        };
        result.insert("webIdentity".into(), web_identity);
        Ok(Value::Object(result))
    }

    /// AssumeRoleWithWebIdentity (public; no IAM credential): exchanges a verified external OIDC token for a role
    /// session of kind 'role' under a web-identity trust, acting as the trust's service account and bounded by the
    /// role, the trust's ceiling, and the authorities of the trust's and the provider's creators. The token must be
    /// signed by the provider's keys with an allowed algorithm, name the provider's issuer and one of its audiences, be
    /// fresh, satisfy the trust's claim conditions and (by default) not have been redeemed before at this provider.
    /// Every refusal that depends on stored state or on the token is WEB_IDENTITY_REJECTED (403) with the same body.
    /// The attempt counts against `sts.webIdentity.maxExchangesPerWindow` for the trust before anything is looked up.
    /// The credential is returned once, in the body; this route never sets a cookie. Audited as
    /// `role:assumed-with-web-identity` (allow, or deny with a reason once the trust resolved).
    pub async fn assume_role_with_web_identity(&self, input: &Value) -> IamResult<Value> {
        let ctx = &self.ctx;
        let settings = &ctx.config.sts.web_identity;
        if !settings.enabled || ctx.web_identity().is_none() {
            return Err(feature_disabled());
        }
        // (1) Shape only: nothing here depends on stored state.
        let Value::Object(input) = input else {
            return Err(invalid("Expected an object"));
        };
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let trust_id = text(input.get("trustId"), "trustId", 256)?;
        let token = match input.get("webIdentityToken") {
            Some(Value::String(token))
                if utf16_len(token) <= MAX_TOKEN_LENGTH && TOKEN_SHAPE.is_match(token) =>
            {
                token.clone()
            }
            _ => {
                return Err(invalid(
                    "webIdentityToken must be a compact JWT of at most 8192 characters",
                ));
            }
        };
        let session_name = match input.get("sessionName") {
            Some(Value::String(name)) if SESSION_NAME_PATTERN.is_match(name) => name.clone(),
            _ => {
                return Err(invalid(
                    "sessionName must be 2-64 letters, digits or +=,.@_- characters",
                ));
            }
        };
        if input
            .get("durationSeconds")
            .is_some_and(|value| !value.is_number())
        {
            return Err(invalid("durationSeconds must be a number"));
        }
        let policy = input.get("policy").cloned();
        if policy.as_ref().is_some_and(|policy| !policy.is_object()) {
            return Err(invalid("policy must be a policy document"));
        }
        if input
            .get("format")
            .is_some_and(|format| !format.is_string())
        {
            return Err(invalid("format must be 'opaque' or 'jwt'"));
        }
        if input
            .get("audience")
            .is_some_and(|audience| !audience.is_array())
        {
            return Err(invalid("audience must be a list"));
        }

        // (2) Counted before any lookup and outside any transaction, so a refusal cannot roll it back. Trust ids are
        // public (they sit in CI workflow files), so when the client's address is known the budget is per address,
        // and one source posting junk tokens cannot use up the trust's exchanges for everyone; the trust as a whole
        // still has a ceiling (ten budgets) that bounds the work any number of sources can cause.
        let ip = ctx
            .auth
            .current_client()
            .and_then(|client| client.ip)
            .filter(|ip| !ip.is_empty());
        if let Some(ip) = ip {
            // An IPv6 /64 counts as one source, so rotating through it earns no fresh budget.
            let source = better_iam_core::ip_counter_key(&ip).unwrap_or(ip);
            ctx.auth
                .limit_attempt(
                    &tenant_id,
                    &format!("web-identity:{trust_id}:{source}"),
                    LimitAttemptOptions {
                        limit: Some(settings.max_exchanges_per_window),
                        ..LimitAttemptOptions::default()
                    },
                )
                .await?;
            ctx.auth
                .limit_attempt(
                    &tenant_id,
                    &format!("web-identity:{trust_id}"),
                    LimitAttemptOptions {
                        limit: Some(settings.max_exchanges_per_window * 10.0),
                        count_client: Some(false),
                        ..LimitAttemptOptions::default()
                    },
                )
                .await?;
        } else {
            ctx.auth
                .limit_attempt(
                    &tenant_id,
                    &format!("web-identity:{trust_id}"),
                    LimitAttemptOptions {
                        limit: Some(settings.max_exchanges_per_window),
                        ..LimitAttemptOptions::default()
                    },
                )
                .await?;
        }

        // (3) The trust and its provider; an unknown trust is refused like every other failure, without an audit.
        let tenant_value = Value::String(tenant_id.clone());
        let trust = ctx.store.get("trusts", &trust_id).await?;
        let trust = match trust {
            Some(trust) if live_trust(Some(&trust), Some(&tenant_value)) => trust,
            _ => return Err(rejected()),
        };
        let provider = ctx
            .store
            .get(
                "oidcProviders",
                string_member(&trust, "providerId").unwrap_or_default(),
            )
            .await?;
        let provider = match provider {
            Some(provider) if live_provider(Some(&provider), Some(&tenant_value)) => provider,
            _ => return Err(rejected()),
        };

        // (4)-(6) Verification, claim conditions and mappings, outside any transaction (keys may be fetched).
        let token_value = Value::String(token.clone());
        let inspection = inspect(ctx, &trust, &provider, Some(&token_value)).await?;
        let verified = match (&inspection.verified, &inspection.evaluation.reason) {
            (Some(verified), None) => verified.clone(),
            (verified, reason) => {
                self.record_denial(
                    &trust,
                    reason.as_deref().unwrap_or("malformed"),
                    verified.as_ref(),
                )
                .await;
                return Err(rejected());
            }
        };

        // (7) Issuance. Stored-state failures and replays are rejections; the rest surface as themselves.
        let outcome = async {
            let format = credential_format(input.get("format"))?;
            let audience = audience_value(input.get("audience"), &format)?;
            let format_value = serde_json::to_value(&format).unwrap_or(Value::Null);
            if format_value == "jwt" && ctx.session_tokens().is_none() {
                return Err(IamError::with_status(
                    "FEATURE_DISABLED",
                    "Session JWTs are not enabled on this deployment (sts.jwt)",
                    403,
                ));
            }
            let request = IssueRequest {
                tenant_id: tenant_id.clone(),
                trust_id: trust_id.clone(),
                token: token.clone(),
                session_name: session_name.clone(),
                duration_seconds: input.get("durationSeconds").cloned(),
                policy: policy.clone(),
                format,
                audience,
            };
            let provider = provider.clone();
            let verified = verified.clone();
            ctx.store
                .transaction(|tx| {
                    let request = &request;
                    let provider = &provider;
                    let verified = &verified;
                    async move { self.issue(&tx, request, provider, verified).await }
                })
                .await
        }
        .await;
        match outcome {
            Ok(credential) => Ok(credential),
            Err(error) => {
                // A concurrent redemption of the same token loses the insert race: the same refusal as a replay.
                let reason = rejection_reason(&error)
                    .or_else(|| (error.code == "CONFLICT").then(|| "replay".to_owned()));
                if let Some(reason) = reason {
                    self.record_denial(&trust, &reason, Some(&verified)).await;
                    return Err(rejected());
                }
                // Exceptions that are not IamErrors in TypeScript (INTERNAL_ERROR here) are not recorded.
                if error.code != "INTERNAL_ERROR" {
                    self.record_denial(&trust, &error.code, Some(&verified))
                        .await;
                }
                Err(error)
            }
        }
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        match method {
            "assumeRoleWithWebIdentity" => Some(
                self.assume_role_with_web_identity(args.first().unwrap_or(&Value::Null))
                    .await,
            ),
            _ => None,
        }
    }
}
