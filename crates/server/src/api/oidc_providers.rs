//! Port of `packages/server/src/api/oidc-providers.ts`: the `oidcProviders` group, tenant-managed OIDC identity
//! providers whose tokens web-identity trusts admit.
//!
//! Every provider records its creator's grant authority, which bounds each web-identity session through it; it is
//! edited only under that authority (or by root). Creating and changing providers needs `sts.webIdentity.enabled`,
//! except an update that only disables one; reading, deleting and revoking sessions keep working when the feature is
//! off.

use std::sync::Arc;

use better_iam_core::{
    AuditOutcome, CredentialInput, Filter, FindOptions, IamError, IamResult, Record, js as core_js,
};
use better_iam_types::api::oidc_providers;
use indexmap::IndexSet;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::hosts::url_origin;
use crate::js::number;
use crate::session_kinds::next_watermark;
use crate::temporary_credentials::delete_temporary_sessions;
use crate::utils::{hash, id};
use crate::validation::{integer, text};
use crate::web_identity::{
    IssuerRules, web_identity_algorithms, web_identity_audiences, web_identity_issuer,
    web_identity_jwks_uri, web_identity_keys,
};

fn feature_disabled() -> IamError {
    IamError::with_status(
        "FEATURE_DISABLED",
        "Web identity federation is not enabled",
        403,
    )
}

const UPDATABLE_FIELDS: [&str; 9] = [
    "name",
    "audiences",
    "jwksUri",
    "jwks",
    "algorithms",
    "maxTokenLifetimeSeconds",
    "clockToleranceSeconds",
    "replayProtection",
    "enabled",
];

/// The settings a token's acceptance depends on (keys, algorithms, audiences, lifetime and skew). An update that
/// changes any of them ends the sessions issued under the old ones, as `trust.update` does when a trust tightens.
const VERIFICATION_FIELDS: [&str; 6] = [
    "audiences",
    "jwksUri",
    "jwks",
    "algorithms",
    "maxTokenLifetimeSeconds",
    "clockToleranceSeconds",
];

fn invalid(message: &str) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// The provider's natural key within its tenant, `issuer:{issuer}`. Stored keys are limited to 512 bytes, so an issuer
/// too long for that is keyed by its SHA-256 instead; both forms are deterministic, so duplicates still collide.
fn issuer_key(issuer: &str) -> String {
    let key = format!("issuer:{issuer}");
    if key.len() <= 512 {
        key
    } else {
        format!("issuer#sha256:{}", hash(issuer))
    }
}

/// An OIDC provider as the API returns it (`publicOidcProvider`): an explicit allowlist projection (static keys are
/// public members only, as validated when they were stored).
pub fn public_oidc_provider(provider: &Record) -> Value {
    let mut result = Map::new();
    let copy = |result: &mut Map<String, Value>, key: &str| {
        if let Some(value) = provider.get(key) {
            result.insert(key.into(), value.clone());
        }
    };
    for key in [
        "id",
        "tenantId",
        "name",
        "issuer",
        "audiences",
        "algorithms",
        "maxTokenLifetimeSeconds",
        "clockToleranceSeconds",
    ] {
        copy(&mut result, key);
    }
    result.insert(
        "replayProtection".into(),
        json!(if provider.get("replayProtection") == Some(&json!("off")) {
            "off"
        } else {
            "single-use"
        }),
    );
    result.insert(
        "enabled".into(),
        Value::Bool(provider.get("enabled") == Some(&Value::Bool(true))),
    );
    for key in ["authorityId", "createdAt", "createdBy", "updatedAt"] {
        copy(&mut result, key);
    }
    for key in ["jwksUri", "jwks", "sessionsRevokedBefore"] {
        copy(&mut result, key);
    }
    Value::Object(result)
}

fn replay_protection_value(value: &Value) -> IamResult<String> {
    match value.as_str() {
        Some(mode @ ("single-use" | "off")) => Ok(mode.to_owned()),
        _ => Err(invalid("replayProtection must be 'single-use' or 'off'")),
    }
}

fn enabled_value(value: &Value) -> IamResult<bool> {
    value
        .as_bool()
        .ok_or_else(|| invalid("enabled must be a boolean"))
}

/// Deletes the provider's web-identity sessions created before `created_before`, across every trust that uses it.
async fn delete_provider_sessions(
    tx: &Store,
    provider: &Record,
    created_before: f64,
) -> IamResult<f64> {
    let tenant_id = provider.get("tenantId").cloned().unwrap_or(Value::Null);
    let provider_id = provider.get("id").cloned().unwrap_or(Value::Null);
    let mut revoked = 0.0;
    for trust in tx
        .find(
            "trusts",
            &Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("providerId", provider_id.clone()),
            &FindOptions::default(),
        )
        .await?
    {
        if trust.get("providerId") == Some(&provider_id)
            && let Some(Value::String(role_id)) = trust.get("roleId")
        {
            revoked += delete_temporary_sessions(
                tx,
                &json!({
                    "tenantId": tenant_id,
                    "roleId": role_id,
                    "trustId": trust.get("id").cloned().unwrap_or(Value::Null),
                    "providerId": provider_id,
                    "createdBefore": number(created_before),
                }),
            )
            .await?;
        }
    }
    Ok(revoked)
}

/// The `oidcProviders` API group (`createOidcProvidersApi(ctx)`): one method per route `oidcProviders/{method}`.
pub struct OidcProvidersApi {
    ctx: Arc<ServerContext>,
}

/// `createOidcProvidersApi(ctx)`.
pub fn create_oidc_providers_api(ctx: &Arc<ServerContext>) -> IamResult<OidcProvidersApi> {
    Ok(OidcProvidersApi { ctx: ctx.clone() })
}

impl OidcProvidersApi {
    /// The issuer rules: https (loopback http in development), not IAM's own issuer, and on the deployment's pin list.
    fn issuer_value(&self, value: Option<&Value>) -> IamResult<String> {
        let ctx = &self.ctx;
        let settings = &ctx.config.sts.web_identity;
        let default_issuer = format!(
            "{}{}",
            url_origin(&ctx.config.base_url),
            ctx.config.base_path
        );
        let own = ctx
            .session_tokens()
            .map(|tokens| tokens.issuer().to_owned())
            .unwrap_or_else(|| default_issuer.clone());
        let issuers: IndexSet<String> = [own, default_issuer].into_iter().collect();
        for self_issuer in &issuers {
            web_identity_issuer(
                value,
                &IssuerRules {
                    allow_insecure_localhost: settings.allow_insecure_localhost,
                    self_issuer: Some(self_issuer),
                    allowed_issuers: settings.allowed_issuers.as_deref(),
                },
            )?;
        }
        Ok(value.and_then(Value::as_str).unwrap_or_default().to_owned())
    }

    fn jwks_uri_value(&self, value: Option<&Value>) -> IamResult<String> {
        let settings = &self.ctx.config.sts.web_identity;
        web_identity_jwks_uri(
            value,
            &json!({
                "allowInsecureLocalhost": settings.allow_insecure_localhost,
                "allowPrivateNetworks": settings.allow_private_networks,
            }),
        )
    }

    /// Forgets cached keys once a change is committed, so the next token is checked against the new settings.
    fn forget(&self, provider_id: &str) {
        if let Some(verifier) = self.ctx.web_identity() {
            verifier.forget(provider_id);
        }
    }

    /// `oidcProviders/create`: registers an OIDC provider (iam:oidc-providers:create on the tenant, recent
    /// authentication, web identity enabled). One provider per issuer and tenant (CONFLICT otherwise). Nothing is
    /// fetched now: keys are fetched (or discovered) when a token first needs them.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<oidc_providers::CreateInput>,
    ) -> IamResult<Reply<oidc_providers::CreateOutput>> {
        let ctx = &self.ctx;
        if !ctx.config.sts.web_identity.enabled {
            return Err(feature_disabled());
        }
        let name = text(input.get("name"), "name", 128)?;
        let issuer = self.issuer_value(input.get("issuer"))?;
        let audiences = web_identity_audiences(input.get("audiences"))?;
        let jwks_uri = match input.get("jwksUri") {
            None => None,
            Some(value) => Some(self.jwks_uri_value(Some(value))?),
        };
        let jwks = match input.get("jwks") {
            None => None,
            Some(value) => Some(web_identity_keys(Some(value))?),
        };
        if jwks_uri.is_some() && jwks.is_some() {
            return Err(invalid("Give jwks or jwksUri, not both"));
        }
        let algorithms = web_identity_algorithms(input.get("algorithms"))?;
        let max_token_lifetime_seconds = match input.get("maxTokenLifetimeSeconds") {
            None => 3600.0,
            Some(value) => integer(Some(value), "maxTokenLifetimeSeconds", 60.0, 86400.0)?,
        };
        let clock_tolerance_seconds = match input.get("clockToleranceSeconds") {
            None => 30.0,
            Some(value) => integer(Some(value), "clockToleranceSeconds", 0.0, 120.0)?,
        };
        let replay_protection = match input.get("replayProtection") {
            None => "single-use".to_owned(),
            Some(value) => replay_protection_value(value)?,
        };
        let enabled = match input.get("enabled") {
            None => true,
            Some(value) => enabled_value(value)?,
        };
        let tenant_id = string_member(&input, "tenantId");
        let tenant_ref = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let unique_key = issuer_key(&issuer);
                if !tx
                    .find(
                        "oidcProviders",
                        &Filter::new()
                            .eq("tenantId", tenant_ref.clone())
                            .eq("uniqueKey", unique_key.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                    .is_empty()
                {
                    return Err(IamError::with_status(
                        "CONFLICT",
                        "A provider for this issuer already exists",
                        409,
                    )
                    .into());
                }
                let authority = ctx
                    .granting_authority(&tx, &principal, tenant_ref, None)
                    .await?;
                let now = ctx.now();
                let mut provider = Record::new();
                provider.insert("id".into(), Value::String(id()));
                provider.insert("tenantId".into(), Value::String(tenant_ref.clone()));
                provider.insert("uniqueKey".into(), Value::String(unique_key));
                provider.insert("name".into(), Value::String(name));
                provider.insert("issuer".into(), Value::String(issuer));
                provider.insert("audiences".into(), json!(audiences));
                provider.insert("algorithms".into(), json!(algorithms));
                provider.insert(
                    "maxTokenLifetimeSeconds".into(),
                    number(max_token_lifetime_seconds),
                );
                provider.insert(
                    "clockToleranceSeconds".into(),
                    number(clock_tolerance_seconds),
                );
                provider.insert("replayProtection".into(), Value::String(replay_protection));
                provider.insert("enabled".into(), Value::Bool(enabled));
                provider.insert("authorityId".into(), Value::String(authority.id.clone()));
                provider.insert("createdAt".into(), number(now));
                provider.insert(
                    "createdBy".into(),
                    Value::String(principal.identity.id.clone()),
                );
                provider.insert("updatedAt".into(), number(now));
                if let Some(jwks_uri) = jwks_uri {
                    provider.insert("jwksUri".into(), Value::String(jwks_uri));
                }
                if let Some(jwks) = jwks {
                    provider.insert("jwks".into(), jwks);
                }
                let stored = tx.insert("oidcProviders", &provider).await?;
                Ok(public_oidc_provider(&stored))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:oidc-providers:create",
                &tenant_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `oidcProviders/delete`: deletes a provider (iam:oidc-providers:delete, recent authentication, the creator's
    /// authority or root). Refused with CONFLICT while unrevoked trusts reference it.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<oidc_providers::DeleteInput>,
    ) -> IamResult<Reply<oidc_providers::DeleteOutput>> {
        let ctx = &self.ctx;
        let provider_id = text(input.get("providerId"), "providerId", 256)?;
        let tenant_id = string_member(&input, "tenantId");
        let provider_ref = &provider_id;
        let tenant_ref = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let provider = ctx
                    .scoped(
                        &tx,
                        "oidcProviders",
                        Some(&Value::String(provider_ref.clone())),
                        tenant_ref,
                    )
                    .await?;
                ctx.can_edit_grant_resource(&tx, &principal, &provider)
                    .await?;
                let trusts = tx
                    .find(
                        "trusts",
                        &Filter::new()
                            .eq("tenantId", tenant_ref.clone())
                            .eq("providerId", provider_ref.clone()),
                        &FindOptions::default(),
                    )
                    .await?;
                if trusts.iter().any(|trust| {
                    trust.get("providerId") == provider.get("id")
                        && trust.get("revoked") != Some(&Value::Bool(true))
                }) {
                    return Err(IamError::with_status(
                        "CONFLICT",
                        "Revoke the trusts that use this provider first",
                        409,
                    )
                    .into());
                }
                tx.delete("oidcProviders", better_iam_core::record_id(&provider))
                    .await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:oidc-providers:delete",
                &provider_id,
                mutation,
                false,
            )
            .await?;
        self.forget(&provider_id);
        Ok(Reply::json(result))
    }

    /// `oidcProviders/get`: one provider (iam:oidc-providers:read on the provider).
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<oidc_providers::GetInput>,
    ) -> IamResult<Reply<oidc_providers::GetOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant_ref = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let provider = ctx
                    .scoped(&tx, "oidcProviders", body.get("providerId"), tenant_ref)
                    .await?;
                Ok(public_oidc_provider(&provider))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:oidc-providers:read",
                &string_member(&input, "providerId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `oidcProviders/list`: the tenant's OIDC providers (iam:oidc-providers:read on the tenant), oldest first.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<oidc_providers::ListInput>,
    ) -> IamResult<Reply<oidc_providers::ListOutput>> {
        let ctx = &self.ctx;
        let tenant_id = string_member(&input, "tenantId");
        let tenant_ref = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let mut providers = tx
                    .find(
                        "oidcProviders",
                        &Filter::new().eq("tenantId", tenant_ref.clone()),
                        &FindOptions::default(),
                    )
                    .await?;
                let created =
                    |record: &Record| record.get("createdAt").map_or(f64::NAN, core_js::to_number);
                providers.sort_by(|a, b| {
                    let difference = created(a) - created(b);
                    if difference != 0.0 && !difference.is_nan() {
                        return difference
                            .partial_cmp(&0.0)
                            .unwrap_or(std::cmp::Ordering::Equal);
                    }
                    let id = |record: &Record| {
                        record
                            .get("id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()
                    };
                    core_js::cmp_utf16(&id(a), &id(b))
                });
                Ok(Value::Array(
                    providers.iter().map(public_oidc_provider).collect(),
                ))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:oidc-providers:read",
                &tenant_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `oidcProviders/revokeSessions`: revokes the web-identity sessions issued through this provider before `before`
    /// (default: every session so far). Requires iam:roles:revoke-sessions on the provider and recent
    /// authentication; works while the feature is off. Audited as `role:sessions-revoked`.
    pub async fn revoke_sessions(
        &self,
        credential: &CredentialInput,
        input: Body<oidc_providers::RevokeSessionsInput>,
    ) -> IamResult<Reply<oidc_providers::RevokeSessionsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant_ref = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let provider = ctx
                    .scoped(&tx, "oidcProviders", body.get("providerId"), tenant_ref)
                    .await?;
                let sessions_revoked_before = next_watermark(
                    provider
                        .get("sessionsRevokedBefore")
                        .and_then(core_js::as_number),
                    body.get("before"),
                    ctx.now(),
                )?;
                // updatedAt stays: it versions the provider's key settings, which have not changed.
                let mut next = provider.clone();
                next.insert(
                    "sessionsRevokedBefore".into(),
                    number(sessions_revoked_before),
                );
                tx.put("oidcProviders", &next).await?;
                let revoked =
                    delete_provider_sessions(&tx, &provider, sessions_revoked_before).await?;
                let provider_id = provider
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let mut metadata = Map::new();
                metadata.insert(
                    "sessionsRevokedBefore".into(),
                    number(sessions_revoked_before),
                );
                metadata.insert("revoked".into(), number(revoked));
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "role:sessions-revoked",
                        tenant_ref,
                        &provider_id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(json!({
                    "providerId": provider_id,
                    "sessionsRevokedBefore": number(sessions_revoked_before),
                    "revoked": number(revoked),
                }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:roles:revoke-sessions",
                &string_member(&input, "providerId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `oidcProviders/update`: changes a provider (iam:oidc-providers:update on the provider, recent authentication,
    /// the creator's authority or root). The issuer cannot change. Needs web identity enabled unless the update only
    /// disables the provider. Disabling, or changing the keys, algorithms, audiences, lifetime or skew, ends the
    /// sessions issued through the provider so far. An update that changes nothing is INVALID_INPUT.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<oidc_providers::UpdateInput>,
    ) -> IamResult<Reply<oidc_providers::UpdateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let changed: Vec<&str> = UPDATABLE_FIELDS
            .iter()
            .copied()
            .filter(|field| input.get(*field).is_some())
            .collect();
        let only_disables = changed.len() == 1
            && changed[0] == "enabled"
            && input.get("enabled") == Some(&Value::Bool(false));
        if !ctx.config.sts.web_identity.enabled && !only_disables {
            return Err(feature_disabled());
        }
        if input.get("issuer").is_some() {
            return Err(invalid("The issuer of a provider cannot change"));
        }
        let provider_id = text(input.get("providerId"), "providerId", 256)?;
        let tenant_id = string_member(&input, "tenantId");
        let provider_ref = &provider_id;
        let tenant_ref = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let provider = ctx
                    .scoped(
                        &tx,
                        "oidcProviders",
                        Some(&Value::String(provider_ref.clone())),
                        tenant_ref,
                    )
                    .await?;
                ctx.can_edit_grant_resource(&tx, &principal, &provider)
                    .await?;
                let mut next = provider.clone();
                if let Some(value) = body.get("name") {
                    next.insert(
                        "name".into(),
                        Value::String(text(Some(value), "name", 128)?),
                    );
                }
                if let Some(value) = body.get("audiences") {
                    next.insert(
                        "audiences".into(),
                        json!(web_identity_audiences(Some(value))?),
                    );
                }
                match body.get("jwksUri") {
                    Some(Value::Null) => {
                        next.shift_remove("jwksUri");
                    }
                    Some(value) => {
                        next.insert(
                            "jwksUri".into(),
                            Value::String(self.jwks_uri_value(Some(value))?),
                        );
                    }
                    None => {}
                }
                match body.get("jwks") {
                    Some(Value::Null) => {
                        next.shift_remove("jwks");
                    }
                    Some(value) => {
                        next.insert("jwks".into(), web_identity_keys(Some(value))?);
                    }
                    None => {}
                }
                if next.get("jwksUri").is_some() && next.get("jwks").is_some() {
                    return Err(invalid("Give jwks or jwksUri, not both").into());
                }
                if let Some(value) = body.get("algorithms") {
                    next.insert(
                        "algorithms".into(),
                        json!(web_identity_algorithms(Some(value))?),
                    );
                }
                if let Some(value) = body.get("maxTokenLifetimeSeconds") {
                    next.insert(
                        "maxTokenLifetimeSeconds".into(),
                        number(integer(
                            Some(value),
                            "maxTokenLifetimeSeconds",
                            60.0,
                            86400.0,
                        )?),
                    );
                }
                if let Some(value) = body.get("clockToleranceSeconds") {
                    next.insert(
                        "clockToleranceSeconds".into(),
                        number(integer(Some(value), "clockToleranceSeconds", 0.0, 120.0)?),
                    );
                }
                if let Some(value) = body.get("replayProtection") {
                    next.insert(
                        "replayProtection".into(),
                        Value::String(replay_protection_value(value)?),
                    );
                }
                if let Some(value) = body.get("enabled") {
                    next.insert("enabled".into(), Value::Bool(enabled_value(value)?));
                }
                if core_js::stringify_object(&next) == core_js::stringify_object(&provider) {
                    return Err(invalid("The update changes nothing").into());
                }
                let now = ctx.now();
                // Sessions verified under the old keys or claim rules would outlive them, so they end: the watermark
                // covers concurrent issuance, and the matching rows are deleted. Disabling is a kill switch and ends
                // them the same way (also with the feature off), so re-enabling the provider cannot bring them back.
                let field = |record: &Record, key: &str| {
                    core_js::stringify(record.get(key).unwrap_or(&Value::Null))
                };
                let ends_sessions = (provider.get("enabled") == Some(&Value::Bool(true))
                    && next.get("enabled") != Some(&Value::Bool(true)))
                    || VERIFICATION_FIELDS
                        .iter()
                        .any(|key| field(&provider, key) != field(&next, key));
                let mut watermark = None;
                if ends_sessions {
                    let value = next_watermark(
                        provider
                            .get("sessionsRevokedBefore")
                            .and_then(core_js::as_number),
                        None,
                        now,
                    )?;
                    next.insert("sessionsRevokedBefore".into(), number(value));
                    watermark = Some(value);
                }
                next.insert("updatedAt".into(), number(now));
                let stored = tx.put("oidcProviders", &next).await?;
                if let Some(watermark) = watermark {
                    delete_provider_sessions(&tx, &stored, watermark).await?;
                }
                Ok(public_oidc_provider(&stored))
            })
        });
        let updated = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:oidc-providers:update",
                &provider_id,
                mutation,
                false,
            )
            .await?;
        if let Some(id) = updated.get("id").and_then(Value::as_str) {
            self.forget(id);
        }
        Ok(Reply::json(updated))
    }
}
