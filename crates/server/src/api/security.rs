//! Port of `packages/server/src/api/security.ts`: the `security` API group (incident response: network blocks).

use std::sync::Arc;

use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, Record, Tenant, ip_matches, is_ip_range, js as core_js,
};
use better_iam_types::api::security;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::utils::{by_newest_records, id};
use crate::validation::{integer, text};

const MIN_DURATION_MS: f64 = 60_000.0;
const MAX_DURATION_MS: f64 = 365.0 * 24.0 * 60.0 * 60_000.0;

/// Incident response: network blocks. A block refuses every authentication flow and every live session whose
/// recorded client IP it covers, and every API key or assumed-role token presented from it, for one tenant or, when
/// root administrators set it on the root tenant with `platform`, for the whole installation. Blocks are checked
/// before rate limits and credentials, so a blocked address cannot count against anyone, and they need a recorded IP
/// (`http.clientInfo`) to bite. Lapsed blocks are deleted by the retention worker (`purgeDeleted`).
pub struct SecurityApi {
    ctx: Arc<ServerContext>,
}

/// `createSecurityApi(ctx)`.
pub fn create_security_api(ctx: &Arc<ServerContext>) -> IamResult<SecurityApi> {
    Ok(SecurityApi { ctx: ctx.clone() })
}

/// `withStatus(block)`: the block with `active` (not yet lapsed).
fn with_status(ctx: &ServerContext, block: &Record) -> Value {
    let mut out = block.clone();
    let active = match block.get("expiresAt") {
        None => true,
        Some(expires) => core_js::as_number(expires).is_some_and(|expires| expires > ctx.now()),
    };
    out.insert("active".into(), Value::Bool(active));
    Value::Object(out)
}

/// Platform-wide blocks are set by root administrators on the root tenant.
async fn platform_scope(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    principal: &AuthenticatedPrincipal,
) -> IamResult<()> {
    let realm = ctx.tenant(tx, tenant_id).await?;
    if realm.parent_id.is_some() || !ctx.root_principal(tx, principal).await? {
        return Err(IamError::with_status(
            "ACCESS_DENIED",
            "Platform-wide blocks are set by root administrators on the root tenant",
            403,
        ));
    }
    Ok(())
}

/// The root tenant's own blocks decide whether root administrators can sign in, so they are root's alone as well: a
/// platform staff member could otherwise block every root administrator's address.
async fn root_tenant_scope(
    ctx: &ServerContext,
    tx: &Store,
    realm: &Tenant,
    principal: &AuthenticatedPrincipal,
) -> IamResult<()> {
    if realm.parent_id.is_none() && !ctx.root_principal(tx, principal).await? {
        return Err(IamError::with_status(
            "ACCESS_DENIED",
            "Blocks on the root tenant are set by root administrators",
            403,
        ));
    }
    Ok(())
}

impl SecurityApi {
    /// Runs a block change and clears the cached block lists again once its transaction has committed: the clear
    /// inside the transaction alone can race a concurrent read that caches the pre-change list for a few seconds.
    async fn block_change(
        &self,
        credential: &CredentialInput,
        tenant_id: Option<&Value>,
        action: &str,
        resource_id: &str,
        mutation: Mutation<'_>,
    ) -> IamResult<Value> {
        let result = match self.ctx.operations() {
            Ok(operations) => {
                operations
                    .operation(credential, tenant_id, action, resource_id, mutation, false)
                    .await
            }
            Err(error) => Err(error),
        };
        self.ctx.auth.invalidate_network_blocks();
        result
    }

    /// `security/blockNetwork`: blocks a network (IPv4/IPv6 address or CIDR block) for the tenant, or for the whole
    /// platform with `platform` (root administrators, on the root tenant). `durationMs` (one minute to a year) makes
    /// it lapse by itself; without it the block stays until lifted. A network covering the caller's own address (the
    /// one their session was issued from, or the one the request comes from) is refused so nobody locks themselves
    /// out. Requires iam:security:manage and recent authentication; audited as `security:network-block`.
    pub async fn block_network(
        &self,
        credential: &CredentialInput,
        input: Body<security::BlockNetworkInput>,
    ) -> IamResult<Reply<security::BlockNetworkOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let auth = &ctx.auth;
                    auth.require_recent(&principal)?;
                    root_tenant_scope(ctx, &tx, &tenant, &principal).await?;
                    let network =
                        core_js::trim(&text(body.get("network"), "network", 64)?).to_owned();
                    if !is_ip_range(&network) {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "network must be an IPv4/IPv6 address or CIDR block",
                        )
                        .into());
                    }
                    let reason =
                        core_js::trim(&text(body.get("reason"), "reason", 512)?).to_owned();
                    if reason.is_empty() {
                        return Err(IamError::new("INVALID_INPUT", "reason is required").into());
                    }
                    let duration_ms = match body.get("durationMs") {
                        None => None,
                        Some(value) => Some(integer(
                            Some(value),
                            "durationMs",
                            MIN_DURATION_MS,
                            MAX_DURATION_MS,
                        )?),
                    };
                    let platform = body.get("platform") == Some(&Value::Bool(true));
                    let tenant_id = string_member(body, "tenantId");
                    if platform {
                        platform_scope(ctx, &tx, &tenant_id, &principal).await?;
                    }
                    // Neither the address this session was issued from nor the one this request comes from may be
                    // blocked: the first would end the caller's session, the second would refuse their next sign-in
                    // and the reauthentication they need to lift the block.
                    let own = [
                        principal
                            .session
                            .client
                            .as_ref()
                            .and_then(|client| client.ip.clone()),
                        auth.current_client().and_then(|client| client.ip),
                    ];
                    if own.iter().flatten().any(|ip| ip_matches(ip, &network)) {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "That network includes your own address",
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let existing = tx
                        .find(
                            "authBlocks",
                            &Filter::new().eq("tenantId", tenant_id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                        .into_iter()
                        .find(|block| {
                            block.get("network").and_then(Value::as_str) == Some(network.as_str())
                                && crate::js::truthy(block.get("platform")) == platform
                        });
                    let block_id = existing
                        .as_ref()
                        .map(|existing| better_iam_core::record_id(existing).to_owned())
                        .unwrap_or_else(id);
                    let mut block = Record::new();
                    block.insert("id".into(), Value::String(block_id.clone()));
                    block.insert("tenantId".into(), Value::String(tenant_id.clone()));
                    block.insert("network".into(), Value::String(network.clone()));
                    block.insert("reason".into(), Value::String(reason.clone()));
                    block.insert("createdAt".into(), crate::js::number(now));
                    block.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let expires_at = duration_ms.map(|duration| now + duration);
                    if let Some(expires_at) = expires_at {
                        block.insert("expiresAt".into(), crate::js::number(expires_at));
                    }
                    if platform {
                        block.insert("platform".into(), Value::Bool(true));
                    }
                    if existing.is_some() {
                        tx.put("authBlocks", &block).await?;
                    } else {
                        tx.insert("authBlocks", &block).await?;
                    }
                    auth.invalidate_network_blocks();
                    let mut metadata = Map::new();
                    metadata.insert("network".into(), Value::String(network));
                    metadata.insert("reason".into(), Value::String(reason));
                    metadata.insert("platform".into(), Value::Bool(platform));
                    if let Some(expires_at) = expires_at {
                        metadata.insert("expiresAt".into(), crate::js::number(expires_at));
                    }
                    metadata.insert("renewed".into(), Value::Bool(existing.is_some()));
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "security:network-block",
                            &tenant_id,
                            &block_id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(with_status(ctx, &block))
                })
            },
        );
        let result = self
            .block_change(
                credential,
                input.get("tenantId"),
                "iam:security:manage",
                "security/networks",
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `security/listBlocks`: the tenant's blocks, newest first, each with `active` (not yet lapsed). Requires
    /// iam:security:read.
    pub async fn list_blocks(
        &self,
        credential: &CredentialInput,
        input: Body<security::ListBlocksInput>,
    ) -> IamResult<Reply<security::ListBlocksOutput>> {
        let ctx = &self.ctx;
        let tenant_id = string_member(&input, "tenantId");
        let tenant_id = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let mut blocks = tx
                    .find(
                        "authBlocks",
                        &Filter::new().eq("tenantId", tenant_id.clone()),
                        &FindOptions::default(),
                    )
                    .await?;
                blocks.sort_by(by_newest_records);
                Ok(Value::Array(
                    blocks.iter().map(|block| with_status(ctx, block)).collect(),
                ))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:security:read",
                "security/networks",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `security/unblockNetwork`: lifts a block early. Requires iam:security:manage and recent authentication;
    /// audited as `security:network-unblock`.
    pub async fn unblock_network(
        &self,
        credential: &CredentialInput,
        input: Body<security::UnblockNetworkInput>,
    ) -> IamResult<Reply<security::UnblockNetworkOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let auth = &ctx.auth;
                    auth.require_recent(&principal)?;
                    root_tenant_scope(ctx, &tx, &tenant, &principal).await?;
                    let tenant_id = string_member(body, "tenantId");
                    let block_id = text(body.get("blockId"), "blockId", 256)?;
                    let block = ctx
                        .scoped(
                            &tx,
                            "authBlocks",
                            Some(&Value::String(block_id)),
                            &tenant_id,
                        )
                        .await?;
                    let platform = crate::js::truthy(block.get("platform"));
                    if platform {
                        platform_scope(ctx, &tx, &tenant_id, &principal).await?;
                    }
                    let block_id = better_iam_core::record_id(&block).to_owned();
                    tx.delete("authBlocks", &block_id).await?;
                    auth.invalidate_network_blocks();
                    let mut metadata = Map::new();
                    if let Some(network) = block.get("network") {
                        metadata.insert("network".into(), network.clone());
                    }
                    metadata.insert("platform".into(), Value::Bool(platform));
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "security:network-unblock",
                            &tenant_id,
                            &block_id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(json!({ "success": true }))
                })
            },
        );
        let result = self
            .block_change(
                credential,
                input.get("tenantId"),
                "iam:security:manage",
                "security/networks",
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }
}
