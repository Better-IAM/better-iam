//! Port of `packages/server/src/api/service-accounts.ts`: the `serviceAccounts` API group (machine identities and
//! their lifecycle) and the `credentials` group (API keys, with `credentialSummary` and `scopesPolicy`).

use std::sync::Arc;

use better_iam_core::{
    AuditOutcome, CredentialInput, Filter, FindOptions, IamError, IamResult, Identity,
    IdentityStatus, Record,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use better_iam_types::api::{credentials, service_accounts};

use better_iam_auth::{CredentialTokenType, new_credential_token};

use crate::api::{Body, Reply, string_member};
use crate::contracts::{Mutation, MutationContext};
use crate::port::decode;
use crate::utils::{date_now, hash, id, public_identity_record};
use crate::validation::{integer, strings, text};

/// `ctx.serviceAccount(tx, identityId, tenantId)` as the stored record (member order and unknown members kept).
async fn service_account(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    identity_id: Option<&Value>,
    tenant_id: &str,
) -> IamResult<(Record, Identity)> {
    let raw = ctx.scoped(tx, "identities", identity_id, tenant_id).await?;
    if raw.get("kind").and_then(Value::as_str) != Some("service") {
        return Err(IamError::with_status(
            "NOT_FOUND",
            "Service account not found",
            404,
        ));
    }
    let account: Identity = decode(raw.clone())?;
    Ok((raw, account))
}

/// `if (account.status === 'deleted') throw ...`.
fn assert_not_deleted(account: &Identity) -> IamResult<()> {
    if account.status == IdentityStatus::Deleted {
        return Err(IamError::with_status(
            "NOT_FOUND",
            "Service account has been deleted",
            404,
        ));
    }
    Ok(())
}

/// The `serviceAccounts` API group (`createServiceAccountsApi(ctx)`): one method per route `serviceAccounts/{method}`.
pub struct ServiceAccountsApi {
    ctx: Arc<ServerContext>,
}

/// `createServiceAccountsApi(ctx)`.
pub fn create_service_accounts_api(ctx: &Arc<ServerContext>) -> IamResult<ServiceAccountsApi> {
    Ok(ServiceAccountsApi { ctx: ctx.clone() })
}

impl ServiceAccountsApi {
    /// `operation(credential, input.tenantId, action, resourceId, mutation)`.
    async fn run(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        action: &str,
        resource_id: &str,
        mutation: Mutation<'_>,
    ) -> IamResult<Value> {
        self.ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                action,
                resource_id,
                mutation,
                false,
            )
            .await
    }

    /// `.then((account) => afterIdentityChange(ctx, input.tenantId, [account.id], account))`.
    async fn after_change(&self, input: &Map<String, Value>, result: Value) -> IamResult<Value> {
        let identity_id = crate::js::js_string(result.get("id"));
        crate::api::package_automation::after_identity_change(
            &self.ctx,
            &string_member(input, "tenantId"),
            &[identity_id],
            &result,
        )
        .await
    }

    /// `serviceAccounts/create`: `expiresAt` schedules deactivation; the account's keys stop working at that time and
    /// the worker disables it.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<service_accounts::CreateInput>,
    ) -> IamResult<Reply<service_accounts::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant_ref = &tenant_id;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    ctx.granting_authority(&tx, &principal, tenant_ref, None)
                        .await?;
                    ctx.enforce_limit(
                        &tenant,
                        "serviceAccounts",
                        || async {
                            Ok(tx
                                .find(
                                    "identities",
                                    &Filter::new()
                                        .eq("tenantId", tenant_ref.as_str())
                                        .eq("kind", "service"),
                                    &FindOptions::default(),
                                )
                                .await?
                                .iter()
                                .filter(|item| {
                                    item.get("status").and_then(Value::as_str) != Some("deleted")
                                })
                                .count() as f64)
                        },
                        None,
                    )
                    .await?;
                    let mut account = Map::new();
                    account.insert("id".into(), Value::String(id()));
                    account.insert("tenantId".into(), Value::String(tenant_ref.clone()));
                    account.insert("kind".into(), Value::String("service".into()));
                    account.insert(
                        "name".into(),
                        Value::String(text(body.get("name"), "name", 256)?),
                    );
                    account.insert("status".into(), Value::String("active".into()));
                    account.insert("emailVerified".into(), Value::Bool(false));
                    account.insert("owner".into(), Value::Bool(false));
                    account.insert("rootAdmin".into(), Value::Bool(false));
                    account.insert("createdAt".into(), crate::js::number(date_now()));
                    if let Some(description) = body.get("description") {
                        account.insert(
                            "description".into(),
                            Value::String(text(Some(description), "description", 512)?),
                        );
                    }
                    if let Some(expires_at) = body.get("expiresAt") {
                        account.insert(
                            "expiresAt".into(),
                            crate::js::number(ctx.binding_expiry(Some(expires_at))?),
                        );
                    }
                    Ok(Value::Object(tx.insert("identities", &account).await?))
                })
            },
        );
        let account = self
            .run(
                credential,
                &input,
                "iam:identities:create",
                &tenant_id,
                mutation,
            )
            .await?;
        Ok(Reply::json(self.after_change(&input, account).await?))
    }

    /// `serviceAccounts/delete`.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<service_accounts::DeleteInput>,
    ) -> IamResult<Reply<service_accounts::DeleteOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let (_, account) =
                    service_account(ctx, &tx, body.get("identityId"), tenant).await?;
                let result =
                    crate::api::identities::delete_identity(ctx, &tx, &principal, &account).await?;
                let mut metadata = Map::new();
                metadata.insert("kind".into(), Value::String("service".into()));
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "identity:delete",
                        tenant,
                        &account.id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(result)
            })
        });
        let resource_id = string_member(&input, "identityId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:delete",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `serviceAccounts/get`.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<service_accounts::GetInput>,
    ) -> IamResult<Reply<service_accounts::GetOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let (raw, _) = service_account(ctx, &tx, body.get("identityId"), tenant).await?;
                Ok(Value::Object(public_identity_record(&raw)))
            })
        });
        let resource_id = string_member(&input, "identityId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:read",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `serviceAccounts/list`.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<service_accounts::ListInput>,
    ) -> IamResult<Reply<service_accounts::ListOutput>> {
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let include_deleted = body.get("includeDeleted") == Some(&Value::Bool(true));
                Ok(Value::Array(
                    tx.find(
                        "identities",
                        &Filter::new()
                            .eq("tenantId", tenant.as_str())
                            .eq("kind", "service"),
                        &FindOptions::default(),
                    )
                    .await?
                    .iter()
                    .filter(|account| {
                        include_deleted
                            || account.get("status").and_then(Value::as_str) != Some("deleted")
                    })
                    .map(|account| Value::Object(public_identity_record(account)))
                    .collect(),
                ))
            })
        });
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:read",
                &tenant_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `serviceAccounts/setStatus`: disabling a service account revokes every API key and assumed-role session it
    /// holds until it is enabled again.
    pub async fn set_status(
        &self,
        credential: &CredentialInput,
        input: Body<service_accounts::SetStatusInput>,
    ) -> IamResult<Reply<service_accounts::SetStatusOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let Some(status) = body
                    .get("status")
                    .and_then(Value::as_str)
                    .filter(|status| ["active", "disabled"].contains(status))
                else {
                    return Err(IamError::new("INVALID_INPUT", "Invalid status").into());
                };
                let (raw, account) =
                    service_account(ctx, &tx, body.get("identityId"), tenant).await?;
                assert_not_deleted(&account)?;
                if status == "active" && ctx.identity_expired(&account) {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "Extend or clear expiresAt before re-enabling an expired service account",
                        409,
                    )
                    .into());
                }
                let mut next = raw;
                next.insert("status".into(), Value::String(status.to_owned()));
                let updated = tx.put("identities", &next).await?;
                // The status is now this call's: a threats containment is over (released here, or held by this
                // disable).
                crate::threats::end_containment(&tx, &account.id, ctx.now()).await?;
                if status == "disabled" {
                    ctx.revoke_all(&tx, &account.id).await?;
                }
                Ok(Value::Object(public_identity_record(&updated)))
            })
        });
        let resource_id = string_member(&input, "identityId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:update",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `serviceAccounts/update`: renames, describes, sets attributes, or schedules (epoch milliseconds) or clears
    /// (null) the account's deactivation.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<service_accounts::UpdateInput>,
    ) -> IamResult<Reply<service_accounts::UpdateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let (raw, account) =
                    service_account(ctx, &tx, body.get("identityId"), tenant).await?;
                assert_not_deleted(&account)?;
                if ["name", "description", "attributes", "expiresAt"]
                    .iter()
                    .all(|key| !body.contains_key(*key))
                {
                    return Err(IamError::new("INVALID_INPUT", "Nothing to update").into());
                }
                let mut next = raw;
                if let Some(name) = body.get("name") {
                    next.insert("name".into(), Value::String(text(Some(name), "name", 256)?));
                }
                if let Some(description) = body.get("description") {
                    next.insert(
                        "description".into(),
                        Value::String(text(Some(description), "description", 512)?),
                    );
                }
                if let Some(attributes) = body.get("attributes") {
                    next.insert(
                        "attributes".into(),
                        Value::Object(crate::catalog::attribute_values(
                            &ctx.catalog.identity_attributes,
                            Some(attributes),
                        )?),
                    );
                }
                match body.get("expiresAt") {
                    Some(Value::Null) => {
                        next.shift_remove("expiresAt");
                    }
                    Some(expires_at) => {
                        next.insert(
                            "expiresAt".into(),
                            crate::js::number(ctx.binding_expiry(Some(expires_at))?),
                        );
                    }
                    None => {}
                }
                Ok(Value::Object(public_identity_record(
                    &tx.put("identities", &next).await?,
                )))
            })
        });
        let resource_id = string_member(&input, "identityId");
        let updated = self
            .run(
                credential,
                &input,
                "iam:identities:update",
                &resource_id,
                mutation,
            )
            .await?;
        Ok(Reply::json(self.after_change(&input, updated).await?))
    }
}

/// The `credentials` API group (`createCredentialsApi(ctx)`): one method per route `credentials/{method}`.
pub struct CredentialsApi {
    ctx: Arc<ServerContext>,
}

/// `createCredentialsApi(ctx)`.
pub fn create_credentials_api(ctx: &Arc<ServerContext>) -> IamResult<CredentialsApi> {
    Ok(CredentialsApi { ctx: ctx.clone() })
}

impl CredentialsApi {
    /// A key's expiry may be extended or shortened, but only into the future and at most a year out (`keyExpiry`).
    fn key_expiry(value: Option<&Value>, now: f64) -> IamResult<f64> {
        let expires_at = integer(value, "expiresAt", 0.0, 9_007_199_254_740_991.0)?;
        if expires_at <= now {
            return Err(IamError::new(
                "INVALID_INPUT",
                "expiresAt must be in the future",
            ));
        }
        if expires_at > now + 86_400_000.0 * 365.0 {
            return Err(IamError::new(
                "INVALID_INPUT",
                "expiresAt must be within one year",
            ));
        }
        Ok(expires_at)
    }

    /// `apiKey(tx, credentialId, tenantId)`: the API key session a credential ID names.
    async fn api_key(
        &self,
        tx: &Store,
        credential_id: Option<&Value>,
        tenant_id: &str,
    ) -> IamResult<Map<String, Value>> {
        let session = self
            .ctx
            .scoped(tx, "sessions", credential_id, tenant_id)
            .await?;
        if session.get("kind").and_then(Value::as_str) != Some("api-key") {
            return Err(IamError::new(
                "INVALID_CREDENTIAL",
                "Not an API key credential",
            ));
        }
        Ok(session)
    }

    async fn run(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        action: &str,
        resource_id: &str,
        mutation: Mutation<'_>,
    ) -> IamResult<Value> {
        self.ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                action,
                resource_id,
                mutation,
                false,
            )
            .await
    }

    /// `credentials/create`: issues an opaque API key for a service account, bounded by the issuer's grant authority
    /// and an optional session policy (or `scopes`). The plaintext is returned once.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<credentials::CreateInput>,
    ) -> IamResult<Reply<credentials::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = crate::api::string_member(body, "tenantId");
                ctx.auth.require_recent(&principal)?;
                let authority = ctx
                    .granting_authority(&tx, &principal, &tenant_id, None)
                    .await?;
                let identity: better_iam_core::Identity = crate::port::decode(
                    ctx.scoped(&tx, "identities", body.get("identityId"), &tenant_id)
                        .await?,
                )?;
                if !crate::agents::machine_identity(&identity)
                    || identity.status != better_iam_core::IdentityStatus::Active
                    || ctx.identity_expired(&identity)
                {
                    return Err(IamError::new(
                        "INVALID_IDENTITY",
                        "API keys require an active service account",
                    )
                    .into());
                }
                // An agent gets keys only while its sponsor is an active person (agents.ts).
                if identity.kind == better_iam_core::IdentityKind::Agent
                    && crate::agents::agent_standing(ctx, &tx, &identity).await? != "ok"
                {
                    return Err(IamError::new(
                        "INVALID_IDENTITY",
                        "API keys require an agent in good standing",
                    )
                    .into());
                }
                if body.contains_key("scopes") && body.contains_key("policy") {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "Provide either scopes or a session policy",
                    )
                    .into());
                }
                let mut policy: Option<Value> = body.get("policy").cloned();
                if let Some(scopes) = body.get("scopes") {
                    let scopes = crate::js::unique(strings(Some(scopes), "scopes")?);
                    if scopes.is_empty() {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "scopes must name at least one action",
                        )
                        .into());
                    }
                    policy = Some(scopes_policy(&scopes));
                }
                // A key never mints a broader key: a caller key with scopes or a session policy passes them on, and a
                // new key's own scopes must fall within the caller's.
                if let Some(caller) = &principal.session.policy {
                    let caller = caller.to_value();
                    match &policy {
                        None => policy = Some(caller),
                        Some(own) if !within_key_policy(&caller, Some(own)) => {
                            return Err(IamError::with_status(
                                "ACCESS_DENIED",
                                "A key can only issue keys within its own scopes or policy",
                                403,
                            )
                            .into());
                        }
                        Some(_) => {}
                    }
                }
                if let Some(policy) = &policy {
                    ctx.catalog
                        .validate(tx.as_ref(), &tenant_id, policy)
                        .await?;
                }
                // Typed and checksummed (`biam_key_…`) so secret scanners recognise leaked keys.
                let raw = new_credential_token(CredentialTokenType::Key);
                // The injected clock, so creation and expiry agree with every other time check.
                let now = ctx.now();
                let duration = integer(
                    Some(&match body.get("expiresInSeconds") {
                        None | Some(Value::Null) => crate::js::number(86400.0 * 90.0),
                        Some(value) => value.clone(),
                    }),
                    "expiresInSeconds",
                    60.0,
                    86400.0 * 365.0,
                )?;
                let mut record = Map::new();
                record.insert("id".into(), Value::String(id()));
                record.insert("tenantId".into(), Value::String(tenant_id.clone()));
                record.insert("identityId".into(), Value::String(identity.id.clone()));
                record.insert("kind".into(), json!("api-key"));
                record.insert("tokenHash".into(), Value::String(hash(&raw)));
                record.insert("uniqueKey".into(), Value::String(hash(&raw)));
                record.insert("createdAt".into(), crate::js::number(now));
                record.insert("lastSeenAt".into(), crate::js::number(now));
                record.insert("authenticatedAt".into(), crate::js::number(now));
                record.insert(
                    "expiresAt".into(),
                    crate::js::number(now + duration * 1000.0),
                );
                record.insert("mfa".into(), Value::Bool(false));
                if let Some(policy) = policy {
                    record.insert("policy".into(), policy);
                }
                record.insert(
                    "credentialAuthorityId".into(),
                    Value::String(authority.id.clone()),
                );
                if let Some(name) = body.get("name") {
                    record.insert("name".into(), Value::String(text(Some(name), "name", 128)?));
                }
                if let Some(description) = body.get("description") {
                    record.insert(
                        "description".into(),
                        Value::String(text(Some(description), "description", 512)?),
                    );
                }
                let session = tx.insert("sessions", &record).await?;
                let mut out = Map::new();
                out.insert("token".into(), Value::String(raw));
                out.insert(
                    "credentialId".into(),
                    session.get("id").cloned().unwrap_or(Value::Null),
                );
                out.insert(
                    "expiresAt".into(),
                    session.get("expiresAt").cloned().unwrap_or(Value::Null),
                );
                if let Some(name) = session.get("name") {
                    out.insert("name".into(), name.clone());
                }
                Ok(Value::Object(out))
            })
        });
        let resource_id = crate::api::string_member(&input, "identityId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:credentials:create",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `credentials/get`.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<credentials::GetInput>,
    ) -> IamResult<Reply<credentials::GetOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = crate::api::string_member(body, "tenantId");
                let session = self
                    .api_key(&tx, body.get("credentialId"), &tenant_id)
                    .await?;
                Ok(credential_summary_json(&session, ctx.now()))
            })
        });
        let resource_id = crate::api::string_member(&input, "credentialId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:credentials:read",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `credentials/list`: API keys of the tenant, or of one service account, newest first. `unusedForMs` keeps only
    /// keys that have not authenticated a request in that long.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<credentials::ListInput>,
    ) -> IamResult<Reply<credentials::ListOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = crate::api::string_member(body, "tenantId");
                let mut filter = Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("kind", "api-key");
                if let Some(identity_id) = body.get("identityId") {
                    filter = filter.eq("identityId", text(Some(identity_id), "identityId", 256)?);
                }
                let now = ctx.now();
                let unused_since = match body.get("unusedForMs") {
                    Some(value) => Some(
                        now - integer(
                            Some(value),
                            "unusedForMs",
                            0.0,
                            10.0 * 365.0 * 86_400_000.0,
                        )?,
                    ),
                    None => None,
                };
                let mut summaries: Vec<Map<String, Value>> = tx
                    .find("sessions", &filter, &FindOptions::default())
                    .await?
                    .iter()
                    .map(|session| match credential_summary_json(session, now) {
                        Value::Object(map) => map,
                        _ => Map::new(),
                    })
                    .filter(|summary| {
                        let number = |key: &str| summary.get(key).and_then(Value::as_f64);
                        unused_since.is_none_or(|since| {
                            number("lastUsedAt")
                                .or_else(|| number("createdAt"))
                                .unwrap_or(f64::NAN)
                                <= since
                        })
                    })
                    .collect();
                summaries.sort_by(|a, b| {
                    let created = |summary: &Map<String, Value>| {
                        summary
                            .get("createdAt")
                            .and_then(Value::as_f64)
                            .unwrap_or(f64::NAN)
                    };
                    let id = |summary: &Map<String, Value>| {
                        summary
                            .get("id")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned()
                    };
                    let difference = created(b) - created(a);
                    if difference != 0.0 && !difference.is_nan() {
                        return difference
                            .partial_cmp(&0.0)
                            .unwrap_or(std::cmp::Ordering::Equal);
                    }
                    if better_iam_core::js::cmp_utf16(&id(a), &id(b)) == std::cmp::Ordering::Less {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Greater
                    }
                });
                Ok(Value::Array(
                    summaries.into_iter().map(Value::Object).collect(),
                ))
            })
        });
        let resource_id = match input.get("identityId") {
            Some(Value::String(identity_id)) => identity_id.clone(),
            Some(_) => String::new(),
            None => crate::api::string_member(&input, "tenantId"),
        };
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:credentials:read",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `credentials/revoke`: deletes an API key at once. Other sessions (user, role) are refused.
    pub async fn revoke(
        &self,
        credential: &CredentialInput,
        input: Body<credentials::RevokeInput>,
    ) -> IamResult<Reply<credentials::RevokeOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = crate::api::string_member(body, "tenantId");
                ctx.auth.require_recent(&principal)?;
                let session = self
                    .api_key(&tx, body.get("credentialId"), &tenant_id)
                    .await?;
                let session_id = session
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                tx.delete("sessions", &session_id).await?;
                Ok(json!({ "revoked": true }))
            })
        });
        let resource_id = crate::api::string_member(&input, "credentialId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:credentials:revoke",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `credentials/rotate`: replaces the key material atomically; the old key stops working in the same transaction.
    pub async fn rotate(
        &self,
        credential: &CredentialInput,
        input: Body<credentials::RotateInput>,
    ) -> IamResult<Reply<credentials::RotateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = crate::api::string_member(body, "tenantId");
                ctx.auth.require_recent(&principal)?;
                let old = ctx
                    .scoped(&tx, "sessions", body.get("credentialId"), &tenant_id)
                    .await?;
                if old.get("kind").and_then(Value::as_str) != Some("api-key") {
                    return Err(
                        IamError::new("INVALID_CREDENTIAL", "Only API keys can rotate").into(),
                    );
                }
                // Rotating hands over the new token, so a key may only rotate keys within its own scopes.
                if let Some(caller) = &principal.session.policy
                    && !within_key_policy(&caller.to_value(), old.get("policy"))
                {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "A key can only rotate keys within its own scopes or policy",
                        403,
                    )
                    .into());
                }
                let authority = ctx
                    .granting_authority(
                        &tx,
                        &principal,
                        &tenant_id,
                        old.get("credentialAuthorityId").and_then(Value::as_str),
                    )
                    .await?;
                let raw = new_credential_token(CredentialTokenType::Key);
                let old_id = old
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                tx.delete("sessions", &old_id).await?;
                let now = ctx.now();
                // The replacement keeps the label, policy, and expiry; its usage history and authentication time start
                // over.
                let mut replacement = old.clone();
                replacement.insert("id".into(), Value::String(id()));
                replacement.insert("tokenHash".into(), Value::String(hash(&raw)));
                replacement.insert("uniqueKey".into(), Value::String(hash(&raw)));
                replacement.insert("createdAt".into(), crate::js::number(now));
                replacement.insert("lastSeenAt".into(), crate::js::number(now));
                replacement.insert("authenticatedAt".into(), crate::js::number(now));
                replacement.insert(
                    "credentialAuthorityId".into(),
                    Value::String(authority.id.clone()),
                );
                tx.insert("sessions", &replacement).await?;
                let mut out = Map::new();
                out.insert("token".into(), Value::String(raw));
                out.insert(
                    "credentialId".into(),
                    replacement.get("id").cloned().unwrap_or(Value::Null),
                );
                out.insert(
                    "expiresAt".into(),
                    replacement.get("expiresAt").cloned().unwrap_or(Value::Null),
                );
                if let Some(name) = replacement.get("name") {
                    out.insert("name".into(), name.clone());
                }
                Ok(Value::Object(out))
            })
        });
        let resource_id = crate::api::string_member(&input, "credentialId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:credentials:create",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `credentials/update`: relabels a key or moves its expiry (future, at most a year out); the token never changes.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<credentials::UpdateInput>,
    ) -> IamResult<Reply<credentials::UpdateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = crate::api::string_member(body, "tenantId");
                let mut session = self
                    .api_key(&tx, body.get("credentialId"), &tenant_id)
                    .await?;
                if !body.contains_key("name")
                    && !body.contains_key("description")
                    && !body.contains_key("expiresAt")
                {
                    return Err(IamError::new("INVALID_INPUT", "Nothing to update").into());
                }
                if body.contains_key("expiresAt") {
                    ctx.auth.require_recent(&principal)?;
                    ctx.granting_authority(
                        &tx,
                        &principal,
                        &tenant_id,
                        session.get("credentialAuthorityId").and_then(Value::as_str),
                    )
                    .await?;
                }
                match body.get("name") {
                    Some(Value::Null) => {
                        session.shift_remove("name");
                    }
                    Some(name) => {
                        session
                            .insert("name".into(), Value::String(text(Some(name), "name", 128)?));
                    }
                    None => {}
                }
                match body.get("description") {
                    Some(Value::Null) => {
                        session.shift_remove("description");
                    }
                    Some(description) => {
                        session.insert(
                            "description".into(),
                            Value::String(text(Some(description), "description", 512)?),
                        );
                    }
                    None => {}
                }
                if let Some(expires_at) = body.get("expiresAt") {
                    session.insert(
                        "expiresAt".into(),
                        crate::js::number(Self::key_expiry(Some(expires_at), ctx.now())?),
                    );
                }
                let stored = tx.put("sessions", &session).await?;
                Ok(credential_summary_json(&stored, ctx.now()))
            })
        });
        let resource_id = crate::api::string_member(&input, "credentialId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:credentials:create",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }
}

/// The session policy's statement id of a scopes list (`scopesSid`).
const SCOPES_SID: &str = "KeyScopes";

/// `scopesPolicy(scopes)`: a scopes list compiles to a session policy allowing exactly those actions on every resource.
pub fn scopes_policy(scopes: &[String]) -> Value {
    json!({
        "version": 1,
        "statements": [{ "sid": SCOPES_SID, "effect": "allow", "actions": scopes, "resources": ["*"] }],
    })
}

/// `policyScopes(policy)`: the scopes list behind a session policy, when the policy is exactly the compiled form.
fn policy_scopes(policy: Option<&Value>) -> Option<Vec<String>> {
    let statements = policy?.get("statements")?.as_array()?;
    let [statement] = statements.as_slice() else {
        return None;
    };
    let resources = statement.get("resources")?.as_array()?;
    (statement.get("sid").and_then(Value::as_str) == Some(SCOPES_SID)
        && statement.get("effect").and_then(Value::as_str) == Some("allow")
        && resources.len() == 1
        && resources[0] == json!("*")
        && statement.get("conditions").is_none_or(Value::is_null))
    .then(|| {
        statement
            .get("actions")
            .and_then(Value::as_array)
            .map(|actions| {
                actions
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// `/[*?]|\$\{/`.
fn has_wildcard(value: &str) -> bool {
    value.contains('*') || value.contains('?') || value.contains(concat!("$", "{"))
}

/// `scopeCovers(outer, inner)`: every action `inner` names is also named by `outer`; a wildcard scope needs an equal
/// or broader prefix.
fn scope_covers(outer: &str, inner: &str) -> bool {
    if outer == inner {
        return true;
    }
    if !has_wildcard(inner) {
        return better_iam_core::match_pattern(outer, inner, None);
    }
    let prefix = &outer[..outer.len().saturating_sub(1)];
    outer.ends_with('*') && !has_wildcard(prefix) && inner.starts_with(prefix)
}

/// `withinKeyPolicy(outer, inner)`: whether a key policy stays within a caller key's own.
fn within_key_policy(outer: &Value, inner: Option<&Value>) -> bool {
    let Some(inner) = inner.filter(|inner| !inner.is_null()) else {
        return false;
    };
    if better_iam_core::js::stringify(outer) == better_iam_core::js::stringify(inner) {
        return true;
    }
    match (policy_scopes(Some(outer)), policy_scopes(Some(inner))) {
        (Some(outer), Some(inner)) => inner
            .iter()
            .all(|scope| outer.iter().any(|allowed| scope_covers(allowed, scope))),
        _ => false,
    }
}

/// `credentialSummary(session, now)` as the TypeScript object (member order included).
pub fn credential_summary_json(session: &Map<String, Value>, now: f64) -> Value {
    let number = |key: &str| session.get(key).and_then(Value::as_f64).unwrap_or(f64::NAN);
    let mut out = Map::new();
    for key in ["id", "identityId", "createdAt", "expiresAt"] {
        out.insert(key.into(), session.get(key).cloned().unwrap_or(Value::Null));
    }
    out.insert("expired".into(), Value::Bool(number("expiresAt") <= now));
    if let Some(policy) = session.get("policy") {
        out.insert("policy".into(), policy.clone());
    }
    if let Some(authority) = session.get("credentialAuthorityId") {
        out.insert("credentialAuthorityId".into(), authority.clone());
    }
    if let Some(name) = session.get("name") {
        out.insert("name".into(), name.clone());
    }
    if let Some(description) = session.get("description") {
        out.insert("description".into(), description.clone());
    }
    if number("lastSeenAt") > number("createdAt") {
        out.insert(
            "lastUsedAt".into(),
            session.get("lastSeenAt").cloned().unwrap_or(Value::Null),
        );
    }
    if let Some(scopes) = policy_scopes(session.get("policy")) {
        out.insert("scopes".into(), json!(scopes));
    }
    Value::Object(out)
}

/// An API key as administrators see it: label, lifetime, and usage, never token material.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialSummary {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    #[serde(rename = "name", default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    /// When the key last authenticated a request (recorded at most once a minute); absent until first use.
    #[serde(
        rename = "lastUsedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_used_at: Option<f64>,
    #[serde(rename = "expired")]
    pub expired: bool,
    #[serde(rename = "policy", default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<better_iam_core::PolicyDocument>,
    /// The action allowlist the key was issued with (`credentials.create({ scopes })`), when its policy is exactly
    /// that.
    #[serde(rename = "scopes", default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(
        rename = "credentialAuthorityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub credential_authority_id: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

pub fn credential_summary(
    session: &better_iam_core::Session,
    now: f64,
) -> IamResult<crate::api::service_accounts::CredentialSummary> {
    serde_json::from_value(credential_summary_json(&crate::port::encode(session), now))
        .map_err(|_| crate::js::internal_error())
}
