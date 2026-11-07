//! Port of `packages/server/src/api/features.ts`: the `features` API group (feature flags at platform and tenant
//! level) and the credential-free evaluator behind `iam.features`.

use std::sync::Arc;

use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, Record, Tenant, TenantStatus,
};
use better_iam_types::api::features;
use indexmap::IndexMap;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::features::{
    EvaluateFeaturesOptions, FEATURE_FLAGS, FEATURE_TARGETS, FeatureEvaluation, FeatureFlag,
    FeatureState, FeatureTarget, MAX_FEATURE_FLAGS_PER_TENANT, evaluate_features, evaluate_flag,
    feature_key, feature_settings_map, feature_state,
};
use crate::js::{cmp_utf16, invalid_input, number, number_to_string};
use crate::port::decode;
use crate::utils::id;
use crate::validation::{object, strings, text};

/// `features/{key}`: the resource of a flag.
fn resource(key: &str) -> String {
    format!("features/{key}")
}

/// `rootOf(chain)`: the root tenant at the end of an ancestry.
fn root_of(chain: &[Tenant]) -> &str {
    chain.last().map(|realm| realm.id.as_str()).unwrap_or("")
}

/// `definition(flag, rootId)`: a flag's definition as the managers of its defining tenant see it.
fn definition(flag: &FeatureFlag, root_id: &str) -> Value {
    let mut out = Map::new();
    out.insert("id".into(), Value::String(flag.id.clone()));
    out.insert("key".into(), Value::String(flag.key.clone()));
    out.insert("tenantId".into(), Value::String(flag.tenant_id.clone()));
    out.insert(
        "scope".into(),
        Value::String(if flag.tenant_id == root_id {
            "platform".into()
        } else {
            "tenant".into()
        }),
    );
    if let Some(description) = &flag.description {
        out.insert("description".into(), Value::String(description.clone()));
    }
    out.insert("defaultValue".into(), Value::Bool(flag.default_value));
    if let Some(rollout) = flag.rollout_percentage {
        out.insert("rolloutPercentage".into(), number(rollout));
    }
    out.insert(
        "tenantOverridable".into(),
        Value::Bool(flag.tenant_overridable),
    );
    out.insert("killSwitch".into(), Value::Bool(flag.kill_switch));
    out.insert("internal".into(), Value::Bool(flag.internal));
    out.insert("createdAt".into(), number(flag.created_at));
    out.insert("createdBy".into(), Value::String(flag.created_by.clone()));
    out.insert("updatedAt".into(), number(flag.updated_at));
    out.insert("updatedBy".into(), Value::String(flag.updated_by.clone()));
    Value::Object(out)
}

/// Audit metadata for a flag's settings.
fn settings_metadata(flag: &FeatureFlag) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert("key".into(), Value::String(flag.key.clone()));
    out.insert("defaultValue".into(), Value::Bool(flag.default_value));
    out.insert(
        "rolloutPercentage".into(),
        flag.rollout_percentage.map(number).unwrap_or(Value::Null),
    );
    out.insert(
        "tenantOverridable".into(),
        Value::Bool(flag.tenant_overridable),
    );
    out.insert("killSwitch".into(), Value::Bool(flag.kill_switch));
    out.insert("internal".into(), Value::Bool(flag.internal));
    out
}

/// `writable(realm)`: deleted tenants cannot be updated.
fn writable(realm: &Tenant) -> IamResult<()> {
    if realm.status == TenantStatus::Deleted {
        return Err(IamError::new(
            "INVALID_TRANSITION",
            "Deleted tenants cannot be updated",
        ));
    }
    Ok(())
}

fn status_json(status: &TenantStatus) -> Value {
    serde_json::to_value(status).unwrap_or(Value::Null)
}

/// `ownFlag(tx, tenantId, key)`: the stored record and the flag the tenant defines with the key.
async fn own_flag(tx: &Store, tenant_id: &str, key: &str) -> IamResult<(Record, FeatureFlag)> {
    let found = tx
        .find(
            FEATURE_FLAGS,
            &Filter::new()
                .eq("tenantId", tenant_id.to_owned())
                .eq("uniqueKey", key.to_owned()),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .next();
    let Some(record) = found else {
        return Err(IamError::with_status(
            "NOT_FOUND",
            "Feature flag not found",
            404,
        ));
    };
    let flag = decode(record.clone())?;
    Ok((record, flag))
}

/// `entryAt(tx, tenantId, flag, source)`: the target or override a tenant holds for a flag.
async fn entry_at(
    tx: &Store,
    tenant_id: &str,
    flag: &FeatureFlag,
    source: &str,
) -> IamResult<Option<FeatureTarget>> {
    let found = tx
        .find(
            FEATURE_TARGETS,
            &Filter::new()
                .eq("tenantId", tenant_id.to_owned())
                .eq("uniqueKey", format!("{}:{source}", flag.id)),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .next();
    found.map(decode).transpose()
}

/// `view(tx, state, flag, withDefinition)`: one flag as a tenant's administrators see it.
async fn view(
    tx: &Store,
    state: &FeatureState,
    flag: &FeatureFlag,
    with_definition: bool,
) -> IamResult<Value> {
    let realm = state.chain.first().ok_or_else(crate::js::internal_error)?;
    let evaluation = evaluate_flag(state, flag)?;
    let (override_entry, target) = if flag.tenant_id == realm.id {
        (None, None)
    } else {
        let override_entry = entry_at(tx, &realm.id, flag, "override").await?;
        let target = entry_at(tx, &realm.id, flag, "target").await?;
        (override_entry, target)
    };
    let mut out = Map::new();
    out.insert("key".into(), Value::String(flag.key.clone()));
    if let Some(description) = &flag.description {
        out.insert("description".into(), Value::String(description.clone()));
    }
    out.insert("scope".into(), Value::String(evaluation.scope.clone()));
    out.insert("definedBy".into(), Value::String(flag.tenant_id.clone()));
    if with_definition {
        out.insert("definition".into(), definition(flag, root_of(&state.chain)));
    }
    out.insert(
        "tenantOverridable".into(),
        Value::Bool(flag.tenant_overridable),
    );
    out.insert("evaluation".into(), evaluation.to_json());
    if let Some(entry) = override_entry {
        out.insert(
            "override".into(),
            json!({ "value": entry.value, "setAt": number(entry.set_at), "setBy": entry.set_by }),
        );
    }
    if let Some(entry) = target {
        let mut target = Map::new();
        target.insert("value".into(), Value::Bool(entry.value));
        target.insert("locked".into(), Value::Bool(entry.locked == Some(true)));
        if let Some(expires_at) = entry.expires_at {
            target.insert("expiresAt".into(), number(expires_at));
        }
        out.insert("target".into(), Value::Object(target));
    }
    Ok(Value::Object(out))
}

/// Settings input without the addressing fields.
fn settings_input(input: &Map<String, Value>) -> IamResult<Map<String, Value>> {
    let value = Value::Object(input.clone());
    let mut rest = object(Some(&value))?.clone();
    rest.shift_remove("tenantId");
    rest.shift_remove("key");
    Ok(rest)
}

fn by_key(a: &FeatureFlag, b: &FeatureFlag) -> std::cmp::Ordering {
    cmp_utf16(&a.key, &b.key)
}

/// The `features` API group (`createFeaturesApi(ctx)`): one method per route `features/{method}`.
///
/// Feature flags at platform and tenant level. The root tenant's flags are platform flags; any organization or
/// project can define flags for its own subtree. A flag's value for a tenant comes from, in order: its kill switch,
/// the nearest target or tenant override along the ancestry (a tenant's own override beats a target on the same
/// tenant; a locked target silences overrides beneath it), a percentage rollout, and its default.
pub struct FeaturesApi {
    ctx: Arc<ServerContext>,
}

/// `createFeaturesApi(ctx)`.
pub fn create_features_api(ctx: &Arc<ServerContext>) -> IamResult<FeaturesApi> {
    Ok(FeaturesApi { ctx: ctx.clone() })
}

impl FeaturesApi {
    async fn audit(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        action: &str,
        tenant_id: &str,
        key: &str,
        metadata: Map<String, Value>,
    ) -> IamResult<()> {
        self.ctx
            .events()?
            .audit(
                tx,
                principal,
                action,
                tenant_id,
                &resource(key),
                AuditOutcome::Allow,
                false,
                Some(metadata),
            )
            .await
    }

    /// `features/create`: defines a flag in the tenant: on the root tenant a platform flag, elsewhere a flag for the
    /// tenant's subtree. Keys are unique per tenant and may not repeat a key an ancestor defines; at most 200 flags
    /// per tenant. Requires iam:features:manage on `iam/features/{key}`; audited as `feature:create`.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<features::CreateInput>,
    ) -> IamResult<Reply<features::CreateOutput>> {
        let key = feature_key(input.get("key"))?;
        let ctx = &self.ctx;
        let body = &input;
        let key_ref = &key;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    let key = key_ref.clone();
                    writable(&realm)?;
                    let settings = feature_settings_map(&settings_input(body)?, None)?;
                    let chain = ctx.ancestry(&tx, &realm).await?;
                    for ancestor in chain.iter().skip(1) {
                        let taken = tx
                            .find(
                                FEATURE_FLAGS,
                                &Filter::new()
                                    .eq("tenantId", ancestor.id.clone())
                                    .eq("uniqueKey", key.clone()),
                                &FindOptions::default(),
                            )
                            .await?;
                        if !taken.is_empty() {
                            return Err(IamError::with_status(
                                "CONFLICT",
                                if ancestor.parent_id.is_none() {
                                    "A platform flag already uses this key"
                                } else {
                                    "An enclosing tenant already defines a flag with this key"
                                },
                                409,
                            )
                            .into());
                        }
                    }
                    let existing = tx
                        .find(
                            FEATURE_FLAGS,
                            &Filter::new().eq("tenantId", realm.id.clone()),
                            &FindOptions::default(),
                        )
                        .await?;
                    if existing
                        .iter()
                        .any(|flag| flag.get("key").and_then(Value::as_str) == Some(key.as_str()))
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A flag with this key already exists",
                            409,
                        )
                        .into());
                    }
                    if existing.len() as f64 >= MAX_FEATURE_FLAGS_PER_TENANT {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!(
                                "A tenant can define at most {} feature flags",
                                number_to_string(MAX_FEATURE_FLAGS_PER_TENANT)
                            ),
                            409,
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let mut record = Record::new();
                    record.insert("id".into(), Value::String(id()));
                    record.insert("tenantId".into(), Value::String(realm.id.clone()));
                    record.insert("uniqueKey".into(), Value::String(key.clone()));
                    record.insert("key".into(), Value::String(key.clone()));
                    for (name, value) in settings {
                        record.insert(name, value);
                    }
                    record.insert("createdAt".into(), number(now));
                    record.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    record.insert("updatedAt".into(), number(now));
                    record.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let stored = tx.insert(FEATURE_FLAGS, &record).await?;
                    let flag: FeatureFlag = decode(stored)?;
                    self.audit(
                        &tx,
                        &principal,
                        "feature:create",
                        &realm.id,
                        &key,
                        settings_metadata(&flag),
                    )
                    .await?;
                    Ok(definition(&flag, root_of(&chain)))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:features:manage",
                &resource(&key),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `features/delete`: deletes a flag with every target and override set for it; code that still asks for the
    /// key gets `false`. Requires iam:features:manage; audited as `feature:delete`.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<features::DeleteInput>,
    ) -> IamResult<Reply<features::DeleteOutput>> {
        let key = feature_key(input.get("key"))?;
        let ctx = &self.ctx;
        let key_ref = &key;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    let key = key_ref.clone();
                    let (_, flag) = own_flag(&tx, &realm.id, &key).await?;
                    let entries = tx
                        .find(
                            FEATURE_TARGETS,
                            &Filter::new().eq("flagId", flag.id.clone()),
                            &FindOptions::default(),
                        )
                        .await?;
                    for entry in &entries {
                        let entry_id = entry.get("id").and_then(Value::as_str).unwrap_or("");
                        tx.delete(FEATURE_TARGETS, entry_id).await?;
                    }
                    tx.delete(FEATURE_FLAGS, &flag.id).await?;
                    let mut metadata = Map::new();
                    metadata.insert("key".into(), Value::String(key.clone()));
                    metadata.insert("removedTargets".into(), number(entries.len() as f64));
                    self.audit(&tx, &principal, "feature:delete", &realm.id, &key, metadata)
                        .await?;
                    Ok(json!({ "success": true, "removedTargets": entries.len() }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:features:manage",
                &resource(&key),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `features/evaluate`: `{ key: value }` for the flags that reach the tenant (internal flags of ancestors
    /// excluded), or for `keys` only (at most 100; unknown keys are `false`). Needs only a session of the tenant;
    /// root administrators may evaluate any tenant. Not audited.
    pub async fn evaluate(
        &self,
        credential: &CredentialInput,
        input: Body<features::EvaluateInput>,
    ) -> IamResult<Reply<features::EvaluateOutput>> {
        let ctx = self.ctx.clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let keys = match input.get("keys") {
            None => None,
            Some(keys) => Some(feature_keys(Some(keys))?),
        };
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let result = ctx
            .store
            .clone()
            .transaction(|tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                let realm = ctx.tenant(&tx, &tenant_id).await?;
                if principal.session.tenant_id != realm.id
                    && !ctx.root_principal(&tx, &principal).await?
                {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Feature flags are evaluated from a session of their tenant",
                        403,
                    ));
                }
                let chain = ctx.ancestry(&tx, &realm).await?;
                let state = feature_state(&tx, &chain, ctx.now()).await?;
                let mut flags = Map::new();
                for evaluation in evaluate_features(
                    &state,
                    &EvaluateFeaturesOptions {
                        keys,
                        include_internal: false,
                    },
                )? {
                    flags.insert(evaluation.key, Value::Bool(evaluation.value));
                }
                Ok(json!({ "tenantId": realm.id, "flags": flags }))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `features/list`: the flags that reach the tenant, sorted by key, each with its value for the tenant, the
    /// reason, and this tenant's own override and target. `definition` holds the settings of flags the tenant defines
    /// itself; internal flags of ancestors are left out (root administrators see everything). `shadowed` lists flags
    /// this tenant defines whose key an ancestor also defines. Requires iam:features:read.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<features::ListInput>,
    ) -> IamResult<Reply<features::ListOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    let root = ctx.root_principal(&tx, &principal).await?;
                    let chain = ctx.ancestry(&tx, &realm).await?;
                    let state = feature_state(&tx, &chain, ctx.now()).await?;
                    let mut sorted: Vec<&FeatureFlag> = state.flags.values().collect();
                    sorted.sort_by(|a, b| by_key(a, b));
                    let mut flags = Vec::new();
                    for flag in sorted {
                        let defined_here = flag.tenant_id == realm.id;
                        if flag.internal && !defined_here && !root {
                            continue;
                        }
                        flags.push(view(&tx, &state, flag, defined_here || root).await?);
                    }
                    let mut shadowed: Vec<&FeatureFlag> = state
                        .shadowed
                        .iter()
                        .filter(|flag| flag.tenant_id == realm.id)
                        .collect();
                    shadowed.sort_by(|a, b| by_key(a, b));
                    let shadowed: Vec<Value> = shadowed
                        .into_iter()
                        .map(|flag| definition(flag, root_of(&state.chain)))
                        .collect();
                    Ok(json!({ "tenantId": realm.id, "flags": flags, "shadowed": shadowed }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:features:read",
                "features",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `features/listTargets`: every target the defining tenant set for the flag and every override tenants below
    /// it chose, newest first, with the tenant's name and whether the entry currently counts. Requires
    /// iam:features:read.
    pub async fn list_targets(
        &self,
        credential: &CredentialInput,
        input: Body<features::ListTargetsInput>,
    ) -> IamResult<Reply<features::ListTargetsOutput>> {
        let key = feature_key(input.get("key"))?;
        let ctx = &self.ctx;
        let key_ref = &key;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      tenant: definer,
                      ..
                  }| {
                Box::pin(async move {
                    let (_, flag) = own_flag(&tx, &definer.id, key_ref).await?;
                    let now = ctx.now();
                    let mut views: Vec<(f64, String, Value)> = Vec::new();
                    for record in tx
                        .find(
                            FEATURE_TARGETS,
                            &Filter::new().eq("flagId", flag.id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        let entry: FeatureTarget = decode(record)?;
                        let Some(realm) = tx.get("tenants", &entry.tenant_id).await? else {
                            continue;
                        };
                        let realm: Tenant = decode(realm)?;
                        let lapsed = entry.expires_at.is_some_and(|expires_at| expires_at <= now);
                        let mut out = Map::new();
                        out.insert("id".into(), Value::String(entry.id.clone()));
                        out.insert("tenantId".into(), Value::String(realm.id.clone()));
                        out.insert("tenantName".into(), Value::String(realm.name.clone()));
                        out.insert("tenantStatus".into(), status_json(&realm.status));
                        out.insert("source".into(), Value::String(entry.source.clone()));
                        out.insert("value".into(), Value::Bool(entry.value));
                        out.insert("locked".into(), Value::Bool(entry.locked == Some(true)));
                        if let Some(expires_at) = entry.expires_at {
                            out.insert("expiresAt".into(), number(expires_at));
                        }
                        out.insert(
                            "active".into(),
                            Value::Bool(
                                !lapsed
                                    && (entry.source == "target"
                                        || (flag.tenant_overridable && !flag.internal)),
                            ),
                        );
                        if let Some(note) = &entry.note {
                            out.insert("note".into(), Value::String(note.clone()));
                        }
                        out.insert("setAt".into(), number(entry.set_at));
                        out.insert("setBy".into(), Value::String(entry.set_by.clone()));
                        views.push((entry.set_at, entry.id, Value::Object(out)));
                    }
                    // `b.setAt - a.setAt || (a.id < b.id ? -1 : 1)`.
                    views.sort_by(|a, b| {
                        let by_time = b.0 - a.0;
                        if by_time != 0.0 && !by_time.is_nan() {
                            return if by_time < 0.0 {
                                std::cmp::Ordering::Less
                            } else {
                                std::cmp::Ordering::Greater
                            };
                        }
                        if cmp_utf16(&a.1, &b.1) == std::cmp::Ordering::Less {
                            std::cmp::Ordering::Less
                        } else {
                            std::cmp::Ordering::Greater
                        }
                    });
                    Ok(Value::Array(
                        views.into_iter().map(|(_, _, view)| view).collect(),
                    ))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:features:read",
                &resource(&key),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `features/setOverride`: the tenant's own choice for a flag an ancestor defines with `tenantOverridable`.
    /// Refused with FEATURE_LOCKED when the flag does not allow overrides or a locked target covers the tenant;
    /// `value: null` withdraws the choice (always allowed). Requires iam:features:override on `iam/features/{key}`;
    /// audited as `feature:override`. Returns the new evaluation.
    pub async fn set_override(
        &self,
        credential: &CredentialInput,
        input: Body<features::SetOverrideInput>,
    ) -> IamResult<Reply<features::SetOverrideOutput>> {
        let key = feature_key(input.get("key"))?;
        let ctx = &self.ctx;
        let body = &input;
        let key_ref = &key;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    let key = key_ref.clone();
                    let chain = ctx.ancestry(&tx, &realm).await?;
                    let state = feature_state(&tx, &chain, ctx.now()).await?;
                    let flag = match state.flags.get(&key) {
                        Some(flag) if !(flag.internal && flag.tenant_id != realm.id) => {
                            flag.clone()
                        }
                        _ => {
                            return Err(IamError::with_status(
                                "NOT_FOUND",
                                "Feature flag not found",
                                404,
                            )
                            .into());
                        }
                    };
                    if flag.tenant_id == realm.id {
                        return Err(invalid_input(
                            "This tenant defines the flag; change its settings with features.update",
                        )
                        .into());
                    }
                    let existing = entry_at(&tx, &realm.id, &flag, "override").await?;
                    let value = body.get("value");
                    if value == Some(&Value::Null) {
                        if let Some(existing) = &existing {
                            tx.delete(FEATURE_TARGETS, &existing.id).await?;
                        }
                    } else {
                        writable(&realm)?;
                        let Some(Value::Bool(chosen)) = value else {
                            return Err(invalid_input("value must be a boolean or null").into());
                        };
                        if !flag.tenant_overridable {
                            return Err(IamError::with_status(
                                "FEATURE_LOCKED",
                                "This flag does not let tenants choose their own value",
                                409,
                            )
                            .into());
                        }
                        if evaluate_flag(&state, &flag)?.locked {
                            return Err(IamError::with_status(
                                "FEATURE_LOCKED",
                                "A locked target decides this flag for the tenant",
                                409,
                            )
                            .into());
                        }
                        let mut entry = Record::new();
                        entry.insert(
                            "id".into(),
                            Value::String(
                                existing
                                    .as_ref()
                                    .map(|existing| existing.id.clone())
                                    .unwrap_or_else(id),
                            ),
                        );
                        entry.insert("tenantId".into(), Value::String(realm.id.clone()));
                        entry.insert(
                            "uniqueKey".into(),
                            Value::String(format!("{}:override", flag.id)),
                        );
                        entry.insert("flagId".into(), Value::String(flag.id.clone()));
                        entry.insert("key".into(), Value::String(key.clone()));
                        entry.insert("definerId".into(), Value::String(flag.tenant_id.clone()));
                        entry.insert("source".into(), Value::String("override".into()));
                        entry.insert("value".into(), Value::Bool(*chosen));
                        entry.insert("setAt".into(), number(ctx.now()));
                        entry.insert("setBy".into(), Value::String(principal.identity.id.clone()));
                        if existing.is_some() {
                            tx.put(FEATURE_TARGETS, &entry).await?;
                        } else {
                            tx.insert(FEATURE_TARGETS, &entry).await?;
                        }
                    }
                    let mut metadata = Map::new();
                    metadata.insert("key".into(), Value::String(key.clone()));
                    metadata.insert("value".into(), value.cloned().unwrap_or(Value::Null));
                    metadata.insert("definedBy".into(), Value::String(flag.tenant_id.clone()));
                    self.audit(
                        &tx,
                        &principal,
                        "feature:override",
                        &realm.id,
                        &key,
                        metadata,
                    )
                    .await?;
                    let state = feature_state(&tx, &chain, ctx.now()).await?;
                    Ok(evaluate_flag(&state, &flag)?.to_json())
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:features:override",
                &resource(&key),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `features/setTarget`: pins the flag's value for a tenant below the defining tenant (`tenantId`), and for that
    /// tenant's descendants unless they have a closer target or override. `locked` also keeps tenants in that subtree
    /// from overriding; `expiresAt` makes the target lapse by itself; `value: null` removes the target. Requires
    /// iam:features:manage in the defining tenant; audited as `feature:target`.
    pub async fn set_target(
        &self,
        credential: &CredentialInput,
        input: Body<features::SetTargetInput>,
    ) -> IamResult<Reply<features::SetTargetOutput>> {
        let key = feature_key(input.get("key"))?;
        let ctx = &self.ctx;
        let body = &input;
        let key_ref = &key;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: definer,
                  }| {
                Box::pin(async move {
                    let key = key_ref.clone();
                    let (_, flag) = own_flag(&tx, &definer.id, &key).await?;
                    let target_id = text(body.get("targetTenantId"), "targetTenantId", 256)?;
                    let target = ctx.tenant(&tx, &target_id).await?;
                    let chain = ctx.ancestry(&tx, &target).await?;
                    if target.id == definer.id || !chain.iter().any(|realm| realm.id == definer.id)
                    {
                        return Err(invalid_input(
                            "targetTenantId must be a tenant below the one that defines the flag; use defaultValue for the tenant itself",
                        )
                        .into());
                    }
                    let existing = entry_at(&tx, &target.id, &flag, "target").await?;
                    if body.get("value") == Some(&Value::Null) {
                        if let Some(existing) = &existing {
                            tx.delete(FEATURE_TARGETS, &existing.id).await?;
                        }
                        let mut metadata = Map::new();
                        metadata.insert("key".into(), Value::String(key.clone()));
                        metadata.insert("targetTenantId".into(), Value::String(target.id.clone()));
                        metadata.insert("value".into(), Value::Null);
                        self.audit(
                            &tx,
                            &principal,
                            "feature:target",
                            &definer.id,
                            &key,
                            metadata,
                        )
                        .await?;
                        return Ok(Value::Null);
                    }
                    writable(&target)?;
                    let Some(Value::Bool(value)) = body.get("value") else {
                        return Err(invalid_input("value must be a boolean or null").into());
                    };
                    let locked = match body.get("locked") {
                        None => None,
                        Some(Value::Bool(locked)) => Some(*locked),
                        Some(_) => return Err(invalid_input("locked must be a boolean").into()),
                    };
                    let set_at = ctx.now();
                    let mut entry = Record::new();
                    entry.insert(
                        "id".into(),
                        Value::String(
                            existing
                                .as_ref()
                                .map(|existing| existing.id.clone())
                                .unwrap_or_else(id),
                        ),
                    );
                    entry.insert("tenantId".into(), Value::String(target.id.clone()));
                    entry.insert(
                        "uniqueKey".into(),
                        Value::String(format!("{}:target", flag.id)),
                    );
                    entry.insert("flagId".into(), Value::String(flag.id.clone()));
                    entry.insert("key".into(), Value::String(key.clone()));
                    entry.insert("definerId".into(), Value::String(definer.id.clone()));
                    entry.insert("source".into(), Value::String("target".into()));
                    entry.insert("value".into(), Value::Bool(*value));
                    entry.insert("setAt".into(), number(set_at));
                    entry.insert("setBy".into(), Value::String(principal.identity.id.clone()));
                    let is_locked = locked == Some(true);
                    if is_locked {
                        entry.insert("locked".into(), Value::Bool(true));
                    }
                    let mut expires_at = None;
                    if body.contains_key("expiresAt") {
                        let at = ctx.binding_expiry(body.get("expiresAt"))?;
                        entry.insert("expiresAt".into(), number(at));
                        expires_at = Some(at);
                    }
                    let mut note = None;
                    if body.contains_key("note") {
                        let given = text(body.get("note"), "note", 512)?;
                        let trimmed = better_iam_core::js::trim(&given).to_owned();
                        entry.insert("note".into(), Value::String(trimmed.clone()));
                        note = Some(trimmed);
                    }
                    if existing.is_some() {
                        tx.put(FEATURE_TARGETS, &entry).await?;
                    } else {
                        tx.insert(FEATURE_TARGETS, &entry).await?;
                    }
                    let mut metadata = Map::new();
                    metadata.insert("key".into(), Value::String(key.clone()));
                    metadata.insert("targetTenantId".into(), Value::String(target.id.clone()));
                    metadata.insert("value".into(), Value::Bool(*value));
                    metadata.insert("locked".into(), Value::Bool(is_locked));
                    if let Some(at) = expires_at {
                        metadata.insert("expiresAt".into(), number(at));
                    }
                    self.audit(
                        &tx,
                        &principal,
                        "feature:target",
                        &definer.id,
                        &key,
                        metadata,
                    )
                    .await?;
                    let mut out = Map::new();
                    out.insert("id".into(), entry.get("id").cloned().unwrap_or(Value::Null));
                    out.insert("tenantId".into(), Value::String(target.id.clone()));
                    out.insert("tenantName".into(), Value::String(target.name.clone()));
                    out.insert("tenantStatus".into(), status_json(&target.status));
                    out.insert("source".into(), Value::String("target".into()));
                    out.insert("value".into(), Value::Bool(*value));
                    out.insert("locked".into(), Value::Bool(is_locked));
                    if let Some(at) = expires_at {
                        out.insert("expiresAt".into(), number(at));
                    }
                    out.insert("active".into(), Value::Bool(true));
                    if let Some(note) = note {
                        out.insert("note".into(), Value::String(note));
                    }
                    out.insert("setAt".into(), number(set_at));
                    out.insert("setBy".into(), Value::String(principal.identity.id.clone()));
                    Ok(Value::Object(out))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:features:manage",
                &resource(&key),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `features/update`: changes a flag's settings; fields left out keep their value and `null` clears
    /// `description` or `rolloutPercentage`. Turning `killSwitch` on switches the flag off everywhere at once.
    /// Requires iam:features:manage; audited as `feature:update` with the settings before and after.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<features::UpdateInput>,
    ) -> IamResult<Reply<features::UpdateOutput>> {
        let key = feature_key(input.get("key"))?;
        let ctx = &self.ctx;
        let body = &input;
        let key_ref = &key;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    let key = key_ref.clone();
                    writable(&realm)?;
                    let (record, flag) = own_flag(&tx, &realm.id, &key).await?;
                    let settings = feature_settings_map(&settings_input(body)?, Some(&record))?;
                    // `{ ...rest, ...settings, updatedAt, updatedBy }` without the cleared members.
                    let mut next = record.clone();
                    next.shift_remove("description");
                    next.shift_remove("rolloutPercentage");
                    for (name, value) in settings {
                        next.insert(name, value);
                    }
                    next.insert("updatedAt".into(), number(ctx.now()));
                    next.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let stored = tx.put(FEATURE_FLAGS, &next).await?;
                    let next: FeatureFlag = decode(stored)?;
                    let mut metadata = Map::new();
                    metadata.insert("before".into(), Value::Object(settings_metadata(&flag)));
                    metadata.insert("after".into(), Value::Object(settings_metadata(&next)));
                    self.audit(&tx, &principal, "feature:update", &realm.id, &key, metadata)
                        .await?;
                    let chain = ctx.ancestry(&tx, &realm).await?;
                    Ok(definition(&next, root_of(&chain)))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:features:manage",
                &resource(&key),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// `strings(keys, 'keys').map(featureKey)`.
fn feature_keys(keys: Option<&Value>) -> IamResult<Vec<String>> {
    strings(keys, "keys")?
        .into_iter()
        .map(|key| feature_key(Some(&Value::String(key))))
        .collect()
}

/// Credential-free evaluation, shared by `iam.features` and tests.
pub struct FeatureEvaluator {
    ctx: Arc<ServerContext>,
}

/// `createFeatureEvaluator(ctx)`.
pub fn create_feature_evaluator(ctx: &Arc<ServerContext>) -> IamResult<FeatureEvaluator> {
    Ok(FeatureEvaluator { ctx: ctx.clone() })
}

impl FeatureEvaluator {
    /// `evaluate(tenantId, keys)`: every flag that reaches the tenant (internal ones included), or only `keys`.
    async fn evaluate_in(
        &self,
        tenant_id: Option<&Value>,
        keys: Option<Vec<String>>,
    ) -> IamResult<Vec<FeatureEvaluation>> {
        let ctx = self.ctx.clone();
        let tenant_id = tenant_id.cloned();
        ctx.store
            .clone()
            .transaction(|tx| async move {
                let realm = ctx
                    .tenant(&tx, &text(tenant_id.as_ref(), "tenantId", 256)?)
                    .await?;
                let chain = ctx.ancestry(&tx, &realm).await?;
                let state = feature_state(&tx, &chain, ctx.now()).await?;
                evaluate_features(
                    &state,
                    &EvaluateFeaturesOptions {
                        keys,
                        include_internal: true,
                    },
                )
            })
            .await
    }

    async fn evaluate_value(
        &self,
        tenant_id: Option<&Value>,
        options: Option<&Value>,
    ) -> IamResult<Vec<FeatureEvaluation>> {
        let keys = match crate::js::member(options, "keys") {
            None => None,
            Some(keys) => Some(feature_keys(Some(keys))?),
        };
        self.evaluate_in(tenant_id, keys).await
    }

    async fn values_value(&self, tenant_id: Option<&Value>) -> IamResult<IndexMap<String, bool>> {
        Ok(self
            .evaluate_in(tenant_id, None)
            .await?
            .into_iter()
            .map(|evaluation| (evaluation.key, evaluation.value))
            .collect())
    }

    async fn is_enabled_value(
        &self,
        tenant_id: Option<&Value>,
        key: Option<&Value>,
    ) -> IamResult<bool> {
        let key = feature_key(key)?;
        let evaluations = self.evaluate_in(tenant_id, Some(vec![key])).await?;
        evaluations
            .first()
            .map(|evaluation| evaluation.value)
            .ok_or_else(crate::js::internal_error)
    }

    /// Every flag that reaches the tenant (internal ones included), or only `keys`, with values and reasons.
    pub async fn evaluate(
        &self,
        tenant_id: &str,
        options: Option<&Value>,
    ) -> IamResult<Vec<crate::features::FeatureEvaluation>> {
        self.evaluate_value(Some(&Value::String(tenant_id.to_owned())), options)
            .await
    }
    /// `{ key: value }` for every flag that reaches the tenant, internal ones included.
    pub async fn values(&self, tenant_id: &str) -> IamResult<IndexMap<String, bool>> {
        self.values_value(Some(&Value::String(tenant_id.to_owned())))
            .await
    }
    /// Whether one flag is on for the tenant; `false` when no flag with the key reaches it.
    pub async fn is_enabled(&self, tenant_id: &str, key: &str) -> IamResult<bool> {
        self.is_enabled_value(
            Some(&Value::String(tenant_id.to_owned())),
            Some(&Value::String(key.to_owned())),
        )
        .await
    }
    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        let arg = |index: usize| args.get(index);
        match method {
            "evaluate" => Some(
                self.evaluate_value(arg(0), arg(1))
                    .await
                    .map(|evaluations| {
                        Value::Array(evaluations.iter().map(FeatureEvaluation::to_json).collect())
                    }),
            ),
            "values" => Some(self.values_value(arg(0)).await.map(|values| {
                Value::Object(
                    values
                        .into_iter()
                        .map(|(key, value)| (key, Value::Bool(value)))
                        .collect(),
                )
            })),
            "isEnabled" => Some(self.is_enabled_value(arg(0), arg(1)).await.map(Value::Bool)),
            _ => None,
        }
    }
}
