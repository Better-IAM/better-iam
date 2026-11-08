//! Port of `packages/server/src/api/resources.ts`: managed resources, registered with IAM so authorization can
//! resolve their ownership, attributes, and parent without an application callback.

use std::sync::Arc;

use better_iam_core::{
    AuditOutcome, CredentialInput, Decision, Filter, FindOptions, IamError, IamResult, IamStoreExt,
    Record, js as core_js,
};
use better_iam_types::api::resources;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply, string_member};
use crate::catalog::{CatalogResourceType, attribute_values, managed_resource, resolved_managed};
use crate::clearances::keep_inherited_label;
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, decide_on};
use crate::decisions::impersonating_actor;
use crate::models::ResourceRecord;
use crate::options::{AuthorizationRequest, ResolvedResource, ResourceTarget};
use crate::port::decode;
use crate::utils::{date_now, id};
use crate::validation::{integer, object, text};

/// `resourceKey(input)`: `{type}/{id}`, both validated.
fn resource_key(input: &Map<String, Value>) -> IamResult<String> {
    let kind = text(input.get("type"), "resource type", 64)?;
    let id = text(input.get("id"), "resource id", 128)?;
    Ok(format!("{kind}/{id}"))
}

/// `countResources(tx, tenantId)`.
async fn count_resources(tx: &Store, tenant_id: &str) -> IamResult<f64> {
    Ok(tx
        .find(
            "resources",
            &Filter::new().eq("tenantId", tenant_id),
            &FindOptions::default(),
        )
        .await?
        .len() as f64)
}

/// `value ?? fallback` for a numeric option: an absent or null member takes the fallback.
fn or_default(value: Option<&Value>, fallback: f64) -> Value {
    match value {
        None | Some(Value::Null) => crate::js::number(fallback),
        Some(value) => value.clone(),
    }
}

/// The `resources` API group (`createResourcesApi(ctx)`): one method per route `resources/{method}`.
pub struct ResourcesApi {
    ctx: Arc<ServerContext>,
}

/// `createResourcesApi(ctx)`.
pub fn create_resources_api(ctx: &Arc<ServerContext>) -> IamResult<ResourcesApi> {
    Ok(ResourcesApi { ctx: ctx.clone() })
}

/// `applyResourceLinks(tx, record, definition, input)`: the parent a typed resource requires and its owner.
async fn apply_resource_links(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    record: &mut Record,
    tenant_id: &str,
    definition: &CatalogResourceType,
    input: &Map<String, Value>,
) -> IamResult<()> {
    if let Some(parent_type) = &definition.parent {
        let Some(parent_id) = input.get("parentId") else {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!(
                    "Resources of type {} require a {parent_type} parent",
                    definition.name
                ),
            ));
        };
        let parent_id = text(Some(parent_id), "parentId", 128)?;
        let Some(parent) =
            managed_resource(tx.as_ref(), tenant_id, parent_type, &parent_id).await?
        else {
            return Err(IamError::with_status(
                "NOT_FOUND",
                "Parent resource is not registered",
                404,
            ));
        };
        record.insert("parentType".into(), Value::String(parent_type.clone()));
        record.insert("parentId".into(), Value::String(parent.resource_id));
    } else if input.get("parentId").is_some() {
        return Err(IamError::new(
            "INVALID_INPUT",
            "This resource type has no parent",
        ));
    }
    if let Some(owner_id) = input.get("ownerId") {
        // `activeIdentity` reads the identity through `scoped`, which validates the record ID.
        let owner = text(Some(owner_id), "id", 256)?;
        ctx.active_identity(tx, &owner, tenant_id).await?;
        record.insert("ownerId".into(), owner_id.clone());
    }
    Ok(())
}

/// `registerResource(tx, tenantId, input)`: one registration (`input` is `ResourceInput`).
async fn register_resource(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    input: &Map<String, Value>,
) -> IamResult<Record> {
    let definition = ctx
        .catalog
        .managed_definition(tx.as_ref(), tenant_id, input.get("type"))
        .await?;
    let resource_id = string_member(input, "id");
    // Resource patterns treat `*` and `?` as wildcards: an ID holding them would read as a pattern in
    // `iam/{type}/{id}`.
    if resource_id.contains('*') || resource_id.contains('?') {
        return Err(IamError::new(
            "INVALID_INPUT",
            "A resource ID cannot contain * or ?",
        ));
    }
    if managed_resource(tx.as_ref(), tenant_id, &definition.name, &resource_id)
        .await?
        .is_some()
    {
        return Err(IamError::with_status(
            "CONFLICT",
            "Resource is already registered",
            409,
        ));
    }
    let at = date_now();
    let mut item = Record::new();
    item.insert("id".into(), Value::String(id()));
    item.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    item.insert(
        "uniqueKey".into(),
        Value::String(format!("{}/{resource_id}", definition.name)),
    );
    item.insert("type".into(), Value::String(definition.name.clone()));
    item.insert("resourceId".into(), Value::String(resource_id));
    item.insert(
        "attributes".into(),
        Value::Object(attribute_values(
            &definition.attributes,
            input.get("attributes"),
        )?),
    );
    item.insert("createdAt".into(), crate::js::number(at));
    item.insert("updatedAt".into(), crate::js::number(at));
    apply_resource_links(ctx, tx, &mut item, tenant_id, &definition, input).await?;
    tx.insert("resources", &item).await
}

impl ResourcesApi {
    /// `resources/register`: registers a managed resource so authorization can resolve its ownership, attributes,
    /// and parent without an application callback.
    pub async fn register(
        &self,
        credential: &CredentialInput,
        input: Body<resources::RegisterInput>,
    ) -> IamResult<Reply<resources::RegisterOutput>> {
        let ctx = &self.ctx;
        let key = resource_key(&input)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                ctx.enforce_limit(
                    &tenant,
                    "resources",
                    || count_resources(&tx, &tenant.id),
                    None,
                )
                .await?;
                let tenant_id = string_member(body, "tenantId");
                Ok(Value::Object(
                    register_resource(ctx, &tx, &tenant_id, body).await?,
                ))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:resources:create",
                &key,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `resources/registerMany`: registers up to 100 resources atomically. Each item is authorized as
    /// `iam:resources:create` on `iam/{type}/{id}`, so one denied item rejects the batch.
    pub async fn register_many(
        &self,
        credential: &CredentialInput,
        input: Body<resources::RegisterManyInput>,
    ) -> IamResult<Reply<resources::RegisterManyOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let list = match input.get("resources") {
            Some(Value::Array(list)) if !list.is_empty() && list.len() <= 100 => list,
            _ => return Err(IamError::new("INVALID_INPUT", "Provide 1-100 resources")),
        };
        let mut items: Vec<Map<String, Value>> = Vec::with_capacity(list.len());
        for item in list {
            let value = object(Some(item))?;
            let mut resource = Map::new();
            resource.insert(
                "type".into(),
                Value::String(text(value.get("type"), "resource type", 64)?),
            );
            resource.insert(
                "id".into(),
                Value::String(text(value.get("id"), "resource id", 128)?),
            );
            for key in ["attributes", "parentId", "ownerId"] {
                if let Some(member) = value.get(key) {
                    resource.insert(key.into(), member.clone());
                }
            }
            items.push(resource);
        }
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let outcome: Result<Vec<Value>, String> = ctx
            .store
            .transaction(|tx| {
                let (authenticated, tenant_id, items) = (&authenticated, &tenant_id, &items);
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    let tenant = ctx.tenant(&tx, tenant_id).await?;
                    ctx.enforce_limit(
                        &tenant,
                        "resources",
                        || count_resources(&tx, tenant_id),
                        Some(items.len() as f64),
                    )
                    .await?;
                    // Authorize every item before writing anything, so a denial commits only its audit record.
                    let mut decisions: Vec<Decision> = Vec::new();
                    for item in items {
                        let resource_id = format!(
                            "{}/{}",
                            string_member(item, "type"),
                            string_member(item, "id")
                        );
                        let decision = ctx
                            .decisions()?
                            .decide(
                                &tx,
                                &principal,
                                &AuthorizationRequest {
                                    credential: CredentialInput::default(),
                                    tenant_id: tenant_id.clone(),
                                    action: "iam:resources:create".into(),
                                    resource: ResourceTarget {
                                        kind: "iam".into(),
                                        id: resource_id.clone(),
                                    },
                                },
                                true,
                            )
                            .await?;
                        if !decision.allowed {
                            ctx.events()?
                                .audit(
                                    &tx,
                                    &principal,
                                    "iam:resources:create",
                                    tenant_id,
                                    &resource_id,
                                    AuditOutcome::Deny,
                                    false,
                                    None,
                                )
                                .await?;
                            return Ok(Err(resource_id));
                        }
                        decisions.push(decision);
                    }
                    let mut registered = Vec::new();
                    for (index, item) in items.iter().enumerate() {
                        registered.push(Value::Object(
                            register_resource(ctx, &tx, tenant_id, item).await?,
                        ));
                        ctx.events()?
                            .audit(
                                &tx,
                                &principal,
                                "iam:resources:create",
                                tenant_id,
                                &format!(
                                    "{}/{}",
                                    string_member(item, "type"),
                                    string_member(item, "id")
                                ),
                                AuditOutcome::Allow,
                                decisions[index].reason == "ROOT_OVERRIDE",
                                None,
                            )
                            .await?;
                    }
                    Ok(Ok(registered))
                }
            })
            .await?;
        match outcome {
            Err(denied) => Err(IamError::with_status(
                "ACCESS_DENIED",
                format!("Access denied for {denied}"),
                403,
            )),
            Ok(registered) => Ok(Reply::json(json!({ "resources": registered }))),
        }
    }

    /// `resources/update`: new attributes (validated against the type's schema) and owner (`null` clears it).
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<resources::UpdateInput>,
    ) -> IamResult<Reply<resources::UpdateOutput>> {
        let ctx = &self.ctx;
        let key = resource_key(&input)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let definition = ctx
                    .catalog
                    .managed_definition(tx.as_ref(), &tenant_id, body.get("type"))
                    .await?;
                let Some(record) = find_managed(
                    &tx,
                    &tenant_id,
                    &definition.name,
                    &string_member(body, "id"),
                )
                .await?
                else {
                    return Err(IamError::with_status(
                        "NOT_FOUND",
                        "Resource is not registered",
                        404,
                    )
                    .into());
                };
                let mut next = record;
                next.insert("updatedAt".into(), crate::js::number(date_now()));
                if let Some(attributes) = body.get("attributes") {
                    next.insert(
                        "attributes".into(),
                        Value::Object(attribute_values(&definition.attributes, Some(attributes))?),
                    );
                }
                match body.get("ownerId") {
                    Some(Value::Null) => {
                        next.shift_remove("ownerId");
                    }
                    Some(owner_id) => {
                        ctx.scoped(&tx, "identities", Some(owner_id), &tenant_id)
                            .await?;
                        next.insert("ownerId".into(), owner_id.clone());
                    }
                    None => {}
                }
                Ok(Value::Object(tx.put("resources", &next).await?))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:resources:update",
                &key,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `resources/get`: one registered resource.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<resources::GetInput>,
    ) -> IamResult<Reply<resources::GetOutput>> {
        let ctx = &self.ctx;
        let key = resource_key(&input)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let Some(record) = find_managed(
                    &tx,
                    &string_member(body, "tenantId"),
                    &string_member(body, "type"),
                    &string_member(body, "id"),
                )
                .await?
                else {
                    return Err(IamError::with_status(
                        "NOT_FOUND",
                        "Resource is not registered",
                        404,
                    )
                    .into());
                };
                Ok(Value::Object(record))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:resources:read",
                &key,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `resources/list`: the resources the caller may read, ordered by type/id, paged.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<resources::ListInput>,
    ) -> IamResult<Reply<resources::ListOutput>> {
        let ctx = &self.ctx;
        let resource = match input.get("type") {
            Some(kind) => format!("{}/*", text(Some(kind), "resource type", 64)?),
            None => "*".to_owned(),
        };
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let mut filter = Filter::new().eq("tenantId", tenant.id.clone());
                    if let Some(kind) = body.get("type") {
                        filter.set("type", Some(kind.clone()));
                    }
                    if let Some(parent_id) = body.get("parentId") {
                        let parent_id = text(Some(parent_id), "parentId", 128)?;
                        filter.set("parentId", Some(Value::String(parent_id)));
                    }
                    if let Some(owner_id) = body.get("ownerId") {
                        let owner_id = text(Some(owner_id), "ownerId", 256)?;
                        filter.set("ownerId", Some(Value::String(owner_id)));
                    }
                    let limit = integer(
                        Some(&or_default(body.get("limit"), 100.0)),
                        "limit",
                        1.0,
                        1000.0,
                    )?;
                    let offset = integer(
                        Some(&or_default(body.get("offset"), 0.0)),
                        "offset",
                        0.0,
                        1_000_000.0,
                    )?;
                    // Listing is reading each record: one a policy keeps from the caller (a Deny on
                    // iam/document/payroll, an owner condition) is left out, as resources.get would refuse it. A
                    // "view as" session sees what both may.
                    let mut readers = vec![principal.clone()];
                    if let Some(actor) = impersonating_actor(&tx, &principal).await? {
                        readers.push(actor);
                    }
                    let decisions = ctx.decisions()?;
                    let mut prepared = Vec::new();
                    for who in &readers {
                        prepared.push(
                            decisions
                                .prepare_decision(&tx, who, &tenant, "iam:resources:read")
                                .await?,
                        );
                    }
                    let mut readable: Vec<(String, Record)> = Vec::new();
                    for raw in tx
                        .find("resources", &filter, &FindOptions::default())
                        .await?
                    {
                        let record: ResourceRecord = decode(raw.clone())?;
                        let resource = ResolvedResource {
                            tenant_id: record.tenant_id.clone(),
                            kind: "iam".into(),
                            id: format!("{}/{}", record.kind, record.resource_id),
                            attributes: resolved_managed(&record).attributes,
                            classification: None,
                        };
                        let mut allowed = true;
                        for ready in &prepared {
                            if !decide_on(ready, &resource, None)?.allowed {
                                allowed = false;
                                break;
                            }
                        }
                        if allowed {
                            readable.push((record.unique_key.clone().unwrap_or_default(), raw));
                        }
                    }
                    // Order by type/id rather than by opaque record ID so pages are meaningful to callers.
                    readable.sort_by(|(a, _), (b, _)| core_js::cmp_utf16(a, b));
                    Ok(Value::Array(
                        readable
                            .into_iter()
                            .skip(offset as usize)
                            .take(limit as usize)
                            .map(|(_, record)| Value::Object(record))
                            .collect(),
                    ))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:resources:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `resources/delete`: refused while child resources exist; removes the resource's relationship tuples.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<resources::DeleteInput>,
    ) -> IamResult<Reply<resources::DeleteOutput>> {
        let ctx = &self.ctx;
        let key = resource_key(&input)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let Some(raw) = find_managed(
                    &tx,
                    &string_member(body, "tenantId"),
                    &string_member(body, "type"),
                    &string_member(body, "id"),
                )
                .await?
                else {
                    return Err(IamError::with_status(
                        "NOT_FOUND",
                        "Resource is not registered",
                        404,
                    )
                    .into());
                };
                let record: ResourceRecord = decode(raw)?;
                let tenant_id = string_member(body, "tenantId");
                let children = tx
                    .find(
                        "resources",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("parentType", record.kind.clone())
                            .eq("parentId", record.resource_id.clone()),
                        &FindOptions::default(),
                    )
                    .await?;
                if !children.is_empty() {
                    return Err(IamError::with_status(
                        "RESOURCE_IN_USE",
                        "Delete child resources first",
                        409,
                    )
                    .into());
                }
                for tuple in tx
                    .find(
                        "relationships",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("type", record.kind.clone())
                            .eq("resourceId", record.resource_id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    tx.delete("relationships", &string_member(&tuple, "id"))
                        .await?;
                }
                // Security clearances: what it inherits stays its label, so registering it again elsewhere cannot
                // declassify. (`keepInheritedLabel` returns at once when clearances are off.)
                if ctx.options.clearances.is_some() {
                    keep_inherited_label(ctx, &tx, &principal, &record).await?;
                }
                tx.delete("resources", &record.id).await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:resources:delete",
                &key,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// `managedResource(tx, tenantId, type, resourceId)` as the stored record (members kept as stored), checked
/// against its type.
async fn find_managed(
    tx: &Store,
    tenant_id: &str,
    kind: &str,
    resource_id: &str,
) -> IamResult<Option<Record>> {
    let found = tx
        .find(
            "resources",
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("uniqueKey", format!("{kind}/{resource_id}")),
            &FindOptions::default(),
        )
        .await?;
    match found.into_iter().next() {
        Some(record) => {
            decode::<ResourceRecord>(record.clone())?;
            Ok(Some(record))
        }
        None => Ok(None),
    }
}
