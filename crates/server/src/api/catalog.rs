//! Port of `packages/server/src/api/catalog.ts`: the `actions` and `resourceTypes` API groups (tenant-defined actions
//! and resource types), and the resource type helpers configuration sync shares.

use std::sync::Arc;

use better_iam_core::{CredentialInput, Filter, FindOptions, IamError, IamResult};
use better_iam_types::api::{actions, resource_types};
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply, string_member};
use crate::catalog::{
    CatalogResourceType, RESERVED_RESOURCE_TYPES, attribute_schema, attribute_values,
    is_resource_type_name, relation_names,
};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::models::{ActionDefinition, Relationship, ResourceRecord, ResourceTypeRecord};
use crate::port::decode;
use crate::utils::{date_now, id};
use crate::validation::{strings, text};

/// `ActionSummary`: one action of the catalog listing.
fn action_summary(
    name: &str,
    source: &str,
    resource_type: Option<&str>,
    description: Option<&str>,
) -> Value {
    let mut out = Map::new();
    out.insert("name".into(), Value::String(name.to_owned()));
    out.insert("source".into(), Value::String(source.to_owned()));
    if let Some(resource_type) = resource_type {
        out.insert(
            "resourceType".into(),
            Value::String(resource_type.to_owned()),
        );
    }
    if let Some(description) = description {
        out.insert("description".into(), Value::String(description.to_owned()));
    }
    Value::Object(out)
}

fn definition_json(definition: &CatalogResourceType) -> IamResult<Value> {
    serde_json::to_value(definition).map_err(|_| crate::js::internal_error())
}

/// The `actions` API group (`createActionsApi(ctx)`).
pub struct ActionsApi {
    ctx: Arc<ServerContext>,
}

/// `createActionsApi(ctx)`.
pub fn create_actions_api(ctx: &Arc<ServerContext>) -> IamResult<ActionsApi> {
    Ok(ActionsApi { ctx: ctx.clone() })
}

impl ActionsApi {
    /// `actions/list`: the platform's actions, then the tenant's own.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<actions::ListInput>,
    ) -> IamResult<Reply<actions::ListOutput>> {
        let ctx = &self.ctx;
        let tenant = string_member(&input, "tenantId");
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let catalog = &ctx.catalog;
                let mut result: Vec<Value> = catalog
                    .actions
                    .iter()
                    .map(|name| {
                        action_summary(
                            name,
                            "platform",
                            catalog.action_types.get(name).map(String::as_str),
                            None,
                        )
                    })
                    .collect();
                for record in tx
                    .find(
                        "actions",
                        &Filter::new().eq("tenantId", tenant.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    let definition: ActionDefinition = decode(record)?;
                    result.push(action_summary(
                        &definition.name,
                        "tenant",
                        definition.resource_type.as_deref(),
                        definition.description.as_deref(),
                    ));
                }
                Ok(Value::Array(result))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:actions:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `actions/register`: tenant-defined actions are namespaced under a tenant-defined resource type,
    /// `{type}:{verb}`.
    pub async fn register(
        &self,
        credential: &CredentialInput,
        input: Body<actions::RegisterInput>,
    ) -> IamResult<Reply<actions::RegisterOutput>> {
        let ctx = &self.ctx;
        let tenant = string_member(&input, "tenantId");
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let definition = ctx
                    .catalog
                    .register_tenant_action(
                        tx.as_ref(),
                        &tenant,
                        body.get("name"),
                        body.get("description"),
                    )
                    .await?;
                Ok(Value::Object(crate::port::encode(&definition)))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:actions:create",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `actions/unregister`: refused while any policy or role names the action.
    pub async fn unregister(
        &self,
        credential: &CredentialInput,
        input: Body<actions::UnregisterInput>,
    ) -> IamResult<Reply<actions::UnregisterOutput>> {
        let ctx = &self.ctx;
        let tenant = string_member(&input, "tenantId");
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let name = text(body.get("name"), "action", 128)?;
                let definition = tx
                    .find(
                        "actions",
                        &Filter::new()
                            .eq("tenantId", tenant.clone())
                            .eq("uniqueKey", name),
                        &FindOptions::default(),
                    )
                    .await?
                    .into_iter()
                    .next();
                let Some(definition) = definition else {
                    return Err(IamError::with_status("NOT_FOUND", "Action not found", 404).into());
                };
                let definition: ActionDefinition = decode(definition)?;
                ctx.catalog
                    .assert_action_unused(tx.as_ref(), &tenant, &definition.name)
                    .await?;
                tx.delete("actions", &definition.id).await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:actions:delete",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// `registerResourceType(ctx, tx, input)`: registers a tenant-defined resource type; shared by
/// `resourceTypes.register` and configuration sync. `input` is `ResourceTypeInput` as JSON.
pub async fn register_resource_type(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    input: &Map<String, Value>,
) -> IamResult<CatalogResourceType> {
    let catalog = &ctx.catalog;
    if !ctx.config.tenant_defined {
        return Err(IamError::with_status(
            "CATALOG_LOCKED",
            "Tenant-defined resource types are disabled",
            403,
        ));
    }
    let tenant_id = string_member(input, "tenantId");
    let name = text(input.get("name"), "name", 64)?;
    if !is_resource_type_name(&name)
        || RESERVED_RESOURCE_TYPES.contains(&name.as_str())
        || catalog.resource_types.contains_key(&name)
        || catalog.namespaces.contains(&name)
    {
        return Err(IamError::new(
            "INVALID_RESOURCE_TYPE",
            "Resource type name is reserved or already defined by the platform",
        ));
    }
    if catalog
        .tenant_resource_type(tx.as_ref(), &tenant_id, &name)
        .await?
        .is_some()
    {
        return Err(IamError::with_status(
            "CONFLICT",
            "Resource type already exists",
            409,
        ));
    }
    let attributes = attribute_schema(input.get("attributes"), catalog.reserved_attributes)?;
    let mut record = Map::new();
    record.insert("id".into(), Value::String(id()));
    record.insert("tenantId".into(), Value::String(tenant_id.clone()));
    record.insert("uniqueKey".into(), Value::String(name.clone()));
    record.insert("name".into(), Value::String(name.clone()));
    record.insert(
        "attributes".into(),
        serde_json::to_value(&attributes).map_err(|_| crate::js::internal_error())?,
    );
    record.insert("createdAt".into(), crate::js::number(date_now()));
    let mut description = None;
    if let Some(value) = input.get("description") {
        let value = text(Some(value), "description", 512)?;
        record.insert("description".into(), Value::String(value.clone()));
        description = Some(value);
    }
    let mut relations = None;
    if let Some(value) = input.get("relations") {
        let names = relation_names(Some(value))?;
        record.insert("relations".into(), json!(names));
        relations = Some(names);
    }
    let mut parent_name = None;
    if let Some(value) = input.get("parent") {
        let parent = catalog
            .resource_type_definition(tx.as_ref(), &tenant_id, &text(Some(value), "parent", 64)?)
            .await?;
        let Some(parent) = parent.filter(|parent| parent.name != name && parent.managed) else {
            return Err(IamError::new(
                "INVALID_RESOURCE_TYPE",
                "Parent must be an existing managed resource type",
            ));
        };
        record.insert("parent".into(), Value::String(parent.name.clone()));
        parent_name = Some(parent.name);
    }
    tx.insert("resourceTypes", &record).await?;
    let mut registered = Vec::new();
    let verbs = strings(
        Some(
            input
                .get("actions")
                .filter(|value| !value.is_null())
                .unwrap_or(&json!([])),
        ),
        "actions",
    )?;
    for verb in verbs {
        let action = Value::String(format!("{name}:{verb}"));
        registered.push(
            catalog
                .register_tenant_action(tx.as_ref(), &tenant_id, Some(&action), None)
                .await?
                .name,
        );
    }
    Ok(CatalogResourceType {
        name,
        source: "tenant".into(),
        description,
        actions: registered,
        attributes,
        parent: parent_name,
        managed: true,
        relations: relations.unwrap_or_default(),
    })
}

/// `updateResourceType(ctx, tx, input, replaceActions = false)`: updates a tenant-defined resource type. `actions` adds
/// verbs; with `replace_actions` (configuration sync) verbs no longer listed are removed too, provided no policy or
/// role still names them.
pub async fn update_resource_type(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    input: &Map<String, Value>,
    replace_actions: bool,
) -> IamResult<CatalogResourceType> {
    let catalog = &ctx.catalog;
    let tenant_id = string_member(input, "tenantId");
    let name = text(input.get("name"), "name", 64)?;
    let Some(record) = catalog
        .tenant_resource_type(tx.as_ref(), &tenant_id, &name)
        .await?
    else {
        return Err(IamError::with_status(
            "NOT_FOUND",
            "Resource type not found",
            404,
        ));
    };
    let mut next = match tx.get("resourceTypes", &record.id).await? {
        Some(raw) => raw,
        None => crate::port::encode(&record),
    };
    if let Some(value) = input.get("description") {
        next.insert(
            "description".into(),
            Value::String(text(Some(value), "description", 512)?),
        );
    }
    if let Some(value) = input.get("relations") {
        let names = relation_names(Some(value))?;
        next.insert("relations".into(), json!(names));
        // A relation still held by someone cannot be removed from the type.
        let held: Vec<Relationship> = tx
            .find(
                "relationships",
                &Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("type", record.name.clone()),
                &FindOptions::default(),
            )
            .await?
            .into_iter()
            .map(decode)
            .collect::<IamResult<_>>()?;
        if held.iter().any(|item| !names.contains(&item.relation)) {
            return Err(IamError::with_status(
                "RESOURCE_IN_USE",
                "Remove relationships before dropping a relation",
                409,
            ));
        }
    }
    if let Some(value) = input.get("attributes") {
        let attributes = attribute_schema(Some(value), catalog.reserved_attributes)?;
        next.insert(
            "attributes".into(),
            serde_json::to_value(&attributes).map_err(|_| crate::js::internal_error())?,
        );
        // Registered resources must keep satisfying the schema, otherwise conditions would silently stop matching.
        for resource in tx
            .find(
                "resources",
                &Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("type", record.name.clone()),
                &FindOptions::default(),
            )
            .await?
        {
            let resource: ResourceRecord = decode(resource)?;
            attribute_values(&attributes, Some(&Value::Object(resource.attributes)))?;
        }
    }
    tx.put("resourceTypes", &next).await?;
    let verbs = strings(
        Some(
            input
                .get("actions")
                .filter(|value| !value.is_null())
                .unwrap_or(&json!([])),
        ),
        "actions",
    )?;
    for verb in &verbs {
        let action = format!("{}:{verb}", record.name);
        if !catalog
            .known_action(tx.as_ref(), &tenant_id, &action)
            .await?
        {
            catalog
                .register_tenant_action(tx.as_ref(), &tenant_id, Some(&Value::String(action)), None)
                .await?;
        }
    }
    if replace_actions && input.contains_key("actions") {
        for raw in tx
            .find(
                "actions",
                &Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("resourceType", record.name.clone()),
                &FindOptions::default(),
            )
            .await?
        {
            let action: ActionDefinition = decode(raw)?;
            let verb = action.name.get(record.name.len() + 1..).unwrap_or("");
            if !verbs.iter().any(|known| known == verb) {
                catalog
                    .assert_action_unused(tx.as_ref(), &tenant_id, &action.name)
                    .await?;
                tx.delete("actions", &action.id).await?;
            }
        }
    }
    catalog
        .resource_type_definition(tx.as_ref(), &tenant_id, &record.name)
        .await?
        .ok_or_else(crate::js::internal_error)
}

/// `deleteResourceType(ctx, tx, record)`: deletes a tenant-defined resource type once nothing registered, related,
/// nested, or granted depends on it.
pub async fn delete_resource_type(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    record: &ResourceTypeRecord,
) -> IamResult<()> {
    let catalog = &ctx.catalog;
    let in_tenant = || Filter::new().eq("tenantId", record.tenant_id.clone());
    let all = FindOptions::default();
    if !tx
        .find(
            "resources",
            &in_tenant().eq("type", record.name.clone()),
            &all,
        )
        .await?
        .is_empty()
    {
        return Err(IamError::with_status(
            "RESOURCE_IN_USE",
            "Delete registered resources first",
            409,
        ));
    }
    if !tx
        .find(
            "relationships",
            &in_tenant().eq("type", record.name.clone()),
            &all,
        )
        .await?
        .is_empty()
    {
        return Err(IamError::with_status(
            "RESOURCE_IN_USE",
            "Delete relationships first",
            409,
        ));
    }
    if !tx
        .find(
            "resourceTypes",
            &in_tenant().eq("parent", record.name.clone()),
            &all,
        )
        .await?
        .is_empty()
    {
        return Err(IamError::with_status(
            "RESOURCE_IN_USE",
            "Other resource types use this type as their parent",
            409,
        ));
    }
    for raw in tx
        .find(
            "actions",
            &in_tenant().eq("resourceType", record.name.clone()),
            &all,
        )
        .await?
    {
        let action: ActionDefinition = decode(raw)?;
        catalog
            .assert_action_unused(tx.as_ref(), &record.tenant_id, &action.name)
            .await?;
        tx.delete("actions", &action.id).await?;
    }
    tx.delete("resourceTypes", &record.id).await?;
    Ok(())
}

/// The `resourceTypes` API group (`createResourceTypesApi(ctx)`).
pub struct ResourceTypesApi {
    ctx: Arc<ServerContext>,
}

/// `createResourceTypesApi(ctx)`.
pub fn create_resource_types_api(ctx: &Arc<ServerContext>) -> IamResult<ResourceTypesApi> {
    Ok(ResourceTypesApi { ctx: ctx.clone() })
}

impl ResourceTypesApi {
    async fn run(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        action: &str,
        mutation: Mutation<'_>,
    ) -> IamResult<Value> {
        let resource_id = string_member(input, "tenantId");
        self.ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                action,
                &resource_id,
                mutation,
                false,
            )
            .await
    }

    /// `resourceTypes/delete`.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<resource_types::DeleteInput>,
    ) -> IamResult<Reply<resource_types::DeleteOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let name = text(body.get("name"), "name", 64)?;
                let Some(record) = ctx
                    .catalog
                    .tenant_resource_type(tx.as_ref(), &tenant_id, &name)
                    .await?
                else {
                    return Err(
                        IamError::with_status("NOT_FOUND", "Resource type not found", 404).into(),
                    );
                };
                delete_resource_type(ctx, &tx, &record).await?;
                Ok(json!({ "deleted": true }))
            })
        });
        Ok(Reply::json(
            self.run(credential, &input, "iam:resource-types:delete", mutation)
                .await?,
        ))
    }

    /// `resourceTypes/get`.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<resource_types::GetInput>,
    ) -> IamResult<Reply<resource_types::GetOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let name = text(body.get("name"), "name", 64)?;
                let Some(definition) = ctx
                    .catalog
                    .resource_type_definition(tx.as_ref(), &tenant_id, &name)
                    .await?
                else {
                    return Err(
                        IamError::with_status("NOT_FOUND", "Resource type not found", 404).into(),
                    );
                };
                Ok(definition_json(&definition)?)
            })
        });
        Ok(Reply::json(
            self.run(credential, &input, "iam:resource-types:read", mutation)
                .await?,
        ))
    }

    /// `resourceTypes/list`: the platform's types, then the tenant's own.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<resource_types::ListInput>,
    ) -> IamResult<Reply<resource_types::ListOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let mut result: Vec<Value> = ctx
                    .catalog
                    .resource_types
                    .values()
                    .map(definition_json)
                    .collect::<IamResult<_>>()?;
                for raw in tx
                    .find(
                        "resourceTypes",
                        &Filter::new().eq("tenantId", tenant_id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    let record: ResourceTypeRecord = decode(raw)?;
                    let definition = ctx
                        .catalog
                        .resource_type_definition(tx.as_ref(), &tenant_id, &record.name)
                        .await?
                        .ok_or_else(crate::js::internal_error)?;
                    result.push(definition_json(&definition)?);
                }
                Ok(Value::Array(result))
            })
        });
        Ok(Reply::json(
            self.run(credential, &input, "iam:resource-types:read", mutation)
                .await?,
        ))
    }

    /// `resourceTypes/register`: registers a tenant-defined resource type; its resources are managed by IAM and its
    /// actions are `{name}:{verb}`.
    pub async fn register(
        &self,
        credential: &CredentialInput,
        input: Body<resource_types::RegisterInput>,
    ) -> IamResult<Reply<resource_types::RegisterOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                Ok(definition_json(
                    &register_resource_type(ctx, &tx, body).await?,
                )?)
            })
        });
        Ok(Reply::json(
            self.run(credential, &input, "iam:resource-types:create", mutation)
                .await?,
        ))
    }

    /// `resourceTypes/update`: changes description, attributes, or relations, and adds action verbs.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<resource_types::UpdateInput>,
    ) -> IamResult<Reply<resource_types::UpdateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                Ok(definition_json(
                    &update_resource_type(ctx, &tx, body, false).await?,
                )?)
            })
        });
        Ok(Reply::json(
            self.run(credential, &input, "iam:resource-types:update", mutation)
                .await?,
        ))
    }
}
