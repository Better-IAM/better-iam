//! Port of `packages/server/src/api/relationships.ts`: relationship tuples, "this identity or group is a {relation}
//! of {type}/{id}". Policies read the relations a principal holds on the evaluated resource as `resource.relations`
//! (and on its parent as `resource.parentRelations`), so a role such as
//! `{ ArrayContains: { 'resource.relations': ['editor'] } }` expresses sharing without listing IDs.

use std::collections::HashMap;
use std::sync::Arc;

use better_iam_core::{CredentialInput, Filter, FindOptions, IamError, IamResult, Record};
use better_iam_types::api::relationships;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply, string_member};
use crate::catalog::{managed_resource, resolved_managed};
use crate::context::ServerContext;
use crate::contracts::{Mutation, MutationContext, decide_on};
use crate::decisions::impersonating_actor;
use crate::models::Relationship;
use crate::options::ResolvedResource;
use crate::port::decode;
use crate::utils::{by_newest, id};
use crate::validation::text;

/// `subjectTypes`.
const SUBJECT_TYPES: [&str; 2] = ["identity", "group"];

/// `subjectTypes.has(value)`.
fn is_subject_type(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|kind| SUBJECT_TYPES.contains(&kind))
}

/// `resourceKey(input)`: `{type}/{id}`, both validated.
fn resource_key(input: &Map<String, Value>) -> IamResult<String> {
    let kind = text(input.get("type"), "resource type", 64)?;
    let id = text(input.get("id"), "resource id", 128)?;
    Ok(format!("{kind}/{id}"))
}

/// The `relationships` API group (`createRelationshipsApi(ctx)`): one method per route `relationships/{method}`.
pub struct RelationshipsApi {
    ctx: Arc<ServerContext>,
}

/// `createRelationshipsApi(ctx)`.
pub fn create_relationships_api(ctx: &Arc<ServerContext>) -> IamResult<RelationshipsApi> {
    Ok(RelationshipsApi { ctx: ctx.clone() })
}

impl RelationshipsApi {
    /// `relationships/create`: grants a declared relation on one resource to an identity or group. Requires
    /// iam:relationships:create on `iam/{type}/{id}`.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<relationships::CreateInput>,
    ) -> IamResult<Reply<relationships::CreateOutput>> {
        let ctx = &self.ctx;
        let key = resource_key(&input)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let tenant_id = tenant.id.clone();
                    let kind = string_member(body, "type");
                    let resource_id = string_member(body, "id");
                    let Some(definition) = ctx
                        .catalog
                        .resource_type_definition(tx.as_ref(), &tenant_id, &kind)
                        .await?
                    else {
                        return Err(IamError::new(
                            "INVALID_RESOURCE_TYPE",
                            "Unknown resource type",
                        )
                        .into());
                    };
                    let relation = text(body.get("relation"), "relation", 64)?;
                    if !definition.relations.contains(&relation) {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            format!(
                                "Relation {relation} is not declared for {}",
                                definition.name
                            ),
                        )
                        .into());
                    }
                    if definition.managed
                        && managed_resource(tx.as_ref(), &tenant_id, &definition.name, &resource_id)
                            .await?
                            .is_none()
                    {
                        return Err(IamError::with_status(
                            "NOT_FOUND",
                            "Resource is not registered",
                            404,
                        )
                        .into());
                    }
                    if !is_subject_type(body.get("subjectType")) {
                        return Err(IamError::new("INVALID_INPUT", "Invalid subject type").into());
                    }
                    let subject_type = string_member(body, "subjectType");
                    if subject_type == "identity" {
                        // `activeIdentity` reads the identity through `scoped`, which validates the record ID.
                        let identity_id = text(body.get("subjectId"), "id", 256)?;
                        ctx.active_identity(&tx, &identity_id, &tenant_id).await?;
                    } else {
                        ctx.scoped(&tx, "groups", body.get("subjectId"), &tenant_id)
                            .await?;
                    }
                    let subject_id = string_member(body, "subjectId");
                    let unique_key = format!(
                        "{}/{resource_id}#{relation}@{subject_type}:{subject_id}",
                        definition.name
                    );
                    let existing = tx
                        .find(
                            "relationships",
                            &Filter::new()
                                .eq("tenantId", tenant_id.clone())
                                .eq("uniqueKey", unique_key.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                        .into_iter()
                        .next();
                    let existing: Option<Relationship> = existing.map(decode).transpose()?;
                    let mut tuple = Record::new();
                    tuple.insert(
                        "id".into(),
                        Value::String(
                            existing
                                .as_ref()
                                .map(|existing| existing.id.clone())
                                .unwrap_or_else(id),
                        ),
                    );
                    tuple.insert("tenantId".into(), Value::String(tenant_id.clone()));
                    tuple.insert("uniqueKey".into(), Value::String(unique_key));
                    tuple.insert("type".into(), Value::String(definition.name.clone()));
                    tuple.insert("resourceId".into(), Value::String(resource_id));
                    tuple.insert("relation".into(), Value::String(relation));
                    tuple.insert("subjectType".into(), Value::String(subject_type));
                    tuple.insert("subjectId".into(), Value::String(subject_id));
                    tuple.insert(
                        "createdAt".into(),
                        crate::js::number(
                            existing
                                .as_ref()
                                .map(|existing| existing.created_at)
                                .unwrap_or_else(|| ctx.now()),
                        ),
                    );
                    tuple.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    if let Some(expires_at) = body.get("expiresAt") {
                        tuple.insert(
                            "expiresAt".into(),
                            crate::js::number(ctx.binding_expiry(Some(expires_at))?),
                        );
                    }
                    let saved = if existing.is_some() {
                        tx.put("relationships", &tuple).await?
                    } else {
                        tx.insert("relationships", &tuple).await?
                    };
                    Ok(Value::Object(saved))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:relationships:create",
                &key,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `relationships/list`: relationships of a resource, of a subject, or of the whole tenant; expired tuples are
    /// omitted unless requested.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<relationships::ListInput>,
    ) -> IamResult<Reply<relationships::ListOutput>> {
        let ctx = &self.ctx;
        let has_type = input.get("type").is_some();
        let resource = if has_type && input.get("id").is_some() {
            resource_key(&input)?
        } else if has_type {
            format!("{}/*", text(input.get("type"), "resource type", 64)?)
        } else {
            "*".to_owned()
        };
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    // Listing is reading each resource's tuples: one a policy keeps from the caller (a Deny on
                    // iam/document/payroll, an owner condition) is left out. A "view as" session sees what both
                    // may.
                    let mut readers = vec![principal.clone()];
                    if let Some(actor) = impersonating_actor(&tx, &principal).await? {
                        readers.push(actor);
                    }
                    let decisions = ctx.decisions()?;
                    let mut prepared = Vec::new();
                    for who in &readers {
                        prepared.push(
                            decisions
                                .prepare_decision(&tx, who, &tenant, "iam:relationships:read")
                                .await?,
                        );
                    }
                    let mut verdicts: HashMap<String, bool> = HashMap::new();
                    let mut filter = Filter::new().eq("tenantId", tenant.id.clone());
                    if let Some(kind) = body.get("type") {
                        filter.set("type", Some(kind.clone()));
                    }
                    if let Some(resource_id) = body.get("id") {
                        let resource_id = text(Some(resource_id), "resource id", 128)?;
                        filter.set("resourceId", Some(Value::String(resource_id)));
                    }
                    if let Some(relation) = body.get("relation") {
                        let relation = text(Some(relation), "relation", 64)?;
                        filter.set("relation", Some(Value::String(relation)));
                    }
                    if let Some(subject_type) = body.get("subjectType") {
                        if !is_subject_type(Some(subject_type)) {
                            return Err(
                                IamError::new("INVALID_INPUT", "Invalid subject type").into()
                            );
                        }
                        filter.set("subjectType", Some(subject_type.clone()));
                    }
                    if let Some(subject_id) = body.get("subjectId") {
                        let subject_id = text(Some(subject_id), "subjectId", 256)?;
                        filter.set("subjectId", Some(Value::String(subject_id)));
                    }
                    let include_expired = body.get("includeExpired") == Some(&Value::Bool(true));
                    let mut tuples: Vec<(Relationship, Record)> = Vec::new();
                    for record in tx
                        .find("relationships", &filter, &FindOptions::default())
                        .await?
                    {
                        let tuple: Relationship = decode(record.clone())?;
                        // `live(tuple)`: no expiry, or one still ahead.
                        let live = tuple.expires_at.is_none_or(|expires| expires > ctx.now());
                        if !(include_expired || live) {
                            continue;
                        }
                        let key = format!("{}/{}", tuple.kind, tuple.resource_id);
                        let verdict = match verdicts.get(&key) {
                            Some(verdict) => *verdict,
                            None => {
                                let managed = managed_resource(
                                    tx.as_ref(),
                                    &tenant.id,
                                    &tuple.kind,
                                    &tuple.resource_id,
                                )
                                .await?;
                                let resource = ResolvedResource {
                                    tenant_id: tenant.id.clone(),
                                    kind: "iam".into(),
                                    id: key.clone(),
                                    attributes: managed
                                        .as_ref()
                                        .and_then(|record| resolved_managed(record).attributes),
                                    classification: None,
                                };
                                let mut verdict = true;
                                for ready in &prepared {
                                    if !decide_on(ready, &resource, None)?.allowed {
                                        verdict = false;
                                        break;
                                    }
                                }
                                verdicts.insert(key, verdict);
                                verdict
                            }
                        };
                        if verdict {
                            tuples.push((tuple, record));
                        }
                    }
                    tuples.sort_by(|(a, _), (b, _)| {
                        by_newest(a.created_at, &a.id, b.created_at, &b.id)
                    });
                    Ok(Value::Array(
                        tuples
                            .into_iter()
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
                "iam:relationships:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `relationships/delete`: removes one tuple. Requires iam:relationships:delete on the tuple's resource.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<relationships::DeleteInput>,
    ) -> IamResult<Reply<relationships::DeleteOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let existing: Relationship = decode(
            ctx.scoped(
                &ctx.store,
                "relationships",
                input.get("relationshipId"),
                &tenant_id,
            )
            .await?,
        )?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                ctx.scoped(&tx, "relationships", body.get("relationshipId"), &tenant.id)
                    .await?;
                tx.delete("relationships", &string_member(body, "relationshipId"))
                    .await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:relationships:delete",
                &format!("{}/{}", existing.kind, existing.resource_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}
