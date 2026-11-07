//! Port of `packages/server/src/api/invariants.ts`: the `invariants` API group (access invariants, or guardrails)
//! and `saveInvariant`, which configuration apply shares.

use std::sync::Arc;

use better_iam_core::{
    AttributeType, CredentialInput, Filter, FindOptions, IamError, IamResult, Record, ResourceRef,
    js as core_js,
};
use better_iam_types::api::invariants;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::invariants::{AccessInvariant, InvariantSubject, evaluate_invariants};
use crate::metrics::locale_compare;
use crate::port::decode;
use crate::utils::id;
use crate::validation::{object, text};

const MAX_INVARIANTS: usize = 100;

const SUBJECT_SHAPE: &str =
    "subject must be exactly one of identityId, groupId, attribute, or everyone";

async fn valid_subject(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    value: Option<&Value>,
) -> IamResult<InvariantSubject> {
    let subject = object(value)?;
    if subject.len() != 1 {
        return Err(IamError::new("INVALID_INPUT", SUBJECT_SHAPE));
    }
    if let Some(identity_id) = subject.get("identityId") {
        let identity_id = text(Some(identity_id), "subject.identityId", 256)?;
        ctx.scoped(
            tx,
            "identities",
            Some(&Value::String(identity_id.clone())),
            tenant_id,
        )
        .await?;
        return Ok(json!({ "identityId": identity_id }));
    }
    if let Some(group_id) = subject.get("groupId") {
        let group_id = text(Some(group_id), "subject.groupId", 256)?;
        ctx.scoped(
            tx,
            "groups",
            Some(&Value::String(group_id.clone())),
            tenant_id,
        )
        .await?;
        return Ok(json!({ "groupId": group_id }));
    }
    if let Some(everyone) = subject.get("everyone") {
        if everyone != &Value::Bool(true) {
            return Err(IamError::new(
                "INVALID_INPUT",
                "subject.everyone must be true",
            ));
        }
        return Ok(json!({ "everyone": true }));
    }
    if let Some(attribute) = subject.get("attribute") {
        let attribute = object(Some(attribute))?;
        let name = text(attribute.get("name"), "subject.attribute.name", 256)?;
        let Some(kind) = ctx.catalog.identity_attributes.get(&name) else {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!("Unknown identity attribute {name}"),
            ));
        };
        let kind = match kind {
            AttributeType::String => "string",
            AttributeType::Number => "number",
            AttributeType::Boolean => "boolean",
        };
        let value = attribute.get("value");
        let matches = matches!(
            (kind, value),
            ("string", Some(Value::String(_)))
                | ("number", Some(Value::Number(_)))
                | ("boolean", Some(Value::Bool(_)))
        );
        if !matches {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!("subject.attribute.value must be a {kind}"),
            ));
        }
        return Ok(json!({ "attribute": { "name": name, "value": value } }));
    }
    Err(IamError::new("INVALID_INPUT", SUBJECT_SHAPE))
}

/// A member of the input, or the previous invariant's when the input leaves it out (`input.x ?? previous?.x`).
fn pick<'a>(
    input: &'a Map<String, Value>,
    previous: Option<&'a Record>,
    key: &str,
) -> Option<&'a Value> {
    match input.get(key) {
        Some(value) if !value.is_null() => Some(value),
        _ => previous
            .and_then(|previous| previous.get(key))
            .filter(|value| !value.is_null()),
    }
}

/// The stored fields `create` and `update` derive from input, in the order TypeScript writes them.
async fn build(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    input: &Map<String, Value>,
    previous: Option<&Record>,
) -> IamResult<Record> {
    let name = core_js::trim(&text(pick(input, previous, "name"), "name", 100)?).to_owned();
    if name.is_empty() {
        return Err(IamError::new("INVALID_INPUT", "name is required"));
    }
    let action = text(pick(input, previous, "action"), "action", 256)?;
    if !ctx
        .catalog
        .known_action(tx.as_ref(), tenant_id, &action)
        .await?
    {
        return Err(IamError::new(
            "INVALID_ACTION",
            format!("Unknown action {action}"),
        ));
    }
    let raw_resource = object(pick(input, previous, "resource"))?;
    let resource_type = text(raw_resource.get("type"), "resource type", 256)?;
    let resource_id = text(raw_resource.get("id"), "resource id", 256)?;
    // The resource must resolve now; an invariant over a resource that does not exist would never evaluate.
    ctx.decisions()?
        .resolve(
            tx,
            &ResourceRef {
                tenant_id: tenant_id.to_owned(),
                kind: resource_type.clone(),
                id: resource_id.clone(),
            },
            true,
            None,
            None,
        )
        .await?;
    let expect = match pick(input, previous, "expect").and_then(Value::as_str) {
        Some(expect @ ("allow" | "deny")) => expect.to_owned(),
        _ => {
            return Err(IamError::new(
                "INVALID_INPUT",
                "expect must be allow or deny",
            ));
        }
    };
    let mode = match pick(input, previous, "mode") {
        None => "monitor".to_owned(),
        Some(Value::String(mode)) if mode == "enforce" || mode == "monitor" => mode.clone(),
        Some(_) => {
            return Err(IamError::new(
                "INVALID_INPUT",
                "mode must be enforce or monitor",
            ));
        }
    };
    let assume_mfa = match pick(input, previous, "assumeMfa") {
        None => true,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => {
            return Err(IamError::new(
                "INVALID_INPUT",
                "assumeMfa must be a boolean",
            ));
        }
    };
    let description = match input.get("description") {
        None => previous
            .and_then(|previous| previous.get("description"))
            .cloned(),
        Some(Value::String(empty)) if empty.is_empty() => None,
        Some(value) => Some(Value::String(text(Some(value), "description", 500)?)),
    };
    let subject = valid_subject(ctx, tx, tenant_id, pick(input, previous, "subject")).await?;
    let mut fields = Record::new();
    fields.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    fields.insert(
        "uniqueKey".into(),
        Value::String(format!("name:{}", core_js::to_lower(&name))),
    );
    fields.insert("name".into(), Value::String(name));
    if let Some(description) =
        description.filter(|description| crate::js::truthy(Some(description)))
    {
        fields.insert("description".into(), description);
    }
    fields.insert("subject".into(), subject);
    fields.insert("action".into(), Value::String(action));
    fields.insert(
        "resource".into(),
        json!({ "type": resource_type, "id": resource_id }),
    );
    fields.insert("expect".into(), Value::String(expect));
    fields.insert("mode".into(), Value::String(mode));
    fields.insert("assumeMfa".into(), Value::Bool(assume_mfa));
    fields.insert("updatedAt".into(), crate::js::number(ctx.now()));
    Ok(fields)
}

/// Creates (without `previous`) or updates an invariant after validating it like the API does; shared by the
/// `invariants` API and configuration apply. `actorId` is recorded as the creator.
pub async fn save_invariant(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    input: &Value,
    actor_id: &str,
    previous: Option<&AccessInvariant>,
) -> IamResult<AccessInvariant> {
    let empty = Map::new();
    let input = match input {
        Value::Object(input) => input,
        _ => &empty,
    };
    // The previous invariant as stored, so members this port does not know survive the update.
    let previous_record = match previous {
        Some(previous) => Some(
            tx.get("accessInvariants", &previous.id)
                .await?
                .unwrap_or_else(|| crate::port::encode(previous)),
        ),
        None => None,
    };
    let fields = build(ctx, tx, tenant_id, input, previous_record.as_ref()).await?;
    let clash: Vec<Record> = tx
        .find(
            "accessInvariants",
            &Filter::new().eq("tenantId", tenant_id),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .filter(|invariant| {
            previous.is_none_or(|previous| better_iam_core::record_id(invariant) != previous.id)
        })
        .collect();
    if clash
        .iter()
        .any(|invariant| invariant.get("uniqueKey") == fields.get("uniqueKey"))
    {
        return Err(IamError::with_status(
            "CONFLICT",
            "An invariant with this name exists",
            409,
        ));
    }
    if let Some(mut kept) = previous_record {
        kept.shift_remove("description");
        for (key, value) in fields {
            kept.insert(key, value);
        }
        return decode(tx.put("accessInvariants", &kept).await?);
    }
    if clash.len() >= MAX_INVARIANTS {
        return Err(IamError::with_status(
            "LIMIT_EXCEEDED",
            format!("At most {MAX_INVARIANTS} invariants"),
            409,
        ));
    }
    let updated_at = fields.get("updatedAt").cloned().unwrap_or(Value::Null);
    let mut record = fields;
    record.insert("id".into(), Value::String(id()));
    record.insert("createdBy".into(), Value::String(actor_id.to_owned()));
    record.insert("createdAt".into(), updated_at);
    decode(tx.insert("accessInvariants", &record).await?)
}

/// The tenant's invariants, by name.
async fn sorted_invariants(tx: &Store, tenant_id: &str) -> IamResult<Vec<Record>> {
    let mut invariants = tx
        .find(
            "accessInvariants",
            &Filter::new().eq("tenantId", tenant_id),
            &FindOptions::default(),
        )
        .await?;
    invariants.sort_by(|a, b| {
        locale_compare(
            a.get("name").and_then(Value::as_str).unwrap_or_default(),
            b.get("name").and_then(Value::as_str).unwrap_or_default(),
        )
    });
    Ok(invariants)
}

/// `{ invariant, result }` for a saved invariant, evaluated now.
async fn saved_with_result(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant: &better_iam_core::Tenant,
    invariant: AccessInvariant,
) -> IamResult<Value> {
    let results =
        evaluate_invariants(ctx, tx, tenant, std::slice::from_ref(&invariant), false).await?;
    let result = results
        .first()
        .map(|result| result.to_json())
        .unwrap_or(Value::Null);
    // The record as stored (member order and numbers as TypeScript returns them from `put`/`insert`).
    let stored = match tx.get("accessInvariants", &invariant.id).await? {
        Some(record) => record,
        None => crate::port::encode(&invariant),
    };
    Ok(json!({
        "invariant": Value::Object(stored),
        "result": result,
    }))
}

/// Access invariants (guardrails): assertions about who may or must never perform an action on a resource, checked
/// by `run` and, in `enforce` mode, around every operation that changes access, so a role edit, binding, group
/// change, package assignment, or configuration apply that would newly break one is refused with
/// `INVARIANT_VIOLATION`. Invariants already broken when enforcement starts are reported but do not block unrelated
/// changes. Reading needs `iam:invariants:read`; changing them needs `iam:invariants:manage`.
pub struct InvariantsApi {
    ctx: Arc<ServerContext>,
}

/// `createInvariantsApi(ctx)`.
pub fn create_invariants_api(ctx: &Arc<ServerContext>) -> IamResult<InvariantsApi> {
    Ok(InvariantsApi { ctx: ctx.clone() })
}

impl InvariantsApi {
    /// `invariants/create`: creates an invariant (default mode `monitor`) and returns it with its current result.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<invariants::CreateInput>,
    ) -> IamResult<Reply<invariants::CreateOutput>> {
        let ctx = &self.ctx;
        let body = input.value();
        let body = &body;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let invariant =
                        save_invariant(ctx, &tx, &tenant.id, body, &principal.identity.id, None)
                            .await?;
                    Ok(saved_with_result(ctx, &tx, &tenant, invariant).await?)
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:invariants:manage",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `invariants/delete`.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<invariants::DeleteInput>,
    ) -> IamResult<Reply<invariants::DeleteOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("invariantId"), "invariantId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let invariant = ctx
                    .scoped(&tx, "accessInvariants", body.get("invariantId"), &tenant.id)
                    .await?;
                tx.delete("accessInvariants", better_iam_core::record_id(&invariant))
                    .await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:invariants:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `invariants/list`: the tenant's invariants, by name.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<invariants::ListInput>,
    ) -> IamResult<Reply<invariants::ListOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                Ok(Value::Array(
                    sorted_invariants(&tx, &tenant.id)
                        .await?
                        .into_iter()
                        .map(Value::Object)
                        .collect(),
                ))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:invariants:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `invariants/run`: evaluates every invariant (or one) against the current configuration.
    pub async fn run(
        &self,
        credential: &CredentialInput,
        input: Body<invariants::RunInput>,
    ) -> IamResult<Reply<invariants::RunOutput>> {
        let ctx = &self.ctx;
        let resource = match input.get("invariantId") {
            None => string_member(&input, "tenantId"),
            Some(invariant_id) => text(Some(invariant_id), "invariantId", 256)?,
        };
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let records = match body.get("invariantId") {
                    None => sorted_invariants(&tx, &tenant.id).await?,
                    Some(invariant_id) => vec![
                        ctx.scoped(&tx, "accessInvariants", Some(invariant_id), &tenant.id)
                            .await?,
                    ],
                };
                let invariants = records
                    .into_iter()
                    .map(decode::<AccessInvariant>)
                    .collect::<IamResult<Vec<_>>>()?;
                let results = evaluate_invariants(ctx, &tx, &tenant, &invariants, false).await?;
                let (mut passed, mut failed, mut errors) = (0.0, 0.0, 0.0);
                for result in &results {
                    if result.error.is_some() {
                        errors += 1.0;
                    } else if result.passed {
                        passed += 1.0;
                    } else {
                        failed += 1.0;
                    }
                }
                let number = crate::js::number;
                Ok(json!({
                    "generatedAt": number(ctx.now()),
                    "summary": {
                        "passed": number(passed),
                        "failed": number(failed),
                        "errors": number(errors),
                    },
                    "results": results.iter().map(|result| result.to_json()).collect::<Vec<_>>(),
                }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:invariants:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `invariants/update`: changes any field; switching to `enforce` is allowed even while the invariant is broken.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<invariants::UpdateInput>,
    ) -> IamResult<Reply<invariants::UpdateOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("invariantId"), "invariantId", 256)?;
        let body = input.value();
        let body = &body;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let previous: AccessInvariant = decode(
                        ctx.scoped(&tx, "accessInvariants", body.get("invariantId"), &tenant.id)
                            .await?,
                    )?;
                    let invariant = save_invariant(
                        ctx,
                        &tx,
                        &tenant.id,
                        body,
                        &principal.identity.id,
                        Some(&previous),
                    )
                    .await?;
                    Ok(saved_with_result(ctx, &tx, &tenant, invariant).await?)
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:invariants:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}
