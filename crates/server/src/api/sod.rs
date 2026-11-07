//! Port of `packages/server/src/api/sod.ts`: separation-of-duties rules (toxic role combinations). A `prevent` rule
//! makes every granting operation (bindings, group membership, bulk onboarding, access-request approval,
//! configuration apply, invitation acceptance) fail with `SOD_CONFLICT` when it would leave someone holding two of
//! its roles; conflicts that predate the rule are reported by `violations` and the access analysis instead of
//! blocking unrelated work.

use std::collections::HashMap;
use std::sync::Arc;

use better_iam_core::js::trim;
use better_iam_core::{CredentialInput, Filter, FindOptions, IamError, IamResult, Record};
use better_iam_types::api::sod;
use indexmap::IndexSet;
use serde_json::{Map, Value};

use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::sod::{SodRule, sod_violations};
use crate::utils::{by_newest_records, id};
use crate::validation::{strings, text};

/// `modes`: the rule modes.
const MODES: [&str; 2] = ["prevent", "detect"];

/// The `sod` API group (`createSodApi(ctx)`): one method per route `sod/{method}`.
pub struct SodApi {
    ctx: Arc<ServerContext>,
}

/// `createSodApi(ctx)`.
pub fn create_sod_api(ctx: &Arc<ServerContext>) -> IamResult<SodApi> {
    Ok(SodApi { ctx: ctx.clone() })
}

/// The tenant's rules, as stored.
async fn tenant_rules(tx: &Store, tenant_id: &str) -> IamResult<Vec<Record>> {
    tx.find(
        "sodRules",
        &Filter::new().eq("tenantId", tenant_id),
        &FindOptions::default(),
    )
    .await
}

/// `validate(tx, tenantId, input, rule)`: applies the given members of `input` to `rule`, in the TypeScript order.
async fn validate(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    input: &Map<String, Value>,
    rule: &mut Map<String, Value>,
) -> IamResult<()> {
    if let Some(name) = input.get("name") {
        let name = text(Some(name), "name", 200)?;
        rule.insert("name".into(), Value::String(trim(&name).to_owned()));
    }
    if let Some(description) = input.get("description") {
        let description = text(Some(description), "description", 1000)?;
        rule.insert(
            "description".into(),
            Value::String(trim(&description).to_owned()),
        );
    }
    if let Some(mode) = input.get("mode") {
        let known = mode.as_str().is_some_and(|mode| MODES.contains(&mode));
        if !known {
            return Err(IamError::new(
                "INVALID_INPUT",
                "mode must be prevent or detect",
            ));
        }
        rule.insert("mode".into(), mode.clone());
    }
    if let Some(role_ids) = input.get("roleIds") {
        let role_ids: Vec<String> = strings(Some(role_ids), "roleIds")?
            .into_iter()
            .collect::<IndexSet<String>>()
            .into_iter()
            .collect();
        if role_ids.len() < 2 || role_ids.len() > 20 {
            return Err(IamError::new(
                "INVALID_INPUT",
                "A rule names 2 to 20 conflicting roles",
            ));
        }
        for role_id in &role_ids {
            let role = ctx
                .scoped(
                    tx,
                    "roles",
                    Some(&Value::String(role_id.clone())),
                    tenant_id,
                )
                .await?;
            if crate::js::truthy(role.get("protected")) {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "Owner roles cannot be part of a rule",
                ));
            }
        }
        rule.insert(
            "roleIds".into(),
            Value::Array(role_ids.into_iter().map(Value::String).collect()),
        );
    }
    Ok(())
}

impl SodApi {
    /// `sod/create`: declares conflicting roles. Requires iam:sod:manage.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<sod::CreateInput>,
    ) -> IamResult<Reply<sod::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let mut rule = Map::new();
                rule.insert("mode".into(), Value::String("prevent".into()));
                validate(ctx, &tx, &tenant_id, body, &mut rule).await?;
                if !crate::js::truthy(rule.get("name")) || rule.get("roleIds").is_none() {
                    return Err(
                        IamError::new("INVALID_INPUT", "name and roleIds are required").into(),
                    );
                }
                rule.insert("id".into(), Value::String(id()));
                rule.insert("tenantId".into(), Value::String(tenant_id.clone()));
                rule.insert("createdAt".into(), crate::js::number(ctx.now()));
                rule.insert(
                    "createdBy".into(),
                    Value::String(principal.identity.id.clone()),
                );
                let mut saved = tx.insert("sodRules", &rule).await?;
                let typed = crate::port::decode::<SodRule>(saved.clone())?;
                let existing = sod_violations(ctx, &tx, &tenant_id, Some(&[typed]), None).await?;
                saved.insert(
                    "existingViolations".into(),
                    crate::js::number(existing.len() as f64),
                );
                Ok(Value::Object(saved))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:sod:manage",
                "sod/*",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `sod/delete`: removes a rule. Requires iam:sod:manage.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<sod::DeleteInput>,
    ) -> IamResult<Reply<sod::DeleteOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let resource = format!("sod/{}", text(input.get("ruleId"), "ruleId", 256)?);
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let rule = ctx
                    .scoped(&tx, "sodRules", body.get("ruleId"), &tenant_id)
                    .await?;
                let rule_id = rule.get("id").and_then(Value::as_str).unwrap_or_default();
                tx.delete("sodRules", rule_id).await?;
                Ok(serde_json::json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:sod:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `sod/list`: rules of the tenant, newest first. Requires iam:sod:read.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<sod::ListInput>,
    ) -> IamResult<Reply<sod::ListOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let mut rules = tenant_rules(&tx, &string_member(body, "tenantId")).await?;
                rules.sort_by(by_newest_records);
                Ok(Value::Array(rules.into_iter().map(Value::Object).collect()))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:sod:read",
                "sod/*",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `sod/update`: changes a rule's name, description, roles, or mode. Requires iam:sod:manage.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<sod::UpdateInput>,
    ) -> IamResult<Reply<sod::UpdateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let resource = format!("sod/{}", text(input.get("ruleId"), "ruleId", 256)?);
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let mut next = ctx
                    .scoped(&tx, "sodRules", body.get("ruleId"), &tenant_id)
                    .await?;
                validate(ctx, &tx, &tenant_id, body, &mut next).await?;
                let saved = tx.put("sodRules", &next).await?;
                Ok(Value::Object(saved))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:sod:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `sod/violations`: everyone currently holding two or more roles of a rule, with names for review screens.
    /// Requires iam:sod:read.
    pub async fn violations(
        &self,
        credential: &CredentialInput,
        input: Body<sod::ViolationsInput>,
    ) -> IamResult<Reply<sod::ViolationsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let mut records = tenant_rules(&tx, &tenant_id).await?;
                if let Some(rule_id) = body.get("ruleId") {
                    records.retain(|rule| rule.get("id") == Some(rule_id));
                }
                let mut rules = Vec::new();
                for record in records {
                    rules.push(crate::port::decode::<SodRule>(record)?);
                }
                let mut roles: HashMap<String, Value> = HashMap::new();
                for role in tx
                    .find(
                        "roles",
                        &Filter::new().eq("tenantId", tenant_id.as_str()),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    let role_id = role.get("id").and_then(Value::as_str).unwrap_or_default();
                    match crate::js::defined(role.get("name")) {
                        Some(name) => roles.insert(role_id.to_owned(), name.clone()),
                        None => roles.remove(role_id),
                    };
                }
                let mut result = Vec::new();
                for violation in sod_violations(ctx, &tx, &tenant_id, Some(&rules), None).await? {
                    let Value::Object(mut view) = violation else {
                        continue;
                    };
                    let identity_id = view
                        .get("identityId")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let identity = tx.get("identities", &identity_id).await?;
                    let identity_name = identity
                        .as_ref()
                        .and_then(|identity| {
                            crate::js::defined(identity.get("email"))
                                .or_else(|| crate::js::defined(identity.get("name")))
                                .cloned()
                        })
                        .unwrap_or(Value::String(identity_id));
                    let role_names: Vec<Value> = view
                        .get("roleIds")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .map(|role_id| {
                            role_id
                                .as_str()
                                .and_then(|role_id| roles.get(role_id).cloned())
                                .unwrap_or_else(|| role_id.clone())
                        })
                        .collect();
                    view.insert("identityName".into(), identity_name);
                    view.insert("roleNames".into(), Value::Array(role_names));
                    result.push(Value::Object(view));
                }
                Ok(Value::Array(result))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:sod:read",
                "sod/*",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}
