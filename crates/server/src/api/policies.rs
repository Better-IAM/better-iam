//! Port of `packages/server/src/api/policies.ts`: the `policies` API group (versioned policies, document tests,
//! simulations and access reviews) and the policy helpers configuration sync and impact previews share.

use std::sync::Arc;

use better_iam_core::{
    CredentialInput, Decision, EvaluationInput, Filter, IamError, IamResult, Identity,
    PolicyDocument, Record, ResourceRef, evaluate_policy,
};
use better_iam_types::api::policies;
use serde_json::{Map, Value, json};

use crate::api::roles::{
    assert_denies_kept_with, defined, find_all, member_str, or_default, relied_on, same_member,
    string_list,
};
use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, PreparedDecision, decide_on};
use crate::decisions::document_deny_statements;
use crate::features::{
    FEATURE_CONTEXT_KEY, enabled_feature_keys, feature_state, mentions_features,
};
use crate::js::{as_number, internal_error, number, number_to_string, sort_strings, unique};
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::port::{decode, encode};
use crate::utils::{by_id, id};
use crate::validation::{integer, object, strings, text};

/// The `policies` API group (`createPoliciesApi(ctx)`): one method per route `policies/{method}`.
pub struct PoliciesApi {
    ctx: Arc<ServerContext>,
}

/// `createPoliciesApi(ctx)`.
pub fn create_policies_api(ctx: &Arc<ServerContext>) -> IamResult<PoliciesApi> {
    Ok(PoliciesApi { ctx: ctx.clone() })
}

/// A decision as the API answers it.
fn decision_json(decision: &Decision) -> Value {
    json!({ "allowed": decision.allowed, "reason": decision.reason, "matched": decision.matched })
}

/// `ctx.scoped<Identity>(...)` read as an identity.
async fn scoped_identity(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    identity_id: Option<&Value>,
    tenant_id: &str,
) -> IamResult<Identity> {
    decode(ctx.scoped(tx, "identities", identity_id, tenant_id).await?)
}

/// `ctx.decisions.resolve(tx, { tenantId, type: text(reference.type), id: text(reference.id) }, true)`: reviews
/// accept platform resources (`iam/...`) as well as catalog resources.
async fn review_resource(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    resource: Option<&Value>,
) -> IamResult<crate::options::ResolvedResource> {
    let reference = object(resource)?;
    let reference = ResourceRef {
        tenant_id: tenant_id.to_owned(),
        kind: text(reference.get("type"), "resource type", 256)?,
        id: text(reference.get("id"), "resource id", 256)?,
    };
    ctx.decisions()?
        .resolve(tx, &reference, true, None, None)
        .await
}

impl PoliciesApi {
    /// `policies/create`.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<policies::CreateInput>,
    ) -> IamResult<Reply<policies::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let policy = create_policy_record(ctx, &tx, &principal, &tenant, body).await?;
                    Ok(Value::Object(policy))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:policies:create",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `policies/delete`.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<policies::DeleteInput>,
    ) -> IamResult<Reply<policies::DeleteOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let policy = ctx
                    .scoped(&tx, "policies", body.get("policyId"), &tenant_id)
                    .await?;
                delete_policy_record(ctx, &tx, &principal, &policy).await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:policies:delete",
                &string_member(&input, "policyId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `policies/effectiveActions`: access review, which catalog actions (or the given `actions`) an identity could
    /// perform on one resource. Grants are loaded once and evaluated per action. Advisory, like `simulate`.
    pub async fn effective_actions(
        &self,
        credential: &CredentialInput,
        input: Body<policies::EffectiveActionsInput>,
    ) -> IamResult<Reply<policies::EffectiveActionsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let identity =
                    scoped_identity(ctx, &tx, body.get("identityId"), &tenant.id).await?;
                let resource = review_resource(ctx, &tx, &tenant.id, body.get("resource")).await?;
                let mut candidates: Vec<String>;
                if let Some(actions) = defined(body, "actions") {
                    candidates = unique(strings(Some(actions), "actions")?);
                    if candidates.len() > 200 {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "Review at most 200 actions at once",
                        )
                        .into());
                    }
                    for action in &candidates {
                        if !ctx
                            .catalog
                            .known_action(tx.as_ref(), &tenant.id, action)
                            .await?
                        {
                            return Err(IamError::new(
                                "INVALID_ACTION",
                                format!("Unknown action {action}"),
                            )
                            .into());
                        }
                    }
                } else {
                    let tenant_actions = tx
                        .find(
                            "actions",
                            &Filter::new().eq("tenantId", tenant.id.clone()),
                            &find_all(),
                        )
                        .await?;
                    candidates = ctx.catalog.actions.iter().cloned().collect();
                    candidates.extend(
                        tenant_actions
                            .iter()
                            .map(|item| member_str(item, "name").to_owned()),
                    );
                }
                sort_strings(&mut candidates);
                let decisions = ctx.decisions()?;
                let principal = decisions
                    .simulated_principal(&identity, body.get("assumeMfa") == Some(&json!(true)));
                let prepared = decisions
                    .prepare_decision(
                        &tx,
                        &principal,
                        &tenant,
                        candidates.first().map_or("*", String::as_str),
                    )
                    .await?;
                let mut results = Vec::new();
                let mut allowed = Vec::new();
                for action in &candidates {
                    let decision = decide_on(&prepared, &resource, Some(action))?;
                    if decision.allowed {
                        allowed.push(Value::String(action.clone()));
                    }
                    results.push(json!({
                        "action": action,
                        "allowed": decision.allowed,
                        "reason": decision.reason,
                    }));
                }
                Ok(json!({ "allowed": allowed, "results": results }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:policies:simulate",
                &string_member(&input, "identityId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `policies/get`.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<policies::GetInput>,
    ) -> IamResult<Reply<policies::GetOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let policy = ctx
                    .scoped(&tx, "policies", body.get("policyId"), &tenant_id)
                    .await?;
                Ok(Value::Object(policy))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:policies:read",
                &string_member(&input, "policyId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `policies/list`.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<policies::ListInput>,
    ) -> IamResult<Reply<policies::ListOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let policies = tx
                    .find(
                        "policies",
                        &Filter::new().eq("tenantId", string_member(body, "tenantId")),
                        &find_all(),
                    )
                    .await?;
                Ok(Value::Array(
                    policies.into_iter().map(Value::Object).collect(),
                ))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:policies:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `policies/listVersions`: the archived versions and the current one, oldest first.
    pub async fn list_versions(
        &self,
        credential: &CredentialInput,
        input: Body<policies::ListVersionsInput>,
    ) -> IamResult<Reply<policies::ListVersionsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let policy = ctx
                    .scoped(&tx, "policies", body.get("policyId"), &tenant_id)
                    .await?;
                let mut versions: Vec<Record> = tx
                    .find(
                        "policyVersions",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("policyId", member_str(&policy, "id")),
                        &find_all(),
                    )
                    .await?
                    .into_iter()
                    .map(|mut version| {
                        version.shift_remove("uniqueKey");
                        version
                    })
                    .collect();
                versions.push(policy);
                let version_of = |record: &Record| {
                    record
                        .get("version")
                        .and_then(as_number)
                        .unwrap_or(f64::NAN)
                };
                versions.sort_by(|a, b| {
                    (version_of(a) - version_of(b))
                        .partial_cmp(&0.0)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                Ok(Value::Array(
                    versions.into_iter().map(Value::Object).collect(),
                ))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:policies:read",
                &string_member(&input, "policyId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `policies/restoreVersion`: rolls a policy back to an earlier document as a new version; the old document is
    /// re-validated against the catalog.
    pub async fn restore_version(
        &self,
        credential: &CredentialInput,
        input: Body<policies::RestoreVersionInput>,
    ) -> IamResult<Reply<policies::RestoreVersionOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let policy = ctx
                    .scoped(&tx, "policies", body.get("policyId"), &tenant_id)
                    .await?;
                ctx.granting_authority(&tx, &principal, &tenant_id, None)
                    .await?;
                ctx.can_edit_grant_resource(&tx, &principal, &policy)
                    .await?;
                if policy.get("uniqueKey").and_then(Value::as_str) == Some("system:owner") {
                    return Err(IamError::with_status(
                        "PROTECTED_RESOURCE",
                        "Owner policy is protected",
                        403,
                    )
                    .into());
                }
                let current = policy
                    .get("version")
                    .and_then(as_number)
                    .unwrap_or(f64::NAN);
                let version = integer(body.get("version"), "version", 1.0, current)?;
                if version == current {
                    return Err(
                        IamError::new("INVALID_INPUT", "That version is already current").into(),
                    );
                }
                let policy_id = member_str(&policy, "id").to_owned();
                let archived = tx
                    .find(
                        "policyVersions",
                        &Filter::new().eq("tenantId", tenant_id.clone()).eq(
                            "uniqueKey",
                            format!("{policy_id}:{}", number_to_string(version)),
                        ),
                        &find_all(),
                    )
                    .await?
                    .into_iter()
                    .next();
                let Some(archived) = archived else {
                    return Err(IamError::with_status(
                        "NOT_FOUND",
                        "Policy version not found",
                        404,
                    )
                    .into());
                };
                let document = archived.get("document").cloned().unwrap_or(Value::Null);
                ctx.catalog
                    .validate(tx.as_ref(), &tenant_id, &document)
                    .await?;
                assert_policy_denies_kept(ctx, &tx, &principal, &policy, &document).await?;
                tx.insert("policyVersions", &archived_version(&policy))
                    .await?;
                let mut next = policy.clone();
                next.insert("document".into(), document);
                next.insert("version".into(), number(current + 1.0));
                Ok(Value::Object(tx.put("policies", &next).await?))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:policies:update",
                &string_member(&input, "policyId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `policies/simulate`: administrator-only explanation of a decision for any identity; it creates no session
    /// and grants nothing. `assumeMfa` simulates an MFA session.
    pub async fn simulate(
        &self,
        credential: &CredentialInput,
        input: Body<policies::SimulateInput>,
    ) -> IamResult<Reply<policies::SimulateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let identity =
                    scoped_identity(ctx, &tx, body.get("identityId"), &tenant_id).await?;
                let decisions = ctx.decisions()?;
                let principal = decisions
                    .simulated_principal(&identity, body.get("assumeMfa") == Some(&json!(true)));
                // `decide` reads the tenant, then the action, as `text(request.action, 'action')`.
                let target = ctx.tenant(&tx, &tenant_id).await?;
                let action = text(body.get("action"), "action", 256)?;
                let resource = match body.get("resource") {
                    None | Some(Value::Null) => {
                        // `request.resource.type` of a missing resource throws once the decision needs the
                        // resource: after the refusals that do not depend on it.
                        let prepared = decisions
                            .prepare_decision(&tx, &principal, &target, &action)
                            .await?;
                        if let PreparedDecision::Fixed(decision) = &prepared
                            && !decision.allowed
                        {
                            return Ok(decision_json(decision));
                        }
                        if !ctx
                            .catalog
                            .known_action(tx.as_ref(), &target.id, &action)
                            .await?
                        {
                            return Ok(decision_json(&Decision {
                                allowed: false,
                                reason: "UNKNOWN_ACTION".into(),
                                matched: Vec::new(),
                            }));
                        }
                        return Err(internal_error().into());
                    }
                    Some(resource) => {
                        let member = |key: &str| {
                            resource
                                .get(key)
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned()
                        };
                        ResourceTarget {
                            kind: member("type"),
                            id: member("id"),
                        }
                    }
                };
                let decision = decisions
                    .decide(
                        &tx,
                        &principal,
                        &AuthorizationRequest {
                            credential: CredentialInput::default(),
                            tenant_id: target.id.clone(),
                            action,
                            resource,
                        },
                        false,
                    )
                    .await?;
                Ok(decision_json(&decision))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:policies:simulate",
                &string_member(&input, "identityId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `policies/test`: evaluates a candidate document (not stored) against an action, a resource string, and a
    /// caller-supplied context, for policy editors. Requires iam:policies:simulate. The document is validated
    /// against the catalog first.
    pub async fn test(
        &self,
        credential: &CredentialInput,
        input: Body<policies::TestInput>,
    ) -> IamResult<Reply<policies::TestOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let document = body.get("document").cloned().unwrap_or(Value::Null);
                ctx.catalog
                    .validate(tx.as_ref(), &tenant.id, &document)
                    .await?;
                let caller = object(Some(or_default(body.get("context"), &json!({}))))?.clone();
                if caller.len() > 200 {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "context may hold at most 200 keys",
                    )
                    .into());
                }
                let now = better_iam_core::js::iso_string(ctx.now()).ok_or_else(internal_error)?;
                let action = text(body.get("action"), "action", 256)?;
                let resource = text(body.get("resource"), "resource", 2048)?;
                let grant = PolicyDocument::from_value(&document)?;
                let mut context = Map::new();
                let mut set = |key: &str, value: Value| {
                    context.insert(key.to_owned(), value);
                };
                // Defaults for the always-present server keys, as a synthetic session issued now would carry them;
                // the caller's context overrides any of them.
                set("resource.tenantId", json!(tenant.id));
                set("principal.tenantId", json!(tenant.id));
                set("principal.sessionId", json!("simulation"));
                set("principal.tokenIssueTime", json!(now));
                set("principal.authTime", json!(now));
                set("principal.sessionTagKeys", json!([]));
                set("principal.delegated", json!(false));
                // Threat detection keys as for a person nothing was detected about (threats.ts).
                set("principal.riskLevel", json!("none"));
                set("principal.riskScore", json!(0));
                // No license seats (licenses.ts), as for a person nothing was assigned to.
                set("principal.licenses", json!([]));
                // A member rather than a guest (guests.ts).
                set("principal.guest", json!(false));
                // Device posture keys as for a request without a verified device (devices.ts).
                set("request.deviceAssurance", json!("none"));
                set("request.deviceManaged", json!(false));
                set("request.deviceCompliant", json!(false));
                // With security clearances (clearances.ts): an uncleared person and an unlabeled resource. A
                // document test never applies mandatory access control itself.
                if ctx.config.clearances.is_some() {
                    set("principal.clearanceRank", json!(-1));
                    set("principal.clearanceStatus", json!("none"));
                    set("principal.clearanceCompartments", json!([]));
                    set("principal.clearanceCitizenship", json!([]));
                    set("resource.classificationRank", json!(-1));
                    set("resource.compartments", json!([]));
                    set("resource.noforn", json!(false));
                    set("resource.releasableTo", json!([]));
                }
                set("request.time", json!(now));
                // The tenant's feature flags as they are now, read only when the document names them.
                if mentions_features(&[&grant]) {
                    let chain = ctx.ancestry(&tx, &tenant).await?;
                    let state = feature_state(&tx, &chain, ctx.now()).await?;
                    set(FEATURE_CONTEXT_KEY, json!(enabled_feature_keys(&state)?));
                }
                for (key, value) in caller {
                    set(&key, value);
                }
                let decision = evaluate_policy(&EvaluationInput {
                    action,
                    resource,
                    context: Some(context),
                    grants: vec![grant],
                    boundaries: None,
                })?;
                Ok(decision_json(&decision))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:policies:simulate",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `policies/update`: optimistic concurrency, the caller supplies the version it read; previous versions are
    /// retained.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<policies::UpdateInput>,
    ) -> IamResult<Reply<policies::UpdateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let policy = update_policy_record(ctx, &tx, &principal, body).await?;
                Ok(Value::Object(policy))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:policies:update",
                &string_member(&input, "policyId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `policies/whoCan`: access review, every active identity of the tenant that could perform `action` on
    /// `resource`, with the reason. Root administrators are not listed: their override applies everywhere (except,
    /// with security clearances, to labeled resources above their own clearance). Advisory, like `simulate`.
    pub async fn who_can(
        &self,
        credential: &CredentialInput,
        input: Body<policies::WhoCanInput>,
    ) -> IamResult<Reply<policies::WhoCanOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let action = text(body.get("action"), "action", 256)?;
                if !ctx
                    .catalog
                    .known_action(tx.as_ref(), &tenant.id, &action)
                    .await?
                {
                    return Err(IamError::new(
                        "INVALID_ACTION",
                        format!("Unknown action {action}"),
                    )
                    .into());
                }
                let limit = integer(
                    Some(or_default(body.get("limit"), &json!(100))),
                    "limit",
                    1.0,
                    1000.0,
                )?;
                let offset = integer(
                    Some(or_default(body.get("offset"), &json!(0))),
                    "offset",
                    0.0,
                    1_000_000.0,
                )?;
                let kind = defined(body, "kind");
                if let Some(kind) = kind
                    && kind != &json!("user")
                    && kind != &json!("service")
                {
                    return Err(
                        IamError::new("INVALID_INPUT", "kind must be user or service").into(),
                    );
                }
                let resource = review_resource(ctx, &tx, &tenant.id, body.get("resource")).await?;
                let mut filter = Filter::new()
                    .eq("tenantId", tenant.id.clone())
                    .eq("status", "active");
                if let Some(kind) = kind {
                    filter = filter.eq("kind", kind.clone());
                }
                let mut identities = tx.find("identities", &filter, &find_all()).await?;
                identities.sort_by(|a, b| by_id(member_str(a, "id"), member_str(b, "id")));
                let decisions = ctx.decisions()?;
                let assume_mfa = body.get("assumeMfa") == Some(&json!(true));
                let mut matches: Vec<Value> = Vec::new();
                for record in identities {
                    let identity: Identity = decode(record)?;
                    let principal = decisions.simulated_principal(&identity, assume_mfa);
                    let prepared = decisions
                        .prepare_decision(&tx, &principal, &tenant, &action)
                        .await?;
                    let decision = decide_on(&prepared, &resource, None)?;
                    if decision.allowed {
                        let mut found = Map::new();
                        found.insert("identityId".into(), json!(identity.id));
                        found.insert("name".into(), json!(identity.name));
                        if let Some(email) = &identity.email {
                            found.insert("email".into(), json!(email));
                        }
                        found.insert(
                            "kind".into(),
                            serde_json::to_value(identity.kind).unwrap_or(Value::Null),
                        );
                        found.insert("reason".into(), json!(decision.reason));
                        matches.push(Value::Object(found));
                    }
                }
                let total = matches.len();
                let page: Vec<Value> = matches
                    .into_iter()
                    .skip(offset as usize)
                    .take(limit as usize)
                    .collect();
                Ok(json!({ "identities": page, "total": total }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:policies:simulate",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// `{ ...policy, id: id(), policyId: policy.id, uniqueKey: `${policy.id}:${policy.version}` }`: the archived copy
/// of the current version.
fn archived_version(policy: &Record) -> Record {
    let mut archived = policy.clone();
    let policy_id = member_str(policy, "id").to_owned();
    let version = policy
        .get("version")
        .map(|version| crate::js::js_string(Some(version)))
        .unwrap_or_else(|| "undefined".into());
    archived.insert("id".into(), Value::String(id()));
    archived.insert("policyId".into(), Value::String(policy_id.clone()));
    archived.insert(
        "uniqueKey".into(),
        Value::String(format!("{policy_id}:{version}")),
    );
    archived
}

/// [`create_policy`] on a raw input, answering the stored record.
pub async fn create_policy_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    tenant: &better_iam_core::Tenant,
    input: &Map<String, Value>,
) -> IamResult<Record> {
    let tenant_id = string_member(input, "tenantId");
    let document = input.get("document").cloned().unwrap_or(Value::Null);
    ctx.catalog
        .validate(tx.as_ref(), &tenant_id, &document)
        .await?;
    let authority = ctx
        .granting_authority(tx, principal, &tenant_id, None)
        .await?;
    ctx.enforce_limit(
        tenant,
        "policies",
        || async {
            Ok(tx
                .find(
                    "policies",
                    &Filter::new().eq("tenantId", tenant_id.clone()),
                    &find_all(),
                )
                .await?
                .len() as f64)
        },
        None,
    )
    .await?;
    let mut policy = Record::new();
    policy.insert("id".into(), Value::String(id()));
    policy.insert("tenantId".into(), Value::String(tenant_id.clone()));
    policy.insert(
        "name".into(),
        Value::String(text(input.get("name"), "name", 256)?),
    );
    policy.insert("document".into(), document);
    policy.insert("version".into(), json!(1));
    policy.insert("authorityId".into(), Value::String(authority.id.clone()));
    if let Some(description) = defined(input, "description") {
        policy.insert(
            "description".into(),
            Value::String(text(Some(description), "description", 512)?),
        );
    }
    tx.insert("policies", &policy).await
}

/// Creates a policy under the caller's grant authority; shared by `policies.create` and configuration sync.
pub async fn create_policy(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    tenant: &better_iam_core::Tenant,
    input: &Value,
) -> IamResult<crate::models::Policy> {
    let input = input.as_object().cloned().unwrap_or_default();
    decode(create_policy_record(ctx, tx, principal, tenant, &input).await?)
}

/// A policy another authority attached to a role (or whose role it inherits or bound) carries denies that authority
/// relies on: its editor may not remove or change one (roles.ts assertDeniesKept).
async fn assert_policy_denies_kept(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    policy: &Record,
    document: &Value,
) -> IamResult<()> {
    let current = policy
        .get("document")
        .map(PolicyDocument::from_value)
        .transpose()?;
    let candidate = PolicyDocument::from_value(document)?;
    let before = document_deny_statements(current.as_ref());
    let after = document_deny_statements(Some(&candidate));
    let tenant_id = member_str(policy, "tenantId").to_owned();
    let policy_id = member_str(policy, "id").to_owned();
    let authority_id = policy.get("authorityId").cloned();
    assert_denies_kept_with(ctx, tx, principal, &before, &after, || async {
        let role_ids: Vec<String> = tx
            .find(
                "roles",
                &Filter::new().eq("tenantId", tenant_id.clone()),
                &find_all(),
            )
            .await?
            .into_iter()
            .filter(|role| string_list(role, "policyIds").contains(&policy_id))
            .map(|role| member_str(&role, "id").to_owned())
            .collect();
        relied_on(tx, &tenant_id, authority_id.as_ref(), role_ids).await
    })
    .await
}

/// [`update_policy`] on a raw input (`policies.update`, impact previews), answering the stored record.
pub async fn update_policy_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    input: &Map<String, Value>,
) -> IamResult<Record> {
    let tenant_id = string_member(input, "tenantId");
    let document = defined(input, "document");
    if let Some(document) = document {
        ctx.catalog
            .validate(tx.as_ref(), &tenant_id, document)
            .await?;
    }
    ctx.granting_authority(tx, principal, &tenant_id, None)
        .await?;
    let policy = ctx
        .scoped(tx, "policies", input.get("policyId"), &tenant_id)
        .await?;
    ctx.can_edit_grant_resource(tx, principal, &policy).await?;
    if policy.get("uniqueKey").and_then(Value::as_str) == Some("system:owner") {
        return Err(IamError::with_status(
            "PROTECTED_RESOURCE",
            "Owner policy is protected",
            403,
        ));
    }
    if !same_member(policy.get("version"), input.get("version")) {
        return Err(IamError::with_status(
            "VERSION_CONFLICT",
            "Policy version changed",
            409,
        ));
    }
    if document.is_none() && !input.contains_key("name") && !input.contains_key("description") {
        return Err(IamError::new("INVALID_INPUT", "Nothing to update"));
    }
    if let Some(document) = document {
        assert_policy_denies_kept(ctx, tx, principal, &policy, document).await?;
    }
    tx.insert("policyVersions", &archived_version(&policy))
        .await?;
    let mut next = policy.clone();
    if let Some(document) = document.filter(|document| !document.is_null()) {
        next.insert("document".into(), document.clone());
    }
    let version = policy
        .get("version")
        .and_then(as_number)
        .unwrap_or(f64::NAN);
    next.insert("version".into(), number(version + 1.0));
    if let Some(name) = defined(input, "name") {
        next.insert("name".into(), Value::String(text(Some(name), "name", 256)?));
    }
    if let Some(description) = defined(input, "description") {
        next.insert(
            "description".into(),
            Value::String(text(Some(description), "description", 512)?),
        );
    }
    tx.put("policies", &next).await
}

/// Updates a policy as a new version (optimistic concurrency on `version`); the previous version is retained.
pub async fn update_policy(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    input: &Value,
) -> IamResult<crate::models::Policy> {
    let input = input.as_object().cloned().unwrap_or_default();
    decode(update_policy_record(ctx, tx, principal, &input).await?)
}

/// [`delete_policy`] for a stored record.
pub async fn delete_policy_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    policy: &Record,
) -> IamResult<()> {
    ctx.can_edit_grant_resource(tx, principal, policy).await?;
    if policy.get("uniqueKey").and_then(Value::as_str) == Some("system:owner") {
        return Err(IamError::with_status(
            "PROTECTED_RESOURCE",
            "Owner policy is protected",
            403,
        ));
    }
    let policy_id = member_str(policy, "id").to_owned();
    if tx
        .find(
            "roles",
            &Filter::new().eq("tenantId", member_str(policy, "tenantId")),
            &find_all(),
        )
        .await?
        .iter()
        .any(|role| string_list(role, "policyIds").contains(&policy_id))
    {
        return Err(IamError::with_status(
            "RESOURCE_IN_USE",
            "Detach policy before deletion",
            409,
        ));
    }
    tx.delete("policies", &policy_id).await
}

/// Deletes a policy that no role still attaches; the Owner policy is protected.
pub async fn delete_policy(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    policy: &crate::models::Policy,
) -> IamResult<()> {
    delete_policy_record(ctx, tx, principal, &encode(policy)).await
}
