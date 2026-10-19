//! Port of `packages/server/src/api/filters.ts`: data filtering. Which resources of a type may a principal perform an
//! action on, as a filter for the application's own queries (compile it with `filter_to_sql`, `filter_to_prisma`,
//! `filter_to_mongo`, or test rows with `filter_matches`).

use std::sync::Arc;

use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, IamError, IamResult, IamStoreExt, Identity,
    IdentityStatus, PlanInput, PlanKind, PlanPath, PlanRelation, ResourcePlan, Tenant, fixed_plan,
    intersect_plans, plan_resources,
};
use better_iam_types::api::filters;
use serde_json::{Map, Value};

use crate::api::{Body, Reply};
use crate::catalog::{is_internal_resource_type, is_resource_type_name};
use crate::context::{ServerContext, Store};
use crate::context_keys::RESOURCE_SERVER_KEYS;
use crate::contracts::{MutationContext, PreparedDecision, is_root_override};
use crate::decisions::impersonating_actor;
use crate::observe::SpanKind;
use crate::validation::text;

/// `planTarget(input)`: the action and resource type of a plan request.
fn plan_target(input: &Map<String, Value>) -> IamResult<(String, String)> {
    let action = text(input.get("action"), "action", 256)?;
    let kind = text(input.get("type"), "type", 64)?;
    if !is_resource_type_name(&kind) || is_internal_resource_type(&kind) {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Plans cover application and managed resource types",
        ));
    }
    // Platform administration (`iam:*`) resolves its own resources; plan application actions only.
    if action.starts_with("iam:") {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Plans cover application actions, not iam:* administration",
        ));
    }
    Ok((action, kind))
}

/// `principalPlan(ctx, tx, principal, realm, action, type)`: the plan for one principal, mirroring
/// `decisions.decide` for every resource of the type.
async fn principal_plan(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    realm: &Tenant,
    action: &str,
    kind: &str,
) -> IamResult<ResourcePlan> {
    if !ctx
        .catalog
        .known_action(tx.as_ref(), &realm.id, action)
        .await?
    {
        return Ok(fixed_plan(false));
    }
    let prepared = ctx
        .decisions()?
        .prepare_decision(tx, principal, realm, action)
        .await?;
    let inputs = match &prepared {
        PreparedDecision::Fixed(decision) => return Ok(fixed_plan(decision.allowed)),
        PreparedDecision::Evaluator { inputs, .. } => inputs.clone(),
    };
    let Some(inputs) = inputs else {
        return Ok(fixed_plan(false));
    };
    // Mandatory access control (clearances.ts): the resources of the type the session may read at all, AND-ed with
    // whatever the policies (or root's override) allow.
    let mandatory = match &inputs.mandatory {
        Some(mandatory) => Some(mandatory.filter(kind, Some(action)).await?),
        None => None,
    };
    if is_root_override(&prepared) {
        return Ok(match mandatory {
            Some(filter) => intersect_plans(
                &fixed_plan(true),
                &ResourcePlan {
                    kind: PlanKind::Conditional,
                    filter,
                },
            ),
            None => fixed_plan(true),
        });
    }
    if let Some(confirm) = &inputs.confirm
        && confirm(action, kind, "\u{0}plan").is_some()
    {
        return Ok(fixed_plan(false));
    }
    plan_resources(&PlanInput {
        action: action.to_owned(),
        resource_type: kind.to_owned(),
        tenant_id: realm.id.clone(),
        context: inputs.context.clone(),
        denies: inputs.denies.clone(),
        boundaries: inputs.boundaries.clone(),
        paths: inputs
            .paths
            .iter()
            .map(|path| PlanPath {
                grants: path.grants.clone(),
                boundaries: path.boundaries.clone(),
            })
            .collect(),
        relations: Some(
            inputs
                .held
                .iter()
                .map(|(held, relations)| {
                    let slash = held.find('/').unwrap_or(held.len());
                    PlanRelation {
                        kind: held[..slash].to_owned(),
                        id: held.get(slash + 1..).unwrap_or("").to_owned(),
                        relations: relations.iter().cloned().collect(),
                    }
                })
                .collect(),
        ),
        mandatory,
        // A label's keys are derived per resource, not read from the row: conditions on them cannot be planned.
        derived_resource_keys: ctx.config.clearances.as_ref().map(|_| {
            RESOURCE_SERVER_KEYS
                .keys()
                .map(|key| (*key).to_owned())
                .collect()
        }),
    })
}

/// `callerPlan(...)`: the caller's plan; a "view as" session gets only what the administrator behind it could reach.
async fn caller_plan(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    realm: &Tenant,
    action: &str,
    kind: &str,
) -> IamResult<ResourcePlan> {
    let own = principal_plan(ctx, tx, principal, realm, action, kind).await?;
    match impersonating_actor(tx, principal).await? {
        Some(actor) => Ok(intersect_plans(
            &own,
            &principal_plan(ctx, tx, &actor, realm, action, kind).await?,
        )),
        None => Ok(own),
    }
}

/// `{ tenantId, action, type, ...plan }` (`ResourcePlanResult`).
fn plan_result(tenant_id: &str, action: &str, kind: &str, plan: &ResourcePlan) -> Value {
    let mut out = Map::new();
    out.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    out.insert("action".into(), Value::String(action.to_owned()));
    out.insert("type".into(), Value::String(kind.to_owned()));
    if let Ok(Value::Object(plan)) = serde_json::to_value(plan) {
        for (key, value) in plan {
            out.insert(key, value);
        }
    }
    Value::Object(out)
}

/// The `filters` API group (`createFiltersApi(ctx)`).
pub struct FiltersApi {
    ctx: Arc<ServerContext>,
}

/// `createFiltersApi(ctx)`.
pub fn create_filters_api(ctx: &Arc<ServerContext>) -> IamResult<FiltersApi> {
    Ok(FiltersApi { ctx: ctx.clone() })
}

impl FiltersApi {
    /// `filters/plan`: the caller's plan for `action` on resources of `type`: `always`, `never`, or `conditional`
    /// with a filter over `id` and the resource's attributes. Needs only a session of the tenant; not audited.
    pub async fn plan(
        &self,
        credential: &CredentialInput,
        input: Body<filters::PlanInput>,
    ) -> IamResult<Reply<filters::PlanOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let (action, kind) = plan_target(&input)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let result = ctx
            .store
            .transaction(|tx| {
                let (authenticated, tenant_id, action, kind) =
                    (&authenticated, &tenant_id, &action, &kind);
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    let realm = ctx.tenant(&tx, tenant_id).await?;
                    let plan = caller_plan(ctx, &tx, &principal, &realm, action, kind).await?;
                    Ok(plan_result(&realm.id, action, kind, &plan))
                }
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `filters/planFor`: an administrator's preview of another identity's plan, as `policies.simulate` does for one
    /// decision. `assumeMfa` plans as if the identity had signed in with MFA. Requires iam:policies:simulate on the
    /// identity; audited as that action.
    pub async fn plan_for(
        &self,
        credential: &CredentialInput,
        input: Body<filters::PlanForInput>,
    ) -> IamResult<Reply<filters::PlanForOutput>> {
        let ctx = self.ctx.clone();
        let (action, kind) = plan_target(&input)?;
        let identity_id = text(input.get("identityId"), "identityId", 256)?;
        let assume_mfa = input.get("assumeMfa") == Some(&Value::Bool(true));
        let raw_identity = input.get("identityId").cloned();
        let mutation: crate::contracts::Mutation<'_> = Box::new(move |call: MutationContext| {
            Box::pin(async move {
                let MutationContext {
                    tx, tenant: realm, ..
                } = call;
                let record = ctx
                    .scoped(&tx, "identities", raw_identity.as_ref(), &realm.id)
                    .await?;
                let identity: Identity = crate::port::decode(record)?;
                if identity.status == IdentityStatus::Deleted {
                    return Err(
                        IamError::with_status("NOT_FOUND", "Identity not found", 404).into(),
                    );
                }
                let principal = ctx.decisions()?.simulated_principal(&identity, assume_mfa);
                let plan = principal_plan(&ctx, &tx, &principal, &realm, &action, &kind).await?;
                Ok(plan_result(&realm.id, &action, &kind, &plan))
            })
        });
        let result = self
            .ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:policies:simulate",
                &identity_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// `PlanResourcesRequest`: a plan request for the caller: the credential and which resources, as `authorize` takes
/// them.
#[derive(Debug, Clone, Default)]
pub struct PlanResourcesRequest {
    pub credential: CredentialInput,
    pub tenant_id: String,
    pub action: String,
    /// The resource type whose rows are filtered.
    pub kind: String,
}

/// `createPlanRuntime(ctx)`: `iam.planResources`, the caller's plan in process.
pub struct PlanRuntime {
    ctx: Arc<ServerContext>,
    api: FiltersApi,
}

/// `createPlanRuntime(ctx)`.
pub fn create_plan_runtime(ctx: &Arc<ServerContext>) -> IamResult<PlanRuntime> {
    Ok(PlanRuntime {
        ctx: ctx.clone(),
        api: create_filters_api(ctx)?,
    })
}

impl PlanRuntime {
    /// `iam.planResources(request)`: a fixed span name, since actions are caller-controlled and would otherwise mint
    /// unbounded metric series.
    pub async fn plan_resources(&self, request: &PlanResourcesRequest) -> IamResult<Value> {
        let mut body = Map::new();
        body.insert("tenantId".into(), Value::String(request.tenant_id.clone()));
        body.insert("action".into(), Value::String(request.action.clone()));
        body.insert("type".into(), Value::String(request.kind.clone()));
        let work = async {
            self.api
                .plan(&request.credential, Body::new(body))
                .await?
                .into_value()
        };
        self.ctx
            .observe
            .span(
                SpanKind::ListAccessible,
                "planResources",
                Some(&request.tenant_id),
                work,
                None,
                None,
            )
            .await
    }

    /// The conformance server's `call` (`planResources` is the runtime itself: `call("", [request])`).
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        if !method.is_empty() {
            return None;
        }
        let request = args.first().cloned().unwrap_or(Value::Null);
        let string = |key: &str| {
            request
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        };
        let headers = request
            .get("headers")
            .and_then(Value::as_object)
            .map(|headers| {
                headers
                    .iter()
                    .filter_map(|(name, value)| {
                        value.as_str().map(|value| (name.clone(), value.to_owned()))
                    })
                    .collect()
            });
        let token = request
            .get("token")
            .and_then(Value::as_str)
            .map(str::to_owned);
        Some(
            self.plan_resources(&PlanResourcesRequest {
                credential: CredentialInput { headers, token },
                tenant_id: string("tenantId"),
                action: string("action"),
                kind: string("type"),
            })
            .await,
        )
    }
}
