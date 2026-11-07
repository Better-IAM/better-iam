//! Port of `packages/server/src/api/impact.ts`.
//!
//! Change impact preview: before editing a role or policy (or deleting a role), see who would gain or lose which
//! actions on which resources. The change is applied exactly as the real call would apply it — same validation and
//! the same edit rights — inside a transaction that is always rolled back, and every holder's decisions are compared
//! before and after, so inheritance, authority ceilings, boundaries, conditions, and eligibility all count.

use std::sync::{Arc, Mutex};

use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError, IamResult, IamStoreExt,
    Identity, IdentityStatus, Record, ResourceRef, Tenant,
};
use better_iam_types::api::impact;
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, decide_on};
use crate::invariants::{AccessInvariant, InvariantResult, evaluate_invariants};
use crate::js::truthy;
use crate::models::{Binding, GroupMember, Role};
use crate::options::{AuthorizationRequest, ResolvedResource, ResourceTarget};
use crate::port::decode;
use crate::validation::{object, strings, text};

const MAX_HOLDERS: usize = 200;
const MAX_RESOURCES: usize = 10;

/// The `impact` API group (`createImpactApi(ctx)`): one method per route `impact/{method}`.
pub struct ImpactApi {
    ctx: Arc<ServerContext>,
}

/// `createImpactApi(ctx)`.
pub fn create_impact_api(ctx: &Arc<ServerContext>) -> IamResult<ImpactApi> {
    Ok(ImpactApi { ctx: ctx.clone() })
}

/// The error that rolls the simulation transaction back (`class Rollback`); its result travels in a slot beside it.
fn rollback_error() -> IamError {
    IamError::with_status("IMPACT_ROLLBACK", "rollback", 500)
}

async fn find_records(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

fn member_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// `{ id, name, mode }` of an invariant result, leaving out members the invariant does not have.
fn invariant_summary(invariant: &Value) -> Map<String, Value> {
    let mut summary = Map::new();
    for key in ["id", "name", "mode"] {
        if let Some(value) = invariant.get(key) {
            summary.insert(key.into(), value.clone());
        }
    }
    summary
}

/// Invariants whose violations grew (broken) or disappeared (fixed) between two evaluations; without `detailed`,
/// only how many.
fn compare_invariants(
    before: &[InvariantResult],
    after: &[InvariantResult],
    detailed: bool,
) -> Value {
    let previous: IndexMap<String, &InvariantResult> = before
        .iter()
        .map(|result| {
            (
                member_str(&result.invariant, "id")
                    .unwrap_or_default()
                    .to_owned(),
                result,
            )
        })
        .collect();
    let mut broken: Vec<Value> = Vec::new();
    let mut fixed: Vec<Value> = Vec::new();
    for result in after {
        let id = member_str(&result.invariant, "id").unwrap_or_default();
        let earlier = previous.get(id);
        let known: IndexSet<String> = earlier
            .map(|earlier| {
                earlier
                    .violations
                    .iter()
                    .map(|violation| crate::js::js_string(violation.identity.get("id")))
                    .collect()
            })
            .unwrap_or_default();
        let added: Vec<Value> = result
            .violations
            .iter()
            .filter(|violation| {
                !known.contains(&crate::js::js_string(violation.identity.get("id")))
            })
            .map(|violation| serde_json::to_value(violation).unwrap_or(Value::Null))
            .collect();
        if !added.is_empty() {
            let mut entry = invariant_summary(&result.invariant);
            entry.insert("violations".into(), Value::Array(added));
            broken.push(Value::Object(entry));
        } else if result.passed
            && earlier.is_some_and(|earlier| !earlier.passed && !truthy(earlier.error.as_ref()))
        {
            fixed.push(Value::Object(invariant_summary(&result.invariant)));
        }
    }
    let (broken_count, fixed_count) = (broken.len(), fixed.len());
    if detailed {
        json!({
            "detailed": detailed,
            "brokenCount": broken_count,
            "fixedCount": fixed_count,
            "broken": broken,
            "fixed": fixed,
        })
    } else {
        json!({
            "detailed": detailed,
            "brokenCount": broken_count,
            "fixedCount": fixed_count,
            "broken": [],
            "fixed": [],
        })
    }
}

/// Every role whose grants include `roleIds` (the roles themselves and their inheritors, transitively).
fn inheritors(roles: &[Role], role_ids: &IndexSet<String>) -> IndexSet<String> {
    let mut affected = role_ids.clone();
    let mut grew = true;
    while grew {
        grew = false;
        for role in roles {
            if !affected.contains(&role.id)
                && role
                    .inherits
                    .as_ref()
                    .is_some_and(|parents| parents.iter().any(|parent| affected.contains(parent)))
            {
                affected.insert(role.id.clone());
                grew = true;
            }
        }
    }
    affected
}

/// The active people and service accounts of the tenant holding one of `roleIds`, directly or through a group, by ID.
async fn holders(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    role_ids: &IndexSet<String>,
) -> IamResult<Vec<Identity>> {
    let mut bindings: Vec<Binding> = Vec::new();
    for record in find_records(tx, "bindings", Filter::new().eq("tenantId", tenant_id)).await? {
        let binding: Binding = decode(record)?;
        if role_ids.contains(&binding.role_id) && !ctx.expired_binding(&binding) {
            bindings.push(binding);
        }
    }
    let mut ids: IndexSet<String> = IndexSet::new();
    let mut groups: IndexSet<String> = IndexSet::new();
    for binding in bindings {
        if binding.subject_type == "identity" {
            ids.insert(binding.subject_id);
        } else {
            groups.insert(binding.subject_id);
        }
    }
    if !groups.is_empty() {
        for record in
            find_records(tx, "groupMembers", Filter::new().eq("tenantId", tenant_id)).await?
        {
            let member: GroupMember = decode(record)?;
            if groups.contains(&member.group_id) && ctx.live_membership(&member) {
                ids.insert(member.identity_id);
            }
        }
    }
    let mut sorted: Vec<String> = ids.into_iter().collect();
    crate::js::sort_strings(&mut sorted);
    let mut people: Vec<Identity> = Vec::new();
    for identity_id in sorted {
        let Some(record) = tx.get("identities", &identity_id).await? else {
            continue;
        };
        let identity: Identity = decode(record)?;
        if identity.tenant_id == tenant_id && identity.status == IdentityStatus::Active {
            people.push(identity);
        }
    }
    Ok(people)
}

/// `identityId -> resource -> Set(action)`.
type Allowed = IndexMap<String, IndexMap<String, IndexSet<String>>>;

/// The allowed actions per identity and resource.
async fn allowed(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant: &Tenant,
    people: &[Identity],
    resources: &[ResolvedResource],
    actions: &[String],
    assume_mfa: bool,
) -> IamResult<Allowed> {
    let decisions = ctx.decisions()?;
    let mut result: Allowed = IndexMap::new();
    for identity in people {
        let principal = decisions.simulated_principal(identity, assume_mfa);
        let prepared = decisions
            .prepare_decision(
                tx,
                &principal,
                tenant,
                actions.first().map(String::as_str).unwrap_or_default(),
            )
            .await?;
        let mut by_resource: IndexMap<String, IndexSet<String>> = IndexMap::new();
        for resource in resources {
            let mut set: IndexSet<String> = IndexSet::new();
            for action in actions {
                let decision = decide_on(&prepared, resource, Some(action))?;
                if decision.allowed {
                    set.insert(action.clone());
                }
            }
            by_resource.insert(format!("{}/{}", resource.kind, resource.id), set);
        }
        result.insert(identity.id.clone(), by_resource);
    }
    Ok(result)
}

/// Applies the change as the real call would, after checking the caller holds the permission that call needs (not
/// only the edit rights the helpers check).
async fn apply(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    change: &Map<String, Value>,
) -> IamResult<()> {
    if truthy(change.get("role")) {
        let role = change.get("role").and_then(Value::as_object);
        let role_id = crate::js::js_string(role.and_then(|role| role.get("roleId")));
        crate::api::packages::allow(
            ctx,
            tx,
            principal,
            tenant_id,
            "iam:roles:update",
            &role_id,
            "update this role",
        )
        .await?;
        let mut update = role.cloned().unwrap_or_default();
        update.insert("tenantId".into(), json!(tenant_id));
        crate::api::roles::update_role_record(ctx, tx, principal, &update).await?;
    } else if truthy(change.get("policy")) {
        let change_policy = change.get("policy");
        let policy = ctx
            .scoped(
                tx,
                "policies",
                crate::js::member(change_policy, "policyId"),
                tenant_id,
            )
            .await?;
        let policy_id = crate::js::js_string(policy.get("id"));
        crate::api::packages::allow(
            ctx,
            tx,
            principal,
            tenant_id,
            "iam:policies:update",
            &policy_id,
            "update this policy",
        )
        .await?;
        let mut update = Map::new();
        update.insert("tenantId".into(), json!(tenant_id));
        update.insert("policyId".into(), json!(policy_id));
        if let Some(version) = policy.get("version") {
            update.insert("version".into(), version.clone());
        }
        if let Some(document) = crate::js::member(change_policy, "document") {
            update.insert("document".into(), document.clone());
        }
        crate::api::policies::update_policy_record(ctx, tx, principal, &update).await?;
    } else {
        let role = ctx
            .scoped(tx, "roles", change.get("deleteRole"), tenant_id)
            .await?;
        let role_id = crate::js::js_string(role.get("id"));
        crate::api::packages::allow(
            ctx,
            tx,
            principal,
            tenant_id,
            "iam:roles:delete",
            &role_id,
            "delete this role",
        )
        .await?;
        crate::api::roles::delete_role_record(ctx, tx, principal, &role).await?;
    }
    Ok(())
}

impl ImpactApi {
    /// `impact/preview`: previews a role update (`change.role`, as `roles.update` takes it), a policy document change
    /// (`change.policy`), or a role deletion (`change.deleteRole`) against 1-10 `resources`. For every holder of the
    /// affected roles (at most 200), reports the actions gained and lost per resource; `actions` (at most 200)
    /// narrows the comparison, which otherwise covers every known action. `assumeMfa` evaluates holders as if
    /// MFA-verified. Nothing is saved. Requires iam:policies:simulate, plus the rights the change itself needs; which
    /// invariants break or pass is detailed only for callers allowed iam:invariants:read (others see counts).
    pub async fn preview(
        &self,
        credential: &CredentialInput,
        input: Body<impact::PreviewInput>,
    ) -> IamResult<Reply<impact::PreviewOutput>> {
        let ctx = &self.ctx;
        let change = object(input.get("change"))?.clone();
        let kinds = ["role", "policy", "deleteRole"]
            .iter()
            .filter(|key| change.get(**key).is_some())
            .count();
        if kinds != 1 {
            return Err(IamError::new(
                "INVALID_INPUT",
                "Provide exactly one of role, policy, or deleteRole",
            ));
        }
        if truthy(change.get("role")) {
            text(object(change.get("role"))?.get("roleId"), "roleId", 256)?;
        }
        if truthy(change.get("policy")) {
            text(
                object(change.get("policy"))?.get("policyId"),
                "policyId",
                256,
            )?;
            object(crate::js::member(change.get("policy"), "document"))?;
        }
        if change.get("deleteRole").is_some() {
            text(change.get("deleteRole"), "deleteRole", 256)?;
        }
        let items = match input.get("resources") {
            Some(Value::Array(items)) if !items.is_empty() && items.len() <= MAX_RESOURCES => items,
            _ => {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    format!("Provide 1-{MAX_RESOURCES} resources"),
                ));
            }
        };
        let mut references: Vec<ResourceTarget> = Vec::new();
        for item in items {
            let reference = object(Some(item))?;
            references.push(ResourceTarget {
                kind: text(reference.get("type"), "resource type", 256)?,
                id: text(reference.get("id"), "resource id", 256)?,
            });
        }
        let requested: Option<Vec<String>> = match input.get("actions") {
            None => None,
            Some(actions) => Some(crate::js::unique(strings(Some(actions), "actions")?)),
        };
        if requested
            .as_ref()
            .is_some_and(|requested| requested.is_empty() || requested.len() > 200)
        {
            return Err(IamError::new("INVALID_INPUT", "Compare 1-200 actions"));
        }
        let assume_mfa = input.get("assumeMfa") == Some(&Value::Bool(true));
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        // Authorize (and audit) the preview itself; the simulation runs in its own transaction below.
        let caller: Mutex<Option<(AuthenticatedPrincipal, bool)>> = Mutex::new(None);
        {
            let caller = &caller;
            let tenant_id = &tenant_id;
            let mutation: Mutation<'_> =
                Box::new(move |MutationContext { tx, principal, .. }| {
                    Box::pin(async move {
                        // The change rights below are checked for the session holder alone, so "view as" cannot borrow
                        // them.
                        if principal
                            .session
                            .impersonator_id
                            .as_deref()
                            .is_some_and(|id| !id.is_empty())
                        {
                            return Err(IamError::with_status(
                                "IMPERSONATION_RESTRICTED",
                                "Change previews are not available while impersonating",
                                403,
                            )
                            .into());
                        }
                        // Invariant names, modes and violators are for those who may read invariants, decided before the
                        // change is simulated so the change cannot grant the right to see them.
                        let invariants = ctx
                            .decisions()?
                            .decide(
                                &tx,
                                &principal,
                                &AuthorizationRequest {
                                    credential: CredentialInput::default(),
                                    tenant_id: tenant_id.clone(),
                                    action: "iam:invariants:read".into(),
                                    resource: ResourceTarget {
                                        kind: "iam".into(),
                                        id: tenant_id.clone(),
                                    },
                                },
                                true,
                            )
                            .await?;
                        let details = invariants.allowed;
                        *caller.lock().unwrap_or_else(|e| e.into_inner()) =
                            Some((principal.clone(), details));
                        Ok(json!({ "invariantDetails": details }))
                    })
                });
            ctx.operations()?
                .operation(
                    credential,
                    input.get("tenantId"),
                    "iam:policies:simulate",
                    tenant_id,
                    mutation,
                    false,
                )
                .await?;
        }
        let Some((principal, invariant_details)) =
            caller.lock().unwrap_or_else(|e| e.into_inner()).take()
        else {
            return Err(crate::js::internal_error());
        };
        let slot: Mutex<Option<Value>> = Mutex::new(None);
        let outcome = ctx
            .store
            .transaction(|tx| {
                let slot = &slot;
                let tenant_id = &tenant_id;
                let change = &change;
                let references = &references;
                let requested = &requested;
                let principal = &principal;
                async move {
                    let tenant = ctx.tenant(&tx, tenant_id).await?;
                    let roles: Vec<Role> = find_records(
                        &tx,
                        "roles",
                        Filter::new().eq("tenantId", tenant_id.as_str()),
                    )
                    .await?
                    .into_iter()
                    .map(decode)
                    .collect::<IamResult<_>>()?;
                    let mut changed: IndexSet<String> = IndexSet::new();
                    if truthy(change.get("role")) {
                        changed.insert(crate::js::js_string(crate::js::member(
                            change.get("role"),
                            "roleId",
                        )));
                    }
                    if truthy(change.get("deleteRole")) {
                        changed.insert(crate::js::js_string(change.get("deleteRole")));
                    }
                    if truthy(change.get("policy")) {
                        let policy_id = crate::js::js_string(crate::js::member(
                            change.get("policy"),
                            "policyId",
                        ));
                        for role in &roles {
                            if role.policy_ids.contains(&policy_id) {
                                changed.insert(role.id.clone());
                            }
                        }
                    }
                    let affected = inheritors(&roles, &changed);
                    let everyone = holders(ctx, &tx, tenant_id, &affected).await?;
                    let people: Vec<Identity> =
                        everyone.iter().take(MAX_HOLDERS).cloned().collect();
                    let decisions = ctx.decisions()?;
                    let mut resources: Vec<ResolvedResource> = Vec::new();
                    for reference in references {
                        resources.push(
                            decisions
                                .resolve(
                                    &tx,
                                    &ResourceRef {
                                        tenant_id: tenant_id.clone(),
                                        kind: reference.kind.clone(),
                                        id: reference.id.clone(),
                                    },
                                    true,
                                    None,
                                    None,
                                )
                                .await?,
                        );
                    }
                    let mut actions: Vec<String> = match requested {
                        Some(requested) => {
                            for action in requested {
                                if !ctx.catalog.known_action(&*tx, tenant_id, action).await? {
                                    return Err(IamError::new(
                                        "INVALID_ACTION",
                                        format!("Unknown action {action}"),
                                    ));
                                }
                            }
                            requested.clone()
                        }
                        None => {
                            let mut names: IndexSet<String> =
                                ctx.catalog.actions.iter().cloned().collect();
                            for record in find_records(
                                &tx,
                                "actions",
                                Filter::new().eq("tenantId", tenant_id.as_str()),
                            )
                            .await?
                            {
                                names.insert(crate::js::js_string(record.get("name")));
                            }
                            names.into_iter().collect()
                        }
                    };
                    crate::js::sort_strings(&mut actions);
                    let before =
                        allowed(ctx, &tx, &tenant, &people, &resources, &actions, assume_mfa)
                            .await?;
                    let guardrails: Vec<AccessInvariant> = find_records(
                        &tx,
                        "accessInvariants",
                        Filter::new().eq("tenantId", tenant_id.as_str()),
                    )
                    .await?
                    .into_iter()
                    .map(decode)
                    .collect::<IamResult<_>>()?;
                    let invariants_before =
                        evaluate_invariants(ctx, &tx, &tenant, &guardrails, false).await?;
                    apply(ctx, &tx, principal, tenant_id, change).await?;
                    let after =
                        allowed(ctx, &tx, &tenant, &people, &resources, &actions, assume_mfa)
                            .await?;
                    let invariants_after =
                        evaluate_invariants(ctx, &tx, &tenant, &guardrails, false).await?;
                    let mut identities: Vec<Value> = Vec::new();
                    let mut gained_total = 0usize;
                    let mut lost_total = 0usize;
                    let empty = IndexSet::new();
                    for identity in &people {
                        let mut changes: Vec<Value> = Vec::new();
                        for resource in &resources {
                            let key = format!("{}/{}", resource.kind, resource.id);
                            let was = before
                                .get(&identity.id)
                                .and_then(|by| by.get(&key))
                                .unwrap_or(&empty);
                            let now = after
                                .get(&identity.id)
                                .and_then(|by| by.get(&key))
                                .unwrap_or(&empty);
                            let gained: Vec<&String> =
                                now.iter().filter(|action| !was.contains(*action)).collect();
                            let lost: Vec<&String> =
                                was.iter().filter(|action| !now.contains(*action)).collect();
                            if gained.is_empty() && lost.is_empty() {
                                continue;
                            }
                            gained_total += gained.len();
                            lost_total += lost.len();
                            changes
                                .push(json!({ "resource": key, "gained": gained, "lost": lost }));
                        }
                        if !changes.is_empty() {
                            identities.push(json!({
                                "identity": {
                                    "id": identity.id,
                                    "name": identity.email.as_deref().unwrap_or(&identity.name),
                                },
                                "changes": changes,
                            }));
                        }
                    }
                    let role_by_id: IndexMap<&str, &Role> =
                        roles.iter().map(|role| (role.id.as_str(), role)).collect();
                    let mut summaries: Vec<(String, String)> = affected
                        .iter()
                        .map(|role_id| {
                            (
                                role_id.clone(),
                                role_by_id
                                    .get(role_id.as_str())
                                    .map(|role| role.name.clone())
                                    .unwrap_or_else(|| role_id.clone()),
                            )
                        })
                        .collect();
                    summaries.sort_by(|a, b| crate::metrics::locale_compare(&a.1, &b.1));
                    let result = json!({
                        "roles": summaries
                            .iter()
                            .map(|(id, name)| json!({ "id": id, "name": name }))
                            .collect::<Vec<_>>(),
                        "evaluated": people.len(),
                        "truncated": everyone.len() > people.len(),
                        "identities": identities,
                        "gainedTotal": gained_total,
                        "lostTotal": lost_total,
                        "invariants": compare_invariants(
                            &invariants_before,
                            &invariants_after,
                            invariant_details,
                        ),
                    });
                    *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(result);
                    Err::<(), IamError>(rollback_error())
                }
            })
            .await;
        match outcome {
            Err(error) if error == rollback_error() => {
                if let Some(result) = slot.lock().unwrap_or_else(|e| e.into_inner()).take() {
                    return Ok(Reply::json(result));
                }
                Err(error)
            }
            Err(error) => Err(error),
            Ok(()) => Err(IamError::with_status(
                "INTERNAL_ERROR",
                "Impact preview did not complete",
                500,
            )),
        }
    }
}
