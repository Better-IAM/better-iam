//! Port of `packages/server/src/api/access-paths.ts`.
//!
//! Self-service access paths: when a person is denied, the ways they could become allowed on their own — step up to
//! MFA, accept pending terms of use, activate one of their eligible (just-in-time) bindings, or request a
//! requestable access package — each confirmed by applying it inside a transaction that is always rolled back and
//! re-running the ordinary decision. Needs only an ordinary session of the tenant; activation and package options are
//! listed only when the caller may use them (`iam:bindings:activate`, `iam:packages:request`).

use std::sync::{Arc, Mutex};

use better_iam_core::boxed;
use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Decision, Filter, FindOptions, IamError, IamResult,
    IamStoreExt, IdentityKind, Record, Tenant,
};
use better_iam_types::api::access_paths;
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::agreements::{Agreement, AgreementAcceptance, acceptance_current};
use crate::api::{Body, Reply};
use crate::context::{ServerContext, Store};
use crate::models::{AccessPackage, Binding, BindingActivation, GroupMember, Role};
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::port::decode;
use crate::session_kinds::acts_in_own_right;
use crate::utils::id;
use crate::validation::{object, text};

const MAX_CANDIDATES: usize = 50;

/// The `accessPaths` API group (`createAccessPathsApi(ctx)`): one method per route `accessPaths/{method}`.
pub struct AccessPathsApi {
    ctx: Arc<ServerContext>,
}

/// `createAccessPathsApi(ctx)`.
pub fn create_access_paths_api(ctx: &Arc<ServerContext>) -> IamResult<AccessPathsApi> {
    Ok(AccessPathsApi { ctx: ctx.clone() })
}

/// The error that rolls the simulation transaction back (`class Rollback`); its result travels in a slot beside it.
fn rollback_error() -> IamError {
    IamError::with_status("ACCESS_PATHS_ROLLBACK", "rollback", 500)
}

async fn find_records(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

/// `allowed(tx, principal, tenantId, action, resource)`.
async fn allowed(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    action: &str,
    resource: &ResourceTarget,
) -> IamResult<Decision> {
    ctx.decisions()?
        .decide(
            tx,
            principal,
            &AuthorizationRequest {
                credential: CredentialInput::default(),
                tenant_id: tenant_id.to_owned(),
                action: action.to_owned(),
                resource: resource.clone(),
            },
            action.starts_with("iam:"),
        )
        .await
}

/// `may(tx, principal, tenantId, action, resourceId)`.
async fn may(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    action: &str,
    resource_id: &str,
) -> IamResult<bool> {
    Ok(ctx
        .decisions()?
        .decide(
            tx,
            principal,
            &AuthorizationRequest {
                credential: CredentialInput::default(),
                tenant_id: tenant_id.to_owned(),
                action: action.to_owned(),
                resource: ResourceTarget {
                    kind: "iam".into(),
                    id: resource_id.to_owned(),
                },
            },
            true,
        )
        .await?
        .allowed)
}

/// `paths(tx, principal, tenant, action, resource)`.
async fn paths(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant: &Tenant,
    action: &str,
    resource: &ResourceTarget,
) -> IamResult<Value> {
    let tenant_id = tenant.id.as_str();
    let identity_id = principal.identity.id.as_str();
    let now = ctx.now();
    let check = |who: AuthenticatedPrincipal| async move {
        Ok::<bool, IamError>(
            boxed(|| allowed(ctx, tx, &who, tenant_id, action, resource))
                .await?
                .allowed,
        )
    };
    let base = boxed(|| allowed(ctx, tx, principal, tenant_id, action, resource)).await?;
    if base.allowed {
        return Ok(json!({ "allowed": true, "reason": base.reason, "paths": [] }));
    }
    // Mandatory access control (security clearances): nothing a person can do on their own lifts a clearance refusal,
    // and naming a way would reveal that the resource is labeled above them.
    if base.reason == "CLEARANCE_REQUIRED" {
        return Ok(json!({ "allowed": false, "reason": "ACCESS_DENIED", "paths": [] }));
    }
    let mut found: Vec<Value> = Vec::new();

    // A second factor.
    if !principal.session.mfa {
        let mut stepped = principal.clone();
        stepped.session.mfa = true;
        if boxed(|| check(stepped)).await? {
            found.push(json!({ "kind": "mfa" }));
        }
    }

    // Required terms of use not yet accepted (simulated as accepted, then removed again).
    let agreements: Vec<Agreement> =
        boxed(|| find_records(tx, "agreements", Filter::new().eq("tenantId", tenant_id)))
            .await?
            .into_iter()
            .map(decode)
            .collect::<IamResult<_>>()?;
    if !agreements.is_empty() && principal.identity.kind == IdentityKind::User {
        let mut acceptances: IndexMap<String, (AgreementAcceptance, Record)> = IndexMap::new();
        for record in boxed(|| {
            find_records(
                tx,
                "agreementAcceptances",
                Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("identityId", identity_id),
            )
        })
        .await?
        {
            let acceptance: AgreementAcceptance = decode(record.clone())?;
            acceptances.insert(acceptance.agreement_id.clone(), (acceptance, record));
        }
        let owed: Vec<&Agreement> = agreements
            .iter()
            .filter(|agreement| {
                agreement.required
                    && !acceptance_current(
                        agreement,
                        acceptances.get(&agreement.id).map(|(typed, _)| typed),
                        now,
                    )
            })
            .collect();
        if !owed.is_empty() {
            let mut written: Vec<(String, Option<Record>)> = Vec::new();
            for agreement in &owed {
                let acceptance_id = format!("{}:{identity_id}", agreement.id);
                let previous = acceptances.get(&agreement.id).map(|(_, raw)| raw.clone());
                let mut record = Map::new();
                record.insert("id".into(), json!(acceptance_id));
                record.insert("tenantId".into(), json!(tenant_id));
                record.insert("agreementId".into(), json!(agreement.id));
                record.insert("identityId".into(), json!(identity_id));
                record.insert("version".into(), crate::js::number(agreement.version));
                record.insert("acceptedAt".into(), crate::js::number(now));
                if previous.is_some() {
                    boxed(|| tx.put("agreementAcceptances", &record)).await?;
                } else {
                    boxed(|| tx.insert("agreementAcceptances", &record)).await?;
                }
                written.push((acceptance_id, previous));
            }
            if boxed(|| check(principal.clone())).await? {
                found.push(json!({
                    "kind": "accept-agreements",
                    "agreements": owed
                        .iter()
                        .map(|agreement| json!({
                            "id": agreement.id,
                            "name": agreement.name,
                            "version": crate::js::number(agreement.version),
                        }))
                        .collect::<Vec<_>>(),
                }));
            }
            for (entry_id, previous) in &written {
                match previous {
                    Some(previous) => {
                        boxed(|| tx.put("agreementAcceptances", previous)).await?;
                    }
                    None => boxed(|| tx.delete("agreementAcceptances", entry_id)).await?,
                }
            }
        }
    }

    // Eligible bindings the caller holds directly or through a group, simulated as activated.
    let mut group_ids: IndexSet<String> = IndexSet::new();
    for record in boxed(|| {
        find_records(
            tx,
            "groupMembers",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("identityId", identity_id),
        )
    })
    .await?
    {
        let member: GroupMember = decode(record)?;
        if ctx.live_membership(&member) {
            group_ids.insert(member.group_id);
        }
    }
    let mut eligible: Vec<Binding> = Vec::new();
    for record in
        boxed(|| find_records(tx, "bindings", Filter::new().eq("tenantId", tenant_id))).await?
    {
        let binding: Binding = decode(record)?;
        let holds = if binding.subject_type == "identity" {
            binding.subject_id == identity_id
        } else {
            group_ids.contains(&binding.subject_id)
        };
        if binding.eligible == Some(true) && ctx.live_binding(&binding) && holds {
            eligible.push(binding);
        }
    }
    eligible.truncate(MAX_CANDIDATES);
    let mut activations: IndexMap<String, Record> = IndexMap::new();
    for record in boxed(|| {
        find_records(
            tx,
            "bindingActivations",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("identityId", identity_id),
        )
    })
    .await?
    {
        let activation: BindingActivation = decode(record.clone())?;
        activations.insert(activation.binding_id, record);
    }
    for binding in &eligible {
        let Some(role) = boxed(|| tx.get("roles", &binding.role_id)).await? else {
            continue;
        };
        let role: Role = decode(role)?;
        let previous = activations.get(&binding.id);
        let simulated_id = match previous.and_then(|record| record.get("id")) {
            Some(Value::String(existing)) => existing.clone(),
            _ => id(),
        };
        let mut simulated = Map::new();
        simulated.insert("id".into(), json!(simulated_id));
        simulated.insert("tenantId".into(), json!(tenant_id));
        simulated.insert(
            "uniqueKey".into(),
            json!(format!("{}:{identity_id}", binding.id)),
        );
        simulated.insert("bindingId".into(), json!(binding.id));
        simulated.insert("identityId".into(), json!(identity_id));
        simulated.insert("roleId".into(), json!(binding.role_id));
        simulated.insert("activatedAt".into(), crate::js::number(now));
        simulated.insert("expiresAt".into(), crate::js::number(now + 3_600_000.0));
        simulated.insert("sessionId".into(), json!(principal.session.id));
        if previous.is_some() {
            boxed(|| tx.put("bindingActivations", &simulated)).await?;
        } else {
            boxed(|| tx.insert("bindingActivations", &simulated)).await?;
        }
        // `requireMfa` gates the activation itself, not the grants it brings, so the caller is evaluated as is.
        let helps = boxed(|| check(principal.clone())).await?;
        match previous {
            Some(previous) => {
                boxed(|| tx.put("bindingActivations", previous)).await?;
            }
            None => boxed(|| tx.delete("bindingActivations", &simulated_id)).await?,
        }
        if helps
            && boxed(|| {
                may(
                    ctx,
                    tx,
                    principal,
                    tenant_id,
                    "iam:bindings:activate",
                    &binding.role_id,
                )
            })
            .await?
        {
            let mut path = Map::new();
            path.insert("kind".into(), json!("activate"));
            path.insert("bindingId".into(), json!(binding.id));
            path.insert("role".into(), json!({ "id": role.id, "name": role.name }));
            path.insert(
                "requireApproval".into(),
                json!(binding.require_approval == Some(true)),
            );
            path.insert(
                "requireJustification".into(),
                json!(binding.require_justification == Some(true)),
            );
            path.insert(
                "requireMfa".into(),
                json!(binding.require_mfa == Some(true)),
            );
            if let Some(max) = binding.max_activation_ms {
                path.insert("maxActivationMs".into(), crate::js::number(max));
            }
            found.push(Value::Object(path));
        }
    }

    // Requestable packages, simulated as assigned (standing bindings under each role's own authority, memberships).
    let mut packages: Vec<AccessPackage> = Vec::new();
    for record in boxed(|| {
        find_records(
            tx,
            "accessPackages",
            Filter::new().eq("tenantId", tenant_id),
        )
    })
    .await?
    {
        let package: AccessPackage = decode(record)?;
        if package.requestable == Some(true) {
            packages.push(package);
        }
    }
    packages.truncate(MAX_CANDIDATES);
    for package in &packages {
        if !boxed(|| {
            may(
                ctx,
                tx,
                principal,
                tenant_id,
                "iam:packages:request",
                &package.id,
            )
        })
        .await?
        {
            continue;
        }
        let mut created: Vec<(&str, String)> = Vec::new();
        for role_id in &package.role_ids {
            let Some(role) = boxed(|| tx.get("roles", role_id)).await? else {
                continue;
            };
            let Some(Value::String(authority_id)) = role.get("authorityId") else {
                continue;
            };
            let binding_id = id();
            let mut binding = Map::new();
            binding.insert("id".into(), json!(binding_id));
            binding.insert("tenantId".into(), json!(tenant_id));
            binding.insert(
                "uniqueKey".into(),
                json!(format!("simulation:{binding_id}")),
            );
            binding.insert("subjectType".into(), json!("identity"));
            binding.insert("subjectId".into(), json!(identity_id));
            binding.insert("roleId".into(), json!(role_id));
            binding.insert("authorityId".into(), json!(authority_id));
            boxed(|| tx.insert("bindings", &binding)).await?;
            created.push(("bindings", binding_id));
        }
        for group_id in &package.group_ids {
            if group_ids.contains(group_id) {
                continue;
            }
            let member_id = id();
            let mut member = Map::new();
            member.insert("id".into(), json!(member_id));
            member.insert("tenantId".into(), json!(tenant_id));
            member.insert("uniqueKey".into(), json!(format!("simulation:{member_id}")));
            member.insert("groupId".into(), json!(group_id));
            member.insert("identityId".into(), json!(identity_id));
            boxed(|| tx.insert("groupMembers", &member)).await?;
            created.push(("groupMembers", member_id));
        }
        let helps = !created.is_empty() && boxed(|| check(principal.clone())).await?;
        for (collection, record_id) in &created {
            boxed(|| tx.delete(collection, record_id)).await?;
        }
        if helps {
            let mut summary = Map::new();
            summary.insert("id".into(), json!(package.id));
            summary.insert("name".into(), json!(package.name));
            if let Some(description) = &package.description {
                summary.insert("description".into(), json!(description));
            }
            found.push(json!({
                "kind": "request-package",
                "package": summary,
                "requireJustification": package.require_justification == Some(true),
            }));
        }
    }
    // Like `authorize`, a denial does not reveal which rule refused it.
    Ok(json!({ "allowed": false, "reason": "ACCESS_DENIED", "paths": found }))
}

impl AccessPathsApi {
    /// `accessPaths/find`: for an `action` on a `resource` the caller is denied, lists what they could do themselves
    /// to be allowed. Nothing is saved. The caller's own ordinary session only (not impersonation, assumed roles or
    /// session tokens).
    pub async fn find(
        &self,
        credential: &CredentialInput,
        input: Body<access_paths::FindInput>,
    ) -> IamResult<Reply<access_paths::FindOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let action = text(input.get("action"), "action", 256)?;
        let reference = object(input.get("resource"))?;
        let resource = ResourceTarget {
            kind: text(reference.get("type"), "resource type", 256)?,
            id: text(reference.get("id"), "resource id", 256)?,
        };
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let slot: Mutex<Option<Value>> = Mutex::new(None);
        let outcome = ctx
            .store
            .transaction(|tx| {
                let authenticated = &authenticated;
                let tenant_id = &tenant_id;
                let action = &action;
                let resource = &resource;
                let slot = &slot;
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    if !acts_in_own_right(principal.session.kind)
                        || &principal.session.tenant_id != tenant_id
                        || &principal.identity.tenant_id != tenant_id
                    {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "Access paths are for an ordinary session of the tenant",
                            403,
                        ));
                    }
                    if principal
                        .session
                        .impersonator_id
                        .as_deref()
                        .is_some_and(|id| !id.is_empty())
                    {
                        return Err(IamError::with_status(
                            "IMPERSONATION_RESTRICTED",
                            "Access paths are not available while impersonating",
                            403,
                        ));
                    }
                    if !ctx.catalog.known_action(&*tx, tenant_id, action).await? {
                        return Err(IamError::new(
                            "INVALID_ACTION",
                            format!("Unknown action {action}"),
                        ));
                    }
                    let tenant = ctx.tenant(&tx, tenant_id).await?;
                    let result = paths(ctx, &tx, &principal, &tenant, action, resource).await?;
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
                "Access paths did not complete",
                500,
            )),
        }
    }
}
