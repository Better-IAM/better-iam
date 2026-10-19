//! Port of `packages/server/src/decisions.ts`: the decision engine. Grants come from bindings (directly or through
//! groups), the roles they name (inline documents, attached policies, inherited roles) and the authorities that
//! issued them; every decision is bounded by the tenant chain's boundaries, the agent and delegation scope, the
//! principal boundary, the guest ceiling, session policies and credential authorities. Context keys from the modules
//! (agreements, onboarding, teams, departments, spend, consents, licenses, risk, device posture, clearances) are read
//! only when a document names them, through those modules' providers.

use std::sync::{Arc, Weak};

use async_trait::async_trait;
use better_iam_core::{
    AuthenticatedPrincipal, Decision, EvaluationInput, Filter, FindOptions, IamError, IamResult,
    Identity, IdentityKind, IdentityStatus, PolicyDocument, PolicyStatement, ResourceRef, Session,
    SessionKind, Tenant, TenantStatus, canonical_json, compare_ids, evaluate_policy,
    ip_counter_key, js as core_js,
};
use futures::future::BoxFuture;
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::agents::agent_decision_scope;
use crate::agreements::agreement_context;
use crate::catalog::{is_internal_resource_type, managed_resource, resolved_managed};
use crate::clearances::{
    KnownLabeling, MandatoryAccess, attach_label, clearance_scope, scheme_for_tenant,
};
use crate::context::{ServerContext, Store};
use crate::context_keys::{is_server_owned_key, session_tag_name};
pub use crate::contracts::decide_on;
/// `decideOn` and `isRootOverride` are exported by decisions.ts; they live in contracts.rs with `PreparedDecision`.
pub use crate::contracts::is_root_override;
use crate::contracts::{
    ActivationSummary, BindingVia, DecisionInputs, DecisionService, EffectiveBinding, Evaluate,
    GrantPath, GrantSources, PendingActivation, PreparedDecision,
};
use crate::devices::{device_context, mentions_device, with_request_device};
use crate::features::{
    FEATURE_CONTEXT_KEY, enabled_feature_keys, feature_state, mentions_features,
};
use crate::flows::trust_passes_source_attributes;
use crate::guests::{guest_boundary, guest_context};
use crate::inference::resolve_model_resource;
use crate::models::{Binding, BindingActivation, GroupMember, OidcProvider, Policy, Role, Trust};
use crate::onboarding::{mentions_onboarding, onboarding_context};
use crate::options::{AuthorizationRequest, ResolvedResource};
use crate::port::decode;
use crate::privacy::{consent_context, mentions_consents};
use crate::session_kinds::acts_in_own_right;
use crate::ssh::resolve_ssh_resource;
use crate::teams::{mentioned_org_keys, team_context};
use crate::utils::all;
use crate::validation::text_str;
use crate::vault::resolve_secret_resource;
use crate::vc::resolve_credential_type_resource;
use crate::{billing_service, departments, licenses, threats};

/// `impersonatingActor(tx, principal)`: the administrator behind an impersonation ("view as") session, acting through
/// their own source session; None for every other principal. `currentPrincipal` has already checked that the source
/// session and identity are live.
pub async fn impersonating_actor(
    tx: &Store,
    principal: &AuthenticatedPrincipal,
) -> IamResult<Option<AuthenticatedPrincipal>> {
    let Some(actor_id) = principal
        .session
        .impersonator_id
        .as_deref()
        .filter(|id| !id.is_empty())
    else {
        return Ok(None);
    };
    let session: Option<Session> = match principal
        .session
        .impersonator_session_id
        .as_deref()
        .filter(|id| !id.is_empty())
    {
        Some(source_id) => get(tx, "sessions", source_id).await?,
        None => None,
    };
    let identity: Option<Identity> = get(tx, "identities", actor_id).await?;
    let (Some(session), Some(identity)) = (session, identity) else {
        return Err(impersonation_ended());
    };
    if session.identity_id != identity.id || identity.status != IdentityStatus::Active {
        return Err(impersonation_ended());
    }
    // The administrator's side of the decision sees the device this request proves (bound to the "view as"
    // session), when it is the administrator's own or shared.
    Ok(Some(with_request_device(
        AuthenticatedPrincipal {
            identity,
            session,
            device_proof: None,
        },
        principal,
    )))
}

fn impersonation_ended() -> IamError {
    IamError::with_status("UNAUTHENTICATED", "Impersonation has ended", 401)
}

/// `shadowsApplicationType(definition, type, action, resolver)`: whether a type only a tenant registered
/// (tenant-defined mode) must not answer for `action` from that tenant's registry. Tenant types answer for their own
/// actions (`{type}:{verb}`); the application's actions on a type it never declared still go to resolveResource.
pub fn shadows_application_type(
    source: Option<&str>,
    kind: &str,
    action: Option<&str>,
    resolver: bool,
) -> bool {
    resolver
        && source == Some("tenant")
        && action.is_some_and(|action| !action.starts_with(&format!("{kind}:")))
}

/// How deep an inheritance hierarchy is followed: roles.ts refuses writes past 200 roles, so none is cut short.
const MAX_INHERITED_ROLES: usize = 256;

/// Above this many groups one tenant-wide read is cheaper than a lookup per group.
const GROUP_LOOKUP_LIMIT: usize = 24;

async fn get<T: serde::de::DeserializeOwned>(
    tx: &Store,
    collection: &str,
    id: &str,
) -> IamResult<Option<T>> {
    match tx.get(collection, id).await? {
        Some(record) => Ok(Some(decode(record)?)),
        None => Ok(None),
    }
}

async fn find<T: serde::de::DeserializeOwned>(
    tx: &Store,
    collection: &str,
    filter: Filter,
) -> IamResult<Vec<T>> {
    tx.find(collection, &filter, &FindOptions::default())
        .await?
        .into_iter()
        .map(decode)
        .collect()
}

/// A string member of a record's undeclared members (`typeof record.key === 'string'`).
fn extra_str<'a>(extra: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    extra.get(key).and_then(Value::as_str)
}

/// A string that JavaScript reads as true (`Boolean(value)`).
fn present(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

/// `{ ...document, statements: document.statements.filter(deny) }`.
fn deny_only(document: &PolicyDocument) -> PolicyDocument {
    PolicyDocument {
        statements: document
            .statements
            .iter()
            .filter(|statement| statement.effect == better_iam_core::Effect::Deny)
            .cloned()
            .collect(),
    }
}

/// `denyPaths(documents, authorityId)`: the deny statements of documents as one path that grants nothing.
fn deny_paths(documents: &[PolicyDocument], authority_id: &str) -> Vec<GrantPath> {
    let grants: Vec<PolicyDocument> = documents
        .iter()
        .map(deny_only)
        .filter(|document| !document.statements.is_empty())
        .collect();
    if grants.is_empty() {
        Vec::new()
    } else {
        vec![GrantPath {
            grants,
            boundaries: Vec::new(),
            authority_id: authority_id.to_owned(),
        }]
    }
}

/// `roleDenies(tx, role, tenantId, authorityId, seen)`: every deny statement a role carries (its inline document,
/// its attached policies, and the roles it inherits), used where an authority behind the role has been revoked: what
/// it granted lapses, what it forbade does not.
async fn role_denies(
    tx: &Store,
    role: &Role,
    tenant_id: &str,
    authority_id: &str,
    seen: &mut IndexSet<String>,
) -> IamResult<Vec<GrantPath>> {
    let mut documents: Vec<PolicyDocument> = Vec::new();
    seen.insert(role.id.clone());
    let mut queue = vec![role.clone()];
    while let Some(current) = queue.pop() {
        if current.tenant_id != tenant_id {
            continue;
        }
        if let Some(document) = &current.document {
            documents.push(document.clone());
        }
        for policy_id in &current.policy_ids {
            let policy: Option<Policy> = get(tx, "policies", policy_id).await?;
            if let Some(policy) = policy
                && policy.tenant_id == tenant_id
            {
                documents.push(policy.document.clone());
            }
        }
        for inherited_id in current.inherits.iter().flatten() {
            if seen.contains(inherited_id) || seen.len() > MAX_INHERITED_ROLES {
                continue;
            }
            seen.insert(inherited_id.clone());
            let inherited: Option<Role> = get(tx, "roles", inherited_id).await?;
            if let Some(inherited) = inherited
                && !inherited.protected
            {
                queue.push(inherited);
            }
        }
    }
    Ok(deny_paths(&documents, authority_id))
}

/// `roleDenyStatements(tx, role)`: every deny statement a role carries (inline, attached policies, inherited roles),
/// as canonical JSON, whatever the authorities behind them: what holders of the role are forbidden.
pub async fn role_deny_statements(tx: &Store, role: &Role) -> IamResult<IndexSet<String>> {
    let paths = role_denies(tx, role, &role.tenant_id, "", &mut IndexSet::new()).await?;
    Ok(paths
        .iter()
        .flat_map(|path| path.grants.iter())
        .flat_map(|document| document.statements.iter())
        .map(statement_json)
        .collect())
}

fn statement_json(statement: &PolicyStatement) -> String {
    canonical_json(&serde_json::to_value(statement).unwrap_or(Value::Null))
}

/// `documentDenyStatements(document)`: the deny statements of a document, as canonical JSON.
pub fn document_deny_statements(document: Option<&PolicyDocument>) -> IndexSet<String> {
    document
        .map(|document| {
            document
                .statements
                .iter()
                .filter(|statement| statement.effect == better_iam_core::Effect::Deny)
                .map(statement_json)
                .collect()
        })
        .unwrap_or_default()
}

/// `preparedLabeling(prepared)`: what `resolve` may take as known from a decision prepared in the same tenant: the
/// scheme its mandatory check enforces (None: none). None for a fixed decision, which says nothing about it.
pub fn prepared_labeling(prepared: &PreparedDecision) -> Option<KnownLabeling> {
    match prepared {
        PreparedDecision::Fixed(_) => None,
        PreparedDecision::Evaluator { inputs, .. } => inputs.as_ref().map(|inputs| KnownLabeling {
            scheme: inputs
                .mandatory
                .as_ref()
                .map(|mandatory| mandatory.scheme().clone()),
            named: None,
        }),
    }
}

/// What `moduleResourceLabels` returns: gives each of the resources it was built for its label exactly as `resolve`
/// attaches it (the identity when clearances are off).
#[derive(Clone, Default)]
pub struct ModuleResourceLabels {
    tenant_id: String,
    labels: Option<IndexMap<String, Option<Value>>>,
}

impl ModuleResourceLabels {
    /// The resource with its label, when it was one of the resources passed in.
    pub fn apply(&self, resource: &ResolvedResource) -> ResolvedResource {
        let Some(labels) = &self.labels else {
            return resource.clone();
        };
        let key = format!("{}/{}", resource.kind, resource.id);
        match labels.get(&key) {
            Some(classification) if resource.tenant_id == self.tenant_id => ResolvedResource {
                classification: classification.clone(),
                ..resource.clone()
            },
            _ => resource.clone(),
        }
    }
}

/// `moduleResourceLabels(ctx, tx, tenantId, resources)`: classification labels (security clearances) for resources a
/// module builds itself instead of through `resolve` (SSH logins and hosts, credential types).
pub async fn module_resource_labels(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    resources: &[ResolvedResource],
) -> IamResult<ModuleResourceLabels> {
    if ctx.config.clearances.is_none() || resources.is_empty() {
        return Ok(ModuleResourceLabels::default());
    }
    let scheme = scheme_for_tenant(tx, tenant_id).await?;
    let known = KnownLabeling {
        scheme,
        named: None,
    };
    let mut labels: IndexMap<String, Option<Value>> = IndexMap::new();
    for resource in resources {
        let key = format!("{}/{}", resource.kind, resource.id);
        if resource.tenant_id == tenant_id && !labels.contains_key(&key) {
            let labeled = attach_label(ctx, tx, tenant_id, resource, Some(&known)).await?;
            labels.insert(key, labeled.classification);
        }
    }
    Ok(ModuleResourceLabels {
        tenant_id: tenant_id.to_owned(),
        labels: Some(labels),
    })
}

/// `classificationKeys(mandatory, resource)`: a resource's classification keys as the scheme applies its label. An
/// entry of None means the key is absent (TypeScript sets it to `undefined`).
fn classification_keys(
    mandatory: Option<&Arc<dyn MandatoryAccess>>,
    resource: &ResolvedResource,
) -> Vec<(&'static str, Option<Value>)> {
    let label = mandatory.and_then(|mandatory| mandatory.label(resource));
    let label_value = label
        .as_ref()
        .and_then(|label| serde_json::to_value(label).ok());
    let member = |key: &str| label_value.as_ref().and_then(|value| value.get(key));
    let ids = |value: Option<&Value>| {
        Value::Array(match value {
            Some(Value::Array(items)) => items
                .iter()
                .filter(|item| item.is_string())
                .cloned()
                .collect(),
            _ => Vec::new(),
        })
    };
    let rank = match (&label, mandatory) {
        (Some(label), Some(mandatory)) => mandatory.rank(label).map(crate::js::number),
        _ => Some(crate::js::number(-1.0)),
    };
    vec![
        (
            "resource.classification",
            member("level").filter(|level| level.is_string()).cloned(),
        ),
        ("resource.classificationRank", rank),
        ("resource.compartments", Some(ids(member("compartments")))),
        (
            "resource.noforn",
            Some(Value::Bool(member("noforn") == Some(&Value::Bool(true)))),
        ),
        ("resource.releasableTo", Some(ids(member("releasableTo")))),
    ]
}

/// `unclearedKeys()`: clearance keys when clearances are on but the tenant has no scheme: no clearance applies.
fn uncleared_keys() -> Map<String, Value> {
    let mut keys = Map::new();
    keys.insert("principal.clearanceRank".into(), crate::js::number(-1.0));
    keys.insert("principal.clearanceStatus".into(), json!("none"));
    keys.insert("principal.clearanceCompartments".into(), json!([]));
    keys.insert("principal.clearanceCitizenship".into(), json!([]));
    keys
}

/// `subjectBindings(tx, tenantId, identityId, groupIds)`: the bindings whose subject is the identity or one of the
/// groups, in id order (the store's order), found through the `subjectId` index.
async fn subject_bindings(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    group_ids: &IndexSet<String>,
) -> IamResult<Vec<Binding>> {
    if group_ids.len() > GROUP_LOOKUP_LIMIT {
        let all: Vec<Binding> =
            find(tx, "bindings", Filter::new().eq("tenantId", tenant_id)).await?;
        return Ok(all
            .into_iter()
            .filter(|binding| {
                if binding.subject_type == "identity" {
                    binding.subject_id == identity_id
                } else {
                    group_ids.contains(&binding.subject_id)
                }
            })
            .collect());
    }
    let mut found: Vec<Binding> = find(
        tx,
        "bindings",
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("subjectType", "identity")
            .eq("subjectId", identity_id),
    )
    .await?;
    for group_id in group_ids {
        found.extend(
            find::<Binding>(
                tx,
                "bindings",
                Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("subjectType", "group")
                    .eq("subjectId", group_id.clone()),
            )
            .await?,
        );
    }
    found.sort_by(|left, right| compare_ids(&left.id, &right.id));
    Ok(found)
}

/// `isoTime(value)`: an ISO-8601 timestamp; a value that is not a usable time reads as the epoch, which fails
/// freshness checks closed.
fn iso_time(value: f64) -> String {
    let at = if value.abs() <= 8.64e15 { value } else { 0.0 };
    core_js::iso_string(at).unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_owned())
}

/// `sessionContextKeys(session, clientIp)`: the session-aware context keys (see context-keys.ts).
fn session_context_keys(session: &Session, client_ip: Option<&str>) -> Map<String, Value> {
    let mut tags: Vec<(String, String)> = session
        .session_tags
        .iter()
        .flatten()
        .filter_map(|(key, value)| match value {
            Value::String(value) if session_tag_name(key).is_some() => {
                Some((key.clone(), value.clone()))
            }
            _ => None,
        })
        .collect();
    tags.sort_by(|(left, _), (right, _)| core_js::cmp_utf16(left, right));
    let mut keys = Map::new();
    keys.insert(
        "principal.sessionId".into(),
        Value::String(session.id.clone()),
    );
    keys.insert(
        "principal.tokenIssueTime".into(),
        Value::String(iso_time(session.created_at)),
    );
    keys.insert(
        "principal.authTime".into(),
        Value::String(iso_time(session.authenticated_at)),
    );
    keys.insert(
        "principal.sessionTagKeys".into(),
        Value::Array(
            tags.iter()
                .map(|(key, _)| Value::String(key.clone()))
                .collect(),
        ),
    );
    if session.mfa
        && let Some(at) = session.mfa_authenticated_at.filter(|at| at.is_finite())
        && !present(session.trusted_device_id.as_deref())
        && !present(session.impersonator_id.as_deref())
    {
        keys.insert("principal.mfaTime".into(), Value::String(iso_time(at)));
    }
    if session.kind == SessionKind::Role
        && let Some(source) = &session.source_tenant_id
    {
        keys.insert(
            "principal.sourceTenantId".into(),
            Value::String(source.clone()),
        );
    }
    if let Some(name) = &session.session_name {
        keys.insert("principal.sessionName".into(), Value::String(name.clone()));
    }
    if let Some(source) = &session.source_identity {
        keys.insert(
            "principal.sourceIdentity".into(),
            Value::String(source.clone()),
        );
    }
    for (key, value) in &tags {
        if let Some(name) = session_tag_name(key) {
            keys.insert(name, Value::String(value.clone()));
        }
    }
    if let Some(web) = &session.web_identity {
        keys.insert(
            "principal.webIdentityProvider".into(),
            Value::String(web.provider_id.clone()),
        );
        keys.insert(
            "principal.webIdentitySubject".into(),
            Value::String(web.subject.clone()),
        );
    }
    if session.id != "simulation"
        && let Some(ip) = client_ip.filter(|ip| !ip.is_empty())
        && ip_counter_key(ip).is_some()
    {
        keys.insert("request.sourceIp".into(), Value::String(ip.to_owned()));
    }
    keys
}

/// `Object.assign(base, keys)`.
fn assign(base: &mut Map<String, Value>, keys: Map<String, Value>) {
    for (key, value) in keys {
        base.insert(key, value);
    }
}

fn fixed(allowed: bool, reason: &str) -> PreparedDecision {
    PreparedDecision::Fixed(Decision {
        allowed,
        reason: reason.to_owned(),
        matched: Vec::new(),
    })
}

/// `createDecisions(ctx)`: the decision service ([`DecisionService`]).
pub fn create_decisions(ctx: &Arc<ServerContext>) -> Arc<Decisions> {
    Arc::new(Decisions {
        ctx: Arc::downgrade(ctx),
    })
}

/// The decision service of one server context.
pub struct Decisions {
    ctx: Weak<ServerContext>,
}

impl Decisions {
    fn context(&self) -> IamResult<Arc<ServerContext>> {
        self.ctx.upgrade().ok_or_else(crate::js::internal_error)
    }

    /// `resolve` without the classification label (see there).
    async fn resolve_unlabeled(
        &self,
        ctx: &Arc<ServerContext>,
        tx: &Store,
        reference: &ResourceRef,
        internal: bool,
        action: Option<&str>,
    ) -> IamResult<ResolvedResource> {
        text_str(&reference.kind, "resource type", 256)?;
        text_str(&reference.id, "resource id", 256)?;
        if internal && is_internal_resource_type(&reference.kind) {
            // Vault secrets (`iam/vault/secrets/{name}`) carry their tags and settings (vault.ts).
            if let Some(secret) = resolve_secret_resource(tx, reference).await? {
                return Ok(secret);
            }
            // `iam/{type}/{id}` naming a registered managed resource carries that resource's owner, parent, and
            // attributes, so administrative actions such as sharing can be conditioned on them and on relations.
            if reference.kind == "iam"
                && let Some(slash) = reference.id.find('/').filter(|slash| *slash > 0)
                && let Some(record) = managed_resource(
                    tx.as_ref(),
                    &reference.tenant_id,
                    &reference.id[..slash],
                    &reference.id[slash + 1..],
                )
                .await?
            {
                return Ok(ResolvedResource {
                    attributes: resolved_managed(&record).attributes,
                    ..ResolvedResource::of(reference)
                });
            }
            return Ok(ResolvedResource::of(reference));
        }
        // AI models (`inference` option) resolve from the inference catalog, inherited down the tenant tree.
        if let Some(model) = resolve_model_resource(ctx, tx, reference).await? {
            return Ok(model);
        }
        // SSH logins and hosts (`ssh` option): `ssh-login/{host}/{login}` and `ssh-host/{host}`.
        if let Some(ssh) = resolve_ssh_resource(ctx, tx, reference).await? {
            return Ok(ssh);
        }
        // Credential types (`verifiableCredentials` option): `credential-type/{name}`.
        if let Some(credential_type) = resolve_credential_type_resource(ctx, tx, reference).await? {
            return Ok(credential_type);
        }
        let resolver = ctx.options.resolve_resource.clone();
        let definition = ctx
            .catalog
            .resource_type_definition(tx.as_ref(), &reference.tenant_id, &reference.kind)
            .await?;
        if let Some(definition) = &definition
            && definition.managed
            && !shadows_application_type(
                Some(&definition.source),
                &reference.kind,
                action,
                resolver.is_some(),
            )
        {
            let Some(record) = managed_resource(
                tx.as_ref(),
                &reference.tenant_id,
                &reference.kind,
                &reference.id,
            )
            .await?
            else {
                return Err(IamError::with_status(
                    "NOT_FOUND",
                    "Resource is not registered",
                    404,
                ));
            };
            return Ok(resolved_managed(&record));
        }
        let Some(resolver) = resolver else {
            return Err(IamError::new(
                "RESOURCE_RESOLVER_REQUIRED",
                "Configure resolveResource for application resources",
            ));
        };
        let resolved = resolver(reference.clone()).await?;
        if resolved.tenant_id != reference.tenant_id
            || resolved.id != reference.id
            || resolved.kind != reference.kind
        {
            return Err(IamError::with_status(
                "RESOURCE_MISMATCH",
                "Resource ownership mismatch",
                403,
            ));
        }
        Ok(resolved)
    }

    /// `namedResource(tx, reference, action)`: under clearances, the resource an `iam/{type}/{id}` alias names, as
    /// `resolve` answers for it when it is decided directly. None when the alias names nothing beyond IAM's own records
    /// (a platform type, a type IAM registers, or no resolver configured); `Some(None)` when resolving it fails.
    async fn named_resource(
        &self,
        ctx: &Arc<ServerContext>,
        tx: &Store,
        reference: &ResourceRef,
        action: Option<&str>,
    ) -> IamResult<Option<Option<ResolvedResource>>> {
        if reference.kind != "iam" {
            return Ok(None);
        }
        let Some(slash) = reference.id.find('/').filter(|slash| *slash > 0) else {
            return Ok(None);
        };
        let named = ResourceRef {
            tenant_id: reference.tenant_id.clone(),
            kind: reference.id[..slash].to_owned(),
            id: reference.id[slash + 1..].to_owned(),
        };
        if named.id.is_empty() || is_internal_resource_type(&named.kind) {
            return Ok(None);
        }
        let definition = ctx
            .catalog
            .resource_type_definition(tx.as_ref(), &named.tenant_id, &named.kind)
            .await?;
        if let Some(definition) = &definition
            && definition.managed
            && !shadows_application_type(
                Some(&definition.source),
                &named.kind,
                action,
                ctx.options.resolve_resource.is_some(),
            )
        {
            return Ok(None);
        }
        match self.resolve_unlabeled(ctx, tx, &named, false, action).await {
            Ok(resolved) => Ok(Some(Some(resolved))),
            Err(error) if error.code == "RESOURCE_RESOLVER_REQUIRED" => Ok(None),
            // Every Rust error is an IamError; TypeScript rethrows non-IamErrors (INTERNAL_ERROR here).
            Err(error) if error.code == "INTERNAL_ERROR" => Err(error),
            Err(_) => Ok(Some(None)),
        }
    }

    /// `roleGrants` with an explicit `seen` set (boxed: it recurses through inherited roles).
    #[allow(clippy::too_many_arguments)]
    fn role_grants_in<'a>(
        &'a self,
        ctx: &'a Arc<ServerContext>,
        tx: &'a Store,
        role: &'a Role,
        tenant_id: &'a str,
        ceilings: &'a [PolicyDocument],
        authority_id: &'a str,
        seen: &'a mut IndexSet<String>,
        mut lapsed: Option<&'a mut Vec<GrantPath>>,
    ) -> BoxFuture<'a, IamResult<Vec<GrantPath>>> {
        Box::pin(async move {
            let mut paths = Vec::new();
            // As deep as roles.ts lets a hierarchy grow, so no inherited role (or its denies) is silently left out.
            if role.tenant_id != tenant_id
                || seen.contains(&role.id)
                || seen.len() > MAX_INHERITED_ROLES
            {
                return Ok(paths);
            }
            seen.insert(role.id.clone());
            let role_ceilings = match extra_str(&role.extra, "authorityId") {
                Some(authority) => ctx.authority_chain(tx, authority).await?,
                None if role.protected => Some(Vec::new()),
                None => None,
            };
            let Some(role_ceilings) = role_ceilings else {
                if let Some(lapsed) = lapsed {
                    lapsed.extend(role_denies(tx, role, tenant_id, authority_id, seen).await?);
                }
                return Ok(paths);
            };
            // Inherited roles are evaluated under this role's ceilings too, so inheriting cannot widen a grant.
            let mut bounded: Vec<PolicyDocument> = ceilings.to_vec();
            bounded.extend(role_ceilings.iter().cloned());
            for inherited_id in role.inherits.iter().flatten() {
                let inherited: Option<Role> = get(tx, "roles", inherited_id).await?;
                let Some(inherited) = inherited.filter(|inherited| !inherited.protected) else {
                    continue;
                };
                let grants = self
                    .role_grants_in(
                        ctx,
                        tx,
                        &inherited,
                        tenant_id,
                        &bounded,
                        authority_id,
                        seen,
                        lapsed.as_deref_mut(),
                    )
                    .await?;
                paths.extend(grants);
            }
            if let Some(document) = &role.document {
                paths.push(GrantPath {
                    grants: vec![document.clone()],
                    boundaries: bounded.clone(),
                    authority_id: authority_id.to_owned(),
                });
            }
            for policy_id in &role.policy_ids {
                let policy: Option<Policy> = get(tx, "policies", policy_id).await?;
                let Some(policy) = policy.filter(|policy| policy.tenant_id == tenant_id) else {
                    continue;
                };
                let policy_ceilings = match extra_str(&policy.extra, "authorityId") {
                    Some(authority) => ctx.authority_chain(tx, authority).await?,
                    None if policy.unique_key.as_deref() == Some("system:owner") => {
                        Some(Vec::new())
                    }
                    None => None,
                };
                let Some(policy_ceilings) = policy_ceilings else {
                    if let Some(lapsed) = lapsed.as_deref_mut() {
                        lapsed.extend(deny_paths(
                            std::slice::from_ref(&policy.document),
                            authority_id,
                        ));
                    }
                    continue;
                };
                // A higher authority attaching a lower authority's mutable policy cannot silently remove the limits
                // under which that policy was created.
                let mut boundaries = bounded.clone();
                boundaries.extend(policy_ceilings);
                paths.push(GrantPath {
                    grants: vec![policy.document.clone()],
                    boundaries,
                    authority_id: authority_id.to_owned(),
                });
            }
            Ok(paths)
        })
    }

    async fn grant_sources_in(
        &self,
        ctx: &Arc<ServerContext>,
        tx: &Store,
        identity_id: &str,
        tenant_id: &str,
    ) -> IamResult<GrantSources> {
        let memberships: Vec<GroupMember> = find(
            tx,
            "groupMembers",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("identityId", identity_id),
        )
        .await?;
        let group_ids: IndexSet<String> = memberships
            .into_iter()
            .filter(|member| ctx.live_membership(member))
            .map(|member| member.group_id)
            .collect();
        let activations = self.live_activations(tx, tenant_id, identity_id).await?;
        let mut bindings = Vec::new();
        for binding in subject_bindings(tx, tenant_id, identity_id, &group_ids).await? {
            if ctx.live_binding(&binding)
                && ctx.within_window(&binding, None)?
                && (binding.eligible != Some(true) || activations.contains_key(&binding.id))
            {
                bindings.push(binding);
            }
        }
        Ok(GrantSources {
            group_ids,
            bindings,
        })
    }

    async fn identity_grants_in(
        &self,
        ctx: &Arc<ServerContext>,
        tx: &Store,
        tenant_id: &str,
        bindings: &[Binding],
        mut lapsed: Option<&mut Vec<GrantPath>>,
    ) -> IamResult<Vec<GrantPath>> {
        let mut paths = Vec::new();
        for binding in bindings {
            let role: Option<Role> = get(tx, "roles", &binding.role_id).await?;
            let Some(role) = role.filter(|role| role.tenant_id == tenant_id) else {
                continue;
            };
            let Some(ceilings) = ctx.authority_chain(tx, &binding.authority_id).await? else {
                if let Some(lapsed) = lapsed.as_deref_mut() {
                    lapsed.extend(
                        role_denies(
                            tx,
                            &role,
                            tenant_id,
                            &binding.authority_id,
                            &mut IndexSet::new(),
                        )
                        .await?,
                    );
                }
                continue;
            };
            let mut seen = IndexSet::new();
            paths.extend(
                self.role_grants_in(
                    ctx,
                    tx,
                    &role,
                    tenant_id,
                    &ceilings,
                    &binding.authority_id,
                    &mut seen,
                    lapsed.as_deref_mut(),
                )
                .await?,
            );
        }
        Ok(paths)
    }

    /// `prepareDecision` for a principal that is not the platform's root.
    async fn prepare_for(
        &self,
        ctx: &Arc<ServerContext>,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        target: &Tenant,
        action: &str,
    ) -> IamResult<PreparedDecision> {
        let clearances = ctx.config.clearances.is_some();
        let chain = ctx.ancestry(tx, target).await?;
        if chain
            .iter()
            .any(|realm| realm.status != TenantStatus::Active)
        {
            return Ok(fixed(false, "TENANT_INACTIVE"));
        }
        if principal.session.tenant_id != target.id {
            return Ok(fixed(false, "TENANT_MISMATCH"));
        }
        let session = &principal.session;
        let role_session = session.kind == SessionKind::Role;
        let sources = if role_session {
            GrantSources::default()
        } else {
            self.grant_sources_in(ctx, tx, &principal.identity.id, &target.id)
                .await?
        };
        let role_ids: Vec<String> = if role_session {
            vec![session.role_id.clone().unwrap_or_default()]
        } else {
            let mut ids: Vec<String> = sources
                .bindings
                .iter()
                .map(|binding| binding.role_id.clone())
                .collect::<IndexSet<String>>()
                .into_iter()
                .collect();
            crate::js::sort_strings(&mut ids);
            ids
        };
        // A role session's role and trust, read once: the trust decides whether source attributes pass and bounds the
        // role's grants below.
        let role: Option<Role> = match (role_session, &session.role_id) {
            (true, Some(role_id)) => get(tx, "roles", role_id).await?,
            _ => None,
        };
        let trust: Option<Trust> = match (role_session, &session.trust_id) {
            (true, Some(trust_id)) => get(tx, "trusts", trust_id).await?,
            _ => None,
        };
        // Untrusted or lower-precedence keys first: application context, plugin context, declared identity
        // attributes; the server-derived principal and request keys always win.
        let mut base: Map<String, Value> = Map::new();
        if let Some(resolve_context) = &ctx.options.resolve_context {
            assign(&mut base, resolve_context(principal.clone()).await?);
        }
        for plugin in &ctx.plugins {
            assign(&mut base, plugin.resolve_context(principal).await?);
        }
        // Keys only the server may set are removed, including the optional ones it leaves absent, so an application
        // or plugin value can never stand in for them (the bare `principal.sessionTags` too).
        base.retain(|key, _| {
            !(is_server_owned_key(key, clearances) || key == "principal.sessionTags")
        });
        // A trust may keep the source identity's attributes out of its role sessions (new cross-tenant trusts do).
        // Read fail-closed: a role session whose trust cannot be read passes none.
        let passes = !role_session || trust.as_ref().is_some_and(trust_passes_source_attributes);
        if passes {
            for (key, value) in principal.identity.attributes.iter().flatten() {
                if !is_server_owned_key(&format!("principal.{key}"), clearances)
                    && key != "sessionTags"
                {
                    base.insert(format!("principal.{key}"), value.clone());
                }
            }
        }
        // Ownership and root status describe the account in its own tenant. An assumed role carries only the role's
        // grants, so a source account's flags must not satisfy the target's conditions.
        let own_tenant = !role_session && principal.identity.tenant_id == session.tenant_id;
        // Only a session acting in the account's own right (a user session or an API key) is ever the owner or a root
        // admin; a session token (or any future temporary kind) never is.
        let own_account = own_tenant && acts_in_own_right(session.kind);
        let now = ctx.now();
        let mut principal_keys = Map::new();
        principal_keys.insert(
            "principal.id".into(),
            Value::String(principal.identity.id.clone()),
        );
        principal_keys.insert(
            "principal.tenantId".into(),
            Value::String(session.tenant_id.clone()),
        );
        principal_keys.insert("principal.mfa".into(), Value::Bool(session.mfa));
        principal_keys.insert(
            "principal.kind".into(),
            serde_json::to_value(principal.identity.kind).unwrap_or(Value::Null),
        );
        principal_keys.insert(
            "principal.owner".into(),
            Value::Bool(own_account && principal.identity.owner),
        );
        principal_keys.insert(
            "principal.rootAdmin".into(),
            Value::Bool(own_account && principal.identity.root_admin),
        );
        principal_keys.insert(
            "principal.sessionKind".into(),
            serde_json::to_value(session.kind).unwrap_or(Value::Null),
        );
        if let Some(method) = &session.method {
            principal_keys.insert(
                "principal.authMethod".into(),
                serde_json::to_value(method).unwrap_or(Value::Null),
            );
        }
        principal_keys.insert(
            "principal.impersonated".into(),
            Value::Bool(present(session.impersonator_id.as_deref())),
        );
        if let Some(impersonator) = session.impersonator_id.as_ref().filter(|id| !id.is_empty()) {
            principal_keys.insert(
                "principal.impersonatorId".into(),
                Value::String(impersonator.clone()),
            );
        }
        let mut groups: Vec<String> = sources.group_ids.iter().cloned().collect();
        crate::js::sort_strings(&mut groups);
        principal_keys.insert(
            "principal.groups".into(),
            Value::Array(groups.into_iter().map(Value::String).collect()),
        );
        principal_keys.insert(
            "principal.roles".into(),
            Value::Array(role_ids.iter().cloned().map(Value::String).collect()),
        );
        // B2B guests (guests.ts): `principal.guest` always, the sponsor and home tenant when set.
        assign(
            &mut principal_keys,
            guest_context(&principal.identity, own_tenant),
        );
        // Terms of use the person accepted (names) and required ones still owed; nothing for assumed roles.
        if own_tenant {
            assign(
                &mut principal_keys,
                agreement_context(
                    tx,
                    &target.id,
                    &principal.identity.id,
                    principal.identity.kind,
                    now,
                )
                .await?,
            );
        } else {
            principal_keys.insert("principal.agreements".into(), json!([]));
            principal_keys.insert("principal.pendingAgreements".into(), crate::js::number(0.0));
        }
        principal_keys.insert(
            "request.time".into(),
            Value::String(core_js::iso_string(now).unwrap_or_default()),
        );
        let client_ip = ctx.auth.current_client().and_then(|client| client.ip);
        assign(
            &mut principal_keys,
            session_context_keys(session, client_ip.as_deref()),
        );
        assign(&mut base, principal_keys);
        // AI agents (agents.ts): `principal.delegated` always, and for an agent's own credential or a delegated
        // session the agent's keys plus its ceiling and the delegation's scope. A delegated session whose agent or
        // delegation cannot be read is refused.
        let Some(agent_scope) = agent_decision_scope(tx, principal, Some(now)).await? else {
            return Ok(fixed(false, "DELEGATION_REVOKED"));
        };
        assign(&mut base, agent_scope.keys.clone());
        // Mandatory access control (security clearances): every party of the session must dominate a labeled
        // resource's label. Read whenever clearances are on, never lazily. None without a scheme.
        let mandatory = if clearances {
            clearance_scope(
                ctx,
                tx,
                principal,
                target,
                &chain,
                Some(&agent_scope),
                now,
                Some(false),
            )
            .await?
        } else {
            None
        };
        if clearances {
            match &mandatory {
                Some(mandatory) => assign(&mut base, mandatory.keys().clone()),
                None => assign(&mut base, uncleared_keys()),
            }
        }
        let mut boundaries: Vec<PolicyDocument> = chain
            .iter()
            .filter_map(|realm| realm.boundary.clone())
            .collect();
        boundaries.extend(agent_scope.boundaries.iter().cloned());
        // Hand-offs (delegations.ts): the key issuers behind the sessions that handed the work on bound it too.
        for authority_id in agent_scope.authorities.iter().flatten() {
            let Some(ceilings) = ctx.authority_chain(tx, authority_id).await? else {
                return Ok(fixed(false, "CREDENTIAL_AUTHORITY_REVOKED"));
            };
            boundaries.extend(ceilings);
        }
        let principal_boundary: Option<crate::models::PrincipalBoundary> = find(
            tx,
            "principalBoundaries",
            Filter::new()
                .eq("tenantId", target.id.clone())
                .eq("identityId", principal.identity.id.clone()),
        )
        .await?
        .into_iter()
        .next();
        if let Some(principal_boundary) = principal_boundary {
            boundaries.push(principal_boundary.document);
        }
        // A guest stays within the tenant's guest ceiling (`crossTenantAccess.guestBoundary`, guests.ts).
        if own_tenant
            && principal.identity.guest.is_some()
            && let Some(ceiling) = guest_boundary(tx, &target.id).await?
        {
            boundaries.push(ceiling);
        }
        if let Some(policy) = &session.policy {
            boundaries.push(policy.clone());
        }
        // A session token also stays within its source credential's own policy (such as API-key scopes).
        if let Some(policy) = &session.source_policy {
            boundaries.push(policy.clone());
        }
        if let Some(authority_id) = &session.credential_authority_id {
            let Some(ceilings) = ctx.authority_chain(tx, authority_id).await? else {
                return Ok(fixed(false, "CREDENTIAL_AUTHORITY_REVOKED"));
            };
            boundaries.extend(ceilings);
        }
        // A web-identity session is bounded by the authority of whoever registered its OIDC provider as well.
        if let Some(web) = &session.web_identity {
            let provider: Option<OidcProvider> = get(tx, "oidcProviders", &web.provider_id).await?;
            let ceilings = match provider.filter(|provider| provider.tenant_id == session.tenant_id)
            {
                Some(provider) => ctx.authority_chain(tx, &provider.authority_id).await?,
                None => None,
            };
            let Some(ceilings) = ceilings else {
                return Ok(fixed(false, "CREDENTIAL_AUTHORITY_REVOKED"));
            };
            boundaries.extend(ceilings);
        }
        // Denies outlive the authority that issued them: a revoked or offboarded author takes away what they granted,
        // never what they forbade. Those denies join as paths that grant nothing.
        let mut lapsed: Vec<GrantPath> = Vec::new();
        let mut paths = if role_session {
            match (&role, &trust) {
                (Some(role), Some(trust)) if !trust.revoked => {
                    let ceilings: Vec<PolicyDocument> = trust.ceiling.iter().cloned().collect();
                    let mut seen = IndexSet::new();
                    self.role_grants_in(
                        ctx,
                        tx,
                        role,
                        &target.id,
                        &ceilings,
                        "",
                        &mut seen,
                        Some(&mut lapsed),
                    )
                    .await?
                }
                _ => Vec::new(),
            }
        } else {
            self.identity_grants_in(ctx, tx, &target.id, &sources.bindings, Some(&mut lapsed))
                .await?
        };
        paths.extend(lapsed);
        let documents: Vec<&PolicyDocument> = boundaries
            .iter()
            .chain(
                paths
                    .iter()
                    .flat_map(|path| path.grants.iter().chain(path.boundaries.iter())),
            )
            .collect();
        // Feature flags that are on for the tenant, as `tenant.features`: read only when a condition names the key.
        if mentions_features(&documents) {
            let state = feature_state(tx, &chain, now).await?;
            base.insert(
                FEATURE_CONTEXT_KEY.into(),
                Value::Array(
                    enabled_feature_keys(&state)?
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
        // Onboarding flows the person completed and required ones still open, read only when a condition names them.
        if mentions_onboarding(&documents) {
            if own_tenant {
                assign(
                    &mut base,
                    onboarding_context(tx, &chain, &principal.identity, now).await?,
                );
            } else {
                base.insert("principal.onboarding".into(), json!([]));
                base.insert("principal.pendingOnboarding".into(), crate::js::number(0.0));
            }
        }
        // Teams and departments (teams.ts, departments.ts), read only when a document names them.
        let org_keys = mentioned_org_keys(&documents);
        if org_keys.teams {
            if own_tenant {
                assign(
                    &mut base,
                    team_context(tx, &target.id, &principal.identity.id, now).await?,
                );
            } else {
                base.insert("principal.teams".into(), json!([]));
            }
        }
        if org_keys.departments {
            if own_tenant {
                assign(
                    &mut base,
                    departments::department_context(tx, &target.id, &principal.identity.id).await?,
                );
            } else {
                base.insert("principal.departments".into(), json!([]));
            }
        }
        // Spend (billing-service.ts): read only when a document names it; an assumed role sees the tenant's budgets.
        if billing_service::mentions_spend(&documents) {
            let service = billing_service::billing_service_of(ctx)?;
            assign(
                &mut base,
                service
                    .spend_context(
                        tx,
                        target,
                        own_tenant.then_some(principal.identity.id.as_str()),
                    )
                    .await?,
            );
        }
        // Privacy (privacy.ts): `principal.consents`, read only when a document names it; nothing for assumed roles.
        if mentions_consents(&documents) {
            if own_tenant {
                assign(
                    &mut base,
                    consent_context(tx, &target.id, &principal.identity, now).await?,
                );
            } else {
                base.insert("principal.consents".into(), json!([]));
            }
        }
        // License management (licenses.ts): `principal.licenses`, read only when a document names it.
        if licenses::mentions_licenses(&documents) {
            if own_tenant {
                assign(
                    &mut base,
                    licenses::license_context(tx, &target.id, &principal.identity.id, now).await?,
                );
            } else {
                base.insert("principal.licenses".into(), json!([]));
            }
        }
        // Threat detection (threats.ts): `principal.riskLevel` and `principal.riskScore`, read only when named.
        if threats::mentions_risk(&documents) {
            assign(&mut base, threats::risk_context(tx, principal, now).await?);
        }
        // Device posture (devices.ts): the request's verified device, read only when a document names it.
        if mentions_device(&documents) {
            assign(&mut base, device_context(tx, principal, now).await?);
        }
        // Deny in any applicable identity policy applies across grant paths.
        let denies: Vec<PolicyDocument> = paths
            .iter()
            .flat_map(|path| path.grants.iter().map(deny_only))
            .collect();
        // Relationship tuples the principal holds directly or through a group, keyed by `type/id`.
        let mut held: IndexMap<String, IndexSet<String>> = IndexMap::new();
        for tuple in find::<crate::models::Relationship>(
            tx,
            "relationships",
            Filter::new().eq("tenantId", target.id.clone()),
        )
        .await?
        {
            let applies = !role_session
                && tuple.expires_at.is_none_or(|at| at > now)
                && if tuple.subject_type == "identity" {
                    tuple.subject_id == principal.identity.id
                } else {
                    sources.group_ids.contains(&tuple.subject_id)
                };
            if !applies {
                continue;
            }
            held.entry(format!("{}/{}", tuple.kind, tuple.resource_id))
                .or_default()
                .insert(tuple.relation.clone());
        }
        let inputs = Arc::new(DecisionInputs {
            context: base,
            boundaries,
            paths,
            denies,
            held,
            confirm: agent_scope.confirm.clone(),
            mandatory,
        });
        let evaluate = evaluator(inputs.clone(), action.to_owned(), clearances);
        Ok(PreparedDecision::Evaluator {
            evaluate,
            inputs: Some(inputs),
            root_override: false,
        })
    }
}

/// `relationsOf(type, id)`: the relations held on `{type}/{id}` (on the named resource for `iam/{type}/{id}`), sorted.
fn relations_of(
    held: &IndexMap<String, IndexSet<String>>,
    kind: Option<&Value>,
    id: Option<&Value>,
) -> Value {
    let (Some(Value::String(kind)), Some(Value::String(id))) = (kind, id) else {
        return json!([]);
    };
    let key = if kind == "iam" {
        id.clone()
    } else {
        format!("{kind}/{id}")
    };
    let mut relations: Vec<String> = held
        .get(&key)
        .map(|set| set.iter().cloned().collect())
        .unwrap_or_default();
    crate::js::sort_strings(&mut relations);
    Value::Array(relations.into_iter().map(Value::String).collect())
}

/// The `evaluate` of a prepared decision.
fn evaluator(inputs: Arc<DecisionInputs>, action: String, clearances: bool) -> Evaluate {
    let allow_all = all();
    Arc::new(
        move |resource: &ResolvedResource, evaluated: Option<&str>| {
            let evaluated = evaluated.unwrap_or(&action);
            // Mandatory access control first, keyed on the evaluated action (`iam:` administration is never subject): no
            // grant, relationship, ownership or confirmation opens a resource above the session's clearance.
            if let Some(mandatory) = &inputs.mandatory
                && let Some(refused) = mandatory.check(resource, evaluated)
            {
                return Ok(refused);
            }
            let empty = Map::new();
            let attributes = resource.attributes.as_ref().unwrap_or(&empty);
            let mut context = inputs.context.clone();
            for (key, value) in attributes {
                context.insert(format!("resource.{key}"), value.clone());
            }
            context.insert(
                "resource.tenantId".into(),
                Value::String(resource.tenant_id.clone()),
            );
            // Held on the resource itself; for `iam/{type}/{id}` administration, on the named resource.
            context.insert(
                "resource.relations".into(),
                relations_of(
                    &inputs.held,
                    Some(&Value::String(resource.kind.clone())),
                    Some(&Value::String(resource.id.clone())),
                ),
            );
            context.insert(
                "resource.parentRelations".into(),
                relations_of(
                    &inputs.held,
                    attributes.get("parentType"),
                    attributes.get("parentId"),
                ),
            );
            // The classification label's keys, after the attributes so an attribute can never stand in for them.
            if clearances {
                for (key, value) in classification_keys(inputs.mandatory.as_ref(), resource) {
                    match value {
                        Some(value) => {
                            context.insert(key.into(), value);
                        }
                        None => {
                            context.shift_remove(key);
                        }
                    }
                }
            }
            let resource_name = format!("{}/{}", resource.kind, resource.id);
            let mut grants = vec![allow_all.clone()];
            grants.extend(inputs.denies.iter().cloned());
            let deny_decision = evaluate_policy(&EvaluationInput {
                action: evaluated.to_owned(),
                resource: resource_name.clone(),
                context: Some(context.clone()),
                grants,
                boundaries: Some(inputs.boundaries.clone()),
            })?;
            if !deny_decision.allowed {
                return Ok(deny_decision);
            }
            for path in &inputs.paths {
                let mut boundaries = inputs.boundaries.clone();
                boundaries.extend(path.boundaries.iter().cloned());
                let decision = evaluate_policy(&EvaluationInput {
                    action: evaluated.to_owned(),
                    resource: resource_name.clone(),
                    context: Some(context.clone()),
                    grants: path.grants.clone(),
                    boundaries: Some(boundaries),
                })?;
                // A delegation may hold back some actions until the person confirms them (delegations.ts).
                if decision.allowed {
                    if let Some(confirm) = &inputs.confirm
                        && let Some(held_back) = confirm(evaluated, &resource.kind, &resource.id)
                    {
                        return Ok(held_back);
                    }
                    return Ok(decision);
                }
            }
            Ok(Decision {
                allowed: false,
                reason: "NO_APPLICABLE_GRANT".into(),
                matched: Vec::new(),
            })
        },
    )
}

#[async_trait]
impl DecisionService for Decisions {
    async fn role_grants(
        &self,
        tx: &Store,
        role: &Role,
        tenant_id: &str,
        ceilings: &[PolicyDocument],
        authority_id: &str,
        seen: Option<&mut IndexSet<String>>,
        lapsed: Option<&mut Vec<GrantPath>>,
    ) -> IamResult<Vec<GrantPath>> {
        let ctx = self.context()?;
        let mut own = IndexSet::new();
        let seen = match seen {
            Some(seen) => seen,
            None => &mut own,
        };
        self.role_grants_in(
            &ctx,
            tx,
            role,
            tenant_id,
            ceilings,
            authority_id,
            seen,
            lapsed,
        )
        .await
    }

    async fn grant_sources(
        &self,
        tx: &Store,
        identity_id: &str,
        tenant_id: &str,
    ) -> IamResult<GrantSources> {
        let ctx = self.context()?;
        self.grant_sources_in(&ctx, tx, identity_id, tenant_id)
            .await
    }

    async fn live_activations(
        &self,
        tx: &Store,
        tenant_id: &str,
        identity_id: &str,
    ) -> IamResult<IndexMap<String, BindingActivation>> {
        let ctx = self.context()?;
        let mut result = IndexMap::new();
        for activation in find::<BindingActivation>(
            tx,
            "bindingActivations",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("identityId", identity_id),
        )
        .await?
        {
            let status = activation.status.as_deref();
            if activation.expires_at > ctx.now()
                && status != Some("pending")
                && status != Some("denied")
            {
                result.insert(activation.binding_id.clone(), activation);
            }
        }
        Ok(result)
    }

    async fn identity_grants(
        &self,
        tx: &Store,
        identity_id: &str,
        tenant_id: &str,
        sources: Option<&GrantSources>,
        lapsed: Option<&mut Vec<GrantPath>>,
    ) -> IamResult<Vec<GrantPath>> {
        let ctx = self.context()?;
        let owned;
        let sources = match sources {
            Some(sources) => sources,
            None => {
                owned = self
                    .grant_sources_in(&ctx, tx, identity_id, tenant_id)
                    .await?;
                &owned
            }
        };
        self.identity_grants_in(&ctx, tx, tenant_id, &sources.bindings, lapsed)
            .await
    }

    async fn effective_bindings(
        &self,
        tx: &Store,
        tenant_id: &str,
        identity_id: &str,
    ) -> IamResult<Vec<EffectiveBinding>> {
        let ctx = self.context()?;
        let memberships: Vec<GroupMember> = find(
            tx,
            "groupMembers",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("identityId", identity_id),
        )
        .await?;
        let group_ids: IndexSet<String> = memberships
            .into_iter()
            .filter(|member| ctx.live_membership(member))
            .map(|member| member.group_id)
            .collect();
        let activations = self.live_activations(tx, tenant_id, identity_id).await?;
        let mut pending: IndexMap<String, BindingActivation> = IndexMap::new();
        for activation in find::<BindingActivation>(
            tx,
            "bindingActivations",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("identityId", identity_id),
        )
        .await?
        {
            if activation.status.as_deref() == Some("pending") && activation.expires_at > ctx.now()
            {
                pending.insert(activation.binding_id.clone(), activation);
            }
        }
        let mut result = Vec::new();
        for binding in subject_bindings(tx, tenant_id, identity_id, &group_ids).await? {
            // Future-dated bindings are listed (with their start) but grant nothing until then.
            if ctx.expired_binding(&binding) {
                continue;
            }
            let role: Option<Role> = get(tx, "roles", &binding.role_id).await?;
            let eligible = binding.eligible.unwrap_or(false);
            let activation = if eligible {
                activations.get(&binding.id)
            } else {
                None
            };
            let request = if eligible {
                pending.get(&binding.id)
            } else {
                None
            };
            let in_window = match &binding.window {
                Some(_) => Some(ctx.within_window(&binding, None)?),
                None => None,
            };
            result.push(EffectiveBinding {
                role: role.filter(|role| role.tenant_id == tenant_id),
                via: if binding.subject_type == "identity" {
                    BindingVia::Identity
                } else {
                    BindingVia::Group(binding.subject_id.clone())
                },
                in_window,
                activation: activation.map(|activation| ActivationSummary {
                    id: activation.id.clone(),
                    activated_at: activation.activated_at,
                    expires_at: activation.expires_at,
                }),
                pending_activation: request.map(|request| PendingActivation {
                    id: request.id.clone(),
                    requested_at: request.activated_at,
                    expires_at: request.expires_at,
                }),
                binding,
            });
        }
        Ok(result)
    }

    async fn resolve(
        &self,
        tx: &Store,
        reference: &ResourceRef,
        internal: bool,
        action: Option<&str>,
        known: Option<&KnownLabeling>,
    ) -> IamResult<ResolvedResource> {
        let ctx = self.context()?;
        let resolved = self
            .resolve_unlabeled(&ctx, tx, reference, internal, action)
            .await?;
        // Security clearances: every resource but the platform's own carries its effective classification label,
        // attached at this one exit so no early return skips it. Only a platform resource resolved for an `iam:` action
        // goes without (that action never reads it).
        if ctx.config.clearances.is_none()
            || (internal
                && is_internal_resource_type(&reference.kind)
                && action.is_some_and(|action| action.starts_with("iam:")))
        {
            return Ok(resolved);
        }
        let scheme = match known {
            Some(known) => known.scheme.clone(),
            None => scheme_for_tenant(tx, &reference.tenant_id).await?,
        };
        let Some(scheme) = scheme else {
            return Ok(resolved);
        };
        // For anything but administration, `iam/{type}/{id}` also carries what the application answers for the
        // resource it names, so the alias never reads lower than the resource itself.
        let named = if action.is_some_and(|action| action.starts_with("iam:")) {
            None
        } else {
            self.named_resource(&ctx, tx, reference, action).await?
        };
        attach_label(
            &ctx,
            tx,
            &reference.tenant_id,
            &resolved,
            Some(&KnownLabeling {
                scheme: Some(scheme),
                named,
            }),
        )
        .await
    }

    async fn prepare_decision(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        target: &Tenant,
        action: &str,
    ) -> IamResult<PreparedDecision> {
        let ctx = self.context()?;
        if ctx.root_principal(tx, principal).await? {
            let override_decision = Decision {
                allowed: true,
                reason: "ROOT_OVERRIDE".into(),
                matched: Vec::new(),
            };
            let applies_to_root = ctx
                .config
                .clearances
                .as_ref()
                .is_some_and(|clearances| clearances.applies_to_root);
            if !applies_to_root {
                return Ok(PreparedDecision::Fixed(override_decision));
            }
            // Root does not read up (security clearances): it keeps its override for everything else, but a labeled
            // resource needs a clearance of root's own issued under the target's scheme.
            let chain = ctx.ancestry(tx, target).await?;
            let mandatory = clearance_scope(
                &ctx,
                tx,
                principal,
                target,
                &chain,
                None,
                ctx.now(),
                Some(true),
            )
            .await?;
            let Some(mandatory) = mandatory else {
                return Ok(PreparedDecision::Fixed(override_decision));
            };
            let inputs = Arc::new(DecisionInputs {
                context: mandatory.keys().clone(),
                boundaries: Vec::new(),
                paths: vec![GrantPath {
                    grants: vec![all()],
                    boundaries: Vec::new(),
                    authority_id: String::new(),
                }],
                denies: Vec::new(),
                held: IndexMap::new(),
                confirm: None,
                mandatory: Some(mandatory.clone()),
            });
            let action = action.to_owned();
            let evaluate: Evaluate = Arc::new(move |resource, evaluated| {
                let evaluated = evaluated.unwrap_or(&action);
                Ok(mandatory
                    .check(resource, evaluated)
                    .unwrap_or_else(|| override_decision.clone()))
            });
            return Ok(PreparedDecision::Evaluator {
                evaluate,
                inputs: Some(inputs),
                root_override: true,
            });
        }
        self.prepare_for(&ctx, tx, principal, target, action).await
    }

    async fn decide(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        request: &AuthorizationRequest,
        internal_resource: bool,
    ) -> IamResult<Decision> {
        let ctx = self.context()?;
        let target = ctx.tenant(tx, &request.tenant_id).await?;
        let action = text_str(&request.action, "action", 256)?;
        // Refusals that do not depend on the resource (a principal of another tenant, an inactive tenant) come first,
        // so an outsider learns nothing about the tenant's actions or resources and its resolver never runs for them.
        let prepared = self
            .prepare_decision(tx, principal, &target, &action)
            .await?;
        if let PreparedDecision::Fixed(decision) = &prepared
            && !decision.allowed
        {
            return Ok(decision.clone());
        }
        if !ctx
            .catalog
            .known_action(tx.as_ref(), &target.id, &action)
            .await?
        {
            return Ok(Decision {
                allowed: false,
                reason: "UNKNOWN_ACTION".into(),
                matched: Vec::new(),
            });
        }
        let reference = ResourceRef {
            tenant_id: target.id.clone(),
            kind: request.resource.kind.clone(),
            id: request.resource.id.clone(),
        };
        let resource = self
            .resolve(
                tx,
                &reference,
                internal_resource || action.starts_with("iam:"),
                Some(&action),
                prepared_labeling(&prepared).as_ref(),
            )
            .await?;
        let decision = decide_on(&prepared, &resource, None)?;
        // "View as" never exceeds the administrator behind it: every check must pass for both of them.
        let actor = if decision.allowed {
            impersonating_actor(tx, principal).await?
        } else {
            None
        };
        let Some(actor) = actor else {
            return Ok(decision);
        };
        let own = decide_on(
            &self.prepare_decision(tx, &actor, &target, &action).await?,
            &resource,
            None,
        )?;
        if own.allowed {
            return Ok(decision);
        }
        // The administrator's own clearance refusal stays one, so it is audited with the mandatory marker.
        Ok(if own.reason == "CLEARANCE_REQUIRED" {
            own
        } else {
            Decision {
                allowed: false,
                reason: "IMPERSONATOR_DENIED".into(),
                matched: Vec::new(),
            }
        })
    }

    fn simulated_principal(&self, identity: &Identity, mfa: bool) -> AuthenticatedPrincipal {
        let at = self
            .ctx
            .upgrade()
            .map(|ctx| ctx.now())
            .unwrap_or_else(crate::utils::date_now);
        let session: Session = serde_json::from_value(json!({
            "id": "simulation",
            "tenantId": identity.tenant_id,
            "identityId": identity.id,
            "tokenHash": "",
            // Machine accounts (service accounts and agents) act through API keys.
            "kind": if identity.kind == IdentityKind::User { "user" } else { "api-key" },
            "createdAt": at,
            "authenticatedAt": at,
            "lastSeenAt": at,
            "expiresAt": at + 1.0,
            "mfa": mfa,
        }))
        .expect("a simulated session has the session shape");
        AuthenticatedPrincipal {
            identity: identity.clone(),
            session,
            device_proof: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadowing() {
        assert!(shadows_application_type(
            Some("tenant"),
            "doc",
            Some("files:read"),
            true
        ));
        assert!(!shadows_application_type(
            Some("tenant"),
            "doc",
            Some("doc:read"),
            true
        ));
        assert!(!shadows_application_type(
            Some("platform"),
            "doc",
            Some("files:read"),
            true
        ));
        assert!(!shadows_application_type(
            Some("tenant"),
            "doc",
            Some("files:read"),
            false
        ));
        assert!(!shadows_application_type(Some("tenant"), "doc", None, true));
    }

    #[test]
    fn iso_times() {
        assert_eq!(iso_time(0.0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_time(f64::NAN), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_time(9e15), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_time(1_700_000_000_000.0), "2023-11-14T22:13:20.000Z");
    }
}
