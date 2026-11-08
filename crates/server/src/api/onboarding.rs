//! Port of `packages/server/src/api/onboarding.ts`.
//!
//! Onboarding: checklists for newcomers, customized at every level of the tenant hierarchy. `member` flows walk
//! people through their first days (forms, acknowledgements, tasks, accepting terms, verifying their email, enrolling
//! MFA or a passkey); `tenant` flows walk a new organization's or project's administrators through setup (a verified
//! domain, enough owners and members, an MFA policy, SSO, directory sync). Flows defined at the platform root reach
//! every tenant below; organizations add their own and switch off the platform's unlocked ones; projects do the same.
//! Policies see `principal.onboarding` and `principal.pendingOnboarding`. Managing needs `iam:onboarding:manage`,
//! reports `iam:onboarding:read`; people work through their own flows without a permission.

use std::collections::HashMap;
use std::sync::Arc;

use better_iam_core::boxed;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, Identity, IdentityKind, IdentityStatus, Record, Tenant, TenantStatus,
    js as core_js,
};
use better_iam_types::api::onboarding;
use indexmap::IndexSet;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply, string_member};
use crate::catalog::attribute_values;
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, OperationResult};
use crate::invariants::{invariant_snapshot, invariant_verify};
use crate::js::{internal_error, number, truthy, utf16_len};
use crate::metrics::locale_compare;
use crate::onboarding::{
    AUTOMATIC_STEPS, CandidateFlow, FlowFacts, MAX_COMPLETION_GROUPS, MAX_FLOWS_PER_TENANT,
    SettingsReader, array_of, candidate_flows, evaluate_flow, flag_of, flow_applies_to,
    flows_for_identity, live_group_ids, long_text, member_facts, num_of, parse_answers, parse_rule,
    parse_settings, parse_steps, progress_id, public_flow, resolve_settings, settings_id,
    source_of, steps_of, str_of, tenant_facts, tenant_flow_applies, tenant_status,
};
use crate::port::decode;
use crate::session_kinds::acts_in_own_right;
use crate::sod::sod_assert_identity;
use crate::teams::{assert_not_team_group, team_chain_bindings, teams_syncing_from};
use crate::utils::{date_now, id};
use crate::validation::text;

const MAX_DESCENDANTS: usize = 1000;

/// One evaluated flow: the candidate and its `OnboardingFlowStatus`.
type Statuses = Vec<(CandidateFlow, Map<String, Value>)>;

/// Progress records of one subject, by flow ID.
type ProgressMap = HashMap<String, Record>;

/// Who a progress record belongs to: a person (in their tenant) or a tenant being set up.
#[derive(Debug, Clone)]
struct Subject {
    /// `'identity' | 'tenant'`.
    kind: &'static str,
    id: String,
    tenant_id: String,
}

/// `principal.session.impersonatorId` is set (truthy).
fn impersonating(principal: &AuthenticatedPrincipal) -> bool {
    principal
        .session
        .impersonator_id
        .as_deref()
        .is_some_and(|id| !id.is_empty())
}

/// Onboarding is the caller's own business: an ordinary session (or API key) of the tenant.
fn self_session(principal: &AuthenticatedPrincipal, tenant_id: &str) -> IamResult<()> {
    if !acts_in_own_right(principal.session.kind)
        || principal.session.tenant_id != tenant_id
        || principal.identity.tenant_id != tenant_id
    {
        return Err(IamError::with_status(
            "ACCESS_DENIED",
            "Onboarding is completed from an ordinary session of its tenant",
            403,
        ));
    }
    Ok(())
}

fn not_impersonating(principal: &AuthenticatedPrincipal, what: &str) -> IamResult<()> {
    if impersonating(principal) {
        return Err(IamError::with_status(
            "IMPERSONATION_RESTRICTED",
            format!("{what} while impersonating"),
            403,
        ));
    }
    Ok(())
}

fn flow_not_found() -> IamError {
    IamError::with_status("NOT_FOUND", "Onboarding flow not found", 404)
}

fn step_not_found() -> IamError {
    IamError::with_status("NOT_FOUND", "Onboarding step not found", 404)
}

async fn flow_record(tx: &Store, flow_id: Option<&Value>) -> IamResult<Record> {
    tx.get("onboardingFlows", &text(flow_id, "flowId", 128)?)
        .await?
        .ok_or_else(flow_not_found)
}

/// A flow of this tenant (`scopedFlow`).
async fn scoped_flow(tx: &Store, flow_id: Option<&Value>, tenant_id: &str) -> IamResult<Record> {
    let flow = flow_record(tx, flow_id).await?;
    if str_of(&flow, "tenantId") != Some(tenant_id) {
        return Err(flow_not_found());
    }
    Ok(flow)
}

/// Every tenant below `root`, breadth first, at most `MAX_DESCENDANTS`.
async fn descendants_of(tx: &Store, root: &Tenant) -> IamResult<(Vec<Tenant>, bool)> {
    let mut tenants: Vec<Tenant> = Vec::new();
    let mut frontier = vec![root.id.clone()];
    while !frontier.is_empty() {
        let mut next = Vec::new();
        for parent_id in &frontier {
            let mut children: Vec<Tenant> = Vec::new();
            for record in tx
                .find(
                    "tenants",
                    &Filter::new().eq("parentId", parent_id.clone()),
                    &FindOptions::default(),
                )
                .await?
            {
                children.push(decode(record)?);
            }
            children.sort_by(|a, b| {
                (a.created_at - b.created_at)
                    .partial_cmp(&0.0)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            for child in children {
                if tenants.len() >= MAX_DESCENDANTS {
                    return Ok((tenants, true));
                }
                next.push(child.id.clone());
                tenants.push(child);
            }
        }
        frontier = next;
    }
    Ok((tenants, false))
}

/// The tenant types that can appear below a tenant of `type`, following the hierarchy's allowed children.
fn descendant_types(ctx: &ServerContext, kind: &str) -> IndexSet<String> {
    let types = &ctx.config.hierarchy.types;
    let mut found = IndexSet::new();
    let mut queue: std::collections::VecDeque<String> = types
        .get(kind)
        .map(|definition| definition.allowed_children.clone())
        .unwrap_or_default()
        .into();
    while let Some(next) = queue.pop_front() {
        if found.contains(&next) {
            continue;
        }
        if let Some(definition) = types.get(&next) {
            queue.extend(definition.allowed_children.iter().cloned());
        }
        found.insert(next);
    }
    found
}

/// `JSON.stringify(a) === JSON.stringify(b)` (`undefined` stringifies to `undefined`).
fn same_json(a: Option<&Value>, b: Option<&Value>) -> bool {
    a.map(core_js::stringify) == b.map(core_js::stringify)
}

/// `value.length` is truthy (arrays and strings by their length, objects by a `length` member).
fn has_length(value: &Value) -> bool {
    match value {
        Value::Array(items) => !items.is_empty(),
        Value::String(text) => !text.is_empty(),
        Value::Object(map) => truthy(map.get("length")),
        _ => false,
    }
}

/// `error.message.slice(0, 500)` (UTF-16 code units).
fn truncate_utf16(message: &str, max: usize) -> String {
    if utf16_len(message) <= max {
        return message.to_owned();
    }
    let mut out = String::new();
    let mut units = 0;
    for c in message.chars() {
        let width = c.len_utf16();
        if units + width > max {
            break;
        }
        units += width;
        out.push(c);
    }
    out
}

/// Whether `principal` may put people into a completion group: iam:groups:update on it and the use of the grant
/// authority behind each of its bindings, and behind those of the teams that sync from it (and of the teams above
/// them), since team sync copies the group's members there; and iam:licenses:assign when a license product is
/// assigned to the group or to one of those teams, since the people who finish the flow claim its seats.
async fn authorize_completion_group(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    group_id: &str,
) -> OperationResult<()> {
    crate::api::packages::allow(
        ctx,
        tx,
        principal,
        tenant_id,
        "iam:groups:update",
        group_id,
        "add people to a completion group",
    )
    .await?;
    let syncing: Vec<Value> = teams_syncing_from(tx, tenant_id, group_id)
        .await?
        .into_iter()
        .map(|team| Value::String(team.id))
        .collect();
    let mut authorities: Vec<String> = Vec::new();
    for binding in tx
        .find(
            "bindings",
            &Filter::new()
                .eq("tenantId", tenant_id.to_owned())
                .eq("subjectType", "group")
                .eq("subjectId", group_id.to_owned()),
            &FindOptions::default(),
        )
        .await?
    {
        authorities.push(str_of(&binding, "authorityId").unwrap_or("").to_owned());
    }
    for binding in team_chain_bindings(tx, tenant_id, &Value::Array(syncing)).await? {
        authorities.push(binding.authority_id);
    }
    for authority_id in &authorities {
        ctx.granting_authority(tx, principal, tenant_id, Some(authority_id))
            .await?;
    }
    crate::api::groups::assert_may_claim_licenses(
        ctx,
        tx,
        principal,
        tenant_id,
        &Value::String(group_id.to_owned()),
        Some("A completion group carries license seats; adding people to it needs iam:licenses:assign"),
    )
    .await
}

/// Whether the flow's owner (`groupsOwnerId`) may still put people into a completion group: active, and passing the
/// check `saveFlow` made. Groups whose authority the owner lost (demoted, revoked, left) are skipped.
async fn owner_may_grant(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    owner: Option<&Identity>,
    tenant_id: &str,
    group_id: &str,
) -> bool {
    let Some(owner) = owner else {
        return false;
    };
    if owner.status != IdentityStatus::Active || ctx.identity_expired(owner) {
        return false;
    }
    let Ok(decisions) = ctx.decisions() else {
        return false;
    };
    let principal = decisions.simulated_principal(owner, true);
    authorize_completion_group(ctx, tx, &principal, tenant_id, group_id)
        .await
        .is_ok()
}

/// Validates and stores a flow (a new one without `previous`). Answers that fill identity attributes need
/// iam:identities:update, and completion groups need iam:groups:update on each group plus the use of the grant
/// authorities behind the group's bindings, because finishing the flow makes the person a member. Every completion
/// group is checked again whenever a change alters who completes the flow or when (steps, rule, scope,
/// includeExisting, new groups), and the editor then becomes the owner the groups are applied under.
async fn save_flow(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant: &Tenant,
    input: &Map<String, Value>,
    previous: Option<&Record>,
) -> OperationResult<Record> {
    let audience_value = match previous {
        Some(previous) => previous.get("audience"),
        None => input.get("audience"),
    };
    let audience = match audience_value.and_then(Value::as_str) {
        Some(audience @ ("member" | "tenant")) => audience.to_owned(),
        _ => {
            return Err(IamError::new("INVALID_INPUT", "audience must be member or tenant").into());
        }
    };
    if let Some(previous) = previous
        && let Some(requested) = input.get("audience")
        && !core_js::strict_equal(requested, previous.get("audience").unwrap_or(&Value::Null))
    {
        return Err(IamError::new(
            "INVALID_INPUT",
            "A flow keeps its audience; create a new flow instead",
        )
        .into());
    }
    let previous_member = |key: &str| previous.and_then(|record| record.get(key));
    let name_value = crate::js::defined(input.get("name")).or_else(|| previous_member("name"));
    let name = core_js::trim(&text(name_value, "name", 100)?).to_owned();
    let description: Option<Value> = match input.get("description") {
        None => previous_member("description").cloned(),
        Some(Value::Null) => None,
        Some(Value::String(text)) if text.is_empty() => None,
        Some(value) => Some(Value::String(long_text(
            Some(value),
            "description",
            2_000.0,
        )?)),
    };
    let below = descendant_types(ctx, &tenant.kind);
    let applies_value: Value = crate::js::defined(input.get("appliesTo"))
        .or_else(|| crate::js::defined(previous_member("appliesTo")))
        .cloned()
        .unwrap_or_else(|| {
            Value::String(
                if audience == "tenant" || tenant.parent_id.is_none() {
                    "descendants"
                } else {
                    "tenant"
                }
                .to_owned(),
            )
        });
    let applies_to = match applies_value.as_str() {
        Some(scope @ ("tenant" | "descendants" | "subtree")) => scope.to_owned(),
        _ => {
            return Err(IamError::new(
                "INVALID_INPUT",
                "appliesTo must be tenant, descendants or subtree",
            )
            .into());
        }
    };
    if audience == "tenant" && applies_to != "descendants" {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Tenant setup flows apply to descendant tenants",
        )
        .into());
    }
    if applies_to != "tenant" && below.is_empty() {
        return Err(IamError::new(
            "INVALID_INPUT",
            format!(
                "{} tenants have no descendants; use appliesTo: tenant",
                tenant.kind
            ),
        )
        .into());
    }
    let tenant_types_input: Option<Value> = match input.get("tenantTypes") {
        None => previous_member("tenantTypes").cloned(),
        Some(Value::Null) => None,
        Some(value) => Some(value.clone()),
    };
    let mut tenant_types: Option<Vec<String>> = None;
    if let Some(types) = &tenant_types_input {
        if applies_to == "tenant" {
            return Err(IamError::new(
                "INVALID_INPUT",
                "tenantTypes applies to flows that reach descendants",
            )
            .into());
        }
        let items = match types {
            Value::Array(items) if !items.is_empty() && items.len() <= 20 => items,
            _ => {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "tenantTypes must list 1-20 tenant types",
                )
                .into());
            }
        };
        let mut parsed = Vec::with_capacity(items.len());
        for item in items {
            parsed.push(text(Some(item), "tenantTypes", 64)?);
        }
        let mut parsed = crate::js::unique(parsed);
        parsed.sort_by(|a, b| core_js::cmp_utf16(a, b));
        for kind in &parsed {
            if !below.contains(kind) {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    format!(
                        "tenantTypes: {kind} tenants cannot exist below a {} tenant",
                        tenant.kind
                    ),
                )
                .into());
            }
        }
        tenant_types = Some(parsed);
    }
    let groups: IndexSet<String> = tx
        .find(
            "groups",
            &Filter::new().eq("tenantId", tenant.id.clone()),
            &FindOptions::default(),
        )
        .await?
        .iter()
        .map(|group| str_of(group, "id").unwrap_or("").to_owned())
        .collect();
    let rule_input: Option<Value> = match input.get("rule") {
        None => previous_member("rule").cloned(),
        Some(Value::Null) => None,
        Some(value) => Some(value.clone()),
    };
    if rule_input.is_some() && audience != "member" {
        return Err(IamError::new("INVALID_INPUT", "rule applies to member flows only").into());
    }
    let rule: Option<Value> = match &rule_input {
        None => None,
        Some(rule_input) => Some(Value::Object(parse_rule(
            Some(rule_input),
            &ctx.catalog.identity_attributes,
            &if applies_to == "descendants" {
                IndexSet::new()
            } else {
                groups.clone()
            },
        )?)),
    };
    let flag = |value: Option<&Value>, key: &str, fallback: bool| -> IamResult<bool> {
        match value {
            None => Ok(fallback),
            Some(Value::Bool(flag)) => Ok(*flag),
            Some(_) => Err(IamError::new(
                "INVALID_INPUT",
                format!("{key} must be a boolean"),
            )),
        }
    };
    let previous_flag = |key: &str, fallback: bool| {
        crate::js::defined(previous_member(key))
            .and_then(Value::as_bool)
            .unwrap_or(fallback)
    };
    let required = flag(
        input.get("required"),
        "required",
        previous_flag("required", true),
    )?;
    let locked = flag(
        input.get("locked"),
        "locked",
        previous_flag("locked", false),
    )?;
    let include_existing = flag(
        input.get("includeExisting"),
        "includeExisting",
        previous_flag("includeExisting", false),
    )?;
    let enabled = flag(
        input.get("enabled"),
        "enabled",
        previous_flag("enabled", true),
    )?;
    if input.get("steps").is_none() && previous.is_none() {
        return Err(IamError::new("INVALID_INPUT", "steps are required").into());
    }
    let steps: Value = match (input.get("steps"), previous) {
        (None, Some(previous)) => previous.get("steps").cloned().unwrap_or(Value::Null),
        (steps, _) => Value::Array(parse_steps(
            steps,
            &audience,
            &ctx.catalog.identity_attributes,
        )?),
    };
    let group_input: Option<Value> = match input.get("completionGroupIds") {
        None => previous_member("completionGroupIds").cloned(),
        Some(Value::Null) => None,
        Some(value) => Some(value.clone()),
    };
    let mut completion_group_ids: Option<Vec<String>> = None;
    if let Some(group_input) = group_input.as_ref().filter(|value| has_length(value)) {
        if audience != "member" || applies_to == "descendants" {
            return Err(IamError::new(
                "INVALID_INPUT",
                "completionGroupIds apply to member flows that reach the defining tenant\u{2019}s own people",
            )
            .into());
        }
        let items = match group_input {
            Value::Array(items) if items.len() as f64 <= MAX_COMPLETION_GROUPS => items,
            _ => {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    format!(
                        "completionGroupIds must list at most {} groups",
                        core_js::number_to_string(MAX_COMPLETION_GROUPS)
                    ),
                )
                .into());
            }
        };
        let mut parsed = Vec::with_capacity(items.len());
        for item in items {
            parsed.push(text(Some(item), "groupId", 128)?);
        }
        let parsed = crate::js::unique(parsed);
        for group_id in &parsed {
            if !groups.contains(group_id) {
                return Err(IamError::with_status(
                    "NOT_FOUND",
                    format!("Group {group_id} not found"),
                    404,
                )
                .into());
            }
            // A team's backing group takes its members from the team only (teams.ts).
            let group = tx.get("groups", group_id).await?.map(Value::Object);
            assert_not_team_group(group.as_ref())?;
        }
        completion_group_ids = Some(parsed);
    }
    let mapped = steps.as_array().is_some_and(|steps| {
        steps.iter().filter_map(Value::as_object).any(|step| {
            array_of(step, "fields")
                .iter()
                .filter_map(Value::as_object)
                .any(|field| field.get("attribute").is_some())
        })
    });
    // Answers fill attributes only for the defining tenant's own people: a tenant has no authority over the
    // identities of the tenants below it, whose policies may grant access by those attributes.
    if mapped && applies_to == "descendants" {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Answers fill identity attributes only for the defining tenant\u{2019}s own people; a flow that reaches only tenants below cannot map fields to attributes",
        )
        .into());
    }
    let maps_attributes = input.get("steps").is_some() && mapped;
    let previous_group_ids: Vec<String> = previous
        .map(|previous| {
            array_of(previous, "completionGroupIds")
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let groups_list = completion_group_ids.clone().unwrap_or_default();
    let new_groups: Vec<&String> = groups_list
        .iter()
        .filter(|group_id| !previous_group_ids.contains(group_id))
        .collect();
    // Finishing the flow puts people into its completion groups, so a change to who finishes it or when (easier
    // steps, a wider rule or scope, existing people, resuming it, another group) re-checks every group.
    let reauthorize = !groups_list.is_empty()
        && match previous {
            None => true,
            Some(previous) => {
                !new_groups.is_empty()
                    || !same_json(previous.get("steps"), Some(&steps))
                    || !same_json(previous.get("rule"), rule.as_ref())
                    || previous.get("appliesTo") != Some(&Value::String(applies_to.clone()))
                    || previous.get("includeExisting") != Some(&Value::Bool(include_existing))
                    || (enabled && !flag_of(previous, "enabled"))
            }
        };
    if maps_attributes || reauthorize {
        if !acts_in_own_right(principal.session.kind) {
            return Err(IamError::new(
                "INVALID_INPUT",
                "Attribute answers and completion groups are set from an ordinary session or API key",
            )
            .into());
        }
        not_impersonating(
            principal,
            "Attribute answers and completion groups cannot be set",
        )?;
    }
    if maps_attributes {
        crate::api::packages::allow(
            ctx,
            tx,
            principal,
            &tenant.id,
            "iam:identities:update",
            &tenant.id,
            "let answers fill identity attributes",
        )
        .await?;
    }
    if reauthorize {
        for group_id in &groups_list {
            authorize_completion_group(ctx, tx, principal, &tenant.id, group_id).await?;
        }
    }
    // The groups stand on the authority of whoever last passed that check (kept by edits that change nothing of it).
    let mut groups_owner_id: Option<String> = if reauthorize {
        Some(principal.identity.id.clone())
    } else {
        crate::js::defined(previous_member("groupsOwnerId"))
            .or_else(|| crate::js::defined(previous_member("authorId")))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    // Naming the groups again hands them to an editor who passes the check (how an administrator takes over the
    // groups of an owner who lost the authority); an editor who does not pass it leaves the owner as it was.
    if !reauthorize
        && !groups_list.is_empty()
        && input.get("completionGroupIds").is_some()
        && groups_owner_id.as_deref() != Some(principal.identity.id.as_str())
        && acts_in_own_right(principal.session.kind)
        && !impersonating(principal)
    {
        let mut passed = true;
        for group_id in &groups_list {
            if authorize_completion_group(ctx, tx, principal, &tenant.id, group_id)
                .await
                .is_err()
            {
                passed = false;
                break;
            }
        }
        if passed {
            groups_owner_id = Some(principal.identity.id.clone());
        }
    }
    let previous_id = previous.and_then(|record| str_of(record, "id"));
    let others: Vec<Record> = tx
        .find(
            "onboardingFlows",
            &Filter::new().eq("tenantId", tenant.id.clone()),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .filter(|flow| previous_id.is_none() || str_of(flow, "id") != previous_id)
        .collect();
    let unique_key = format!("name:{}", core_js::to_lower(&name));
    if name.is_empty() {
        return Err(IamError::new("INVALID_INPUT", "name is required").into());
    }
    if others
        .iter()
        .any(|flow| str_of(flow, "uniqueKey") == Some(unique_key.as_str()))
    {
        return Err(IamError::with_status(
            "CONFLICT",
            "An onboarding flow with this name exists",
            409,
        )
        .into());
    }
    if previous.is_none() && others.len() as f64 >= MAX_FLOWS_PER_TENANT {
        return Err(IamError::with_status(
            "LIMIT_EXCEEDED",
            format!(
                "At most {} onboarding flows",
                core_js::number_to_string(MAX_FLOWS_PER_TENANT)
            ),
            409,
        )
        .into());
    }
    let now = ctx.now();
    let mut record = Map::new();
    record.insert(
        "id".into(),
        Value::String(previous_id.map(str::to_owned).unwrap_or_else(id)),
    );
    record.insert("tenantId".into(), Value::String(tenant.id.clone()));
    record.insert("uniqueKey".into(), Value::String(unique_key));
    record.insert("name".into(), Value::String(name));
    if let Some(description) = description {
        record.insert("description".into(), description);
    }
    record.insert("audience".into(), Value::String(audience));
    record.insert("appliesTo".into(), Value::String(applies_to));
    if let Some(types) = tenant_types {
        record.insert(
            "tenantTypes".into(),
            Value::Array(types.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(rule) = rule {
        record.insert("rule".into(), rule);
    }
    record.insert("required".into(), Value::Bool(required));
    record.insert("locked".into(), Value::Bool(locked));
    record.insert("includeExisting".into(), Value::Bool(include_existing));
    record.insert("enabled".into(), Value::Bool(enabled));
    if let Some(effective_from) = previous_member("effectiveFrom") {
        record.insert("effectiveFrom".into(), effective_from.clone());
    } else if enabled {
        record.insert("effectiveFrom".into(), number(now));
    }
    let version = match previous {
        Some(previous) => {
            num_of(previous, "version").unwrap_or(f64::NAN)
                + if same_json(previous.get("steps"), Some(&steps)) {
                    0.0
                } else {
                    1.0
                }
        }
        None => 1.0,
    };
    record.insert("steps".into(), steps);
    if !groups_list.is_empty() {
        record.insert(
            "completionGroupIds".into(),
            Value::Array(groups_list.into_iter().map(Value::String).collect()),
        );
        if let Some(owner) = groups_owner_id {
            record.insert("groupsOwnerId".into(), Value::String(owner));
        }
    }
    record.insert("version".into(), number(version));
    record.insert(
        "authorId".into(),
        Value::String(principal.identity.id.clone()),
    );
    record.insert(
        "createdAt".into(),
        crate::js::defined(previous_member("createdAt"))
            .cloned()
            .unwrap_or_else(|| number(now)),
    );
    record.insert("updatedAt".into(), number(now));
    Ok(if previous.is_some() {
        tx.put("onboardingFlows", &record).await?
    } else {
        tx.insert("onboardingFlows", &record).await?
    })
}

/// Deletes a flow with every progress record of it, in every tenant it reached.
pub async fn delete_onboarding_flow(tx: &Store, flow: &Record) -> IamResult<usize> {
    let flow_id = str_of(flow, "id").unwrap_or("").to_owned();
    let progress = tx
        .find(
            "onboardingProgress",
            &Filter::new().eq("flowId", flow_id.clone()),
            &FindOptions::default(),
        )
        .await?;
    for record in &progress {
        tx.delete("onboardingProgress", str_of(record, "id").unwrap_or(""))
            .await?;
    }
    for settings in tx
        .find(
            "onboardingSettings",
            &Filter::new(),
            &FindOptions::default(),
        )
        .await?
    {
        let disabled = array_of(&settings, "disabledFlowIds");
        if disabled
            .iter()
            .any(|id| id.as_str() == Some(flow_id.as_str()))
        {
            let kept: Vec<Value> = disabled
                .iter()
                .filter(|id| id.as_str() != Some(flow_id.as_str()))
                .cloned()
                .collect();
            let mut updated = settings.clone();
            updated.insert("disabledFlowIds".into(), Value::Array(kept));
            tx.put("onboardingSettings", &updated).await?;
        }
    }
    tx.delete("onboardingFlows", &flow_id).await?;
    Ok(progress.len())
}

async fn progress_for(tx: &Store, tenant_id: &str, subject_id: &str) -> IamResult<ProgressMap> {
    let mut progress = ProgressMap::new();
    for record in tx
        .find(
            "onboardingProgress",
            &Filter::new()
                .eq("tenantId", tenant_id.to_owned())
                .eq("subjectId", subject_id.to_owned()),
            &FindOptions::default(),
        )
        .await?
    {
        progress.insert(str_of(&record, "flowId").unwrap_or("").to_owned(), record);
    }
    Ok(progress)
}

async fn upsert_progress(tx: &Store, record: &Record, existed: bool) -> IamResult<Record> {
    if existed {
        tx.put("onboardingProgress", record).await
    } else {
        tx.insert("onboardingProgress", record).await
    }
}

fn new_progress(flow: &Record, subject: &Subject, now: f64) -> Record {
    let flow_id = str_of(flow, "id").unwrap_or("");
    let mut record = Map::new();
    record.insert(
        "id".into(),
        Value::String(progress_id(flow_id, &subject.id)),
    );
    record.insert("tenantId".into(), Value::String(subject.tenant_id.clone()));
    record.insert("flowId".into(), Value::String(flow_id.to_owned()));
    record.insert(
        "flowTenantId".into(),
        flow.get("tenantId").cloned().unwrap_or(Value::Null),
    );
    record.insert("subjectType".into(), Value::String(subject.kind.to_owned()));
    record.insert("subjectId".into(), Value::String(subject.id.clone()));
    record.insert("steps".into(), Value::Array(Vec::new()));
    record.insert("startedAt".into(), number(now));
    record.insert("updatedAt".into(), number(now));
    record
}

fn with_step(progress: &Record, record: Map<String, Value>) -> Record {
    let step_id = str_of(&record, "stepId").unwrap_or("").to_owned();
    let mut steps: Vec<Value> = array_of(progress, "steps")
        .iter()
        .filter(|step| {
            step.as_object().and_then(|step| str_of(step, "stepId")) != Some(step_id.as_str())
        })
        .cloned()
        .collect();
    steps.push(Value::Object(record));
    let mut next = progress.clone();
    next.insert("steps".into(), Value::Array(steps));
    next
}

/// Records flows seen complete that are not yet recorded in their current version (audited `onboarding:complete`),
/// and returns the member flows whose completion groups still need applying.
async fn record_completions(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    subject: &Subject,
    statuses: &mut Statuses,
    progress: &mut ProgressMap,
) -> IamResult<Vec<String>> {
    let mut pending_groups = Vec::new();
    let now = ctx.now();
    for (candidate, status) in statuses.iter_mut() {
        if status.get("complete") != Some(&Value::Bool(true)) {
            continue;
        }
        let flow = &candidate.flow;
        let flow_id = str_of(flow, "id").unwrap_or("").to_owned();
        let version = flow.get("version").cloned().unwrap_or(Value::Null);
        let existing = progress.get(&flow_id).cloned();
        let mut record = existing.clone();
        let current = existing.as_ref().is_some_and(|existing| {
            existing.get("completedAt").is_some()
                && existing
                    .get("completedVersion")
                    .is_some_and(|completed| core_js::strict_equal(completed, &version))
        });
        if !current {
            let mut next = existing
                .clone()
                .unwrap_or_else(|| new_progress(flow, subject, now));
            next.insert("completedAt".into(), number(now));
            next.insert("completedVersion".into(), version.clone());
            next.insert("updatedAt".into(), number(now));
            let saved = upsert_progress(tx, &next, existing.is_some()).await?;
            progress.insert(flow_id.clone(), saved.clone());
            record = Some(saved);
            status.insert("completedAt".into(), number(now));
            let mut metadata = Map::new();
            metadata.insert("flowId".into(), Value::String(flow_id.clone()));
            metadata.insert(
                "flow".into(),
                flow.get("name").cloned().unwrap_or(Value::Null),
            );
            metadata.insert("version".into(), version.clone());
            metadata.insert("subjectType".into(), Value::String(subject.kind.to_owned()));
            ctx.events()?
                .audit(
                    tx,
                    principal,
                    "onboarding:complete",
                    &subject.tenant_id,
                    &subject.id,
                    AuditOutcome::Allow,
                    false,
                    Some(metadata),
                )
                .await?;
        }
        let applied = record
            .as_ref()
            .and_then(|record| record.get("groupsAppliedVersion"))
            .is_some_and(|applied| core_js::strict_equal(applied, &version));
        if subject.kind == "identity"
            && !array_of(flow, "completionGroupIds").is_empty()
            && !applied
        {
            pending_groups.push(flow_id);
        }
    }
    Ok(pending_groups)
}

/// One flow's completion groups for one person, in its own transaction; whether anyone was added.
async fn apply_flow_groups(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    flow_id: &str,
) -> IamResult<bool> {
    let flow = tx.get("onboardingFlows", flow_id).await?;
    let progress = tx
        .get("onboardingProgress", &progress_id(flow_id, identity_id))
        .await?;
    let identity: Option<Identity> = match tx.get("identities", identity_id).await? {
        Some(record) => Some(decode(record)?),
        None => None,
    };
    let (Some(flow), Some(progress), Some(identity)) = (flow, progress, identity) else {
        return Ok(false);
    };
    let version = flow.get("version").cloned().unwrap_or(Value::Null);
    let same_version = |key: &str| {
        progress
            .get(key)
            .is_some_and(|value| core_js::strict_equal(value, &version))
    };
    let group_ids: Vec<String> = array_of(&flow, "completionGroupIds")
        .iter()
        .map(|id| crate::js::js_string(Some(id)))
        .collect();
    if group_ids.is_empty()
        || !same_version("completedVersion")
        || same_version("groupsAppliedVersion")
        || identity.status != IdentityStatus::Active
        || identity.tenant_id != tenant_id
    {
        return Ok(false);
    }
    let now = ctx.now();
    // The groups are applied under the authority of the flow's owner (saveFlow), checked again now: a group they
    // can no longer add people to is skipped, reported, and retried on the next read.
    let owner_id = crate::js::defined(flow.get("groupsOwnerId"))
        .or_else(|| crate::js::defined(flow.get("authorId")))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned);
    let owner: Option<Identity> = match &owner_id {
        Some(owner_id) => match tx.get("identities", owner_id).await? {
            Some(record) => Some(decode(record)?),
            None => None,
        },
        None => None,
    };
    let mut planned: Vec<(String, String, Option<Record>)> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for group_id in &group_ids {
        let group = tx.get("groups", group_id).await?;
        if group.as_ref().and_then(|group| str_of(group, "tenantId")) != Some(tenant_id) {
            continue;
        }
        let unique_key = format!("{group_id}:{identity_id}");
        let existing = tx
            .find(
                "groupMembers",
                &Filter::new()
                    .eq("tenantId", tenant_id.to_owned())
                    .eq("uniqueKey", unique_key.clone()),
                &FindOptions::default(),
            )
            .await?
            .into_iter()
            .next();
        if let Some(existing) = &existing {
            let live = match existing.get("expiresAt") {
                None => true,
                Some(expires) => core_js::as_number(expires).is_some_and(|expires| expires > now),
            };
            if live {
                continue;
            }
        }
        if !owner_may_grant(ctx, tx, owner.as_ref(), tenant_id, group_id).await {
            skipped.push(group_id.clone());
        } else {
            planned.push((group_id.clone(), unique_key, existing));
        }
    }
    // Enforced invariants and separation of duties hold for completion groups as for groups.addMember.
    let guardrails = if planned.is_empty() {
        None
    } else {
        invariant_snapshot(ctx, tx, tenant_id, "iam:groups:update").await?
    };
    let mut added: Vec<String> = Vec::new();
    for (group_id, unique_key, existing) in planned {
        if let Some(existing) = existing {
            let mut kept = existing;
            kept.shift_remove("expiresAt");
            kept.shift_remove("packageAssignmentId");
            tx.put("groupMembers", &kept).await?;
        } else {
            let mut member = Map::new();
            member.insert("id".into(), Value::String(id()));
            member.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
            member.insert("uniqueKey".into(), Value::String(unique_key));
            member.insert("groupId".into(), Value::String(group_id.clone()));
            member.insert("identityId".into(), Value::String(identity_id.to_owned()));
            tx.insert("groupMembers", &member).await?;
        }
        added.push(group_id);
    }
    if !added.is_empty() {
        sod_assert_identity(ctx, tx, tenant_id, identity_id).await?;
        invariant_verify(ctx, tx, tenant_id, guardrails.as_ref()).await?;
    }
    let previous_error = progress.get("completionError").cloned();
    let mut rest = progress.clone();
    rest.shift_remove("completionError");
    let refusal = if skipped.is_empty() {
        None
    } else {
        Some(format!(
            "Completion groups skipped: the flow's owner can no longer add people to {} {}; an administrator who can should save the flow's completion groups again",
            if skipped.len() == 1 {
                "group"
            } else {
                "groups"
            },
            skipped.join(", ")
        ))
    };
    match &refusal {
        Some(refusal) => {
            rest.insert("completionError".into(), Value::String(refusal.clone()));
        }
        None => {
            rest.insert("groupsAppliedVersion".into(), version.clone());
        }
    }
    tx.put("onboardingProgress", &rest).await?;
    let flow_name = flow.get("name").cloned().unwrap_or(Value::Null);
    if let Some(refusal) = &refusal
        && previous_error.as_ref().and_then(Value::as_str) != Some(refusal.as_str())
    {
        let mut metadata = Map::new();
        metadata.insert("flowId".into(), Value::String(flow_id.to_owned()));
        metadata.insert("flow".into(), flow_name.clone());
        metadata.insert(
            "groupIds".into(),
            Value::Array(skipped.iter().cloned().map(Value::String).collect()),
        );
        if let Some(owner_id) = &owner_id {
            metadata.insert("ownerId".into(), Value::String(owner_id.clone()));
        }
        ctx.events()?
            .record_audit(
                tx,
                &system_event(
                    tenant_id,
                    identity_id,
                    "onboarding:groups-skipped",
                    "deny",
                    metadata,
                ),
            )
            .await?;
    }
    if !added.is_empty() {
        let mut metadata = Map::new();
        metadata.insert("flowId".into(), Value::String(flow_id.to_owned()));
        metadata.insert("flow".into(), flow_name);
        metadata.insert(
            "groupIds".into(),
            Value::Array(added.iter().cloned().map(Value::String).collect()),
        );
        ctx.events()?
            .record_audit(
                tx,
                &system_event(
                    tenant_id,
                    identity_id,
                    "onboarding:groups",
                    "allow",
                    metadata,
                ),
            )
            .await?;
    }
    Ok(!added.is_empty())
}

/// An audit event the person's completion caused (`actorId` is the person).
fn system_event(
    tenant_id: &str,
    identity_id: &str,
    action: &str,
    outcome: &str,
    metadata: Map<String, Value>,
) -> Record {
    let mut event = Map::new();
    event.insert("id".into(), Value::String(id()));
    event.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    event.insert("actorId".into(), Value::String(identity_id.to_owned()));
    event.insert("action".into(), Value::String(action.to_owned()));
    event.insert("resourceId".into(), Value::String(identity_id.to_owned()));
    event.insert("timestamp".into(), number(date_now()));
    event.insert("outcome".into(), Value::String(outcome.to_owned()));
    event.insert("metadata".into(), Value::Object(metadata));
    event
}

/// Makes a person a member of the completion groups of flows they finished, one transaction per flow so a
/// separation-of-duties or invariant refusal in one leaves the others (and the recorded completion) in place. A
/// refusal is kept on the progress record as `completionError` and retried the next time the person's onboarding is
/// read, and so is a group the flow's owner may no longer add people to (audited once as `onboarding:groups-skipped`).
async fn apply_completion_groups(
    ctx: &Arc<ServerContext>,
    tenant_id: &str,
    identity_id: &str,
    flow_ids: &[String],
) -> IamResult<()> {
    let mut changed = false;
    for flow_id in flow_ids {
        let attempt = {
            let ctx = ctx.clone();
            let (tenant_id, identity_id, flow_id) = (
                tenant_id.to_owned(),
                identity_id.to_owned(),
                flow_id.clone(),
            );
            ctx.store
                .clone()
                .transaction(move |tx| async move {
                    apply_flow_groups(&ctx, &tx, &tenant_id, &identity_id, &flow_id).await
                })
                .await
        };
        match attempt {
            Ok(added) => changed = added || changed,
            Err(error) => {
                let message = truncate_utf16(&error.message, 500);
                let id = progress_id(flow_id, identity_id);
                // Bookkeeping never masks the completion.
                let _ = ctx
                    .store
                    .transaction(move |tx| async move {
                        if let Some(progress) = tx.get("onboardingProgress", &id).await?
                            && str_of(&progress, "completionError") != Some(message.as_str())
                        {
                            let mut updated = progress;
                            updated.insert("completionError".into(), Value::String(message));
                            tx.put("onboardingProgress", &updated).await?;
                        }
                        Ok(())
                    })
                    .await;
            }
        }
    }
    if changed {
        crate::api::package_automation::after_identity_change(
            ctx,
            tenant_id,
            &[identity_id.to_owned()],
            &Value::Null,
        )
        .await?;
    }
    Ok(())
}

/// Evaluates a person's member flows (optionally with their answers).
async fn member_statuses(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    chain: &[Tenant],
    identity: &Identity,
    answers: bool,
    candidates: Option<Vec<CandidateFlow>>,
) -> IamResult<(Statuses, ProgressMap)> {
    let now = ctx.now();
    let flows = flows_for_identity(tx, chain, identity, now, candidates).await?;
    let progress = progress_for(tx, &identity.tenant_id, &identity.id).await?;
    let records: Vec<&Record> = flows.iter().map(|candidate| &candidate.flow).collect();
    let facts = member_facts(tx, identity, &records, now).await?;
    let statuses = flows
        .into_iter()
        .map(|candidate| {
            let status = evaluate_flow(
                &candidate,
                progress.get(str_of(&candidate.flow, "id").unwrap_or("")),
                FlowFacts {
                    member: Some((identity, &facts)),
                    tenant: None,
                },
                answers,
            );
            (candidate, status)
        })
        .collect();
    Ok((statuses, progress))
}

/// Evaluates a tenant's setup flows (always with answers: the tenant's administrators and the definer see them).
async fn tenant_statuses(
    tx: &Store,
    chain: &[Tenant],
    candidates: Option<Vec<CandidateFlow>>,
) -> IamResult<(Statuses, ProgressMap)> {
    let tenant = chain.first().ok_or_else(internal_error)?;
    let candidates = match candidates {
        Some(candidates) => candidates,
        None => candidate_flows(tx, chain, "tenant", None).await?,
    };
    let flows: Vec<CandidateFlow> = candidates
        .into_iter()
        .filter(|candidate| tenant_flow_applies(&candidate.flow, tenant))
        .collect();
    let progress = progress_for(tx, &tenant.id, &tenant.id).await?;
    let records: Vec<&Record> = flows.iter().map(|candidate| &candidate.flow).collect();
    let facts = tenant_facts(tx, tenant, &records).await?;
    let statuses = flows
        .into_iter()
        .map(|candidate| {
            let status = evaluate_flow(
                &candidate,
                progress.get(str_of(&candidate.flow, "id").unwrap_or("")),
                FlowFacts {
                    member: None,
                    tenant: Some(&facts),
                },
                true,
            );
            (candidate, status)
        })
        .collect();
    Ok((statuses, progress))
}

/// `status.required && !status.complete`.
fn pending_required(status: &Map<String, Value>) -> bool {
    flag_of(status, "required") && !flag_of(status, "complete")
}

/// A `MyOnboarding` object.
fn summarize(tenant: &Tenant, welcome: Map<String, Value>, statuses: Statuses) -> Value {
    let flows: Vec<Map<String, Value>> = statuses.into_iter().map(|(_, status)| status).collect();
    let pending = flows.iter().filter(|flow| pending_required(flow)).count();
    let mut summary = Map::new();
    summary.insert("tenant".into(), source_of(tenant));
    summary.insert("welcome".into(), Value::Object(welcome));
    summary.insert(
        "flows".into(),
        Value::Array(flows.into_iter().map(Value::Object).collect()),
    );
    summary.insert("pending".into(), number(pending as f64));
    summary.insert("complete".into(), Value::Bool(pending == 0));
    Value::Object(summary)
}

/// An `OnboardingSubjectProgress` object.
fn subject_progress(
    status: &Map<String, Value>,
    record: Option<&Record>,
    answers: bool,
) -> Map<String, Value> {
    let mut result = Map::new();
    let member = |key: &str| status.get(key).cloned().unwrap_or(Value::Null);
    result.insert("complete".into(), member("complete"));
    result.insert("done".into(), member("done"));
    result.insert("total".into(), member("total"));
    result.insert(
        "awaiting".into(),
        Value::Array(
            array_of(status, "steps")
                .iter()
                .filter_map(Value::as_object)
                .filter(|step| str_of(step, "state") == Some("submitted"))
                .map(|step| step.get("id").cloned().unwrap_or(Value::Null))
                .collect(),
        ),
    );
    if let Some(completed_at) = status.get("completedAt") {
        result.insert("completedAt".into(), completed_at.clone());
    }
    if let Some(record) = record {
        result.insert(
            "startedAt".into(),
            record.get("startedAt").cloned().unwrap_or(Value::Null),
        );
        if let Some(error) = record
            .get("completionError")
            .filter(|error| truthy(Some(error)))
        {
            result.insert("completionError".into(), error.clone());
        }
    }
    if answers {
        let mut collected = Map::new();
        for step in record
            .map(|record| array_of(record, "steps"))
            .unwrap_or(&[])
            .iter()
            .filter_map(Value::as_object)
        {
            if let Some(Value::Object(recorded)) = step.get("answers")
                && !recorded.is_empty()
            {
                collected.insert(
                    crate::js::js_string(step.get("stepId")),
                    Value::Object(recorded.clone()),
                );
            }
        }
        if !collected.is_empty() {
            result.insert("answers".into(), Value::Object(collected));
        }
    }
    result
}

/// Records one step the subject completed by hand: form answers, an acknowledgement, or a task (done, or submitted
/// for verification). Steps that complete on their own are refused. Returns the step's progress record.
fn complete_step(
    step: &Map<String, Value>,
    answers: Option<&Value>,
    acknowledged: Option<&Value>,
    actor_id: &str,
    now: f64,
) -> IamResult<Map<String, Value>> {
    let kind = str_of(step, "kind").unwrap_or("");
    if AUTOMATIC_STEPS.contains(&kind) {
        return Err(IamError::new(
            "INVALID_INPUT",
            if kind == "check" {
                "This step completes when the organization\u{2019}s setup meets it"
            } else {
                "This step completes on its own once you have done it"
            },
        ));
    }
    let mut record = Map::new();
    record.insert(
        "stepId".into(),
        step.get("id").cloned().unwrap_or(Value::Null),
    );
    if kind == "form" {
        record.insert("completedAt".into(), number(now));
        record.insert("completedBy".into(), Value::String(actor_id.to_owned()));
        record.insert(
            "answers".into(),
            Value::Object(parse_answers(step, answers)?),
        );
        return Ok(record);
    }
    if answers.is_some() {
        return Err(IamError::new(
            "INVALID_INPUT",
            "answers apply to form steps only",
        ));
    }
    if kind == "acknowledge" && acknowledged != Some(&Value::Bool(true)) {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Confirm that you have read this (acknowledged: true)",
        ));
    }
    if kind == "task" && str_of(step, "verification") == Some("admin") {
        record.insert("submittedAt".into(), number(now));
        record.insert("completedBy".into(), Value::String(actor_id.to_owned()));
        return Ok(record);
    }
    record.insert("completedAt".into(), number(now));
    record.insert("completedBy".into(), Value::String(actor_id.to_owned()));
    Ok(record)
}

/// The step of a flow with this ID (`flow.steps.find((item) => item.id === stepId)`).
fn find_step<'a>(flow: &'a Record, step_id: &Value) -> Option<&'a Map<String, Value>> {
    steps_of(flow).find(|step| {
        step.get("id")
            .is_some_and(|id| core_js::strict_equal(id, step_id))
    })
}

/// `{ id, name, email? }` of a person.
fn person(identity: &Identity) -> Value {
    let mut person = Map::new();
    person.insert("id".into(), Value::String(identity.id.clone()));
    person.insert("name".into(), Value::String(identity.name.clone()));
    if let Some(email) = identity.email.as_ref().filter(|email| !email.is_empty()) {
        person.insert("email".into(), Value::String(email.clone()));
    }
    Value::Object(person)
}

/// `a.createdAt - b.createdAt || a.name.localeCompare(b.name)` for flow records.
fn by_created_then_name(a: &Record, b: &Record) -> std::cmp::Ordering {
    let difference =
        num_of(a, "createdAt").unwrap_or(f64::NAN) - num_of(b, "createdAt").unwrap_or(f64::NAN);
    if difference < 0.0 {
        std::cmp::Ordering::Less
    } else if difference > 0.0 {
        std::cmp::Ordering::Greater
    } else {
        locale_compare(
            str_of(a, "name").unwrap_or(""),
            str_of(b, "name").unwrap_or(""),
        )
    }
}

/// The `onboarding` API group (`createOnboardingApi(ctx)`): one method per route `onboarding/{method}`.
pub struct OnboardingApi {
    ctx: Arc<ServerContext>,
}

/// `createOnboardingApi(ctx)`.
pub fn create_onboarding_api(ctx: &Arc<ServerContext>) -> IamResult<OnboardingApi> {
    Ok(OnboardingApi { ctx: ctx.clone() })
}

impl OnboardingApi {
    /// `onboarding/createFlow`: creates a flow at this tenant's level (member onboarding for its people or those
    /// below; setup for tenants below).
    pub async fn create_flow(
        &self,
        credential: &CredentialInput,
        input: Body<onboarding::CreateFlowInput>,
    ) -> IamResult<Reply<onboarding::CreateFlowOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let saved = save_flow(ctx, &tx, &principal, &tenant, body, None).await?;
                    Ok(Value::Object(saved))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:onboarding:manage",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `onboarding/deleteFlow`: deletes a flow and everyone's progress through it.
    pub async fn delete_flow(
        &self,
        credential: &CredentialInput,
        input: Body<onboarding::DeleteFlowInput>,
    ) -> IamResult<Reply<onboarding::DeleteFlowOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("flowId"), "flowId", 128)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let flow = scoped_flow(&tx, body.get("flowId"), &tenant.id).await?;
                let removed = delete_onboarding_flow(&tx, &flow).await?;
                Ok(json!({ "deleted": true, "progressRemoved": number(removed as f64) }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:onboarding:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `onboarding/effective`: everything onboarding looks like from this tenant: the member flows that reach its
    /// people (own and inherited, with where each comes from and whether it is switched off), the setup flows its
    /// administrators complete, the flows it defines for tenants below, and its welcome settings with the level each
    /// value comes from.
    pub async fn effective(
        &self,
        credential: &CredentialInput,
        input: Body<onboarding::EffectiveInput>,
    ) -> IamResult<Reply<onboarding::EffectiveOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let chain = ctx.ancestry(&tx, &tenant).await?;
                let settings = SettingsReader::new(&tx);
                let describe = |candidate: CandidateFlow| -> Value {
                    let mut item = Map::new();
                    item.insert(
                        "flow".into(),
                        Value::Object(if candidate.inherited {
                            public_flow(&candidate.flow)
                        } else {
                            candidate.flow.clone()
                        }),
                    );
                    item.insert("source".into(), source_of(&candidate.source));
                    item.insert("inherited".into(), Value::Bool(candidate.inherited));
                    if let Some(disabled_by) = &candidate.disabled_by {
                        item.insert("disabledBy".into(), source_of(disabled_by));
                    }
                    item.insert(
                        "canDisable".into(),
                        Value::Bool(
                            candidate.inherited
                                && str_of(&candidate.flow, "audience") == Some("member")
                                && !flag_of(&candidate.flow, "locked")
                                && candidate
                                    .disabled_by
                                    .as_ref()
                                    .is_none_or(|by| by.id == tenant.id),
                        ),
                    );
                    Value::Object(item)
                };
                let mut result = Map::new();
                result.insert("tenant".into(), source_of(&tenant));
                result.insert(
                    "levels".into(),
                    Value::Array(chain.iter().rev().map(source_of).collect()),
                );
                result.insert(
                    "memberFlows".into(),
                    Value::Array(
                        candidate_flows(&tx, &chain, "member", Some(&settings))
                            .await?
                            .into_iter()
                            .map(describe)
                            .collect(),
                    ),
                );
                result.insert(
                    "setupFlows".into(),
                    Value::Array(
                        candidate_flows(&tx, &chain, "tenant", Some(&settings))
                            .await?
                            .into_iter()
                            .filter(|candidate| tenant_flow_applies(&candidate.flow, &tenant))
                            .map(describe)
                            .collect(),
                    ),
                );
                let mut own = tx
                    .find(
                        "onboardingFlows",
                        &Filter::new().eq("tenantId", tenant.id.clone()),
                        &FindOptions::default(),
                    )
                    .await?;
                own.sort_by(by_created_then_name);
                result.insert(
                    "ownFlows".into(),
                    Value::Array(own.into_iter().map(Value::Object).collect()),
                );
                let mut types: Vec<String> =
                    descendant_types(ctx, &tenant.kind).into_iter().collect();
                types.sort_by(|a, b| core_js::cmp_utf16(a, b));
                result.insert(
                    "descendantTypes".into(),
                    Value::Array(types.into_iter().map(Value::String).collect()),
                );
                result.insert(
                    "identityAttributes".into(),
                    serde_json::to_value(&ctx.catalog.identity_attributes)
                        .map_err(|_| internal_error())?,
                );
                let mut settings_view = Map::new();
                if let Some(own) = settings.get(&tenant.id).await? {
                    settings_view.insert("own".into(), Value::Object(own));
                }
                settings_view.insert(
                    "resolved".into(),
                    Value::Object(resolve_settings(&chain, &settings).await?),
                );
                result.insert("settings".into(), Value::Object(settings_view));
                Ok(Value::Object(result))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:onboarding:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `onboarding/getFlow`.
    pub async fn get_flow(
        &self,
        credential: &CredentialInput,
        input: Body<onboarding::GetFlowInput>,
    ) -> IamResult<Reply<onboarding::GetFlowOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("flowId"), "flowId", 128)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                Ok(Value::Object(
                    scoped_flow(&tx, body.get("flowId"), &tenant.id).await?,
                ))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:onboarding:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `onboarding/listFlows`: the flows this tenant defines, oldest first.
    pub async fn list_flows(
        &self,
        credential: &CredentialInput,
        input: Body<onboarding::ListFlowsInput>,
    ) -> IamResult<Reply<onboarding::ListFlowsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let audience = body.get("audience");
                let mut flows: Vec<Record> = tx
                    .find(
                        "onboardingFlows",
                        &Filter::new().eq("tenantId", tenant.id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                    .into_iter()
                    .filter(|flow| {
                        audience.is_none_or(|audience| {
                            flow.get("audience")
                                .is_some_and(|value| core_js::strict_equal(value, audience))
                        })
                    })
                    .collect();
                flows.sort_by(by_created_then_name);
                Ok(Value::Array(flows.into_iter().map(Value::Object).collect()))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:onboarding:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `onboarding/memberProgress`: one person's onboarding in this tenant, with their answers (for member pages).
    pub async fn member_progress(
        &self,
        credential: &CredentialInput,
        input: Body<onboarding::MemberProgressInput>,
    ) -> IamResult<Reply<onboarding::MemberProgressOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("identityId"), "identityId", 256)?;
        let identity_id = &resource;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let identity = ctx.active_identity(&tx, identity_id, &tenant.id).await?;
                let chain = ctx.ancestry(&tx, &tenant).await?;
                let (statuses, _) =
                    member_statuses(ctx, &tx, &chain, &identity, true, None).await?;
                let flows: Vec<Map<String, Value>> =
                    statuses.into_iter().map(|(_, status)| status).collect();
                let pending = flows.iter().filter(|flow| pending_required(flow)).count();
                let mut result = Map::new();
                result.insert("identity".into(), person(&identity));
                result.insert(
                    "flows".into(),
                    Value::Array(flows.into_iter().map(Value::Object).collect()),
                );
                result.insert("pending".into(), number(pending as f64));
                Ok(Value::Object(result))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:onboarding:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `onboarding/mine`: the caller's own onboarding: welcome copy and their member flows; needs only an ordinary
    /// session of the tenant.
    pub async fn mine(
        &self,
        credential: &CredentialInput,
        input: Body<onboarding::MineInput>,
    ) -> IamResult<Reply<onboarding::MineOutput>> {
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = self.ctx.principals()?.authenticate(credential).await?;
        let ctx = self.ctx.clone();
        let (result, pending_groups, identity_id) = {
            let ctx = ctx.clone();
            let tenant_id = tenant_id.clone();
            ctx.store
                .clone()
                .transaction(move |tx| async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, &authenticated)
                        .await?;
                    self_session(&principal, &tenant_id)?;
                    let tenant = ctx.tenant(&tx, &tenant_id).await?;
                    let chain = ctx.ancestry(&tx, &tenant).await?;
                    let (mut statuses, mut progress) =
                        member_statuses(&ctx, &tx, &chain, &principal.identity, true, None).await?;
                    // Completions are recorded for the person themselves, never while an administrator views as
                    // them.
                    let pending_groups = if impersonating(&principal) {
                        Vec::new()
                    } else {
                        record_completions(
                            &ctx,
                            &tx,
                            &principal,
                            &Subject {
                                kind: "identity",
                                id: principal.identity.id.clone(),
                                tenant_id: tenant_id.clone(),
                            },
                            &mut statuses,
                            &mut progress,
                        )
                        .await?
                    };
                    let welcome = resolve_settings(&chain, &SettingsReader::new(&tx)).await?;
                    Ok((
                        summarize(&tenant, welcome, statuses),
                        pending_groups,
                        principal.identity.id.clone(),
                    ))
                })
                .await?
        };
        if !pending_groups.is_empty() {
            apply_completion_groups(&ctx, &tenant_id, &identity_id, &pending_groups).await?;
        }
        Ok(Reply::json(result))
    }

    /// `onboarding/progress`: progress through one flow as seen from this tenant. Member flows (own or inherited)
    /// list this tenant's people the flow applies to, with their answers; a flow defined here that reaches
    /// descendant tenants adds per-tenant counts (never names). Tenant setup flows defined here list every descendant
    /// tenant they apply to, with its answers.
    pub async fn progress(
        &self,
        credential: &CredentialInput,
        input: Body<onboarding::ProgressInput>,
    ) -> IamResult<Reply<onboarding::ProgressOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("flowId"), "flowId", 128)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move { progress_report(ctx, &tx, &tenant, body).await })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:onboarding:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `onboarding/resetProgress`: clears progress so people (or tenants) go through a flow, or one step of it,
    /// again. The tenant that defines the flow may reset anyone it reaches (everyone when `subjectId` is omitted); a
    /// tenant the flow reaches may reset its own people. Resetting one's own progress through a flow with completion
    /// groups needs the right to add oneself to those groups. Audited as `onboarding:reset`.
    pub async fn reset_progress(
        &self,
        credential: &CredentialInput,
        input: Body<onboarding::ResetProgressInput>,
    ) -> IamResult<Reply<onboarding::ResetProgressOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("flowId"), "flowId", 128)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let flow = flow_record(&tx, body.get("flowId")).await?;
                    let flow_id = str_of(&flow, "id").unwrap_or("").to_owned();
                    let flow_tenant = str_of(&flow, "tenantId").unwrap_or("").to_owned();
                    let step_id = match body.get("stepId") {
                        None => None,
                        Some(value) => Some(text(Some(value), "stepId", 64)?),
                    };
                    if let Some(step_id) = &step_id
                        && find_step(&flow, &Value::String(step_id.clone())).is_none()
                    {
                        return Err(step_not_found().into());
                    }
                    let definer = flow_tenant == tenant.id;
                    if !definer {
                        if str_of(&flow, "audience") != Some("member") {
                            return Err(flow_not_found().into());
                        }
                        let chain = ctx.ancestry(&tx, &tenant).await?;
                        if !candidate_flows(&tx, &chain, "member", None)
                            .await?
                            .iter()
                            .any(|item| str_of(&item.flow, "id") == Some(flow_id.as_str()))
                        {
                            return Err(flow_not_found().into());
                        }
                    }
                    let subject_id = match body.get("subjectId") {
                        None => None,
                        Some(value) => Some(text(Some(value), "subjectId", 128)?),
                    };
                    let mut filter = Filter::new().eq("flowId", flow_id.clone());
                    if let Some(subject_id) = &subject_id {
                        filter = filter.eq("subjectId", subject_id.clone());
                    }
                    let records: Vec<Record> = tx
                        .find("onboardingProgress", &filter, &FindOptions::default())
                        .await?
                        .into_iter()
                        .filter(|record| {
                            definer || str_of(record, "tenantId") == Some(tenant.id.as_str())
                        })
                        .collect();
                    // Finishing the flow again would put the caller back into its completion groups (after an
                    // administrator took them out, say), so resetting one's own progress needs the right to add
                    // oneself to them.
                    let group_ids: Vec<String> = array_of(&flow, "completionGroupIds")
                        .iter()
                        .map(|id| crate::js::js_string(Some(id)))
                        .collect();
                    if !group_ids.is_empty()
                        && records.iter().any(|record| {
                            str_of(record, "subjectId") == Some(principal.identity.id.as_str())
                                && str_of(record, "tenantId") == Some(flow_tenant.as_str())
                        })
                    {
                        for group_id in &group_ids {
                            if authorize_completion_group(
                                ctx,
                                &tx,
                                &principal,
                                &flow_tenant,
                                group_id,
                            )
                            .await
                            .is_err()
                            {
                                return Err(IamError::with_status(
                                    "ACCESS_DENIED",
                                    "Resetting your own progress through a flow with completion groups needs the right to add yourself to them",
                                    403,
                                )
                                .into());
                            }
                        }
                    }
                    for record in &records {
                        match &step_id {
                            None => {
                                tx.delete("onboardingProgress", str_of(record, "id").unwrap_or(""))
                                    .await?;
                            }
                            Some(step_id) => {
                                let mut rest = record.clone();
                                rest.shift_remove("completedAt");
                                rest.shift_remove("completedVersion");
                                let steps: Vec<Value> = array_of(record, "steps")
                                    .iter()
                                    .filter(|step| {
                                        step.as_object().and_then(|step| str_of(step, "stepId"))
                                            != Some(step_id.as_str())
                                    })
                                    .cloned()
                                    .collect();
                                rest.insert("steps".into(), Value::Array(steps));
                                rest.insert("updatedAt".into(), number(ctx.now()));
                                tx.put("onboardingProgress", &rest).await?;
                            }
                        }
                    }
                    let mut metadata = Map::new();
                    metadata.insert("flowId".into(), Value::String(flow_id.clone()));
                    metadata.insert(
                        "flow".into(),
                        flow.get("name").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert("reset".into(), number(records.len() as f64));
                    if let Some(subject_id) = &subject_id {
                        metadata.insert("subjectId".into(), Value::String(subject_id.clone()));
                    }
                    if let Some(step_id) = &step_id {
                        metadata.insert("stepId".into(), Value::String(step_id.clone()));
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "onboarding:reset",
                            &tenant.id,
                            &flow_id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(json!({ "reset": number(records.len() as f64) }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:onboarding:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `onboarding/setSettings`: replaces this tenant's onboarding settings: welcome title and message, support
    /// contacts, and the inherited (unlocked) member flows switched off for this tenant and every tenant below it.
    /// `null` values clear a field.
    pub async fn set_settings(
        &self,
        credential: &CredentialInput,
        input: Body<onboarding::SetSettingsInput>,
    ) -> IamResult<Reply<onboarding::SetSettingsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let mut values = parse_settings(body)?;
                let previous = tx
                    .get("onboardingSettings", &settings_id(&tenant.id))
                    .await?;
                let disabled: Vec<String> = array_of(&values, "disabledFlowIds")
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect();
                if !disabled.is_empty() {
                    let chain = ctx.ancestry(&tx, &tenant).await?;
                    let switchable: HashMap<String, Record> =
                        candidate_flows(&tx, &chain, "member", Some(&SettingsReader::new(&tx)))
                            .await?
                            .into_iter()
                            .filter(|candidate| candidate.inherited)
                            .map(|candidate| {
                                (
                                    str_of(&candidate.flow, "id").unwrap_or("").to_owned(),
                                    candidate.flow,
                                )
                            })
                            .collect();
                    let previously_disabled = |flow_id: &str| {
                        previous.as_ref().is_some_and(|previous| {
                            array_of(previous, "disabledFlowIds")
                                .iter()
                                .any(|id| id.as_str() == Some(flow_id))
                        })
                    };
                    // A switch kept from before whose flow no longer reaches here (deleted, retargeted, or now
                    // locked) is dropped quietly, so re-saving the settings never fails on someone else's change.
                    let kept: Vec<String> = disabled
                        .into_iter()
                        .filter(|flow_id| {
                            switchable
                                .get(flow_id)
                                .is_some_and(|flow| !flag_of(flow, "locked"))
                                || !previously_disabled(flow_id)
                        })
                        .collect();
                    for flow_id in &kept {
                        let Some(flow) = switchable.get(flow_id) else {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                format!(
                                    "disabledFlowIds: {flow_id} is not an inherited member flow of this tenant"
                                ),
                            )
                            .into());
                        };
                        if flag_of(flow, "locked") {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                format!(
                                    "disabledFlowIds: {} is locked by the tenant that defines it",
                                    crate::js::js_string(flow.get("name"))
                                ),
                            )
                            .into());
                        }
                    }
                    values.insert(
                        "disabledFlowIds".into(),
                        Value::Array(kept.into_iter().map(Value::String).collect()),
                    );
                }
                let mut record = Map::new();
                record.insert("id".into(), Value::String(settings_id(&tenant.id)));
                record.insert("tenantId".into(), Value::String(tenant.id.clone()));
                for (key, value) in values {
                    record.insert(key, value);
                }
                record.insert("updatedAt".into(), number(ctx.now()));
                let saved = if previous.is_some() {
                    tx.put("onboardingSettings", &record).await?
                } else {
                    tx.insert("onboardingSettings", &record).await?
                };
                Ok(Value::Object(saved))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:onboarding:manage",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `onboarding/setup`: this tenant's own setup checklists (defined by the tenants above it), with the state of
    /// every step.
    pub async fn setup(
        &self,
        credential: &CredentialInput,
        input: Body<onboarding::SetupInput>,
    ) -> IamResult<Reply<onboarding::SetupOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let chain = ctx.ancestry(&tx, &tenant).await?;
                    let (mut statuses, mut progress) = tenant_statuses(&tx, &chain, None).await?;
                    if !impersonating(&principal) {
                        record_completions(
                            ctx,
                            &tx,
                            &principal,
                            &Subject {
                                kind: "tenant",
                                id: tenant.id.clone(),
                                tenant_id: tenant.id.clone(),
                            },
                            &mut statuses,
                            &mut progress,
                        )
                        .await?;
                    }
                    let welcome = resolve_settings(&chain, &SettingsReader::new(&tx)).await?;
                    Ok(summarize(&tenant, welcome, statuses))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:onboarding:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `onboarding/submitSetupStep`: completes a form, acknowledgement or task step of this tenant's setup; check
    /// steps follow the tenant's state.
    pub async fn submit_setup_step(
        &self,
        credential: &CredentialInput,
        input: Body<onboarding::SubmitSetupStepInput>,
    ) -> IamResult<Reply<onboarding::SubmitSetupStepOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("flowId"), "flowId", 128)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    not_impersonating(&principal, "Setup steps cannot be completed")?;
                    let step_id = text(body.get("stepId"), "stepId", 64)?;
                    let chain = ctx.ancestry(&tx, &tenant).await?;
                    let wanted = body.get("flowId").cloned().unwrap_or(Value::Null);
                    let candidate = candidate_flows(&tx, &chain, "tenant", None)
                        .await?
                        .into_iter()
                        .find(|item| {
                            item.flow
                                .get("id")
                                .is_some_and(|id| core_js::strict_equal(id, &wanted))
                                && tenant_flow_applies(&item.flow, &tenant)
                        })
                        .ok_or_else(flow_not_found)?;
                    let step = find_step(&candidate.flow, &Value::String(step_id.clone()))
                        .ok_or_else(step_not_found)?
                        .clone();
                    let now = ctx.now();
                    let record = complete_step(
                        &step,
                        body.get("answers"),
                        body.get("acknowledged"),
                        &principal.identity.id,
                        now,
                    )?;
                    let awaiting = record.contains_key("submittedAt");
                    let subject = Subject {
                        kind: "tenant",
                        id: tenant.id.clone(),
                        tenant_id: tenant.id.clone(),
                    };
                    let flow_id = str_of(&candidate.flow, "id").unwrap_or("").to_owned();
                    let mut progress = progress_for(&tx, &tenant.id, &tenant.id).await?;
                    let existing = progress.get(&flow_id).cloned();
                    let mut next = with_step(
                        &existing
                            .clone()
                            .unwrap_or_else(|| new_progress(&candidate.flow, &subject, now)),
                        record,
                    );
                    next.insert("updatedAt".into(), number(now));
                    let saved = upsert_progress(&tx, &next, existing.is_some()).await?;
                    progress.insert(flow_id.clone(), saved);
                    let mut metadata = Map::new();
                    metadata.insert("flowId".into(), Value::String(flow_id.clone()));
                    metadata.insert(
                        "flow".into(),
                        candidate.flow.get("name").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert("stepId".into(), Value::String(step_id.clone()));
                    metadata.insert(
                        "kind".into(),
                        step.get("kind").cloned().unwrap_or(Value::Null),
                    );
                    if awaiting {
                        metadata.insert("awaitingVerification".into(), Value::Bool(true));
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "onboarding:step",
                            &tenant.id,
                            &tenant.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    let facts = tenant_facts(&tx, &tenant, &[&candidate.flow]).await?;
                    let status = evaluate_flow(
                        &candidate,
                        progress.get(&flow_id),
                        FlowFacts {
                            member: None,
                            tenant: Some(&facts),
                        },
                        true,
                    );
                    let mut statuses = vec![(candidate, status)];
                    record_completions(
                        ctx,
                        &tx,
                        &principal,
                        &subject,
                        &mut statuses,
                        &mut progress,
                    )
                    .await?;
                    let (_, status) = statuses.pop().ok_or_else(internal_error)?;
                    Ok(json!({ "flow": Value::Object(status) }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:onboarding:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `onboarding/submitStep`: completes one step of the caller's own flow: `answers` for a form, `acknowledged:
    /// true` for an acknowledgement, nothing for a task (an admin-verified task waits for an administrator). Answers
    /// mapped to identity attributes fill only empty attributes. Impersonating administrators cannot complete steps on
    /// someone's behalf. Audited as `onboarding:step`, and `onboarding:complete` when the flow is done.
    pub async fn submit_step(
        &self,
        credential: &CredentialInput,
        input: Body<onboarding::SubmitStepInput>,
    ) -> IamResult<Reply<onboarding::SubmitStepOutput>> {
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let flow_id = text(input.get("flowId"), "flowId", 128)?;
        let step_id = text(input.get("stepId"), "stepId", 64)?;
        let answers = input.get("answers").cloned();
        let acknowledged = input.get("acknowledged").cloned();
        let authenticated = self.ctx.principals()?.authenticate(credential).await?;
        let ctx = self.ctx.clone();
        let (status, filled, pending_groups, identity_id) = {
            let ctx = ctx.clone();
            let tenant_id = tenant_id.clone();
            ctx.store
                .clone()
                .transaction(move |tx| async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, &authenticated)
                        .await?;
                    self_session(&principal, &tenant_id)?;
                    not_impersonating(&principal, "Onboarding steps cannot be completed")?;
                    if principal.identity.kind != IdentityKind::User {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "Only people complete onboarding",
                        ));
                    }
                    let tenant = boxed(|| ctx.tenant(&tx, &tenant_id)).await?;
                    let chain = boxed(|| ctx.ancestry(&tx, &tenant)).await?;
                    let now = ctx.now();
                    let candidate =
                        boxed(|| flows_for_identity(&tx, &chain, &principal.identity, now, None))
                            .await?
                            .into_iter()
                            .find(|item| str_of(&item.flow, "id") == Some(flow_id.as_str()))
                            .ok_or_else(flow_not_found)?;
                    let step = find_step(&candidate.flow, &Value::String(step_id.clone()))
                        .ok_or_else(step_not_found)?
                        .clone();
                    let record = complete_step(
                        &step,
                        answers.as_ref(),
                        acknowledged.as_ref(),
                        &principal.identity.id,
                        now,
                    )?;
                    // Answers fill the person's empty declared attributes, and only in the tenant that defines the
                    // flow (a flow inherited from above records answers but never writes this tenant's identities);
                    // values someone else set are kept, and every value passes the same validation as
                    // identities.update.
                    let mut filled: Vec<String> = Vec::new();
                    let mut identity = principal.identity.clone();
                    if str_of(&step, "kind") == Some("form")
                        && str_of(&candidate.flow, "tenantId") == Some(tenant_id.as_str())
                    {
                        let mut attributes = identity.attributes.clone().unwrap_or_default();
                        let recorded = record.get("answers").and_then(Value::as_object);
                        for field in array_of(&step, "fields")
                            .iter()
                            .filter_map(Value::as_object)
                        {
                            let name = str_of(field, "name").unwrap_or("");
                            let value = recorded.and_then(|answers| answers.get(name));
                            let attribute = field
                                .get("attribute")
                                .filter(|attribute| truthy(Some(attribute)))
                                .map(|attribute| crate::js::js_string(Some(attribute)));
                            let (Some(attribute), Some(value)) = (attribute, value) else {
                                continue;
                            };
                            if attributes.contains_key(&attribute) {
                                continue;
                            }
                            if str_of(field, "type") == Some("boolean")
                                && value == &Value::Bool(false)
                                && !flag_of(field, "required")
                            {
                                continue;
                            }
                            let mut single = Map::new();
                            single.insert(attribute.clone(), value.clone());
                            for (key, value) in attribute_values(
                                &ctx.catalog.identity_attributes,
                                Some(&Value::Object(single)),
                            )? {
                                attributes.insert(key, value);
                            }
                            filled.push(attribute);
                        }
                        if !filled.is_empty() {
                            let mut raw = boxed(|| tx.get("identities", &identity.id))
                                .await?
                                .ok_or_else(internal_error)?;
                            raw.insert("attributes".into(), Value::Object(attributes));
                            identity = decode(boxed(|| tx.put("identities", &raw)).await?)?;
                        }
                    }
                    let mut progress =
                        boxed(|| progress_for(&tx, &tenant_id, &identity.id)).await?;
                    let existing = progress.get(&flow_id).cloned();
                    let subject = Subject {
                        kind: "identity",
                        id: identity.id.clone(),
                        tenant_id: tenant_id.clone(),
                    };
                    let awaiting = record.contains_key("submittedAt");
                    let mut next = with_step(
                        &existing
                            .clone()
                            .unwrap_or_else(|| new_progress(&candidate.flow, &subject, now)),
                        record,
                    );
                    next.insert("updatedAt".into(), number(now));
                    let saved = boxed(|| upsert_progress(&tx, &next, existing.is_some())).await?;
                    progress.insert(flow_id.clone(), saved);
                    let mut metadata = Map::new();
                    metadata.insert("flowId".into(), Value::String(flow_id.clone()));
                    metadata.insert(
                        "flow".into(),
                        candidate.flow.get("name").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert("stepId".into(), Value::String(step_id.clone()));
                    metadata.insert(
                        "kind".into(),
                        step.get("kind").cloned().unwrap_or(Value::Null),
                    );
                    if awaiting {
                        metadata.insert("awaitingVerification".into(), Value::Bool(true));
                    }
                    if !filled.is_empty() {
                        metadata.insert(
                            "attributes".into(),
                            Value::Array(filled.iter().cloned().map(Value::String).collect()),
                        );
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "onboarding:step",
                            &tenant_id,
                            &identity.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    let facts = boxed(|| async {
                        member_facts(&tx, &identity, &[&candidate.flow], now).await
                    })
                    .await?;
                    let status = evaluate_flow(
                        &candidate,
                        progress.get(&flow_id),
                        FlowFacts {
                            member: Some((&identity, &facts)),
                            tenant: None,
                        },
                        true,
                    );
                    let mut statuses = vec![(candidate, status)];
                    let acting = AuthenticatedPrincipal {
                        identity: identity.clone(),
                        ..principal.clone()
                    };
                    let pending_groups = boxed(|| {
                        record_completions(
                            &ctx,
                            &tx,
                            &acting,
                            &subject,
                            &mut statuses,
                            &mut progress,
                        )
                    })
                    .await?;
                    let (_, status) = statuses.pop().ok_or_else(internal_error)?;
                    Ok((status, filled, pending_groups, identity.id.clone()))
                })
                .await?
        };
        if !pending_groups.is_empty() {
            boxed(|| apply_completion_groups(&ctx, &tenant_id, &identity_id, &pending_groups))
                .await?;
        } else if !filled.is_empty() {
            boxed(|| async {
                crate::api::package_automation::after_identity_change(
                    &ctx,
                    &tenant_id,
                    &[identity_id],
                    &Value::Null,
                )
                .await
            })
            .await?;
        }
        Ok(Reply::json(json!({
            "flow": Value::Object(status),
            "attributesFilled": filled,
        })))
    }

    /// `onboarding/updateFlow`: edits a flow. Changing the steps bumps the version: finished steps stay finished
    /// (progress is kept per step ID), and a new required step reopens the flow for everyone it applies to.
    pub async fn update_flow(
        &self,
        credential: &CredentialInput,
        input: Body<onboarding::UpdateFlowInput>,
    ) -> IamResult<Reply<onboarding::UpdateFlowOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("flowId"), "flowId", 128)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let previous = scoped_flow(&tx, body.get("flowId"), &tenant.id).await?;
                    let mut changes: Map<String, Value> = (**body).clone();
                    changes.shift_remove("tenantId");
                    changes.shift_remove("flowId");
                    let saved =
                        save_flow(ctx, &tx, &principal, &tenant, &changes, Some(&previous)).await?;
                    Ok(Value::Object(saved))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:onboarding:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `onboarding/verifyStep`: approves (the default) or sends back an administrator-verified task. For member
    /// flows the caller administers the person's tenant (`tenantId` is the person's tenant); for setup flows the
    /// caller administers the tenant that defines the flow and names the tenant being set up as `subjectId`. Audited
    /// as `onboarding:verify` or `onboarding:reject`.
    pub async fn verify_step(
        &self,
        credential: &CredentialInput,
        input: Body<onboarding::VerifyStepInput>,
    ) -> IamResult<Reply<onboarding::VerifyStepOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("subjectId"), "subjectId", 128)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move { verify(ctx, &tx, &principal, &tenant, body).await })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:onboarding:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// The subject of an administrator verification, with what evaluating their flow needs.
enum Verified {
    Member(Identity),
    Tenant(Tenant),
}

/// The mutation of `verifyStep`.
async fn verify(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant: &Tenant,
    body: &Map<String, Value>,
) -> OperationResult<Value> {
    not_impersonating(principal, "Onboarding steps cannot be verified")?;
    let approve = match crate::js::defined(body.get("approve")) {
        None => true,
        Some(Value::Bool(approve)) => *approve,
        Some(_) => {
            return Err(IamError::new("INVALID_INPUT", "approve must be a boolean").into());
        }
    };
    let note = match body.get("note") {
        None => None,
        Some(Value::String(note)) if note.is_empty() => None,
        Some(value) => Some(core_js::trim(&text(Some(value), "note", 500)?).to_owned()),
    };
    let flow = boxed(|| flow_record(tx, body.get("flowId"))).await?;
    let flow_id = str_of(&flow, "id").unwrap_or("").to_owned();
    let now = ctx.now();
    let (candidate, subject, verified) = if str_of(&flow, "audience") == Some("member") {
        let identity = boxed(|| async {
            ctx.active_identity(tx, &string_member(body, "subjectId"), &tenant.id)
                .await
        })
        .await?;
        if identity.id == principal.identity.id {
            return Err(IamError::new(
                "INVALID_INPUT",
                "People cannot verify their own onboarding",
            )
            .into());
        }
        let chain = boxed(|| ctx.ancestry(tx, tenant)).await?;
        let candidate = boxed(|| flows_for_identity(tx, &chain, &identity, now, None))
            .await?
            .into_iter()
            .find(|item| str_of(&item.flow, "id") == Some(flow_id.as_str()));
        let subject = Subject {
            kind: "identity",
            id: identity.id.clone(),
            tenant_id: tenant.id.clone(),
        };
        (candidate, subject, Verified::Member(identity))
    } else {
        if str_of(&flow, "tenantId") != Some(tenant.id.as_str()) {
            return Err(flow_not_found().into());
        }
        let target = ctx
            .tenant(tx, &text(body.get("subjectId"), "subjectId", 128)?)
            .await?;
        let target_chain = boxed(|| ctx.ancestry(tx, &target)).await?;
        if !target_chain.iter().skip(1).any(|item| item.id == tenant.id) {
            return Err(IamError::with_status("NOT_FOUND", "Tenant not found", 404).into());
        }
        let candidate = boxed(|| candidate_flows(tx, &target_chain, "tenant", None))
            .await?
            .into_iter()
            .find(|item| {
                str_of(&item.flow, "id") == Some(flow_id.as_str())
                    && tenant_flow_applies(&item.flow, &target)
            });
        let subject = Subject {
            kind: "tenant",
            id: target.id.clone(),
            tenant_id: target.id.clone(),
        };
        (candidate, subject, Verified::Tenant(target))
    };
    let candidate = candidate.ok_or_else(flow_not_found)?;
    let wanted = body.get("stepId").cloned().unwrap_or(Value::Null);
    let step = find_step(&flow, &wanted)
        .filter(|step| {
            str_of(step, "kind") == Some("task") && str_of(step, "verification") == Some("admin")
        })
        .ok_or_else(|| {
            IamError::new(
                "INVALID_INPUT",
                "Only administrator-verified tasks are verified",
            )
        })?
        .clone();
    let mut progress = boxed(|| progress_for(tx, &subject.tenant_id, &subject.id)).await?;
    let existing = progress.get(&flow_id).cloned();
    let mut record = Map::new();
    record.insert(
        "stepId".into(),
        step.get("id").cloned().unwrap_or(Value::Null),
    );
    if approve {
        record.insert("completedAt".into(), number(now));
        record.insert("completedBy".into(), Value::String(subject.id.clone()));
    } else {
        record.insert("rejectedAt".into(), number(now));
    }
    record.insert(
        "verifiedBy".into(),
        Value::String(principal.identity.id.clone()),
    );
    if let Some(note) = note.as_ref().filter(|note| !note.is_empty()) {
        record.insert("note".into(), Value::String(note.clone()));
    }
    let mut next = with_step(
        &existing
            .clone()
            .unwrap_or_else(|| new_progress(&flow, &subject, now)),
        record,
    );
    next.insert("updatedAt".into(), number(now));
    let saved = boxed(|| upsert_progress(tx, &next, existing.is_some())).await?;
    progress.insert(flow_id.clone(), saved);
    let mut metadata = Map::new();
    metadata.insert("flowId".into(), Value::String(flow_id.clone()));
    metadata.insert(
        "flow".into(),
        flow.get("name").cloned().unwrap_or(Value::Null),
    );
    metadata.insert(
        "stepId".into(),
        step.get("id").cloned().unwrap_or(Value::Null),
    );
    metadata.insert("subjectType".into(), Value::String(subject.kind.to_owned()));
    if let Some(note) = note.as_ref().filter(|note| !note.is_empty()) {
        metadata.insert("note".into(), Value::String(note.clone()));
    }
    ctx.events()?
        .audit(
            tx,
            principal,
            if approve {
                "onboarding:verify"
            } else {
                "onboarding:reject"
            },
            &tenant.id,
            &subject.id,
            AuditOutcome::Allow,
            false,
            Some(metadata),
        )
        .await?;
    let status = match &verified {
        Verified::Member(identity) => {
            let facts = boxed(|| async { member_facts(tx, identity, &[&flow], now).await }).await?;
            evaluate_flow(
                &candidate,
                progress.get(&flow_id),
                FlowFacts {
                    member: Some((identity, &facts)),
                    tenant: None,
                },
                true,
            )
        }
        Verified::Tenant(target) => {
            let facts = boxed(|| async { tenant_facts(tx, target, &[&flow]).await }).await?;
            evaluate_flow(
                &candidate,
                progress.get(&flow_id),
                FlowFacts {
                    member: None,
                    tenant: Some(&facts),
                },
                true,
            )
        }
    };
    // Completion is recorded here; completion groups are applied the next time the person reads their onboarding.
    let mut statuses = vec![(candidate, status)];
    boxed(|| record_completions(ctx, tx, principal, &subject, &mut statuses, &mut progress))
        .await?;
    let (_, status) = statuses.pop().ok_or_else(internal_error)?;
    Ok(json!({ "flow": Value::Object(status) }))
}

/// The mutation of `progress` (an `OnboardingProgressReport`).
async fn progress_report(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant: &Tenant,
    body: &Map<String, Value>,
) -> OperationResult<Value> {
    let flow = boxed(|| flow_record(tx, body.get("flowId"))).await?;
    let flow_id = str_of(&flow, "id").unwrap_or("").to_owned();
    let audience = str_of(&flow, "audience").unwrap_or("").to_owned();
    let defined_here = str_of(&flow, "tenantId") == Some(tenant.id.as_str());
    let chain = boxed(|| ctx.ancestry(tx, tenant)).await?;
    let settings = SettingsReader::new(tx);
    let now = ctx.now();
    let candidate = if defined_here {
        Some(CandidateFlow {
            flow: flow.clone(),
            source: tenant.clone(),
            inherited: false,
            depth: 0,
            disabled_by: None,
        })
    } else {
        boxed(|| candidate_flows(tx, &chain, &audience, Some(&settings)))
            .await?
            .into_iter()
            .find(|item| str_of(&item.flow, "id") == Some(flow_id.as_str()))
    };
    let candidate = match candidate {
        Some(candidate) if !(audience == "tenant" && !defined_here) => candidate,
        _ => return Err(flow_not_found().into()),
    };
    let mut flow_view = Map::new();
    let member = |key: &str| flow.get(key).cloned().unwrap_or(Value::Null);
    flow_view.insert("id".into(), member("id"));
    flow_view.insert("name".into(), member("name"));
    flow_view.insert("audience".into(), member("audience"));
    flow_view.insert("version".into(), member("version"));
    flow_view.insert("required".into(), member("required"));
    flow_view.insert("source".into(), source_of(&candidate.source));
    flow_view.insert("inherited".into(), Value::Bool(candidate.inherited));
    if let Some(disabled_by) = &candidate.disabled_by {
        flow_view.insert("disabledBy".into(), source_of(disabled_by));
    }
    let mut report = Map::new();
    report.insert("flow".into(), Value::Object(flow_view));
    report.insert(
        "summary".into(),
        json!({ "subjects": number(0.0), "complete": number(0.0) }),
    );
    let summary = |rows: &[Value]| {
        let complete = rows
            .iter()
            .filter(|row| row.get("complete") == Some(&Value::Bool(true)))
            .count();
        json!({ "subjects": number(rows.len() as f64), "complete": number(complete as f64) })
    };
    if audience == "tenant" {
        let (tenants, truncated) = boxed(|| descendants_of(tx, tenant)).await?;
        let mut rows: Vec<Value> = Vec::new();
        report.insert("tenants".into(), Value::Array(Vec::new()));
        for target in tenants {
            if target.status == TenantStatus::Deleted {
                continue;
            }
            let target_chain = boxed(|| ctx.ancestry(tx, &target)).await?;
            let Some(found) =
                boxed(|| candidate_flows(tx, &target_chain, "tenant", Some(&settings)))
                    .await?
                    .into_iter()
                    .find(|item| {
                        str_of(&item.flow, "id") == Some(flow_id.as_str())
                            && tenant_flow_applies(&item.flow, &target)
                    })
            else {
                continue;
            };
            let (statuses, progress) =
                boxed(|| tenant_statuses(tx, &target_chain, Some(vec![found]))).await?;
            let (_, status) = statuses.first().ok_or_else(internal_error)?;
            let mut source = match source_of(&target) {
                Value::Object(map) => map,
                _ => Map::new(),
            };
            source.insert(
                "status".into(),
                Value::String(tenant_status(target.status).to_owned()),
            );
            let mut row = Map::new();
            row.insert("tenant".into(), Value::Object(source));
            for (key, value) in subject_progress(status, progress.get(&flow_id), true) {
                row.insert(key, value);
            }
            rows.push(Value::Object(row));
        }
        report.insert("summary".into(), summary(&rows));
        report.insert("tenants".into(), Value::Array(rows));
        if truncated {
            report.insert("truncated".into(), Value::Bool(true));
        }
        return Ok(Value::Object(report));
    }
    report.insert("members".into(), Value::Array(Vec::new()));
    let mut rows: Vec<Value> = Vec::new();
    let reaches_here = if candidate.inherited || str_of(&flow, "appliesTo") != Some("descendants") {
        candidate.disabled_by.is_none()
    } else {
        false
    };
    if reaches_here {
        let mut people: Vec<Identity> = Vec::new();
        for record in boxed(|| async {
            tx.find(
                "identities",
                &Filter::new().eq("tenantId", tenant.id.clone()),
                &FindOptions::default(),
            )
            .await
        })
        .await?
        {
            let identity: Identity = decode(record)?;
            if identity.kind == IdentityKind::User && identity.status == IdentityStatus::Active {
                people.push(identity);
            }
        }
        people.sort_by(|a, b| {
            locale_compare(
                a.email.as_deref().unwrap_or(&a.name),
                b.email.as_deref().unwrap_or(&b.name),
            )
        });
        let has_rule = flag_of(&flow, "rule");
        for identity in &people {
            let group_ids = if has_rule {
                Some(boxed(|| live_group_ids(tx, identity, now)).await?)
            } else {
                None
            };
            if !flow_applies_to(&flow, identity, group_ids.as_deref())? {
                continue;
            }
            let (statuses, progress) = boxed(|| {
                member_statuses(
                    ctx,
                    tx,
                    &chain,
                    identity,
                    true,
                    Some(vec![candidate.clone()]),
                )
            })
            .await?;
            let Some((_, status)) = statuses.first() else {
                continue;
            };
            let mut row = Map::new();
            row.insert("identity".into(), person(identity));
            for (key, value) in subject_progress(status, progress.get(&flow_id), true) {
                row.insert(key, value);
            }
            rows.push(Value::Object(row));
        }
    }
    report.insert("summary".into(), summary(&rows));
    report.insert("members".into(), Value::Array(rows));
    if defined_here && str_of(&flow, "appliesTo") != Some("tenant") {
        let (tenants, truncated) = boxed(|| descendants_of(tx, tenant)).await?;
        let mut descendants: Vec<Value> = Vec::new();
        for target in tenants {
            if target.status != TenantStatus::Active {
                continue;
            }
            let target_chain = boxed(|| ctx.ancestry(tx, &target)).await?;
            let Some(found) =
                boxed(|| candidate_flows(tx, &target_chain, "member", Some(&settings)))
                    .await?
                    .into_iter()
                    .find(|item| {
                        str_of(&item.flow, "id") == Some(flow_id.as_str())
                            && item.disabled_by.is_none()
                    })
            else {
                continue;
            };
            let mut people = 0;
            let mut complete = 0;
            for record in boxed(|| async {
                tx.find(
                    "identities",
                    &Filter::new().eq("tenantId", target.id.clone()),
                    &FindOptions::default(),
                )
                .await
            })
            .await?
            {
                let identity: Identity = decode(record)?;
                if identity.kind != IdentityKind::User || identity.status != IdentityStatus::Active
                {
                    continue;
                }
                let (statuses, _) = boxed(|| {
                    member_statuses(
                        ctx,
                        tx,
                        &target_chain,
                        &identity,
                        false,
                        Some(vec![found.clone()]),
                    )
                })
                .await?;
                let Some((_, status)) = statuses.first() else {
                    continue;
                };
                people += 1;
                if status.get("complete") == Some(&Value::Bool(true)) {
                    complete += 1;
                }
            }
            let mut row = Map::new();
            row.insert("tenant".into(), source_of(&target));
            row.insert("people".into(), number(people as f64));
            row.insert("complete".into(), number(complete as f64));
            descendants.push(Value::Object(row));
        }
        report.insert("descendants".into(), Value::Array(descendants));
        if truncated {
            report.insert("truncated".into(), Value::Bool(true));
        }
    }
    Ok(Value::Object(report))
}
