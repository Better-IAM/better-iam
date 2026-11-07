//! Port of `packages/server/src/api/analysis.ts`.
//!
//! Access analysis: a read-only scan of a tenant's policies, roles, groups, bindings, trusts, and members that
//! reports risky or stale configuration — unrestricted administrator policies, administrators without a second
//! factor, dormant members who still hold access, trusts that skip MFA, and unused policies, roles, and groups —
//! plus standing administrator bindings, eligible bindings never activated, broken manager links, and policy lint
//! warnings. Findings can be suppressed with a recorded reason; suppressed findings stay listed on request.

use std::sync::Arc;

use better_iam_core::{
    CredentialInput, Direction, Effect, Filter, FindOptions, IamError, IamResult, Identity,
    IdentityKind, IdentityStatus, OrderOptions, PolicyDocument, Record, Tenant, find_ordered,
};
use better_iam_types::api::analysis;
use indexmap::{IndexMap, IndexSet};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::api::{Body, Reply};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::models::{
    Binding, BindingActivation, Group, GroupMember, Policy, ResourceTypeRecord, Role, Trust,
};
use crate::policy_lint::{PolicyLintContext, lint_policy};
use crate::validation::{integer, strings, text};

/// Refusals in a day from which an agent is reported (`agent-denials`).
const AGENT_DENIAL_THRESHOLD: usize = 20;
const DAY_MS: f64 = 86_400_000.0;

/// The `analysis` API group (`createAnalysisApi(ctx)`): one method per route `analysis/{method}`.
pub struct AnalysisApi {
    ctx: Arc<ServerContext>,
}

/// `createAnalysisApi(ctx)`.
pub fn create_analysis_api(ctx: &Arc<ServerContext>) -> IamResult<AnalysisApi> {
    Ok(AnalysisApi { ctx: ctx.clone() })
}

/// `severityRank`.
fn severity_rank(severity: &str) -> u8 {
    match severity {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    }
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// `findingId(kind, subject)`: deterministic, so the same condition on the same subject always has the same ID.
fn finding_id(kind: &str, subject: &str) -> String {
    sha256_hex(&format!("{kind}:{subject}"))[..24].to_owned()
}

/// What a suppression accepts: the finding's severity and evidence (its detail, unless the check names something
/// steadier). A suppression only hides a finding whose fingerprint still matches, so one that grows worse shows again.
fn fingerprint(severity: &str, evidence: &str) -> String {
    sha256_hex(&format!("{severity}\n{evidence}"))[..32].to_owned()
}

fn suppression_id(tenant_id: &str, finding: &str) -> String {
    format!("{tenant_id}:{finding}")
}

/// Audit actions bindings.activate and approveActivation record for a live activation (resourceId is the binding ID).
const ACTIVATION_ACTIONS: [&str; 2] = ["binding:activate", "binding:activation-approved"];

/// An activation the bindings API recorded. Anyone can make authorize() audit a denied decision under any action and
/// resource ID, so only allowed events carrying the activation ID (which authorization decisions never have) count.
fn recorded_activation(event: &Record) -> bool {
    event
        .get("action")
        .and_then(Value::as_str)
        .is_some_and(|action| ACTIVATION_ACTIONS.contains(&action))
        && event.get("outcome").and_then(Value::as_str) == Some("allow")
        && matches!(
            event
                .get("metadata")
                .and_then(|metadata| metadata.get("activationId")),
            Some(Value::String(_))
        )
}

fn system_policy(policy: &Policy) -> bool {
    policy
        .unique_key
        .as_deref()
        .is_some_and(|key| key.starts_with("system:"))
}

fn is_unrestricted_admin(document: Option<&PolicyDocument>) -> bool {
    document.is_some_and(|document| {
        document.statements.iter().any(|statement| {
            statement.effect == Effect::Allow
                && statement.conditions.is_none()
                && statement
                    .actions
                    .iter()
                    .any(|action| action == "*" || action == "iam:*")
                && statement.resources.iter().any(|resource| resource == "*")
        })
    })
}

/// An allow statement without conditions over every action (or every platform action) on every resource.
pub fn unrestricted_admin(document: Option<&better_iam_core::PolicyDocument>) -> IamResult<bool> {
    Ok(is_unrestricted_admin(document))
}

/// `/(^|:)\*$/`: a whole-name or service-wide wildcard.
fn service_wildcard(action: &str) -> bool {
    action == "*" || action.ends_with(":*")
}

/// Unconditional service-wide action wildcards (`documents:*`) that are not already full administration.
fn broad_actions(document: Option<&PolicyDocument>) -> Vec<String> {
    let mut found: IndexSet<String> = IndexSet::new();
    for statement in document
        .map(|document| document.statements.as_slice())
        .unwrap_or(&[])
    {
        if statement.effect == Effect::Allow && statement.conditions.is_none() {
            for action in &statement.actions {
                if action != "*" && action != "iam:*" && service_wildcard(action) {
                    found.insert(action.clone());
                }
            }
        }
    }
    found.into_iter().collect()
}

/// `value ?? fallback` for a numeric input member.
fn or_default(value: Option<&Value>, fallback: f64) -> Value {
    match value {
        None | Some(Value::Null) => crate::js::number(fallback),
        Some(value) => value.clone(),
    }
}

fn number_text(value: f64) -> String {
    crate::js::number_to_string(value)
}

/// `new Date(ms).toISOString().slice(0, 10)`; the JavaScript call throws for dates it cannot represent.
fn iso_day(ms: f64) -> IamResult<String> {
    better_iam_core::js::iso_string(ms)
        .map(|iso| iso.chars().take(10).collect())
        .ok_or_else(crate::js::internal_error)
}

fn status_name(status: IdentityStatus) -> &'static str {
    match status {
        IdentityStatus::Active => "active",
        IdentityStatus::Disabled => "disabled",
        IdentityStatus::Deleted => "deleted",
    }
}

/// `identity.email ?? identity.name`.
fn label(identity: &Identity) -> String {
    identity
        .email
        .clone()
        .unwrap_or_else(|| identity.name.clone())
}

/// `{ type, id, name }` (name left out when undefined).
fn subject(kind: &str, id: &str, name: Option<&str>) -> Value {
    let mut map = Map::new();
    map.insert("type".into(), json!(kind));
    map.insert("id".into(), json!(id));
    if let Some(name) = name {
        map.insert("name".into(), json!(name));
    }
    Value::Object(map)
}

fn member_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

fn record_str<'a>(map: &'a Map<String, Value>, key: &str) -> &'a str {
    map.get(key).and_then(Value::as_str).unwrap_or("")
}

/// A JSON comparison that works whatever Rust type a (string-union) member decodes to.
fn equals_str<T: serde::Serialize>(value: &T, expected: &str) -> bool {
    serde_json::to_value(value)
        .ok()
        .as_ref()
        .and_then(Value::as_str)
        == Some(expected)
}

/// The records of a collection matching `filter`, decoded.
async fn find_typed<T: DeserializeOwned>(
    tx: &Store,
    collection: &str,
    filter: Filter,
) -> IamResult<Vec<T>> {
    tx.find(collection, &filter, &FindOptions::default())
        .await?
        .into_iter()
        .map(crate::port::decode)
        .collect()
}

async fn find_records(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

fn tenant_filter(tenant_id: &str) -> Filter {
    Filter::new().eq("tenantId", tenant_id)
}

fn timestamp(event: &Record) -> f64 {
    number_member(event, "timestamp")
}

fn number_member(record: &Record, key: &str) -> f64 {
    match record.get(key) {
        Some(value) => better_iam_core::js::to_number(value),
        None => f64::NAN,
    }
}

/// `Math.max(a, b)`: NaN when either is NaN.
fn js_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.max(b)
    }
}

/// `Math.min(a, b)`: NaN when either is NaN.
fn js_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

/// A number's truthiness (`0` and `NaN` are falsy).
fn truthy_number(value: f64) -> bool {
    value != 0.0 && !value.is_nan()
}

/// Every finding the checks report, with each finding's fingerprint (by ID).
struct ScanResult {
    now: f64,
    findings: Vec<Map<String, Value>>,
    fingerprints: IndexMap<String, String>,
}

impl ScanResult {
    /// `report(kind, severity, subject, title, detail, key = '{type}:{id}', evidence = detail)`. `evidence` must not
    /// change while the condition stays the same, e.g. with time.
    #[allow(clippy::too_many_arguments)]
    fn report(
        &mut self,
        kind: &str,
        severity: &str,
        subject: Value,
        title: String,
        detail: String,
        key: Option<String>,
        evidence: Option<String>,
    ) {
        let key = key.unwrap_or_else(|| {
            format!(
                "{}:{}",
                member_str(&subject, "type"),
                member_str(&subject, "id")
            )
        });
        let id = finding_id(kind, &key);
        let evidence = evidence.unwrap_or_else(|| detail.clone());
        self.fingerprints
            .insert(id.clone(), fingerprint(severity, &evidence));
        let mut finding = Map::new();
        finding.insert("id".into(), json!(id));
        finding.insert("kind".into(), json!(kind));
        finding.insert("severity".into(), json!(severity));
        finding.insert("title".into(), json!(title));
        finding.insert("detail".into(), json!(detail));
        finding.insert("subject".into(), subject);
        self.findings.push(finding);
    }

    /// [`ScanResult::report`] with the default key and evidence.
    fn add(&mut self, kind: &str, severity: &str, subject: Value, title: String, detail: &str) {
        self.report(
            kind,
            severity,
            subject,
            title,
            detail.to_owned(),
            None,
            None,
        );
    }
}

/// What the policy linter may assume for a tenant: the declared identity attributes and, when every resource is
/// registered with IAM (no application resolver, which may return any attribute), the known resource attributes.
async fn lint_context(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
) -> IamResult<PolicyLintContext> {
    let mut context = PolicyLintContext {
        identity_attributes: Some(ctx.catalog.identity_attributes.clone()),
        resource_attributes: None,
        context_keys: None,
        clearances: None,
        extra: Map::new(),
    };
    if ctx.config.clearances.is_some() {
        context.clearances = Some(true);
    }
    if ctx.options.resolve_resource.is_none() {
        let mut names: IndexSet<String> = IndexSet::new();
        for kind in ctx.catalog.resource_types.values() {
            for name in kind.attributes.keys() {
                names.insert(name.clone());
            }
        }
        for record in
            find_typed::<ResourceTypeRecord>(tx, "resourceTypes", tenant_filter(tenant_id)).await?
        {
            for name in record.attributes.keys() {
                names.insert(name.clone());
            }
        }
        let mut names: Vec<String> = names.into_iter().collect();
        crate::js::sort_strings(&mut names);
        context.resource_attributes = Some(names);
    }
    Ok(context)
}

/// Every finding the checks report for the tenant now, before suppressions, with each finding's fingerprint (by ID):
/// what a suppression of it accepts.
async fn scan(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant: &Tenant,
    dormant_days: f64,
) -> IamResult<ScanResult> {
    let tenant_id = tenant.id.as_str();
    let now = ctx.now();
    let window_ms = dormant_days * DAY_MS;
    // Sequential reads: a transaction holds one database connection.
    let policies: Vec<Policy> = find_typed(tx, "policies", tenant_filter(tenant_id)).await?;
    let roles: Vec<Role> = find_typed(tx, "roles", tenant_filter(tenant_id)).await?;
    let bindings: Vec<Binding> = find_typed(tx, "bindings", tenant_filter(tenant_id)).await?;
    let members: Vec<GroupMember> =
        find_typed::<GroupMember>(tx, "groupMembers", tenant_filter(tenant_id))
            .await?
            .into_iter()
            .filter(|member| ctx.live_membership(member))
            .collect();
    let groups: Vec<Group> = find_typed(tx, "groups", tenant_filter(tenant_id)).await?;
    let identities: Vec<Identity> = find_typed(tx, "identities", tenant_filter(tenant_id)).await?;
    let trusts: Vec<Trust> = find_typed(tx, "trusts", tenant_filter(tenant_id)).await?;
    let live: Vec<&Binding> = bindings
        .iter()
        .filter(|binding| ctx.live_binding(binding))
        .collect();
    let policy_by_id: IndexMap<&str, &Policy> = policies
        .iter()
        .map(|policy| (policy.id.as_str(), policy))
        .collect();
    let mut out = ScanResult {
        now,
        findings: Vec::new(),
        fingerprints: IndexMap::new(),
    };

    // Policies and inline role documents.
    let attached: IndexSet<&str> = roles
        .iter()
        .flat_map(|role| role.policy_ids.iter().map(String::as_str))
        .collect();
    for policy in &policies {
        let system = system_policy(policy);
        let policy_subject = || subject("policy", &policy.id, Some(&policy.name));
        if !system && is_unrestricted_admin(Some(&policy.document)) {
            out.add(
                "unrestricted-admin-policy",
                "high",
                policy_subject(),
                format!("Policy {} grants every action on every resource", policy.name),
                "An unconditional allow of * (or iam:*) on * makes every holder a full administrator. Scope the actions and resources, or add conditions such as principal.mfa.",
            );
        } else if !system && !broad_actions(Some(&policy.document)).is_empty() {
            out.add(
                "broad-action-wildcard",
                "medium",
                policy_subject(),
                format!("Policy {} uses service-wide action wildcards", policy.name),
                &format!(
                    "Unconditional {} also grants actions added to those services later. List the actions holders need.",
                    broad_actions(Some(&policy.document)).join(", ")
                ),
            );
        }
        if !system && !attached.contains(policy.id.as_str()) {
            out.add(
                "unattached-policy",
                "low",
                policy_subject(),
                format!("Policy {} is not attached to any role", policy.name),
                "Unattached policies grant nothing; delete them or attach them where intended.",
            );
        }
    }
    let mut admin_roles: IndexSet<&str> = IndexSet::new();
    for role in &roles {
        let mut documents = std::iter::once(role.document.as_ref()).chain(
            role.policy_ids
                .iter()
                .map(|id| policy_by_id.get(id.as_str()).map(|policy| &policy.document)),
        );
        if documents.any(is_unrestricted_admin) {
            admin_roles.insert(role.id.as_str());
        }
        if role.protected {
            continue;
        }
        let role_subject = || subject("role", &role.id, Some(&role.name));
        if is_unrestricted_admin(role.document.as_ref()) {
            out.add(
                "unrestricted-admin-policy",
                "high",
                role_subject(),
                format!(
                    "Role {} has an inline document granting every action on every resource",
                    role.name
                ),
                "Replace the inline * statement with scoped policies.",
            );
        }
        if role.document.is_none()
            && !role
                .policy_ids
                .iter()
                .any(|id| policy_by_id.contains_key(id.as_str()))
        {
            out.add(
                "empty-role",
                "low",
                role_subject(),
                format!("Role {} grants nothing", role.name),
                "The role has no inline document and no attached policies.",
            );
        }
        let bound = live.iter().any(|binding| binding.role_id == role.id);
        let trusted = trusts
            .iter()
            .any(|trust| !trust.revoked && trust.role_id == role.id);
        if !bound && !trusted {
            out.add(
                "unused-role",
                "low",
                role_subject(),
                format!("Role {} is not bound to anyone", role.name),
                "No identity, group, or trust uses this role; remove it if it is no longer needed.",
            );
        }
    }

    // Groups that hold access but have no members.
    for group in &groups {
        if live
            .iter()
            .any(|binding| binding.subject_type == "group" && binding.subject_id == group.id)
            && !members.iter().any(|member| member.group_id == group.id)
        {
            out.add(
                "empty-group-with-access",
                "low",
                subject("group", &group.id, Some(&group.name)),
                format!(
                    "Group {} holds role bindings but has no members",
                    group.name
                ),
                "Anyone added later inherits the access immediately; review the bindings.",
            );
        }
    }

    // Identities: effective bindings (direct and through groups), factor enrollment, and last sign-in.
    let mut groups_of: IndexMap<&str, IndexSet<&str>> = IndexMap::new();
    for member in &members {
        groups_of
            .entry(member.identity_id.as_str())
            .or_default()
            .insert(member.group_id.as_str());
    }
    let tenant_requires_mfa = tenant
        .auth_policy
        .as_ref()
        .and_then(|policy| policy.require_mfa)
        == Some(true);
    let no_groups: IndexSet<&str> = IndexSet::new();
    for identity in &identities {
        if identity.status != IdentityStatus::Active {
            continue;
        }
        let member_of = groups_of.get(identity.id.as_str()).unwrap_or(&no_groups);
        let held: Vec<&&Binding> = live
            .iter()
            .filter(|binding| {
                if binding.subject_type == "identity" {
                    binding.subject_id == identity.id
                } else {
                    member_of.contains(binding.subject_id.as_str())
                }
            })
            .collect();
        let name = label(identity);
        let identity_subject = || subject("identity", &identity.id, Some(&name));
        let admin = identity.owner
            || held
                .iter()
                .any(|binding| admin_roles.contains(binding.role_id.as_str()));
        if admin && identity.kind == IdentityKind::Service {
            out.add(
                "service-account-admin",
                "medium",
                identity_subject(),
                format!(
                    "Service account {} has full administrator access",
                    identity.name
                ),
                "A leaked API key would control the whole organization. Bind a role scoped to what the automation does.",
            );
        }
        if admin && identity.kind == IdentityKind::Agent {
            out.add(
                "agent-admin",
                "high",
                identity_subject(),
                format!("AI agent {} has full administrator access", identity.name),
                "An agent follows instructions it reads, so a prompt injection or a leaked key would control the whole organization. Bind a role scoped to its task and set a ceiling (agents.update boundary).",
            );
        }
        if admin && identity.kind == IdentityKind::User && !tenant_requires_mfa {
            let enabled = tx
                .get("authMfa", &identity.id)
                .await?
                .and_then(|record| record.get("enabled").cloned())
                == Some(Value::Bool(true));
            let factor = enabled
                || !find_records(
                    tx,
                    "authPasskeys",
                    tenant_filter(tenant_id).eq("identityId", identity.id.clone()),
                )
                .await?
                .is_empty();
            if !factor {
                out.add(
                    "admin-without-mfa",
                    "high",
                    identity_subject(),
                    format!("{name} is an administrator without a second factor"),
                    "Administrators should enroll an authenticator app or passkey; the tenant authentication policy can require MFA for everyone.",
                );
            }
        }
        if identity.kind == IdentityKind::User && (!held.is_empty() || identity.owner) {
            let sign_ins = find_records(
                tx,
                "audit",
                tenant_filter(tenant_id)
                    .eq("actorId", identity.id.clone())
                    .eq("action", "auth:session:create"),
            )
            .await?;
            // "View as" sessions are recorded on the member but are not the member signing in.
            let last = sign_ins
                .iter()
                .filter(|event| !crate::js::truthy(event.get("impersonatorId")))
                .map(timestamp)
                .fold(0.0, js_max);
            let since = if truthy_number(last) {
                last
            } else {
                identity.created_at
            };
            if now - since > window_ms {
                let title = if truthy_number(last) {
                    format!(
                        "{name} has not signed in for {} days",
                        number_text(((now - last) / DAY_MS).floor())
                    )
                } else {
                    format!("{name} has never signed in")
                };
                out.add(
                    "dormant-access",
                    "medium",
                    identity_subject(),
                    title,
                    &format!(
                        "The account still holds {} role binding(s){}. Disable it or remove its access if it is no longer used.",
                        held.len(),
                        if identity.owner { " and ownership" } else { "" }
                    ),
                );
            }
        }
    }

    let identity_by_id: IndexMap<&str, &Identity> = identities
        .iter()
        .map(|identity| (identity.id.as_str(), identity))
        .collect();
    let role_name: IndexMap<&str, &str> = roles
        .iter()
        .map(|role| (role.id.as_str(), role.name.as_str()))
        .collect();
    for violation in crate::sod::sod_violations(ctx, tx, tenant_id, None, None).await? {
        let Some(identity) = identity_by_id
            .get(member_str(&violation, "identityId"))
            .copied()
        else {
            continue;
        };
        if identity.status != IdentityStatus::Active {
            continue;
        }
        let held: Vec<String> = violation
            .get("roleIds")
            .and_then(Value::as_array)
            .map(|ids| {
                ids.iter()
                    .map(|id| {
                        let id = id.as_str().unwrap_or("");
                        role_name.get(id).copied().unwrap_or(id).to_owned()
                    })
                    .collect()
            })
            .unwrap_or_default();
        let name = label(identity);
        out.report(
            "separation-of-duties",
            "high",
            subject("identity", &identity.id, Some(&name)),
            format!(
                "{name} holds conflicting roles ({})",
                crate::js::js_string(violation.get("ruleName"))
            ),
            format!(
                "{} must not be held together. Remove one of the bindings{}.",
                held.join(" and "),
                if member_str(&violation, "mode") == "detect" {
                    ", or keep the rule in detect mode if the combination is accepted"
                } else {
                    "; the conflict predates the rule, which now prevents new ones"
                }
            ),
            Some(format!(
                "identity:{}:{}",
                identity.id,
                crate::js::js_string(violation.get("ruleId"))
            )),
            None,
        );
    }

    // API keys nobody has used for the dormant window (lastSeenAt only moves when a key authenticates).
    for key in find_records(
        tx,
        "sessions",
        tenant_filter(tenant_id).eq("kind", "api-key"),
    )
    .await?
    {
        let expires_at = number_member(&key, "expiresAt");
        if expires_at <= now {
            continue;
        }
        let created_at = number_member(&key, "createdAt");
        let last_seen_at = number_member(&key, "lastSeenAt");
        let last_used = (last_seen_at > created_at).then_some(last_seen_at);
        if now - last_used.unwrap_or(created_at) <= window_ms {
            continue;
        }
        let key_id = record_str(&key, "id").to_owned();
        let identity_id = record_str(&key, "identityId").to_owned();
        let owner = identity_by_id.get(identity_id.as_str()).copied();
        let key_label = match key.get("name") {
            Some(Value::String(name)) => name.clone(),
            _ => key_id.chars().take(8).collect(),
        };
        let title = match last_used {
            Some(last_used) => format!(
                "API key {key_label} has not been used for {} days",
                number_text(((now - last_used) / DAY_MS).floor())
            ),
            None => format!("API key {key_label} has never been used"),
        };
        out.add(
            "stale-api-key",
            "medium",
            subject("credential", &key_id, Some(&key_label)),
            title,
            &format!(
                "The key belongs to {} and stays valid until {}. Revoke it if nothing depends on it.",
                owner.map(|owner| owner.name.clone()).unwrap_or(identity_id),
                iso_day(expires_at)?
            ),
        );
    }

    // AI agents: the person accountable for each, their ceilings, and the delegations people gave them.
    for agent in &identities {
        if agent.kind != IdentityKind::Agent || agent.status == IdentityStatus::Deleted {
            continue;
        }
        let agent_subject = || subject("identity", &agent.id, Some(&agent.name));
        let standing = crate::agents::agent_standing(ctx, tx, agent).await?;
        if standing == "sponsor-missing" || standing == "sponsor-inactive" {
            out.add(
                "agent-without-sponsor",
                "high",
                agent_subject(),
                format!("AI agent {} has no active sponsor", agent.name),
                "Its credentials are refused until someone is accountable for it. Name an active person as its sponsor (agents.update) or delete the agent.",
            );
        } else if agent.status == IdentityStatus::Active
            && agent
                .agent
                .as_ref()
                .and_then(|profile| profile.boundary.as_ref())
                .is_none()
            && agent.agent.as_ref().and_then(|profile| profile.delegable) != Some(false)
        {
            out.add(
                "unbounded-agent",
                "low",
                agent_subject(),
                format!(
                    "AI agent {} accepts delegation without a ceiling",
                    agent.name
                ),
                "Each delegation lets it do whatever the delegation scope and the person allow. A boundary policy caps what any delegation, and its own keys, can reach.",
            );
        }
    }
    let agent_name = |agent_id: &str| -> String {
        identity_by_id
            .get(agent_id)
            .map(|identity| identity.name.clone())
            .unwrap_or_else(|| agent_id.to_owned())
    };
    for delegation in
        find_typed::<crate::delegations::Delegation>(tx, "delegations", tenant_filter(tenant_id))
            .await?
    {
        if delegation.status != "active" || delegation.expires_at <= now {
            continue;
        }
        let person = identity_by_id.get(delegation.subject_id.as_str()).copied();
        let person_label = person
            .map(label)
            .unwrap_or_else(|| delegation.subject_id.clone());
        let name = format!(
            "{person_label} \u{2192} {}",
            agent_name(&delegation.agent_id)
        );
        let delegation_subject = || subject("delegation", &delegation.id, Some(&name));
        let everything = delegation.policy.statements.iter().any(|statement| {
            statement.effect == Effect::Allow
                && statement
                    .actions
                    .iter()
                    .any(|action| action == "*" || action == "iam:*")
        });
        if everything {
            out.add(
                "broad-delegation",
                "medium",
                delegation_subject(),
                format!("{name}: the agent may do anything the person can"),
                "The delegation scope allows every action. Revoke it and grant the actions the agent needs.",
            );
        }
        let last_used = delegation
            .last_used_at
            .or(delegation.decided_at)
            .unwrap_or(delegation.created_at);
        if now - last_used > window_ms {
            out.add(
                "unused-delegation",
                "low",
                delegation_subject(),
                format!(
                    "{name}: unused for {} days",
                    number_text(((now - last_used) / DAY_MS).floor())
                ),
                &format!(
                    "The delegation stays active until {}. Revoke it if the agent no longer acts for this person.",
                    iso_day(delegation.expires_at)?
                ),
            );
        }
        // Hand-offs to any agent at all (delegations.ts): the person's access can travel further than they chose.
        if let Some(handoff) = &delegation.handoff
            && handoff.agents.as_ref().is_none_or(Vec::is_empty)
        {
            let depth = handoff.depth;
            out.report(
                "open-handoff",
                if depth > 1.0 { "medium" } else { "low" },
                delegation_subject(),
                format!(
                    "{name}: the agent may hand the work on to any agent{}",
                    if depth > 1.0 {
                        format!(", {} levels deep", number_text(depth))
                    } else {
                        String::new()
                    }
                ),
                "Name the agents it may hand work to (handoff.agents), or grant the delegation without hand-offs.".to_owned(),
                None,
                // A deeper hand-off is a worse finding.
                Some(format!("depth:{}", number_text(depth))),
            );
        }
    }

    // Agents refused often in the last day, with their own keys or acting for people: a sign of an agent looping,
    // misconfigured, or following instructions injected into what it reads.
    let agent_ids: IndexSet<&str> = identities
        .iter()
        .filter(|identity| identity.kind == IdentityKind::Agent)
        .map(|agent| agent.id.as_str())
        .collect();
    if !agent_ids.is_empty() {
        let mut denials: IndexMap<String, usize> = IndexMap::new();
        let denied = |event: &Record| event.get("outcome").and_then(Value::as_str) == Some("deny");
        let events = find_ordered(
            tx.as_ref(),
            "audit",
            &tenant_filter(tenant_id),
            &OrderOptions {
                direction: Direction::Desc,
                from: Some(now - DAY_MS),
                limit: Some(10_000),
                ..OrderOptions::by("timestamp")
            },
            Some(&denied),
        )
        .await?;
        for event in events {
            let session_agent = event
                .get("sessionContext")
                .and_then(|context| context.get("agentId"))
                .filter(|value| !value.is_null());
            let actor = record_str(&event, "actorId");
            let agent_id = match session_agent {
                Some(value) => value.as_str().map(str::to_owned),
                None => agent_ids.contains(actor).then(|| actor.to_owned()),
            };
            if let Some(agent_id) = agent_id
                && !agent_id.is_empty()
                && agent_ids.contains(agent_id.as_str())
            {
                *denials.entry(agent_id).or_insert(0) += 1;
            }
        }
        for (agent_id, count) in &denials {
            if *count >= AGENT_DENIAL_THRESHOLD {
                let name = agent_name(agent_id);
                out.add(
                    "agent-denials",
                    "medium",
                    subject("identity", agent_id, Some(&name)),
                    format!("AI agent {name} was refused {count} times in the last day"),
                    "Check what it attempted (agents.activity). Suspend it if it is looping or following instructions it should not.",
                );
            }
        }
    }

    // Teams and departments (teams.ts, departments.ts): who can hand out a team's access, and who leads.
    let teams: Vec<crate::teams::Team> = find_typed(
        tx,
        crate::teams::TEAM_COLLECTIONS["teams"]
            .as_str()
            .unwrap_or("teams"),
        tenant_filter(tenant_id),
    )
    .await?;
    if !teams.is_empty() {
        let team_by_id: IndexMap<String, crate::teams::Team> = teams
            .iter()
            .map(|team| (team.id.clone(), team.clone()))
            .collect();
        let mut team_members: Vec<crate::teams::TeamMember> = Vec::new();
        for member in find_typed::<crate::teams::TeamMember>(
            tx,
            crate::teams::TEAM_COLLECTIONS["members"]
                .as_str()
                .unwrap_or("teamMembers"),
            tenant_filter(tenant_id),
        )
        .await?
        {
            if crate::teams::live_team_member(&member, now)? {
                team_members.push(member);
            }
        }
        let active_person = |identity_id: &str| {
            identity_by_id
                .get(identity_id)
                .is_some_and(|identity| identity.status == IdentityStatus::Active)
        };
        for team in &teams {
            let chain = crate::teams::team_chain(&team_by_id, &team.id)?;
            let team_subject = || subject("team", &team.id, Some(&team.name));
            let maintainers = team_members
                .iter()
                .filter(|member| {
                    equals_str(&member.role, "maintainer")
                        && chain.iter().any(|holder| holder.id == member.team_id)
                        && active_person(&member.identity_id)
                })
                .count();
            let admin_grant = live.iter().find(|binding| {
                binding.subject_type == "group"
                    && admin_roles.contains(binding.role_id.as_str())
                    && binding.eligible != Some(true)
                    && chain
                        .iter()
                        .any(|holder| holder.group_id == binding.subject_id)
            });
            let admins_only = equals_str(&team.member_management, "admins");
            if let Some(admin_grant) = admin_grant
                && !admins_only
                && maintainers > 0
            {
                out.add(
                    "team-maintainers-grant-admin",
                    "high",
                    team_subject(),
                    format!(
                        "Maintainers of {} can make anyone a full administrator",
                        team.name
                    ),
                    &format!(
                        "The team holds {} as standing access, and its {maintainers} maintainer(s) add members without an administrator's authority. Set memberManagement to admins, or make the binding eligible (just-in-time).",
                        role_name
                            .get(admin_grant.role_id.as_str())
                            .copied()
                            .unwrap_or("an administrator role")
                    ),
                );
            }
            let direct = team_members
                .iter()
                .filter(|member| member.team_id == team.id && active_person(&member.identity_id))
                .count();
            if direct > 0 && maintainers == 0 && !admins_only {
                out.add(
                    "team-without-maintainer",
                    "low",
                    team_subject(),
                    format!("Team {} has members but no maintainer", team.name),
                    "Nobody but administrators can manage its membership or answer its join requests. Name a maintainer, or set memberManagement to admins to make that the rule.",
                );
            }
        }
    }
    let departments: Vec<crate::departments::Department> = find_typed(
        tx,
        crate::departments::DEPARTMENT_COLLECTIONS["departments"]
            .as_str()
            .unwrap_or("departments"),
        tenant_filter(tenant_id),
    )
    .await?;
    if !departments.is_empty() {
        let mut placed: IndexMap<String, usize> = IndexMap::new();
        for member in find_typed::<crate::departments::DepartmentMember>(
            tx,
            crate::departments::DEPARTMENT_COLLECTIONS["members"]
                .as_str()
                .unwrap_or("departmentMembers"),
            tenant_filter(tenant_id),
        )
        .await?
        {
            if identity_by_id
                .get(member.identity_id.as_str())
                .is_some_and(|identity| identity.status == IdentityStatus::Active)
            {
                *placed.entry(member.department_id.clone()).or_insert(0) += 1;
            }
        }
        for department in &departments {
            let people = placed.get(&department.id).copied().unwrap_or(0);
            let head = department
                .head_id
                .as_deref()
                .filter(|head| !head.is_empty())
                .and_then(|head| identity_by_id.get(head).copied());
            if people > 0 && head.is_none_or(|head| head.status != IdentityStatus::Active) {
                out.add(
                    "department-without-head",
                    "low",
                    subject("department", &department.id, Some(&department.name)),
                    if head.is_some() {
                        format!("The head of {} is no longer active", department.name)
                    } else {
                        format!("Department {} has no head", department.name)
                    },
                    &format!(
                        "{people} {} in it have no department head to report to, so manager approvals routed through the org chart stop there. Name a head (departments.update).",
                        if people == 1 { "person" } else { "people" }
                    ),
                );
            }
        }
    }

    for trust in &trusts {
        if trust.revoked {
            continue;
        }
        let web_identity = trust.kind.as_deref() == Some("web-identity");
        // Web-identity trusts have no source session to verify; their claim conditions pin the workload.
        // Stored flags are read through the same fail-closed readers roles.assume enforces with.
        if !web_identity && !crate::flows::trust_requires_mfa(trust) {
            out.add(
                "trust-without-mfa",
                "medium",
                subject("trust", &trust.id, None),
                "A cross-tenant trust lets its source assume a role without MFA".to_owned(),
                "Recreate the trust with requireMfa so a stolen password alone cannot assume the role.",
            );
        }
        // Another tenant controls the source identity's attributes, so they must not satisfy this tenant's
        // ABAC conditions. New cross-tenant trusts keep them out; legacy ones (no field) still pass them.
        if !web_identity
            && trust.source_tenant_id != tenant_id
            && crate::flows::trust_passes_source_attributes(trust)
        {
            out.add(
                "trust-passes-foreign-attributes",
                "medium",
                subject("trust", &trust.id, None),
                "A cross-tenant trust passes the source account\u{2019}s attributes into role sessions".to_owned(),
                "The source tenant controls these attributes, so they can satisfy this tenant\u{2019}s attribute conditions. Call trust.update({ passSourceAttributes: false }) and use session tags for the data role sessions need.",
            );
        }
    }

    // Standing administrator access: direct, permanent, always-on bindings to administrator roles.
    let role_by_id: IndexMap<&str, &Role> =
        roles.iter().map(|role| (role.id.as_str(), role)).collect();
    for binding in &bindings {
        let Some(role) = role_by_id.get(binding.role_id.as_str()).copied() else {
            continue;
        };
        let identity = if binding.subject_type == "identity" {
            identity_by_id.get(binding.subject_id.as_str()).copied()
        } else {
            None
        };
        let Some(identity) = identity else { continue };
        if role.protected
            || !admin_roles.contains(role.id.as_str())
            || binding.eligible == Some(true)
            || binding.expires_at.is_some()
            || identity.kind != IdentityKind::User
            || identity.status != IdentityStatus::Active
        {
            continue;
        }
        let name = label(identity);
        out.report(
            "standing-privileged-access",
            "medium",
            subject("identity", &identity.id, Some(&name)),
            format!("{name} holds {} as standing administrator access", role.name),
            "The binding grants full administration permanently and without activation. Make it eligible (just-in-time activation) or give it an expiry.".to_owned(),
            Some(format!("binding:{}", binding.id)),
            None,
        );
    }

    // Eligible bindings nobody has ever activated. Bindings carry no creation time, so their age is bounded
    // from below by the subject's creation and from above by the first audit event naming the binding.
    let eligible: Vec<&Binding> = bindings
        .iter()
        .filter(|binding| binding.eligible == Some(true) && !ctx.expired_binding(binding))
        .collect();
    if !eligible.is_empty() {
        let ids: IndexSet<&str> = eligible.iter().map(|binding| binding.id.as_str()).collect();
        let mut activated: IndexSet<String> = IndexSet::new();
        let mut first_seen: IndexMap<String, f64> = IndexMap::new();
        for event in find_records(tx, "audit", tenant_filter(tenant_id)).await? {
            let resource_id = record_str(&event, "resourceId");
            if !ids.contains(resource_id) {
                continue;
            }
            if recorded_activation(&event) {
                activated.insert(resource_id.to_owned());
            }
            let earlier = first_seen
                .get(resource_id)
                .copied()
                .unwrap_or(f64::INFINITY);
            first_seen.insert(resource_id.to_owned(), js_min(earlier, timestamp(&event)));
        }
        for activation in
            find_typed::<BindingActivation>(tx, "bindingActivations", tenant_filter(tenant_id))
                .await?
        {
            let status = activation.status.as_deref();
            if status != Some("pending") && status != Some("denied") {
                activated.insert(activation.binding_id.clone());
            }
        }
        let group_by_id: IndexMap<&str, &Group> = groups
            .iter()
            .map(|group| (group.id.as_str(), group))
            .collect();
        for binding in eligible {
            if activated.contains(&binding.id) {
                continue;
            }
            let mut not_before = js_max(tenant.created_at, binding.starts_at.unwrap_or(0.0));
            let (binding_subject, subject_name) = if binding.subject_type == "identity" {
                let Some(identity) = identity_by_id.get(binding.subject_id.as_str()).copied()
                else {
                    continue;
                };
                if identity.status != IdentityStatus::Active {
                    continue;
                }
                let name = label(identity);
                not_before = js_max(not_before, identity.created_at);
                (subject("identity", &identity.id, Some(&name)), name)
            } else {
                let Some(group) = group_by_id.get(binding.subject_id.as_str()).copied() else {
                    continue;
                };
                (
                    subject("group", &group.id, Some(&group.name)),
                    group.name.clone(),
                )
            };
            let existed_for = first_seen.get(&binding.id).map(|seen| now - seen);
            if existed_for.is_none_or(|existed| existed <= window_ms)
                && now - not_before <= window_ms
            {
                continue;
            }
            let role = role_name
                .get(binding.role_id.as_str())
                .copied()
                .unwrap_or(binding.role_id.as_str());
            let detail = match existed_for {
                Some(existed) if existed > window_ms => format!(
                    "The just-in-time binding has existed for at least {} days and was never activated. Remove it if the access is no longer needed.",
                    number_text((existed / DAY_MS).floor())
                ),
                _ => "The audit trail shows no activation of this just-in-time binding. Remove it if the access is no longer needed.".to_owned(),
            };
            out.report(
                "unused-eligible-binding",
                "low",
                binding_subject,
                format!("Eligible {role} binding for {subject_name} has no recorded activation"),
                detail,
                Some(format!("binding:{}", binding.id)),
                // The detail counts days; the binding's role and subject are what the suppression accepts.
                Some(format!("role:{}", binding.role_id)),
            );
        }
    }

    // Manager links that lead nowhere or back to the person. Manager links form a functional graph (one
    // outgoing link each), so a single walk that marks people in progress and done finds every loop in linear
    // time, however deep the reporting chains are.
    let mut loops: IndexMap<String, (Arc<Vec<&Identity>>, usize)> = IndexMap::new();
    // true: walking, false: done.
    let mut walked: IndexMap<String, bool> = IndexMap::new();
    for start in &identities {
        let mut path: Vec<&Identity> = Vec::new();
        let mut cursor: Option<&Identity> = Some(start);
        while let Some(current) = cursor {
            if walked.contains_key(&current.id) {
                break;
            }
            walked.insert(current.id.clone(), true);
            path.push(current);
            cursor = current
                .manager_id
                .as_deref()
                .filter(|manager| !manager.is_empty())
                .and_then(|manager| identity_by_id.get(manager).copied());
        }
        // Reaching someone still in progress closes a loop from them to the end of this walk.
        if let Some(current) = cursor
            && walked.get(&current.id) == Some(&true)
        {
            let index = path
                .iter()
                .position(|person| std::ptr::eq(*person, current))
                .unwrap_or(0);
            let loop_members = Arc::new(path[index..].to_vec());
            for (position, member) in loop_members.iter().enumerate() {
                loops.insert(member.id.clone(), (loop_members.clone(), position));
            }
        }
        for person in &path {
            walked.insert(person.id.clone(), false);
        }
    }
    for identity in &identities {
        if identity.status != IdentityStatus::Active {
            continue;
        }
        let Some(manager_id) = identity.manager_id.as_deref() else {
            continue;
        };
        let name = label(identity);
        let identity_subject = || subject("identity", &identity.id, Some(&name));
        let manager = identity_by_id.get(manager_id).copied();
        if manager.is_none_or(|manager| manager.status != IdentityStatus::Active) {
            out.add(
                "orphaned-manager",
                "low",
                identity_subject(),
                match manager {
                    Some(manager) => format!(
                        "{name}'s manager {} is {}",
                        label(manager),
                        status_name(manager.status)
                    ),
                    None => format!("{name}'s manager no longer exists"),
                },
                "Approvals routed to the manager and offboarding handoffs cannot reach them. Assign an active manager or clear the link.",
            );
            continue;
        }
        // Someone who only reports into a loop is not part of it; the loop is reported for its members.
        let Some((loop_members, position)) = loops.get(&identity.id) else {
            continue;
        };
        // The loop as seen from this person, shortened when it is long.
        let length = loop_members.len();
        let mut chain: Vec<String> = (0..length.min(10))
            .map(|step| label(loop_members[(position + step) % length]))
            .collect();
        if length > 10 {
            chain.splice(9..10, [format!("\u{2026} {} more", length - 9)]);
        }
        chain.push(label(identity));
        out.add(
            "manager-cycle",
            "medium",
            identity_subject(),
            format!("{name}'s manager chain loops back to them"),
            &format!(
                "{}. Manager approvals and offboarding handoffs cannot resolve a loop; give someone in it a manager outside the chain.",
                chain.join(" \u{2192} ")
            ),
        );
    }

    // Stored policies and inline role documents the linter warns about.
    let linting = lint_context(ctx, tx, tenant_id).await?;
    let lint_finding = |out: &mut ScanResult,
                        lint_subject: Value,
                        lint_label: String,
                        document: &PolicyDocument|
     -> IamResult<()> {
        let result = lint_policy(Some(&document.to_value()), Some(&linting))?;
        let warnings: Vec<&Value> = result
            .warnings
            .iter()
            // unrestricted-admin already has its own high-severity finding.
            .filter(|warning| {
                member_str(warning, "severity") == "warning"
                    && member_str(warning, "code") != "unrestricted-admin"
            })
            .collect();
        if warnings.is_empty() {
            return Ok(());
        }
        let codes: Vec<String> = crate::js::unique(
            warnings
                .iter()
                .map(|warning| crate::js::js_string(warning.get("code"))),
        );
        out.add(
            "policy-lint",
            "low",
            lint_subject,
            format!(
                "{lint_label} has {} lint warning{}",
                warnings.len(),
                if warnings.len() == 1 { "" } else { "s" }
            ),
            &format!(
                "{}{}. Lint the document (analysis.lintPolicy) for details.",
                codes.iter().take(3).cloned().collect::<Vec<_>>().join(", "),
                if codes.len() > 3 {
                    format!(" and {} more", codes.len() - 3)
                } else {
                    String::new()
                }
            ),
        );
        Ok(())
    };
    for policy in &policies {
        if !system_policy(policy) {
            lint_finding(
                &mut out,
                subject("policy", &policy.id, Some(&policy.name)),
                format!("Policy {}", policy.name),
                &policy.document,
            )?;
        }
    }
    for role in &roles {
        if !role.protected
            && let Some(document) = &role.document
        {
            lint_finding(
                &mut out,
                subject("role", &role.id, Some(&role.name)),
                format!("Role {}'s inline document", role.name),
                document,
            )?;
        }
    }
    Ok(out)
}

impl AnalysisApi {
    /// `analysis/findings`: runs every check. `dormantDays` (default 90) sets when an unused account holding access
    /// is reported. A suppressed finding is hidden only while it is as it was when suppressed (same severity and
    /// detail).
    pub async fn findings(
        &self,
        credential: &CredentialInput,
        input: Body<analysis::FindingsInput>,
    ) -> IamResult<Reply<analysis::FindingsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let dormant_days = integer(
                    Some(&or_default(body.get("dormantDays"), 90.0)),
                    "dormantDays",
                    1.0,
                    3650.0,
                )?;
                let ScanResult {
                    now,
                    findings,
                    fingerprints,
                } = scan(ctx, &tx, &tenant, dormant_days).await?;
                // A suppression stands for the finding it was accepted for: once the finding changes, it shows again.
                let mut suppressions: IndexMap<String, Record> = IndexMap::new();
                for row in
                    find_records(&tx, "analysisSuppressions", tenant_filter(&tenant.id)).await?
                {
                    let Some(finding) = row.get("findingId").and_then(Value::as_str) else {
                        continue;
                    };
                    let matches = match (row.get("fingerprint"), fingerprints.get(finding)) {
                        (Some(Value::String(stored)), Some(current)) => stored == current,
                        _ => false,
                    };
                    if matches {
                        suppressions.insert(finding.to_owned(), row);
                    }
                }
                let include_suppressed = body.get("includeSuppressed") == Some(&Value::Bool(true));
                let mut annotated: Vec<Map<String, Value>> = Vec::new();
                for finding in &findings {
                    let mut entry = finding.clone();
                    if let Some(suppression) = suppressions.get(record_str(finding, "id")) {
                        let mut suppressed = Map::new();
                        for (from, to) in [
                            ("reason", "reason"),
                            ("createdBy", "by"),
                            ("createdAt", "at"),
                        ] {
                            if let Some(value) = suppression.get(from) {
                                suppressed.insert(to.into(), value.clone());
                            }
                        }
                        entry.insert("suppressed".into(), Value::Object(suppressed));
                    }
                    if include_suppressed || !entry.contains_key("suppressed") {
                        annotated.push(entry);
                    }
                }
                annotated.sort_by(|a, b| {
                    severity_rank(record_str(a, "severity"))
                        .cmp(&severity_rank(record_str(b, "severity")))
                        .then_with(|| {
                            crate::metrics::locale_compare(
                                record_str(a, "kind"),
                                record_str(b, "kind"),
                            )
                        })
                        .then_with(|| {
                            crate::metrics::locale_compare(record_str(a, "id"), record_str(b, "id"))
                        })
                });
                let (mut high, mut medium, mut low, mut suppressed) = (0, 0, 0, 0);
                for finding in &findings {
                    if suppressions.contains_key(record_str(finding, "id")) {
                        suppressed += 1;
                    } else {
                        match record_str(finding, "severity") {
                            "high" => high += 1,
                            "medium" => medium += 1,
                            _ => low += 1,
                        }
                    }
                }
                Ok(json!({
                    "generatedAt": crate::js::number(now),
                    "dormantDays": crate::js::number(dormant_days),
                    "summary": { "high": high, "medium": medium, "low": low, "suppressed": suppressed },
                    "findings": annotated,
                }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:analysis:read",
                "analysis/*",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `analysis/lintPolicy`: lints a candidate `document` or a stored policy (`policyId`, exactly one of the two):
    /// validation as storage applies it (unknown actions and resource types included) plus warnings about grants
    /// broader than intended and conditions that never match or fail open. A document storage would reject is
    /// reported without warnings. `contextKeys` names keys the application supplies through resolveContext. Requires
    /// iam:policies:read on the policy (or the tenant, for a candidate document).
    pub async fn lint_policy(
        &self,
        credential: &CredentialInput,
        input: Body<analysis::LintPolicyInput>,
    ) -> IamResult<Reply<analysis::LintPolicyOutput>> {
        let ctx = &self.ctx;
        if input.get("document").is_none() == input.get("policyId").is_none() {
            return Err(IamError::new(
                "INVALID_INPUT",
                "Provide either a document or a policyId",
            ));
        }
        let policy_id = match input.get("policyId") {
            None => None,
            Some(value) => Some(text(Some(value), "policyId", 256)?),
        };
        let context_keys = match input.get("contextKeys") {
            None => None,
            Some(value) => Some(strings(Some(value), "contextKeys")?),
        };
        let resource_id = policy_id
            .clone()
            .unwrap_or_else(|| crate::api::string_member(&input, "tenantId"));
        let body = &input;
        let policy_id_ref = &policy_id;
        let context_keys_ref = &context_keys;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let document = match policy_id_ref {
                    None => body.get("document").cloned().unwrap_or(Value::Null),
                    Some(policy_id) => ctx
                        .scoped(&tx, "policies", Some(&json!(policy_id)), &tenant.id)
                        .await?
                        .get("document")
                        .cloned()
                        .unwrap_or(Value::Null),
                };
                // Validation first: it rejects unknown actions and resource types cheaply, before any pattern
                // matching.
                if let Err(error) = ctx
                    .catalog
                    .validate(tx.as_ref(), &tenant.id, &document)
                    .await
                {
                    return Ok(json!({
                        "valid": false,
                        "error": { "code": error.code, "message": error.message },
                        "warnings": [],
                    }));
                }
                let mut context = lint_context(ctx, &tx, &tenant.id).await?;
                if let Some(keys) = context_keys_ref {
                    context.context_keys = Some(keys.clone());
                }
                let result = lint_policy(Some(&document), Some(&context))?;
                serde_json::to_value(result).map_err(|_| crate::js::internal_error().into())
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:policies:read",
                &resource_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `analysis/suppress`: hides one finding the scan reports now from future results, with a reason kept for
    /// reviewers, for as long as the finding stays as it is (same severity and detail); if it changes, it shows
    /// again. `dormantDays` (default 90) must match the window the finding was listed with. Requires
    /// iam:analysis:update.
    pub async fn suppress(
        &self,
        credential: &CredentialInput,
        input: Body<analysis::SuppressInput>,
    ) -> IamResult<Reply<analysis::SuppressOutput>> {
        let ctx = &self.ctx;
        let finding = text(input.get("findingId"), "findingId", 64)?;
        let resource_id = format!("analysis/{finding}");
        let body = &input;
        let finding_ref = &finding;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 tenant,
                 principal,
             }| {
                Box::pin(async move {
                    let hex_id = finding_ref.len() == 24
                        && finding_ref
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
                    if !hex_id {
                        return Err(IamError::new("INVALID_INPUT", "Unknown finding ID").into());
                    }
                    let reason =
                        crate::js::trim(&text(body.get("reason"), "reason", 500)?).to_owned();
                    let dormant_days = integer(
                        Some(&or_default(body.get("dormantDays"), 90.0)),
                        "dormantDays",
                        1.0,
                        3650.0,
                    )?;
                    // Only a finding reported now can be accepted, and only as it is now: a predictable ID alone is
                    // not enough.
                    let current = scan(ctx, &tx, &tenant, dormant_days)
                        .await?
                        .fingerprints
                        .get(finding_ref)
                        .cloned();
                    let Some(current) = current else {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "Unknown finding ID: only a finding reported now can be suppressed",
                        )
                        .into());
                    };
                    let tenant_id = crate::api::string_member(body, "tenantId");
                    let id = suppression_id(&tenant_id, finding_ref);
                    let mut record = Map::new();
                    record.insert("id".into(), json!(id));
                    record.insert("tenantId".into(), json!(tenant_id));
                    record.insert("findingId".into(), json!(finding_ref));
                    record.insert("reason".into(), json!(reason));
                    record.insert("createdBy".into(), json!(principal.identity.id));
                    record.insert("createdAt".into(), crate::js::number(ctx.now()));
                    record.insert("fingerprint".into(), json!(current));
                    if tx.get("analysisSuppressions", &id).await?.is_some() {
                        tx.put("analysisSuppressions", &record).await?;
                    } else {
                        tx.insert("analysisSuppressions", &record).await?;
                    }
                    Ok(json!({ "suppressed": true }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:analysis:update",
                &resource_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `analysis/unsuppress`: shows a suppressed finding again. Requires iam:analysis:update.
    pub async fn unsuppress(
        &self,
        credential: &CredentialInput,
        input: Body<analysis::UnsuppressInput>,
    ) -> IamResult<Reply<analysis::UnsuppressOutput>> {
        let ctx = &self.ctx;
        let finding = text(input.get("findingId"), "findingId", 64)?;
        let resource_id = format!("analysis/{finding}");
        let body = &input;
        let finding_ref = &finding;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let id = suppression_id(&crate::api::string_member(body, "tenantId"), finding_ref);
                if tx.get("analysisSuppressions", &id).await?.is_some() {
                    tx.delete("analysisSuppressions", &id).await?;
                }
                Ok(json!({ "suppressed": false }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:analysis:update",
                &resource_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}
