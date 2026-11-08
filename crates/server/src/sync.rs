//! Port of `packages/server/src/sync.ts`.
//!
//! Declarative tenant configuration ("configuration as code"): `config.export` writes a tenant's roles, policies,
//! groups, tenant-defined resource types, group bindings, access packages, invariants, agreements, teams,
//! departments and AI kinds as a document keyed by name; `config.plan` diffs a document against the tenant;
//! `config.apply` applies the plan in one transaction, authorizing every change like the equivalent API call.

use std::sync::{Arc, Mutex};

use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, Identity, IdentityStatus, Record, Tenant, js as core_js,
};
use better_iam_types::api::config;
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::access_policy::{MAX_ACTIVATION_MS, tenant_access_policy};
use crate::ai_sync::{
    AiPlan, AiState, apply_ai, export_ai, parse_agents_config, parse_budgets_config,
    parse_models_config, plan_ai, read_ai_state,
};
use crate::api::agreements::{delete_agreement, save_agreement};
use crate::api::bindings::{create_binding, delete_binding};
use crate::api::catalog::{delete_resource_type, register_resource_type, update_resource_type};
use crate::api::groups::{add_group_member, create_group, delete_group, remove_group_member};
use crate::api::invariants::save_invariant;
use crate::api::packages::{create_package, delete_package, update_package};
use crate::api::policies::{create_policy, delete_policy, update_policy};
use crate::api::roles::{create_role, delete_role, update_role_record};
use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, OperationFailure, OperationResult};
use crate::js::{internal_error, invalid_input, truthy};
use crate::licenses::{batch_group_licenses, license_rule_keys};
use crate::metrics::locale_compare;
use crate::models::{Binding, GroupMember};
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::org_sync::{
    Directory, OrgApplyEnv, OrgPlan, OrgPlanEnv, OrgState, apply_org, export_org,
    org_rule_environment_after, org_rule_ids, org_rule_names, parse_departments_config,
    parse_teams_config, plan_org, read_org_state,
};
use crate::package_rules::{RuleEnvironment, map_rule_groups, parse_auto_assign, rule_input};
use crate::port::{Callback, decode};
use crate::teams::is_team_group;
use crate::validation::{integer, object, strings, text};

/// The `config` API group (`createConfigApi(ctx)`): one method per route `config/{method}`.
pub struct ConfigApi {
    ctx: Arc<ServerContext>,
}

/// `createConfigApi(ctx)`.
pub fn create_config_api(ctx: &Arc<ServerContext>) -> IamResult<ConfigApi> {
    Ok(ConfigApi { ctx: ctx.clone() })
}

impl ConfigApi {
    /// `config/apply`: applies a desired configuration in one transaction: every change is authorized like the
    /// direct API call (create/update/delete on the item) under the caller's grant authority, and one failure rolls
    /// everything back. Requires iam:config:apply; audited as `config:apply` with the change summary.
    pub async fn apply(
        &self,
        credential: &CredentialInput,
        input: Body<config::ApplyInput>,
    ) -> IamResult<Reply<config::ApplyOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let tenant_id = string_member(body, "tenantId");
                    let desired = validate_tenant_config(body.get("config"))?;
                    let state = read_state(ctx, &tx, &tenant_id).await?;
                    let prune = body.get("prune") == Some(&Value::Bool(true));
                    let planned = compute_plan(ctx, &tenant_id, &desired, &state, prune)?;
                    apply_plan(ctx, &tx, &principal, &tenant, &planned, &state).await?;
                    let plan = &planned.plan;
                    let mut metadata = Map::new();
                    metadata.insert("prune".into(), Value::Bool(plan.prune));
                    plan.summary.write_into(&mut metadata);
                    metadata.insert(
                        "changed".into(),
                        Value::Array(
                            plan.changes
                                .iter()
                                .filter(|change| change.action != "unchanged")
                                .map(|change| {
                                    Value::String(format!(
                                        "{} {} {}",
                                        change.action, change.kind, change.name
                                    ))
                                })
                                .collect(),
                        ),
                    );
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "config:apply",
                            &tenant_id,
                            &tenant_id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    let mut result = plan.to_json();
                    result.insert("applied".into(), Value::Bool(true));
                    Ok(Value::Object(result))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:config:apply",
                &tenant_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `config/export`: the tenant's roles, policies, groups (with member emails), tenant-defined resource types,
    /// group bindings, and access packages as a configuration document that `plan`/`apply` accept. Requires
    /// iam:config:read.
    pub async fn export(
        &self,
        credential: &CredentialInput,
        input: Body<config::ExportInput>,
    ) -> IamResult<Reply<config::ExportOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let state = read_state(ctx, &tx, &tenant_id).await?;
                Ok(Value::Object(export_state(&state)?))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:config:read",
                &tenant_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `config/plan`: dry run: the changes `apply` would make for a desired configuration, by name. Kinds absent
    /// from the configuration are left alone; with `prune`, items of a listed kind that the configuration omits are
    /// deleted. Requires iam:config:read; nothing is written.
    pub async fn plan(
        &self,
        credential: &CredentialInput,
        input: Body<config::PlanInput>,
    ) -> IamResult<Reply<config::PlanOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let desired = validate_tenant_config(body.get("config"))?;
                let state = read_state(ctx, &tx, &tenant_id).await?;
                let prune = body.get("prune") == Some(&Value::Bool(true));
                let planned = compute_plan(ctx, &tenant_id, &desired, &state, prune)?;
                Ok(Value::Object(planned.plan.to_json()))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:config:read",
                &tenant_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// One planned change. `kind` is a `ConfigChangeKind`, `action` a `ConfigChangeAction` (`create`, `update`,
/// `delete`, `unchanged`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigChange {
    #[serde(rename = "kind")]
    pub kind: String,
    /// The item's name; for bindings, `{group} -> {role}`.
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "action")]
    pub action: String,
    /// The properties that differ, for updates.
    #[serde(rename = "fields", default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<String>>,
    #[serde(rename = "before", default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    #[serde(rename = "after", default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Value>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl ConfigChange {
    fn bare(kind: &str, name: &str, action: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            name: name.to_owned(),
            action: action.to_owned(),
            fields: None,
            before: None,
            after: None,
            extra: Map::new(),
        }
    }

    /// `{ kind, name, action: 'create', after }`.
    pub fn create(kind: &str, name: &str, after: Map<String, Value>) -> Self {
        Self {
            after: Some(Value::Object(after)),
            ..Self::bare(kind, name, "create")
        }
    }

    /// `{ kind, name, action: 'delete' }`.
    pub fn delete(kind: &str, name: &str) -> Self {
        Self::bare(kind, name, "delete")
    }

    /// `{ kind, name, action: 'unchanged' }`.
    pub fn unchanged(kind: &str, name: &str) -> Self {
        Self::bare(kind, name, "unchanged")
    }

    /// `fields.length ? { kind, name, action: 'update', fields, before, after } : { kind, name, action: 'unchanged' }`.
    pub fn compared(
        kind: &str,
        name: &str,
        fields: Vec<String>,
        before: Map<String, Value>,
        after: Map<String, Value>,
    ) -> Self {
        if fields.is_empty() {
            return Self::unchanged(kind, name);
        }
        Self {
            fields: Some(fields),
            before: Some(Value::Object(before)),
            after: Some(Value::Object(after)),
            ..Self::bare(kind, name, "update")
        }
    }

    /// The change as the plan lists it.
    pub fn to_json(&self) -> Map<String, Value> {
        let mut out = Map::new();
        out.insert("kind".into(), Value::String(self.kind.clone()));
        out.insert("name".into(), Value::String(self.name.clone()));
        out.insert("action".into(), Value::String(self.action.clone()));
        if let Some(fields) = &self.fields {
            out.insert(
                "fields".into(),
                Value::Array(fields.iter().cloned().map(Value::String).collect()),
            );
        }
        if let Some(before) = &self.before {
            out.insert("before".into(), before.clone());
        }
        if let Some(after) = &self.after {
            out.insert("after".into(), after.clone());
        }
        out
    }
}

/// Declarative tenant configuration ("configuration as code"): the roles, policies, groups, tenant-defined resource
/// types, and group role bindings of one tenant, keyed by name so the same file applies to several environments.
/// Identities, their direct bindings, credentials, and webhooks are runtime state and are not part of it. Items of
/// the core kinds are the validated JSON objects (`TenantConfigRole`, ...), with undefined members left out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TenantConfig {
    #[serde(rename = "version")]
    pub version: f64,
    /// Tenant-defined resource types (only with `permissions.mode: 'tenant-defined'`); `actions` lists verbs.
    #[serde(
        rename = "resourceTypes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub resource_types: Option<Vec<Value>>,
    #[serde(rename = "policies", default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<Value>>,
    #[serde(rename = "roles", default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<Value>>,
    #[serde(rename = "groups", default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<Value>>,
    /// Group role bindings; identity bindings are assigned at runtime and never synced.
    #[serde(rename = "bindings", default, skip_serializing_if = "Option::is_none")]
    pub bindings: Option<Vec<Value>>,
    /// Organization-wide activation floors (`tenants.setAccessPolicy`); `{}` clears them.
    #[serde(
        rename = "accessPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub access_policy: Option<Value>,
    /// Access packages naming their roles, groups, and optional birthright rule; who holds them is runtime state and
    /// never synced.
    #[serde(rename = "packages", default, skip_serializing_if = "Option::is_none")]
    pub packages: Option<Vec<Value>>,
    /// Access invariants (guardrails), naming groups and people by group name and email.
    #[serde(
        rename = "invariants",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub invariants: Option<Vec<Value>>,
    /// Terms of use; a content change publishes a new version that everyone accepts again.
    #[serde(
        rename = "agreements",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub agreements: Option<Vec<Value>>,
    /// Teams by slug, with maintainers and members by email and the roles they hold by name (org-sync.ts).
    #[serde(rename = "teams", default, skip_serializing_if = "Option::is_none")]
    pub teams: Option<Vec<crate::org_sync::TenantConfigTeam>>,
    /// Departments by name, with heads and people by email (org-sync.ts).
    #[serde(
        rename = "departments",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub departments: Option<Vec<crate::org_sync::TenantConfigDepartment>>,
    /// AI agents by name, with their sponsor by email; keys and delegations are runtime state (ai-sync.ts).
    #[serde(rename = "agents", default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<crate::ai_sync::TenantConfigAgent>>,
    /// The tenant's own AI models, with their provider by name (ai-sync.ts; needs the `inference` option).
    #[serde(
        rename = "inferenceModels",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub inference_models: Option<Vec<crate::ai_sync::TenantConfigInferenceModel>>,
    /// Inference budgets, naming groups, people and agents (ai-sync.ts; needs the `inference` option).
    #[serde(
        rename = "inferenceBudgets",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub inference_budgets: Option<Vec<crate::ai_sync::TenantConfigInferenceBudget>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

const KIND_ORDER: [&str; 14] = [
    "accessPolicy",
    "resourceType",
    "policy",
    "role",
    "group",
    "binding",
    "package",
    "agreement",
    "invariant",
    "department",
    "team",
    "agent",
    "inferenceModel",
    "inferenceBudget",
];
const PERMISSIONS_SID: &str = "RolePermissions";

// --- JSON helpers -------------------------------------------------------------------------------------------------

/// A copy of a value with object keys sorted (by UTF-16 code units) at every level.
fn sort_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| core_js::cmp_utf16(a.0, b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, item)| (key.clone(), sort_keys(item)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_keys).collect()),
        other => other.clone(),
    }
}

/// Stable JSON for comparisons: object keys sorted at every level; `None` is `undefined`.
pub(crate) fn canonical(value: Option<&Value>) -> Option<String> {
    value.map(|value| core_js::stringify(&sort_keys(value)))
}

fn same(a: Option<&Value>, b: Option<&Value>) -> bool {
    canonical(a) == canonical(b)
}

/// `sorted(items)`: distinct items in JavaScript's default sort order.
fn sorted(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let set: IndexSet<String> = items.into_iter().collect();
    let mut list: Vec<String> = set.into_iter().collect();
    list.sort_by(|a, b| core_js::cmp_utf16(a, b));
    list
}

/// The keys of both objects whose values differ, sorted.
pub(crate) fn diff_fields(before: &Map<String, Value>, after: &Map<String, Value>) -> Vec<String> {
    let keys: IndexSet<&String> = core_js::keys(before)
        .into_iter()
        .chain(core_js::keys(after))
        .collect();
    let mut fields: Vec<String> = keys
        .into_iter()
        .filter(|key| !same(before.get(*key), after.get(*key)))
        .cloned()
        .collect();
    fields.sort_by(|a, b| core_js::cmp_utf16(a, b));
    fields
}

fn strings_value(items: &[String]) -> Value {
    Value::Array(items.iter().cloned().map(Value::String).collect())
}

fn str_member<'a>(item: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    item.get(key).and_then(Value::as_str)
}

fn name_of(item: &Map<String, Value>) -> &str {
    str_member(item, "name").unwrap_or("")
}

fn id_of(record: &Record) -> &str {
    str_member(record, "id").unwrap_or("")
}

/// A string-list member (`string[] | undefined`).
fn list_member(item: &Map<String, Value>, key: &str) -> Option<Vec<String>> {
    match item.get(key) {
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect(),
        ),
        _ => None,
    }
}

fn bool_member(item: &Map<String, Value>, key: &str) -> Option<bool> {
    item.get(key).and_then(Value::as_bool)
}

fn number(value: f64) -> Value {
    crate::js::number(value)
}

fn as_object(value: &Value) -> &Map<String, Value> {
    static EMPTY: std::sync::LazyLock<Map<String, Value>> = std::sync::LazyLock::new(Map::new);
    value.as_object().unwrap_or(&EMPTY)
}

fn put_opt(out: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        out.insert(key.into(), value);
    }
}

/// `text.slice(n)` by UTF-16 code units.
fn slice_utf16(value: &str, count: usize) -> String {
    let units: Vec<u16> = value.encode_utf16().collect();
    if count >= units.len() {
        return String::new();
    }
    String::from_utf16_lossy(&units[count..])
}

/// `(a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)`.
fn by_name(a: &Record, b: &Record) -> std::cmp::Ordering {
    core_js::cmp_utf16(name_of(a), name_of(b))
}

async fn find(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

fn in_tenant(tenant_id: &str) -> Filter {
    Filter::new().eq("tenantId", tenant_id.to_owned())
}

/// `name.trim().toLowerCase()`.
fn lower(name: &str) -> String {
    core_js::to_lower(core_js::trim(name))
}

// --- Roles ----------------------------------------------------------------------------------------------------------

/// A role's inline document, from a permissions list or a document; `None` when it has neither.
fn role_document(role: &Map<String, Value>) -> IamResult<Option<Value>> {
    let permissions = role.get("permissions");
    let document = role.get("document");
    if permissions.is_some() && document.is_some() {
        return Err(invalid_input(format!(
            "Role {}: provide permissions or a document",
            name_of(role)
        )));
    }
    if let Some(permissions) = permissions {
        return Ok(Some(json!({
            "version": 1,
            "statements": [
                { "sid": PERMISSIONS_SID, "effect": "allow", "actions": permissions, "resources": ["*"] },
            ],
        })));
    }
    Ok(document.cloned())
}

/// Presents a stored inline document as a permissions list when it is exactly the compiled form.
fn exported_document(document: Option<&Value>) -> IamResult<Map<String, Value>> {
    let mut out = Map::new();
    let Some(document) = document.filter(|document| truthy(Some(document))) else {
        return Ok(out);
    };
    let Some(statements) = document.get("statements").and_then(Value::as_array) else {
        // `document.statements[0]` of a malformed document is a TypeError in TypeScript.
        return Err(internal_error());
    };
    if let [statement] = statements.as_slice()
        && statement.get("sid").and_then(Value::as_str) == Some(PERMISSIONS_SID)
        && statement.get("effect").and_then(Value::as_str) == Some("allow")
        && statement
            .get("resources")
            .and_then(Value::as_array)
            .is_some_and(|resources| resources.len() == 1 && resources[0].as_str() == Some("*"))
        && !truthy(statement.get("conditions"))
    {
        out.insert(
            "permissions".into(),
            statement.get("actions").cloned().unwrap_or(Value::Null),
        );
        return Ok(out);
    }
    out.insert("document".into(), document.clone());
    Ok(out)
}

/// Refuses two items of one kind with the same name.
fn unique_names(items: impl IntoIterator<Item = String>, kind: &str) -> IamResult<()> {
    let mut seen: IndexSet<String> = IndexSet::new();
    for name in items {
        if seen.contains(&name) {
            return Err(invalid_input(format!("Duplicate {kind} {name}")));
        }
        seen.insert(name);
    }
    Ok(())
}

// --- Validation -----------------------------------------------------------------------------------------------------

fn optional_text(item: &Map<String, Value>, key: &str, max: usize) -> IamResult<Option<Value>> {
    match item.get(key) {
        None => Ok(None),
        Some(value) => Ok(Some(Value::String(text(Some(value), key, max)?))),
    }
}

fn optional_strings(item: &Map<String, Value>, key: &str) -> IamResult<Option<Vec<String>>> {
    match item.get(key) {
        None => Ok(None),
        Some(value) => Ok(Some(strings(Some(value), key)?)),
    }
}

fn optional_boolean(item: &Map<String, Value>, key: &str) -> IamResult<Option<Value>> {
    match item.get(key) {
        None => Ok(None),
        Some(Value::Bool(flag)) => Ok(Some(Value::Bool(*flag))),
        Some(_) => Err(invalid_input(format!("{key} must be boolean"))),
    }
}

/// A duration in milliseconds from a minute up to `max`; null and absent both mean none.
fn optional_duration(item: &Map<String, Value>, key: &str, max: f64) -> IamResult<Option<Value>> {
    match item.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => Ok(Some(number(integer(Some(value), key, 60_000.0, max)?))),
    }
}

/// The access policy as `tenantAccessPolicy` builds it, members in its order.
fn access_policy_json(value: Option<&Value>) -> IamResult<Map<String, Value>> {
    let policy = tenant_access_policy(value)?;
    let mut out = Map::new();
    if let Some(ms) = policy.max_activation_ms {
        out.insert("maxActivationMs".into(), number(ms));
    }
    if let Some(ms) = policy.approval_lifetime_ms {
        out.insert("approvalLifetimeMs".into(), number(ms));
    }
    if policy.require_justification == Some(true) {
        out.insert("requireJustification".into(), Value::Bool(true));
    }
    if policy.require_mfa == Some(true) {
        out.insert("requireMfa".into(), Value::Bool(true));
    }
    if policy.require_approval == Some(true) {
        out.insert("requireApproval".into(), Value::Bool(true));
    }
    Ok(out)
}

/// Validates the shape of a desired configuration; references are checked against the tenant during planning.
pub fn validate_tenant_config(value: Option<&Value>) -> IamResult<TenantConfig> {
    let input = object(value)?;
    if input.get("version").and_then(core_js::as_number) != Some(1.0) {
        return Err(invalid_input("Configuration version must be 1"));
    }
    let list = |key: &str| -> IamResult<Option<Vec<Map<String, Value>>>> {
        match input.get(key) {
            None => Ok(None),
            Some(Value::Array(items)) if items.len() <= 1000 => Ok(Some(
                items
                    .iter()
                    .map(|item| object(Some(item)).cloned())
                    .collect::<IamResult<_>>()?,
            )),
            Some(_) => Err(invalid_input(format!(
                "{key} must be an array of at most 1000 items"
            ))),
        }
    };
    let mut config = TenantConfig {
        version: 1.0,
        resource_types: None,
        policies: None,
        roles: None,
        groups: None,
        bindings: None,
        access_policy: None,
        packages: None,
        invariants: None,
        agreements: None,
        teams: None,
        departments: None,
        agents: None,
        inference_models: None,
        inference_budgets: None,
        extra: Map::new(),
    };
    if let Some(items) = list("resourceTypes")? {
        let mut parsed = Vec::with_capacity(items.len());
        for item in &items {
            let mut out = Map::new();
            out.insert(
                "name".into(),
                Value::String(text(item.get("name"), "resource type name", 64)?),
            );
            put_opt(
                &mut out,
                "description",
                optional_text(item, "description", 512)?,
            );
            put_opt(
                &mut out,
                "actions",
                optional_strings(item, "actions")?.map(|list| strings_value(&list)),
            );
            if let Some(attributes) = item.get("attributes") {
                out.insert(
                    "attributes".into(),
                    Value::Object(object(Some(attributes))?.clone()),
                );
            }
            put_opt(&mut out, "parent", optional_text(item, "parent", 64)?);
            put_opt(
                &mut out,
                "relations",
                optional_strings(item, "relations")?.map(|list| strings_value(&list)),
            );
            parsed.push(Value::Object(out));
        }
        config.resource_types = Some(parsed);
    }
    if let Some(items) = list("policies")? {
        let mut parsed = Vec::with_capacity(items.len());
        for item in &items {
            let mut out = Map::new();
            out.insert(
                "name".into(),
                Value::String(text(item.get("name"), "policy name", 256)?),
            );
            put_opt(
                &mut out,
                "description",
                optional_text(item, "description", 512)?,
            );
            out.insert(
                "document".into(),
                Value::Object(object(item.get("document"))?.clone()),
            );
            parsed.push(Value::Object(out));
        }
        config.policies = Some(parsed);
    }
    if let Some(items) = list("roles")? {
        let mut parsed = Vec::with_capacity(items.len());
        for item in &items {
            let mut out = Map::new();
            out.insert(
                "name".into(),
                Value::String(text(item.get("name"), "role name", 256)?),
            );
            put_opt(
                &mut out,
                "description",
                optional_text(item, "description", 512)?,
            );
            put_opt(
                &mut out,
                "policies",
                optional_strings(item, "policies")?.map(|list| strings_value(&list)),
            );
            put_opt(
                &mut out,
                "permissions",
                optional_strings(item, "permissions")?.map(|list| strings_value(&list)),
            );
            if let Some(document) = item.get("document") {
                out.insert(
                    "document".into(),
                    Value::Object(object(Some(document))?.clone()),
                );
            }
            put_opt(
                &mut out,
                "inherits",
                optional_strings(item, "inherits")?.map(|list| strings_value(&list)),
            );
            parsed.push(Value::Object(out));
        }
        config.roles = Some(parsed);
    }
    if let Some(items) = list("groups")? {
        let mut parsed = Vec::with_capacity(items.len());
        for item in &items {
            let mut out = Map::new();
            out.insert(
                "name".into(),
                Value::String(text(item.get("name"), "group name", 256)?),
            );
            put_opt(
                &mut out,
                "description",
                optional_text(item, "description", 512)?,
            );
            put_opt(
                &mut out,
                "members",
                optional_strings(item, "members")?.map(|list| {
                    Value::Array(
                        list.iter()
                            .map(|member| Value::String(lower(member)))
                            .collect(),
                    )
                }),
            );
            parsed.push(Value::Object(out));
        }
        config.groups = Some(parsed);
    }
    if let Some(items) = list("bindings")? {
        let mut parsed = Vec::with_capacity(items.len());
        for item in &items {
            let mut out = Map::new();
            out.insert(
                "group".into(),
                Value::String(text(item.get("group"), "binding group", 256)?),
            );
            out.insert(
                "role".into(),
                Value::String(text(item.get("role"), "binding role", 256)?),
            );
            put_opt(&mut out, "eligible", optional_boolean(item, "eligible")?);
            put_opt(
                &mut out,
                "maxActivationMs",
                optional_duration(item, "maxActivationMs", MAX_ACTIVATION_MS)?,
            );
            put_opt(
                &mut out,
                "requireJustification",
                optional_boolean(item, "requireJustification")?,
            );
            put_opt(
                &mut out,
                "requireMfa",
                optional_boolean(item, "requireMfa")?,
            );
            put_opt(
                &mut out,
                "requireApproval",
                optional_boolean(item, "requireApproval")?,
            );
            put_opt(
                &mut out,
                "approverGroup",
                optional_text(item, "approverGroup", 512)?,
            );
            put_opt(
                &mut out,
                "managerApproval",
                optional_boolean(item, "managerApproval")?,
            );
            if let Some(window) = item.get("window") {
                out.insert(
                    "window".into(),
                    Value::Object(object(Some(window))?.clone()),
                );
            }
            parsed.push(Value::Object(out));
        }
        config.bindings = Some(parsed);
    }
    if let Some(policy) = input.get("accessPolicy") {
        config.access_policy = Some(Value::Object(access_policy_json(Some(policy))?));
    }
    if let Some(items) = list("packages")? {
        let mut parsed = Vec::with_capacity(items.len());
        for item in &items {
            let mut out = Map::new();
            out.insert(
                "name".into(),
                Value::String(text(item.get("name"), "package name", 128)?),
            );
            put_opt(
                &mut out,
                "description",
                optional_text(item, "description", 512)?,
            );
            put_opt(
                &mut out,
                "roles",
                optional_strings(item, "roles")?.map(|list| strings_value(&list)),
            );
            put_opt(
                &mut out,
                "groups",
                optional_strings(item, "groups")?.map(|list| strings_value(&list)),
            );
            put_opt(
                &mut out,
                "maxDurationMs",
                optional_duration(item, "maxDurationMs", 315_360_000_000.0)?,
            );
            put_opt(
                &mut out,
                "requireJustification",
                optional_boolean(item, "requireJustification")?,
            );
            put_opt(
                &mut out,
                "requestable",
                optional_boolean(item, "requestable")?,
            );
            put_opt(
                &mut out,
                "approverGroup",
                optional_text(item, "approverGroup", 512)?,
            );
            put_opt(
                &mut out,
                "managerApproval",
                optional_boolean(item, "managerApproval")?,
            );
            // Checked fully during planning, where the group names are known.
            match item.get("autoAssign") {
                None => {}
                Some(Value::Null) => {
                    out.insert("autoAssign".into(), Value::Null);
                }
                Some(rule) => {
                    out.insert(
                        "autoAssign".into(),
                        Value::Object(object(Some(rule))?.clone()),
                    );
                }
            }
            parsed.push(Value::Object(out));
        }
        config.packages = Some(parsed);
    }
    if let Some(items) = list("invariants")? {
        let mut parsed = Vec::with_capacity(items.len());
        for item in &items {
            let name = text(item.get("name"), "invariant name", 100)?;
            let subject = object(item.get("subject"))?;
            let single = subject.len() == 1;
            let parsed_subject = if single && subject.get("everyone") == Some(&Value::Bool(true)) {
                json!({ "everyone": true })
            } else if single && subject.contains_key("group") {
                json!({ "group": text(subject.get("group"), "invariant subject group", 256)? })
            } else if single && subject.contains_key("identity") {
                json!({
                    "identity": core_js::to_lower(&text(
                        subject.get("identity"),
                        "invariant subject identity",
                        256,
                    )?),
                })
            } else if single && subject.contains_key("attribute") {
                let attribute = object(subject.get("attribute"))?;
                let mut parsed = Map::new();
                parsed.insert(
                    "name".into(),
                    Value::String(text(
                        attribute.get("name"),
                        "invariant subject attribute",
                        256,
                    )?),
                );
                put_opt(&mut parsed, "value", attribute.get("value").cloned());
                json!({ "attribute": parsed })
            } else {
                return Err(invalid_input(format!(
                    "Invariant {name}: subject must be one of everyone, group, identity, or attribute"
                )));
            };
            let resource = object(item.get("resource"))?;
            let expect = item.get("expect").and_then(Value::as_str);
            if expect != Some("allow") && expect != Some("deny") {
                return Err(invalid_input(format!(
                    "Invariant {name}: expect must be allow or deny"
                )));
            }
            if let Some(mode) = item.get("mode")
                && mode.as_str() != Some("enforce")
                && mode.as_str() != Some("monitor")
            {
                return Err(invalid_input(format!(
                    "Invariant {name}: mode must be enforce or monitor"
                )));
            }
            let mut out = Map::new();
            out.insert("name".into(), Value::String(name));
            put_opt(
                &mut out,
                "description",
                optional_text(item, "description", 500)?,
            );
            out.insert("subject".into(), parsed_subject);
            out.insert(
                "action".into(),
                Value::String(text(item.get("action"), "invariant action", 256)?),
            );
            let mut target = Map::new();
            target.insert(
                "type".into(),
                Value::String(text(resource.get("type"), "invariant resource type", 256)?),
            );
            target.insert(
                "id".into(),
                Value::String(text(resource.get("id"), "invariant resource id", 256)?),
            );
            out.insert("resource".into(), Value::Object(target));
            out.insert("expect".into(), json!(expect));
            put_opt(&mut out, "mode", item.get("mode").cloned());
            put_opt(&mut out, "assumeMfa", optional_boolean(item, "assumeMfa")?);
            parsed.push(Value::Object(out));
        }
        config.invariants = Some(parsed);
    }
    if let Some(items) = list("agreements")? {
        let mut parsed = Vec::with_capacity(items.len());
        for item in &items {
            let name = text(item.get("name"), "agreement name", 100)?;
            let content = match item.get("content") {
                Some(Value::String(content)) if !core_js::trim(content).is_empty() => {
                    content.clone()
                }
                _ => {
                    return Err(invalid_input(format!(
                        "Agreement {name}: content is required"
                    )));
                }
            };
            let mut out = Map::new();
            out.insert("name".into(), Value::String(name));
            out.insert("content".into(), Value::String(content));
            put_opt(&mut out, "url", optional_text(item, "url", 2048)?);
            put_opt(&mut out, "required", optional_boolean(item, "required")?);
            match item.get("reacceptAfterDays") {
                None | Some(Value::Null) => {}
                Some(days) => {
                    out.insert(
                        "reacceptAfterDays".into(),
                        number(integer(Some(days), "reacceptAfterDays", 1.0, 3650.0)?),
                    );
                }
            }
            parsed.push(Value::Object(out));
        }
        config.agreements = Some(parsed);
    }
    // Teams and departments (org-sync.ts).
    if let Some(items) = list("teams")? {
        config.teams = Some(parse_teams_config(&items)?);
    }
    if let Some(items) = list("departments")? {
        config.departments = Some(parse_departments_config(&items)?);
    }
    // AI agents, models and budgets (ai-sync.ts).
    if let Some(items) = list("agents")? {
        config.agents = Some(parse_agents_config(&items)?);
    }
    if let Some(items) = list("inferenceModels")? {
        config.inference_models = Some(parse_models_config(&items)?);
    }
    if let Some(items) = list("inferenceBudgets")? {
        config.inference_budgets = Some(parse_budgets_config(&items)?);
    }
    for (kind, items) in [
        ("resource type", &config.resource_types),
        ("policy", &config.policies),
        ("role", &config.roles),
        ("group", &config.groups),
    ] {
        if let Some(items) = items {
            unique_names(
                items.iter().map(|item| name_of(as_object(item)).to_owned()),
                kind,
            )?;
        }
    }
    // Invariant and agreement names are unique regardless of case, as their APIs enforce.
    for (kind, items) in [
        ("invariant", &config.invariants),
        ("agreement", &config.agreements),
    ] {
        if let Some(items) = items {
            unique_names(
                items.iter().map(|item| lower(name_of(as_object(item)))),
                kind,
            )?;
        }
    }
    // Package names are unique regardless of case, as `packages.create` enforces.
    if let Some(packages) = &config.packages {
        unique_names(
            packages.iter().map(|item| lower(name_of(as_object(item)))),
            "package",
        )?;
    }
    if let Some(bindings) = &config.bindings {
        let mut seen: IndexSet<String> = IndexSet::new();
        for binding in bindings {
            let binding = as_object(binding);
            let key = format!(
                "{} -> {}",
                str_member(binding, "group").unwrap_or(""),
                str_member(binding, "role").unwrap_or("")
            );
            if seen.contains(&key) {
                return Err(invalid_input(format!("Duplicate binding {key}")));
            }
            seen.insert(key);
        }
    }
    Ok(config)
}

// --- Current state --------------------------------------------------------------------------------------------------

/// The tenant's current state in configuration form, with the records behind each item.
struct CurrentState {
    /// The tenant as stored, for the access policy write.
    tenant_record: Record,
    resource_types: Vec<Record>,
    resource_type_actions: IndexMap<String, Vec<String>>,
    policies: Vec<Record>,
    roles: Vec<Record>,
    groups: Vec<Record>,
    members: IndexMap<String, Vec<Identity>>,
    bindings: Vec<Record>,
    packages: Vec<Record>,
    identities_by_email: IndexMap<String, Identity>,
    identity_emails: IndexMap<String, String>,
    invariants: Vec<Record>,
    agreements: Vec<Record>,
    /// Teams and departments (org-sync.ts).
    org: OrgState,
    /// AI agents, models and budgets (ai-sync.ts).
    ai: AiState,
    /// The keys of the license products visible to the tenant: the valid identity.licenses values (licenses.ts).
    license_keys: IndexSet<String>,
}

impl CurrentState {
    fn policy_names(&self) -> IndexMap<String, String> {
        id_names(&self.policies)
    }
    fn role_names(&self) -> IndexMap<String, String> {
        id_names(&self.roles)
    }
    fn group_names(&self) -> IndexMap<String, String> {
        id_names(&self.groups)
    }
    fn directory(&self) -> Directory {
        Directory {
            identity_emails: self.identity_emails.clone(),
            role_names: self.role_names(),
            group_names: self.group_names(),
        }
    }
}

fn id_names(records: &[Record]) -> IndexMap<String, String> {
    records
        .iter()
        .map(|record| (id_of(record).to_owned(), name_of(record).to_owned()))
        .collect()
}

fn names_of(ids: &[String], names: &IndexMap<String, String>) -> Vec<String> {
    ids.iter().filter_map(|id| names.get(id).cloned()).collect()
}

async fn read_state(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
) -> IamResult<CurrentState> {
    // `ctx.tenant(tx, tenantId)`: NOT_FOUND for a missing tenant.
    ctx.tenant(tx, tenant_id).await?;
    let tenant_record = tx
        .get("tenants", tenant_id)
        .await?
        .ok_or_else(|| IamError::with_status("NOT_FOUND", "Tenant not found", 404))?;
    let mut resource_types = find(tx, "resourceTypes", in_tenant(tenant_id)).await?;
    resource_types.sort_by(by_name);
    let mut resource_type_actions: IndexMap<String, Vec<String>> = IndexMap::new();
    for record in &resource_types {
        let name = name_of(record).to_owned();
        let actions = match ctx
            .catalog
            .resource_type_definition(tx.as_ref(), tenant_id, &name)
            .await?
        {
            Some(definition) => {
                let prefix = core_js::utf16_len(&name) + 1;
                let mut actions: Vec<String> = definition
                    .actions
                    .iter()
                    .map(|action| slice_utf16(action, prefix))
                    .collect();
                actions.sort_by(|a, b| core_js::cmp_utf16(a, b));
                actions
            }
            None => Vec::new(),
        };
        resource_type_actions.insert(name, actions);
    }
    let mut policies: Vec<Record> = find(tx, "policies", in_tenant(tenant_id))
        .await?
        .into_iter()
        .filter(|policy| str_member(policy, "uniqueKey") != Some("system:owner"))
        .collect();
    policies.sort_by(by_name);
    let mut roles: Vec<Record> = find(tx, "roles", in_tenant(tenant_id))
        .await?
        .into_iter()
        .filter(|role| !truthy(role.get("protected")))
        .collect();
    roles.sort_by(by_name);
    // Teams' backing groups (and what is bound to them) belong to the teams API, never to configuration sync.
    let all_groups = find(tx, "groups", in_tenant(tenant_id)).await?;
    let mut outside_group_ids: IndexSet<String> = IndexSet::new();
    for group in &all_groups {
        if is_team_group(Some(&Value::Object(group.clone())))? {
            outside_group_ids.insert(id_of(group).to_owned());
        }
    }
    // Configuration names groups, and an identity provider's directory sync (SCIM) names the groups it creates: when
    // such a group shares its name with another group, the name means the other one, so an IdP cannot capture the
    // roles and approvals configuration gives a group by creating one of the same name. Those groups stay out of
    // sync's view.
    let scim_group_ids: IndexSet<String> = find(tx, "scimGroups", in_tenant(tenant_id))
        .await?
        .iter()
        .map(|link| crate::js::js_string(link.get("groupId")))
        .collect();
    let own_names: IndexSet<&str> = all_groups
        .iter()
        .filter(|group| {
            !outside_group_ids.contains(id_of(group)) && !scim_group_ids.contains(id_of(group))
        })
        .map(name_of)
        .collect();
    let mut planted: Vec<String> = Vec::new();
    for group in &all_groups {
        if scim_group_ids.contains(id_of(group)) && own_names.contains(name_of(group)) {
            planted.push(id_of(group).to_owned());
        }
    }
    outside_group_ids.extend(planted);
    let mut groups: Vec<Record> = all_groups
        .iter()
        .filter(|group| !outside_group_ids.contains(id_of(group)))
        .cloned()
        .collect();
    groups.sort_by(by_name);
    let identities: Vec<Identity> = find(tx, "identities", in_tenant(tenant_id))
        .await?
        .into_iter()
        .map(decode::<Identity>)
        .collect::<IamResult<Vec<_>>>()?
        .into_iter()
        .filter(|identity| identity.status != IdentityStatus::Deleted)
        .collect();
    let mut identities_by_email: IndexMap<String, Identity> = IndexMap::new();
    for identity in &identities {
        if let Some(email) = identity.email.as_deref().filter(|email| !email.is_empty()) {
            identities_by_email.insert(core_js::to_lower(email), identity.clone());
        }
    }
    let mut members: IndexMap<String, Vec<Identity>> = IndexMap::new();
    let by_id: IndexMap<&str, &Identity> = identities
        .iter()
        .map(|identity| (identity.id.as_str(), identity))
        .collect();
    for membership in find(tx, "groupMembers", in_tenant(tenant_id)).await? {
        let membership: GroupMember = decode(membership)?;
        let Some(identity) = by_id.get(membership.identity_id.as_str()) else {
            continue;
        };
        if !ctx.live_membership(&membership) {
            continue;
        }
        members
            .entry(membership.group_id.clone())
            .or_default()
            .push((*identity).clone());
    }
    let mut bindings: Vec<Record> = Vec::new();
    for record in find(
        tx,
        "bindings",
        in_tenant(tenant_id).eq("subjectType", "group"),
    )
    .await?
    {
        let binding: Binding = decode(record.clone())?;
        if !ctx.expired_binding(&binding) && !outside_group_ids.contains(&binding.subject_id) {
            bindings.push(record);
        }
    }
    let mut packages = find(tx, "accessPackages", in_tenant(tenant_id)).await?;
    packages.sort_by(by_name);
    let mut invariants = find(tx, "accessInvariants", in_tenant(tenant_id)).await?;
    invariants.sort_by(by_name);
    let mut agreements = find(tx, "agreements", in_tenant(tenant_id)).await?;
    agreements.sort_by(by_name);
    let mut identity_emails: IndexMap<String, String> = IndexMap::new();
    for identity in &identities {
        if let Some(email) = identity.email.as_deref().filter(|email| !email.is_empty()) {
            identity_emails.insert(identity.id.clone(), core_js::to_lower(email));
        }
    }
    let org = read_org_state(ctx, tx, tenant_id).await?;
    let ai = read_ai_state(ctx, tx, tenant_id).await?;
    let license_keys = license_rule_keys(tx, tenant_id).await?;
    Ok(CurrentState {
        tenant_record,
        resource_types,
        resource_type_actions,
        policies,
        roles,
        groups,
        members,
        bindings,
        packages,
        identities_by_email,
        identity_emails,
        invariants,
        agreements,
        org,
        ai,
        license_keys,
    })
}

/// An invariant's stored subject in document form (group names, member emails); unknown references keep their IDs.
fn portable_subject(
    subject: Option<&Value>,
    group_names: &IndexMap<String, String>,
    identity_emails: &IndexMap<String, String>,
) -> Value {
    let subject = subject.and_then(Value::as_object);
    if let Some(group_id) = subject.and_then(|subject| subject.get("groupId")) {
        let id = crate::js::js_string(Some(group_id));
        return json!({ "group": group_names.get(&id).cloned().map_or(group_id.clone(), Value::String) });
    }
    if let Some(identity_id) = subject.and_then(|subject| subject.get("identityId")) {
        let id = crate::js::js_string(Some(identity_id));
        return json!({
            "identity": identity_emails.get(&id).cloned().map_or(identity_id.clone(), Value::String),
        });
    }
    if let Some(subject) = subject
        && subject.contains_key("attribute")
    {
        let mut out = Map::new();
        put_opt(&mut out, "attribute", subject.get("attribute").cloned());
        return Value::Object(out);
    }
    json!({ "everyone": true })
}

/// An invariant record in document form, with defaults filled in so plans compare like with like.
fn exported_invariant(
    invariant: &Record,
    group_names: &IndexMap<String, String>,
    identity_emails: &IndexMap<String, String>,
) -> Map<String, Value> {
    let mut out = Map::new();
    put_opt(&mut out, "name", invariant.get("name").cloned());
    put_opt(
        &mut out,
        "description",
        invariant.get("description").cloned(),
    );
    out.insert(
        "subject".into(),
        portable_subject(invariant.get("subject"), group_names, identity_emails),
    );
    put_opt(&mut out, "action", invariant.get("action").cloned());
    put_opt(&mut out, "resource", invariant.get("resource").cloned());
    put_opt(&mut out, "expect", invariant.get("expect").cloned());
    put_opt(&mut out, "mode", invariant.get("mode").cloned());
    put_opt(&mut out, "assumeMfa", invariant.get("assumeMfa").cloned());
    out
}

fn exported_agreement(agreement: &Map<String, Value>) -> Map<String, Value> {
    let mut out = Map::new();
    put_opt(&mut out, "name", agreement.get("name").cloned());
    put_opt(&mut out, "content", agreement.get("content").cloned());
    put_opt(&mut out, "url", agreement.get("url").cloned());
    put_opt(&mut out, "required", agreement.get("required").cloned());
    put_opt(
        &mut out,
        "reacceptAfterDays",
        agreement.get("reacceptAfterDays").cloned(),
    );
    out
}

/// A stored birthright rule in document form: groups, teams and departments by name.
fn rule_names(
    state: &CurrentState,
    rule: &Value,
    group_names: &IndexMap<String, String>,
) -> IamResult<Value> {
    let input = serde_json::to_value(rule_input(rule)?).map_err(|_| internal_error())?;
    let named = map_rule_groups(&input, &|group_id: &str| {
        group_names
            .get(group_id)
            .cloned()
            .unwrap_or_else(|| group_id.to_owned())
    })?;
    org_rule_names(&state.org, &named)
}

fn export_state(state: &CurrentState) -> IamResult<Map<String, Value>> {
    let policy_names = state.policy_names();
    let role_names = state.role_names();
    let group_names = state.group_names();
    let mut config = Map::new();
    config.insert("version".into(), json!(1));
    let resource_types = state
        .resource_types
        .iter()
        .map(|record| {
            let mut out = Map::new();
            out.insert("name".into(), json!(name_of(record)));
            put_opt(&mut out, "description", record.get("description").cloned());
            out.insert(
                "actions".into(),
                strings_value(
                    state
                        .resource_type_actions
                        .get(name_of(record))
                        .map(Vec::as_slice)
                        .unwrap_or_default(),
                ),
            );
            put_opt(&mut out, "attributes", record.get("attributes").cloned());
            put_opt(&mut out, "parent", record.get("parent").cloned());
            let mut relations = list_member(record, "relations").unwrap_or_default();
            relations.sort_by(|a, b| core_js::cmp_utf16(a, b));
            out.insert("relations".into(), strings_value(&relations));
            Value::Object(out)
        })
        .collect();
    config.insert("resourceTypes".into(), Value::Array(resource_types));
    let policies = state
        .policies
        .iter()
        .map(|record| {
            let mut out = Map::new();
            out.insert("name".into(), json!(name_of(record)));
            put_opt(&mut out, "description", record.get("description").cloned());
            put_opt(&mut out, "document", record.get("document").cloned());
            Value::Object(out)
        })
        .collect();
    config.insert("policies".into(), Value::Array(policies));
    let mut roles = Vec::with_capacity(state.roles.len());
    for record in &state.roles {
        let mut out = Map::new();
        out.insert("name".into(), json!(name_of(record)));
        put_opt(&mut out, "description", record.get("description").cloned());
        out.insert(
            "policies".into(),
            strings_value(&sorted(names_of(
                &list_member(record, "policyIds").unwrap_or_default(),
                &policy_names,
            ))),
        );
        out.extend(exported_document(record.get("document"))?);
        let inherits = list_member(record, "inherits").unwrap_or_default();
        if !inherits.is_empty() {
            out.insert(
                "inherits".into(),
                strings_value(&sorted(names_of(&inherits, &role_names))),
            );
        }
        roles.push(Value::Object(out));
    }
    config.insert("roles".into(), Value::Array(roles));
    let groups = state
        .groups
        .iter()
        .map(|record| {
            let mut out = Map::new();
            out.insert("name".into(), json!(name_of(record)));
            put_opt(&mut out, "description", record.get("description").cloned());
            out.insert(
                "members".into(),
                strings_value(&sorted(group_member_emails(state, id_of(record)))),
            );
            Value::Object(out)
        })
        .collect();
    config.insert("groups".into(), Value::Array(groups));
    let mut bindings: Vec<(String, Value)> = Vec::new();
    for record in &state.bindings {
        let (Some(group), Some(role)) = (
            group_names.get(str_member(record, "subjectId").unwrap_or("")),
            role_names.get(str_member(record, "roleId").unwrap_or("")),
        ) else {
            continue;
        };
        let mut out = Map::new();
        out.insert("group".into(), json!(group));
        out.insert("role".into(), json!(role));
        if truthy(record.get("eligible")) {
            out.insert("eligible".into(), Value::Bool(true));
            put_opt(
                &mut out,
                "maxActivationMs",
                record.get("maxActivationMs").cloned(),
            );
            for flag in ["requireJustification", "requireMfa", "requireApproval"] {
                if truthy(record.get(flag)) {
                    out.insert(flag.into(), Value::Bool(true));
                }
            }
            if let Some(approver) = str_member(record, "approverGroupId")
                .filter(|id| !id.is_empty())
                .and_then(|id| group_names.get(id))
            {
                out.insert("approverGroup".into(), json!(approver));
            }
            if truthy(record.get("managerApproval")) {
                out.insert("managerApproval".into(), Value::Bool(true));
            }
        }
        if truthy(record.get("window")) {
            put_opt(&mut out, "window", record.get("window").cloned());
        }
        bindings.push((format!("{group} -> {role}"), Value::Object(out)));
    }
    bindings.sort_by(|a, b| locale_compare(&a.0, &b.0));
    config.insert(
        "bindings".into(),
        Value::Array(bindings.into_iter().map(|(_, value)| value).collect()),
    );
    let mut packages = Vec::with_capacity(state.packages.len());
    for record in &state.packages {
        let mut out = Map::new();
        out.insert("name".into(), json!(name_of(record)));
        put_opt(&mut out, "description", record.get("description").cloned());
        out.insert(
            "roles".into(),
            strings_value(&sorted(names_of(
                &list_member(record, "roleIds").unwrap_or_default(),
                &role_names,
            ))),
        );
        out.insert(
            "groups".into(),
            strings_value(&sorted(names_of(
                &list_member(record, "groupIds").unwrap_or_default(),
                &group_names,
            ))),
        );
        put_opt(
            &mut out,
            "maxDurationMs",
            record.get("maxDurationMs").cloned(),
        );
        if truthy(record.get("requireJustification")) {
            out.insert("requireJustification".into(), Value::Bool(true));
        }
        if truthy(record.get("requestable")) {
            out.insert("requestable".into(), Value::Bool(true));
        }
        if let Some(approver) = str_member(record, "approverGroupId")
            .filter(|id| !id.is_empty())
            .and_then(|id| group_names.get(id))
        {
            out.insert("approverGroup".into(), json!(approver));
        }
        if truthy(record.get("managerApproval")) {
            out.insert("managerApproval".into(), Value::Bool(true));
        }
        // The rule as written, with group names; owner, authority, revision, and approval are runtime state.
        if let Some(rule) = record.get("autoAssign").filter(|rule| truthy(Some(rule))) {
            out.insert("autoAssign".into(), rule_names(state, rule, &group_names)?);
        }
        packages.push(Value::Object(out));
    }
    config.insert("packages".into(), Value::Array(packages));
    if let Some(policy) = state
        .tenant_record
        .get("accessPolicy")
        .filter(|policy| truthy(Some(policy)))
    {
        config.insert("accessPolicy".into(), policy.clone());
    }
    // Listed only when the tenant has some, so documents of tenants that use neither stay unchanged.
    if !state.invariants.is_empty() {
        config.insert(
            "invariants".into(),
            Value::Array(
                state
                    .invariants
                    .iter()
                    .map(|invariant| {
                        Value::Object(exported_invariant(
                            invariant,
                            &group_names,
                            &state.identity_emails,
                        ))
                    })
                    .collect(),
            ),
        );
    }
    if !state.agreements.is_empty() {
        config.insert(
            "agreements".into(),
            Value::Array(
                state
                    .agreements
                    .iter()
                    .map(|agreement| Value::Object(exported_agreement(agreement)))
                    .collect(),
            ),
        );
    }
    // Teams and departments (org-sync.ts), each only when the tenant has some.
    config.extend(export_org(&state.org, &state.directory())?);
    // AI agents, models and budgets (ai-sync.ts), each only when the tenant has some.
    let names = json!({
        "identityEmails": state.identity_emails,
        "groupNames": group_names,
    });
    if let Value::Object(ai) = export_ai(&state.ai, &names)? {
        config.extend(ai);
    }
    Ok(config)
}

/// The lowercase emails of a group's live members (people without an email are left out).
fn group_member_emails(state: &CurrentState, group_id: &str) -> Vec<String> {
    state
        .members
        .get(group_id)
        .into_iter()
        .flatten()
        .filter_map(|identity| {
            identity
                .email
                .as_deref()
                .filter(|email| !email.is_empty())
                .map(core_js::to_lower)
        })
        .collect()
}

// --- Planning -------------------------------------------------------------------------------------------------------

/// One desired item next to the record it matches, if any.
#[derive(Debug, Clone)]
struct Planned<R> {
    change: ConfigChange,
    desired: Option<Map<String, Value>>,
    record: Option<R>,
}

/// `ConfigPlan.summary`.
#[derive(Debug, Clone, Copy, Default)]
struct Summary {
    create: u32,
    update: u32,
    delete: u32,
    unchanged: u32,
}

impl Summary {
    fn count(&mut self, action: &str) {
        match action {
            "create" => self.create += 1,
            "update" => self.update += 1,
            "delete" => self.delete += 1,
            _ => self.unchanged += 1,
        }
    }

    fn write_into(&self, out: &mut Map<String, Value>) {
        out.insert("create".into(), json!(self.create));
        out.insert("update".into(), json!(self.update));
        out.insert("delete".into(), json!(self.delete));
        out.insert("unchanged".into(), json!(self.unchanged));
    }
}

/// `ConfigPlan`.
#[derive(Debug, Clone)]
struct ConfigPlan {
    tenant_id: String,
    prune: bool,
    changes: Vec<ConfigChange>,
    summary: Summary,
}

impl ConfigPlan {
    fn to_json(&self) -> Map<String, Value> {
        let mut out = Map::new();
        out.insert("tenantId".into(), json!(self.tenant_id));
        out.insert("prune".into(), Value::Bool(self.prune));
        out.insert(
            "changes".into(),
            Value::Array(
                self.changes
                    .iter()
                    .map(|change| Value::Object(change.to_json()))
                    .collect(),
            ),
        );
        let mut summary = Map::new();
        self.summary.write_into(&mut summary);
        out.insert("summary".into(), Value::Object(summary));
        out
    }

    fn note(&mut self, change: &ConfigChange) {
        self.changes.push(change.clone());
        self.summary.count(&change.action);
    }
}

struct PlanResult {
    plan: ConfigPlan,
    access_policy: Option<Planned<Record>>,
    resource_types: Vec<Planned<Record>>,
    policies: Vec<Planned<Record>>,
    roles: Vec<Planned<Record>>,
    groups: Vec<Planned<Record>>,
    bindings: Vec<Planned<Vec<Record>>>,
    packages: Vec<Planned<Record>>,
    invariants: Vec<Planned<Record>>,
    agreements: Vec<Planned<Record>>,
    /// Teams and departments (org-sync.ts).
    org: OrgPlan,
    /// AI agents, models and budgets (ai-sync.ts).
    ai: AiPlan,
}

fn push<R>(plan: &mut ConfigPlan, list: &mut Vec<Planned<R>>, item: Planned<R>) {
    plan.note(&item.change);
    list.push(item);
}

fn compute_plan(
    ctx: &Arc<ServerContext>,
    tenant_id: &str,
    desired: &TenantConfig,
    state: &CurrentState,
    prune: bool,
) -> IamResult<PlanResult> {
    let mut plan = ConfigPlan {
        tenant_id: tenant_id.to_owned(),
        prune,
        changes: Vec::new(),
        summary: Summary::default(),
    };
    let mut result_access_policy = None;
    let mut resource_types = Vec::new();
    let mut policies = Vec::new();
    let mut roles = Vec::new();
    let mut groups = Vec::new();
    let mut bindings = Vec::new();
    let mut packages = Vec::new();
    let mut invariants = Vec::new();
    let mut agreements = Vec::new();
    let mut org = OrgPlan::default();
    let mut ai = AiPlan {
        agents: Vec::new(),
        models: Vec::new(),
        budgets: Vec::new(),
        extra: Map::new(),
    };

    // Access policy (one record; a present document value replaces it, `{}` clears it)
    if let Some(after) = &desired.access_policy {
        let before = state
            .tenant_record
            .get("accessPolicy")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let fields = diff_fields(as_object(&before), as_object(after));
        let change = if fields.is_empty() {
            ConfigChange::unchanged("accessPolicy", "accessPolicy")
        } else {
            ConfigChange {
                fields: Some(fields),
                before: Some(before),
                after: Some(after.clone()),
                ..ConfigChange::bare("accessPolicy", "accessPolicy", "update")
            }
        };
        plan.note(&change);
        result_access_policy = Some(Planned {
            change,
            desired: Some(as_object(after).clone()),
            record: Some(state.tenant_record.clone()),
        });
    }

    // Resource types
    if let Some(desired_types) = &desired.resource_types {
        let existing: IndexMap<&str, &Record> = state
            .resource_types
            .iter()
            .map(|record| (name_of(record), record))
            .collect();
        for item in desired_types.iter().map(as_object) {
            let name = name_of(item);
            let record = existing.get(name).copied();
            let mut after = Map::new();
            put_opt(&mut after, "description", item.get("description").cloned());
            after.insert(
                "actions".into(),
                strings_value(&sorted(list_member(item, "actions").unwrap_or_default())),
            );
            after.insert(
                "attributes".into(),
                item.get("attributes").cloned().unwrap_or_else(|| json!({})),
            );
            put_opt(&mut after, "parent", item.get("parent").cloned());
            after.insert(
                "relations".into(),
                strings_value(&sorted(list_member(item, "relations").unwrap_or_default())),
            );
            let Some(record) = record else {
                push(
                    &mut plan,
                    &mut resource_types,
                    Planned {
                        change: ConfigChange::create("resourceType", name, after),
                        desired: Some(item.clone()),
                        record: None,
                    },
                );
                continue;
            };
            let mut before = Map::new();
            put_opt(
                &mut before,
                "description",
                record.get("description").cloned(),
            );
            before.insert(
                "actions".into(),
                strings_value(
                    state
                        .resource_type_actions
                        .get(name_of(record))
                        .map(Vec::as_slice)
                        .unwrap_or_default(),
                ),
            );
            put_opt(&mut before, "attributes", record.get("attributes").cloned());
            put_opt(&mut before, "parent", record.get("parent").cloned());
            before.insert(
                "relations".into(),
                strings_value(&sorted(
                    list_member(record, "relations").unwrap_or_default(),
                )),
            );
            let fields = diff_fields(&before, &after);
            if fields.iter().any(|field| field == "parent") {
                return Err(invalid_input(format!(
                    "Resource type {name}: the parent cannot change; delete and recreate the type"
                )));
            }
            push(
                &mut plan,
                &mut resource_types,
                Planned {
                    change: ConfigChange::compared("resourceType", name, fields, before, after),
                    desired: Some(item.clone()),
                    record: Some(record.clone()),
                },
            );
        }
        if prune {
            for record in &state.resource_types {
                if !desired_types
                    .iter()
                    .any(|item| name_of(as_object(item)) == name_of(record))
                {
                    push(
                        &mut plan,
                        &mut resource_types,
                        Planned {
                            change: ConfigChange::delete("resourceType", name_of(record)),
                            desired: None,
                            record: Some(record.clone()),
                        },
                    );
                }
            }
        }
    }

    // Policies
    let mut policy_names_after: IndexSet<String> = IndexSet::new();
    if let Some(desired_policies) = &desired.policies {
        let existing: IndexMap<&str, &Record> = state
            .policies
            .iter()
            .map(|record| (name_of(record), record))
            .collect();
        for item in desired_policies.iter().map(as_object) {
            let name = name_of(item);
            policy_names_after.insert(name.to_owned());
            let record = existing.get(name).copied();
            let mut after = Map::new();
            put_opt(&mut after, "description", item.get("description").cloned());
            put_opt(&mut after, "document", item.get("document").cloned());
            let Some(record) = record else {
                push(
                    &mut plan,
                    &mut policies,
                    Planned {
                        change: ConfigChange::create("policy", name, after),
                        desired: Some(item.clone()),
                        record: None,
                    },
                );
                continue;
            };
            let mut before = Map::new();
            put_opt(
                &mut before,
                "description",
                record.get("description").cloned(),
            );
            put_opt(&mut before, "document", record.get("document").cloned());
            let fields = diff_fields(&before, &after);
            push(
                &mut plan,
                &mut policies,
                Planned {
                    change: ConfigChange::compared("policy", name, fields, before, after),
                    desired: Some(item.clone()),
                    record: Some(record.clone()),
                },
            );
        }
        for record in &state.policies {
            if desired_policies
                .iter()
                .any(|item| name_of(as_object(item)) == name_of(record))
            {
                continue;
            }
            if prune {
                push(
                    &mut plan,
                    &mut policies,
                    Planned {
                        change: ConfigChange::delete("policy", name_of(record)),
                        desired: None,
                        record: Some(record.clone()),
                    },
                );
            } else {
                policy_names_after.insert(name_of(record).to_owned());
            }
        }
    } else {
        for record in &state.policies {
            policy_names_after.insert(name_of(record).to_owned());
        }
    }

    // Roles
    let mut role_names_after: IndexSet<String> = IndexSet::new();
    if let Some(desired_roles) = &desired.roles {
        let existing: IndexMap<&str, &Record> = state
            .roles
            .iter()
            .map(|record| (name_of(record), record))
            .collect();
        let policy_names = state.policy_names();
        let role_names = state.role_names();
        // Every role of the document plus the survivors decides which inheritance targets exist afterwards.
        let mut roles_after_apply: IndexSet<String> = desired_roles
            .iter()
            .map(|item| name_of(as_object(item)).to_owned())
            .collect();
        if !prune {
            for record in &state.roles {
                roles_after_apply.insert(name_of(record).to_owned());
            }
        }
        for item in desired_roles.iter().map(as_object) {
            let name = name_of(item);
            role_names_after.insert(name.to_owned());
            for policy in list_member(item, "policies").unwrap_or_default() {
                if !policy_names_after.contains(&policy) {
                    return Err(invalid_input(format!(
                        "Role {name} attaches unknown policy {policy}"
                    )));
                }
            }
            for inherited in list_member(item, "inherits").unwrap_or_default() {
                if inherited == name {
                    return Err(invalid_input(format!("Role {name} cannot inherit itself")));
                }
                if !roles_after_apply.contains(&inherited) {
                    return Err(invalid_input(format!(
                        "Role {name} inherits unknown role {inherited}"
                    )));
                }
            }
            let record = existing.get(name).copied();
            let mut after = Map::new();
            put_opt(&mut after, "description", item.get("description").cloned());
            after.insert(
                "policies".into(),
                strings_value(&sorted(list_member(item, "policies").unwrap_or_default())),
            );
            put_opt(&mut after, "document", role_document(item)?);
            after.insert(
                "inherits".into(),
                strings_value(&sorted(list_member(item, "inherits").unwrap_or_default())),
            );
            let Some(record) = record else {
                push(
                    &mut plan,
                    &mut roles,
                    Planned {
                        change: ConfigChange::create("role", name, after),
                        desired: Some(item.clone()),
                        record: None,
                    },
                );
                continue;
            };
            let mut before = Map::new();
            put_opt(
                &mut before,
                "description",
                record.get("description").cloned(),
            );
            before.insert(
                "policies".into(),
                strings_value(&sorted(names_of(
                    &list_member(record, "policyIds").unwrap_or_default(),
                    &policy_names,
                ))),
            );
            put_opt(&mut before, "document", record.get("document").cloned());
            before.insert(
                "inherits".into(),
                strings_value(&sorted(names_of(
                    &list_member(record, "inherits").unwrap_or_default(),
                    &role_names,
                ))),
            );
            let fields = diff_fields(&before, &after);
            push(
                &mut plan,
                &mut roles,
                Planned {
                    change: ConfigChange::compared("role", name, fields, before, after),
                    desired: Some(item.clone()),
                    record: Some(record.clone()),
                },
            );
        }
        for record in &state.roles {
            if desired_roles
                .iter()
                .any(|item| name_of(as_object(item)) == name_of(record))
            {
                continue;
            }
            if prune {
                push(
                    &mut plan,
                    &mut roles,
                    Planned {
                        change: ConfigChange::delete("role", name_of(record)),
                        desired: None,
                        record: Some(record.clone()),
                    },
                );
            } else {
                role_names_after.insert(name_of(record).to_owned());
            }
        }
    } else {
        for record in &state.roles {
            role_names_after.insert(name_of(record).to_owned());
        }
    }

    // Groups
    let mut group_names_after: IndexSet<String> = IndexSet::new();
    if let Some(desired_groups) = &desired.groups {
        let existing: IndexMap<&str, &Record> = state
            .groups
            .iter()
            .map(|record| (name_of(record), record))
            .collect();
        for item in desired_groups.iter().map(as_object) {
            let name = name_of(item);
            group_names_after.insert(name.to_owned());
            let wanted = list_member(item, "members");
            for email in wanted.iter().flatten() {
                if !state.identities_by_email.contains_key(email) {
                    return Err(invalid_input(format!(
                        "Group {name}: unknown member {email}"
                    )));
                }
            }
            let record = existing.get(name).copied();
            let mut after = Map::new();
            put_opt(&mut after, "description", item.get("description").cloned());
            if let Some(wanted) = &wanted {
                after.insert("members".into(), strings_value(&sorted(wanted.clone())));
            }
            let Some(record) = record else {
                push(
                    &mut plan,
                    &mut groups,
                    Planned {
                        change: ConfigChange::create("group", name, after),
                        desired: Some(item.clone()),
                        record: None,
                    },
                );
                continue;
            };
            let mut before = Map::new();
            put_opt(
                &mut before,
                "description",
                record.get("description").cloned(),
            );
            if wanted.is_some() {
                before.insert(
                    "members".into(),
                    strings_value(&sorted(group_member_emails(state, id_of(record)))),
                );
            }
            let fields = diff_fields(&before, &after);
            push(
                &mut plan,
                &mut groups,
                Planned {
                    change: ConfigChange::compared("group", name, fields, before, after),
                    desired: Some(item.clone()),
                    record: Some(record.clone()),
                },
            );
        }
        for record in &state.groups {
            if desired_groups
                .iter()
                .any(|item| name_of(as_object(item)) == name_of(record))
            {
                continue;
            }
            if prune {
                push(
                    &mut plan,
                    &mut groups,
                    Planned {
                        change: ConfigChange::delete("group", name_of(record)),
                        desired: None,
                        record: Some(record.clone()),
                    },
                );
            } else {
                group_names_after.insert(name_of(record).to_owned());
            }
        }
    } else {
        for record in &state.groups {
            group_names_after.insert(name_of(record).to_owned());
        }
    }

    // Group bindings
    if let Some(desired_bindings) = &desired.bindings {
        let role_names = state.role_names();
        let group_names = state.group_names();
        let key = |binding: &Record| {
            let subject = str_member(binding, "subjectId").unwrap_or("");
            let role = str_member(binding, "roleId").unwrap_or("");
            format!(
                "{} -> {}",
                group_names.get(subject).map_or(subject, String::as_str),
                role_names.get(role).map_or(role, String::as_str)
            )
        };
        let mut existing: IndexMap<String, Vec<Record>> = IndexMap::new();
        for binding in &state.bindings {
            if group_names.contains_key(str_member(binding, "subjectId").unwrap_or(""))
                && role_names.contains_key(str_member(binding, "roleId").unwrap_or(""))
            {
                existing
                    .entry(key(binding))
                    .or_default()
                    .push(binding.clone());
            }
        }
        let mut wanted: IndexSet<String> = IndexSet::new();
        for item in desired_bindings.iter().map(as_object) {
            let group = str_member(item, "group").unwrap_or("");
            let role = str_member(item, "role").unwrap_or("");
            let name = format!("{group} -> {role}");
            wanted.insert(name.clone());
            if !group_names_after.contains(group) {
                return Err(invalid_input(format!(
                    "Binding {name}: unknown group {group}"
                )));
            }
            if !role_names_after.contains(role) {
                return Err(invalid_input(format!(
                    "Binding {name}: unknown role {role}"
                )));
            }
            let eligible = truthy(item.get("eligible"));
            let mut after = Map::new();
            after.insert(
                "eligible".into(),
                Value::Bool(bool_member(item, "eligible") == Some(true)),
            );
            if eligible {
                put_opt(
                    &mut after,
                    "maxActivationMs",
                    item.get("maxActivationMs").cloned(),
                );
            }
            for flag in ["requireJustification", "requireMfa", "requireApproval"] {
                after.insert(
                    flag.into(),
                    Value::Bool(eligible && bool_member(item, flag) == Some(true)),
                );
            }
            if eligible {
                put_opt(
                    &mut after,
                    "approverGroup",
                    item.get("approverGroup").cloned(),
                );
            }
            after.insert(
                "managerApproval".into(),
                Value::Bool(eligible && bool_member(item, "managerApproval") == Some(true)),
            );
            if let Some(window) = item.get("window") {
                let window = ctx.access_window(Some(window))?;
                after.insert(
                    "window".into(),
                    serde_json::to_value(window).map_err(|_| internal_error())?,
                );
            }
            if let Some(approver) = str_member(&after, "approverGroup")
                && !group_names_after.contains(approver)
            {
                return Err(invalid_input(format!(
                    "Binding {name}: unknown approver group {approver}"
                )));
            }
            let Some(records) = existing.get(&name) else {
                push(
                    &mut plan,
                    &mut bindings,
                    Planned {
                        change: ConfigChange::create("binding", &name, after),
                        desired: Some(item.clone()),
                        record: None,
                    },
                );
                continue;
            };
            let first = &records[0];
            let mut before = Map::new();
            before.insert(
                "eligible".into(),
                Value::Bool(first.get("eligible") == Some(&Value::Bool(true))),
            );
            put_opt(
                &mut before,
                "maxActivationMs",
                first.get("maxActivationMs").cloned(),
            );
            for flag in ["requireJustification", "requireMfa", "requireApproval"] {
                before.insert(
                    flag.into(),
                    Value::Bool(first.get(flag) == Some(&Value::Bool(true))),
                );
            }
            if let Some(approver) = first.get("approverGroupId") {
                let id = crate::js::js_string(Some(approver));
                put_opt(
                    &mut before,
                    "approverGroup",
                    group_names.get(&id).cloned().map(Value::String),
                );
            }
            before.insert(
                "managerApproval".into(),
                Value::Bool(first.get("managerApproval") == Some(&Value::Bool(true))),
            );
            put_opt(&mut before, "window", first.get("window").cloned());
            let fields = diff_fields(&before, &after);
            push(
                &mut plan,
                &mut bindings,
                Planned {
                    change: ConfigChange::compared("binding", &name, fields, before, after),
                    desired: Some(item.clone()),
                    record: Some(records.clone()),
                },
            );
        }
        if prune {
            for (name, records) in &existing {
                if !wanted.contains(name) {
                    push(
                        &mut plan,
                        &mut bindings,
                        Planned {
                            change: ConfigChange::delete("binding", name),
                            desired: None,
                            record: Some(records.clone()),
                        },
                    );
                }
            }
        }
    }

    // Access packages
    if let Some(desired_packages) = &desired.packages {
        let role_names = state.role_names();
        let group_names = state.group_names();
        // Matched regardless of case, like package uniqueness; a case-only difference is a rename.
        let existing: IndexMap<String, &Record> = state
            .packages
            .iter()
            .map(|record| (lower(name_of(record)), record))
            .collect();
        // Rules name teams by slug and departments by name (org-sync.ts).
        let org_after = org_rule_environment_after(desired, &state.org, prune)?;
        for item in desired_packages.iter().map(as_object) {
            let name = name_of(item);
            let package_roles = list_member(item, "roles");
            let package_groups = list_member(item, "groups");
            for role in package_roles.iter().flatten() {
                if !role_names_after.contains(role) {
                    return Err(invalid_input(format!(
                        "Package {name}: unknown role {role}"
                    )));
                }
            }
            for group in package_groups.iter().flatten() {
                if !group_names_after.contains(group) {
                    return Err(invalid_input(format!(
                        "Package {name}: unknown group {group}"
                    )));
                }
            }
            if package_roles.as_ref().is_none_or(Vec::is_empty)
                && package_groups.as_ref().is_none_or(Vec::is_empty)
            {
                return Err(invalid_input(format!(
                    "Package {name} needs at least one role or group"
                )));
            }
            if let Some(approver) = str_member(item, "approverGroup")
                && !group_names_after.contains(approver)
            {
                return Err(invalid_input(format!(
                    "Package {name}: unknown approver group {approver}"
                )));
            }
            // A rule is compared only when the document names one: omission leaves it alone, null removes it.
            let rule: Option<Value> = match item.get("autoAssign") {
                None => None,
                Some(Value::Null) => Some(Value::Null),
                Some(written) => {
                    let mut org_env = org_after.env(Some(written));
                    org_env.insert(
                        "licenses".into(),
                        Value::Array(
                            state
                                .license_keys
                                .iter()
                                .cloned()
                                .map(Value::String)
                                .collect(),
                        ),
                    );
                    let env = RuleEnvironment {
                        identity_attributes: ctx.catalog.identity_attributes.clone(),
                        groups: Some(group_names_after.clone()),
                        packaged_groups: Some(package_groups.iter().flatten().cloned().collect()),
                        org: Some(Value::Object(org_env)),
                        extra: Map::new(),
                    };
                    let parsed = parse_auto_assign(
                        Some(written),
                        &env,
                        Some(&format!("Package {name}: autoAssign")),
                    )?;
                    let parsed = serde_json::to_value(parsed).map_err(|_| internal_error())?;
                    let canonical = org_after.canonical(&parsed)?;
                    if item.contains_key("maxDurationMs") {
                        return Err(invalid_input(format!(
                            "Package {name}: a package with autoAssign cannot have maxDurationMs"
                        )));
                    }
                    Some(canonical)
                }
            };
            let mut normalized = item.clone();
            if let Some(rule) = &rule {
                normalized.insert("autoAssign".into(), rule.clone());
            }
            let record = existing.get(&lower(name)).copied();
            let mut after = Map::new();
            if let Some(rule) = &rule {
                after.insert("autoAssign".into(), rule.clone());
            }
            if let Some(renamed) = record
                && name_of(renamed) != name
            {
                after.insert("name".into(), json!(name));
            }
            put_opt(&mut after, "description", item.get("description").cloned());
            after.insert(
                "roles".into(),
                strings_value(&sorted(package_roles.clone().unwrap_or_default())),
            );
            after.insert(
                "groups".into(),
                strings_value(&sorted(package_groups.clone().unwrap_or_default())),
            );
            put_opt(
                &mut after,
                "maxDurationMs",
                item.get("maxDurationMs").cloned(),
            );
            after.insert(
                "requireJustification".into(),
                Value::Bool(bool_member(item, "requireJustification") == Some(true)),
            );
            after.insert(
                "requestable".into(),
                Value::Bool(bool_member(item, "requestable") == Some(true)),
            );
            put_opt(
                &mut after,
                "approverGroup",
                item.get("approverGroup").cloned(),
            );
            after.insert(
                "managerApproval".into(),
                Value::Bool(bool_member(item, "managerApproval") == Some(true)),
            );
            let Some(record) = record else {
                push(
                    &mut plan,
                    &mut packages,
                    Planned {
                        change: ConfigChange::create("package", name, after),
                        desired: Some(normalized),
                        record: None,
                    },
                );
                continue;
            };
            let mut before = Map::new();
            if rule.is_some() {
                let stored = match record.get("autoAssign").filter(|rule| truthy(Some(rule))) {
                    Some(stored) => rule_names(state, stored, &group_names)?,
                    None => Value::Null,
                };
                before.insert("autoAssign".into(), stored);
            }
            if name_of(record) != name {
                before.insert("name".into(), json!(name_of(record)));
            }
            put_opt(
                &mut before,
                "description",
                record.get("description").cloned(),
            );
            before.insert(
                "roles".into(),
                strings_value(&sorted(names_of(
                    &list_member(record, "roleIds").unwrap_or_default(),
                    &role_names,
                ))),
            );
            before.insert(
                "groups".into(),
                strings_value(&sorted(names_of(
                    &list_member(record, "groupIds").unwrap_or_default(),
                    &group_names,
                ))),
            );
            put_opt(
                &mut before,
                "maxDurationMs",
                record.get("maxDurationMs").cloned(),
            );
            before.insert(
                "requireJustification".into(),
                Value::Bool(record.get("requireJustification") == Some(&Value::Bool(true))),
            );
            before.insert(
                "requestable".into(),
                Value::Bool(record.get("requestable") == Some(&Value::Bool(true))),
            );
            if let Some(approver) = record.get("approverGroupId") {
                let id = crate::js::js_string(Some(approver));
                put_opt(
                    &mut before,
                    "approverGroup",
                    group_names.get(&id).cloned().map(Value::String),
                );
            }
            before.insert(
                "managerApproval".into(),
                Value::Bool(record.get("managerApproval") == Some(&Value::Bool(true))),
            );
            let fields = diff_fields(&before, &after);
            push(
                &mut plan,
                &mut packages,
                Planned {
                    change: ConfigChange::compared("package", name, fields, before, after),
                    desired: Some(normalized),
                    record: Some(record.clone()),
                },
            );
        }
        if prune {
            for record in &state.packages {
                if !desired_packages
                    .iter()
                    .any(|item| lower(name_of(as_object(item))) == lower(name_of(record)))
                {
                    push(
                        &mut plan,
                        &mut packages,
                        Planned {
                            change: ConfigChange::delete("package", name_of(record)),
                            desired: None,
                            record: Some(record.clone()),
                        },
                    );
                }
            }
        }
    }

    // Terms of use (matched by name regardless of case)
    if let Some(desired_agreements) = &desired.agreements {
        let existing: IndexMap<String, &Record> = state
            .agreements
            .iter()
            .map(|record| (lower(name_of(record)), record))
            .collect();
        for item in desired_agreements.iter().map(as_object) {
            let name = name_of(item);
            let record = existing.get(&lower(name)).copied();
            let mut defaulted = item.clone();
            if bool_member(item, "required").is_none() {
                defaulted.insert("required".into(), Value::Bool(true));
            }
            let after = exported_agreement(&defaulted);
            let Some(record) = record else {
                push(
                    &mut plan,
                    &mut agreements,
                    Planned {
                        change: ConfigChange::create("agreement", name, after),
                        desired: Some(item.clone()),
                        record: None,
                    },
                );
                continue;
            };
            let before = exported_agreement(record);
            let fields = diff_fields(&before, &after);
            push(
                &mut plan,
                &mut agreements,
                Planned {
                    change: ConfigChange::compared("agreement", name, fields, before, after),
                    desired: Some(item.clone()),
                    record: Some(record.clone()),
                },
            );
        }
        if prune {
            for record in &state.agreements {
                if !desired_agreements
                    .iter()
                    .any(|item| lower(name_of(as_object(item))) == lower(name_of(record)))
                {
                    push(
                        &mut plan,
                        &mut agreements,
                        Planned {
                            change: ConfigChange::delete("agreement", name_of(record)),
                            desired: None,
                            record: Some(record.clone()),
                        },
                    );
                }
            }
        }
    }

    // Access invariants: their groups must exist after the apply, their people now.
    if let Some(desired_invariants) = &desired.invariants {
        let group_names = state.group_names();
        let existing: IndexMap<String, &Record> = state
            .invariants
            .iter()
            .map(|record| (lower(name_of(record)), record))
            .collect();
        for item in desired_invariants.iter().map(as_object) {
            let name = name_of(item);
            let subject = item.get("subject").cloned().unwrap_or(Value::Null);
            if let Some(group) = subject.get("group") {
                let group = crate::js::js_string(Some(group));
                if !group_names_after.contains(&group) {
                    return Err(invalid_input(format!(
                        "Invariant {name}: unknown group {group}"
                    )));
                }
            }
            if let Some(identity) = subject.get("identity") {
                let identity = crate::js::js_string(Some(identity));
                if !state.identities_by_email.contains_key(&identity) {
                    return Err(invalid_input(format!(
                        "Invariant {name}: unknown person {identity}"
                    )));
                }
            }
            let mut after = Map::new();
            put_opt(&mut after, "description", item.get("description").cloned());
            after.insert("subject".into(), subject);
            put_opt(&mut after, "action", item.get("action").cloned());
            put_opt(&mut after, "resource", item.get("resource").cloned());
            put_opt(&mut after, "expect", item.get("expect").cloned());
            after.insert(
                "mode".into(),
                item.get("mode")
                    .cloned()
                    .unwrap_or_else(|| json!("monitor")),
            );
            after.insert(
                "assumeMfa".into(),
                item.get("assumeMfa").cloned().unwrap_or(Value::Bool(true)),
            );
            let Some(record) = existing.get(&lower(name)).copied() else {
                push(
                    &mut plan,
                    &mut invariants,
                    Planned {
                        change: ConfigChange::create("invariant", name, after),
                        desired: Some(item.clone()),
                        record: None,
                    },
                );
                continue;
            };
            let mut before = exported_invariant(record, &group_names, &state.identity_emails);
            before.shift_remove("name");
            let mut fields = diff_fields(&before, &after);
            if name_of(record) != name {
                fields.push("name".into());
            }
            push(
                &mut plan,
                &mut invariants,
                Planned {
                    change: ConfigChange::compared("invariant", name, fields, before, after),
                    desired: Some(item.clone()),
                    record: Some(record.clone()),
                },
            );
        }
        if prune {
            for record in &state.invariants {
                if !desired_invariants
                    .iter()
                    .any(|item| lower(name_of(as_object(item))) == lower(name_of(record)))
                {
                    push(
                        &mut plan,
                        &mut invariants,
                        Planned {
                            change: ConfigChange::delete("invariant", name_of(record)),
                            desired: None,
                            record: Some(record.clone()),
                        },
                    );
                }
            }
        }
    }

    // Teams and departments (org-sync.ts): their roles must exist after the apply, their people now.
    if desired.teams.is_some() || desired.departments.is_some() {
        let directory = state.directory();
        org = plan_org(
            desired,
            &state.org,
            &OrgPlanEnv {
                directory: &directory,
                identities_by_email: &state.identities_by_email,
                role_names_after: &role_names_after,
                group_names_after: &group_names_after,
                prune,
            },
        )?;
        for item in &org.departments {
            plan.note(&item.change);
        }
        for item in &org.teams {
            plan.note(&item.change);
        }
    }

    // AI agents, models and budgets (ai-sync.ts): sponsors are people now, budget groups exist after the apply.
    if desired.agents.is_some()
        || desired.inference_models.is_some()
        || desired.inference_budgets.is_some()
    {
        let env = json!({
            "identityEmails": state.identity_emails,
            "groupNames": state.group_names(),
            "identitiesByEmail": state.identities_by_email,
            "groupNamesAfter": group_names_after,
            "prune": prune,
        });
        ai = plan_ai(desired, &state.ai, &env)?;
        for item in ai.agents.iter().chain(&ai.models).chain(&ai.budgets) {
            let change: ConfigChange =
                serde_json::from_value(item.get("change").cloned().unwrap_or(Value::Null))
                    .map_err(|_| internal_error())?;
            plan.note(&change);
        }
    }

    let order = |kind: &str| {
        KIND_ORDER
            .iter()
            .position(|item| *item == kind)
            .map_or(-1, |index| index as i64)
    };
    plan.changes.sort_by(|a, b| {
        order(&a.kind)
            .cmp(&order(&b.kind))
            .then_with(|| locale_compare(&a.name, &b.name))
    });
    Ok(PlanResult {
        plan,
        access_policy: result_access_policy,
        resource_types,
        policies,
        roles,
        groups,
        bindings,
        packages,
        invariants,
        agreements,
        org,
        ai,
    })
}

// --- Applying -------------------------------------------------------------------------------------------------------

/// Authorizes the changes of one apply: every change is authorized like the equivalent direct API call; one denial
/// rejects the whole apply (`allow` in TypeScript, shared with org-sync.ts and ai-sync.ts).
pub struct ConfigAllow {
    ctx: Arc<ServerContext>,
    tx: Store,
    principal: AuthenticatedPrincipal,
    tenant_id: String,
}

impl ConfigAllow {
    pub fn new(
        ctx: &Arc<ServerContext>,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
    ) -> Self {
        Self {
            ctx: ctx.clone(),
            tx: tx.clone(),
            principal: principal.clone(),
            tenant_id: tenant_id.to_owned(),
        }
    }

    /// `allow(tx, principal, tenantId, action, resourceId, what)`.
    pub async fn allow(&self, action: &str, resource_id: &str, what: &str) -> IamResult<()> {
        let decision = self
            .ctx
            .decisions()?
            .decide(
                &self.tx,
                &self.principal,
                &AuthorizationRequest {
                    credential: CredentialInput::default(),
                    tenant_id: self.tenant_id.clone(),
                    action: action.to_owned(),
                    resource: ResourceTarget {
                        kind: "iam".into(),
                        id: resource_id.to_owned(),
                    },
                },
                true,
            )
            .await?;
        if !decision.allowed {
            return Err(IamError::with_status(
                "ACCESS_DENIED",
                format!("Not allowed to {what} ({action})"),
                403,
            ));
        }
        Ok(())
    }
}

/// The ID of a name, or `Unknown {kind} {name}`.
fn id_for(ids: &IndexMap<String, String>, name: &str, kind: &str) -> IamResult<String> {
    ids.get(name)
        .cloned()
        .ok_or_else(|| invalid_input(format!("Unknown {kind} {name}")))
}

async fn apply_plan(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant: &Tenant,
    planned: &PlanResult,
    state: &CurrentState,
) -> OperationResult<()> {
    let tenant_id = tenant.id.as_str();
    let allower = ConfigAllow::new(ctx, tx, principal, tenant_id);
    let allow = |action: &'static str, resource_id: String, what: String| {
        let allower = &allower;
        async move { allower.allow(action, &resource_id, &what).await }
    };
    if let Some(item) = planned
        .access_policy
        .as_ref()
        .filter(|item| item.change.action == "update")
    {
        allow(
            "iam:tenants:update",
            tenant_id.to_owned(),
            "change the access policy".into(),
        )
        .await?;
        // As `tenants.setAccessPolicy`: loosening elevation floors needs a fresh sign-in in person (not a stale,
        // impersonated, assumed-role or delegated session), and is audited as such.
        ctx.auth.require_recent(principal)?;
        let mut rest = item.record.clone().unwrap_or_default();
        rest.shift_remove("accessPolicy");
        let policy = item.desired.clone().unwrap_or_default();
        if !policy.is_empty() {
            rest.insert("accessPolicy".into(), Value::Object(policy.clone()));
        }
        tx.put("tenants", &rest).await?;
        let mut metadata = Map::new();
        metadata.insert(
            "accessPolicy".into(),
            if policy.is_empty() {
                Value::Null
            } else {
                Value::Object(policy)
            },
        );
        ctx.events()?
            .audit(
                tx,
                principal,
                "tenant:access-policy",
                tenant_id,
                tenant_id,
                AuditOutcome::Allow,
                false,
                Some(metadata),
            )
            .await?;
    }
    // Resource types first: policies and roles may name their actions.
    for item in &planned.resource_types {
        let change = &item.change;
        match change.action.as_str() {
            "create" => {
                allow(
                    "iam:resource-types:create",
                    tenant_id.to_owned(),
                    format!("create resource type {}", change.name),
                )
                .await?;
                let mut input = Map::new();
                input.insert("tenantId".into(), json!(tenant_id));
                input.extend(item.desired.clone().unwrap_or_default());
                register_resource_type(ctx, tx, &input).await?;
            }
            "update" => {
                allow(
                    "iam:resource-types:update",
                    tenant_id.to_owned(),
                    format!("update resource type {}", change.name),
                )
                .await?;
                let desired = item.desired.clone().unwrap_or_default();
                let mut input = Map::new();
                input.insert("tenantId".into(), json!(tenant_id));
                put_opt(&mut input, "name", desired.get("name").cloned());
                put_opt(
                    &mut input,
                    "description",
                    desired.get("description").cloned(),
                );
                input.insert(
                    "attributes".into(),
                    desired
                        .get("attributes")
                        .cloned()
                        .unwrap_or_else(|| json!({})),
                );
                input.insert(
                    "actions".into(),
                    desired.get("actions").cloned().unwrap_or_else(|| json!([])),
                );
                input.insert(
                    "relations".into(),
                    desired
                        .get("relations")
                        .cloned()
                        .unwrap_or_else(|| json!([])),
                );
                update_resource_type(ctx, tx, &input, true).await?;
            }
            "delete" => {
                allow(
                    "iam:resource-types:delete",
                    tenant_id.to_owned(),
                    format!("delete resource type {}", change.name),
                )
                .await?;
                let record = decode(item.record.clone().unwrap_or_default())?;
                delete_resource_type(ctx, tx, &record).await?;
            }
            _ => {}
        }
    }
    // Policies
    let mut policy_ids: IndexMap<String, String> = state
        .policies
        .iter()
        .map(|policy| (name_of(policy).to_owned(), id_of(policy).to_owned()))
        .collect();
    for item in &planned.policies {
        let change = &item.change;
        let desired = item.desired.clone().unwrap_or_default();
        if change.action == "create" {
            allow(
                "iam:policies:create",
                tenant_id.to_owned(),
                format!("create policy {}", change.name),
            )
            .await?;
            let mut input = Map::new();
            input.insert("tenantId".into(), json!(tenant_id));
            input.extend(desired);
            let created = create_policy(ctx, tx, principal, tenant, &Value::Object(input)).await?;
            policy_ids.insert(created.name.clone(), created.id.clone());
        } else if change.action == "update" {
            let record = item.record.clone().unwrap_or_default();
            allow(
                "iam:policies:update",
                id_of(&record).to_owned(),
                format!("update policy {}", change.name),
            )
            .await?;
            let mut input = Map::new();
            input.insert("tenantId".into(), json!(tenant_id));
            input.insert("policyId".into(), json!(id_of(&record)));
            put_opt(&mut input, "version", record.get("version").cloned());
            put_opt(
                &mut input,
                "description",
                desired.get("description").cloned(),
            );
            put_opt(&mut input, "document", desired.get("document").cloned());
            update_policy(ctx, tx, principal, &Value::Object(input)).await?;
        }
    }
    // Roles (creates and updates), then deletions after bindings are gone.
    let mut role_ids: IndexMap<String, String> = state
        .roles
        .iter()
        .map(|role| (name_of(role).to_owned(), id_of(role).to_owned()))
        .collect();
    for item in &planned.roles {
        let change = &item.change;
        if change.action == "unchanged" || change.action == "delete" {
            continue;
        }
        let desired = item.desired.clone().unwrap_or_default();
        let policies = list_member(&desired, "policies")
            .unwrap_or_default()
            .iter()
            .map(|name| id_for(&policy_ids, name, "policy"))
            .collect::<IamResult<Vec<String>>>()?;
        let document = role_document(&desired)?;
        if change.action == "create" {
            allow(
                "iam:roles:create",
                tenant_id.to_owned(),
                format!("create role {}", change.name),
            )
            .await?;
            let mut input = Map::new();
            input.insert("tenantId".into(), json!(tenant_id));
            put_opt(&mut input, "name", desired.get("name").cloned());
            put_opt(
                &mut input,
                "description",
                desired.get("description").cloned(),
            );
            input.insert("policyIds".into(), strings_value(&policies));
            put_opt(&mut input, "document", document);
            let created = create_role(ctx, tx, principal, tenant, &Value::Object(input)).await?;
            role_ids.insert(created.name.clone(), created.id.clone());
        } else {
            let record = item.record.clone().unwrap_or_default();
            allow(
                "iam:roles:update",
                id_of(&record).to_owned(),
                format!("update role {}", change.name),
            )
            .await?;
            let mut input = Map::new();
            input.insert("tenantId".into(), json!(tenant_id));
            input.insert("roleId".into(), json!(id_of(&record)));
            put_opt(
                &mut input,
                "description",
                desired.get("description").cloned(),
            );
            input.insert("policyIds".into(), strings_value(&policies));
            input.insert("document".into(), document.unwrap_or(Value::Null));
            update_role_record(ctx, tx, principal, &input).await?;
        }
    }
    // Inheritance is applied once every role exists, so a document may introduce parent and child together.
    for item in &planned.roles {
        let change = &item.change;
        if change.action == "delete" {
            continue;
        }
        let desired = item.desired.clone().unwrap_or_default();
        let wanted = list_member(&desired, "inherits").unwrap_or_default();
        let current: Vec<String> = item
            .record
            .as_ref()
            .and_then(|record| list_member(record, "inherits"))
            .unwrap_or_default()
            .iter()
            .filter_map(|role_id| {
                state
                    .roles
                    .iter()
                    .find(|role| id_of(role) == role_id)
                    .map(|role| name_of(role).to_owned())
            })
            .collect();
        if change.action == "unchanged"
            || same(
                Some(&strings_value(&sorted(wanted.clone()))),
                Some(&strings_value(&sorted(current))),
            )
        {
            continue;
        }
        let Some(role_id) = role_ids.get(name_of(&desired)).cloned() else {
            continue;
        };
        allow(
            "iam:roles:update",
            role_id.clone(),
            format!("set inheritance of role {}", change.name),
        )
        .await?;
        let inherits = wanted
            .iter()
            .map(|name| id_for(&role_ids, name, "role"))
            .collect::<IamResult<Vec<String>>>()?;
        let mut input = Map::new();
        input.insert("tenantId".into(), json!(tenant_id));
        input.insert("roleId".into(), json!(role_id));
        input.insert("inherits".into(), strings_value(&inherits));
        update_role_record(ctx, tx, principal, &input).await?;
    }
    // Groups and their members
    let mut group_ids: IndexMap<String, String> = state
        .groups
        .iter()
        .map(|group| (name_of(group).to_owned(), id_of(group).to_owned()))
        .collect();
    // Groups configuration sync manages; others (teams' backing groups) never appear in a document.
    let managed_group_ids: IndexSet<String> = state
        .groups
        .iter()
        .map(|group| id_of(group).to_owned())
        .collect();
    for item in &planned.groups {
        let change = &item.change;
        if change.action == "delete" {
            continue;
        }
        let desired = item.desired.clone().unwrap_or_default();
        let fields: &[String] = change.fields.as_deref().unwrap_or_default();
        let mut group_id = item.record.as_ref().map(|record| id_of(record).to_owned());
        if change.action == "create" {
            allow(
                "iam:groups:create",
                tenant_id.to_owned(),
                format!("create group {}", change.name),
            )
            .await?;
            let mut input = Map::new();
            input.insert("tenantId".into(), json!(tenant_id));
            input.extend(desired.clone());
            let created = create_group(ctx, tx, tenant, &Value::Object(input)).await?;
            group_ids.insert(name_of(&desired).to_owned(), created.id.clone());
            group_id = Some(created.id);
        } else if change.action == "update" && fields.iter().any(|field| field == "description") {
            let record = item.record.clone().unwrap_or_default();
            allow(
                "iam:groups:update",
                group_id.clone().unwrap_or_default(),
                format!("update group {}", change.name),
            )
            .await?;
            let mut next = record;
            if let Some(description) = desired.get("description") {
                next.insert(
                    "description".into(),
                    Value::String(text(Some(description), "description", 512)?),
                );
            }
            tx.put("groups", &next).await?;
        }
        let Some(wanted_emails) = list_member(&desired, "members") else {
            continue;
        };
        if change.action != "create" && !fields.iter().any(|field| field == "members") {
            continue;
        }
        let group_id = group_id.unwrap_or_default();
        allow(
            "iam:groups:update",
            group_id.clone(),
            format!("change members of {}", change.name),
        )
        .await?;
        let mut wanted_ids: IndexSet<String> = IndexSet::new();
        for email in &wanted_emails {
            let identity = state
                .identities_by_email
                .get(email)
                .ok_or_else(internal_error)?;
            wanted_ids.insert(identity.id.clone());
        }
        let current_ids: IndexSet<String> = state
            .members
            .get(&group_id)
            .into_iter()
            .flatten()
            .map(|identity| identity.id.clone())
            .collect();
        // License seats of the group's products are reconciled once, after its members changed.
        reconcile_members(
            ctx,
            tx,
            principal,
            tenant_id,
            &group_id,
            wanted_ids,
            current_ids,
        )
        .await?;
    }
    // Group bindings
    for item in &planned.bindings {
        let change = &item.change;
        if change.action == "unchanged" {
            continue;
        }
        let records = item.record.clone().unwrap_or_default();
        if change.action == "delete" {
            for record in records {
                allow(
                    "iam:bindings:delete",
                    id_of(&record).to_owned(),
                    format!("delete binding {}", change.name),
                )
                .await?;
                let binding: Binding = decode(record)?;
                delete_binding(ctx, tx, principal, &binding).await?;
            }
            continue;
        }
        let desired = item.desired.clone().unwrap_or_default();
        let role_id = role_ids.get(str_member(&desired, "role").unwrap_or(""));
        let group_id = group_ids.get(str_member(&desired, "group").unwrap_or(""));
        let (Some(role_id), Some(group_id)) = (role_id.cloned(), group_id.cloned()) else {
            return Err(invalid_input(format!("Unknown binding {}", change.name)).into());
        };
        allow(
            "iam:bindings:create",
            role_id.clone(),
            format!("bind {}", change.name),
        )
        .await?;
        // What configuration cannot express survives a replacement: an approver group sync does not manage (a team's
        // backing group, left out of exports), and the start and end dates of a temporary or future-dated grant.
        let previous: Vec<Binding> = records
            .iter()
            .cloned()
            .map(decode::<Binding>)
            .collect::<IamResult<_>>()?;
        let kept_approver = previous
            .iter()
            .find_map(|binding| {
                binding
                    .approver_group_id
                    .as_ref()
                    .filter(|id| !id.is_empty() && !managed_group_ids.contains(*id))
            })
            .cloned();
        let now = ctx.now();
        let mut eligibility = Map::new();
        if truthy(desired.get("eligible")) {
            eligibility.insert("eligible".into(), Value::Bool(true));
            for key in [
                "maxActivationMs",
                "requireJustification",
                "requireMfa",
                "requireApproval",
            ] {
                put_opt(&mut eligibility, key, desired.get(key).cloned());
            }
            if let Some(approver) = str_member(&desired, "approverGroup") {
                eligibility.insert(
                    "approverGroupId".into(),
                    group_ids
                        .get(approver)
                        .cloned()
                        .map_or(Value::Null, Value::String),
                );
            } else if let Some(kept) = &kept_approver {
                eligibility.insert("approverGroupId".into(), json!(kept));
            }
            put_opt(
                &mut eligibility,
                "managerApproval",
                desired.get("managerApproval").cloned(),
            );
        } else {
            eligibility.insert("eligible".into(), Value::Bool(false));
        }
        put_opt(&mut eligibility, "window", desired.get("window").cloned());
        if change.action != "create" {
            if !previous.is_empty() && previous.iter().all(|binding| binding.expires_at.is_some()) {
                let latest = previous
                    .iter()
                    .filter_map(|binding| binding.expires_at)
                    .fold(f64::NEG_INFINITY, f64::max);
                eligibility.insert("expiresAt".into(), number(latest));
            }
            let pending: Vec<f64> = previous
                .iter()
                .filter_map(|binding| binding.starts_at.filter(|starts| *starts > now))
                .collect();
            if !previous.is_empty() && pending.len() == previous.len() {
                let earliest = pending.iter().copied().fold(f64::INFINITY, f64::min);
                eligibility.insert("startsAt".into(), number(earliest));
            }
        }
        let mut input = Map::new();
        input.insert("tenantId".into(), json!(tenant_id));
        input.insert("roleId".into(), json!(role_id));
        input.insert("subjectType".into(), json!("group"));
        input.insert("subjectId".into(), json!(group_id));
        input.extend(eligibility);
        if change.action != "create" {
            // Eligibility changes replace the binding so the authority and activations start clean.
            for binding in &previous {
                delete_binding(ctx, tx, principal, binding).await?;
            }
        }
        create_binding(ctx, tx, principal, &Value::Object(input), None).await?;
    }
    // Teams and departments (org-sync.ts) are created and updated before packages, whose rules may name them.
    let org_env = OrgApplyEnv {
        allow: &allower,
        role_ids: &role_ids,
        group_ids: &group_ids,
        identities_by_email: &state.identities_by_email,
    };
    apply_org(
        ctx,
        tx,
        principal,
        tenant,
        &planned.org,
        &org_env,
        Some("upsert"),
    )
    .await?;
    // AI agents, models and budgets (ai-sync.ts), once groups exist; agents before the budgets that name them.
    let ai_env = json!({
        "groupIds": group_ids,
        "identitiesByEmail": state.identities_by_email,
    });
    apply_ai(
        ctx,
        tx,
        principal,
        tenant,
        &planned.ai,
        &ai_env,
        Some("upsert"),
    )
    .await?;
    let org_ids = org_rule_ids(tx, tenant_id).await?;
    // Rules name groups; the tenant stores their IDs (including groups this apply just created).
    let rule_ids = |rule: &Value| -> IamResult<Value> {
        let mapped = map_rule_groups(rule, &|name: &str| {
            group_ids
                .get(name)
                .cloned()
                .unwrap_or_else(|| name.to_owned())
        })?;
        org_ids.apply(&mapped)
    };
    // Access packages: created and updated once their roles and groups exist, deleted before those go.
    for item in &planned.packages {
        let change = &item.change;
        if change.action == "unchanged" {
            continue;
        }
        if change.action == "delete" {
            let record = item.record.clone().unwrap_or_default();
            allow(
                "iam:packages:delete",
                id_of(&record).to_owned(),
                format!("delete package {}", change.name),
            )
            .await?;
            let pkg = decode(record)?;
            delete_package(ctx, tx, &pkg).await?;
            continue;
        }
        let desired = item.desired.clone().unwrap_or_default();
        let roles = list_member(&desired, "roles")
            .unwrap_or_default()
            .iter()
            .map(|name| id_for(&role_ids, name, "role"))
            .collect::<IamResult<Vec<String>>>()?;
        let groups = list_member(&desired, "groups")
            .unwrap_or_default()
            .iter()
            .map(|name| id_for(&group_ids, name, "group"))
            .collect::<IamResult<Vec<String>>>()?;
        let approver_group_id = str_member(&desired, "approverGroup").map(|approver| {
            group_ids
                .get(approver)
                .cloned()
                .map_or(Value::Null, Value::String)
        });
        if change.action == "create" {
            allow(
                "iam:packages:create",
                tenant_id.to_owned(),
                format!("create package {}", change.name),
            )
            .await?;
            let mut input = Map::new();
            input.insert("tenantId".into(), json!(tenant_id));
            put_opt(&mut input, "name", desired.get("name").cloned());
            put_opt(
                &mut input,
                "description",
                desired.get("description").cloned(),
            );
            input.insert("roleIds".into(), strings_value(&roles));
            input.insert("groupIds".into(), strings_value(&groups));
            put_opt(
                &mut input,
                "maxDurationMs",
                desired.get("maxDurationMs").cloned(),
            );
            put_opt(
                &mut input,
                "requireJustification",
                desired.get("requireJustification").cloned(),
            );
            put_opt(
                &mut input,
                "requestable",
                desired.get("requestable").cloned(),
            );
            put_opt(&mut input, "approverGroupId", approver_group_id);
            put_opt(
                &mut input,
                "managerApproval",
                desired.get("managerApproval").cloned(),
            );
            if let Some(rule) = desired.get("autoAssign").filter(|rule| truthy(Some(rule))) {
                input.insert("autoAssign".into(), rule_ids(rule)?);
            }
            create_package(ctx, tx, &Value::Object(input), Some(principal)).await?;
        } else {
            let record = item.record.clone().unwrap_or_default();
            allow(
                "iam:packages:update",
                id_of(&record).to_owned(),
                format!("update package {}", change.name),
            )
            .await?;
            let mut input = Map::new();
            if name_of(&record) != name_of(&desired) {
                put_opt(&mut input, "name", desired.get("name").cloned());
            }
            input.insert(
                "description".into(),
                desired.get("description").cloned().unwrap_or(Value::Null),
            );
            input.insert("roleIds".into(), strings_value(&roles));
            input.insert("groupIds".into(), strings_value(&groups));
            input.insert(
                "maxDurationMs".into(),
                desired.get("maxDurationMs").cloned().unwrap_or(Value::Null),
            );
            input.insert(
                "requireJustification".into(),
                Value::Bool(bool_member(&desired, "requireJustification") == Some(true)),
            );
            input.insert(
                "requestable".into(),
                Value::Bool(bool_member(&desired, "requestable") == Some(true)),
            );
            // An approver group sync does not manage (a team's backing group) is not in the document; keep it.
            let approver = match approver_group_id {
                Some(approver) => approver,
                None => match str_member(&record, "approverGroupId")
                    .filter(|id| !id.is_empty() && !managed_group_ids.contains(*id))
                {
                    Some(kept) => json!(kept),
                    None => Value::Null,
                },
            };
            input.insert("approverGroupId".into(), approver);
            input.insert(
                "managerApproval".into(),
                Value::Bool(bool_member(&desired, "managerApproval") == Some(true)),
            );
            // Passed only when the plan lists the rule, so an unrelated edit never moves its ownership.
            if change
                .fields
                .as_ref()
                .is_some_and(|fields| fields.iter().any(|field| field == "autoAssign"))
            {
                let rule = match desired.get("autoAssign") {
                    Some(Value::Null) => Value::Null,
                    Some(rule) => rule_ids(rule)?,
                    // `ruleIds(undefined)` is a TypeError in TypeScript.
                    None => return Err(internal_error().into()),
                };
                input.insert("autoAssign".into(), rule);
            }
            let existing = decode(record)?;
            update_package(ctx, tx, &existing, &Value::Object(input), Some(principal)).await?;
        }
    }
    // Terms of use: a content change publishes a new version (people accept what they were shown).
    for item in &planned.agreements {
        let change = &item.change;
        if change.action == "unchanged" {
            continue;
        }
        allow(
            "iam:agreements:manage",
            item.record
                .as_ref()
                .map_or_else(|| tenant_id.to_owned(), |record| id_of(record).to_owned()),
            format!("{} agreement {}", change.action, change.name),
        )
        .await?;
        let record: Option<crate::agreements::Agreement> =
            item.record.clone().map(decode).transpose()?;
        if change.action == "delete" {
            if let Some(record) = &record {
                delete_agreement(tx, record).await?;
            }
            continue;
        }
        let desired = item.desired.clone().unwrap_or_default();
        let mut input = Map::new();
        put_opt(&mut input, "name", desired.get("name").cloned());
        put_opt(&mut input, "content", desired.get("content").cloned());
        input.insert(
            "url".into(),
            desired.get("url").cloned().unwrap_or_else(|| json!("")),
        );
        input.insert(
            "required".into(),
            desired
                .get("required")
                .cloned()
                .unwrap_or(Value::Bool(true)),
        );
        input.insert(
            "reacceptAfterDays".into(),
            desired
                .get("reacceptAfterDays")
                .cloned()
                .unwrap_or(Value::Null),
        );
        let new_version = change.action == "update"
            && change
                .fields
                .as_ref()
                .is_some_and(|fields| fields.iter().any(|field| field == "content"));
        save_agreement(
            ctx,
            tx,
            tenant_id,
            &Value::Object(input),
            record.as_ref(),
            Some(new_version),
        )
        .await?;
    }
    // Access invariants, once their groups exist and before any group is deleted.
    for item in &planned.invariants {
        let change = &item.change;
        if change.action == "unchanged" {
            continue;
        }
        allow(
            "iam:invariants:manage",
            item.record
                .as_ref()
                .map_or_else(|| tenant_id.to_owned(), |record| id_of(record).to_owned()),
            format!("{} invariant {}", change.action, change.name),
        )
        .await?;
        if change.action == "delete" {
            let record = item.record.clone().unwrap_or_default();
            tx.delete("accessInvariants", id_of(&record)).await?;
            continue;
        }
        let desired = item.desired.clone().unwrap_or_default();
        let subject = desired.get("subject").cloned().unwrap_or(Value::Null);
        let stored = if let Some(group) = subject.get("group") {
            let mut out = Map::new();
            put_opt(
                &mut out,
                "groupId",
                group_ids
                    .get(&crate::js::js_string(Some(group)))
                    .cloned()
                    .map(Value::String),
            );
            Value::Object(out)
        } else if let Some(identity) = subject.get("identity") {
            let person = state
                .identities_by_email
                .get(&crate::js::js_string(Some(identity)))
                .ok_or_else(internal_error)?;
            json!({ "identityId": person.id })
        } else {
            subject
        };
        let mut input = Map::new();
        put_opt(&mut input, "name", desired.get("name").cloned());
        input.insert(
            "description".into(),
            desired
                .get("description")
                .cloned()
                .unwrap_or_else(|| json!("")),
        );
        input.insert("subject".into(), stored);
        put_opt(&mut input, "action", desired.get("action").cloned());
        put_opt(&mut input, "resource", desired.get("resource").cloned());
        put_opt(&mut input, "expect", desired.get("expect").cloned());
        input.insert(
            "mode".into(),
            desired
                .get("mode")
                .cloned()
                .unwrap_or_else(|| json!("monitor")),
        );
        input.insert(
            "assumeMfa".into(),
            desired
                .get("assumeMfa")
                .cloned()
                .unwrap_or(Value::Bool(true)),
        );
        let previous: Option<crate::invariants::AccessInvariant> =
            item.record.clone().map(decode).transpose()?;
        save_invariant(
            ctx,
            tx,
            tenant_id,
            &Value::Object(input),
            &principal.identity.id,
            previous.as_ref(),
        )
        .await?;
    }
    // Team and department deletions (org-sync.ts), once packages stopped naming them and before any role is deleted.
    apply_org(
        ctx,
        tx,
        principal,
        tenant,
        &planned.org,
        &org_env,
        Some("delete"),
    )
    .await?;
    // AI budget, model and agent deletions (ai-sync.ts), before the groups budgets name are deleted.
    apply_ai(
        ctx,
        tx,
        principal,
        tenant,
        &planned.ai,
        &ai_env,
        Some("delete"),
    )
    .await?;
    // Deletions, dependents first.
    for item in planned
        .groups
        .iter()
        .filter(|item| item.change.action == "delete")
    {
        let record = item.record.clone().unwrap_or_default();
        allow(
            "iam:groups:delete",
            id_of(&record).to_owned(),
            format!("delete group {}", item.change.name),
        )
        .await?;
        let group = decode(record)?;
        delete_group(ctx, tx, principal, &group).await?;
    }
    for item in planned
        .roles
        .iter()
        .filter(|item| item.change.action == "delete")
    {
        let record = item.record.clone().unwrap_or_default();
        allow(
            "iam:roles:delete",
            id_of(&record).to_owned(),
            format!("delete role {}", item.change.name),
        )
        .await?;
        let role = decode(record)?;
        delete_role(ctx, tx, principal, &role).await?;
    }
    for item in planned
        .policies
        .iter()
        .filter(|item| item.change.action == "delete")
    {
        let record = item.record.clone().unwrap_or_default();
        allow(
            "iam:policies:delete",
            id_of(&record).to_owned(),
            format!("delete policy {}", item.change.name),
        )
        .await?;
        let policy = decode(record)?;
        delete_policy(ctx, tx, principal, &policy).await?;
    }
    Ok(())
}

/// Adds the wanted members a group lacks and removes the ones it should not have, in one license batch
/// (`batchGroupLicenses`), so the group's license seats are reconciled once.
async fn reconcile_members(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    group_id: &str,
    wanted_ids: IndexSet<String>,
    current_ids: IndexSet<String>,
) -> OperationResult<()> {
    // The batch callback answers IamError; a refusal (OperationDenied) is kept here so it stays one.
    let refusal: Arc<Mutex<Option<OperationFailure>>> = Arc::default();
    let run: Callback = {
        let ctx = ctx.clone();
        let tx = tx.clone();
        let principal = principal.clone();
        let tenant_id = tenant_id.to_owned();
        let group_id = group_id.to_owned();
        let refusal = refusal.clone();
        Arc::new(move |_| {
            let ctx = ctx.clone();
            let tx = tx.clone();
            let principal = principal.clone();
            let tenant_id = tenant_id.clone();
            let group_id = group_id.clone();
            let wanted_ids = wanted_ids.clone();
            let current_ids = current_ids.clone();
            let refusal = refusal.clone();
            Box::pin(async move {
                for identity_id in &wanted_ids {
                    if current_ids.contains(identity_id) {
                        continue;
                    }
                    let input = json!({
                        "tenantId": tenant_id,
                        "groupId": group_id,
                        "identityId": identity_id,
                    });
                    if let Err(failure) = add_group_member(&ctx, &tx, &principal, &input).await {
                        let error = failure.error.clone();
                        *refusal
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(failure);
                        return Err(error);
                    }
                }
                for identity_id in &current_ids {
                    if wanted_ids.contains(identity_id) {
                        continue;
                    }
                    let input = json!({
                        "tenantId": tenant_id,
                        "groupId": group_id,
                        "identityId": identity_id,
                    });
                    remove_group_member(&ctx, &tx, &principal, &input).await?;
                }
                Ok(Value::Null)
            })
        })
    };
    if let Err(error) = batch_group_licenses(ctx, tx, &run).await {
        if let Some(failure) = refusal
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            return Err(failure);
        }
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_sorts_keys_at_every_level() {
        let a = json!({ "b": 1, "a": { "d": [ { "y": 1, "x": 2 } ], "c": true } });
        let b = json!({ "a": { "c": true, "d": [ { "x": 2, "y": 1 } ] }, "b": 1 });
        assert_eq!(canonical(Some(&a)), canonical(Some(&b)));
        assert_eq!(
            canonical(Some(&a)).unwrap(),
            r#"{"a":{"c":true,"d":[{"x":2,"y":1}]},"b":1}"#
        );
        assert_eq!(canonical(None), None);
        assert!(!same(Some(&Value::Null), None));
    }

    #[test]
    fn diff_fields_compares_like_typescript() {
        let before = json!({ "description": "x", "actions": ["a"], "parent": "p" });
        let after = json!({ "actions": ["a"], "relations": [] });
        assert_eq!(
            diff_fields(as_object(&before), as_object(&after)),
            vec!["description", "parent", "relations"]
        );
    }

    #[test]
    fn permissions_documents_round_trip() {
        let role = json!({ "name": "Editor", "permissions": ["documents:write"] });
        let document = role_document(as_object(&role)).unwrap();
        let exported = exported_document(document.as_ref()).unwrap();
        assert_eq!(
            Value::Object(exported),
            json!({ "permissions": ["documents:write"] })
        );
        let both = json!({ "name": "A", "permissions": ["x"], "document": { "version": 1, "statements": [] } });
        let error = role_document(as_object(&both)).unwrap_err();
        assert_eq!(error.message, "Role A: provide permissions or a document");
        let custom = json!({ "version": 1, "statements": [
            { "sid": "RolePermissions", "effect": "allow", "actions": ["a"], "resources": ["*"], "conditions": {} },
        ] });
        assert!(
            exported_document(Some(&custom))
                .unwrap()
                .contains_key("document")
        );
    }

    #[test]
    fn validation_messages_follow_typescript() {
        let message = |value: Value| validate_tenant_config(Some(&value)).unwrap_err().message;
        assert_eq!(
            message(json!({ "version": 2 })),
            "Configuration version must be 1"
        );
        assert_eq!(
            message(json!({ "version": 1, "roles": [{ "name": "A" }, { "name": "A" }] })),
            "Duplicate role A"
        );
        assert_eq!(
            message(json!({ "version": 1, "roles": {} })),
            "roles must be an array of at most 1000 items"
        );
        assert_eq!(
            message(
                json!({ "version": 1, "bindings": [{ "group": "G", "role": "R", "maxActivationMs": "600000" }] })
            ),
            "Invalid maxActivationMs"
        );
        assert_eq!(
            message(
                json!({ "version": 1, "bindings": [{ "group": "G", "role": "R", "eligible": 1 }] })
            ),
            "eligible must be boolean"
        );
        assert_eq!(
            message(
                json!({ "version": 1, "agreements": [{ "name": "A", "content": "x" }, { "name": "a", "content": "y" }] })
            ),
            "Duplicate agreement a"
        );
        assert_eq!(
            message(
                json!({ "version": 1, "packages": [{ "name": "Vendor" }, { "name": "vendor" }] })
            ),
            "Duplicate package vendor"
        );
        assert_eq!(
            message(
                json!({ "version": 1, "invariants": [{ "name": "I", "subject": { "group": "G", "identity": "x" } }] })
            ),
            "Invariant I: subject must be one of everyone, group, identity, or attribute"
        );
        let config = validate_tenant_config(Some(&json!({
            "version": 1,
            "groups": [{ "name": "G", "members": [" Alice@Acme.test "] }],
            "bindings": [{ "group": "G", "role": "R", "maxActivationMs": null }],
        })))
        .unwrap();
        assert_eq!(
            config.groups.unwrap()[0],
            json!({ "name": "G", "members": ["alice@acme.test"] })
        );
        assert_eq!(
            config.bindings.unwrap()[0],
            json!({ "group": "G", "role": "R" })
        );
    }
}
