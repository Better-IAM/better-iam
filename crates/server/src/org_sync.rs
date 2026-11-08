//! Port of `packages/server/src/org-sync.ts`.
//!
//! Configuration as code for teams and departments: the `teams` and `departments` kinds of a tenant configuration
//! (sync.ts). Teams are matched by slug and departments by name (ignoring case); people are named by email and roles
//! by name, so one document applies to several environments. Temporary team memberships and join requests are
//! runtime state and never synced.

use std::sync::Arc;

use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, Filter, FindOptions, IamError, IamResult, Identity,
    IdentityKind, Record, Tenant, js as core_js,
};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::api::bindings::{create_binding, delete_binding};
use crate::api::departments::department_mutations;
use crate::api::teams::{TeamMutation, Via, team_mutations};
use crate::context::{ServerContext, Store};
use crate::contracts::OperationResult;
use crate::departments::{
    DEPARTMENT_MEMBERS, DEPARTMENTS, Department, DepartmentMember, department_chain_of,
    department_code,
};
use crate::js::internal_error;
use crate::licenses::reconcile_group_licenses;
use crate::models::Binding;
use crate::package_rules::map_rule_values;
use crate::port::decode;
use crate::sync::{ConfigAllow, ConfigChange, TenantConfig, diff_fields};
use crate::teams::{
    TEAM_MEMBERS, TEAMS, Team, TeamMember, live_member, slug_of, sync_team_groups_of,
    team_chain_of, team_slug,
};
use crate::validation::{strings, text};

/// One desired item next to the record it matches, if any.
#[derive(Debug, Clone, PartialEq)]
pub struct OrgPlanned<D, R> {
    pub change: ConfigChange,
    pub desired: Option<D>,
    pub record: Option<R>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct OrgPlan {
    pub teams: Vec<OrgPlanned<TenantConfigTeam, Team>>,
    pub departments: Vec<OrgPlanned<TenantConfigDepartment, Department>>,
}

/// The tenant's teams and departments with the records the configuration compares against.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrgState {
    #[serde(rename = "teams")]
    pub teams: Vec<crate::teams::Team>,
    /// Live direct team memberships.
    #[serde(rename = "teamMembers")]
    pub team_members: Vec<crate::teams::TeamMember>,
    /// Standing bindings (not eligible, windowed, scheduled, temporary, or from a package) by backing group ID.
    #[serde(rename = "teamBindings")]
    pub team_bindings: IndexMap<String, Vec<crate::models::Binding>>,
    #[serde(rename = "departments")]
    pub departments: Vec<crate::departments::Department>,
    #[serde(rename = "placements")]
    pub placements: Vec<crate::departments::DepartmentMember>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A department in a configuration document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TenantConfigDepartment {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "code", default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    /// Name of the parent department.
    #[serde(rename = "parent", default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Email of the department head.
    #[serde(rename = "head", default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    #[serde(
        rename = "costCenter",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cost_center: Option<String>,
    /// People's emails; when present, the department's people are made to match exactly.
    #[serde(rename = "members", default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<String>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A team in a configuration document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TenantConfigTeam {
    #[serde(rename = "name")]
    pub name: String,
    /// The key teams are matched by; derived from the name when left out.
    #[serde(rename = "slug")]
    pub slug: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    /// Slug of the parent team.
    #[serde(rename = "parent", default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Name of the department the team belongs to.
    #[serde(
        rename = "department",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub department: Option<String>,
    /// Default `closed`.
    #[serde(
        rename = "joinPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub join_policy: Option<String>,
    /// Default `maintainers`.
    #[serde(
        rename = "memberManagement",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub member_management: Option<String>,
    /// Maintainer emails. With `members`, the team's permanent direct members are made to match exactly.
    #[serde(
        rename = "maintainers",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub maintainers: Option<Vec<String>>,
    /// Member emails (see `maintainers`).
    #[serde(rename = "members", default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<String>>,
    /// Names of the roles the team holds as standing bindings; when present, made to match exactly.
    #[serde(rename = "roles", default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// Team sync: names of the groups whose members the team keeps (their synced members are runtime state).
    #[serde(
        rename = "syncGroups",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sync_groups: Option<Vec<String>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `lower(value)`: trimmed and lowercased.
fn lower(value: &str) -> String {
    core_js::to_lower(core_js::trim(value))
}

/// `sortedUnique(items)`: distinct items in JavaScript's default sort order.
fn sorted_unique(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let set: IndexSet<String> = items.into_iter().collect();
    let mut list: Vec<String> = set.into_iter().collect();
    list.sort_by(|a, b| core_js::cmp_utf16(a, b));
    list
}

fn strings_value(items: &[String]) -> Value {
    Value::Array(items.iter().cloned().map(Value::String).collect())
}

async fn find(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

fn in_tenant(tenant_id: &str) -> Filter {
    Filter::new().eq("tenantId", tenant_id.to_owned())
}

fn decode_all<T: serde::de::DeserializeOwned>(records: Vec<Record>) -> IamResult<Vec<T>> {
    records.into_iter().map(decode).collect()
}

fn member_str<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Birthright rules (access package `autoAssign`) name teams by slug and departments by name in a configuration
/// document; the tenant stores IDs. `orgRuleNames` maps a stored rule's IDs to names (export and plan comparisons).
pub fn org_rule_names(state: &OrgState, rule: &Value) -> IamResult<Value> {
    let slugs: IndexMap<&str, &str> = state
        .teams
        .iter()
        .map(|team| (team.id.as_str(), team.slug.as_str()))
        .collect();
    let names: IndexMap<&str, &str> = state
        .departments
        .iter()
        .map(|department| (department.id.as_str(), department.name.as_str()))
        .collect();
    let teams = map_rule_values(rule, "identity.teams", &|team_id: &str| {
        slugs.get(team_id).copied().unwrap_or(team_id).to_owned()
    })?;
    map_rule_values(&teams, "identity.departments", &|department_id: &str| {
        names
            .get(department_id)
            .copied()
            .unwrap_or(department_id)
            .to_owned()
    })
}

/// What `orgRuleEnvironmentAfter` answers: the team slugs and department names (by lowercase name) that exist after
/// an apply.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OrgRuleEnvironment {
    pub teams: IndexSet<String>,
    /// Lowercase name to the spelling in the document (or the tenant).
    pub departments: IndexMap<String, String>,
}

impl OrgRuleEnvironment {
    /// `env`: the `org` member of a rule environment (`RuleEnvironment.org`) for validating `rule`. Teams are matched
    /// exactly; departments regardless of case (`{ has: (name) => departments.has(lower(name)) }`), so every string
    /// of the rule that names a department in another case is valid too.
    pub fn env(&self, rule: Option<&Value>) -> Map<String, Value> {
        let mut departments: IndexSet<String> = self.departments.values().cloned().collect();
        fn collect(value: &Value, out: &mut Vec<String>) {
            match value {
                Value::String(text) => out.push(text.clone()),
                Value::Array(items) => items.iter().for_each(|item| collect(item, out)),
                Value::Object(map) => map.values().for_each(|item| collect(item, out)),
                _ => {}
            }
        }
        let mut found = Vec::new();
        if let Some(rule) = rule {
            collect(rule, &mut found);
        }
        for text in found {
            if self.departments.contains_key(&lower(&text)) {
                departments.insert(text);
            }
        }
        let mut env = Map::new();
        env.insert(
            "teams".into(),
            Value::Array(self.teams.iter().cloned().map(Value::String).collect()),
        );
        env.insert(
            "departments".into(),
            Value::Array(departments.into_iter().map(Value::String).collect()),
        );
        env
    }

    /// `canonical(rule)`: the rule's department names in their spelling in the document (or the tenant), so a
    /// case-only difference never shows as a change.
    pub fn canonical(&self, rule: &Value) -> IamResult<Value> {
        map_rule_values(rule, "identity.departments", &|name: &str| {
            self.departments
                .get(&lower(name))
                .cloned()
                .unwrap_or_else(|| name.to_owned())
        })
    }
}

/// The teams and departments that exist after an apply, for validating package rules at plan time: team slugs, and
/// department names ignoring case. `canonical` rewrites a rule's department names to their spelling in the document
/// (or the tenant), so a case-only difference never shows as a change.
pub fn org_rule_environment_after(
    desired: &TenantConfig,
    state: &OrgState,
    prune: bool,
) -> IamResult<OrgRuleEnvironment> {
    let mut teams: IndexSet<String> = state
        .teams
        .iter()
        .filter(|record| match &desired.teams {
            None => true,
            Some(items) => !prune || items.iter().any(|item| item.slug == record.slug),
        })
        .map(|record| record.slug.clone())
        .collect();
    for team in desired.teams.iter().flatten() {
        teams.insert(team.slug.clone());
    }
    let mut departments: IndexMap<String, String> = IndexMap::new();
    for record in &state.departments {
        let kept = match &desired.departments {
            None => true,
            Some(items) => {
                !prune
                    || items
                        .iter()
                        .any(|item| lower(&item.name) == lower(&record.name))
            }
        };
        if kept {
            departments.insert(lower(&record.name), record.name.clone());
        }
    }
    for department in desired.departments.iter().flatten() {
        departments.insert(lower(&department.name), department.name.clone());
    }
    Ok(OrgRuleEnvironment { teams, departments })
}

/// What `orgRuleIds` answers: maps a document rule's team slugs and department names to the tenant's IDs.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OrgRuleIds {
    teams: IndexMap<String, String>,
    departments: IndexMap<String, String>,
}

impl OrgRuleIds {
    /// The rule with its team slugs and department names replaced by IDs (unknown values are kept).
    pub fn apply(&self, rule: &Value) -> IamResult<Value> {
        let teams = map_rule_values(rule, "identity.teams", &|slug: &str| {
            self.teams
                .get(slug)
                .cloned()
                .unwrap_or_else(|| slug.to_owned())
        })?;
        map_rule_values(&teams, "identity.departments", &|name: &str| {
            self.departments
                .get(&lower(name))
                .cloned()
                .unwrap_or_else(|| name.to_owned())
        })
    }
}

/// Maps a document rule's team slugs and department names to the tenant's IDs (after teams and departments exist).
pub async fn org_rule_ids(tx: &Store, tenant_id: &str) -> IamResult<OrgRuleIds> {
    let teams = find(tx, TEAMS, in_tenant(tenant_id))
        .await?
        .into_iter()
        .map(|team| {
            (
                member_str(&team, "slug").to_owned(),
                member_str(&team, "id").to_owned(),
            )
        })
        .collect();
    let departments = find(tx, DEPARTMENTS, in_tenant(tenant_id))
        .await?
        .into_iter()
        .map(|department| {
            (
                lower(member_str(&department, "name")),
                member_str(&department, "id").to_owned(),
            )
        })
        .collect();
    Ok(OrgRuleIds { teams, departments })
}

fn optional_text(item: &Map<String, Value>, key: &str, max: usize) -> IamResult<Option<String>> {
    match item.get(key) {
        None => Ok(None),
        Some(value) => Ok(Some(
            core_js::trim(&text(Some(value), key, max)?).to_owned(),
        )),
    }
}

fn emails(item: &Map<String, Value>, key: &str) -> IamResult<Option<Vec<String>>> {
    match item.get(key) {
        None => Ok(None),
        Some(value) => Ok(Some(sorted_unique(
            strings(Some(value), key)?.iter().map(|email| lower(email)),
        ))),
    }
}

/// Validates the `teams` list of a configuration document.
pub fn parse_teams_config(
    items: &[Map<String, Value>],
) -> IamResult<Vec<crate::org_sync::TenantConfigTeam>> {
    let mut teams = Vec::with_capacity(items.len());
    for item in items {
        let name = core_js::trim(&text(item.get("name"), "team name", 100)?).to_owned();
        let slug = match item.get("slug") {
            None => slug_of(&name),
            Some(value) => Some(team_slug(Some(value))?),
        };
        let Some(slug) = slug.filter(|slug| !slug.is_empty()) else {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!("Team {name}: choose a slug"),
            ));
        };
        let join_policy = item.get("joinPolicy");
        if let Some(policy) = join_policy
            && policy.as_str() != Some("closed")
            && policy.as_str() != Some("request")
        {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!("Team {slug}: joinPolicy must be closed or request"),
            ));
        }
        let management = item.get("memberManagement");
        if let Some(management) = management
            && management.as_str() != Some("maintainers")
            && management.as_str() != Some("admins")
        {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!("Team {slug}: memberManagement must be maintainers or admins"),
            ));
        }
        let maintainers = emails(item, "maintainers")?;
        let members = emails(item, "members")?;
        let both: Vec<&String> = maintainers
            .iter()
            .flatten()
            .filter(|email| members.as_ref().is_some_and(|list| list.contains(email)))
            .collect();
        if let Some(first) = both.first() {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!("Team {slug}: {first} is listed as both maintainer and member"),
            ));
        }
        let description = optional_text(item, "description", 512)?;
        let parent = match item.get("parent") {
            None => None,
            Some(value) => Some(team_slug(Some(value))?),
        };
        let department = optional_text(item, "department", 100)?;
        let roles = match item.get("roles") {
            None => None,
            Some(value) => Some(sorted_unique(strings(Some(value), "roles")?)),
        };
        let sync_groups = match item.get("syncGroups") {
            None => None,
            Some(value) => Some(sorted_unique(strings(Some(value), "syncGroups")?)),
        };
        teams.push(TenantConfigTeam {
            name,
            slug,
            description,
            parent,
            department,
            join_policy: join_policy.and_then(Value::as_str).map(str::to_owned),
            member_management: management.and_then(Value::as_str).map(str::to_owned),
            maintainers,
            members,
            roles,
            sync_groups,
            extra: Map::new(),
        });
    }
    let mut seen: IndexSet<&str> = IndexSet::new();
    for team in &teams {
        if !seen.insert(team.slug.as_str()) {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!("Duplicate team {}", team.slug),
            ));
        }
    }
    Ok(teams)
}

/// Validates the `departments` list of a configuration document.
pub fn parse_departments_config(
    items: &[Map<String, Value>],
) -> IamResult<Vec<crate::org_sync::TenantConfigDepartment>> {
    let mut departments = Vec::with_capacity(items.len());
    for item in items {
        let name = core_js::trim(&text(item.get("name"), "department name", 100)?).to_owned();
        let code = match item.get("code") {
            None => None,
            Some(value) => Some(department_code(Some(value))?),
        };
        let description = optional_text(item, "description", 512)?;
        let parent = optional_text(item, "parent", 100)?;
        let head = match item.get("head") {
            None => None,
            Some(value) => Some(lower(&text(Some(value), "head", 254)?)),
        };
        let cost_center = optional_text(item, "costCenter", 64)?;
        let members = emails(item, "members")?;
        departments.push(TenantConfigDepartment {
            name,
            code,
            description,
            parent,
            head,
            cost_center,
            members,
            extra: Map::new(),
        });
    }
    let mut names: IndexSet<String> = IndexSet::new();
    let mut codes: IndexSet<String> = IndexSet::new();
    for department in &departments {
        if !names.insert(lower(&department.name)) {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!("Duplicate department {}", department.name),
            ));
        }
        if let Some(code) = &department.code
            && !codes.insert(lower(code))
        {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!("Duplicate department code {code}"),
            ));
        }
    }
    Ok(departments)
}

/// Whether a binding is a standing one: not eligible, windowed, scheduled, temporary, or from a package.
fn standing(binding: &Binding) -> bool {
    binding.eligible != Some(true)
        && binding.window.is_none()
        && binding.starts_at.is_none()
        && binding.expires_at.is_none()
        && binding.package_assignment_id.is_none()
}

/// Whether a raw binding record is a standing one (members as JavaScript reads them).
fn standing_record(binding: &Record) -> bool {
    !crate::js::truthy(binding.get("eligible"))
        && binding.get("window").is_none()
        && binding.get("startsAt").is_none()
        && binding.get("expiresAt").is_none()
        && binding.get("packageAssignmentId").is_none()
}

/// Reads what the `teams` and `departments` kinds compare against.
pub async fn read_org_state(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
) -> IamResult<crate::org_sync::OrgState> {
    let now = ctx.now();
    let mut teams: Vec<Team> = decode_all(find(tx, TEAMS, in_tenant(tenant_id)).await?)?;
    teams.sort_by(|a, b| core_js::cmp_utf16(&a.slug, &b.slug));
    let team_members: Vec<TeamMember> =
        decode_all::<TeamMember>(find(tx, TEAM_MEMBERS, in_tenant(tenant_id)).await?)?
            .into_iter()
            .filter(|member| live_member(member, now))
            .collect();
    let mut team_bindings: IndexMap<String, Vec<Binding>> = IndexMap::new();
    for team in &teams {
        let bindings: Vec<Binding> = decode_all::<Binding>(
            find(
                tx,
                "bindings",
                in_tenant(tenant_id)
                    .eq("subjectType", "group")
                    .eq("subjectId", team.group_id.clone()),
            )
            .await?,
        )?
        .into_iter()
        .filter(standing)
        .collect();
        team_bindings.insert(team.group_id.clone(), bindings);
    }
    let mut departments: Vec<Department> =
        decode_all(find(tx, DEPARTMENTS, in_tenant(tenant_id)).await?)?;
    departments.sort_by(|a, b| crate::metrics::locale_compare(&a.name, &b.name));
    let placements: Vec<DepartmentMember> =
        decode_all(find(tx, DEPARTMENT_MEMBERS, in_tenant(tenant_id)).await?)?;
    Ok(OrgState {
        teams,
        team_members,
        team_bindings,
        departments,
        placements,
        extra: Map::new(),
    })
}

/// What the org kinds read names from: people, roles and ordinary groups by ID.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Directory {
    /// Identity ID to lowercase email, for people who are not deleted.
    pub identity_emails: IndexMap<String, String>,
    /// Role ID to name.
    pub role_names: IndexMap<String, String>,
    /// Group ID to name, for ordinary (not team-backed) groups.
    pub group_names: IndexMap<String, String>,
}

fn is_role(role: &Value, name: &str) -> bool {
    role.as_str() == Some(name)
}

fn exported_team(team: &Team, state: &OrgState, directory: &Directory) -> Map<String, Value> {
    // Temporary and synced memberships are runtime state.
    let permanent: Vec<&TeamMember> = state
        .team_members
        .iter()
        .filter(|member| {
            member.team_id == team.id
                && member.expires_at.is_none()
                && member.source.as_deref() != Some("sync")
        })
        .collect();
    let emails_of = |role: &str| {
        sorted_unique(
            permanent
                .iter()
                .filter(|member| is_role(&member.role, role))
                .filter_map(|member| directory.identity_emails.get(&member.identity_id).cloned()),
        )
    };
    let parent = team
        .parent_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .and_then(|id| state.teams.iter().find(|item| item.id == id));
    let department = team
        .department_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .and_then(|id| state.departments.iter().find(|item| item.id == id));
    let mut out = Map::new();
    if let Some(description) = &team.description {
        out.insert("description".into(), Value::String(description.clone()));
    }
    if let Some(parent) = parent {
        out.insert("parent".into(), Value::String(parent.slug.clone()));
    }
    if let Some(department) = department {
        out.insert("department".into(), Value::String(department.name.clone()));
    }
    out.insert("joinPolicy".into(), team.join_policy.clone());
    out.insert("memberManagement".into(), team.member_management.clone());
    out.insert(
        "maintainers".into(),
        strings_value(&emails_of("maintainer")),
    );
    out.insert("members".into(), strings_value(&emails_of("member")));
    out.insert(
        "roles".into(),
        strings_value(&sorted_unique(
            state
                .team_bindings
                .get(&team.group_id)
                .into_iter()
                .flatten()
                .filter_map(|binding| directory.role_names.get(&binding.role_id).cloned()),
        )),
    );
    if let Some(groups) = team.sync_group_ids.as_ref().filter(|ids| !ids.is_empty()) {
        out.insert(
            "syncGroups".into(),
            strings_value(&sorted_unique(
                groups
                    .iter()
                    .filter_map(|group_id| directory.group_names.get(group_id).cloned()),
            )),
        );
    }
    out
}

fn exported_department(
    department: &Department,
    state: &OrgState,
    directory: &Directory,
) -> Map<String, Value> {
    let parent = department
        .parent_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .and_then(|id| state.departments.iter().find(|item| item.id == id));
    let head = department
        .head_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .and_then(|id| directory.identity_emails.get(id));
    let mut out = Map::new();
    if let Some(code) = &department.code {
        out.insert("code".into(), Value::String(code.clone()));
    }
    if let Some(description) = &department.description {
        out.insert("description".into(), Value::String(description.clone()));
    }
    if let Some(parent) = parent {
        out.insert("parent".into(), Value::String(parent.name.clone()));
    }
    if let Some(head) = head.filter(|head| !head.is_empty()) {
        out.insert("head".into(), Value::String(head.clone()));
    }
    if let Some(cost_center) = &department.cost_center {
        out.insert("costCenter".into(), Value::String(cost_center.clone()));
    }
    out.insert(
        "members".into(),
        strings_value(&sorted_unique(
            state
                .placements
                .iter()
                .filter(|placement| placement.department_id == department.id)
                .filter_map(|placement| {
                    directory
                        .identity_emails
                        .get(&placement.identity_id)
                        .filter(|email| !email.is_empty())
                        .cloned()
                }),
        )),
    );
    out
}

/// The tenant's teams and departments in document form; each kind appears only when the tenant has some.
pub fn export_org(
    state: &crate::org_sync::OrgState,
    directory: &Directory,
) -> IamResult<Map<String, Value>> {
    let mut out = Map::new();
    if !state.departments.is_empty() {
        let departments = state
            .departments
            .iter()
            .map(|department| {
                let mut item = Map::new();
                item.insert("name".into(), Value::String(department.name.clone()));
                item.extend(exported_department(department, state, directory));
                Value::Object(item)
            })
            .collect();
        out.insert("departments".into(), Value::Array(departments));
    }
    if !state.teams.is_empty() {
        let teams = state
            .teams
            .iter()
            .map(|team| {
                let mut item = Map::new();
                item.insert("name".into(), Value::String(team.name.clone()));
                item.insert("slug".into(), Value::String(team.slug.clone()));
                item.extend(exported_team(team, state, directory));
                Value::Object(item)
            })
            .collect();
        out.insert("teams".into(), Value::Array(teams));
    }
    Ok(out)
}

/// Normalizes a desired team to its exported form (defaults filled, membership lists only when given).
fn desired_team_form(team: &TenantConfigTeam) -> Map<String, Value> {
    let manages_members = team.maintainers.is_some() || team.members.is_some();
    let mut out = Map::new();
    if let Some(description) = &team.description {
        out.insert("description".into(), Value::String(description.clone()));
    }
    if let Some(parent) = &team.parent {
        out.insert("parent".into(), Value::String(parent.clone()));
    }
    if let Some(department) = &team.department {
        out.insert("department".into(), Value::String(department.clone()));
    }
    out.insert(
        "joinPolicy".into(),
        Value::String(team.join_policy.clone().unwrap_or_else(|| "closed".into())),
    );
    out.insert(
        "memberManagement".into(),
        Value::String(
            team.member_management
                .clone()
                .unwrap_or_else(|| "maintainers".into()),
        ),
    );
    if manages_members {
        out.insert(
            "maintainers".into(),
            strings_value(team.maintainers.as_deref().unwrap_or_default()),
        );
        out.insert(
            "members".into(),
            strings_value(team.members.as_deref().unwrap_or_default()),
        );
    }
    if let Some(roles) = &team.roles {
        out.insert("roles".into(), strings_value(roles));
    }
    if let Some(groups) = team
        .sync_groups
        .as_ref()
        .filter(|groups| !groups.is_empty())
    {
        out.insert("syncGroups".into(), strings_value(groups));
    }
    out
}

fn desired_department_form(department: &TenantConfigDepartment) -> Map<String, Value> {
    let mut out = Map::new();
    if let Some(code) = &department.code {
        out.insert("code".into(), Value::String(code.clone()));
    }
    if let Some(description) = &department.description {
        out.insert("description".into(), Value::String(description.clone()));
    }
    if let Some(parent) = &department.parent {
        out.insert("parent".into(), Value::String(parent.clone()));
    }
    if let Some(head) = &department.head {
        out.insert("head".into(), Value::String(head.clone()));
    }
    if let Some(cost_center) = &department.cost_center {
        out.insert("costCenter".into(), Value::String(cost_center.clone()));
    }
    if let Some(members) = &department.members {
        out.insert("members".into(), strings_value(members));
    }
    out
}

/// What `planOrg` checks references against.
#[derive(Debug, Clone, Copy)]
pub struct OrgPlanEnv<'a> {
    pub directory: &'a Directory,
    pub identities_by_email: &'a IndexMap<String, Identity>,
    pub role_names_after: &'a IndexSet<String>,
    /// Names of the ordinary groups that exist after the apply.
    pub group_names_after: &'a IndexSet<String>,
    pub prune: bool,
}

/// Follows `parents` from every key, refusing a cycle with `message(key)`.
fn assert_acyclic(
    keys: &IndexSet<String>,
    parents: &IndexMap<String, Option<String>>,
    message: impl Fn(&str) -> String,
) -> IamResult<()> {
    for key in keys {
        let mut seen: IndexSet<String> = IndexSet::new();
        let mut cursor = Some(key.clone());
        while let Some(current) = cursor.filter(|current| !current.is_empty()) {
            if seen.contains(&current) {
                return Err(IamError::new("INVALID_INPUT", message(key)));
            }
            cursor = parents.get(&current).cloned().flatten();
            seen.insert(current);
        }
    }
    Ok(())
}

/// Plans the `teams` and `departments` kinds. References are checked against what will exist after the apply:
/// people now (by email), roles (`roleNamesAfter`), parents and departments from the document or the tenant. Kinds
/// absent from the document are left alone; with `prune`, listed kinds lose the items the document omits.
pub fn plan_org(
    desired: &TenantConfig,
    state: &crate::org_sync::OrgState,
    env: &OrgPlanEnv<'_>,
) -> IamResult<crate::org_sync::OrgPlan> {
    let mut plan = OrgPlan::default();
    let person = |email: &str, place: &str| -> IamResult<()> {
        match env.identities_by_email.get(email) {
            Some(identity) if identity.kind == IdentityKind::User => Ok(()),
            _ => Err(IamError::new(
                "INVALID_INPUT",
                format!("{place}: unknown person {email}"),
            )),
        }
    };

    // Departments, by name regardless of case.
    let mut department_names_after: IndexSet<String> = state
        .departments
        .iter()
        .filter(|record| match &desired.departments {
            None => true,
            Some(items) => {
                !env.prune
                    || items
                        .iter()
                        .any(|item| lower(&item.name) == lower(&record.name))
            }
        })
        .map(|record| lower(&record.name))
        .collect();
    for department in desired.departments.iter().flatten() {
        department_names_after.insert(lower(&department.name));
    }
    if let Some(desired_departments) = &desired.departments {
        let existing: IndexMap<String, &Department> = state
            .departments
            .iter()
            .map(|record| (lower(&record.name), record))
            .collect();
        let mut parents: IndexMap<String, Option<String>> = IndexMap::new();
        for record in &state.departments {
            let parent = record
                .parent_id
                .as_deref()
                .filter(|id| !id.is_empty())
                .and_then(|id| state.departments.iter().find(|item| item.id == id))
                .map(|item| core_js::to_lower(&item.name));
            parents.insert(lower(&record.name), parent);
        }
        for department in desired_departments {
            let place = format!("Department {}", department.name);
            if let Some(parent) = &department.parent
                && !department_names_after.contains(&lower(parent))
            {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    format!("{place}: unknown parent {parent}"),
                ));
            }
            if let Some(head) = &department.head {
                person(head, &place)?;
            }
            for email in department.members.iter().flatten() {
                person(email, &place)?;
            }
            parents.insert(
                lower(&department.name),
                department.parent.as_deref().map(lower),
            );
        }
        assert_acyclic(&department_names_after, &parents, |name| {
            format!("Departments {name}: the parents form a cycle")
        })?;
        for department in desired_departments {
            let record = existing.get(&lower(&department.name)).copied();
            let after = desired_department_form(department);
            let Some(record) = record else {
                plan.departments.push(OrgPlanned {
                    change: ConfigChange::create("department", &department.name, after),
                    desired: Some(department.clone()),
                    record: None,
                });
                continue;
            };
            let mut before = exported_department(record, state, env.directory);
            if department.members.is_none() {
                before.shift_remove("members");
            }
            let mut fields = diff_fields(&before, &after);
            if record.name != department.name {
                fields.push("name".into());
            }
            plan.departments.push(OrgPlanned {
                change: ConfigChange::compared(
                    "department",
                    &department.name,
                    fields,
                    before,
                    after,
                ),
                desired: Some(department.clone()),
                record: Some(record.clone()),
            });
        }
        if env.prune {
            for record in &state.departments {
                if !desired_departments
                    .iter()
                    .any(|item| lower(&item.name) == lower(&record.name))
                {
                    plan.departments.push(OrgPlanned {
                        change: ConfigChange::delete("department", &record.name),
                        desired: None,
                        record: Some(record.clone()),
                    });
                }
            }
        }
    }

    // Teams, by slug.
    if let Some(desired_teams) = &desired.teams {
        let existing: IndexMap<&str, &Team> = state
            .teams
            .iter()
            .map(|record| (record.slug.as_str(), record))
            .collect();
        let mut slugs_after: IndexSet<String> = state
            .teams
            .iter()
            .filter(|record| {
                !env.prune || desired_teams.iter().any(|item| item.slug == record.slug)
            })
            .map(|record| record.slug.clone())
            .collect();
        for team in desired_teams {
            slugs_after.insert(team.slug.clone());
        }
        let mut parents: IndexMap<String, Option<String>> = IndexMap::new();
        for record in &state.teams {
            let parent = record
                .parent_id
                .as_deref()
                .filter(|id| !id.is_empty())
                .and_then(|id| state.teams.iter().find(|item| item.id == id))
                .map(|item| item.slug.clone());
            parents.insert(record.slug.clone(), parent);
        }
        for team in desired_teams {
            let place = format!("Team {}", team.slug);
            if let Some(parent) = &team.parent
                && !slugs_after.contains(parent)
            {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    format!("{place}: unknown parent {parent}"),
                ));
            }
            if let Some(department) = &team.department
                && !department_names_after.contains(&lower(department))
            {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    format!("{place}: unknown department {department}"),
                ));
            }
            for email in team
                .maintainers
                .iter()
                .flatten()
                .chain(team.members.iter().flatten())
            {
                person(email, &place)?;
            }
            for role in team.roles.iter().flatten() {
                if !env.role_names_after.contains(role) {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        format!("{place}: unknown role {role}"),
                    ));
                }
            }
            for group in team.sync_groups.iter().flatten() {
                if !env.group_names_after.contains(group) {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        format!("{place}: unknown sync group {group}"),
                    ));
                }
            }
            parents.insert(team.slug.clone(), team.parent.clone());
        }
        assert_acyclic(&slugs_after, &parents, |slug| {
            format!("Team {slug}: the parents form a cycle")
        })?;
        for team in desired_teams {
            let record = existing.get(team.slug.as_str()).copied();
            let after = desired_team_form(team);
            let Some(record) = record else {
                plan.teams.push(OrgPlanned {
                    change: ConfigChange::create("team", &team.slug, after),
                    desired: Some(team.clone()),
                    record: None,
                });
                continue;
            };
            let mut before = exported_team(record, state, env.directory);
            if !after.contains_key("maintainers") {
                before.shift_remove("maintainers");
                before.shift_remove("members");
            }
            if team.roles.is_none() {
                before.shift_remove("roles");
            }
            if team.sync_groups.is_none() {
                before.shift_remove("syncGroups");
            }
            let mut fields = diff_fields(&before, &after);
            if record.name != team.name {
                fields.push("name".into());
            }
            plan.teams.push(OrgPlanned {
                change: ConfigChange::compared("team", &team.slug, fields, before, after),
                desired: Some(team.clone()),
                record: Some(record.clone()),
            });
        }
        if env.prune {
            for record in &state.teams {
                if !desired_teams.iter().any(|item| item.slug == record.slug) {
                    plan.teams.push(OrgPlanned {
                        change: ConfigChange::delete("team", &record.slug),
                        desired: None,
                        record: Some(record.clone()),
                    });
                }
            }
        }
    }
    Ok(plan)
}

/// Depth of an item in a name→parent map (0 for a top-level item).
fn depth_of(parents: &IndexMap<String, Option<String>>, key: &str) -> usize {
    let mut depth = 0;
    let mut cursor = parents.get(key).cloned().flatten();
    while let Some(current) = cursor.filter(|current| !current.is_empty()) {
        if depth >= 50 {
            break;
        }
        depth += 1;
        cursor = parents.get(&current).cloned().flatten();
    }
    depth
}

/// What `applyOrg` works with besides the plan.
pub struct OrgApplyEnv<'a> {
    /// Authorizes one change like the equivalent API call.
    pub allow: &'a ConfigAllow,
    pub role_ids: &'a IndexMap<String, String>,
    /// Ordinary group name to ID, including groups this apply created.
    pub group_ids: &'a IndexMap<String, String>,
    pub identities_by_email: &'a IndexMap<String, Identity>,
}

/// Applies a planned `teams`/`departments` change set inside the configuration apply transaction, after roles exist
/// and before any role is deleted. Every change is authorized like the equivalent API call (`allow`). `phase`
/// `upsert` creates and updates (before access packages, whose rules may name new teams and departments), `delete`
/// removes (after packages stop naming them); both by default.
pub async fn apply_org(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    tenant: &better_iam_core::Tenant,
    plan: &crate::org_sync::OrgPlan,
    env: &OrgApplyEnv<'_>,
    phase: Option<&str>,
) -> OperationResult<()> {
    let phase = phase.unwrap_or("all");
    let apply = OrgApply {
        ctx,
        tx,
        principal,
        tenant,
        plan,
        env,
    };
    if phase != "delete" {
        apply.upsert().await?;
    }
    if phase != "upsert" {
        apply.delete().await?;
    }
    Ok(())
}

struct OrgApply<'a> {
    ctx: &'a Arc<ServerContext>,
    tx: &'a Store,
    principal: &'a AuthenticatedPrincipal,
    tenant: &'a Tenant,
    plan: &'a OrgPlan,
    env: &'a OrgApplyEnv<'a>,
}

impl OrgApply<'_> {
    fn person_id(&self, email: &str) -> IamResult<String> {
        // Planning checked every person; a missing one is a TypeError in TypeScript.
        self.env
            .identities_by_email
            .get(email)
            .map(|identity| identity.id.clone())
            .ok_or_else(internal_error)
    }

    fn group_ids_of(&self, names: &[String]) -> IamResult<Vec<String>> {
        names
            .iter()
            .map(|name| {
                self.env
                    .group_ids
                    .get(name)
                    .cloned()
                    .ok_or_else(|| IamError::new("INVALID_INPUT", format!("Unknown group {name}")))
            })
            .collect()
    }

    async fn upsert(&self) -> OperationResult<()> {
        let (ctx, tx, principal, tenant) = (self.ctx, self.tx, self.principal, self.tenant);
        let tenant_id = tenant.id.as_str();
        let departments = department_mutations(ctx)?;
        let teams = team_mutations(ctx)?;

        // Departments: creates top-down, then updates, then people.
        let mut department_ids: IndexMap<String, String> =
            find(tx, DEPARTMENTS, in_tenant(tenant_id))
                .await?
                .into_iter()
                .map(|record| {
                    (
                        lower(member_str(&record, "name")),
                        member_str(&record, "id").to_owned(),
                    )
                })
                .collect();
        let department_parents: IndexMap<String, Option<String>> = self
            .plan
            .departments
            .iter()
            .filter_map(|item| item.desired.as_ref())
            .map(|desired| {
                (
                    lower(&desired.name),
                    desired.parent.as_deref().map(core_js::to_lower),
                )
            })
            .collect();
        let mut creates: Vec<&TenantConfigDepartment> = self
            .plan
            .departments
            .iter()
            .filter(|item| item.change.action == "create")
            .filter_map(|item| item.desired.as_ref())
            .collect();
        creates.sort_by_key(|desired| depth_of(&department_parents, &lower(&desired.name)));
        for desired in creates {
            self.env
                .allow
                .allow(
                    "iam:departments:manage",
                    tenant_id,
                    &format!("create department {}", desired.name),
                )
                .await?;
            let mut input = Map::new();
            input.insert("tenantId".into(), json!(tenant_id));
            input.insert("name".into(), json!(desired.name));
            if let Some(code) = &desired.code {
                input.insert("code".into(), json!(code));
            }
            if let Some(description) = &desired.description {
                input.insert("description".into(), json!(description));
            }
            if let Some(parent) = &desired.parent
                && let Some(parent_id) = department_ids.get(&lower(parent))
            {
                input.insert("parentId".into(), json!(parent_id));
            }
            if let Some(head) = &desired.head {
                input.insert("headId".into(), json!(self.person_id(head)?));
            }
            if let Some(cost_center) = &desired.cost_center {
                input.insert("costCenter".into(), json!(cost_center));
            }
            let created = departments
                .create_department(tx, principal, tenant, &input)
                .await?;
            department_ids.insert(lower(&created.name), created.id.clone());
        }
        for item in &self.plan.departments {
            if item.change.action != "update" {
                continue;
            }
            let (Some(desired), Some(record)) = (&item.desired, &item.record) else {
                continue;
            };
            let settings = item
                .change
                .fields
                .iter()
                .flatten()
                .filter(|field| *field != "members")
                .count();
            if settings == 0 {
                continue;
            }
            self.env
                .allow
                .allow(
                    "iam:departments:manage",
                    &record.id,
                    &format!("update department {}", item.change.name),
                )
                .await?;
            let or_null = |value: &Option<String>| value.clone().map_or(Value::Null, Value::String);
            let mut input = Map::new();
            input.insert("tenantId".into(), json!(tenant_id));
            input.insert("departmentId".into(), json!(record.id));
            input.insert("name".into(), json!(desired.name));
            input.insert("code".into(), or_null(&desired.code));
            input.insert("description".into(), or_null(&desired.description));
            match &desired.parent {
                Some(parent) => {
                    if let Some(parent_id) = department_ids.get(&lower(parent)) {
                        input.insert("parentId".into(), json!(parent_id));
                    }
                }
                None => {
                    input.insert("parentId".into(), Value::Null);
                }
            }
            let head = match &desired.head {
                Some(head) => Value::String(self.person_id(head)?),
                None => Value::Null,
            };
            input.insert("headId".into(), head);
            input.insert("costCenter".into(), or_null(&desired.cost_center));
            departments
                .update_department(tx, principal, tenant, &input)
                .await?;
        }
        for item in &self.plan.departments {
            let change = &item.change;
            if change.action == "delete" || change.action == "unchanged" {
                continue;
            }
            let Some(desired) = &item.desired else {
                continue;
            };
            let Some(members) = &desired.members else {
                continue;
            };
            if change.action == "update"
                && !change
                    .fields
                    .as_ref()
                    .is_some_and(|fields| fields.iter().any(|field| field == "members"))
            {
                continue;
            }
            let department_id = department_ids
                .get(&lower(&desired.name))
                .cloned()
                .ok_or_else(internal_error)?;
            let department: Department = match tx.get(DEPARTMENTS, &department_id).await? {
                Some(record) => decode(record)?,
                None => return Err(internal_error().into()),
            };
            self.env
                .allow
                .allow(
                    "iam:departments:manage",
                    &department_id,
                    &format!("place people in {}", change.name),
                )
                .await?;
            let mut wanted: IndexSet<String> = IndexSet::new();
            for email in members {
                wanted.insert(self.person_id(email)?);
            }
            for placement in find(
                tx,
                DEPARTMENT_MEMBERS,
                in_tenant(tenant_id).eq("departmentId", department_id.clone()),
            )
            .await?
            {
                let identity_id = member_str(&placement, "identityId").to_owned();
                if !wanted.contains(&identity_id) {
                    tx.delete(DEPARTMENT_MEMBERS, member_str(&placement, "id"))
                        .await?;
                    let mut metadata = Map::new();
                    metadata.insert(
                        "identityId".into(),
                        placement.get("identityId").cloned().unwrap_or(Value::Null),
                    );
                    ctx.events()?
                        .audit(
                            tx,
                            principal,
                            "department:unassign",
                            tenant_id,
                            &department_id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                }
            }
            for identity_id in &wanted {
                let identity = departments
                    .department_person(tx, tenant_id, Some(&Value::String(identity_id.clone())))
                    .await?;
                let current = find(
                    tx,
                    DEPARTMENT_MEMBERS,
                    in_tenant(tenant_id).eq("uniqueKey", format!("identity:{identity_id}")),
                )
                .await?
                .into_iter()
                .next();
                let current_department = current
                    .as_ref()
                    .and_then(|record| record.get("departmentId"))
                    .and_then(Value::as_str);
                if current_department != Some(department_id.as_str()) {
                    departments
                        .place(tx, principal, &department, &identity.id, None)
                        .await?;
                }
            }
        }

        // Teams: creates top-down, then settings, then members and roles.
        let mut team_ids: IndexMap<String, String> = find(tx, TEAMS, in_tenant(tenant_id))
            .await?
            .into_iter()
            .map(|record| {
                (
                    member_str(&record, "slug").to_owned(),
                    member_str(&record, "id").to_owned(),
                )
            })
            .collect();
        let team_parents: IndexMap<String, Option<String>> = self
            .plan
            .teams
            .iter()
            .filter_map(|item| item.desired.as_ref())
            .map(|desired| (desired.slug.clone(), desired.parent.clone()))
            .collect();
        let mut team_creates: Vec<&TenantConfigTeam> = self
            .plan
            .teams
            .iter()
            .filter(|item| item.change.action == "create")
            .filter_map(|item| item.desired.as_ref())
            .collect();
        team_creates.sort_by_key(|desired| depth_of(&team_parents, &desired.slug));
        for desired in team_creates {
            self.env
                .allow
                .allow(
                    "iam:teams:create",
                    tenant_id,
                    &format!("create team {}", desired.slug),
                )
                .await?;
            let mut input = Map::new();
            input.insert("tenantId".into(), json!(tenant_id));
            input.insert("name".into(), json!(desired.name));
            input.insert("slug".into(), json!(desired.slug));
            if let Some(description) = &desired.description {
                input.insert("description".into(), json!(description));
            }
            if let Some(parent) = &desired.parent
                && let Some(parent_id) = team_ids.get(parent)
            {
                input.insert("parentId".into(), json!(parent_id));
            }
            if let Some(department) = &desired.department
                && let Some(department_id) = department_ids.get(&lower(department))
            {
                input.insert("departmentId".into(), json!(department_id));
            }
            if let Some(policy) = &desired.join_policy {
                input.insert("joinPolicy".into(), json!(policy));
            }
            if let Some(management) = &desired.member_management {
                input.insert("memberManagement".into(), json!(management));
            }
            if let Some(groups) = desired
                .sync_groups
                .as_ref()
                .filter(|groups| !groups.is_empty())
            {
                input.insert("syncGroupIds".into(), json!(self.group_ids_of(groups)?));
            }
            let created = teams.create_team(tx, principal, tenant, &input).await?;
            team_ids.insert(
                member_str(&created, "slug").to_owned(),
                member_str(&created, "id").to_owned(),
            );
        }
        let current = |slug: String| {
            let team_ids = &team_ids;
            async move {
                let team_id = team_ids.get(&slug).ok_or_else(internal_error)?;
                tx.get(TEAMS, team_id).await?.ok_or_else(internal_error)
            }
        };
        for item in &self.plan.teams {
            if item.change.action != "update" {
                continue;
            }
            let Some(desired) = &item.desired else {
                continue;
            };
            let fields: &[String] = item.change.fields.as_deref().unwrap_or_default();
            let has = |field: &str| fields.iter().any(|item| item == field);
            let team = current(desired.slug.clone()).await?;
            let team_id = member_str(&team, "id").to_owned();
            let mut update = Map::new();
            update.insert("tenantId".into(), json!(tenant_id));
            update.insert("teamId".into(), json!(team_id));
            if has("name") {
                update.insert("name".into(), json!(desired.name));
            }
            if has("description") {
                update.insert(
                    "description".into(),
                    desired
                        .description
                        .clone()
                        .map_or(Value::Null, Value::String),
                );
            }
            if has("parent") {
                let parent = match &desired.parent {
                    Some(parent) => team_ids
                        .get(parent)
                        .cloned()
                        .map_or(Value::Null, Value::String),
                    None => Value::Null,
                };
                update.insert("parentId".into(), parent);
            }
            if has("department") {
                let department = match &desired.department {
                    Some(department) => department_ids
                        .get(&lower(department))
                        .cloned()
                        .map_or(Value::Null, Value::String),
                    None => Value::Null,
                };
                update.insert("departmentId".into(), department);
            }
            if has("joinPolicy") {
                update.insert(
                    "joinPolicy".into(),
                    json!(desired.join_policy.as_deref().unwrap_or("closed")),
                );
            }
            if has("memberManagement") {
                update.insert(
                    "memberManagement".into(),
                    json!(
                        desired
                            .member_management
                            .as_deref()
                            .unwrap_or("maintainers")
                    ),
                );
            }
            if has("syncGroups") {
                let groups = match desired
                    .sync_groups
                    .as_ref()
                    .filter(|groups| !groups.is_empty())
                {
                    Some(groups) => json!(self.group_ids_of(groups)?),
                    None => Value::Null,
                };
                update.insert("syncGroupIds".into(), groups);
            }
            if update.len() == 2 {
                continue;
            }
            self.env
                .allow
                .allow(
                    "iam:teams:update",
                    &team_id,
                    &format!("update team {}", item.change.name),
                )
                .await?;
            teams.update_team(tx, principal, &team, &update).await?;
        }
        for item in &self.plan.teams {
            let change = &item.change;
            if change.action == "delete" || change.action == "unchanged" {
                continue;
            }
            let Some(desired) = &item.desired else {
                continue;
            };
            let fields: &[String] = change.fields.as_deref().unwrap_or_default();
            let has = |field: &str| fields.iter().any(|item| item == field);
            let team = current(desired.slug.clone()).await?;
            let team_id = member_str(&team, "id").to_owned();
            let team_slug_text = member_str(&team, "slug").to_owned();
            let group_id = member_str(&team, "groupId").to_owned();
            let membership = (desired.maintainers.is_some() || desired.members.is_some())
                && (change.action == "create" || has("maintainers") || has("members"));
            if membership {
                self.env
                    .allow
                    .allow(
                        "iam:teams:update",
                        &team_id,
                        &format!("set the members of team {}", change.name),
                    )
                    .await?;
                let all_records: IndexMap<String, Record> = find(tx, TEAMS, in_tenant(tenant_id))
                    .await?
                    .into_iter()
                    .map(|record| (member_str(&record, "id").to_owned(), record))
                    .collect();
                let all: IndexMap<String, Team> = all_records
                    .iter()
                    .map(|(id, record)| Ok((id.clone(), decode::<Team>(record.clone())?)))
                    .collect::<IamResult<_>>()?;
                let chain: Vec<Team> = team_chain_of(&all, &team_id);
                let chain_records: Vec<Record> = chain
                    .iter()
                    .filter_map(|item| all_records.get(&item.id).cloned())
                    .collect();
                teams
                    .assert_authority_over(tx, principal, tenant_id, &chain_records)
                    .await?;
                let mut wanted: IndexMap<String, &str> = IndexMap::new();
                for email in desired.members.iter().flatten() {
                    wanted.insert(self.person_id(email)?, "member");
                }
                for email in desired.maintainers.iter().flatten() {
                    wanted.insert(self.person_id(email)?, "maintainer");
                }
                let now = ctx.now();
                let live: Vec<Record> = find(
                    tx,
                    TEAM_MEMBERS,
                    in_tenant(tenant_id).eq("teamId", team_id.clone()),
                )
                .await?
                .into_iter()
                .filter(|member| {
                    member
                        .get("expiresAt")
                        .and_then(core_js::as_number)
                        .is_none_or(|expires| expires > now)
                })
                .collect();
                let mutation = TeamMutation {
                    tx: tx.clone(),
                    principal: principal.clone(),
                    tenant: tenant.clone(),
                    team: team.clone(),
                    via: Via::Permission,
                };
                for member in &live {
                    let identity_id = member_str(member, "identityId").to_owned();
                    let temporary = member.get("expiresAt").is_some();
                    let synced = member.get("source").and_then(Value::as_str) == Some("sync");
                    let Some(role) = wanted.get(&identity_id).copied() else {
                        // Temporary and synced memberships are runtime state: only permanent manual ones are removed.
                        if !temporary && !synced {
                            teams
                                .remove_member(
                                    tx,
                                    principal,
                                    &team,
                                    member,
                                    "team:member:remove",
                                    None,
                                )
                                .await?;
                        }
                        continue;
                    };
                    wanted.shift_remove(&identity_id);
                    let member_role = member.get("role").and_then(Value::as_str);
                    // The document lists manual memberships: a temporary or synced member it names becomes a permanent
                    // manual one.
                    if member_role == Some(role) && !temporary && !synced {
                        continue;
                    }
                    // Keeping someone for good, or appointing a maintainer, of a licensed team needs
                    // iam:licenses:assign.
                    if temporary
                        || synced
                        || (role == "maintainer" && member_role != Some("maintainer"))
                    {
                        teams
                            .assert_may_claim_team_licenses(
                                tx,
                                principal,
                                tenant_id,
                                &chain_records,
                            )
                            .await?;
                    }
                    let mut rest = member.clone();
                    rest.shift_remove("expiresAt");
                    rest.shift_remove("source");
                    rest.insert("role".into(), json!(role));
                    tx.put(TEAM_MEMBERS, &rest).await?;
                    sync_team_groups_of(tx, tenant_id, std::slice::from_ref(&team_id), now).await?;
                    let mut metadata = Map::new();
                    metadata.insert("team".into(), json!(team_slug_text));
                    metadata.insert("identityId".into(), json!(identity_id));
                    metadata.insert("role".into(), json!(role));
                    metadata.insert("source".into(), json!("config"));
                    ctx.events()?
                        .audit(
                            tx,
                            principal,
                            "team:member:update",
                            tenant_id,
                            &team_id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                }
                for (identity_id, role) in &wanted {
                    let mut input = Map::new();
                    input.insert("identityId".into(), json!(identity_id));
                    input.insert("role".into(), json!(role));
                    teams.put_member(&mutation, &input, "config").await?;
                }
                // License seats of the team's chain follow its members in this transaction, as with groups
                // (licenses.ts).
                let group_ids: Vec<String> =
                    chain.iter().map(|item| item.group_id.clone()).collect();
                reconcile_group_licenses(
                    ctx,
                    tx,
                    tenant_id,
                    &json!(group_ids),
                    &crate::conformance::principal_json(principal),
                )
                .await?;
            }
            let roles = desired.roles.is_some() && (change.action == "create" || has("roles"));
            if roles {
                let mut wanted_roles: IndexSet<String> = IndexSet::new();
                for name in desired.roles.iter().flatten() {
                    let role_id = self.env.role_ids.get(name).ok_or_else(|| {
                        IamError::new(
                            "INVALID_INPUT",
                            format!("Team {}: unknown role {name}", change.name),
                        )
                    })?;
                    wanted_roles.insert(role_id.clone());
                }
                let held: Vec<Record> = find(
                    tx,
                    "bindings",
                    in_tenant(tenant_id)
                        .eq("subjectType", "group")
                        .eq("subjectId", group_id.clone()),
                )
                .await?
                .into_iter()
                .filter(standing_record)
                .collect();
                for binding in held {
                    if wanted_roles.shift_remove(member_str(&binding, "roleId")) {
                        continue;
                    }
                    self.env
                        .allow
                        .allow(
                            "iam:bindings:delete",
                            member_str(&binding, "id"),
                            &format!("remove a role from team {}", change.name),
                        )
                        .await?;
                    let binding: Binding = decode(binding)?;
                    delete_binding(ctx, tx, principal, &binding).await?;
                }
                for role_id in wanted_roles {
                    self.env
                        .allow
                        .allow(
                            "iam:bindings:create",
                            &role_id,
                            &format!("give team {} a role", change.name),
                        )
                        .await?;
                    create_binding(
                        ctx,
                        tx,
                        principal,
                        &json!({
                            "tenantId": tenant_id,
                            "roleId": role_id,
                            "subjectType": "group",
                            "subjectId": group_id,
                        }),
                        None,
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    async fn delete(&self) -> OperationResult<()> {
        let (ctx, tx, principal, tenant) = (self.ctx, self.tx, self.principal, self.tenant);
        let tenant_id = tenant.id.as_str();
        let departments = department_mutations(ctx)?;
        let teams = team_mutations(ctx)?;
        // Deletions, lowest teams and departments first.
        let all_teams: IndexMap<String, Team> =
            decode_all::<Team>(find(tx, TEAMS, in_tenant(tenant_id)).await?)?
                .into_iter()
                .map(|team| (team.id.clone(), team))
                .collect();
        let mut team_deletes: Vec<&OrgPlanned<TenantConfigTeam, Team>> = self
            .plan
            .teams
            .iter()
            .filter(|item| item.change.action == "delete")
            .collect();
        let team_depth = |item: &OrgPlanned<TenantConfigTeam, Team>| {
            item.record
                .as_ref()
                .map_or(0, |record| team_chain_of(&all_teams, &record.id).len())
        };
        team_deletes.sort_by_key(|item| std::cmp::Reverse(team_depth(item)));
        for item in team_deletes {
            let Some(record) = &item.record else {
                continue;
            };
            self.env
                .allow
                .allow(
                    "iam:teams:delete",
                    &record.id,
                    &format!("delete team {}", item.change.name),
                )
                .await?;
            if let Some(team) = tx.get(TEAMS, &record.id).await? {
                teams.delete_team(tx, principal, &team).await?;
            }
        }
        let all_departments: IndexMap<String, Department> =
            decode_all::<Department>(find(tx, DEPARTMENTS, in_tenant(tenant_id)).await?)?
                .into_iter()
                .map(|department| (department.id.clone(), department))
                .collect();
        let mut department_deletes: Vec<&OrgPlanned<TenantConfigDepartment, Department>> = self
            .plan
            .departments
            .iter()
            .filter(|item| item.change.action == "delete")
            .collect();
        let department_depth = |item: &OrgPlanned<TenantConfigDepartment, Department>| {
            item.record.as_ref().map_or(0, |record| {
                department_chain_of(&all_departments, &record.id).len()
            })
        };
        department_deletes.sort_by_key(|item| std::cmp::Reverse(department_depth(item)));
        for item in department_deletes {
            let Some(record) = &item.record else {
                continue;
            };
            self.env
                .allow
                .allow(
                    "iam:departments:manage",
                    &record.id,
                    &format!("delete department {}", item.change.name),
                )
                .await?;
            let mut input = Map::new();
            input.insert("tenantId".into(), json!(tenant_id));
            input.insert("departmentId".into(), json!(record.id));
            departments
                .delete_department(tx, principal, tenant, &input)
                .await?;
        }
        Ok(())
    }
}
