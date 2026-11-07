//! Port of `packages/server/src/org-rules.ts`.
//!
//! The org structure as birthright rules (access package rules) see it: `identity.teams`, the teams a person belongs
//! to with every team above them, and `identity.departments`, their department with every department above it (the
//! same sets as the policy keys `principal.teams` and `principal.departments`). A synced team membership counts only
//! while the person is in one of the team's source groups by a membership no access package created, so a rule never
//! feeds on what a package granted (identity.groups follows the same rule).

use better_iam_core::{Filter, FindOptions, IamResult, Record};
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::context::Store;
use crate::departments::{DEPARTMENT_MEMBERS, DEPARTMENTS, Department, department_chain_of};
use crate::licenses::{TenantLicenseFacts, license_rule_keys, load_license_facts};
use crate::package_rules::{RuleOrgFacts, rule_values};
use crate::port::decode;
use crate::teams::{TEAM_MEMBERS, TEAMS, Team, TeamMember, live_member, team_chain_of};

async fn find(reader: &Store, collection: &str, tenant_id: &str) -> IamResult<Vec<Record>> {
    reader
        .find(
            collection,
            &Filter::new().eq("tenantId", tenant_id),
            &FindOptions::default(),
        )
        .await
}

/// A tenant's teams and departments, read once, answering identity.teams / identity.departments per person.
#[derive(Clone)]
pub struct TenantOrgFacts {
    pub team_ids: IndexSet<String>,
    pub department_ids: IndexSet<String>,
    /// The keys of the license products visible to the tenant: the valid identity.licenses values (licenses.ts).
    pub license_keys: IndexSet<String>,
    teams: IndexMap<String, Team>,
    members: IndexMap<String, Vec<TeamMember>>,
    departments: IndexMap<String, Department>,
    placements: IndexMap<String, String>,
    licenses: TenantLicenseFacts,
}

impl TenantOrgFacts {
    /// What a rule sees for one person, given their live memberships no access package created.
    pub fn of(&self, identity_id: &str, direct_group_ids: &[String]) -> RuleOrgFacts {
        let direct: IndexSet<String> = direct_group_ids.iter().cloned().collect();
        let mut team_ids: IndexSet<String> = IndexSet::new();
        for member in self
            .members
            .get(identity_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let Some(team) = self.teams.get(&member.team_id) else {
                continue;
            };
            if member.source.as_deref() == Some("sync")
                && !team
                    .sync_group_ids
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .any(|group_id| direct.contains(group_id))
            {
                continue;
            }
            for link in team_chain_of(&self.teams, &team.id) {
                team_ids.insert(link.id);
            }
        }
        let department_id = self.placements.get(identity_id);
        // Seats held through groups count through the same memberships, a counted team's backing group included.
        let mut license_groups = direct.clone();
        for team_id in &team_ids {
            if let Some(group_id) = self
                .teams
                .get(team_id)
                .map(|team| team.group_id.clone())
                .filter(|group_id| !group_id.is_empty())
            {
                license_groups.insert(group_id);
            }
        }
        let mut teams: Vec<String> = team_ids.into_iter().collect();
        crate::js::sort_strings(&mut teams);
        let departments = match department_id.filter(|id| !id.is_empty()) {
            Some(department_id) => {
                let mut ids: Vec<String> = department_chain_of(&self.departments, department_id)
                    .into_iter()
                    .map(|department| department.id)
                    .collect();
                crate::js::sort_strings(&mut ids);
                ids
            }
            None => Vec::new(),
        };
        RuleOrgFacts {
            teams,
            departments,
            licenses: Some((self.licenses.of)(identity_id, &license_groups)),
            extra: Map::new(),
        }
    }
}

pub async fn load_org_facts(
    reader: &Store,
    tenant_id: &str,
    now: f64,
) -> IamResult<crate::org_rules::TenantOrgFacts> {
    let mut teams: IndexMap<String, Team> = IndexMap::new();
    for record in find(reader, TEAMS, tenant_id).await? {
        let team: Team = decode(record)?;
        teams.insert(team.id.clone(), team);
    }
    let mut members: IndexMap<String, Vec<TeamMember>> = IndexMap::new();
    for record in find(reader, TEAM_MEMBERS, tenant_id).await? {
        let member: TeamMember = decode(record)?;
        if live_member(&member, now) {
            members
                .entry(member.identity_id.clone())
                .or_default()
                .push(member);
        }
    }
    let mut departments: IndexMap<String, Department> = IndexMap::new();
    for record in find(reader, DEPARTMENTS, tenant_id).await? {
        let department: Department = decode(record)?;
        departments.insert(department.id.clone(), department);
    }
    let mut placements: IndexMap<String, String> = IndexMap::new();
    for record in find(reader, DEPARTMENT_MEMBERS, tenant_id).await? {
        let placement: crate::departments::DepartmentMember = decode(record)?;
        placements.insert(placement.identity_id, placement.department_id);
    }
    let licenses = load_license_facts(reader, tenant_id).await?;
    Ok(TenantOrgFacts {
        team_ids: teams.keys().cloned().collect(),
        department_ids: departments.keys().cloned().collect(),
        license_keys: licenses.keys.clone(),
        teams,
        members,
        departments,
        placements,
        licenses,
    })
}

/// The valid identity.teams and identity.departments values of a tenant: its team and department IDs; and the valid
/// identity.licenses values, the keys of the license products it can use. Answers `{ teams, departments, licenses }`
/// (sets as arrays, the shape of `RuleEnvironment.org`).
pub async fn org_rule_environment(reader: &Store, tenant_id: &str) -> IamResult<Value> {
    let teams: IndexSet<String> = find(reader, TEAMS, tenant_id)
        .await?
        .iter()
        .map(|team| better_iam_core::record_id(team).to_owned())
        .collect();
    let departments: IndexSet<String> = find(reader, DEPARTMENTS, tenant_id)
        .await?
        .iter()
        .map(|department| better_iam_core::record_id(department).to_owned())
        .collect();
    let licenses = license_rule_keys(reader, tenant_id).await?;
    Ok(json!({
        "teams": teams.into_iter().collect::<Vec<_>>(),
        "departments": departments.into_iter().collect::<Vec<_>>(),
        "licenses": licenses.into_iter().collect::<Vec<_>>(),
    }))
}

/// The names of the tenant's access packages whose rule names one of `ids` under `key` (a team's backing group
/// under identity.groups counts for the team). Teams and departments stay while a rule names them, like groups.
pub async fn packages_naming(
    reader: &Store,
    tenant_id: &str,
    key: &str,
    ids: &[String],
    backing_group_ids: Option<&[String]>,
) -> IamResult<Vec<String>> {
    let wanted: IndexSet<&String> = ids.iter().collect();
    let groups: IndexSet<&String> = backing_group_ids.unwrap_or(&[]).iter().collect();
    let mut names: Vec<String> = Vec::new();
    for pkg in find(reader, "accessPackages", tenant_id).await? {
        let rule = pkg.get("autoAssign");
        let names_it = rule_values(rule, key)?
            .iter()
            .any(|value| wanted.contains(value))
            || rule_values(rule, "identity.groups")?
                .iter()
                .any(|value| groups.contains(value));
        if names_it {
            names.push(crate::js::js_string(pkg.get("name")));
        }
    }
    names.sort_by(|a, b| crate::metrics::locale_compare(a, b));
    Ok(names)
}
