//! Port of `packages/server/src/org-insights.ts`.
//!
//! Birthright suggestions: access most people of a department (or team) already hold by hand, proposed as an
//! automatic access package whose rule names that department (or team). The population of a unit is exactly who such
//! a rule would match: active people whose `identity.departments` (or `identity.teams`) includes it, so a department
//! counts the people of the departments below it. Only plain grants count: standing, permanent role bindings made
//! directly to the person, and permanent memberships of ordinary groups, neither created by an access package. What
//! most of a unit already receives from an automatic package, or is suggested for a unit above it, is never suggested
//! again.

use std::cmp::Ordering;
use std::sync::Arc;

use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, Identity, IdentityKind, IdentityStatus, Record,
    record_id,
};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::departments::{DEPARTMENTS, Department, department_chain_of};
use crate::js::{defined, js_string, member, number, truthy};
use crate::metrics::locale_compare;
use crate::models::{Binding, GroupMember};
use crate::org_rules::load_org_facts;
use crate::package_rules::rule_values;
use crate::port::decode;
use crate::teams::{TEAMS, Team, team_chain_of};
use crate::validation::integer;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BirthrightSuggestion {
    #[serde(rename = "unit")]
    pub unit: Value,
    /// Active people a rule naming the unit would match.
    #[serde(rename = "people")]
    pub people: f64,
    #[serde(rename = "roles")]
    pub roles: Vec<Value>,
    #[serde(rename = "groups")]
    pub groups: Vec<Value>,
    /// People of the unit who lack at least one suggested item: what creating the package would grant.
    #[serde(rename = "wouldGrant")]
    pub would_grant: f64,
    /// Automatic packages whose rule already names the unit or one above it (their contents are left out).
    #[serde(rename = "existingPackages")]
    pub existing_packages: Vec<String>,
    /// Ready for `packages.create` (add `tenantId`); the caller becomes the rule's owner.
    #[serde(rename = "package")]
    pub package: Value,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The rule key a unit kind is named under.
fn rule_key(kind: &str) -> &'static str {
    if kind == "department" {
        "identity.departments"
    } else {
        "identity.teams"
    }
}

/// Validates the API input of the `suggestBirthright` methods: answers `{ minShare, minPeople }`.
pub fn birthright_options(input: &Value) -> IamResult<Value> {
    let input = Some(input);
    let min_share = defined(member(input, "minShare"))
        .cloned()
        .unwrap_or_else(|| json!(0.8));
    let min_share = match min_share.as_f64() {
        Some(share) if share.is_finite() && (0.5..=1.0).contains(&share) => share,
        _ => {
            return Err(IamError::new(
                "INVALID_INPUT",
                "minShare must be between 0.5 and 1",
            ));
        }
    };
    let min_people_input = defined(member(input, "minPeople"))
        .cloned()
        .unwrap_or_else(|| json!(3));
    let min_people = integer(Some(&min_people_input), "minPeople", 2.0, 100_000.0)?;
    Ok(json!({ "minShare": number(min_share), "minPeople": number(min_people) }))
}

/// `string.slice(0, length)` measured in UTF-16 code units (a split surrogate pair is left out).
fn slice_utf16(value: &str, length: usize) -> String {
    let mut used = 0;
    let mut result = String::new();
    for ch in value.chars() {
        used += ch.len_utf16();
        if used > length {
            break;
        }
        result.push(ch);
    }
    result
}

async fn find(reader: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    reader
        .find(collection, &filter, &FindOptions::default())
        .await
}

fn add(map: &mut IndexMap<String, IndexSet<String>>, identity_id: &str, item_id: &str) {
    map.entry(identity_id.to_owned())
        .or_default()
        .insert(item_id.to_owned());
}

/// One unit (department or team) as the suggestions see it.
struct Unit {
    id: String,
    name: String,
}

pub async fn suggest_birthright(
    ctx: &Arc<ServerContext>,
    reader: &Store,
    tenant_id: &str,
    kind: &str,
    options: &Value,
) -> IamResult<Vec<crate::org_insights::BirthrightSuggestion>> {
    let unit_filter = member(Some(options), "unitId");
    let min_share = member(Some(options), "minShare")
        .and_then(Value::as_f64)
        .unwrap_or(f64::NAN);
    let min_people = member(Some(options), "minPeople")
        .and_then(Value::as_f64)
        .unwrap_or(f64::NAN);
    let now = ctx.now();
    let tenant = || Filter::new().eq("tenantId", tenant_id);
    // Sequential reads: a transaction holds one database connection.
    let mut people: Vec<Identity> = Vec::new();
    for record in find(reader, "identities", tenant()).await? {
        let identity: Identity = decode(record)?;
        if identity.kind == IdentityKind::User
            && identity.status == IdentityStatus::Active
            && !ctx.identity_expired(&identity)
        {
            people.push(identity);
        }
    }
    let roles: IndexMap<String, Record> = find(reader, "roles", tenant())
        .await?
        .into_iter()
        .map(|role| (record_id(&role).to_owned(), role))
        .collect();
    let groups: IndexMap<String, Record> = find(reader, "groups", tenant())
        .await?
        .into_iter()
        .map(|group| (record_id(&group).to_owned(), group))
        .collect();
    let bindings: Vec<Binding> = find(reader, "bindings", tenant().eq("subjectType", "identity"))
        .await?
        .into_iter()
        .map(decode)
        .collect::<IamResult<_>>()?;
    let memberships: Vec<GroupMember> = find(reader, "groupMembers", tenant())
        .await?
        .into_iter()
        .map(decode)
        .collect::<IamResult<_>>()?;
    let packages = find(reader, "accessPackages", tenant()).await?;
    // Assignments an automatic package made: what they grant is birthright access already.
    let automatic: IndexSet<String> = find(reader, "packageAssignments", tenant())
        .await?
        .iter()
        .filter(|assignment| assignment.get("ruleRevision").is_some())
        .map(|assignment| record_id(assignment).to_owned())
        .collect();
    let org = load_org_facts(reader, tenant_id, now).await?;
    let departments: IndexMap<String, Department>;
    let teams: IndexMap<String, Team>;
    let units: Vec<Unit>;
    if kind == "department" {
        departments = find(reader, DEPARTMENTS, tenant())
            .await?
            .into_iter()
            .map(|record| decode::<Department>(record).map(|unit| (unit.id.clone(), unit)))
            .collect::<IamResult<_>>()?;
        teams = IndexMap::new();
        units = departments
            .values()
            .map(|unit| Unit {
                id: unit.id.clone(),
                name: unit.name.clone(),
            })
            .collect();
    } else {
        teams = find(reader, TEAMS, tenant())
            .await?
            .into_iter()
            .map(|record| decode::<Team>(record).map(|unit| (unit.id.clone(), unit)))
            .collect::<IamResult<_>>()?;
        departments = IndexMap::new();
        units = teams
            .values()
            .map(|unit| Unit {
                id: unit.id.clone(),
                name: unit.name.clone(),
            })
            .collect();
    }
    let chain_of = |unit_id: &str| -> Vec<String> {
        if kind == "department" {
            department_chain_of(&departments, unit_id)
                .into_iter()
                .map(|unit| unit.id)
                .collect()
        } else {
            team_chain_of(&teams, unit_id)
                .into_iter()
                .map(|unit| unit.id)
                .collect()
        }
    };

    // What each person holds by hand, and which units a rule would see them in.
    let mut held_roles: IndexMap<String, IndexSet<String>> = IndexMap::new();
    let mut held_groups: IndexMap<String, IndexSet<String>> = IndexMap::new();
    let mut auto_roles: IndexMap<String, IndexSet<String>> = IndexMap::new();
    let mut auto_groups: IndexMap<String, IndexSet<String>> = IndexMap::new();
    for binding in &bindings {
        let role = roles.get(&binding.role_id);
        let live = ctx.live_binding(binding);
        if let Some(role) = role
            && binding
                .package_assignment_id
                .as_ref()
                .is_some_and(|assignment| automatic.contains(assignment))
            && live
        {
            add(&mut auto_roles, &binding.subject_id, record_id(role));
        }
        let Some(role) = role else {
            continue;
        };
        if truthy(role.get("protected"))
            || !live
            || binding.eligible == Some(true)
            || binding.window.is_some()
            || binding.starts_at.is_some()
            || binding.expires_at.is_some()
            || binding.package_assignment_id.is_some()
        {
            continue;
        }
        add(&mut held_roles, &binding.subject_id, record_id(role));
    }
    let mut direct_groups: IndexMap<String, Vec<String>> = IndexMap::new();
    for membership in &memberships {
        let live = ctx.live_membership(membership);
        if membership
            .package_assignment_id
            .as_ref()
            .is_some_and(|assignment| automatic.contains(assignment))
            && live
        {
            add(
                &mut auto_groups,
                &membership.identity_id,
                &membership.group_id,
            );
        }
        if membership.package_assignment_id.is_some() || !live {
            continue;
        }
        direct_groups
            .entry(membership.identity_id.clone())
            .or_default()
            .push(membership.group_id.clone());
        let Some(group) = groups.get(&membership.group_id) else {
            continue;
        };
        if group.get("teamId").is_some() || membership.expires_at.is_some() {
            continue;
        }
        add(&mut held_groups, &membership.identity_id, record_id(group));
    }
    let mut population: IndexMap<String, Vec<String>> = IndexMap::new();
    for person in &people {
        let facts = org.of(
            &person.id,
            direct_groups
                .get(&person.id)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        );
        let unit_ids = if kind == "department" {
            facts.departments
        } else {
            facts.teams
        };
        for unit_id in unit_ids {
            population
                .entry(unit_id)
                .or_default()
                .push(person.id.clone());
        }
    }

    // Top-down, so a unit never repeats what is suggested for a unit above it.
    let mut ordered: Vec<(usize, &Unit)> = units
        .iter()
        .map(|unit| (chain_of(&unit.id).len(), unit))
        .collect();
    ordered.sort_by(|(a_depth, a), (b_depth, b)| {
        a_depth
            .cmp(b_depth)
            .then_with(|| locale_compare(&a.name, &b.name))
    });
    let mut suggested: IndexMap<String, (IndexSet<String>, IndexSet<String>)> = IndexMap::new();
    let mut result: Vec<BirthrightSuggestion> = Vec::new();
    let empty: IndexSet<String> = IndexSet::new();
    for (_, unit) in ordered {
        let members: &[String] = population.get(&unit.id).map(Vec::as_slice).unwrap_or(&[]);
        let chain = chain_of(&unit.id);
        let above = &chain[chain.len().min(1)..];
        let mut inherited_roles: IndexSet<String> = IndexSet::new();
        let mut inherited_groups: IndexSet<String> = IndexSet::new();
        for unit_id in above {
            if let Some((roles, _)) = suggested.get(unit_id) {
                inherited_roles.extend(roles.iter().cloned());
            }
        }
        for unit_id in above {
            if let Some((_, groups)) = suggested.get(unit_id) {
                inherited_groups.extend(groups.iter().cloned());
            }
        }
        let mut existing: Vec<&Record> = Vec::new();
        for pkg in &packages {
            if rule_values(
                pkg.get("autoAssign").filter(|rule| !rule.is_null()),
                rule_key(kind),
            )?
            .iter()
            .any(|value| chain.contains(value))
            {
                existing.push(pkg);
            }
        }
        let ids_of = |pkg: &Record, key: &str| -> Vec<String> {
            match pkg.get(key) {
                Some(Value::Array(items)) => {
                    items.iter().map(|item| js_string(Some(item))).collect()
                }
                _ => Vec::new(),
            }
        };
        let covered_roles: IndexSet<String> = existing
            .iter()
            .flat_map(|pkg| ids_of(pkg, "roleIds"))
            .collect();
        let covered_groups: IndexSet<String> = existing
            .iter()
            .flat_map(|pkg| ids_of(pkg, "groupIds"))
            .collect();
        if (members.len() as f64) < min_people {
            continue;
        }
        let count = members.len() as f64;
        let tally = |held: &IndexMap<String, IndexSet<String>>| -> IndexMap<String, f64> {
            let mut counts: IndexMap<String, f64> = IndexMap::new();
            for person in members {
                for item_id in held.get(person).unwrap_or(&empty) {
                    *counts.entry(item_id.clone()).or_insert(0.0) += 1.0;
                }
            }
            counts
        };
        let share = |holders: f64| holders / count >= min_share;
        // Items most of the unit already receives from some automatic package are birthright access already.
        let already = |counts: IndexMap<String, f64>| -> Vec<String> {
            counts
                .into_iter()
                .filter(|(_, holders)| share(*holders))
                .map(|(item_id, _)| item_id)
                .collect()
        };
        let pick = |counts: IndexMap<String, f64>,
                    skip: IndexSet<String>,
                    items: &IndexMap<String, Record>|
         -> Vec<(String, String, f64)> {
            let mut picked: Vec<(String, String, f64)> = counts
                .into_iter()
                .filter(|(item_id, holders)| !skip.contains(item_id) && share(*holders))
                .map(|(item_id, holders)| {
                    let name = js_string(items.get(&item_id).and_then(|item| item.get("name")));
                    (item_id, name, holders)
                })
                .collect();
            picked.sort_by(|a, b| {
                b.2.partial_cmp(&a.2)
                    .unwrap_or(Ordering::Equal)
                    .then_with(|| locale_compare(&a.1, &b.1))
            });
            picked
        };
        let mut role_skip = covered_roles;
        role_skip.extend(inherited_roles);
        role_skip.extend(already(tally(&auto_roles)));
        let role_items = pick(tally(&held_roles), role_skip, &roles);
        let mut group_skip = covered_groups;
        group_skip.extend(inherited_groups);
        group_skip.extend(already(tally(&auto_groups)));
        let group_items = pick(tally(&held_groups), group_skip, &groups);
        suggested.insert(
            unit.id.clone(),
            (
                role_items.iter().map(|item| item.0.clone()).collect(),
                group_items.iter().map(|item| item.0.clone()).collect(),
            ),
        );
        if role_items.is_empty() && group_items.is_empty() {
            continue;
        }
        let would_grant = members
            .iter()
            .filter(|person| {
                role_items.iter().any(|item| {
                    !held_roles
                        .get(*person)
                        .is_some_and(|held| held.contains(&item.0))
                }) || group_items.iter().any(|item| {
                    !held_groups
                        .get(*person)
                        .is_some_and(|held| held.contains(&item.0))
                })
            })
            .count();
        let item_json = |items: &[(String, String, f64)]| -> Vec<Value> {
            items
                .iter()
                .map(|(item_id, name, holders)| {
                    json!({
                        "id": item_id,
                        "name": name,
                        "holders": number(*holders),
                        "share": number((holders / count * 100.0).round() / 100.0),
                    })
                })
                .collect()
        };
        let mut existing_packages: Vec<String> = existing
            .iter()
            .map(|pkg| js_string(pkg.get("name")))
            .collect();
        existing_packages.sort_by(|a, b| locale_compare(a, b));
        let word = if kind == "department" {
            "department"
        } else {
            "team"
        };
        let below = if kind == "department" {
            " and the departments below it"
        } else {
            " and the teams below it"
        };
        let mut array_contains = Map::new();
        array_contains.insert(rule_key(kind).into(), json!([unit.id]));
        result.push(BirthrightSuggestion {
            unit: json!({ "kind": kind, "id": unit.id, "name": unit.name }),
            people: count,
            roles: item_json(&role_items),
            groups: item_json(&group_items),
            would_grant: would_grant as f64,
            existing_packages,
            package: json!({
                "name": slice_utf16(&format!("{} {word} basics", unit.name), 100),
                "description": format!(
                    "Birthright access for everyone in the {} {kind}{below}.",
                    unit.name
                ),
                "roleIds": role_items.iter().map(|item| item.0.clone()).collect::<Vec<_>>(),
                "groupIds": group_items.iter().map(|item| item.0.clone()).collect::<Vec<_>>(),
                "autoAssign": {
                    "include": [
                        {
                            "StringEquals": { "principal.kind": "user" },
                            "ArrayContains": Value::Object(array_contains),
                        }
                    ]
                },
            }),
            extra: Map::new(),
        });
    }
    if truthy(unit_filter) {
        let wanted = unit_filter.cloned().unwrap_or(Value::Null);
        result.retain(|item| member(Some(&item.unit), "id") == Some(&wanted));
    }
    result.sort_by(|a, b| {
        b.people
            .partial_cmp(&a.people)
            .unwrap_or(Ordering::Equal)
            .then_with(|| {
                locale_compare(
                    &js_string(member(Some(&a.unit), "name")),
                    &js_string(member(Some(&b.unit), "name")),
                )
            })
    });
    Ok(result)
}
