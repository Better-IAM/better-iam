//! Port of `packages/server/src/api/role-mining.ts`.
//!
//! Role mining: reads who holds which roles and suggests simpler ways to grant the same access — role combinations
//! to bundle into access packages, roles every member of a group holds directly, direct bindings a group already
//! covers, and roles that duplicate each other — plus peer-group outliers: access a person holds that few people
//! sharing their manager or an identity attribute hold. Read methods need `iam:analysis:read`; `apply` needs
//! `iam:analysis:update` and the rights of the binding changes it makes.

use std::cmp::Ordering;
use std::sync::Arc;

use better_iam_core::{
    CredentialInput, Filter, FindOptions, IamError, IamResult, Identity, IdentityKind,
    IdentityStatus, Record, canonical_json, match_pattern,
};
use better_iam_types::api::role_mining;
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::api::{Body, Reply};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::js::{ThrownError, js_string, truthy};
use crate::metrics::locale_compare;
use crate::models::{Binding, GroupMember, Role};
use crate::port::decode;
use crate::usage::AccessUsageRecord;
use crate::validation::{integer, text};

/// Distinct role sets considered as bundle seeds; pairwise intersections of these are the candidates.
const MAX_SEED_SETS: usize = 300;
/// Bundles reported at most: the ones saving the most grants (`bundlesTruncated` says when more qualified).
const MAX_BUNDLES: usize = 2000;
const DAY_MS: f64 = 86_400_000.0;

/// Names `name in object` finds on a plain object besides its own members (`Object.prototype`).
const OBJECT_PROTOTYPE: [&str; 12] = [
    "constructor",
    "__defineGetter__",
    "__defineSetter__",
    "hasOwnProperty",
    "__lookupGetter__",
    "__lookupSetter__",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toString",
    "valueOf",
    "__proto__",
    "toLocaleString",
];

/// The suggestion kinds with their rank (`kindRank`), most actionable first.
const KIND_RANK: [(&str, u8); 4] = [
    ("redundant-binding", 0),
    ("group-binding", 1),
    ("duplicate-roles", 2),
    ("bundle", 3),
];

fn kind_rank(kind: &str) -> u8 {
    KIND_RANK
        .iter()
        .find(|(name, _)| *name == kind)
        .map(|(_, rank)| *rank)
        .unwrap_or(u8::MAX)
}

/// `kind in kindRank` (a plain object: its prototype's members count too).
fn known_kind(kind: &str) -> bool {
    KIND_RANK.iter().any(|(name, _)| *name == kind) || OBJECT_PROTOTYPE.contains(&kind)
}

/// The `roleMining` API group (`createRoleMiningApi(ctx)`): one method per route `roleMining/{method}`.
pub struct RoleMiningApi {
    ctx: Arc<ServerContext>,
}

/// `createRoleMiningApi(ctx)`.
pub fn create_role_mining_api(ctx: &Arc<ServerContext>) -> IamResult<RoleMiningApi> {
    Ok(RoleMiningApi { ctx: ctx.clone() })
}

/// `sha256('{kind}:{key}')` in hex, first 24 characters.
fn suggestion_id(kind: &str, key: &str) -> String {
    let digest = Sha256::digest(format!("{kind}:{key}").as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    hex[..24].to_owned()
}

/// `[...ids].sort().join(',')`.
fn set_key<'a>(ids: impl IntoIterator<Item = &'a String>) -> String {
    let mut list: Vec<String> = ids.into_iter().cloned().collect();
    crate::js::sort_strings(&mut list);
    list.join(",")
}

fn label(identity: &Identity) -> String {
    identity
        .email
        .clone()
        .unwrap_or_else(|| identity.name.clone())
}

/// `Math.round(value * 100) / 100`.
fn round(value: f64) -> f64 {
    (value * 100.0 + 0.5).floor() / 100.0
}

/// `Math.max(0, ...values)`: NaN when any value is NaN.
fn max_from_zero(values: impl IntoIterator<Item = f64>) -> f64 {
    let mut result = 0.0_f64;
    for value in values {
        if value.is_nan() || result.is_nan() {
            result = f64::NAN;
        } else if value > result {
            result = value;
        }
    }
    result
}

/// A JavaScript number difference used by a comparator (`b - a`), as an ordering; NaN and zero tie.
fn number_order(difference: f64) -> Ordering {
    if difference > 0.0 {
        Ordering::Greater
    } else if difference < 0.0 {
        Ordering::Less
    } else {
        Ordering::Equal
    }
}

/// `value ?? fallback` for a number member.
fn or_default(value: Option<&Value>, fallback: f64) -> Value {
    match value {
        None | Some(Value::Null) => crate::js::number(fallback),
        Some(value) => value.clone(),
    }
}

fn status_name(status: IdentityStatus) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

async fn find_records(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

fn record_str<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// A named reference (`MiningRef`).
fn reference(id: &str, name: &str) -> Value {
    json!({ "id": id, "name": name })
}

struct Snapshot {
    roles: Vec<Role>,
    role_by_id: IndexMap<String, Role>,
    /// The stored role records, by ID (statements and `protected` as stored).
    role_raw: IndexMap<String, Record>,
    identities: Vec<Identity>,
    identity_by_id: IndexMap<String, Identity>,
    groups: Vec<Record>,
    bindings: Vec<Binding>,
    binding_raw: IndexMap<String, Record>,
    members: Vec<GroupMember>,
    packages: Vec<Record>,
    policies: Vec<Record>,
}

impl Snapshot {
    /// `data.roleById.get(roleId)?.protected === false`.
    fn unprotected(&self, role_id: &str) -> bool {
        self.role_raw
            .get(role_id)
            .is_some_and(|role| role.get("protected") == Some(&Value::Bool(false)))
    }

    /// `role.protected` (truthy).
    fn protected(&self, role_id: &str) -> bool {
        truthy(
            self.role_raw
                .get(role_id)
                .and_then(|role| role.get("protected")),
        )
    }
}

async fn snapshot(ctx: &Arc<ServerContext>, tx: &Store, tenant_id: &str) -> IamResult<Snapshot> {
    let tenant = || Filter::new().eq("tenantId", tenant_id);
    // Sequential reads: a transaction holds one database connection.
    let role_records = find_records(tx, "roles", tenant()).await?;
    let mut roles: Vec<Role> = Vec::new();
    let mut role_raw: IndexMap<String, Record> = IndexMap::new();
    for record in role_records {
        let role: Role = decode(record.clone())?;
        role_raw.insert(role.id.clone(), record);
        roles.push(role);
    }
    let mut identities: Vec<Identity> = Vec::new();
    for record in find_records(tx, "identities", tenant()).await? {
        let identity: Identity = decode(record)?;
        if identity.status == IdentityStatus::Active && !ctx.identity_expired(&identity) {
            identities.push(identity);
        }
    }
    let groups = find_records(tx, "groups", tenant()).await?;
    let mut bindings: Vec<Binding> = Vec::new();
    let mut binding_raw: IndexMap<String, Record> = IndexMap::new();
    for record in find_records(tx, "bindings", tenant()).await? {
        let binding: Binding = decode(record.clone())?;
        if ctx.live_binding(&binding) {
            binding_raw.insert(binding.id.clone(), record);
            bindings.push(binding);
        }
    }
    let mut members: Vec<GroupMember> = Vec::new();
    for record in find_records(tx, "groupMembers", tenant()).await? {
        let member: GroupMember = decode(record)?;
        if ctx.live_membership(&member) {
            members.push(member);
        }
    }
    let packages = find_records(tx, "accessPackages", tenant()).await?;
    let policies = find_records(tx, "policies", tenant()).await?;
    Ok(Snapshot {
        role_by_id: roles
            .iter()
            .map(|role| (role.id.clone(), role.clone()))
            .collect(),
        roles,
        role_raw,
        identity_by_id: identities
            .iter()
            .map(|identity| (identity.id.clone(), identity.clone()))
            .collect(),
        identities,
        groups,
        bindings,
        binding_raw,
        members,
        packages,
        policies,
    })
}

/// Always-on grants: not just-in-time, not limited to a time window.
fn standing(binding: &Binding) -> bool {
    binding.eligible != Some(true) && binding.window.is_none()
}

/// A direct grant an administrator can safely fold into a group: standing, permanent, not owned by a package.
fn plain_direct(binding: &Binding) -> bool {
    binding.subject_type == "identity"
        && standing(binding)
        && binding.expires_at.is_none()
        && binding.starts_at.is_none()
        && binding.package_assignment_id.is_none()
}

/// Role IDs each active identity holds, directly or through groups (`eligible` includes just-in-time bindings).
fn held_roles(data: &Snapshot, eligible: bool) -> IndexMap<String, IndexSet<String>> {
    // Members by group, so a group binding reaches its members without a pass over everyone.
    let mut members_of: IndexMap<&str, Vec<&str>> = IndexMap::new();
    for member in &data.members {
        members_of
            .entry(member.group_id.as_str())
            .or_default()
            .push(member.identity_id.as_str());
    }
    let mut held: IndexMap<String, IndexSet<String>> = IndexMap::new();
    for identity in &data.identities {
        held.insert(identity.id.clone(), IndexSet::new());
    }
    for binding in &data.bindings {
        if !eligible && !standing(binding) {
            continue;
        }
        if !data.unprotected(&binding.role_id) {
            continue;
        }
        if binding.subject_type == "identity" {
            if let Some(set) = held.get_mut(&binding.subject_id) {
                set.insert(binding.role_id.clone());
            }
        } else {
            for identity_id in members_of
                .get(binding.subject_id.as_str())
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                if let Some(set) = held.get_mut(*identity_id) {
                    set.insert(binding.role_id.clone());
                }
            }
        }
    }
    held
}

/// The statements of a document (`document?.statements ?? []`).
fn statements(document: Option<&Value>) -> Vec<&Value> {
    match document.and_then(|document| document.get("statements")) {
        Some(Value::Array(items)) => items.iter().collect(),
        _ => Vec::new(),
    }
}

/// The documents a role contributes itself: its inline document and those of its attached policies.
fn role_documents<'a>(
    data: &'a Snapshot,
    policy_by_id: &IndexMap<&str, &'a Record>,
    role: &Role,
) -> Vec<Option<&'a Value>> {
    let mut documents = vec![
        data.role_raw
            .get(&role.id)
            .and_then(|raw| raw.get("document")),
    ];
    for policy_id in &role.policy_ids {
        documents.push(
            policy_by_id
                .get(policy_id.as_str())
                .and_then(|policy| policy.get("document")),
        );
    }
    documents
}

/// `[...values].sort()` for a statement member.
fn sorted_array(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Array(items)) => {
            let mut items = items.clone();
            items.sort_by(|a, b| match (a, b) {
                (Value::Null, Value::Null) => Ordering::Equal,
                _ => crate::js::cmp_utf16(&js_string(Some(a)), &js_string(Some(b))),
            });
            Value::Array(items)
        }
        Some(Value::String(text)) => Value::Array({
            let mut chars: Vec<String> = text.chars().map(String::from).collect();
            crate::js::sort_strings(&mut chars);
            chars.into_iter().map(Value::String).collect()
        }),
        _ => Value::Array(Vec::new()),
    }
}

/// Statement fields that do not change what it grants are dropped; action and resource order is irrelevant.
fn normalize_statement(statement: &Value) -> Value {
    let mut rest = statement.as_object().cloned().unwrap_or_default();
    rest.shift_remove("sid");
    let actions = sorted_array(statement.get("actions"));
    let resources = sorted_array(statement.get("resources"));
    rest.insert("actions".into(), actions);
    rest.insert("resources".into(), resources);
    Value::Object(rest)
}

/// The statements a role grants (inline, attached policies, inherited roles), as a canonical comparable key.
fn grant_key(data: &Snapshot, role: &Role) -> String {
    let policy_by_id: IndexMap<&str, &Record> = data
        .policies
        .iter()
        .map(|policy| (record_str(policy, "id"), policy))
        .collect();
    // Depth-first: the role, then each inherited role in turn.
    fn walk<'a>(
        data: &'a Snapshot,
        policy_by_id: &IndexMap<&str, &'a Record>,
        current: &Role,
        seen: &mut IndexSet<String>,
        found: &mut IndexSet<String>,
    ) {
        if !seen.insert(current.id.clone()) {
            return;
        }
        for document in role_documents(data, policy_by_id, current) {
            for statement in statements(document) {
                found.insert(canonical_json(&normalize_statement(statement)));
            }
        }
        for parent in current.inherits.as_deref().unwrap_or_default() {
            if let Some(inherited) = data.role_by_id.get(parent) {
                walk(data, policy_by_id, inherited, seen, found);
            }
        }
    }
    let mut found: IndexSet<String> = IndexSet::new();
    let mut seen: IndexSet<String> = IndexSet::new();
    walk(data, &policy_by_id, role, &mut seen, &mut found);
    let mut list: Vec<String> = found.into_iter().collect();
    crate::js::sort_strings(&mut list);
    list.join("\n")
}

/// The known actions a role can allow somewhere (its own, attached, and inherited allow statements). Resources and
/// conditions are not considered: this is what the role could grant, compared with what its holders used.
fn role_actions(data: &Snapshot, role: &Role, known: &[String]) -> Vec<String> {
    let policy_by_id: IndexMap<&str, &Record> = data
        .policies
        .iter()
        .map(|policy| (record_str(policy, "id"), policy))
        .collect();
    fn walk<'a>(
        data: &'a Snapshot,
        policy_by_id: &IndexMap<&str, &'a Record>,
        current: &Role,
        seen: &mut IndexSet<String>,
        patterns: &mut IndexSet<String>,
    ) {
        if !seen.insert(current.id.clone()) {
            return;
        }
        for document in role_documents(data, policy_by_id, current) {
            for statement in statements(document) {
                if statement.get("effect").and_then(Value::as_str) == Some("allow")
                    && let Some(Value::Array(actions)) = statement.get("actions")
                {
                    for action in actions {
                        patterns.insert(js_string(Some(action)));
                    }
                }
            }
        }
        for parent in current.inherits.as_deref().unwrap_or_default() {
            if let Some(inherited) = data.role_by_id.get(parent) {
                walk(data, policy_by_id, inherited, seen, patterns);
            }
        }
    }
    let mut patterns: IndexSet<String> = IndexSet::new();
    let mut seen: IndexSet<String> = IndexSet::new();
    walk(data, &policy_by_id, role, &mut seen, &mut patterns);
    known
        .iter()
        .filter(|action| {
            patterns
                .iter()
                .any(|pattern| match_pattern(pattern, action, None))
        })
        .cloned()
        .collect()
}

/// One suggestion (`RoleSuggestion`).
struct Suggestion {
    id: String,
    kind: &'static str,
    title: String,
    detail: String,
    roles: Vec<Value>,
    identities: Vec<Value>,
    group: Option<(String, String)>,
    binding_ids: Option<Vec<String>>,
    savings: usize,
    applicable: bool,
    /// The role IDs of `roles`, in order.
    role_ids: Vec<String>,
}

impl Suggestion {
    fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("id".into(), json!(self.id));
        out.insert("kind".into(), json!(self.kind));
        out.insert("title".into(), json!(self.title));
        out.insert("detail".into(), json!(self.detail));
        out.insert("roles".into(), Value::Array(self.roles.clone()));
        out.insert("identities".into(), Value::Array(self.identities.clone()));
        if let Some((id, name)) = &self.group {
            out.insert("group".into(), reference(id, name));
        }
        if let Some(binding_ids) = &self.binding_ids {
            out.insert("bindingIds".into(), json!(binding_ids));
        }
        out.insert("savings".into(), json!(self.savings));
        out.insert("applicable".into(), json!(self.applicable));
        Value::Object(out)
    }
}

struct Mined {
    suggestions: Vec<Suggestion>,
    bundles_truncated: bool,
}

struct Settings {
    min_identities: f64,
    min_roles: f64,
}

/// `settingsOf(input)`.
fn settings_of(input: &Map<String, Value>) -> IamResult<Settings> {
    Ok(Settings {
        min_identities: integer(
            Some(&or_default(input.get("minIdentities"), 3.0)),
            "minIdentities",
            2.0,
            10_000.0,
        )?,
        min_roles: integer(
            Some(&or_default(input.get("minRoles"), 2.0)),
            "minRoles",
            2.0,
            50.0,
        )?,
    })
}

fn group_id(group: &Record) -> &str {
    record_str(group, "id")
}

fn group_name(group: &Record) -> String {
    js_string(group.get("name"))
}

fn mine(data: &Snapshot, settings: &Settings) -> IamResult<Mined> {
    let mut suggestions: Vec<Suggestion> = Vec::new();
    let role_name = |role_id: &str| -> String {
        data.role_by_id
            .get(role_id)
            .map(|role| role.name.clone())
            .unwrap_or_else(|| role_id.to_owned())
    };
    let role_ref = |role_id: &str| reference(role_id, &role_name(role_id));
    let identity_ref = |identity_id: &str| match data.identity_by_id.get(identity_id) {
        Some(identity) => reference(identity_id, &label(identity)),
        None => reference(identity_id, identity_id),
    };
    let group_by_id: IndexMap<&str, &Record> = data
        .groups
        .iter()
        .map(|group| (group_id(group), group))
        .collect();

    // Bundles: role combinations many people hold together, found as closed itemsets over the distinct role sets
    // and their pairwise intersections (every maximal shared combination is an intersection of two holders' sets).
    let held = held_roles(data, false);
    let people: Vec<&String> = held.keys().collect();
    struct Distinct {
        key: String,
        roles: Vec<String>,
        count: usize,
        holders: Vec<usize>,
    }
    // Each distinct role set with the people (positions in `people`, ascending) who hold exactly it.
    let mut distinct: IndexMap<String, Distinct> = IndexMap::new();
    for (position, person) in people.iter().enumerate() {
        let roles = &held[*person];
        if (roles.len() as f64) < settings.min_roles {
            continue;
        }
        let key = set_key(roles.iter());
        let entry = distinct.entry(key.clone()).or_insert_with(|| {
            let mut sorted: Vec<String> = roles.iter().cloned().collect();
            crate::js::sort_strings(&mut sorted);
            Distinct {
                key,
                roles: sorted,
                count: 0,
                holders: Vec::new(),
            }
        });
        entry.count += 1;
        entry.holders.push(position);
    }
    let mut seeds: Vec<&Distinct> = distinct.values().collect();
    seeds.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| locale_compare(&a.key, &b.key))
    });
    seeds.truncate(MAX_SEED_SETS);
    let mut candidates: IndexMap<String, Vec<String>> = IndexMap::new();
    for (i, seed) in seeds.iter().enumerate() {
        candidates.insert(set_key(seed.roles.iter()), seed.roles.clone());
        let first: IndexSet<&String> = seed.roles.iter().collect();
        for other in &seeds[i + 1..] {
            let common: Vec<String> = other
                .roles
                .iter()
                .filter(|role_id| first.contains(role_id))
                .cloned()
                .collect();
            if (common.len() as f64) >= settings.min_roles {
                candidates.insert(set_key(common.iter()), common);
            }
        }
    }
    // Holders are counted over the distinct role sets, with one bitset per role (bit i: the i-th set includes it):
    // the sets holding a combination are the AND of its roles' bitsets. No candidate is compared with every person
    // or with every other candidate, so the work grows with the number of candidates, never with its square.
    let sets: Vec<&Distinct> = distinct.values().collect();
    let words = sets.len().div_ceil(32);
    let mut role_bits: IndexMap<&str, Vec<u32>> = IndexMap::new();
    for (index, entry) in sets.iter().enumerate() {
        for role_id in &entry.roles {
            let bits = role_bits
                .entry(role_id.as_str())
                .or_insert_with(|| vec![0u32; words]);
            bits[index >> 5] |= 1u32 << (index & 31);
        }
    }
    // The distinct role sets (indexes into `sets`) that include every role of a combination.
    let holding = |roles: &[String]| -> Vec<usize> {
        let mut bits = roles
            .first()
            .and_then(|first| role_bits.get(first.as_str()))
            .cloned()
            .unwrap_or_else(|| vec![0u32; words]);
        for role_id in roles.iter().skip(1) {
            match role_bits.get(role_id.as_str()) {
                Some(other) => {
                    for word in 0..words {
                        bits[word] &= other[word];
                    }
                }
                None => bits.iter_mut().for_each(|word| *word = 0),
            }
        }
        let mut indexes: Vec<usize> = Vec::new();
        for (word, value) in bits.iter().enumerate() {
            let mut rest = *value;
            while rest != 0 {
                indexes.push(word * 32 + rest.trailing_zeros() as usize);
                rest &= rest - 1;
            }
        }
        indexes
    };
    let packaged: IndexSet<String> = data
        .packages
        .iter()
        .filter(|package| match package.get("groupIds") {
            Some(Value::Array(ids)) => ids.is_empty(),
            _ => false,
        })
        .map(|package| {
            let ids: Vec<String> = match package.get("roleIds") {
                Some(Value::Array(ids)) => ids.iter().map(|id| js_string(Some(id))).collect(),
                _ => Vec::new(),
            };
            set_key(ids.iter())
        })
        .collect();
    let composite: IndexSet<String> = data
        .roles
        .iter()
        .filter(|role| role.inherits.as_ref().is_some_and(|list| !list.is_empty()))
        .map(|role| set_key(role.inherits.as_deref().unwrap_or_default().iter()))
        .collect();
    struct Supported {
        key: String,
        roles: Vec<String>,
        holders: usize,
        order: usize,
    }
    let mut supported: Vec<Supported> = Vec::new();
    for (key, roles) in &candidates {
        if packaged.contains(key) || composite.contains(key) {
            continue;
        }
        let holders: usize = holding(roles).iter().map(|index| sets[*index].count).sum();
        if (holders as f64) >= settings.min_identities {
            let order = supported.len();
            supported.push(Supported {
                key: key.clone(),
                roles: roles.clone(),
                holders,
                order,
            });
        }
    }
    // When more combinations qualify than are reported, the ones saving the most grants are kept.
    let bundles_truncated = supported.len() > MAX_BUNDLES;
    let reported: Vec<Supported> = if bundles_truncated {
        supported.sort_by(|a, b| {
            let saved = |entry: &Supported| entry.holders as f64 * (entry.roles.len() as f64 - 1.0);
            number_order(saved(b) - saved(a)).then_with(|| a.order.cmp(&b.order))
        });
        supported.truncate(MAX_BUNDLES);
        supported.sort_by_key(|entry| entry.order);
        supported
    } else {
        supported
    };
    // Closed sets only: of combinations with exactly the same holders, the largest stands for them. (Every candidate
    // is the intersection of the role sets of the people holding one or two seeds exactly, so each is already
    // closed; grouping by holders keeps that true without comparing candidates pairwise.)
    struct Closed {
        key: String,
        roles: Vec<String>,
        holders: Vec<String>,
    }
    let mut closed: IndexMap<String, Closed> = IndexMap::new();
    for candidate in &reported {
        let mut positions: Vec<usize> = holding(&candidate.roles)
            .iter()
            .flat_map(|index| sets[*index].holders.iter().copied())
            .collect();
        positions.sort_unstable();
        let signature = positions
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let replace = closed
            .get(&signature)
            .is_none_or(|current| candidate.roles.len() > current.roles.len());
        if replace {
            closed.insert(
                signature,
                Closed {
                    key: candidate.key.clone(),
                    roles: candidate.roles.clone(),
                    holders: positions
                        .iter()
                        .map(|position| people[*position].clone())
                        .collect(),
                },
            );
        }
    }
    for candidate in closed.values() {
        let names: Vec<String> = candidate.roles.iter().map(|id| role_name(id)).collect();
        suggestions.push(Suggestion {
            id: suggestion_id("bundle", &candidate.key),
            kind: "bundle",
            title: format!(
                "{} people hold {} together",
                candidate.holders.len(),
                names.join(" + ")
            ),
            detail: "Grant the combination as one access package (optionally assigned automatically by attribute) or as a role that inherits these roles, instead of binding each role separately.".into(),
            roles: candidate.roles.iter().map(|id| role_ref(id)).collect(),
            identities: candidate.holders.iter().map(|id| identity_ref(id)).collect(),
            group: None,
            binding_ids: None,
            savings: candidate.holders.len() * (candidate.roles.len() - 1),
            applicable: false,
            role_ids: candidate.roles.clone(),
        });
    }

    // Group bindings: a role every permanent member of a group holds through their own direct binding. A team's
    // backing group is left out: the team's maintainers decide who belongs to it (teams.ts), so a role bound to it
    // would be theirs to hand out.
    let mut members_of: IndexMap<&str, Vec<&GroupMember>> = IndexMap::new();
    // Every live membership counts, including disabled or expired members: binding the role to the group would
    // reach them too (on re-activation), so a group qualifies only when all of them are active holders.
    for member in &data.members {
        members_of
            .entry(member.group_id.as_str())
            .or_default()
            .push(member);
    }
    // The roles bound to each group, and each person's plain direct bindings of unprotected roles.
    let mut group_roles_of: IndexMap<&str, IndexSet<&str>> = IndexMap::new();
    let mut direct_of: IndexMap<&str, Vec<&Binding>> = IndexMap::new();
    for binding in &data.bindings {
        if binding.subject_type == "group" {
            group_roles_of
                .entry(binding.subject_id.as_str())
                .or_default()
                .insert(binding.role_id.as_str());
        } else if plain_direct(binding) && data.unprotected(&binding.role_id) {
            direct_of
                .entry(binding.subject_id.as_str())
                .or_default()
                .push(binding);
        }
    }
    let no_roles: IndexSet<&str> = IndexSet::new();
    for (group_key, members) in &members_of {
        let Some(group) = group_by_id.get(group_key) else {
            continue;
        };
        if crate::teams::is_team_group(Some(&Value::Object((*group).clone())))?
            || (members.len() as f64) < settings.min_identities
        {
            continue;
        }
        if members.iter().any(|member| member.expires_at.is_some()) {
            continue;
        }
        if members
            .iter()
            .any(|member| !data.identity_by_id.contains_key(&member.identity_id))
        {
            continue;
        }
        let group_roles = group_roles_of.get(group_key).unwrap_or(&no_roles);
        let mut direct: IndexMap<&str, Vec<&Binding>> = IndexMap::new();
        let member_ids: IndexSet<&str> = members
            .iter()
            .map(|member| member.identity_id.as_str())
            .collect();
        for identity_id in &member_ids {
            for binding in direct_of
                .get(identity_id)
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                if !group_roles.contains(binding.role_id.as_str()) {
                    direct
                        .entry(binding.role_id.as_str())
                        .or_default()
                        .push(binding);
                }
            }
        }
        for (role_id, list) in &direct {
            let holders: IndexSet<&str> = list
                .iter()
                .map(|binding| binding.subject_id.as_str())
                .collect();
            if !members
                .iter()
                .all(|member| holders.contains(member.identity_id.as_str()))
            {
                continue;
            }
            // One authority keeps the ceiling identical once the grant moves to the group.
            let authorities: IndexSet<&str> = list
                .iter()
                .map(|binding| binding.authority_id.as_str())
                .collect();
            let mut binding_ids: Vec<String> =
                list.iter().map(|binding| binding.id.clone()).collect();
            crate::js::sort_strings(&mut binding_ids);
            let mut holder_ids: Vec<String> = holders.iter().map(|id| (*id).to_owned()).collect();
            crate::js::sort_strings(&mut holder_ids);
            let name = group_name(group);
            let id = group_id(group).to_owned();
            suggestions.push(Suggestion {
                id: suggestion_id(
                    "group-binding",
                    &format!("{group_key}:{role_id}:{}", binding_ids.join(",")),
                ),
                kind: "group-binding",
                title: format!(
                    "Every member of {name} holds {} directly",
                    role_name(role_id)
                ),
                detail: format!(
                    "Bind {} to the group once and remove {} direct binding(s); new members then receive it automatically and leavers lose it.{}",
                    role_name(role_id),
                    list.len(),
                    if authorities.len() > 1 {
                        " The direct bindings come from different grant authorities, so apply is not offered."
                    } else {
                        ""
                    }
                ),
                roles: vec![role_ref(role_id)],
                identities: holder_ids.iter().map(|id| identity_ref(id)).collect(),
                group: Some((id, name)),
                binding_ids: Some(binding_ids),
                savings: list.len() - 1,
                applicable: authorities.len() == 1,
                role_ids: vec![(*role_id).to_owned()],
            });
        }
    }

    // Redundant direct bindings: the same role already reaches the person through a permanent group membership,
    // under the same authority (so the same ceiling) and at least as broadly. A team's backing group does not count:
    // relying on it would hand control of the access to the team's maintainers.
    let mut group_bindings_of: IndexMap<&str, Vec<&Binding>> = IndexMap::new();
    for other in &data.bindings {
        if other.subject_type == "group"
            && !crate::teams::is_team_group(
                group_by_id
                    .get(other.subject_id.as_str())
                    .map(|group| Value::Object((*group).clone()))
                    .as_ref(),
            )?
        {
            group_bindings_of
                .entry(other.role_id.as_str())
                .or_default()
                .push(other);
        }
    }
    let mut permanent_groups: IndexMap<&str, IndexSet<&str>> = IndexMap::new();
    // Package-owned memberships end with their assignment, so they cannot stand in for a direct binding.
    for member in &data.members {
        if member.expires_at.is_none() && member.package_assignment_id.is_none() {
            permanent_groups
                .entry(member.identity_id.as_str())
                .or_default()
                .insert(member.group_id.as_str());
        }
    }
    let mut redundant: IndexMap<String, Vec<(&Binding, &Record)>> = IndexMap::new();
    for binding in &data.bindings {
        if binding.subject_type != "identity"
            || binding.eligible == Some(true)
            || binding.package_assignment_id.is_some()
            || !data.identity_by_id.contains_key(&binding.subject_id)
            || !data.unprotected(&binding.role_id)
        {
            continue;
        }
        let Some(groups) = permanent_groups.get(binding.subject_id.as_str()) else {
            continue;
        };
        let cover = group_bindings_of
            .get(binding.role_id.as_str())
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .find(|other| {
                groups.contains(other.subject_id.as_str())
                    && other.authority_id == binding.authority_id
                    && standing(other)
                    && other.starts_at.is_none()
                    && match other.expires_at {
                        None => true,
                        Some(other_expires) => binding
                            .expires_at
                            .is_some_and(|expires| other_expires >= expires),
                    }
            });
        let Some(group) = cover.and_then(|cover| group_by_id.get(cover.subject_id.as_str())) else {
            continue;
        };
        let key = format!("{}:{}", group_id(group), binding.role_id);
        redundant.entry(key).or_default().push((binding, group));
    }
    for (key, list) in &redundant {
        let (binding, group) = list[0];
        let mut binding_ids: Vec<String> = list.iter().map(|(entry, _)| entry.id.clone()).collect();
        crate::js::sort_strings(&mut binding_ids);
        let name = group_name(group);
        suggestions.push(Suggestion {
            id: suggestion_id(
                "redundant-binding",
                &format!("{key}:{}", binding_ids.join(",")),
            ),
            kind: "redundant-binding",
            title: format!(
                "{} direct {} binding(s) duplicate {name}'s",
                list.len(),
                role_name(&binding.role_id)
            ),
            detail: format!(
                "These people already receive {} through their permanent membership in {name}. Removing the direct bindings changes nothing today and keeps access tied to the group.",
                role_name(&binding.role_id)
            ),
            roles: vec![role_ref(&binding.role_id)],
            identities: list
                .iter()
                .map(|(entry, _)| identity_ref(&entry.subject_id))
                .collect(),
            group: Some((group_id(group).to_owned(), name)),
            binding_ids: Some(binding_ids),
            savings: list.len(),
            applicable: true,
            role_ids: vec![binding.role_id.clone()],
        });
    }

    // Duplicate roles: different roles that grant exactly the same statements.
    let mut by_grant: IndexMap<String, Vec<&Role>> = IndexMap::new();
    for role in &data.roles {
        if data.protected(&role.id) {
            continue;
        }
        let key = grant_key(data, role);
        if key.is_empty() {
            continue;
        }
        by_grant.entry(key).or_default().push(role);
    }
    for list in by_grant.values() {
        if list.len() < 2 {
            continue;
        }
        let mut ids: Vec<String> = list.iter().map(|role| role.id.clone()).collect();
        crate::js::sort_strings(&mut ids);
        suggestions.push(Suggestion {
            id: suggestion_id("duplicate-roles", &ids.join(",")),
            kind: "duplicate-roles",
            title: format!(
                "{} grant the same permissions",
                list.iter()
                    .map(|role| role.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            detail: "The roles resolve to identical statements. Keep one, move its bindings over, and delete the rest so reviews have one thing to certify.".into(),
            roles: ids.iter().map(|id| role_ref(id)).collect(),
            identities: Vec::new(),
            group: None,
            binding_ids: None,
            savings: list.len() - 1,
            applicable: false,
            role_ids: ids.clone(),
        });
    }
    Ok(Mined {
        suggestions,
        bundles_truncated,
    })
}

/// The known action names of a tenant: the catalog's, then the tenant's own (`[...new Set([...])]`).
async fn known_actions(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
) -> IamResult<Vec<String>> {
    let mut names: IndexSet<String> = ctx.catalog.actions.iter().cloned().collect();
    for record in find_records(tx, "actions", Filter::new().eq("tenantId", tenant_id)).await? {
        names.insert(js_string(record.get("name")));
    }
    Ok(names.into_iter().collect())
}

/// `input.kinds === undefined ? undefined : new Set(input.kinds)`, with the elements `kinds.has(kind)` can match
/// (strings) and every element as `in` sees it (its string form).
struct KindFilter {
    matches: IndexSet<String>,
    keys: Vec<String>,
}

fn kind_filter(value: Option<&Value>) -> IamResult<Option<KindFilter>> {
    match value {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(KindFilter {
            matches: IndexSet::new(),
            keys: Vec::new(),
        })),
        Some(Value::Array(items)) => {
            let mut matches = IndexSet::new();
            let mut keys = Vec::new();
            for item in items {
                if let Value::String(kind) = item {
                    matches.insert(kind.clone());
                }
                keys.push(js_string(Some(item)));
            }
            Ok(Some(KindFilter { matches, keys }))
        }
        Some(Value::String(text)) => {
            let chars: Vec<String> = text.chars().map(String::from).collect();
            Ok(Some(KindFilter {
                matches: chars.iter().cloned().collect(),
                keys: chars,
            }))
        }
        Some(other) => Err(ThrownError::type_error(format!(
            "{} is not iterable",
            crate::js::type_name(Some(other))
        ))
        .into()),
    }
}

impl RoleMiningApi {
    /// `roleMining/apply`: carries out a `group-binding` or `redundant-binding` suggestion, recomputed inside the
    /// transaction so it applies only while the condition still holds (`NOT_FOUND` otherwise). A group binding is
    /// created under the authority the direct bindings share, so the caller must hold that authority (or be root)
    /// and `iam:bindings:create` on the role; every removed binding needs `iam:bindings:delete`. Requires
    /// iam:analysis:update. Bundles and duplicate roles are left to `packages.create` and role edits.
    pub async fn apply(
        &self,
        credential: &CredentialInput,
        input: Body<role_mining::ApplyInput>,
    ) -> IamResult<Reply<role_mining::ApplyOutput>> {
        let ctx = &self.ctx;
        let settings = settings_of(&input)?;
        let wanted = text(input.get("suggestionId"), "suggestionId", 64)?;
        let settings = &settings;
        let wanted_ref = &wanted;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      tenant,
                      principal,
                  }| {
                Box::pin(async move {
                    let data = snapshot(ctx, &tx, &tenant.id).await?;
                    let mined = mine(&data, settings)?;
                    let Some(suggestion) = mined
                        .suggestions
                        .into_iter()
                        .find(|entry| &entry.id == wanted_ref)
                    else {
                        return Err(IamError::with_status(
                            "NOT_FOUND",
                            "The suggestion no longer applies; list suggestions again",
                            404,
                        )
                        .into());
                    };
                    if !suggestion.applicable {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            if suggestion.kind == "bundle" {
                                "Create an access package from a bundle with packages.create"
                            } else {
                                "This suggestion cannot be applied automatically"
                            },
                        )
                        .into());
                    }
                    let mut removals: Vec<Record> = Vec::new();
                    for binding_id in suggestion.binding_ids.as_deref().unwrap_or_default() {
                        if let Some(record) = data.binding_raw.get(binding_id) {
                            removals.push(record.clone());
                        }
                    }
                    let mut created: Option<String> = None;
                    if suggestion.kind == "group-binding" {
                        let role_id = suggestion.role_ids.first().cloned().unwrap_or_default();
                        let group_key = suggestion
                            .group
                            .as_ref()
                            .map(|(id, _)| id.clone())
                            .unwrap_or_default();
                        // Never a team's backing group (mining leaves them out): its maintainers would hand the role out.
                        let group = data
                            .groups
                            .iter()
                            .find(|group| group_id(group) == group_key)
                            .map(|group| Value::Object(group.clone()));
                        crate::teams::assert_not_team_group(group.as_ref())?;
                        crate::api::packages::allow(
                            ctx,
                            &tx,
                            &principal,
                            &tenant.id,
                            "iam:bindings:create",
                            &role_id,
                            "bind this role",
                        )
                        .await?;
                        let mut binding = Map::new();
                        binding.insert("tenantId".into(), json!(tenant.id));
                        binding.insert("roleId".into(), json!(role_id));
                        binding.insert("subjectType".into(), json!("group"));
                        binding.insert("subjectId".into(), json!(group_key));
                        binding.insert(
                            "authorityId".into(),
                            removals
                                .first()
                                .and_then(|removal| removal.get("authorityId"))
                                .cloned()
                                .unwrap_or(Value::Null),
                        );
                        let record = crate::api::bindings::create_binding_record(
                            ctx, &tx, &principal, &binding, None,
                        )
                        .await?;
                        created = Some(js_string(record.get("id")));
                    }
                    for binding in &removals {
                        crate::api::packages::allow(
                            ctx,
                            &tx,
                            &principal,
                            &tenant.id,
                            "iam:bindings:delete",
                            record_str(binding, "id"),
                            "remove this binding",
                        )
                        .await?;
                        crate::api::bindings::delete_binding_record(ctx, &tx, &principal, binding)
                            .await?;
                    }
                    let mut out = Map::new();
                    out.insert("applied".into(), json!(suggestion.kind));
                    if let Some(created) = created {
                        out.insert("createdBindingId".into(), json!(created));
                    }
                    out.insert(
                        "removedBindingIds".into(),
                        Value::Array(
                            removals
                                .iter()
                                .map(|binding| binding.get("id").cloned().unwrap_or(Value::Null))
                                .collect(),
                        ),
                    );
                    Ok(Value::Object(out))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:analysis:update",
                &format!("analysis/{wanted}"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `roleMining/outliers`: peer-group outliers. `peerBy` is `manager` (default: people with the same manager) or
    /// `attribute:{name}` for a declared identity attribute. A role is unusual when fewer than `threshold` (default
    /// 0.25) of the person's peers hold it, and missing when at least `commonShare` (default 0.8) of them hold it;
    /// groups smaller than `minPeers` (default 3, excluding the person) are skipped. Just-in-time (eligible)
    /// bindings count as held.
    pub async fn outliers(
        &self,
        credential: &CredentialInput,
        input: Body<role_mining::OutliersInput>,
    ) -> IamResult<Reply<role_mining::OutliersOutput>> {
        let ctx = &self.ctx;
        let peer_by_value = match input.get("peerBy") {
            None | Some(Value::Null) => Value::String("manager".into()),
            Some(value) => value.clone(),
        };
        let peer_by = text(Some(&peer_by_value), "peerBy", 100)?;
        let attribute: Option<String> = peer_by.strip_prefix("attribute:").map(str::to_owned);
        if peer_by != "manager" && attribute.is_none() {
            return Err(IamError::new(
                "INVALID_INPUT",
                "peerBy must be manager or attribute:{name}",
            ));
        }
        if let Some(attribute) = &attribute
            && !ctx.catalog.identity_attributes.contains_key(attribute)
            && !OBJECT_PROTOTYPE.contains(&attribute.as_str())
        {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!("Unknown identity attribute {attribute}"),
            ));
        }
        let share = |value: Option<&Value>, fallback: f64, name: &str| -> IamResult<f64> {
            let result = match value {
                None | Some(Value::Null) => Some(fallback),
                Some(Value::Number(number)) => Some(better_iam_core::js::number_value(number)),
                Some(_) => None,
            };
            match result {
                Some(result) if result > 0.0 && result <= 1.0 => Ok(result),
                _ => Err(IamError::new(
                    "INVALID_INPUT",
                    format!("{name} must be a number above 0 and at most 1"),
                )),
            }
        };
        let threshold = share(input.get("threshold"), 0.25, "threshold")?;
        let common_share = share(input.get("commonShare"), 0.8, "commonShare")?;
        let min_peers = integer(
            Some(&or_default(input.get("minPeers"), 3.0)),
            "minPeers",
            1.0,
            10_000.0,
        )?;
        let attribute = &attribute;
        let peer_by_ref = &peer_by;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let data = snapshot(ctx, &tx, &tenant.id).await?;
                let held = held_roles(&data, true);
                let peer_value = |identity: &Identity| -> Option<String> {
                    let Some(attribute) = attribute else {
                        return identity.manager_id.clone();
                    };
                    let attributes = identity.attributes.as_ref()?;
                    match attributes.get(attribute) {
                        Some(Value::Null) | Some(Value::Object(_)) | Some(Value::Array(_)) => None,
                        Some(value) => Some(js_string(Some(value))),
                        // A name from Object.prototype resolves to a function (`String(fn)`), or to the prototype
                        // object itself for `__proto__`.
                        None if attribute == "__proto__" => None,
                        None if OBJECT_PROTOTYPE.contains(&attribute.as_str()) => {
                            let name = if attribute == "constructor" {
                                "Object"
                            } else {
                                attribute.as_str()
                            };
                            Some(format!("function {name}() {{ [native code] }}"))
                        }
                        None => None,
                    }
                };
                let mut cohorts: IndexMap<String, Vec<&Identity>> = IndexMap::new();
                for identity in &data.identities {
                    let Some(value) = peer_value(identity) else {
                        continue;
                    };
                    cohorts.entry(value).or_default().push(identity);
                }
                let role_ref = |role_id: &str| {
                    reference(
                        role_id,
                        &data
                            .role_by_id
                            .get(role_id)
                            .map(|role| role.name.clone())
                            .unwrap_or_else(|| role_id.to_owned()),
                    )
                };
                struct Share {
                    role: Value,
                    name: String,
                    peers_holding: usize,
                    share: f64,
                }
                impl Share {
                    fn to_json(&self) -> Value {
                        json!({
                            "role": self.role,
                            "peersHolding": self.peers_holding,
                            "share": crate::js::number(self.share),
                        })
                    }
                }
                let by_share = |a: &Share, b: &Share| -> Ordering {
                    number_order(a.share - b.share).then_with(|| locale_compare(&a.name, &b.name))
                };
                struct Outlier {
                    identity: Value,
                    name: String,
                    peer_value: String,
                    peers: usize,
                    unusual: Vec<Share>,
                    missing: Vec<Share>,
                }
                let mut outliers: Vec<Outlier> = Vec::new();
                let mut compared = 0usize;
                let empty: IndexSet<String> = IndexSet::new();
                for (value, cohort) in &cohorts {
                    if (cohort.len() as f64) - 1.0 < min_peers {
                        continue;
                    }
                    let mut counts: IndexMap<&str, usize> = IndexMap::new();
                    for member in cohort {
                        for role_id in held.get(&member.id).unwrap_or(&empty) {
                            *counts.entry(role_id.as_str()).or_insert(0) += 1;
                        }
                    }
                    for identity in cohort {
                        compared += 1;
                        let own = held.get(&identity.id).unwrap_or(&empty);
                        let peers = cohort.len() - 1;
                        let mut unusual: Vec<Share> = Vec::new();
                        let mut missing: Vec<Share> = Vec::new();
                        for (role_id, total) in &counts {
                            let holds = own.contains(*role_id);
                            let peers_holding = total - usize::from(holds);
                            let fraction = peers_holding as f64 / peers as f64;
                            let role = role_ref(role_id);
                            let entry = Share {
                                name: js_string(role.get("name")),
                                role,
                                peers_holding,
                                share: round(fraction),
                            };
                            if holds && fraction < threshold {
                                unusual.push(entry);
                            } else if !holds && fraction >= common_share {
                                missing.push(entry);
                            }
                        }
                        if unusual.is_empty() && missing.is_empty() {
                            continue;
                        }
                        unusual.sort_by(by_share);
                        missing.sort_by(|a, b| by_share(a, b).reverse());
                        let name = label(identity);
                        outliers.push(Outlier {
                            identity: reference(&identity.id, &name),
                            name,
                            peer_value: value.clone(),
                            peers,
                            unusual,
                            missing,
                        });
                    }
                }
                outliers.sort_by(|a, b| {
                    b.unusual
                        .len()
                        .cmp(&a.unusual.len())
                        .then_with(|| b.missing.len().cmp(&a.missing.len()))
                        .then_with(|| locale_compare(&a.name, &b.name))
                });
                Ok(json!({
                    "generatedAt": crate::js::number(ctx.now()),
                    "peerBy": peer_by_ref,
                    "identitiesCompared": compared,
                    "outliers": outliers
                        .iter()
                        .map(|outlier| json!({
                            "identity": outlier.identity,
                            "peerValue": outlier.peer_value,
                            "peers": outlier.peers,
                            "unusualRoles": outlier.unusual.iter().map(Share::to_json).collect::<Vec<_>>(),
                            "missingRoles": outlier.missing.iter().map(Share::to_json).collect::<Vec<_>>(),
                        }))
                        .collect::<Vec<_>>(),
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

    /// `roleMining/reviewRecommendations`: suggested decisions for an access-certification campaign's items:
    /// `revoke` when the person is no longer active or did not use the role within `unusedDays` (default 90;
    /// recorded usage when it covers the window, otherwise their last sign-in), `keep` when they did, and `none` for
    /// group items and when there is no evidence. Reviewers still decide. Requires iam:analysis:read.
    pub async fn review_recommendations(
        &self,
        credential: &CredentialInput,
        input: Body<role_mining::ReviewRecommendationsInput>,
    ) -> IamResult<Reply<role_mining::ReviewRecommendationsOutput>> {
        let ctx = &self.ctx;
        let unused_days = integer(
            Some(&or_default(input.get("unusedDays"), 90.0)),
            "unusedDays",
            1.0,
            3650.0,
        )?;
        let campaign_id = text(input.get("campaignId"), "campaignId", 256)?;
        let usage = ctx.usage()?;
        if usage.enabled() {
            usage.flush().await?;
        }
        let campaign_ref = &campaign_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                ctx.scoped(
                    &tx,
                    "certificationCampaigns",
                    Some(&Value::String(campaign_ref.clone())),
                    &tenant.id,
                )
                .await?;
                let mut items = find_records(
                    &tx,
                    "certificationItems",
                    Filter::new()
                        .eq("tenantId", tenant.id.as_str())
                        .eq("campaignId", campaign_ref.as_str()),
                )
                .await?;
                let now = ctx.now();
                let since = now - unused_days * DAY_MS;
                let tracking = tx.get("accessUsageTracking", &tenant.id).await?;
                let usage_complete = tracking.as_ref().is_some_and(|tracking| {
                    tracking
                        .get("startedAt")
                        .map(better_iam_core::js::to_number)
                        .unwrap_or(f64::NAN)
                        <= since
                });
                let data = snapshot(ctx, &tx, &tenant.id).await?;
                let known = known_actions(ctx, &tx, &tenant.id).await?;
                let days = format!(
                    "{} day{}",
                    crate::js::number_to_string(unused_days),
                    if unused_days == 1.0 { "" } else { "s" }
                );
                let mut recommendations: Vec<Value> = Vec::new();
                items.sort_by(|a, b| locale_compare(record_str(a, "id"), record_str(b, "id")));
                for item in &items {
                    let item_id = item.get("id").cloned().unwrap_or(Value::Null);
                    if item.get("subjectType").and_then(Value::as_str) != Some("identity") {
                        recommendations.push(json!({
                            "itemId": item_id,
                            "recommendation": "none",
                            "reason": "A group's binding; review who belongs to the group instead.",
                        }));
                        continue;
                    }
                    let identity: Option<Identity> =
                        match tx.get("identities", record_str(item, "subjectId")).await? {
                            Some(record) => Some(decode(record)?),
                            None => None,
                        };
                    let identity = match identity {
                        Some(identity)
                            if identity.status == IdentityStatus::Active
                                && !ctx.identity_expired(&identity) =>
                        {
                            identity
                        }
                        other => {
                            let reason = match other {
                                Some(identity) => format!(
                                    "The account is {}.",
                                    if identity.status == IdentityStatus::Active {
                                        "expired".to_owned()
                                    } else {
                                        status_name(identity.status)
                                    }
                                ),
                                None => "The account no longer exists.".to_owned(),
                            };
                            recommendations.push(json!({
                                "itemId": item_id,
                                "recommendation": "revoke",
                                "basis": "status",
                                "reason": reason,
                            }));
                            continue;
                        }
                    };
                    if usage_complete {
                        let actions: IndexSet<String> = match data
                            .role_by_id
                            .get(record_str(item, "roleId"))
                        {
                            Some(role) => role_actions(&data, role, &known).into_iter().collect(),
                            None => IndexSet::new(),
                        };
                        let mut used: Vec<AccessUsageRecord> = Vec::new();
                        for record in find_records(
                            &tx,
                            "accessUsage",
                            Filter::new()
                                .eq("tenantId", tenant.id.as_str())
                                .eq("identityId", identity.id.as_str()),
                        )
                        .await?
                        {
                            let record: AccessUsageRecord = decode(record)?;
                            if actions.contains(&record.action) && record.last_used_at >= since {
                                used.push(record);
                            }
                        }
                        let last = max_from_zero(used.iter().map(|record| record.last_used_at));
                        recommendations.push(if !used.is_empty() {
                            json!({
                                "itemId": item_id,
                                "recommendation": "keep",
                                "basis": "usage",
                                "reason": format!("Used {} of the role's actions in the last {days}.", used.len()),
                                "lastUsedAt": crate::js::number(last),
                            })
                        } else {
                            json!({
                                "itemId": item_id,
                                "recommendation": "revoke",
                                "basis": "usage",
                                "reason": format!("None of the role's actions were used in the last {days}."),
                            })
                        });
                        continue;
                    }
                    if identity.kind != IdentityKind::User {
                        recommendations.push(json!({
                            "itemId": item_id,
                            "recommendation": "none",
                            "reason": "Service accounts do not sign in; enable access usage tracking for evidence.",
                        }));
                        continue;
                    }
                    let sign_ins = find_records(
                        &tx,
                        "audit",
                        Filter::new()
                            .eq("tenantId", tenant.id.as_str())
                            .eq("actorId", identity.id.as_str())
                            .eq("action", "auth:session:create"),
                    )
                    .await?;
                    // An administrator's "view as" session is recorded on the member but is not the member signing
                    // in.
                    let last = max_from_zero(
                        sign_ins
                            .iter()
                            .filter(|event| !truthy(event.get("impersonatorId")))
                            .map(|event| match event.get("timestamp") {
                                Some(value) => better_iam_core::js::to_number(value),
                                None => f64::NAN,
                            }),
                    );
                    recommendations.push(if last >= since {
                        json!({
                            "itemId": item_id,
                            "recommendation": "keep",
                            "basis": "sign-in",
                            "reason": format!("Signed in within the last {days}."),
                            "lastUsedAt": crate::js::number(last),
                        })
                    } else {
                        json!({
                            "itemId": item_id,
                            "recommendation": "revoke",
                            "basis": "sign-in",
                            "reason": if last != 0.0 && !last.is_nan() {
                                format!("No sign-in in the last {days}.")
                            } else {
                                "Has never signed in.".to_owned()
                            },
                        })
                    });
                }
                Ok(json!({
                    "campaignId": campaign_ref,
                    "unusedDays": crate::js::number(unused_days),
                    "usageComplete": usage_complete,
                    "recommendations": recommendations,
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

    /// `roleMining/rightSize`: least-privilege right-sizing from recorded usage: every live binding whose holder used
    /// none (`unused`) or only some (`partial`) of the role's actions within `unusedDays` (default 90), plus per role
    /// the actions no holder used. `complete` is false until usage has been recorded for the whole window. Requires
    /// iam:analysis:read.
    pub async fn right_size(
        &self,
        credential: &CredentialInput,
        input: Body<role_mining::RightSizeInput>,
    ) -> IamResult<Reply<role_mining::RightSizeOutput>> {
        let ctx = &self.ctx;
        let unused_days = integer(
            Some(&or_default(input.get("unusedDays"), 90.0)),
            "unusedDays",
            1.0,
            3650.0,
        )?;
        let usage = ctx.usage()?;
        if usage.enabled() {
            usage.flush().await?;
        }
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let data = snapshot(ctx, &tx, &tenant.id).await?;
                let now = ctx.now();
                let since = now - unused_days * DAY_MS;
                let tracking = tx.get("accessUsageTracking", &tenant.id).await?;
                let mut used: IndexMap<String, IndexMap<String, f64>> = IndexMap::new();
                for record in find_records(
                    &tx,
                    "accessUsage",
                    Filter::new().eq("tenantId", tenant.id.as_str()),
                )
                .await?
                {
                    let record: AccessUsageRecord = decode(record)?;
                    if record.last_used_at < since {
                        continue;
                    }
                    used.entry(record.identity_id)
                        .or_default()
                        .insert(record.action, record.last_used_at);
                }
                let mut known = known_actions(ctx, &tx, &tenant.id).await?;
                crate::js::sort_strings(&mut known);
                let mut granted: IndexMap<String, Vec<String>> = IndexMap::new();
                let mut actions_of = |role: &Role| -> Vec<String> {
                    granted
                        .entry(role.id.clone())
                        .or_insert_with(|| role_actions(&data, role, &known))
                        .clone()
                };
                let group_by_id: IndexMap<&str, &Record> = data
                    .groups
                    .iter()
                    .map(|group| (group_id(group), group))
                    .collect();
                struct Entry {
                    json: Value,
                    unused: bool,
                    identity_name: String,
                    role_name: String,
                }
                let mut entries: Vec<Entry> = Vec::new();
                let mut role_holders: IndexMap<String, IndexSet<String>> = IndexMap::new();
                let mut role_used: IndexMap<String, IndexSet<String>> = IndexMap::new();
                for binding in &data.bindings {
                    let Some(role) = data.role_by_id.get(&binding.role_id) else {
                        continue;
                    };
                    if data.protected(&role.id) {
                        continue;
                    }
                    let actions = actions_of(role);
                    if actions.is_empty() {
                        continue;
                    }
                    let group = if binding.subject_type == "group" {
                        group_by_id.get(binding.subject_id.as_str()).copied()
                    } else {
                        None
                    };
                    let holders: Vec<&str> = if binding.subject_type == "identity" {
                        vec![binding.subject_id.as_str()]
                    } else {
                        data.members
                            .iter()
                            .filter(|member| member.group_id == binding.subject_id)
                            .map(|member| member.identity_id.as_str())
                            .collect()
                    };
                    for identity_id in holders {
                        let Some(identity) = data.identity_by_id.get(identity_id) else {
                            continue;
                        };
                        let mine = used.get(identity_id);
                        let has =
                            |action: &String| mine.is_some_and(|mine| mine.contains_key(action));
                        let used_actions: Vec<String> = actions
                            .iter()
                            .filter(|action| has(action))
                            .cloned()
                            .collect();
                        role_holders
                            .entry(role.id.clone())
                            .or_default()
                            .insert(identity_id.to_owned());
                        let used_set = role_used.entry(role.id.clone()).or_default();
                        for action in &used_actions {
                            used_set.insert(action.clone());
                        }
                        if used_actions.len() == actions.len() {
                            continue;
                        }
                        let unused: Vec<String> = actions
                            .iter()
                            .filter(|action| !has(action))
                            .cloned()
                            .collect();
                        let last = max_from_zero(used_actions.iter().map(|action| {
                            mine.and_then(|mine| mine.get(action))
                                .copied()
                                .unwrap_or(f64::NAN)
                        }));
                        let name = label(identity);
                        let mut entry = Map::new();
                        entry.insert("identity".into(), reference(&identity.id, &name));
                        entry.insert("role".into(), reference(&role.id, &role.name));
                        entry.insert("bindingId".into(), json!(binding.id));
                        entry.insert(
                            "via".into(),
                            match group {
                                Some(group) => json!({
                                    "type": "group",
                                    "id": group.get("id").cloned().unwrap_or(Value::Null),
                                    "name": group.get("name").cloned().unwrap_or(Value::Null),
                                }),
                                None => json!({ "type": "identity" }),
                            },
                        );
                        entry.insert("eligible".into(), json!(binding.eligible == Some(true)));
                        entry.insert(
                            "status".into(),
                            json!(if used_actions.is_empty() {
                                "unused"
                            } else {
                                "partial"
                            }),
                        );
                        entry.insert("grantedActions".into(), json!(actions.len()));
                        entry.insert("usedActions".into(), json!(used_actions));
                        entry.insert(
                            "unusedActions".into(),
                            json!(unused.iter().take(50).collect::<Vec<_>>()),
                        );
                        entry.insert("unusedCount".into(), json!(unused.len()));
                        if last != 0.0 && !last.is_nan() {
                            entry.insert("lastUsedAt".into(), crate::js::number(last));
                        }
                        entries.push(Entry {
                            json: Value::Object(entry),
                            unused: used_actions.is_empty(),
                            identity_name: name,
                            role_name: role.name.clone(),
                        });
                    }
                }
                entries.sort_by(|a, b| {
                    let rank = |entry: &Entry| if entry.unused { 0 } else { 1 };
                    rank(a)
                        .cmp(&rank(b))
                        .then_with(|| locale_compare(&a.identity_name, &b.identity_name))
                        .then_with(|| locale_compare(&a.role_name, &b.role_name))
                });
                struct Summary {
                    json: Value,
                    never_used_count: usize,
                    name: String,
                }
                let mut roles: Vec<Summary> = Vec::new();
                let no_actions: IndexSet<String> = IndexSet::new();
                for (role_id, holders) in &role_holders {
                    let Some(role) = data.role_by_id.get(role_id) else {
                        continue;
                    };
                    let actions = actions_of(role);
                    let used_set = role_used.get(role_id).unwrap_or(&no_actions);
                    let never_used: Vec<&String> = actions
                        .iter()
                        .filter(|action| !used_set.contains(*action))
                        .collect();
                    roles.push(Summary {
                        json: json!({
                            "role": reference(&role.id, &role.name),
                            "holders": holders.len(),
                            "grantedActions": actions.len(),
                            "usedActions": actions
                                .iter()
                                .filter(|action| used_set.contains(*action))
                                .collect::<Vec<_>>(),
                            "neverUsed": never_used.iter().take(100).collect::<Vec<_>>(),
                            "neverUsedCount": never_used.len(),
                        }),
                        never_used_count: never_used.len(),
                        name: role.name.clone(),
                    });
                }
                roles.sort_by(|a, b| {
                    b.never_used_count
                        .cmp(&a.never_used_count)
                        .then_with(|| locale_compare(&a.name, &b.name))
                });
                let started_at = tracking.as_ref().map(|tracking| {
                    tracking
                        .get("startedAt")
                        .map(better_iam_core::js::to_number)
                        .unwrap_or(f64::NAN)
                });
                let mut out = Map::new();
                out.insert("generatedAt".into(), crate::js::number(now));
                out.insert("unusedDays".into(), crate::js::number(unused_days));
                out.insert("tracking".into(), json!(ctx.usage()?.enabled()));
                if let Some(started) = tracking
                    .as_ref()
                    .and_then(|tracking| tracking.get("startedAt"))
                {
                    out.insert("trackingSince".into(), started.clone());
                }
                out.insert(
                    "complete".into(),
                    json!(started_at.is_some_and(|started| started <= since)),
                );
                out.insert(
                    "entries".into(),
                    Value::Array(entries.into_iter().map(|entry| entry.json).collect()),
                );
                out.insert(
                    "roles".into(),
                    Value::Array(roles.into_iter().map(|summary| summary.json).collect()),
                );
                Ok(Value::Object(out))
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

    /// `roleMining/suggest`: lists suggestions, most actionable first. `minIdentities` (default 3) is how many people
    /// must share a pattern; `minRoles` (default 2) the smallest role combination reported as a bundle; `limit` caps
    /// the list.
    pub async fn suggest(
        &self,
        credential: &CredentialInput,
        input: Body<role_mining::SuggestInput>,
    ) -> IamResult<Reply<role_mining::SuggestOutput>> {
        let ctx = &self.ctx;
        let settings = settings_of(&input)?;
        let limit = integer(
            Some(&or_default(input.get("limit"), 50.0)),
            "limit",
            1.0,
            500.0,
        )?;
        let kinds = kind_filter(input.get("kinds"))?;
        if kinds
            .as_ref()
            .is_some_and(|kinds| kinds.keys.iter().any(|kind| !known_kind(kind)))
        {
            return Err(IamError::new("INVALID_INPUT", "Unknown suggestion kind"));
        }
        let settings = &settings;
        let kinds = &kinds;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let mined = mine(&snapshot(ctx, &tx, &tenant.id).await?, settings)?;
                let mut all: Vec<Suggestion> = mined
                    .suggestions
                    .into_iter()
                    .filter(|suggestion| {
                        kinds
                            .as_ref()
                            .is_none_or(|kinds| kinds.matches.contains(suggestion.kind))
                    })
                    .collect();
                let mut summary: IndexMap<&str, usize> = IndexMap::new();
                for kind in [
                    "bundle",
                    "group-binding",
                    "redundant-binding",
                    "duplicate-roles",
                ] {
                    summary.insert(kind, 0);
                }
                for suggestion in &all {
                    *summary.entry(suggestion.kind).or_insert(0) += 1;
                }
                all.sort_by(|a, b| {
                    kind_rank(a.kind)
                        .cmp(&kind_rank(b.kind))
                        .then_with(|| b.savings.cmp(&a.savings))
                        .then_with(|| locale_compare(&a.id, &b.id))
                });
                let mut out = Map::new();
                out.insert("generatedAt".into(), crate::js::number(ctx.now()));
                out.insert("summary".into(), json!(summary));
                out.insert(
                    "suggestions".into(),
                    Value::Array(
                        all.iter()
                            .take(limit as usize)
                            .map(Suggestion::to_json)
                            .collect(),
                    ),
                );
                if mined.bundles_truncated
                    && kinds
                        .as_ref()
                        .is_none_or(|kinds| kinds.matches.contains("bundle"))
                {
                    out.insert("bundlesTruncated".into(), json!(true));
                }
                Ok(Value::Object(out))
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

    /// `roleMining/usage`: recorded access usage (`accessUsage` option): per identity and action, when it was first
    /// and last allowed and how often, newest first. Buffered usage is written first. Requires iam:analysis:read.
    pub async fn usage(
        &self,
        credential: &CredentialInput,
        input: Body<role_mining::UsageInput>,
    ) -> IamResult<Reply<role_mining::UsageOutput>> {
        let ctx = &self.ctx;
        let limit = integer(
            Some(&or_default(input.get("limit"), 100.0)),
            "limit",
            1.0,
            1000.0,
        )?;
        let offset = integer(
            Some(&or_default(input.get("offset"), 0.0)),
            "offset",
            0.0,
            1_000_000.0,
        )?;
        let identity_id = match input.get("identityId") {
            None => None,
            Some(value) => Some(text(Some(value), "identityId", 256)?),
        };
        let usage = ctx.usage()?;
        if usage.enabled() {
            usage.flush().await?;
        }
        let identity_ref = &identity_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let tracking = tx.get("accessUsageTracking", &tenant.id).await?;
                let mut filter = Filter::new().eq("tenantId", tenant.id.as_str());
                if let Some(identity_id) = identity_ref.as_deref().filter(|id| !id.is_empty()) {
                    filter = filter.eq("identityId", identity_id);
                }
                let mut records: Vec<AccessUsageRecord> = find_records(&tx, "accessUsage", filter)
                    .await?
                    .into_iter()
                    .map(decode)
                    .collect::<IamResult<_>>()?;
                records.sort_by(|a, b| {
                    number_order(b.last_used_at - a.last_used_at)
                        .then_with(|| locale_compare(&a.identity_id, &b.identity_id))
                        .then_with(|| locale_compare(&a.action, &b.action))
                });
                let mut out = Map::new();
                out.insert("tracking".into(), json!(ctx.usage()?.enabled()));
                if let Some(started) = tracking
                    .as_ref()
                    .and_then(|tracking| tracking.get("startedAt"))
                {
                    out.insert("trackingSince".into(), started.clone());
                }
                out.insert("total".into(), json!(records.len()));
                out.insert(
                    "records".into(),
                    Value::Array(
                        records
                            .iter()
                            .skip(offset as usize)
                            .take(limit as usize)
                            .map(|record| {
                                json!({
                                    "identityId": record.identity_id,
                                    "action": record.action,
                                    "firstUsedAt": crate::js::number(record.first_used_at),
                                    "lastUsedAt": crate::js::number(record.last_used_at),
                                    "count": crate::js::number(record.count),
                                })
                            })
                            .collect(),
                    ),
                );
                Ok(Value::Object(out))
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
}
