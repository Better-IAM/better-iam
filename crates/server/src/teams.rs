//! Port of `packages/server/src/teams.ts`.
//!
//! Teams inside an organization: named groups of people with maintainers who manage the membership themselves,
//! nested under parent teams, optionally in a department. Every team owns a backing group (`Team.groupId`, marked
//! with `Group.teamId`) whose memberships this module writes: a team's backing group holds its own live members and
//! those of every descendant team, so a child team's members receive whatever is bound to the parent team. Role
//! bindings, relationships, separation of duties, reviews and analysis all read ordinary group memberships and need
//! nothing else.

use std::collections::VecDeque;
use std::sync::{Arc, LazyLock};

use better_iam_core::{Filter, FindOptions, IamError, IamResult, Identity, Record, record_id};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use unicode_normalization::UnicodeNormalization;

use crate::context::{ServerContext, Store};
use crate::js::{defined, js_string, member, number, truthy};
use crate::models::{Binding, GroupMember};
use crate::port::decode;
use crate::utils::{date_now, id};

/// The `teams` collection.
pub const TEAMS: &str = "teams";
/// The `teamMembers` collection.
pub const TEAM_MEMBERS: &str = "teamMembers";
/// The `teamJoinRequests` collection.
pub const TEAM_JOIN_REQUESTS: &str = "teamJoinRequests";

/// A team; slugs are unique per tenant (uniqueKey `slug:{slug}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Team {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "slug")]
    pub slug: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    /// The parent team: this team's members also belong to it (and receive what is bound to it).
    #[serde(rename = "parentId", default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// The department the team belongs to (departments.ts); informational and used for roll-ups.
    #[serde(
        rename = "departmentId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub department_id: Option<String>,
    /// The team-managed backing group; bind roles to it (`subjectType: 'group'`) to give the team access.
    #[serde(rename = "groupId")]
    pub group_id: String,
    #[serde(rename = "joinPolicy")]
    pub join_policy: crate::teams::TeamJoinPolicy,
    #[serde(rename = "memberManagement")]
    pub member_management: crate::teams::TeamMemberManagement,
    /// Team sync: ordinary groups (such as SCIM-provisioned directory groups) whose members are kept as members of the
    /// team (`syncTeamsFromGroups`). Synced memberships carry `source: 'sync'`; people added by hand are never touched.
    #[serde(
        rename = "syncGroupIds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sync_group_ids: Option<Vec<String>>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamGroupSyncResult {
    #[serde(rename = "added")]
    pub added: f64,
    #[serde(rename = "removed")]
    pub removed: f64,
    #[serde(rename = "updated")]
    pub updated: f64,
    /// Teams whose membership changed.
    #[serde(rename = "teams")]
    pub teams: Vec<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// How members join: only by being added (`closed`), or by asking a maintainer (`request`).
/// TODO(port): a union or intersection type in TypeScript; JSON until ported.
pub type TeamJoinPolicy = Value;

/// A person's request to join a team whose join policy is `request`; `expiresAt` is when a pending request lapses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamJoinRequest {
    #[serde(rename = "teamId")]
    pub team_id: String,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    #[serde(rename = "status")]
    pub status: crate::teams::TeamJoinRequestStatus,
    #[serde(rename = "requestedAt")]
    pub requested_at: f64,
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    #[serde(
        rename = "justification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub justification: Option<String>,
    #[serde(rename = "decidedBy", default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    #[serde(rename = "decidedAt", default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<f64>,
    #[serde(rename = "note", default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// TODO(port): a union or intersection type in TypeScript; JSON until ported.
pub type TeamJoinRequestStatus = Value;

/// One person's direct membership of one team (uniqueKey `{teamId}:{identityId}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamMember {
    #[serde(rename = "teamId")]
    pub team_id: String,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    #[serde(rename = "role")]
    pub role: crate::teams::TeamRole,
    #[serde(rename = "addedAt")]
    pub added_at: f64,
    #[serde(rename = "addedBy")]
    pub added_by: String,
    /// Temporary membership: past this time the person no longer belongs (the backing group membership ends with it).
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    /// `sync` when team sync added the person from a source group (then it also removes them); absent for manual
    /// members.
    #[serde(rename = "source", default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Who manages membership: the team's maintainers as well as administrators, or administrators only.
/// TODO(port): a union or intersection type in TypeScript; JSON until ported.
pub type TeamMemberManagement = Value;

/// A maintainer manages the team's membership (and that of its descendant teams); a member only belongs.
/// TODO(port): a union or intersection type in TypeScript; JSON until ported.
pub type TeamRole = Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamSyncResult {
    #[serde(rename = "added")]
    pub added: f64,
    #[serde(rename = "removed")]
    pub removed: f64,
    #[serde(rename = "updated")]
    pub updated: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Collections owned by the teams module.
pub static TEAM_COLLECTIONS: LazyLock<Value> = LazyLock::new(
    || json!({"teams":"teams","members":"teamMembers","requests":"teamJoinRequests"}),
);

/// Deepest team nesting (a team and nine levels of ancestors).
pub const MAX_TEAM_DEPTH: f64 = 10.0;

/// Teams per tenant.
pub const MAX_TEAMS: f64 = 1000.0;

/// At most this many source groups per team.
pub const MAX_SYNC_GROUPS: f64 = 10.0;

static SLUG_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$").expect("slug pattern"));
static MARKS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\p{M}").expect("marks pattern"));
static NOT_SLUG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-z0-9]+").expect("pattern"));
static EDGE_HYPHENS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^-+|-+$").expect("pattern"));
static TRAILING_HYPHENS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"-+$").expect("pattern"));

async fn find(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

fn str_of<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

fn num_of(record: &Record, key: &str) -> Option<f64> {
    record.get(key).and_then(better_iam_core::js::as_number)
}

/// A team slug: 1-64 lowercase letters, digits or inner hyphens.
pub fn team_slug(value: Option<&Value>) -> IamResult<String> {
    match value {
        Some(Value::String(slug)) if SLUG_PATTERN.is_match(slug) => Ok(slug.clone()),
        _ => Err(IamError::new(
            "INVALID_INPUT",
            "slug must use 1-64 lowercase letters, digits, or inner hyphens",
        )),
    }
}

/// A slug derived from a team name ("Platform Team" → `platform-team`), or undefined when nothing usable is left.
pub fn slug_from_name(name: &str) -> IamResult<Option<String>> {
    Ok(slug_of(name))
}

/// [`slug_from_name`] without the `Result` (it cannot fail).
pub fn slug_of(name: &str) -> Option<String> {
    let decomposed: String = name.nfkd().collect();
    let stripped = MARKS.replace_all(&decomposed, "");
    let lowered = stripped.to_lowercase();
    let hyphenated = NOT_SLUG.replace_all(&lowered, "-");
    let trimmed = EDGE_HYPHENS.replace_all(&hyphenated, "");
    // Only ASCII is left, so slicing by bytes equals slicing by UTF-16 code units.
    let sliced: String = trimmed.chars().take(64).collect();
    let candidate = TRAILING_HYPHENS.replace_all(&sliced, "").into_owned();
    if !candidate.is_empty() && SLUG_PATTERN.is_match(&candidate) {
        Some(candidate)
    } else {
        None
    }
}

/// Whether a direct membership counts at `at` (no expiry, or one still ahead).
pub fn live_team_member(member: &crate::teams::TeamMember, at: f64) -> IamResult<bool> {
    Ok(live_member(member, at))
}

/// [`live_team_member`] without the `Result` (it cannot fail).
pub fn live_member(member: &TeamMember, at: f64) -> bool {
    member.expires_at.is_none_or(|expires| expires > at)
}

/// Loads a team of the tenant or fails with NOT_FOUND.
pub async fn load_team(
    tx: &Store,
    tenant_id: &str,
    team_id: Option<&Value>,
) -> IamResult<crate::teams::Team> {
    let team_id = match team_id {
        Some(Value::String(id)) if !id.is_empty() => id,
        _ => return Err(IamError::new("INVALID_INPUT", "Invalid teamId")),
    };
    match tx.get(TEAMS, team_id).await? {
        Some(record) if str_of(&record, "tenantId") == Some(tenant_id) => decode(record),
        _ => Err(IamError::with_status("NOT_FOUND", "Team not found", 404)),
    }
}

/// The team followed by its ancestors, nearest first; tolerant of a missing parent (the chain stops there).
pub fn team_chain(
    teams: &IndexMap<String, crate::teams::Team>,
    team_id: &str,
) -> IamResult<Vec<crate::teams::Team>> {
    Ok(team_chain_of(teams, team_id))
}

/// [`team_chain`] without the `Result` (it cannot fail).
pub fn team_chain_of(teams: &IndexMap<String, Team>, team_id: &str) -> Vec<Team> {
    let mut chain: Vec<Team> = Vec::new();
    let mut seen: IndexSet<String> = IndexSet::new();
    let mut current = teams.get(team_id);
    while let Some(team) = current {
        if seen.contains(&team.id) || chain.len() as f64 > MAX_TEAM_DEPTH {
            break;
        }
        chain.push(team.clone());
        seen.insert(team.id.clone());
        current = team
            .parent_id
            .as_deref()
            .filter(|parent| !parent.is_empty())
            .and_then(|parent| teams.get(parent));
    }
    chain
}

/// Decodes a JSON array (or object of records) of teams, as the iterables TypeScript passes.
fn teams_from(value: &Value) -> IamResult<Vec<Team>> {
    let items: Vec<&Value> = match value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(map) => map.values().collect(),
        _ => Vec::new(),
    };
    items
        .into_iter()
        .map(|item| match item {
            Value::Object(record) => decode(record.clone()),
            _ => decode(Record::new()),
        })
        .collect()
}

/// Every team below `teamId` (children, grandchildren, …), not including the team itself. `teams` is a JSON array
/// of team records (any iterable of teams in TypeScript); [`team_descendants_of`] takes them typed.
pub fn team_descendants(teams: &Value, team_id: &str) -> IamResult<Vec<crate::teams::Team>> {
    let list = teams_from(teams)?;
    Ok(team_descendants_of(list.iter(), team_id))
}

/// [`team_descendants`] over typed teams.
pub fn team_descendants_of<'a>(
    teams: impl IntoIterator<Item = &'a Team>,
    team_id: &str,
) -> Vec<Team> {
    let mut children: IndexMap<String, Vec<Team>> = IndexMap::new();
    for team in teams {
        if let Some(parent) = team.parent_id.as_deref().filter(|id| !id.is_empty()) {
            children
                .entry(parent.to_owned())
                .or_default()
                .push(team.clone());
        }
    }
    let mut result: Vec<Team> = Vec::new();
    let mut seen: IndexSet<String> = IndexSet::from([team_id.to_owned()]);
    let mut queue: VecDeque<Team> = children.get(team_id).cloned().unwrap_or_default().into();
    while let Some(next) = queue.pop_front() {
        if seen.contains(&next.id) {
            continue;
        }
        seen.insert(next.id.clone());
        if let Some(below) = children.get(&next.id) {
            queue.extend(below.iter().cloned());
        }
        result.push(next);
    }
    result
}

/// The tenant's teams by ID.
pub async fn tenant_teams(tx: &Store, tenant_id: &str) -> IamResult<IndexMap<String, Team>> {
    let mut teams = IndexMap::new();
    for record in find(tx, TEAMS, Filter::new().eq("tenantId", tenant_id)).await? {
        let team: Team = decode(record)?;
        teams.insert(team.id.clone(), team);
    }
    Ok(teams)
}

async fn team_members(tx: &Store, filter: Filter) -> IamResult<Vec<TeamMember>> {
    find(tx, TEAM_MEMBERS, filter)
        .await?
        .into_iter()
        .map(decode)
        .collect()
}

/// `{ at?: number; includeAncestors?: boolean }` read from JSON.
fn at_option(options: Option<&Value>) -> Option<f64> {
    defined(member(options, "at")).and_then(better_iam_core::js::as_number)
}

/// The teams a person belongs to at `at` (default now): their live direct memberships (oldest first) and, with
/// `includeAncestors`, the parent teams those memberships make them part of. Team IDs, never backing group IDs.
/// There is no membership history, so callers that attribute something to teams should call this when it happens.
pub async fn teams_of(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    options: Option<&Value>,
) -> IamResult<Vec<String>> {
    teams_of_at(
        tx,
        tenant_id,
        identity_id,
        at_option(options),
        truthy(member(options, "includeAncestors")),
    )
    .await
}

/// [`teams_of`] with typed options.
pub async fn teams_of_at(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    at: Option<f64>,
    include_ancestors: bool,
) -> IamResult<Vec<String>> {
    let at = at.unwrap_or_else(date_now);
    let mut direct: Vec<TeamMember> = team_members(
        tx,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("identityId", identity_id),
    )
    .await?
    .into_iter()
    .filter(|member| live_member(member, at))
    .collect();
    direct.sort_by(|a, b| {
        a.added_at
            .partial_cmp(&b.added_at)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| better_iam_core::js::cmp_utf16(&a.team_id, &b.team_id))
    });
    if direct.is_empty() {
        return Ok(Vec::new());
    }
    let teams = tenant_teams(tx, tenant_id).await?;
    let ids: Vec<String> = direct
        .into_iter()
        .map(|member| member.team_id)
        .filter(|team_id| teams.contains_key(team_id))
        .collect();
    if !include_ancestors {
        return Ok(ids);
    }
    let mut result: IndexSet<String> = ids.iter().cloned().collect();
    for team_id in &ids {
        for team in team_chain_of(&teams, team_id) {
            result.insert(team.id);
        }
    }
    Ok(result.into_iter().collect())
}

/// The person's oldest live direct team membership, for callers that attribute to one team only.
pub async fn primary_team_of(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    at: Option<f64>,
) -> IamResult<Option<String>> {
    Ok(teams_of_at(tx, tenant_id, identity_id, at, false)
        .await?
        .into_iter()
        .next())
}

/// The live direct maintainers of a team (identity IDs, oldest first).
pub async fn team_maintainers(
    tx: &Store,
    tenant_id: &str,
    team_id: &str,
    at: Option<f64>,
) -> IamResult<Vec<String>> {
    let at = at.unwrap_or_else(date_now);
    let mut maintainers: Vec<TeamMember> = team_members(
        tx,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("teamId", team_id),
    )
    .await?
    .into_iter()
    .filter(|member| member.role == "maintainer" && live_member(member, at))
    .collect();
    maintainers.sort_by(|a, b| {
        a.added_at
            .partial_cmp(&b.added_at)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| better_iam_core::js::cmp_utf16(&a.identity_id, &b.identity_id))
    });
    Ok(maintainers
        .into_iter()
        .map(|member| member.identity_id)
        .collect())
}

/// Whether a person maintains a team: a live maintainer membership of the team itself or, with `includeAncestors`,
/// of any team above it (a parent team's maintainers manage its child teams too).
pub async fn is_team_maintainer(
    tx: &Store,
    tenant_id: &str,
    team_id: &str,
    identity_id: &str,
    options: Option<&Value>,
) -> IamResult<bool> {
    is_team_maintainer_at(
        tx,
        tenant_id,
        team_id,
        identity_id,
        at_option(options),
        truthy(member(options, "includeAncestors")),
    )
    .await
}

/// [`is_team_maintainer`] with typed options.
pub async fn is_team_maintainer_at(
    tx: &Store,
    tenant_id: &str,
    team_id: &str,
    identity_id: &str,
    at: Option<f64>,
    include_ancestors: bool,
) -> IamResult<bool> {
    let at = at.unwrap_or_else(date_now);
    let memberships: Vec<TeamMember> = team_members(
        tx,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("identityId", identity_id),
    )
    .await?
    .into_iter()
    .filter(|member| member.role == "maintainer" && live_member(member, at))
    .collect();
    if memberships.is_empty() {
        return Ok(false);
    }
    let scope: Vec<String> = if include_ancestors {
        team_chain_of(&tenant_teams(tx, tenant_id).await?, team_id)
            .into_iter()
            .map(|team| team.id)
            .collect()
    } else {
        vec![team_id.to_owned()]
    };
    Ok(memberships
        .iter()
        .any(|member| scope.contains(&member.team_id)))
}

/// Refuses direct membership changes to a team's backing group: its members come from the team (TEAM_MANAGED).
pub fn assert_not_team_group(group: Option<&Value>) -> IamResult<()> {
    if matches!(member(group, "teamId"), Some(Value::String(_))) {
        return Err(IamError::with_status(
            "TEAM_MANAGED",
            "This group belongs to a team; manage its members with the teams API",
            409,
        ));
    }
    Ok(())
}

/// Whether a group is a team's backing group.
pub fn is_team_group(group: Option<&Value>) -> IamResult<bool> {
    Ok(matches!(member(group, "teamId"), Some(Value::String(_))))
}

/// Refuses when any of `groupIds` is a team's backing group (packages, invitations, onboarding grant real groups).
pub async fn assert_no_team_groups(tx: &Store, group_ids: &[String]) -> IamResult<()> {
    for group_id in group_ids {
        let group = tx.get("groups", group_id).await?.map(Value::Object);
        assert_not_team_group(group.as_ref())?;
    }
    Ok(())
}

/// Reads the string items of a JSON array (an iterable of IDs in TypeScript).
fn ids_from(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => text.clone(),
                other => js_string(Some(other)),
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Brings the backing groups of `teamIds` and of every team above them in line with team membership: a team's group
/// holds the live direct members of the team and of all its descendant teams (a permanent source wins over a
/// temporary one; otherwise the latest end counts). Deleted identities are left out. Removing a membership also
/// ends the person's activations of the group's eligible bindings, as `groups.removeMember` does. Idempotent.
/// `teamIds` is a JSON array of team IDs; [`sync_team_groups_of`] takes them typed.
pub async fn sync_team_groups(
    tx: &Store,
    tenant_id: &str,
    team_ids: &Value,
    now: f64,
) -> IamResult<crate::teams::TeamSyncResult> {
    sync_team_groups_of(tx, tenant_id, &ids_from(team_ids), now).await
}

/// [`sync_team_groups`] over typed team IDs.
pub async fn sync_team_groups_of(
    tx: &Store,
    tenant_id: &str,
    team_ids: &[String],
    now: f64,
) -> IamResult<TeamSyncResult> {
    let mut result = TeamSyncResult {
        added: 0.0,
        removed: 0.0,
        updated: 0.0,
        extra: Map::new(),
    };
    let teams = tenant_teams(tx, tenant_id).await?;
    let mut affected: IndexMap<String, Team> = IndexMap::new();
    for team_id in team_ids {
        for team in team_chain_of(&teams, team_id) {
            affected.insert(team.id.clone(), team);
        }
    }
    if affected.is_empty() {
        return Ok(result);
    }
    let members: Vec<TeamMember> = team_members(tx, Filter::new().eq("tenantId", tenant_id))
        .await?
        .into_iter()
        .filter(|member| live_member(member, now))
        .collect();
    let mut by_team: IndexMap<String, Vec<TeamMember>> = IndexMap::new();
    for member in members {
        by_team
            .entry(member.team_id.clone())
            .or_default()
            .push(member);
    }
    let mut usable: IndexMap<String, bool> = IndexMap::new();
    for team in affected.values() {
        // None means permanent.
        let mut desired: IndexMap<String, Option<f64>> = IndexMap::new();
        let mut sources = vec![team.clone()];
        sources.extend(team_descendants_of(teams.values(), &team.id));
        for source in &sources {
            for member in by_team.get(&source.id).map(Vec::as_slice).unwrap_or(&[]) {
                if !usable.contains_key(&member.identity_id) {
                    let identity = tx.get("identities", &member.identity_id).await?;
                    let ok = identity.as_ref().is_some_and(|identity| {
                        str_of(identity, "tenantId") == Some(tenant_id)
                            && str_of(identity, "status") != Some("deleted")
                    });
                    usable.insert(member.identity_id.clone(), ok);
                }
                if !usable[&member.identity_id] {
                    continue;
                }
                match desired.get(&member.identity_id).copied() {
                    None => {
                        desired.insert(member.identity_id.clone(), member.expires_at);
                    }
                    Some(Some(previous)) => {
                        desired.insert(
                            member.identity_id.clone(),
                            member.expires_at.map(|expires| previous.max(expires)),
                        );
                    }
                    Some(None) => {}
                }
            }
        }
        let Some(group) = tx.get("groups", &team.group_id).await? else {
            continue;
        };
        if str_of(&group, "tenantId") != Some(tenant_id) {
            continue;
        }
        let group_id = record_id(&group).to_owned();
        let current = find(
            tx,
            "groupMembers",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("groupId", group_id.as_str()),
        )
        .await?;
        let mut bindings: Option<Vec<Record>> = None;
        for mut membership in current {
            let identity_id = str_of(&membership, "identityId")
                .unwrap_or_default()
                .to_owned();
            if !desired.contains_key(&identity_id) {
                tx.delete("groupMembers", record_id(&membership)).await?;
                if bindings.is_none() {
                    bindings = Some(
                        find(
                            tx,
                            "bindings",
                            Filter::new()
                                .eq("tenantId", tenant_id)
                                .eq("subjectType", "group")
                                .eq("subjectId", group_id.as_str()),
                        )
                        .await?,
                    );
                }
                let bound = bindings.as_deref().unwrap_or(&[]);
                for activation in find(
                    tx,
                    "bindingActivations",
                    Filter::new()
                        .eq("tenantId", tenant_id)
                        .eq("identityId", identity_id.as_str()),
                )
                .await?
                {
                    let binding_id = str_of(&activation, "bindingId");
                    if bound
                        .iter()
                        .any(|binding| Some(record_id(binding)) == binding_id)
                    {
                        tx.delete("bindingActivations", record_id(&activation))
                            .await?;
                    }
                }
                result.removed += 1.0;
                continue;
            }
            let expires_at = desired.shift_remove(&identity_id).flatten();
            if num_of(&membership, "expiresAt") == expires_at
                && str_of(&membership, "teamId") == Some(team.id.as_str())
            {
                continue;
            }
            membership.shift_remove("expiresAt");
            membership.shift_remove("packageAssignmentId");
            membership.insert("teamId".into(), Value::String(team.id.clone()));
            if let Some(expires_at) = expires_at {
                membership.insert("expiresAt".into(), number(expires_at));
            }
            tx.put("groupMembers", &membership).await?;
            result.updated += 1.0;
        }
        for (identity_id, expires_at) in desired {
            let mut record = Record::new();
            record.insert("id".into(), Value::String(id()));
            record.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
            record.insert(
                "uniqueKey".into(),
                Value::String(format!("{group_id}:{identity_id}")),
            );
            record.insert("groupId".into(), Value::String(group_id.clone()));
            record.insert("identityId".into(), Value::String(identity_id));
            record.insert("teamId".into(), Value::String(team.id.clone()));
            if let Some(expires_at) = expires_at {
                record.insert("expiresAt".into(), number(expires_at));
            }
            tx.insert("groupMembers", &record).await?;
            result.added += 1.0;
        }
    }
    Ok(result)
}

/// Removes a person from every team of the tenant (offboarding, deletion) and from the teams' backing groups, and
/// cancels their pending join requests. Returns the number of team memberships removed.
pub async fn remove_from_all_teams(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    now: f64,
) -> IamResult<f64> {
    let memberships = find(
        tx,
        TEAM_MEMBERS,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("identityId", identity_id),
    )
    .await?;
    for member in &memberships {
        tx.delete(TEAM_MEMBERS, record_id(member)).await?;
    }
    for mut request in find(
        tx,
        TEAM_JOIN_REQUESTS,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("identityId", identity_id)
            .eq("status", "pending"),
    )
    .await?
    {
        request.insert("status".into(), Value::String("cancelled".into()));
        request.insert("decidedAt".into(), number(now));
        tx.put(TEAM_JOIN_REQUESTS, &request).await?;
    }
    if !memberships.is_empty() {
        let team_ids: Vec<String> = memberships
            .iter()
            .map(|member| js_string(member.get("teamId")))
            .collect();
        sync_team_groups_of(tx, tenant_id, &team_ids, now).await?;
    }
    // Whatever still ties the person to a backing group (records written before a repair) goes as well.
    for membership in find(
        tx,
        "groupMembers",
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("identityId", identity_id),
    )
    .await?
    {
        if matches!(membership.get("teamId"), Some(Value::String(_))) {
            tx.delete("groupMembers", record_id(&membership)).await?;
        }
    }
    Ok(memberships.len() as f64)
}

/// Which organization-structure keys the documents name anywhere (condition keys, condition values such as
/// `${principal.departmentId}`, resource patterns), so decisions read team and department records only when needed.
pub fn mentioned_org_keys(documents: &[&better_iam_core::PolicyDocument]) -> OrgKeys {
    let mut found = OrgKeys::default();
    for document in documents {
        let serialized = better_iam_core::js::stringify(
            &serde_json::to_value(&document.statements).unwrap_or(Value::Null),
        );
        if serialized.contains("principal.teams") {
            found.teams = true;
        }
        if serialized.contains("principal.department") {
            found.departments = true;
        }
        if found.teams && found.departments {
            break;
        }
    }
    found
}

/// What `mentionedOrgKeys` reports: whether any document names the team or department keys.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OrgKeys {
    pub teams: bool,
    pub departments: bool,
}

/// Policy context for a person in their own tenant: `principal.teams` lists the teams they belong to directly and
/// the teams above those (the same teams whose backing groups hold them). Nothing for other principals.
pub async fn team_context(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    now: f64,
) -> IamResult<Map<String, Value>> {
    let mut teams = teams_of_at(tx, tenant_id, identity_id, Some(now), true).await?;
    crate::js::sort_strings(&mut teams);
    let mut context = Map::new();
    context.insert("principal.teams".into(), json!(teams));
    Ok(context)
}

/// Team sync: brings the synced members of teams with `syncGroupIds` in line with their source groups. Every active
/// person with a live membership of a source group is a member (added as `member` with `source: 'sync'`, expiring
/// when their last source membership does); synced members who left every source group are removed. Manual
/// memberships are never changed. `groupId` limits the run to teams syncing from that group, `teamIds` to those
/// teams. Changes are audited as `team:member:add` / `team:member:remove` with `source: 'sync'` under `actorId`.
/// The seats of license products assigned to `groupId`, and to the backing groups the run changed (the synced
/// teams' and those of the teams above them), are reconciled afterwards (licenses.ts), under the same actor.
/// `options` is `{ groupId?: string; teamIds?: string[]; actorId: string }`.
pub async fn sync_teams_from_groups(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    options: &Value,
) -> IamResult<crate::teams::TeamGroupSyncResult> {
    let options = Some(options);
    let group_id: Option<String> = defined(member(options, "groupId")).map(|value| match value {
        Value::String(text) => text.clone(),
        other => js_string(Some(other)),
    });
    let team_ids: Option<Vec<String>> = defined(member(options, "teamIds")).map(ids_from);
    let actor_id = js_string(member(options, "actorId"));
    let mut result = TeamGroupSyncResult {
        added: 0.0,
        removed: 0.0,
        updated: 0.0,
        teams: Vec::new(),
        extra: Map::new(),
    };
    // Every writer of a group's membership comes through here: seats of licenses assigned to the group follow as
    // well.
    let sources: Vec<String> = group_id.iter().cloned().collect();
    let teams: Vec<Team> = find(tx, TEAMS, Filter::new().eq("tenantId", tenant_id))
        .await?
        .into_iter()
        .map(decode)
        .collect::<IamResult<_>>()?;
    // Named teams are included even without sources, so turning sync off removes their synced members.
    let synced: Vec<&Team> = teams
        .iter()
        .filter(|team| {
            let listed = match &team_ids {
                Some(ids) => ids.contains(&team.id),
                None => team
                    .sync_group_ids
                    .as_ref()
                    .is_some_and(|ids| !ids.is_empty()),
            };
            listed
                && group_id.as_ref().is_none_or(|group_id| {
                    team.sync_group_ids
                        .as_deref()
                        .unwrap_or(&[])
                        .contains(group_id)
                })
        })
        .collect();
    let actor = Value::String(actor_id.clone());
    if synced.is_empty() {
        if !sources.is_empty() {
            crate::licenses::reconcile_group_licenses(ctx, tx, tenant_id, &json!(sources), &actor)
                .await?;
        }
        return Ok(result);
    }
    let now = ctx.now();
    let mut people: IndexMap<String, bool> = IndexMap::new();
    let events = ctx.events()?;
    for team in synced {
        // None means permanent: the latest end among the person's source memberships.
        let mut desired: IndexMap<String, Option<f64>> = IndexMap::new();
        for source_group in team.sync_group_ids.as_deref().unwrap_or(&[]) {
            for record in find(
                tx,
                "groupMembers",
                Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("groupId", source_group.as_str()),
            )
            .await?
            {
                let membership: GroupMember = decode(record)?;
                if !ctx.live_membership(&membership) {
                    continue;
                }
                if !people.contains_key(&membership.identity_id) {
                    let active = match tx.get("identities", &membership.identity_id).await? {
                        Some(record) => {
                            let identity: Identity = decode(record)?;
                            identity.tenant_id == tenant_id
                                && identity.kind == better_iam_core::IdentityKind::User
                                && identity.status == better_iam_core::IdentityStatus::Active
                                && !ctx.identity_expired(&identity)
                        }
                        None => false,
                    };
                    people.insert(membership.identity_id.clone(), active);
                }
                if !people[&membership.identity_id] {
                    continue;
                }
                match desired.get(&membership.identity_id).copied() {
                    None => {
                        desired.insert(membership.identity_id.clone(), membership.expires_at);
                    }
                    Some(Some(previous)) => {
                        desired.insert(
                            membership.identity_id.clone(),
                            membership.expires_at.map(|expires| previous.max(expires)),
                        );
                    }
                    Some(None) => {}
                }
            }
        }
        let audit = |action: &'static str, metadata: Map<String, Value>| {
            let mut full = Map::new();
            full.insert("team".into(), Value::String(team.slug.clone()));
            full.insert("source".into(), Value::String("sync".into()));
            for (key, value) in metadata {
                full.insert(key, value);
            }
            let mut event = Record::new();
            event.insert("id".into(), Value::String(id()));
            event.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
            event.insert("actorId".into(), Value::String(actor_id.clone()));
            event.insert("action".into(), Value::String(action.into()));
            event.insert("resourceId".into(), Value::String(team.id.clone()));
            event.insert("timestamp".into(), number(now));
            event.insert("outcome".into(), Value::String("allow".into()));
            event.insert("metadata".into(), Value::Object(full));
            event
        };
        let mut changed = false;
        let records = find(
            tx,
            TEAM_MEMBERS,
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("teamId", team.id.as_str()),
        )
        .await?;
        for raw in &records {
            let member: TeamMember = decode(raw.clone())?;
            let live = live_member(&member, now);
            if !desired.contains_key(&member.identity_id) {
                if member.source.as_deref() == Some("sync") && live {
                    tx.delete(TEAM_MEMBERS, &member.id).await?;
                    let mut metadata = Map::new();
                    metadata.insert(
                        "identityId".into(),
                        Value::String(member.identity_id.clone()),
                    );
                    events
                        .record_audit(tx, &audit("team:member:remove", metadata))
                        .await?;
                    result.removed += 1.0;
                    changed = true;
                }
                continue;
            }
            if !live {
                continue;
            }
            let expires_at = desired.shift_remove(&member.identity_id).flatten();
            // A synced member's end follows the source memberships; manual members keep their own.
            if member.source.as_deref() == Some("sync") && member.expires_at != expires_at {
                let mut record = raw.clone();
                record.shift_remove("expiresAt");
                if let Some(expires_at) = expires_at {
                    record.insert("expiresAt".into(), number(expires_at));
                }
                tx.put(TEAM_MEMBERS, &record).await?;
                result.updated += 1.0;
                changed = true;
            }
        }
        for (identity_id, expires_at) in desired {
            let unique_key = format!("{}:{identity_id}", team.id);
            let lapsed = records
                .iter()
                .find(|member| str_of(member, "uniqueKey") == Some(unique_key.as_str()));
            let mut record = Record::new();
            record.insert(
                "id".into(),
                Value::String(
                    lapsed
                        .map(|record| record_id(record).to_owned())
                        .unwrap_or_else(id),
                ),
            );
            record.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
            record.insert("uniqueKey".into(), Value::String(unique_key));
            record.insert("teamId".into(), Value::String(team.id.clone()));
            record.insert("identityId".into(), Value::String(identity_id.clone()));
            record.insert("role".into(), Value::String("member".into()));
            record.insert("addedAt".into(), number(now));
            record.insert("addedBy".into(), Value::String(actor_id.clone()));
            record.insert("source".into(), Value::String("sync".into()));
            if let Some(expires_at) = expires_at {
                record.insert("expiresAt".into(), number(expires_at));
            }
            if lapsed.is_some() {
                tx.put(TEAM_MEMBERS, &record).await?;
            } else {
                tx.insert(TEAM_MEMBERS, &record).await?;
            }
            let mut metadata = Map::new();
            metadata.insert("identityId".into(), Value::String(identity_id));
            metadata.insert("role".into(), Value::String("member".into()));
            if let Some(expires_at) = expires_at {
                metadata.insert("expiresAt".into(), number(expires_at));
            }
            events
                .record_audit(tx, &audit("team:member:add", metadata))
                .await?;
            result.added += 1.0;
            changed = true;
        }
        if changed {
            sync_team_groups_of(tx, tenant_id, std::slice::from_ref(&team.id), now).await?;
            result.teams.push(team.id.clone());
        }
    }
    // syncTeamGroups filled or emptied the backing groups of the changed teams and of every team above them.
    let by_id: IndexMap<String, Team> = teams
        .iter()
        .map(|team| (team.id.clone(), team.clone()))
        .collect();
    let filled: Vec<String> = result
        .teams
        .iter()
        .flat_map(|team_id| {
            team_chain_of(&by_id, team_id)
                .into_iter()
                .map(|team| team.group_id)
        })
        .collect();
    if !sources.is_empty() || !filled.is_empty() {
        let mut group_ids = sources;
        group_ids.extend(filled);
        crate::licenses::reconcile_group_licenses(ctx, tx, tenant_id, &json!(group_ids), &actor)
            .await?;
    }
    Ok(result)
}

/// Validates a team's source groups: ordinary groups (not teams' backing groups) of the tenant, at most ten.
pub async fn team_sync_groups(
    tx: &Store,
    tenant_id: &str,
    value: Option<&Value>,
) -> IamResult<Vec<String>> {
    let items = match value {
        Some(Value::Array(items)) if items.len() as f64 <= MAX_SYNC_GROUPS => items,
        _ => {
            return Err(IamError::new(
                "INVALID_INPUT",
                "syncGroupIds must list at most 10 groups",
            ));
        }
    };
    let ids = crate::js::unique(items.iter().map(|item| js_string(Some(item))));
    for group_id in &ids {
        let group = match tx.get("groups", group_id).await? {
            Some(group) if str_of(&group, "tenantId") == Some(tenant_id) => group,
            _ => {
                return Err(IamError::with_status(
                    "NOT_FOUND",
                    format!("Group {group_id} not found"),
                    404,
                ));
            }
        };
        if is_team_group(Some(&Value::Object(group)))? {
            return Err(IamError::new(
                "INVALID_INPUT",
                "A team cannot sync from another team\u{2019}s backing group",
            ));
        }
    }
    Ok(ids)
}

/// Teams that sync their members from a group (a group they depend on).
pub async fn teams_syncing_from(
    tx: &Store,
    tenant_id: &str,
    group_id: &str,
) -> IamResult<Vec<crate::teams::Team>> {
    let mut teams = Vec::new();
    for record in find(tx, TEAMS, Filter::new().eq("tenantId", tenant_id)).await? {
        let team: Team = decode(record)?;
        if team
            .sync_group_ids
            .as_ref()
            .is_some_and(|ids| ids.iter().any(|id| id == group_id))
        {
            teams.push(team);
        }
    }
    Ok(teams)
}

/// The bindings on the backing groups of `teamIds` and of every team above them: what membership of those teams
/// hands out. Changing who is in them needs the grant authority behind each binding, as `groups.addMember` does for
/// a group. `teamIds` is a JSON array of team IDs; [`team_chain_bindings_of`] takes them typed.
pub async fn team_chain_bindings(
    tx: &Store,
    tenant_id: &str,
    team_ids: &Value,
) -> IamResult<Vec<crate::models::Binding>> {
    team_chain_bindings_of(tx, tenant_id, &ids_from(team_ids)).await
}

/// [`team_chain_bindings`] over typed team IDs.
pub async fn team_chain_bindings_of(
    tx: &Store,
    tenant_id: &str,
    team_ids: &[String],
) -> IamResult<Vec<Binding>> {
    let teams = tenant_teams(tx, tenant_id).await?;
    let mut group_ids: IndexSet<String> = IndexSet::new();
    for team_id in team_ids {
        for team in team_chain_of(&teams, team_id) {
            group_ids.insert(team.group_id);
        }
    }
    let mut bindings: Vec<Binding> = Vec::new();
    for group_id in &group_ids {
        for record in find(
            tx,
            "bindings",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("subjectType", "group")
                .eq("subjectId", group_id.as_str()),
        )
        .await?
        {
            bindings.push(decode(record)?);
        }
    }
    Ok(bindings)
}

/// Whether a policy document (`{ statements: [...] }` as JSON) holds a deny statement.
fn document_denies(document: Option<&Value>) -> bool {
    match member(document, "statements") {
        Some(Value::Array(statements)) => statements
            .iter()
            .any(|statement| member(Some(statement), "effect") == Some(&json!("deny"))),
        _ => false,
    }
}

/// Whether a role, or a role it inherits, holds a deny statement (in its own document or an attached policy).
/// Leaving a group bound to such a role lifts a restriction, which needs the same authority as removing the person
/// would.
pub async fn role_holds_deny(tx: &Store, role_id: &str) -> IamResult<bool> {
    let mut seen: IndexSet<String> = IndexSet::new();
    let mut queue: VecDeque<String> = VecDeque::from([role_id.to_owned()]);
    while let Some(current) = queue.pop_front() {
        if seen.contains(&current) {
            continue;
        }
        seen.insert(current.clone());
        let Some(role) = tx.get("roles", &current).await? else {
            continue;
        };
        let mut documents: Vec<Value> = Vec::new();
        if let Some(document) = role
            .get("document")
            .filter(|document| truthy(Some(document)))
        {
            documents.push(document.clone());
        }
        for policy_id in ids_from(role.get("policyIds").unwrap_or(&Value::Null)) {
            if let Some(policy) = tx.get("policies", &policy_id).await? {
                documents.push(policy.get("document").cloned().unwrap_or(Value::Null));
            }
        }
        if documents
            .iter()
            .any(|document| document_denies(Some(document)))
        {
            return Ok(true);
        }
        queue.extend(ids_from(role.get("inherits").unwrap_or(&Value::Null)));
    }
    Ok(false)
}
