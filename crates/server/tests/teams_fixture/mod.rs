//! Teams and departments written the way the teams and departments API groups store them (those groups belong to
//! other port units), on top of the organization fixture: a team with its team-managed backing group, direct
//! memberships followed by `syncTeamGroups`, departments and placements, roles and bindings, and an authorization
//! check on a document.

#![allow(dead_code)]

use better_iam_core::{CredentialInput, IamStoreExt};
use better_iam_server::options::{AuthorizationRequest, ResourceTarget};
use better_iam_server::teams::{remove_from_all_teams, sync_team_groups_of};
use better_iam_server::utils::id;
use serde_json::{Value, json};

use crate::org_fixture::Org;

/// A created team: its ID and its backing group.
#[derive(Debug, Clone)]
pub struct TeamRef {
    pub id: String,
    pub group_id: String,
    pub slug: String,
}

/// Creates a team as `teams.create` stores it: the backing group `team:{slug}` marked with `teamId`, then the team.
pub async fn create_team(
    org: &Org,
    name: &str,
    slug: &str,
    parent_id: Option<&str>,
    sync_group_ids: &[String],
) -> TeamRef {
    let team_id = id();
    let group_id = id();
    org.insert(
        "groups",
        json!({
            "id": group_id,
            "tenantId": org.tenant_id,
            "name": format!("team:{slug}"),
            "description": format!("Members of team {name} (managed by the team)"),
            "createdAt": org.now(),
            "teamId": team_id,
        }),
    )
    .await;
    let mut team = json!({
        "id": team_id,
        "tenantId": org.tenant_id,
        "uniqueKey": format!("slug:{slug}"),
        "name": name,
        "slug": slug,
    });
    if let Some(parent_id) = parent_id {
        team["parentId"] = json!(parent_id);
    }
    team["groupId"] = json!(group_id);
    team["joinPolicy"] = json!("closed");
    team["memberManagement"] = json!("maintainers");
    if !sync_group_ids.is_empty() {
        team["syncGroupIds"] = json!(sync_group_ids);
    }
    team["createdAt"] = json!(org.now());
    team["createdBy"] = json!(org.owner_id);
    team["updatedAt"] = json!(org.now());
    org.insert("teams", team).await;
    TeamRef {
        id: team_id,
        group_id,
        slug: slug.to_owned(),
    }
}

/// Adds a direct member (as `teams.addMember` stores it) and refreshes the backing groups.
pub async fn add_team_member(
    org: &Org,
    team_id: &str,
    identity_id: &str,
    role: &str,
    expires_at: Option<f64>,
) {
    let mut member = json!({
        "id": id(),
        "tenantId": org.tenant_id,
        "uniqueKey": format!("{team_id}:{identity_id}"),
        "teamId": team_id,
        "identityId": identity_id,
        "role": role,
        "addedAt": org.now(),
        "addedBy": org.owner_id,
    });
    if let Some(expires_at) = expires_at {
        member["expiresAt"] = json!(expires_at);
    }
    let tenant_id = org.tenant_id.clone();
    let team_id = team_id.to_owned();
    let now = org.now();
    let record = member.as_object().unwrap().clone();
    org.iam
        .store
        .transaction(|tx| async move {
            tx.insert("teamMembers", &record).await?;
            sync_team_groups_of(&tx, &tenant_id, &[team_id], now).await
        })
        .await
        .expect("add team member");
}

/// Removes a direct member (as `teams.removeMember` does) and refreshes the backing groups.
pub async fn remove_team_member(org: &Org, team_id: &str, identity_id: &str) {
    let tenant_id = org.tenant_id.clone();
    let team_id = team_id.to_owned();
    let key = format!("{team_id}:{identity_id}");
    let now = org.now();
    org.iam
        .store
        .transaction(|tx| async move {
            for member in tx
                .find(
                    "teamMembers",
                    &better_iam_core::Filter::new()
                        .eq("tenantId", tenant_id.as_str())
                        .eq("uniqueKey", key),
                    &Default::default(),
                )
                .await?
            {
                tx.delete("teamMembers", better_iam_core::record_id(&member))
                    .await?;
            }
            sync_team_groups_of(&tx, &tenant_id, &[team_id], now).await
        })
        .await
        .expect("remove team member");
}

/// `removeFromAllTeams` in its own transaction.
pub async fn leave_all_teams(org: &Org, identity_id: &str) -> f64 {
    let tenant_id = org.tenant_id.clone();
    let identity_id = identity_id.to_owned();
    let now = org.now();
    org.iam
        .store
        .transaction(
            |tx| async move { remove_from_all_teams(&tx, &tenant_id, &identity_id, now).await },
        )
        .await
        .expect("remove from all teams")
}

/// A role with an inline document (as `roles.create` stores it).
pub async fn role(org: &Org, name: &str, statements: Value) -> String {
    let role_id = id();
    org.insert(
        "roles",
        json!({
            "id": role_id,
            "tenantId": org.tenant_id,
            "name": name,
            "policyIds": [],
            "document": { "version": 1, "statements": statements },
            "protected": false,
            "authorityId": org.authority_id,
        }),
    )
    .await;
    role_id
}

/// A role allowing one action on every resource.
pub async fn permission_role(org: &Org, name: &str, action: &str) -> String {
    role(
        org,
        name,
        json!([{ "effect": "allow", "actions": [action], "resources": ["*"] }]),
    )
    .await
}

/// A binding (as `bindings.create` stores it) under the owner's authority.
pub async fn bind(org: &Org, subject_type: &str, subject_id: &str, role_id: &str) -> String {
    let binding_id = id();
    org.insert(
        "bindings",
        json!({
            "id": binding_id,
            "tenantId": org.tenant_id,
            "subjectType": subject_type,
            "subjectId": subject_id,
            "roleId": role_id,
            "authorityId": org.authority_id,
        }),
    )
    .await;
    binding_id
}

/// Whether the credential may perform `action` on document `a`.
pub async fn can(org: &Org, credential: &CredentialInput, action: &str) -> bool {
    org.iam
        .authorize(&AuthorizationRequest {
            credential: credential.clone(),
            tenant_id: org.tenant_id.clone(),
            action: action.into(),
            resource: ResourceTarget {
                kind: "documents".into(),
                id: "a".into(),
            },
        })
        .await
        .expect("authorize")
        .allowed
}

/// A department (as `departments.create` stores it).
pub async fn create_department(org: &Org, name: &str, parent_id: Option<&str>) -> String {
    let department_id = id();
    let mut department = json!({
        "id": department_id,
        "tenantId": org.tenant_id,
        "uniqueKey": format!("name:{}", name.to_lowercase()),
        "name": name,
    });
    if let Some(parent_id) = parent_id {
        department["parentId"] = json!(parent_id);
    }
    department["createdAt"] = json!(org.now());
    department["updatedAt"] = json!(org.now());
    org.insert("departments", department).await;
    department_id
}

/// Places a person in a department (as `departments.assign` stores it).
pub async fn place(org: &Org, department_id: &str, identity_id: &str) {
    org.insert(
        "departmentMembers",
        json!({
            "id": id(),
            "tenantId": org.tenant_id,
            "uniqueKey": format!("identity:{identity_id}"),
            "departmentId": department_id,
            "identityId": identity_id,
            "since": org.now(),
            "assignedBy": org.owner_id,
        }),
    )
    .await;
}

/// The members of a group, as `identityId` strings, sorted.
pub async fn group_members(org: &Org, group_id: &str) -> Vec<String> {
    let mut members: Vec<String> = org
        .find(
            "groupMembers",
            better_iam_core::Filter::new()
                .eq("tenantId", org.tenant_id.as_str())
                .eq("groupId", group_id),
        )
        .await
        .iter()
        .map(|member| member["identityId"].as_str().unwrap().to_owned())
        .collect();
    members.sort();
    members
}
