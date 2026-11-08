//! Port of `packages/server/src/api/groups.ts`: the `groups` API group and the group helpers other writers share
//! (configuration sync, teams, access packages, workflows, identities): creating and deleting groups, adding and
//! removing members under each group binding's grant authority, and the license seat check for groups that carry
//! license products.

use std::sync::{Arc, Mutex};

use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Filter, IamError, IamResult, Record,
};
use better_iam_types::api::groups;
use indexmap::IndexMap;
use serde_json::{Map, Value, json};

use crate::api::roles::{defined, find_all, member_str, string_list};
use crate::api::{Body, Reply, string_member};
use crate::applications::release_group_apps;
use crate::context::{ServerContext, Store};
use crate::contracts::{
    Mutation, MutationContext, OperationDenied, OperationFailure, OperationResult,
};
use crate::js::{as_number, js_string, number, unique};
use crate::licenses::{batch_group_licenses, groups_hold_licenses, release_group_licenses};
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::package_rules::rule_group_ids;
use crate::port::{Callback, decode, encode};
use crate::teams::{
    TEAM_COLLECTIONS, Team, assert_not_team_group, sync_teams_from_groups, team_chain,
    team_chain_bindings, teams_syncing_from,
};
use crate::utils::id;
use crate::validation::{strings, text};

/// `{ ...filter, key: value }` where the value comes from a request body: an absent member is `undefined`, which
/// matches records that lack the member.
fn with_member(filter: Filter, key: &str, value: Option<&Value>) -> Filter {
    let mut filter = filter;
    filter.set(key, value.cloned());
    filter
}

/// `ctx.liveMembership(member)`: no expiry, or one still ahead.
fn live_membership(ctx: &ServerContext, member: &Record) -> bool {
    match member.get("expiresAt") {
        None => true,
        Some(expires) => as_number(expires).is_some_and(|expires| expires > ctx.now()),
    }
}

/// A team's ID (the record's `id`).
fn team_id(team: &Team) -> String {
    member_str(&encode(team), "id").to_owned()
}

/// The `groups` API group (`createGroupsApi(ctx)`): one method per route `groups/{method}`.
pub struct GroupsApi {
    ctx: Arc<ServerContext>,
}

/// `createGroupsApi(ctx)`.
pub fn create_groups_api(ctx: &Arc<ServerContext>) -> IamResult<GroupsApi> {
    Ok(GroupsApi { ctx: ctx.clone() })
}

impl GroupsApi {
    /// `groups/addMember`: `expiresAt` (epoch milliseconds) makes the membership temporary; it ends by itself and
    /// the purge worker removes it.
    pub async fn add_member(
        &self,
        credential: &CredentialInput,
        input: Body<groups::AddMemberInput>,
    ) -> IamResult<Reply<groups::AddMemberOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let member = add_group_member_record(ctx, &tx, &principal, body).await?;
                Ok(Value::Object(member))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:groups:update",
                &string_member(&input, "groupId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `groups/addMembers`: adds up to 100 members in one transaction, optionally all with the same expiry.
    pub async fn add_members(
        &self,
        credential: &CredentialInput,
        input: Body<groups::AddMembersInput>,
    ) -> IamResult<Reply<groups::AddMembersOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let members = add_group_members(ctx, &tx, &principal, body).await?;
                Ok(json!({
                    "members": members.into_iter().map(Value::Object).collect::<Vec<_>>(),
                }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:groups:update",
                &string_member(&input, "groupId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `groups/create`.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<groups::CreateInput>,
    ) -> IamResult<Reply<groups::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let group = create_group_record(ctx, &tx, &tenant, body).await?;
                Ok(Value::Object(group))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:groups:create",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `groups/delete`.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<groups::DeleteInput>,
    ) -> IamResult<Reply<groups::DeleteOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let group = ctx
                    .scoped(&tx, "groups", body.get("groupId"), &tenant_id)
                    .await?;
                // A team's backing group goes with its team (`teams.delete`).
                assert_not_team_group(Some(&Value::Object(group.clone())))?;
                delete_group_record(ctx, &tx, &principal, &group).await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:groups:delete",
                &string_member(&input, "groupId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `groups/get`.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<groups::GetInput>,
    ) -> IamResult<Reply<groups::GetOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let group = ctx
                    .scoped(&tx, "groups", body.get("groupId"), &tenant_id)
                    .await?;
                Ok(Value::Object(group))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:groups:read",
                &string_member(&input, "groupId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `groups/list`.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<groups::ListInput>,
    ) -> IamResult<Reply<groups::ListOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let groups = tx
                    .find(
                        "groups",
                        &Filter::new().eq("tenantId", string_member(body, "tenantId")),
                        &find_all(),
                    )
                    .await?;
                Ok(Value::Array(
                    groups.into_iter().map(Value::Object).collect(),
                ))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:groups:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `groups/listMembers`: current members (expired memberships are omitted), each with `membershipExpiresAt`
    /// when temporary.
    pub async fn list_members(
        &self,
        credential: &CredentialInput,
        input: Body<groups::ListMembersInput>,
    ) -> IamResult<Reply<groups::ListMembersOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                ctx.scoped(&tx, "groups", body.get("groupId"), &tenant_id)
                    .await?;
                let memberships = tx
                    .find(
                        "groupMembers",
                        &with_member(
                            Filter::new().eq("tenantId", tenant_id.clone()),
                            "groupId",
                            body.get("groupId"),
                        ),
                        &find_all(),
                    )
                    .await?;
                let mut members = Vec::new();
                for membership in memberships {
                    if !live_membership(ctx, &membership) {
                        continue;
                    }
                    let Some(identity_id) = membership.get("identityId").and_then(Value::as_str)
                    else {
                        continue;
                    };
                    let Some(mut identity) = tx.get("identities", identity_id).await? else {
                        continue;
                    };
                    if identity.get("tenantId").and_then(Value::as_str) != Some(tenant_id.as_str())
                    {
                        continue;
                    }
                    // `publicIdentity(identity)`: everything but the password hash.
                    identity.shift_remove("passwordHash");
                    if let Some(expires_at) = membership.get("expiresAt") {
                        identity.insert("membershipExpiresAt".into(), expires_at.clone());
                    }
                    members.push(Value::Object(identity));
                }
                Ok(Value::Array(members))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:groups:read",
                &string_member(&input, "groupId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `groups/removeMember`.
    pub async fn remove_member(
        &self,
        credential: &CredentialInput,
        input: Body<groups::RemoveMemberInput>,
    ) -> IamResult<Reply<groups::RemoveMemberOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                remove_group_member_record(ctx, &tx, &principal, body).await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:groups:update",
                &string_member(&input, "groupId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `groups/update`.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<groups::UpdateInput>,
    ) -> IamResult<Reply<groups::UpdateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let group = ctx
                    .scoped(&tx, "groups", body.get("groupId"), &tenant_id)
                    .await?;
                let name = defined(body, "name");
                let description = defined(body, "description");
                if name.is_none() && description.is_none() {
                    return Err(IamError::new("INVALID_INPUT", "Nothing to update").into());
                }
                let mut next = group;
                if let Some(name) = name {
                    next.insert("name".into(), Value::String(text(Some(name), "name", 256)?));
                }
                if let Some(description) = description {
                    next.insert(
                        "description".into(),
                        Value::String(text(Some(description), "description", 512)?),
                    );
                }
                Ok(Value::Object(tx.put("groups", &next).await?))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:groups:update",
                &string_member(&input, "groupId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `groups/updateMember`: extends, shortens, or clears (null) a temporary membership.
    pub async fn update_member(
        &self,
        credential: &CredentialInput,
        input: Body<groups::UpdateMemberInput>,
    ) -> IamResult<Reply<groups::UpdateMemberOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let member = update_group_member_record(ctx, &tx, &principal, body).await?;
                Ok(Value::Object(member))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:groups:update",
                &string_member(&input, "groupId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// Every binding of a group (`{ tenantId, subjectType: 'group', subjectId: groupId }`).
async fn group_bindings(
    tx: &Store,
    tenant_id: &str,
    group_id: Option<&Value>,
) -> IamResult<Vec<Record>> {
    tx.find(
        "bindings",
        &with_member(
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("subjectType", "group"),
            "subjectId",
            group_id,
        ),
        &find_all(),
    )
    .await
}

/// Requires the grant authority behind each binding (`ctx.grantingAuthority(tx, principal, tenantId,
/// binding.authorityId)`).
async fn require_binding_authorities(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    bindings: &[Record],
) -> IamResult<()> {
    for binding in bindings {
        ctx.granting_authority(
            tx,
            principal,
            tenant_id,
            binding.get("authorityId").and_then(Value::as_str),
        )
        .await?;
    }
    Ok(())
}

/// Brings the teams that sync their members from the group in step (teams.ts). A synced person joins or leaves
/// those teams' backing groups and those of every team above them, so a membership change that moves a team needs
/// the grant authority behind what those groups hold, exactly as changing the team's members directly does.
async fn follow_synced_teams(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    group_id: &str,
) -> IamResult<()> {
    let synced = sync_teams_from_groups(
        ctx,
        tx,
        tenant_id,
        &json!({ "groupId": group_id, "actorId": principal.identity.id }),
    )
    .await?;
    for binding in team_chain_bindings(tx, tenant_id, &json!(synced.teams)).await? {
        ctx.granting_authority(
            tx,
            principal,
            tenant_id,
            Some(binding.authority_id.as_str()),
        )
        .await?;
    }
    Ok(())
}

/// [`assert_may_claim_licenses`] for the groups a write fills.
pub async fn assert_may_claim_license_seats(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    group_ids: &[String],
    message: Option<&str>,
) -> OperationResult<()> {
    let direct = unique(group_ids.iter().cloned());
    if direct.is_empty() {
        return Ok(());
    }
    let mut all_group_ids = direct.clone();
    let mut teams: Option<IndexMap<String, Team>> = None;
    for each in &direct {
        let syncing = teams_syncing_from(tx, tenant_id, each).await?;
        if syncing.is_empty() {
            continue;
        }
        if teams.is_none() {
            let mut map = IndexMap::new();
            let collection = TEAM_COLLECTIONS["teams"].as_str().unwrap_or("teams");
            for record in tx
                .find(
                    collection,
                    &Filter::new().eq("tenantId", tenant_id),
                    &find_all(),
                )
                .await?
            {
                let key = member_str(&record, "id").to_owned();
                map.insert(key, decode::<Team>(record)?);
            }
            teams = Some(map);
        }
        let teams = teams.as_ref().expect("loaded above");
        for team in &syncing {
            for link in team_chain(teams, &team_id(team))? {
                all_group_ids.push(link.group_id);
            }
        }
    }
    if !groups_hold_licenses(tx, tenant_id, &json!(all_group_ids)).await? {
        return Ok(());
    }
    let decision = ctx
        .decisions()?
        .decide(
            tx,
            principal,
            &AuthorizationRequest {
                credential: CredentialInput::default(),
                tenant_id: tenant_id.to_owned(),
                action: "iam:licenses:assign".into(),
                resource: ResourceTarget {
                    kind: "iam".into(),
                    id: "licenses/assignments".into(),
                },
            },
            true,
        )
        .await?;
    if !decision.allowed {
        return Err(OperationDenied::new(Some(message.unwrap_or(
            "Members of this group hold license seats through it; changing them needs iam:licenses:assign",
        ))));
    }
    Ok(())
}

/// A license product assigned to a group gives each member a claim on a seat, as assigning the product to them
/// would: adding someone to such a group, or changing how long they stay, needs iam:licenses:assign in the tenant
/// as well. The same holds for the backing groups the write fills through team sync (of the teams that sync from
/// the group and of the teams above them). Team maintainers manage their own team under its administrators'
/// delegation instead, and directory sync (SCIM) sets members as the directory says. Every other writer that puts
/// people into groups (`identities.createMany` and `invite`, guest invitations, access packages, onboarding
/// completion groups, the teams API for administrators) asks the same, through this check: it refuses with
/// `OperationDenied`, which an operation records as a denial of itself. Pass the groups the write fills
/// (`groupIds`, one ID as a string or a list) and, optionally, the refusal's message.
pub async fn assert_may_claim_licenses(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    tenant_id: &str,
    group_id: &Value,
    message: Option<&str>,
) -> OperationResult<()> {
    let group_ids: Vec<String> = match group_id {
        Value::String(group_id) => vec![group_id.clone()],
        Value::Array(items) => items.iter().map(|item| js_string(Some(item))).collect(),
        _ => Vec::new(),
    };
    assert_may_claim_license_seats(ctx, tx, principal, tenant_id, &group_ids, message).await
}

/// [`create_group`] on a raw input, answering the stored record.
pub async fn create_group_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant: &better_iam_core::Tenant,
    input: &Map<String, Value>,
) -> IamResult<Record> {
    let tenant_id = string_member(input, "tenantId");
    ctx.enforce_limit(
        tenant,
        "groups",
        || async {
            Ok(tx
                .find(
                    "groups",
                    &Filter::new().eq("tenantId", tenant_id.clone()),
                    &find_all(),
                )
                .await?
                .len() as f64)
        },
        None,
    )
    .await?;
    let mut group = Record::new();
    group.insert("id".into(), Value::String(id()));
    group.insert("tenantId".into(), Value::String(tenant_id.clone()));
    group.insert(
        "name".into(),
        Value::String(text(input.get("name"), "name", 256)?),
    );
    if let Some(description) = defined(input, "description") {
        group.insert(
            "description".into(),
            Value::String(text(Some(description), "description", 512)?),
        );
    }
    tx.insert("groups", &group).await
}

/// Creates a group within the tenant's plan limit; shared by `groups.create` and configuration sync.
pub async fn create_group(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant: &better_iam_core::Tenant,
    input: &Value,
) -> IamResult<crate::models::Group> {
    let input = input.as_object().cloned().unwrap_or_default();
    decode(create_group_record(ctx, tx, tenant, &input).await?)
}

/// A membership without its expiry and package assignment (`const { expiresAt, packageAssignmentId, ...rest }`).
fn membership_rest(member: &Record) -> Record {
    let mut rest = member.clone();
    rest.shift_remove("expiresAt");
    rest.shift_remove("packageAssignmentId");
    rest
}

/// [`add_group_member`] on a raw input, answering the stored membership.
pub async fn add_group_member_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    input: &Map<String, Value>,
) -> OperationResult<Record> {
    let tenant_id = string_member(input, "tenantId");
    // A team's backing group takes its members from the team (teams.ts).
    let group = ctx
        .scoped(tx, "groups", input.get("groupId"), &tenant_id)
        .await?;
    assert_not_team_group(Some(&Value::Object(group.clone())))?;
    let identity_id = text(input.get("identityId"), "id", 256)?;
    ctx.active_identity(tx, &identity_id, &tenant_id).await?;
    let group_id = member_str(&group, "id").to_owned();
    let bindings = group_bindings(tx, &tenant_id, input.get("groupId")).await?;
    require_binding_authorities(ctx, tx, principal, &tenant_id, &bindings).await?;
    assert_may_claim_licenses(ctx, tx, principal, &tenant_id, &json!(group_id), None).await?;
    let expires_at = match defined(input, "expiresAt") {
        Some(value) => Some(ctx.binding_expiry(Some(value))?),
        None => None,
    };
    let unique_key = format!("{group_id}:{identity_id}");
    let existing = tx
        .find(
            "groupMembers",
            &Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("uniqueKey", unique_key.clone()),
            &find_all(),
        )
        .await?
        .into_iter()
        .next();
    let member = match existing {
        Some(existing) => {
            if live_membership(ctx, &existing) {
                return Err(IamError::with_status(
                    "CONFLICT",
                    "Already a member of this group",
                    409,
                )
                .into());
            }
            // A renewed membership starts fresh: it no longer belongs to the package assignment that once created
            // it.
            let mut rest = membership_rest(&existing);
            if let Some(expires_at) = expires_at {
                rest.insert("expiresAt".into(), number(expires_at));
            }
            tx.put("groupMembers", &rest).await?
        }
        None => {
            let mut member = Record::new();
            member.insert("id".into(), Value::String(id()));
            member.insert("tenantId".into(), Value::String(tenant_id.clone()));
            member.insert("uniqueKey".into(), Value::String(unique_key));
            member.insert("groupId".into(), Value::String(group_id.clone()));
            member.insert("identityId".into(), Value::String(identity_id.clone()));
            if let Some(expires_at) = expires_at {
                member.insert("expiresAt".into(), number(expires_at));
            }
            tx.insert("groupMembers", &member).await?
        }
    };
    // Teams that sync their members from this group follow (teams.ts).
    follow_synced_teams(ctx, tx, principal, &tenant_id, &group_id).await?;
    Ok(member)
}

/// Adds an identity to a group; membership confers every group binding, so each binding's authority is required
/// (and, for teams that sync from the group, that of their backing groups' bindings), and iam:licenses:assign when
/// license products are assigned to those groups. `expiresAt` makes the membership temporary. Re-adding an expired
/// member renews the membership.
pub async fn add_group_member(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    input: &Value,
) -> OperationResult<crate::models::GroupMember> {
    let input = input.as_object().cloned().unwrap_or_default();
    let member = add_group_member_record(ctx, tx, principal, &input).await?;
    Ok(decode(member)?)
}

/// [`update_group_member`] on a raw input, answering the stored membership.
pub async fn update_group_member_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    input: &Map<String, Value>,
) -> OperationResult<Record> {
    let tenant_id = string_member(input, "tenantId");
    let group = ctx
        .scoped(tx, "groups", input.get("groupId"), &tenant_id)
        .await?;
    assert_not_team_group(Some(&Value::Object(group.clone())))?;
    let group_id = member_str(&group, "id").to_owned();
    let bindings = group_bindings(tx, &tenant_id, input.get("groupId")).await?;
    require_binding_authorities(ctx, tx, principal, &tenant_id, &bindings).await?;
    assert_may_claim_licenses(ctx, tx, principal, &tenant_id, &json!(group_id), None).await?;
    let unique_key = format!(
        "{group_id}:{}",
        match input.get("identityId") {
            None => "undefined".to_owned(),
            Some(value) => js_string(Some(value)),
        }
    );
    let member = tx
        .find(
            "groupMembers",
            &Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("uniqueKey", unique_key),
            &find_all(),
        )
        .await?
        .into_iter()
        .next();
    let Some(member) = member.filter(|member| live_membership(ctx, member)) else {
        return Err(IamError::with_status("NOT_FOUND", "Not a member of this group", 404).into());
    };
    // Editing a package's membership by hand takes it over: revoking the package no longer removes it.
    let mut rest = membership_rest(&member);
    if !matches!(input.get("expiresAt"), Some(Value::Null)) {
        rest.insert(
            "expiresAt".into(),
            number(ctx.binding_expiry(input.get("expiresAt"))?),
        );
    }
    let updated = tx.put("groupMembers", &rest).await?;
    // Synced team memberships end when their source membership does (teams.ts).
    follow_synced_teams(ctx, tx, principal, &tenant_id, &group_id).await?;
    Ok(updated)
}

/// Extends, shortens, or clears (null) a membership's expiry under the same authority rules as adding a member.
pub async fn update_group_member(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    input: &Value,
) -> OperationResult<crate::models::GroupMember> {
    let input = input.as_object().cloned().unwrap_or_default();
    let member = update_group_member_record(ctx, tx, principal, &input).await?;
    Ok(decode(member)?)
}

/// Adds up to 100 identities atomically (cohort onboarding); one failure rejects the batch. License seats of the
/// group's products are reconciled once, after the batch (licenses.ts `batchGroupLicenses`).
pub async fn add_group_members(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    input: &Map<String, Value>,
) -> OperationResult<Vec<Record>> {
    let identity_ids = unique(strings(input.get("identityIds"), "identityIds")?);
    if identity_ids.is_empty() {
        return Err(IamError::new("INVALID_INPUT", "Provide 1-100 identityIds").into());
    }
    let members: Arc<Mutex<Vec<Record>>> = Arc::default();
    // The batch callback answers IamError; a refusal (OperationDenied) is kept here so it stays one.
    let refusal: Arc<Mutex<Option<OperationFailure>>> = Arc::default();
    let run: Callback = {
        let ctx = ctx.clone();
        let tx = tx.clone();
        let principal = principal.clone();
        let tenant_id = input.get("tenantId").cloned();
        let group_id = input.get("groupId").cloned();
        let expires_at = input.get("expiresAt").cloned();
        let members = members.clone();
        let refusal = refusal.clone();
        Arc::new(move |_| {
            let ctx = ctx.clone();
            let tx = tx.clone();
            let principal = principal.clone();
            let identity_ids = identity_ids.clone();
            let members = members.clone();
            let refusal = refusal.clone();
            let mut each = Map::new();
            if let Some(tenant_id) = &tenant_id {
                each.insert("tenantId".into(), tenant_id.clone());
            }
            if let Some(group_id) = &group_id {
                each.insert("groupId".into(), group_id.clone());
            }
            let expires_at = expires_at.clone();
            Box::pin(async move {
                for identity_id in identity_ids {
                    let mut input = each.clone();
                    input.insert("identityId".into(), Value::String(identity_id));
                    if let Some(expires_at) = &expires_at {
                        input.insert("expiresAt".into(), expires_at.clone());
                    }
                    match add_group_member_record(&ctx, &tx, &principal, &input).await {
                        Ok(member) => members.lock().expect("members").push(member),
                        Err(failure) => {
                            let error = failure.error.clone();
                            *refusal.lock().expect("refusal") = Some(failure);
                            return Err(error);
                        }
                    }
                }
                Ok(Value::Null)
            })
        })
    };
    if let Err(error) = batch_group_licenses(ctx, tx, &run).await {
        if let Some(failure) = refusal.lock().expect("refusal").take() {
            return Err(failure);
        }
        return Err(error.into());
    }
    let members = std::mem::take(&mut *members.lock().expect("members"));
    Ok(members)
}

/// [`remove_group_member`] on a raw input.
pub async fn remove_group_member_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    input: &Map<String, Value>,
) -> IamResult<()> {
    let tenant_id = string_member(input, "tenantId");
    let group = ctx
        .scoped(tx, "groups", input.get("groupId"), &tenant_id)
        .await?;
    assert_not_team_group(Some(&Value::Object(group.clone())))?;
    let group_id = member_str(&group, "id").to_owned();
    let bindings = group_bindings(tx, &tenant_id, input.get("groupId")).await?;
    require_binding_authorities(ctx, tx, principal, &tenant_id, &bindings).await?;
    for member in tx
        .find(
            "groupMembers",
            &with_member(
                with_member(
                    Filter::new().eq("tenantId", tenant_id.clone()),
                    "groupId",
                    input.get("groupId"),
                ),
                "identityId",
                input.get("identityId"),
            ),
            &find_all(),
        )
        .await?
    {
        tx.delete("groupMembers", member_str(&member, "id")).await?;
    }
    for activation in tx
        .find(
            "bindingActivations",
            &with_member(
                Filter::new().eq("tenantId", tenant_id.clone()),
                "identityId",
                input.get("identityId"),
            ),
            &find_all(),
        )
        .await?
    {
        let binding_id = activation.get("bindingId");
        if bindings
            .iter()
            .any(|binding| binding.get("id").is_some() && binding.get("id") == binding_id)
        {
            tx.delete("bindingActivations", member_str(&activation, "id"))
                .await?;
        }
    }
    // Teams that sync their members from this group follow (teams.ts); leaving one may lift a deny bound to it.
    follow_synced_teams(ctx, tx, principal, &tenant_id, &group_id).await
}

/// Removes an identity from a group, ending its activations of the group's eligible bindings.
pub async fn remove_group_member(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    input: &Value,
) -> IamResult<()> {
    let input = input.as_object().cloned().unwrap_or_default();
    remove_group_member_record(ctx, tx, principal, &input).await
}

/// [`delete_group`] for a stored record.
pub async fn delete_group_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    group: &Record,
) -> IamResult<()> {
    let tenant_id = member_str(group, "tenantId").to_owned();
    let group_id = member_str(group, "id").to_owned();
    let packages = tx
        .find(
            "accessPackages",
            &Filter::new().eq("tenantId", tenant_id.clone()),
            &find_all(),
        )
        .await?;
    // A group a package grants, or one its birthright rule tests, stays until the package stops using it.
    let mut packaged = Vec::new();
    for pkg in &packages {
        if string_list(pkg, "groupIds").contains(&group_id)
            || rule_group_ids(pkg.get("autoAssign"))?.contains(&group_id)
        {
            packaged.push(js_string(pkg.get("name")));
        }
    }
    if !packaged.is_empty() {
        return Err(IamError::with_status(
            "RESOURCE_IN_USE",
            format!(
                "Access packages still include it or name it in a rule: {}",
                packaged.join(", ")
            ),
            409,
        ));
    }
    // Teams that sync their members from it would silently lose them.
    let syncing = teams_syncing_from(tx, &tenant_id, &group_id).await?;
    if !syncing.is_empty() {
        return Err(IamError::with_status(
            "RESOURCE_IN_USE",
            format!(
                "Teams sync their members from it: {}; stop syncing first",
                syncing
                    .iter()
                    .map(|team| team.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            409,
        ));
    }
    // An approver group that disappeared would silently leave its requests to whoever else may decide.
    let approving: Vec<String> = packages
        .iter()
        .filter(|pkg| pkg.get("approverGroupId").and_then(Value::as_str) == Some(&group_id))
        .map(|pkg| format!("package {}", js_string(pkg.get("name"))))
        .collect();
    let now = ctx.now();
    let approving_bindings = tx
        .find(
            "bindings",
            &Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("approverGroupId", group_id.clone()),
            &find_all(),
        )
        .await?
        .into_iter()
        .filter(|binding| {
            // `!ctx.expiredBinding(binding)`, and the group's own bindings go with it.
            !binding
                .get("expiresAt")
                .and_then(as_number)
                .is_some_and(|expires| expires <= now)
                && !(binding.get("subjectType").and_then(Value::as_str) == Some("group")
                    && binding.get("subjectId").and_then(Value::as_str) == Some(&group_id))
        })
        .count();
    if !approving.is_empty() || approving_bindings > 0 {
        let mut subjects = approving;
        if approving_bindings > 0 {
            subjects.push(format!("{approving_bindings} eligible binding(s)"));
        }
        return Err(IamError::with_status(
            "RESOURCE_IN_USE",
            format!(
                "It approves requests for {}; name another approver group first",
                subjects.join(", ")
            ),
            409,
        ));
    }
    let bindings = group_bindings(tx, &tenant_id, Some(&Value::String(group_id.clone()))).await?;
    require_binding_authorities(ctx, tx, principal, &tenant_id, &bindings).await?;
    for member in tx
        .find(
            "groupMembers",
            &Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("groupId", group_id.clone()),
            &find_all(),
        )
        .await?
    {
        tx.delete("groupMembers", member_str(&member, "id")).await?;
    }
    for binding in &bindings {
        for activation in tx
            .find(
                "bindingActivations",
                &Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("bindingId", member_str(binding, "id")),
                &find_all(),
            )
            .await?
        {
            tx.delete("bindingActivations", member_str(&activation, "id"))
                .await?;
        }
        tx.delete("bindings", member_str(binding, "id")).await?;
    }
    for tuple in tx
        .find(
            "relationships",
            &Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("subjectType", "group")
                .eq("subjectId", group_id.clone()),
            &find_all(),
        )
        .await?
    {
        tx.delete("relationships", member_str(&tuple, "id")).await?;
    }
    // App assignments to the group go with it (applications.ts).
    release_group_apps(tx, &tenant_id, &group_id).await?;
    // So do license assignments to it, releasing the seats they carried (licenses.ts).
    release_group_licenses(
        ctx,
        tx,
        &tenant_id,
        &group_id,
        &crate::conformance::principal_json(principal),
    )
    .await?;
    tx.delete("groups", &group_id).await
}

/// Deletes a group with its memberships, bindings, activations, and relationships.
pub async fn delete_group(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    group: &crate::models::Group,
) -> IamResult<()> {
    delete_group_record(ctx, tx, principal, &encode(group)).await
}
