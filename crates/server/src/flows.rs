//! Port of `packages/server/src/flows.ts`: multi-step flows that create sessions or cross tenant boundaries and
//! therefore do not fit the single-tenant `operation` envelope (owner and member invitations, identity links and
//! switching, AssumeRole).

use std::sync::{Arc, Weak};

use better_iam_auth::service::{CreateIdentityRaw, IssueSessionOptions};
use better_iam_core::{
    AuditOutcome, AuthMethod, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions,
    IamError, IamResult, IamStoreExt, Identity, IdentityKind, IdentityStatus, Record, Session,
    SessionKind, Tenant, TenantStatus,
};
use serde_json::{Map, Value, json};

use crate::api::credential_from_json;
use crate::client_info::client_from_headers;
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::js::truthy;
use crate::models::{Binding, GrantAuthority, MemberInvitation, OwnerInvitation, Role};
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::port::{decode, encode};
use crate::session_kinds::acts_in_own_right;
use crate::temporary_credentials::{
    audience_value, credential_format, duration_within, mint_credential, role_duration_bounds,
    session_name_value, session_tags_value, source_identity_value, temporary_credential,
};
use crate::utils::{by_id, date_now, hash, id, public_identity};
use crate::validation::text;

/// The outcome of redeeming an invitation: the new identity plus either a session or an MFA challenge
/// (`{ identity: PublicIdentity } & SignInResult`, as JSON).
pub type EnrollmentResult = Value;

/// Multi-step flows that create sessions or cross tenant boundaries and therefore do not fit the single-tenant
/// `operation` envelope: the [`crate::contracts::FlowService`] contract, implemented by [`Flows`].
pub use crate::contracts::FlowService;

/// Whether a presented external ID matches a trust's stored hash: SHA-256 hex digests compared in constant time
/// (with a length check first). A trust without an external ID matches anything.
fn external_id_matches(expected_hash: Option<&Value>, provided: Option<&Value>) -> bool {
    if !truthy(expected_hash) {
        return true;
    }
    let Some(Value::String(provided)) = provided else {
        return false;
    };
    // A stored hash that is not a string cannot match any digest.
    let Some(Value::String(expected)) = expected_hash else {
        return false;
    };
    let expected = expected.as_bytes();
    let actual = hash(provided);
    let actual = actual.as_bytes();
    expected.len() == actual.len()
        && expected
            .iter()
            .zip(actual)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// Whether a session may source a role session: one acting in its own right, or a session token minted from one.
fn role_source(session: &Session) -> bool {
    acts_in_own_right(session.kind) || session.kind == SessionKind::SessionToken
}

/// The session tag keys a stored trust admits (`trustAllowedTagKeys`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedTagKeys {
    pub any: bool,
    pub keys: Vec<String>,
}

/// The session tag keys a stored trust admits, read fail-closed: a list of strings, where the `*` wildcard counts
/// only as exactly ['*']. Anything malformed (not an array, or holding a non-string) admits no tags; legacy trusts
/// without the field admit none either.
pub fn trust_allowed_tag_keys(trust: &Record) -> AllowedTagKeys {
    let none = AllowedTagKeys {
        any: false,
        keys: Vec::new(),
    };
    let Some(Value::Array(values)) = trust.get("allowedTagKeys") else {
        return none;
    };
    let mut keys = Vec::with_capacity(values.len());
    for value in values {
        match value {
            Value::String(key) => keys.push(key.clone()),
            _ => return none,
        }
    }
    if keys.len() == 1 && keys[0] == "*" {
        return AllowedTagKeys {
            any: true,
            keys: Vec::new(),
        };
    }
    AllowedTagKeys { any: false, keys }
}

/// A stored trust's source-identity mode, read fail-closed: any value but the three literals means 'forbidden'.
pub fn trust_source_identity_mode(trust: &Record) -> &'static str {
    match trust.get("sourceIdentityMode").and_then(Value::as_str) {
        Some("optional") => "optional",
        Some("required") => "required",
        _ => "forbidden",
    }
}

/// [`trust_passes_source_attributes`] for a stored trust record.
pub fn trust_record_passes_source_attributes(trust: &Record) -> bool {
    match trust.get("passSourceAttributes") {
        None => true,
        Some(Value::Bool(value)) => *value,
        Some(_) => false,
    }
}

/// [`trust_requires_mfa`] for a stored trust record.
pub fn trust_record_requires_mfa(trust: &Record) -> bool {
    trust.get("requireMfa") != Some(&Value::Bool(false))
}

/// Whether a stored trust passes the source identity's attributes into its role sessions, read as a boolean: legacy
/// trusts without the field pass them, and a malformed (non-boolean) value fails closed and passes nothing.
pub fn trust_passes_source_attributes(trust: &crate::models::Trust) -> bool {
    trust_record_passes_source_attributes(&encode(trust))
}

/// Whether a stored trust requires MFA of the source session, read fail-closed: only the boolean `false` waives it.
/// A missing field means what `trust.create` defaults to (required), and any malformed value requires it too.
pub fn trust_requires_mfa(trust: &crate::models::Trust) -> bool {
    trust_record_requires_mfa(&encode(trust))
}

/// `INVITATION_INVALID` with the given message.
fn invitation_invalid(message: &str) -> IamError {
    IamError::new("INVITATION_INVALID", message)
}

fn find_all() -> FindOptions {
    FindOptions::default()
}

/// A member invitation grants no more than its inviter could bind directly, now as when it was sent: the inviter
/// must still be active and still hold iam:identities:create, iam:bindings:create on each role and
/// iam:groups:update on each group (and iam:licenses:assign when a license product is assigned to one of the
/// groups, then or since), and the authorities behind the invitation and each group's bindings must still be
/// theirs. Demoting or disabling the inviter ends the invitations they sent. Throws INVITATION_INVALID otherwise.
/// Acceptance checks it, and so does `identities.resendInvitation`, so only an invitation that can still be
/// accepted goes out again.
pub async fn assert_member_invitation_grantable(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    invitation: &MemberInvitation,
    tenant_id: &str,
) -> IamResult<()> {
    const REFUSED: &str = "The inviter can no longer grant this access";
    if let Some(authority_id) = &invitation.authority_id
        && ctx.authority_chain(tx, authority_id).await?.is_none()
    {
        return Err(invitation_invalid("Invitation authority revoked"));
    }
    let inviter: Option<Identity> = match tx.get("identities", &invitation.inviter_id).await? {
        Some(record) => Some(decode(record)?),
        None => None,
    };
    let Some(inviter) = inviter.filter(|inviter| {
        inviter.status == IdentityStatus::Active && !ctx.identity_expired(inviter)
    }) else {
        return Err(invitation_invalid("The inviter can no longer invite"));
    };
    let decisions = ctx.decisions()?;
    let as_inviter = decisions.simulated_principal(&inviter, true);
    let inviter_may = |action: &'static str, resource_id: String| {
        let as_inviter = &as_inviter;
        async move {
            Ok::<bool, IamError>(
                decisions
                    .decide(
                        tx,
                        as_inviter,
                        &AuthorizationRequest {
                            credential: CredentialInput::default(),
                            tenant_id: tenant_id.to_owned(),
                            action: action.to_owned(),
                            resource: ResourceTarget {
                                kind: "iam".into(),
                                id: resource_id,
                            },
                        },
                        true,
                    )
                    .await?
                    .allowed,
            )
        }
    };
    let inviter_holds = |authority_id: String| {
        let as_inviter = &as_inviter;
        async move {
            ctx.granting_authority(tx, as_inviter, tenant_id, Some(&authority_id))
                .await
                .is_ok()
        }
    };
    let still_grantable = inviter_may("iam:identities:create", tenant_id.to_owned()).await?
        && match &invitation.authority_id {
            None => true,
            Some(authority_id) => inviter_holds(authority_id.clone()).await,
        };
    if !still_grantable {
        return Err(invitation_invalid(REFUSED));
    }
    for role_id in &invitation.role_ids {
        if !inviter_may("iam:bindings:create", role_id.clone()).await? {
            return Err(invitation_invalid(REFUSED));
        }
    }
    for group_id in &invitation.group_ids {
        if !inviter_may("iam:groups:update", group_id.clone()).await? {
            return Err(invitation_invalid(REFUSED));
        }
        let bindings = tx
            .find(
                "bindings",
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("subjectType", "group")
                    .eq("subjectId", group_id.clone()),
                &find_all(),
            )
            .await?;
        for binding in bindings {
            let binding: Binding = decode(binding)?;
            if !inviter_holds(binding.authority_id).await {
                return Err(invitation_invalid(REFUSED));
            }
        }
    }
    // Groups that carry license seats (then or since) need the inviter's iam:licenses:assign (api/groups.ts). Its
    // refusal is an `OperationDenied` (ACCESS_DENIED, 403); any other error propagates.
    match crate::api::groups::assert_may_claim_licenses(
        ctx,
        tx,
        &as_inviter,
        tenant_id,
        &json!(invitation.group_ids),
        None,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(error) if error.code == "ACCESS_DENIED" && error.status == 403 => {
            Err(invitation_invalid(REFUSED))
        }
        Err(error) => Err(error),
    }
}

pub struct Flows {
    ctx: Weak<ServerContext>,
}

/// `createFlows(ctx)`.
pub fn create_flows(ctx: &Arc<ServerContext>) -> IamResult<Flows> {
    Ok(Flows {
        ctx: Arc::downgrade(ctx),
    })
}

impl Flows {
    fn context(&self) -> IamResult<Arc<ServerContext>> {
        self.ctx.upgrade().ok_or_else(crate::js::internal_error)
    }
}

/// `{ identity: publicIdentity(identity), ...issued }`.
fn enrollment(identity: &Identity, issued: &better_iam_auth::SignInResult) -> IamResult<Value> {
    let mut out = Map::new();
    out.insert("identity".into(), Value::Object(public_identity(identity)));
    if let Value::Object(issued) =
        serde_json::to_value(issued).map_err(|_| crate::js::internal_error())?
    {
        for (key, value) in issued {
            out.insert(key, value);
        }
    }
    Ok(Value::Object(out))
}

/// A system audit event (`recordAudit`) in the member order flows write it.
fn audit_event(
    tenant_id: &str,
    actor_id: &str,
    action: &str,
    resource_id: &str,
    metadata: Option<Value>,
) -> Record {
    let mut event = Record::new();
    event.insert("id".into(), Value::String(id()));
    event.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    event.insert("actorId".into(), Value::String(actor_id.to_owned()));
    event.insert("action".into(), Value::String(action.to_owned()));
    event.insert("resourceId".into(), Value::String(resource_id.to_owned()));
    event.insert("timestamp".into(), crate::js::number(date_now()));
    event.insert("outcome".into(), Value::String("allow".into()));
    if let Some(metadata) = metadata {
        event.insert("metadata".into(), metadata);
    }
    event
}

/// Whether an invitation can no longer be redeemed: consumed, revoked or lapsed (on the wall clock).
fn invitation_dead(record: &Record) -> bool {
    truthy(record.get("consumed"))
        || truthy(record.get("revoked"))
        || record
            .get("expiresAt")
            .and_then(better_iam_core::js::as_number)
            // `undefined <= now` is false in JavaScript: an invitation without an expiry does not lapse.
            .is_some_and(|expires| expires <= date_now())
}

#[async_trait::async_trait]
impl FlowService for Flows {
    async fn accept_owner_invitation(&self, input: &Map<String, Value>) -> IamResult<Value> {
        let ctx = self.context()?;
        let link_principal = if truthy(input.get("linkCredential")) {
            Some(
                ctx.principals()?
                    .authenticate(&credential_from_json(input.get("linkCredential")))
                    .await?,
            )
        } else {
            None
        };
        if let Some(link) = &link_principal {
            if !ctx.config.linked_onboarding {
                return Err(IamError::new(
                    "LINKING_DISABLED",
                    "Linked onboarding is disabled",
                ));
            }
            ctx.auth.require_recent(link)?;
            if link.identity.root_admin {
                return Err(IamError::new(
                    "PROTECTED_IDENTITY",
                    "Root identities cannot link",
                ));
            }
            if link.session.kind != SessionKind::User || link.identity.kind != IdentityKind::User {
                return Err(IamError::new(
                    "INVALID_LINK",
                    "Linked onboarding requires an ordinary user session",
                ));
            }
        }
        let ctx_ref = &ctx;
        let link_principal = &link_principal;
        ctx.store
            .transaction(|tx| async move {
                let ctx = ctx_ref;
                let auth = &ctx.auth;
                let realm = ctx.tenant_of(&tx, input.get("tenantId")).await?;
                if realm.status != TenantStatus::Pending {
                    return Err(invitation_invalid("Invitation is invalid"));
                }
                let token = text(input.get("token"), "token", 256)?;
                let found = tx
                    .find(
                        "ownerInvitations",
                        &Filter::new()
                            .eq("tenantId", realm.id.clone())
                            .eq("tokenHash", hash(&token)),
                        &find_all(),
                    )
                    .await?
                    .into_iter()
                    .next();
                let Some(raw_invitation) = found.filter(|record| !invitation_dead(record)) else {
                    return Err(invitation_invalid("Invitation is invalid"));
                };
                let invitation: OwnerInvitation = decode(raw_invitation.clone())?;
                if let Some(parent_id) = realm.parent_id.as_deref().filter(|id| !id.is_empty()) {
                    let parent = ctx.tenant(&tx, parent_id).await?;
                    if ctx
                        .ancestry(&tx, &parent)
                        .await?
                        .iter()
                        .any(|item| item.status != TenantStatus::Active)
                    {
                        return Err(IamError::new("TENANT_INACTIVE", "Parent inactive"));
                    }
                }
                let authority: GrantAuthority = decode(
                    ctx.scoped(
                        &tx,
                        "grantAuthorities",
                        raw_invitation.get("authorityId"),
                        &realm.id,
                    )
                    .await?,
                )?;
                if ctx.authority_chain(&tx, &authority.id).await?.is_none() {
                    return Err(invitation_invalid("Invitation authority revoked"));
                }
                let name = Value::String(text(input.get("name"), "name", 256)?);
                let tenant_id = Value::String(realm.id.clone());
                let email = Value::String(invitation.email.clone());
                let identity = auth
                    .create_identity_raw(
                        &tx,
                        CreateIdentityRaw {
                            tenant_id: Some(&tenant_id),
                            email: Some(&email),
                            name: Some(&name),
                            password: input.get("password"),
                            owner: true,
                            root_admin: false,
                            email_verified: true,
                        },
                    )
                    .await?;
                ctx.owner_setup(&tx, &realm, &identity, &authority).await?;
                // The tenant as stored, so members this port does not know survive (`{ ...realm, status }`).
                let mut activated = match tx.get("tenants", &realm.id).await? {
                    Some(stored) => stored,
                    None => encode(&realm),
                };
                activated.insert("status".into(), Value::String("active".into()));
                tx.put("tenants", &activated).await?;
                let mut consumed = raw_invitation.clone();
                consumed.insert("consumed".into(), Value::Bool(true));
                tx.put("ownerInvitations", &consumed).await?;
                // The owner just set a password: the session is a password sign-in, recorded as one and refused like
                // one where the organization does not accept passwords.
                let issued = auth
                    .complete_authentication(&tx, &identity, Some(AuthMethod::Password), None)
                    .await?;
                if let Some(link) = link_principal {
                    let current = ctx.principals()?.current_principal(&tx, link).await?;
                    if raw_invitation.get("creatorId").and_then(Value::as_str)
                        != Some(current.identity.id.as_str())
                        || current.identity.root_admin
                        || current.session.kind != SessionKind::User
                    {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "Only this ordinary user organization creator may link during enrollment",
                            403,
                        ));
                    }
                    let mut pair = [&current.identity, &identity];
                    pair.sort_by(|a, b| by_id(&a.id, &b.id));
                    let mut link = Record::new();
                    link.insert("id".into(), Value::String(id()));
                    link.insert("tenantId".into(), Value::String(pair[0].tenant_id.clone()));
                    link.insert(
                        "uniqueKey".into(),
                        Value::String(format!("{}:{}", pair[0].id, pair[1].id)),
                    );
                    link.insert("leftId".into(), Value::String(pair[0].id.clone()));
                    link.insert("rightId".into(), Value::String(pair[1].id.clone()));
                    link.insert("revoked".into(), Value::Bool(false));
                    tx.insert("identityLinks", &link).await?;
                }
                ctx.events()?
                    .record_audit(
                        &tx,
                        &audit_event(&realm.id, &identity.id, "tenant:activate", &realm.id, None),
                    )
                    .await?;
                enrollment(&identity, &issued)
            })
            .await
    }

    async fn accept_member_invitation(&self, input: &Map<String, Value>) -> IamResult<Value> {
        let ctx = self.context()?;
        let ctx_ref = &ctx;
        ctx.store
            .transaction(|tx| async move {
                let ctx = ctx_ref;
                let auth = &ctx.auth;
                let realm = ctx.tenant_of(&tx, input.get("tenantId")).await?;
                auth.assert_tenant_active(&tx, &realm.id).await?;
                let token = text(input.get("token"), "token", 256)?;
                let found = tx
                    .find(
                        "memberInvitations",
                        &Filter::new()
                            .eq("tenantId", realm.id.clone())
                            .eq("tokenHash", hash(&token)),
                        &find_all(),
                    )
                    .await?
                    .into_iter()
                    .next();
                let Some(raw_invitation) = found.filter(|record| !invitation_dead(record)) else {
                    return Err(invitation_invalid("Invitation is invalid"));
                };
                let invitation: MemberInvitation = decode(raw_invitation.clone())?;
                // The inviter must still be able to grant what the invitation grants.
                assert_member_invitation_grantable(ctx, &tx, &invitation, &realm.id).await?;
                let name = match input.get("name") {
                    Some(value) => Some(text(Some(value), "name", 256)?),
                    None => invitation.name.clone(),
                };
                let Some(name) = name.filter(|name| !name.is_empty()) else {
                    return Err(IamError::new("INVALID_INPUT", "A name is required"));
                };
                let tenant_id = Value::String(realm.id.clone());
                let email = Value::String(invitation.email.clone());
                let name = Value::String(name);
                let identity = auth
                    .create_identity_raw(
                        &tx,
                        CreateIdentityRaw {
                            tenant_id: Some(&tenant_id),
                            email: Some(&email),
                            name: Some(&name),
                            password: input.get("password"),
                            owner: false,
                            root_admin: false,
                            email_verified: true,
                        },
                    )
                    .await?;
                for role_id in &invitation.role_ids {
                    let role: Role = ctx.scoped_as(&tx, "roles", role_id, &realm.id).await?;
                    if role.protected {
                        return Err(IamError::with_status(
                            "PROTECTED_RESOURCE",
                            "Invitation grants a protected role",
                            403,
                        ));
                    }
                    let authority = invitation.authority_id.as_deref();
                    let mut binding = Record::new();
                    binding.insert("id".into(), Value::String(id()));
                    binding.insert("tenantId".into(), Value::String(realm.id.clone()));
                    binding.insert(
                        "uniqueKey".into(),
                        Value::String(format!(
                            "identity:{}:{}:{}",
                            identity.id,
                            role.id,
                            authority.unwrap_or("undefined")
                        )),
                    );
                    binding.insert("subjectType".into(), Value::String("identity".into()));
                    binding.insert("subjectId".into(), Value::String(identity.id.clone()));
                    binding.insert("roleId".into(), Value::String(role.id.clone()));
                    if let Some(authority) = authority {
                        binding.insert("authorityId".into(), Value::String(authority.to_owned()));
                    }
                    tx.insert("bindings", &binding).await?;
                }
                for group_id in &invitation.group_ids {
                    ctx.scoped(
                        &tx,
                        "groups",
                        Some(&Value::String(group_id.clone())),
                        &realm.id,
                    )
                    .await?;
                    let mut member = Record::new();
                    member.insert("id".into(), Value::String(id()));
                    member.insert("tenantId".into(), Value::String(realm.id.clone()));
                    member.insert(
                        "uniqueKey".into(),
                        Value::String(format!("{group_id}:{}", identity.id)),
                    );
                    member.insert("groupId".into(), Value::String(group_id.clone()));
                    member.insert("identityId".into(), Value::String(identity.id.clone()));
                    tx.insert("groupMembers", &member).await?;
                }
                // License products assigned to those groups seat the new member at once (licenses.ts).
                if !invitation.group_ids.is_empty() {
                    crate::licenses::reconcile_group_licenses(
                        ctx,
                        &tx,
                        &realm.id,
                        &json!(invitation.group_ids),
                        &Value::String(invitation.inviter_id.clone()),
                    )
                    .await?;
                }
                crate::sod::sod_assert_identity(ctx, &tx, &realm.id, &identity.id).await?;
                let mut consumed = raw_invitation.clone();
                consumed.insert("consumed".into(), Value::Bool(true));
                tx.put("memberInvitations", &consumed).await?;
                ctx.events()?
                    .record_audit(
                        &tx,
                        &audit_event(
                            &realm.id,
                            &identity.id,
                            "identity:invitation:accept",
                            &invitation.id,
                            Some(json!({
                                "inviterId": invitation.inviter_id,
                                "roleIds": invitation.role_ids,
                                "groupIds": invitation.group_ids,
                            })),
                        ),
                    )
                    .await?;
                // A password sign-in, like the owner invitation's: METHOD_NOT_ALLOWED applies and `session.method` is
                // set.
                let issued = auth
                    .complete_authentication(&tx, &identity, Some(AuthMethod::Password), None)
                    .await?;
                enrollment(&identity, &issued)
            })
            .await
    }

    async fn link_identities(
        &self,
        left: &CredentialInput,
        right: &CredentialInput,
    ) -> IamResult<Value> {
        let ctx = self.context()?;
        if !ctx.config.linked_onboarding {
            return Err(IamError::new(
                "LINKING_DISABLED",
                "Account linking disabled",
            ));
        }
        let principals = ctx.principals()?;
        let (left, right) = futures::join!(
            principals.authenticate(left),
            principals.authenticate(right)
        );
        let (left, right) = (left?, right?);
        ctx.auth.require_recent(&left)?;
        ctx.auth.require_recent(&right)?;
        if left.identity.root_admin
            || right.identity.root_admin
            || left.session.kind != SessionKind::User
            || right.session.kind != SessionKind::User
            || left.identity.tenant_id == right.identity.tenant_id
        {
            return Err(IamError::new(
                "INVALID_LINK",
                "Only separate ordinary tenant identities can link",
            ));
        }
        let ctx_ref = &ctx;
        let (left, right) = (&left, &right);
        ctx.store
            .transaction(|tx| async move {
                let ctx = ctx_ref;
                let current_left = ctx.principals()?.current_principal(&tx, left).await?;
                let current_right = ctx.principals()?.current_principal(&tx, right).await?;
                if current_left.identity.root_admin
                    || current_right.identity.root_admin
                    || current_left.session.kind != SessionKind::User
                    || current_right.session.kind != SessionKind::User
                {
                    return Err(IamError::new(
                        "INVALID_LINK",
                        "Only ordinary user identities can link",
                    ));
                }
                let mut identities = [&current_left.identity, &current_right.identity];
                identities.sort_by(|a, b| by_id(&a.id, &b.id));
                let tenant_id = identities[0].tenant_id.clone();
                let unique_key = format!("{}:{}", identities[0].id, identities[1].id);
                let existing = tx
                    .find(
                        "identityLinks",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("uniqueKey", unique_key.clone()),
                        &find_all(),
                    )
                    .await?
                    .into_iter()
                    .next();
                if let Some(existing) = &existing
                    && !truthy(existing.get("revoked"))
                {
                    return Err(IamError::with_status(
                        "CONFLICT",
                        "These identities are already linked",
                        409,
                    ));
                }
                let link = match existing {
                    Some(mut existing) => {
                        existing.insert("revoked".into(), Value::Bool(false));
                        tx.put("identityLinks", &existing).await?
                    }
                    None => {
                        let mut link = Record::new();
                        link.insert("id".into(), Value::String(id()));
                        link.insert("tenantId".into(), Value::String(tenant_id));
                        link.insert("uniqueKey".into(), Value::String(unique_key));
                        link.insert("leftId".into(), Value::String(identities[0].id.clone()));
                        link.insert("rightId".into(), Value::String(identities[1].id.clone()));
                        link.insert("revoked".into(), Value::Bool(false));
                        tx.insert("identityLinks", &link).await?
                    }
                };
                ctx.events()?
                    .audit(
                        &tx,
                        &current_left,
                        "identity:link",
                        &current_left.identity.tenant_id,
                        better_iam_core::record_id(&link),
                        AuditOutcome::Allow,
                        false,
                        None,
                    )
                    .await?;
                Ok(Value::Object(link))
            })
            .await
    }

    async fn switch_identity(
        &self,
        credential: &CredentialInput,
        link_id: Option<&Value>,
        target: &CredentialInput,
    ) -> IamResult<Value> {
        let ctx = self.context()?;
        let principals = ctx.principals()?;
        let (source, target) = futures::join!(
            principals.authenticate(credential),
            principals.authenticate(target)
        );
        let (source, target) = (source?, target?);
        ctx.auth.require_recent(&target)?;
        let ctx_ref = &ctx;
        let (source, target) = (&source, &target);
        ctx.store
            .transaction(|tx| async move {
                let ctx = ctx_ref;
                let current_source = ctx.principals()?.current_principal(&tx, source).await?;
                let current_target = ctx.principals()?.current_principal(&tx, target).await?;
                let link_id = text(link_id, "linkId", 256)?;
                let link = tx.get("identityLinks", &link_id).await?;
                let members: Vec<&str> = link
                    .as_ref()
                    .map(|link| {
                        ["leftId", "rightId"]
                            .iter()
                            .filter_map(|key| link.get(*key).and_then(Value::as_str))
                            .collect()
                    })
                    .unwrap_or_default();
                let valid = link
                    .as_ref()
                    .is_some_and(|link| !truthy(link.get("revoked")))
                    && source.identity.id != target.identity.id
                    && members.contains(&source.identity.id.as_str())
                    && members.contains(&target.identity.id.as_str())
                    && !current_source.identity.root_admin
                    && !current_target.identity.root_admin
                    && current_source.session.kind == SessionKind::User
                    && current_target.session.kind == SessionKind::User;
                if !valid {
                    return Err(IamError::with_status(
                        "INVALID_LINK",
                        "Invalid identity link",
                        403,
                    ));
                }
                let issued = ctx
                    .auth
                    .issue_session(
                        &tx,
                        &current_target.identity,
                        IssueSessionOptions {
                            mfa: Some(current_target.session.mfa),
                            authenticated_at: Some(current_target.session.authenticated_at),
                            method: current_target.session.method,
                            trusted_device_id: None,
                            // principal.mfaTime carries the target's own ceremony forward, never the switch time.
                            mfa_authenticated_at: current_target.session.mfa_authenticated_at,
                        },
                    )
                    .await?;
                ctx.events()?
                    .audit(
                        &tx,
                        &current_source,
                        "identity:switch",
                        &current_target.identity.tenant_id,
                        &current_target.identity.id,
                        AuditOutcome::Allow,
                        false,
                        None,
                    )
                    .await?;
                serde_json::to_value(&issued).map_err(|_| crate::js::internal_error())
            })
            .await
    }

    async fn assume_role(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
    ) -> IamResult<Value> {
        let ctx = self.context()?;
        // In-process integrations that pass the incoming request's headers as the credential (with no client scope
        // set) get the client derived from those headers (`http.clientInfo`), as `sts.getSessionToken` does, so the
        // role session records its issuing client and allowlists, network blocks and `bindSessionsToIp` judge it.
        if ctx.auth.current_client().is_none() && credential.headers.is_some() {
            let client = client_from_headers(
                ctx.options.http.as_ref(),
                credential.headers.as_deref(),
                ctx.config.base_url.as_str(),
            );
            return ctx
                .auth
                .with_client(client, Box::pin(assume(&ctx, credential, input)))
                .await;
        }
        assume(&ctx, credential, input).await
    }
}

/// The body of `assumeRole` (the TypeScript `assume` closure).
async fn assume(
    ctx: &Arc<ServerContext>,
    credential: &CredentialInput,
    input: &Map<String, Value>,
) -> IamResult<Value> {
    let principal_before = ctx.principals()?.authenticate(credential).await?;
    if principal_before.session.kind == SessionKind::Role {
        return Err(IamError::new(
            "ROLE_CHAINING_DISABLED",
            "Role chaining is disabled",
        ));
    }
    if principal_before
        .session
        .impersonator_id
        .as_deref()
        .is_some_and(|id| !id.is_empty())
    {
        return Err(IamError::with_status(
            "IMPERSONATION_RESTRICTED",
            "Roles cannot be assumed while impersonating a member",
            403,
        ));
    }
    // Only the sources a role session may be validated against (principals.ts roleSourceKinds): a delegated agent
    // session is bounded by its delegation and must not mint a role credential (a JWT would outlive it offline).
    if !role_source(&principal_before.session) {
        return Err(IamError::with_status(
            "CREDENTIAL_CHAINING_DISABLED",
            "Delegated sessions cannot assume roles",
            400,
        ));
    }
    // Input shapes are refused before any lookup; trust-dependent rules run inside the operation.
    let session_name = session_name_value(input.get("sessionName"))?;
    let source_identity = source_identity_value(input.get("sourceIdentity"))?;
    let tags = session_tags_value(input.get("tags"))?;
    let format = credential_format(input.get("format"))?;
    let audience = audience_value(input.get("audience"), &format)?;
    if format.as_str() == Some("jwt") && ctx.session_tokens().is_none() {
        return Err(IamError::with_status(
            "FEATURE_DISABLED",
            "Session JWTs are not enabled on this deployment (sts.jwt)",
            403,
        ));
    }
    if let Some(external_id) = input.get("externalId")
        && !external_id.is_string()
    {
        return Err(IamError::new(
            "INVALID_INPUT",
            "externalId must be a string",
        ));
    }
    let target_tenant = crate::api::string_member(input, "tenantId");
    let requested_trust = ctx
        .scoped(&ctx.store, "trusts", input.get("trustId"), &target_tenant)
        .await?;
    let requested_role = requested_trust
        .get("roleId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let source_tenant = Value::String(principal_before.identity.tenant_id.clone());
    let tags = &tags;
    let session_name = &session_name;
    let source_identity = &source_identity;
    let format = &format;
    let audience = &audience;
    let target_tenant = &target_tenant;
    let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
        Box::pin(async move {
            let trust = ctx
                .scoped(&tx, "trusts", input.get("trustId"), target_tenant)
                .await?;
            let policy = input.get("policy").filter(|policy| truthy(Some(policy)));
            if let Some(policy) = policy {
                ctx.catalog
                    .validate(tx.as_ref(), target_tenant, policy)
                    .await?;
            }
            // Tags and a source identity can satisfy ABAC conditions, so both are closed unless the trust opens them.
            // Stored values are read fail-closed: a malformed list admits no tags, an unknown mode forbids.
            let allowed_tag_keys = trust_allowed_tag_keys(&trust);
            let mut tag_keys: Vec<String> = tags
                .as_ref()
                .map(|tags| tags.keys().cloned().collect())
                .unwrap_or_default();
            crate::js::sort_strings(&mut tag_keys);
            let tags_admitted = allowed_tag_keys.any
                || tag_keys
                    .iter()
                    .all(|key| allowed_tag_keys.keys.contains(key));
            let source_identity_mode = trust_source_identity_mode(&trust);
            let identity_kind = match trust.get("kind") {
                None | Some(Value::Null) => true,
                Some(kind) => kind.as_str() == Some("identity"),
            };
            let permitted = role_source(&principal.session)
                && !truthy(trust.get("revoked"))
                && identity_kind
                && trust.get("sourceIdentityId").and_then(Value::as_str)
                    == Some(principal.identity.id.as_str())
                && trust.get("sourceTenantId").and_then(Value::as_str)
                    == Some(principal.identity.tenant_id.as_str())
                && !(trust_record_requires_mfa(&trust) && !principal.session.mfa)
                && external_id_matches(trust.get("externalIdHash"), input.get("externalId"))
                && tags_admitted
                && !(source_identity_mode == "forbidden" && source_identity.is_some())
                && !(source_identity_mode == "required" && source_identity.is_none());
            if !permitted {
                return Err(IamError::with_status(
                    "ACCESS_DENIED",
                    "Role trust does not permit assumption",
                    403,
                )
                .into());
            }
            let target: Tenant = ctx.tenant_of(&tx, input.get("tenantId")).await?;
            if ctx
                .ancestry(&tx, &target)
                .await?
                .iter()
                .any(|item| item.status != TenantStatus::Active)
            {
                return Err(IamError::new("TENANT_INACTIVE", "Target tenant inactive").into());
            }
            let role: Role = decode(
                ctx.scoped(&tx, "roles", trust.get("roleId"), target_tenant)
                    .await?,
            )?;
            let trust_value = Value::Object(trust.clone());
            let duration_seconds = duration_within(
                input.get("durationSeconds"),
                &role_duration_bounds(ctx, &trust_value, format)?,
            )?;
            // The injected clock, like user sessions, so validation and issuance agree under a test clock.
            let now = ctx.now();
            let source_authority_ids: Vec<String> = ctx
                .decisions()?
                .identity_grants(
                    &tx,
                    &principal.identity.id,
                    &principal.identity.tenant_id,
                    None,
                    None,
                )
                .await?
                .into_iter()
                .map(|path| path.authority_id)
                .collect();
            let number = crate::js::number;
            let trust_id = trust.get("id").cloned().unwrap_or(Value::Null);
            let mut draft = Map::new();
            draft.insert("id".into(), Value::String(id()));
            draft.insert("tenantId".into(), Value::String(target_tenant.clone()));
            draft.insert(
                "identityId".into(),
                Value::String(principal.identity.id.clone()),
            );
            draft.insert(
                "originalIdentityId".into(),
                Value::String(principal.identity.id.clone()),
            );
            draft.insert(
                "sourceTenantId".into(),
                Value::String(principal.identity.tenant_id.clone()),
            );
            draft.insert(
                "sourceSessionId".into(),
                Value::String(principal.session.id.clone()),
            );
            draft.insert("sourceAuthorityIds".into(), json!(source_authority_ids));
            draft.insert("roleId".into(), Value::String(role.id.clone()));
            draft.insert("trustId".into(), trust_id.clone());
            draft.insert("kind".into(), Value::String("role".into()));
            draft.insert("tokenHash".into(), Value::String(String::new()));
            draft.insert("createdAt".into(), number(now));
            draft.insert("lastSeenAt".into(), number(now));
            // The source's authentication carries over; its sign-in method and remembered device do not.
            draft.insert(
                "authenticatedAt".into(),
                number(principal.session.authenticated_at),
            );
            draft.insert(
                "expiresAt".into(),
                number(
                    principal
                        .session
                        .expires_at
                        .min(now + duration_seconds * 1000.0),
                ),
            );
            draft.insert("mfa".into(), Value::Bool(principal.session.mfa));
            if principal.session.mfa
                && let Some(at) = principal.session.mfa_authenticated_at
            {
                draft.insert("mfaAuthenticatedAt".into(), number(at));
            }
            if let Some(policy) = policy {
                draft.insert("policy".into(), policy.clone());
            }
            if let Some(name) = session_name {
                draft.insert("sessionName".into(), Value::String(name.clone()));
            }
            if let Some(source) = source_identity {
                draft.insert("sourceIdentity".into(), Value::String(source.clone()));
            }
            if let Some(tags) = tags {
                draft.insert("sessionTags".into(), json!(tags));
            }
            // The issuing address, so the target tenant's allowlist and network blocks judge it on every use.
            if let Some(client) = ctx.auth.current_client()
                && let Ok(Value::Object(client)) = serde_json::to_value(&client)
                && !client.is_empty()
            {
                draft.insert("client".into(), Value::Object(client));
            }
            let mut mint = Map::new();
            mint.insert(
                "identity".into(),
                Value::Object(encode(&principal.identity)),
            );
            mint.insert("draft".into(), Value::Object(draft));
            mint.insert("format".into(), format.clone());
            if let Some(audience) = audience {
                mint.insert("audience".into(), json!(audience));
            }
            let minted = mint_credential(ctx, &tx, &Value::Object(mint)).await?;
            let token = minted
                .get("token")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let session: Session = match minted.get("session") {
                Some(Value::Object(session)) => decode(session.clone())?,
                _ => return Err(crate::js::internal_error().into()),
            };
            // The target tenant sees who assumed its role, under the new session's context.
            let mut metadata = Map::new();
            metadata.insert("trustId".into(), trust_id);
            metadata.insert(
                "sourceTenantId".into(),
                Value::String(principal.identity.tenant_id.clone()),
            );
            metadata.insert(
                "sourceSessionKind".into(),
                Value::String(principal.session.kind.as_str().into()),
            );
            metadata.insert("durationSeconds".into(), number(duration_seconds));
            metadata.insert("format".into(), format.clone());
            metadata.insert("tagKeys".into(), json!(tag_keys));
            // Whether the source identity's attributes reach this session's decisions (read as a boolean).
            metadata.insert(
                "passSourceAttributes".into(),
                Value::Bool(trust_record_passes_source_attributes(&trust)),
            );
            ctx.events()?
                .audit(
                    &tx,
                    &AuthenticatedPrincipal {
                        identity: principal.identity.clone(),
                        session: session.clone(),
                        device_proof: None,
                    },
                    "role:assumed",
                    target_tenant,
                    &role.id,
                    AuditOutcome::Allow,
                    false,
                    Some(metadata),
                )
                .await?;
            let credential = temporary_credential(&token, &session, now)?;
            Ok(serde_json::to_value(&credential).map_err(|_| crate::js::internal_error())?)
        })
    });
    ctx.operations()?
        .operation(
            credential,
            Some(&source_tenant),
            "iam:roles:assume",
            &requested_role,
            mutation,
            false,
        )
        .await
}
