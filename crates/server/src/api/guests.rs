//! Port of `packages/server/src/api/guests.ts`: B2B guest collaboration (guests.rs): email invitations and their
//! public redemption, the guest directory, sponsor attestation, sponsor changes, removal, conversion to a member, and
//! the tenant's cross-tenant access settings, plus the guest scheduler jobs (`iam.guests`). Actions
//! `iam:guests:read`, `iam:guests:invite`, `iam:guests:manage` and `iam:guests:settings` on `iam/guests`,
//! `iam/guests/{identityId}`, `iam/guests/invitations[/{id}]` and `iam/guests/settings`.
//!
//! Records are read and written as raw JSON records, so member order and members this port does not know survive a
//! round trip (a mixed fleet shares the database with TypeScript).

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

use better_iam_auth::outbox::EnqueueInput;
use better_iam_auth::service::LimitAttemptOptions;
use better_iam_auth::service::base::CreateIdentityInput;
use better_iam_core::boxed;
use better_iam_core::js::{cmp_utf16, number_to_string, trim};
use better_iam_core::{
    AuditOutcome, AuthMethod, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions,
    IamError, IamResult, IamStoreExt, Identity, OutboxKind, Record, SessionKind, Tenant,
    ip_counter_key,
};
use better_iam_types::api::guests;
use indexmap::IndexSet;
use serde_json::{Map, Value, json};

use crate::api::domains::domain_name;
use crate::api::groups::assert_may_claim_licenses;
use crate::api::identities::{assert_owner_control, revoke_invitations_by};
use crate::api::package_automation::after_identity_change;
use crate::api::packages::{
    allow, assign_package, authorize_package, retime_assignment, revoke_assignment,
};
use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, OperationDenied, OperationResult};
use crate::delegations::revoke_delegations_of;
use crate::departments::release_departments;
use crate::guests::{
    ACCOUNTS, GUEST_DAY_MS, GuestOrigin, INVITATIONS, SETTINGS, assert_guest_admitted, can_sponsor,
    guest_address, guest_origin, guest_settings, guest_settings_value, guest_sponsor, is_guest,
    is_guest_identity, limits, read_guest_settings_record, set_guest_sponsor,
};
use crate::invariants::{invariant_snapshot, invariant_verify};
use crate::js::{internal_error, js_string, number, truthy, unique};
use crate::metrics::locale_compare;
use crate::models::{AccessPackage, PackageAssignment};
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::port::decode;
use crate::session_kinds::acts_in_own_right;
use crate::sod::sod_assert_identity;
use crate::teams::{
    assert_not_team_group, is_team_group, remove_from_all_teams, sync_teams_from_groups,
};
use crate::threats::end_containment;
use crate::utils::{by_newest_records, hash, id, public_identity_record, token};
use crate::validation::{integer, object, strings, text};

const ACCOUNT_STATUSES: [&str; 4] = ["active", "expired", "removed", "converted"];
const INVITATION_STATUSES: [&str; 4] = ["pending", "redeemed", "revoked", "expired"];

fn guest_resource(identity_id: &str) -> String {
    format!("guests/{identity_id}")
}

fn invitation_resource(invitation_id: &str) -> String {
    format!("guests/invitations/{invitation_id}")
}

fn pending_key(address: &str) -> String {
    format!("pending:{address}")
}

/// `new Date(at).toISOString()`.
fn iso(at: f64) -> IamResult<String> {
    better_iam_core::js::iso_string(at).ok_or_else(internal_error)
}

/// A new invitation token: `biam_gst_` and 43 random base64url characters, a prefix secret scanners can look for.
fn invitation_token() -> String {
    format!("biam_gst_{}", token())
}

fn find_all() -> FindOptions {
    FindOptions::default()
}

async fn find(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &find_all()).await
}

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// A member as a string (`record.member` where TypeScript reads a string field); `""` when it is not one.
fn s<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// A numeric member, or None when it is absent or not a number.
fn num(record: &Record, key: &str) -> Option<f64> {
    record.get(key).and_then(Value::as_f64)
}

/// A string-list member (`roleIds`, `bindingIds`, ...): its string items.
fn list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map_or_else(|| js_string(Some(item)), str::to_owned)
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Copies `key` from `from` into `to` when it is present (`{ key: from.key }`, which JSON drops when undefined).
fn copy(to: &mut Map<String, Value>, from: &Record, key: &str) {
    if let Some(value) = from.get(key) {
        to.insert(key.into(), value.clone());
    }
}

/// `value ?? fallback`: the value unless it is absent or null.
fn nullish<'a>(value: Option<&'a Value>, fallback: &'a Value) -> &'a Value {
    match value {
        None | Some(Value::Null) => fallback,
        Some(value) => value,
    }
}

/// `identityExpired(identity)` of a raw identity record.
fn expired_record(ctx: &ServerContext, identity: &Record) -> bool {
    num(identity, "expiresAt").is_some_and(|expires| expires <= ctx.now())
}

fn strings_value(items: &[String]) -> Value {
    Value::Array(items.iter().cloned().map(Value::String).collect())
}

fn sends_email(ctx: &ServerContext) -> bool {
    ctx.options
        .authentication
        .as_ref()
        .is_some_and(|authentication| authentication.send_email.is_some())
}

fn flag(value: Option<&Value>, name: &str) -> IamResult<bool> {
    match value {
        Some(Value::Bool(flag)) => Ok(*flag),
        _ => Err(invalid(format!("{name} must be a boolean"))),
    }
}

/// An object whose keys are all among `allowed`.
fn fields<'a>(
    value: Option<&'a Value>,
    name: &str,
    allowed: &[&str],
) -> IamResult<&'a Map<String, Value>> {
    let record = object(value)?;
    for key in record.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid(format!("Unknown {name} setting {key}")));
        }
    }
    Ok(record)
}

/// Lowercase domains, each checked like a verified domain, deduplicated and sorted.
fn domain_list(value: Option<&Value>, name: &str) -> IamResult<Vec<String>> {
    let mut domains = Vec::new();
    for entry in strings(value, name)? {
        domains.push(domain_name(Some(&Value::String(entry)))?);
    }
    let mut domains = unique(domains);
    domains.sort_by(|a, b| cmp_utf16(a, b));
    Ok(domains)
}

/// Partner organizations by tenant ID: existing tenants other than this one, each named once.
async fn partner_list(
    tx: &Store,
    tenant_id: &str,
    value: Option<&Value>,
    name: &str,
) -> IamResult<Vec<(String, bool)>> {
    let items = match value {
        Some(Value::Array(items)) if items.len() <= 100 => items,
        _ => {
            return Err(invalid(format!(
                "{name} must list at most 100 organizations"
            )));
        }
    };
    let mut partners: Vec<(String, bool)> = Vec::new();
    for item in items {
        let entry = fields(Some(item), name, &["tenantId", "allow"])?;
        let partner_id = text(entry.get("tenantId"), &format!("{name}.tenantId"), 256)?;
        let allowed = flag(entry.get("allow"), &format!("{name}.allow"))?;
        if partner_id == tenant_id {
            return Err(invalid(format!("{name} cannot name this organization")));
        }
        if partners.iter().any(|(id, _)| id == &partner_id) {
            return Err(invalid(format!("{name} names {partner_id} more than once")));
        }
        let partner = tx.get("tenants", &partner_id).await?;
        if partner
            .as_ref()
            .is_none_or(|partner| s(partner, "status") == "deleted")
        {
            return Err(invalid(format!(
                "{name}: unknown organization {partner_id}"
            )));
        }
        partners.push((partner_id, allowed));
    }
    partners.sort_by(|a, b| cmp_utf16(&a.0, &b.0));
    Ok(partners)
}

fn partners_value(partners: &[(String, bool)]) -> Value {
    Value::Array(
        partners
            .iter()
            .map(|(tenant_id, allow)| json!({ "tenantId": tenant_id, "allow": allow }))
            .collect(),
    )
}

/// A person's own session in the tenant: an ordinary user session or their API key, of that tenant.
fn own_session(principal: &AuthenticatedPrincipal, tenant_id: &str, what: &str) -> IamResult<()> {
    if !acts_in_own_right(principal.session.kind)
        || principal.session.tenant_id != tenant_id
        || principal.identity.tenant_id != tenant_id
    {
        return Err(IamError::with_status(
            "ACCESS_DENIED",
            format!("{what} from an ordinary session of the organization"),
            403,
        ));
    }
    Ok(())
}

/// The caller as the sponsor of the guests they invite, when they can sponsor guests themselves.
fn caller_sponsor(
    ctx: &Arc<ServerContext>,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
) -> IamResult<Identity> {
    if !acts_in_own_right(principal.session.kind)
        || principal.session.tenant_id != tenant_id
        || !can_sponsor(ctx, Some(&principal.identity), tenant_id)
    {
        return Err(IamError::new(
            "INVALID_SPONSOR",
            "Name a sponsor (sponsorId): only an active member of the organization who is not a guest can sponsor guests",
        ));
    }
    Ok(principal.identity.clone())
}

fn impersonating(principal: &AuthenticatedPrincipal) -> bool {
    principal
        .session
        .impersonator_id
        .as_deref()
        .is_some_and(|id| !id.is_empty())
}

fn iam_request(tenant_id: &str, action: &str, resource_id: &str) -> AuthorizationRequest {
    AuthorizationRequest {
        credential: CredentialInput::default(),
        tenant_id: tenant_id.to_owned(),
        action: action.to_owned(),
        resource: ResourceTarget {
            kind: "iam".into(),
            id: resource_id.to_owned(),
        },
    }
}

/// Naming someone other than oneself as a guest's sponsor makes them accountable for the guest, and gives the guest
/// whatever policies grant on `principal.guestSponsorId`, so it needs what giving a guest another sponsor needs:
/// iam:guests:manage (here on iam/guests/invitations). Checked before the sponsor is validated, so it reveals nothing
/// about them; the refusal is audited as a denial.
async fn authorize_other_sponsor(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    sponsor_id: Option<&Value>,
) -> OperationResult<()> {
    if text(sponsor_id, "sponsorId", 256)? == principal.identity.id
        && acts_in_own_right(principal.session.kind)
        && principal.session.tenant_id == tenant_id
    {
        return Ok(());
    }
    let decision = ctx
        .decisions()?
        .decide(
            tx,
            principal,
            &iam_request(tenant_id, "iam:guests:manage", "guests/invitations"),
            true,
        )
        .await?;
    if !decision.allowed {
        return Err(OperationDenied::new(Some(
            "Naming someone else as the sponsor needs iam:guests:manage",
        )));
    }
    Ok(())
}

/// Moving the access end of a guest who owns the organization (or is a root administrator) changes an owner's
/// expiry, so it needs what `identities.update` asks for: an owner of the tenant in person or a root caller; and an
/// end (`next`) is never given to the last active owner, nor to the last owner without one.
async fn assert_owner_expiry_control(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    identity: &Identity,
    next: Option<f64>,
) -> OperationResult<()> {
    if identity.root_admin && !ctx.root_principal(tx, principal).await? {
        return Err(
            IamError::with_status("ACCESS_DENIED", "Root capability is protected", 403).into(),
        );
    }
    assert_owner_control(
        ctx,
        tx,
        principal,
        identity,
        "Only an owner can change an owner\u{2019}s expiry",
    )
    .await?;
    if !identity.owner || next.is_none() {
        return Ok(());
    }
    ctx.protect_last_owner(tx, identity).await?;
    if identity.expires_at.is_none() {
        let owners = find(
            tx,
            "identities",
            Filter::new()
                .eq("tenantId", identity.tenant_id.clone())
                .eq("owner", true)
                .eq("status", "active"),
        )
        .await?;
        let another_without_end = owners.iter().any(|other| {
            s(other, "id") != identity.id && !other.get("expiresAt").is_some_and(Value::is_number)
        });
        if !another_without_end {
            return Err(IamError::with_status(
                "LAST_OWNER",
                "The last owner without an expiry cannot be given one",
                409,
            )
            .into());
        }
    }
    Ok(())
}

/// Display names by identity ID, each read once per call.
struct NameReader {
    tx: Store,
    names: HashMap<String, Option<Value>>,
}

impl NameReader {
    fn new(tx: &Store) -> Self {
        Self {
            tx: tx.clone(),
            names: HashMap::new(),
        }
    }

    async fn name_of(&mut self, identity_id: &str) -> IamResult<Option<Value>> {
        if !self.names.contains_key(identity_id) {
            let name = self
                .tx
                .get("identities", identity_id)
                .await?
                .and_then(|identity| identity.get("name").cloned());
            self.names.insert(identity_id.to_owned(), name);
        }
        Ok(self.names.get(identity_id).cloned().flatten())
    }
}

/// A guest's account and identity in the tenant.
struct LoadedGuest {
    account: Record,
    identity: Record,
    typed: Identity,
}

/// A guest's account and identity in the tenant; NOT_FOUND for anyone else.
async fn load_guest(tx: &Store, tenant_id: &str, identity_id: &str) -> IamResult<LoadedGuest> {
    let account = tx.get(ACCOUNTS, identity_id).await?;
    let identity = match &account {
        Some(account) if account.get("tenantId").and_then(Value::as_str) == Some(tenant_id) => {
            tx.get("identities", &js_string(account.get("identityId")))
                .await?
        }
        _ => None,
    };
    match (account, identity) {
        (Some(account), Some(identity))
            if identity.get("tenantId").and_then(Value::as_str) == Some(tenant_id)
                && s(&identity, "status") != "deleted" =>
        {
            let typed = decode(identity.clone())?;
            Ok(LoadedGuest {
                account,
                identity,
                typed,
            })
        }
        _ => Err(IamError::with_status("NOT_FOUND", "Guest not found", 404)),
    }
}

/// Refuses an address that already belongs to someone in the tenant. A former guest's disabled account keeps its
/// address, so the refusal says how to go on: delete that account first (the audit trail keeps its history).
async fn assert_newcomer(tx: &Store, tenant_id: &str, address: &str) -> IamResult<()> {
    let existing = find(
        tx,
        "identities",
        Filter::new().eq("tenantId", tenant_id).eq("email", address),
    )
    .await?;
    if let Some(existing) = existing.first() {
        let message = if truthy(existing.get("guest")) && s(existing, "status") == "disabled" {
            "This address belongs to a former guest whose disabled account still holds it: delete that account to invite the address again"
        } else {
            "Someone with this email address already belongs to this organization"
        };
        return Err(IamError::with_status("CONFLICT", message, 409));
    }
    Ok(())
}

/// Makes way for a pending invitation to `address`: another one still open is a conflict, and one that lapsed
/// without the worker noticing is marked expired first. `except` is the invitation being sent again.
async fn claim_pending_key(
    tx: &Store,
    tenant_id: &str,
    address: &str,
    now: f64,
    except: Option<&str>,
) -> IamResult<()> {
    for open in find(
        tx,
        INVITATIONS,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("uniqueKey", pending_key(address)),
    )
    .await?
    {
        if except.is_some_and(|except| open.get("id").and_then(Value::as_str) == Some(except)) {
            continue;
        }
        if num(&open, "expiresAt").is_some_and(|expires| expires > now) {
            return Err(IamError::with_status(
                "CONFLICT",
                "This address already has a pending guest invitation: send it again or revoke it",
                409,
            ));
        }
        let mut rest = open;
        rest.shift_remove("uniqueKey");
        rest.insert("status".into(), Value::String("expired".into()));
        tx.put(INVITATIONS, &rest).await?;
    }
    Ok(())
}

/// The account's status as it stands: an active account whose access end passed is expired already.
fn account_status(ctx: &ServerContext, account: &Record, identity: &Record) -> Value {
    if s(account, "status") == "active" && expired_record(ctx, identity) {
        Value::String("expired".into())
    } else {
        account.get("status").cloned().unwrap_or(Value::Null)
    }
}

async fn guest_view(
    ctx: &ServerContext,
    tx: &Store,
    account: &Record,
    identity: &Record,
    names: &mut NameReader,
) -> IamResult<Value> {
    let sponsor_name = names.name_of(s(account, "sponsorId")).await?;
    let sign_ins = tx.get("authSignIns", s(identity, "id")).await?;
    let mut view = Map::new();
    copy(&mut view, identity, "id");
    if let Some(id) = view.shift_remove("id") {
        view.insert("identityId".into(), id);
    }
    copy(&mut view, identity, "tenantId");
    copy(&mut view, identity, "name");
    if truthy(identity.get("email")) {
        copy(&mut view, identity, "email");
    }
    copy(&mut view, identity, "status");
    view.insert(
        "accountStatus".into(),
        account_status(ctx, account, identity),
    );
    copy(&mut view, account, "sponsorId");
    if let Some(name) = sponsor_name {
        view.insert("sponsorName".into(), name);
    }
    view.insert(
        "sponsorMissing".into(),
        Value::Bool(account.get("sponsorMissing") == Some(&Value::Bool(true))),
    );
    if truthy(account.get("homeTenantId")) {
        copy(&mut view, account, "homeTenantId");
    }
    let home_domain = identity
        .get("guest")
        .and_then(|guest| guest.get("homeDomain"));
    if truthy(home_domain) {
        view.insert(
            "homeDomain".into(),
            home_domain.cloned().unwrap_or(Value::Null),
        );
    }
    for key in [
        "invitationId",
        "invitedBy",
        "redeemedAt",
        "attestedAt",
        "attestedBy",
        "reviewDueAt",
    ] {
        copy(&mut view, account, key);
    }
    copy(&mut view, identity, "expiresAt");
    if let Some(last) = sign_ins
        .as_ref()
        .and_then(|sign_ins| sign_ins.get("lastAt"))
        .filter(|last| last.is_number())
    {
        view.insert("lastSignInAt".into(), last.clone());
    }
    Ok(Value::Object(view))
}

async fn invitation_view(
    ctx: &ServerContext,
    invitation: &Record,
    names: &mut NameReader,
) -> IamResult<Value> {
    let sponsor_name = names.name_of(s(invitation, "sponsorId")).await?;
    let inviter_name = names.name_of(s(invitation, "invitedBy")).await?;
    let mut view = Map::new();
    for key in ["id", "tenantId", "email"] {
        copy(&mut view, invitation, key);
    }
    let lapsed = s(invitation, "status") == "pending"
        && num(invitation, "expiresAt").is_some_and(|expires| expires <= ctx.now());
    if lapsed {
        view.insert("status".into(), Value::String("expired".into()));
    } else {
        copy(&mut view, invitation, "status");
    }
    copy(&mut view, invitation, "sponsorId");
    if let Some(name) = sponsor_name {
        view.insert("sponsorName".into(), name);
    }
    copy(&mut view, invitation, "invitedBy");
    if let Some(name) = inviter_name {
        view.insert("inviterName".into(), name);
    }
    for key in ["message", "roleIds", "groupIds", "packageIds", "accessDays"] {
        copy(&mut view, invitation, key);
    }
    if truthy(invitation.get("homeTenantId")) {
        copy(&mut view, invitation, "homeTenantId");
    }
    for key in [
        "expiresAt",
        "createdAt",
        "sentAt",
        "redeemedAt",
        "identityId",
        "revokedAt",
        "revokedBy",
        "revokedReason",
    ] {
        copy(&mut view, invitation, key);
    }
    Ok(Value::Object(view))
}

fn settings_view(tenant_id: &str, settings: &Map<String, Value>, stored: Option<&Record>) -> Value {
    let mut view = Map::new();
    view.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    view.insert("configured".into(), Value::Bool(stored.is_some()));
    for key in ["inbound", "outbound", "accessDays", "reviewEveryDays"] {
        copy(&mut view, settings, key);
    }
    if truthy(settings.get("guestBoundary")) {
        copy(&mut view, settings, "guestBoundary");
    }
    if let Some(stored) = stored {
        copy(&mut view, stored, "updatedAt");
        copy(&mut view, stored, "updatedBy");
    }
    Value::Object(view)
}

/// What an invitation may grant, authorized like `identities.invite` and `packages.assign`: iam:bindings:create on
/// each role (never a protected one) under the caller's grant authority, iam:groups:update on each group (never a
/// team's backing group) plus the authorities of the group's own bindings and, when a license product is assigned to
/// one of the groups, iam:licenses:assign (api/groups.ts), and iam:packages:assign on each package with the rights to
/// assign it by hand. Returns the grant authority the roles and groups are made under.
async fn authorize_grants(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    role_ids: &[String],
    group_ids: &[String],
    package_ids: &[String],
) -> OperationResult<Option<String>> {
    let authority_id = if !role_ids.is_empty() || !group_ids.is_empty() {
        Some(
            ctx.granting_authority(tx, principal, tenant_id, None)
                .await?
                .id,
        )
    } else {
        None
    };
    for role_id in role_ids {
        let role = ctx
            .scoped(
                tx,
                "roles",
                Some(&Value::String(role_id.clone())),
                tenant_id,
            )
            .await?;
        if truthy(role.get("protected")) {
            return Err(IamError::with_status(
                "PROTECTED_RESOURCE",
                "Use owner transfer for protected roles",
                403,
            )
            .into());
        }
        allow(
            ctx,
            tx,
            principal,
            tenant_id,
            "iam:bindings:create",
            s(&role, "id"),
            "grant this role",
        )
        .await?;
    }
    for group_id in group_ids {
        let group = ctx
            .scoped(
                tx,
                "groups",
                Some(&Value::String(group_id.clone())),
                tenant_id,
            )
            .await?;
        assert_not_team_group(Some(&Value::Object(group)))?;
        allow(
            ctx,
            tx,
            principal,
            tenant_id,
            "iam:groups:update",
            group_id,
            "add to this group",
        )
        .await?;
        for binding in find(
            tx,
            "bindings",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("subjectType", "group")
                .eq("subjectId", group_id.clone()),
        )
        .await?
        {
            ctx.granting_authority(
                tx,
                principal,
                tenant_id,
                Some(&js_string(binding.get("authorityId"))),
            )
            .await?;
        }
    }
    // The guest claims the seats of licensed groups (re-checked at redemption, inviterStillGrants).
    assert_may_claim_licenses(
        ctx,
        tx,
        principal,
        tenant_id,
        &strings_value(group_ids),
        Some("A group you invite the guest into carries license seats; that needs iam:licenses:assign"),
    )
    .await?;
    for package_id in package_ids {
        let pkg: AccessPackage = decode(
            ctx.scoped(
                tx,
                "accessPackages",
                Some(&Value::String(package_id.clone())),
                tenant_id,
            )
            .await?,
        )?;
        allow(
            ctx,
            tx,
            principal,
            tenant_id,
            "iam:packages:assign",
            &pkg.id,
            "assign this package",
        )
        .await?;
        authorize_package(ctx, tx, principal, &pkg, None).await?;
    }
    Ok(authority_id)
}

fn refused(message: &str) -> IamError {
    IamError::new("INVITATION_INVALID", message)
}

const NO_LONGER_GRANTS: &str = "The inviter can no longer grant this access";

/// An invitation grants no more than its inviter could grant directly, at redemption as when it was sent: the
/// inviter must still be active and hold iam:guests:invite, the invitation's grant authority, iam:bindings:create on
/// each role, iam:groups:update on each group with the authorities of the group's bindings (and iam:licenses:assign
/// when a license product is assigned to one of them), and iam:packages:assign on each package with the rights to
/// assign it by hand. Returns the inviter as a simulated principal, under whom the grants are made.
async fn inviter_still_grants(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    invitation: &Record,
    tenant_id: &str,
) -> IamResult<AuthenticatedPrincipal> {
    let inviter: Option<Identity> = match tx.get("identities", s(invitation, "invitedBy")).await? {
        Some(record) => Some(decode(record)?),
        None => None,
    };
    let inviter = match inviter {
        Some(inviter)
            if inviter.status == better_iam_core::IdentityStatus::Active
                && !ctx.identity_expired(&inviter) =>
        {
            inviter
        }
        _ => return Err(refused("The inviter can no longer invite guests")),
    };
    let decisions = ctx.decisions()?;
    let as_inviter = decisions.simulated_principal(&inviter, true);
    let may = |action: &'static str, resource_id: String| {
        let as_inviter = &as_inviter;
        async move {
            Ok::<bool, IamError>(
                decisions
                    .decide(
                        tx,
                        as_inviter,
                        &iam_request(tenant_id, action, &resource_id),
                        true,
                    )
                    .await?
                    .allowed,
            )
        }
    };
    let holds = |authority_id: String| {
        let as_inviter = &as_inviter;
        async move {
            ctx.granting_authority(tx, as_inviter, tenant_id, Some(&authority_id))
                .await
                .is_ok()
        }
    };
    if !may("iam:guests:invite", "guests/invitations".into()).await? {
        return Err(refused("The inviter can no longer invite guests"));
    }
    if let Some(authority_id) = invitation.get("authorityId")
        && !holds(js_string(Some(authority_id))).await
    {
        return Err(refused(NO_LONGER_GRANTS));
    }
    for role_id in list(invitation.get("roleIds")) {
        let role = tx.get("roles", &role_id).await?;
        let allowed = match &role {
            Some(role)
                if role.get("tenantId").and_then(Value::as_str) == Some(tenant_id)
                    && !truthy(role.get("protected")) =>
            {
                may("iam:bindings:create", js_string(role.get("id"))).await?
            }
            _ => false,
        };
        if !allowed {
            return Err(refused(NO_LONGER_GRANTS));
        }
    }
    let group_ids = list(invitation.get("groupIds"));
    for group_id in &group_ids {
        let group = tx.get("groups", group_id).await?;
        let allowed = match &group {
            Some(group) if group.get("tenantId").and_then(Value::as_str) == Some(tenant_id) => {
                !is_team_group(Some(&Value::Object(group.clone())))?
                    && may("iam:groups:update", js_string(group.get("id"))).await?
            }
            _ => false,
        };
        let Some(group) = group.filter(|_| allowed) else {
            return Err(refused(NO_LONGER_GRANTS));
        };
        for binding in find(
            tx,
            "bindings",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("subjectType", "group")
                .eq("subjectId", group.get("id").cloned().unwrap_or(Value::Null)),
        )
        .await?
        {
            if !holds(js_string(binding.get("authorityId"))).await {
                return Err(refused(NO_LONGER_GRANTS));
            }
        }
    }
    // Groups that carry license seats, then or since, need the inviter's iam:licenses:assign.
    if let Err(failure) = assert_may_claim_licenses(
        ctx,
        tx,
        &as_inviter,
        tenant_id,
        &strings_value(&group_ids),
        None,
    )
    .await
    {
        if !failure.denied {
            return Err(failure.error);
        }
        return Err(refused(NO_LONGER_GRANTS));
    }
    for package_id in list(invitation.get("packageIds")) {
        let pkg = tx.get("accessPackages", &package_id).await?;
        let pkg = match pkg {
            Some(pkg) if pkg.get("tenantId").and_then(Value::as_str) == Some(tenant_id) => {
                if !may("iam:packages:assign", js_string(pkg.get("id"))).await? {
                    return Err(refused(NO_LONGER_GRANTS));
                }
                pkg
            }
            _ => return Err(refused(NO_LONGER_GRANTS)),
        };
        let pkg: AccessPackage = match decode(pkg) {
            Ok(pkg) => pkg,
            Err(_) => return Err(refused(NO_LONGER_GRANTS)),
        };
        if authorize_package(ctx, tx, &as_inviter, &pkg, None)
            .await
            .is_err()
        {
            return Err(refused(NO_LONGER_GRANTS));
        }
    }
    Ok(as_inviter)
}

/// Emails a guest invitation (template `guest-invitation`) with its token.
async fn send_invitation(
    ctx: &ServerContext,
    tx: &Store,
    tenant: &Tenant,
    invitation: &Record,
    secret: &str,
    names: &mut NameReader,
) -> IamResult<()> {
    let inviter_name = names.name_of(s(invitation, "invitedBy")).await?;
    let sponsor_name = names.name_of(s(invitation, "sponsorId")).await?;
    let mut payload = Map::new();
    payload.insert("tenantId".into(), Value::String(tenant.id.clone()));
    payload.insert("tenantName".into(), Value::String(tenant.name.clone()));
    if let Some(name) = inviter_name.filter(|name| truthy(Some(name))) {
        payload.insert("inviterName".into(), name);
    }
    if let Some(name) = sponsor_name.filter(|name| truthy(Some(name))) {
        payload.insert("sponsorName".into(), name);
    }
    if truthy(invitation.get("message")) {
        copy(&mut payload, invitation, "message");
    }
    payload.insert("token".into(), Value::String(secret.to_owned()));
    payload.insert(
        "expiresAt".into(),
        Value::String(iso(num(invitation, "expiresAt").unwrap_or(f64::NAN))?),
    );
    ctx.auth
        .enqueue_delivery(
            tx,
            EnqueueInput {
                tenant_id: tenant.id.clone(),
                kind: OutboxKind::Email,
                to: js_string(invitation.get("email")),
                template: "guest-invitation".into(),
                payload,
                reference: None,
            },
        )
        .await?;
    Ok(())
}

/// The license claim `followAccessEnd` makes when the end moves later (convertToMember asks for
/// iam:licenses:assign).
struct LicenseClaim<'a> {
    principal: &'a AuthenticatedPrincipal,
    tenant_id: &'a str,
    message: &'a str,
}

/// `{ ...record, expiresAt: next }` without the old end (no end when `next` is None).
fn retime(record: &Record, next: Option<f64>) -> Record {
    let mut rest = record.clone();
    rest.shift_remove("expiresAt");
    if let Some(next) = next {
        rest.insert("expiresAt".into(), number(next));
    }
    rest
}

/// Moves the end of what the invitation granted (the account's tracked bindings, memberships and package
/// assignments) from `previous`, the end they were last given (`grantsEndAt`), to `next` (None: no end). Grants whose
/// end was changed since, and package assignments the package's maximum duration would not allow, keep theirs. A
/// package assignment lengthens only the memberships it created at redemption (`grants.packageMembershipIds`). When
/// the end moves later and `claim` is given, it is first shown the groups whose memberships move.
async fn follow_access_end(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    account: &Record,
    previous: Option<f64>,
    next: Option<f64>,
    actor_id: &str,
    claim: Option<LicenseClaim<'_>>,
) -> OperationResult<()> {
    let Some(previous) = previous else {
        return Ok(());
    };
    if Some(previous) == next {
        return Ok(());
    }
    let tenant_id = account.get("tenantId").cloned().unwrap_or(Value::Null);
    let identity_id = account.get("identityId").cloned().unwrap_or(Value::Null);
    let grants = account.get("grants");
    let member_of = |key: &str| list(grants.and_then(|grants| grants.get(key)));
    let ends_then = |record: &Record| num(record, "expiresAt") == Some(previous);
    let mut bindings = Vec::new();
    for binding_id in member_of("bindingIds") {
        let Some(binding) = tx.get("bindings", &binding_id).await? else {
            continue;
        };
        if binding.get("tenantId") != Some(&tenant_id)
            || s(&binding, "subjectType") != "identity"
            || binding.get("subjectId") != Some(&identity_id)
            || !ends_then(&binding)
        {
            continue;
        }
        bindings.push(binding);
    }
    let mut members = Vec::new();
    for membership_id in member_of("membershipIds") {
        let Some(member) = tx.get("groupMembers", &membership_id).await? else {
            continue;
        };
        if member.get("tenantId") != Some(&tenant_id)
            || member.get("identityId") != Some(&identity_id)
            || !ends_then(&member)
        {
            continue;
        }
        members.push(member);
    }
    let mut assignments: Vec<(AccessPackage, PackageAssignment)> = Vec::new();
    for assignment_id in member_of("packageAssignmentIds") {
        let Some(assignment) = tx.get("packageAssignments", &assignment_id).await? else {
            continue;
        };
        if assignment.get("tenantId") != Some(&tenant_id)
            || assignment.get("identityId") != Some(&identity_id)
            || !ends_then(&assignment)
        {
            continue;
        }
        let Some(pkg) = tx
            .get("accessPackages", s(&assignment, "packageId"))
            .await?
        else {
            continue;
        };
        if pkg.get("tenantId") != Some(&tenant_id) {
            continue;
        }
        let pkg: AccessPackage = decode(pkg)?;
        if let Some(max) = pkg.max_duration_ms
            && next.is_none_or(|next| next > ctx.now() + max)
        {
            continue;
        }
        assignments.push((pkg, decode(assignment)?));
    }
    // Accounts redeemed before the package memberships were recorded lengthen the assignments' own memberships.
    let recorded = grants
        .and_then(|grants| grants.get("packageMembershipIds"))
        .filter(|value| !value.is_null());
    let created = |assignment: &PackageAssignment| -> IndexSet<String> {
        match recorded {
            Some(ids) => list(Some(ids)).into_iter().collect(),
            None => assignment.membership_ids.iter().cloned().collect(),
        }
    };
    if let Some(claim) = &claim
        && next.is_none_or(|next| next > previous)
    {
        let mut group_ids: Vec<String> = members
            .iter()
            .map(|member| js_string(member.get("groupId")))
            .collect();
        for (pkg, assignment) in &assignments {
            let lengthened = created(assignment);
            for membership_id in &assignment.membership_ids {
                if !lengthened.contains(membership_id) {
                    continue;
                }
                let Some(member) = tx.get("groupMembers", membership_id).await? else {
                    continue;
                };
                let live = member
                    .get("expiresAt")
                    .is_none_or(|end| end.as_f64().is_some_and(|end| end > ctx.now()));
                let group_id = s(&member, "groupId");
                if member.get("packageAssignmentId").and_then(Value::as_str)
                    == Some(assignment.id.as_str())
                    && live
                    && pkg.group_ids.iter().any(|id| id == group_id)
                {
                    group_ids.push(group_id.to_owned());
                }
            }
        }
        assert_may_claim_licenses(
            ctx,
            tx,
            claim.principal,
            claim.tenant_id,
            &strings_value(&group_ids),
            Some(claim.message),
        )
        .await?;
    }
    for binding in &bindings {
        tx.put("bindings", &retime(binding, next)).await?;
    }
    for member in &members {
        tx.put("groupMembers", &retime(member, next)).await?;
    }
    // Teams that sync their members from these groups follow the new end (teams.ts).
    let tenant_text = js_string(Some(&tenant_id));
    let synced = unique(
        members
            .iter()
            .map(|member| js_string(member.get("groupId"))),
    );
    for group_id in synced {
        sync_teams_from_groups(
            ctx,
            tx,
            &tenant_text,
            &json!({ "groupId": group_id, "actorId": actor_id }),
        )
        .await?;
    }
    for (pkg, assignment) in &assignments {
        let lengthen = created(assignment);
        retime_assignment(ctx, tx, pkg, assignment, next, Some(&lengthen)).await?;
    }
    Ok(())
}

/// Renews a guest's access; `as_sponsor` when the caller is the guest's sponsor acting without iam:guests:manage.
async fn attest_guest(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    identity_id: &str,
    days: Option<&Value>,
    as_sponsor: bool,
) -> OperationResult<Value> {
    if principal.identity.id == identity_id {
        return Err(OperationDenied::new(Some(
            "Guests cannot renew their own access",
        )));
    }
    if is_guest_identity(&principal.identity) {
        return Err(OperationDenied::new(Some(
            "Guests cannot renew guests\u{2019} access",
        )));
    }
    let LoadedGuest {
        account,
        identity,
        typed,
    } = load_guest(tx, tenant_id, identity_id).await?;
    if as_sponsor
        && (s(&account, "sponsorId") != principal.identity.id
            || !can_sponsor(ctx, Some(&principal.identity), tenant_id))
    {
        return Err(IamError::with_status(
            "ACCESS_DENIED",
            "Only the guest\u{2019}s sponsor or an administrator can renew their access",
            403,
        )
        .into());
    }
    if s(&account, "status") != "active"
        || !truthy(identity.get("guest"))
        || s(&identity, "status") != "active"
        || expired_record(ctx, &identity)
    {
        return Err(IamError::with_status(
            "INVALID_TRANSITION",
            "This guest is disabled or their access has ended: an administrator can restore it (a later expiresAt, then re-enable the account), or delete the account and invite the person again",
            409,
        )
        .into());
    }
    let settings = guest_settings(tx, tenant_id).await?;
    let fallback = number(settings.access_days);
    let access_days = integer(
        Some(nullish(days, &fallback)),
        "days",
        1.0,
        limits::MAX_ACCESS_DAYS,
    )?;
    let now = ctx.now();
    let expires_at = now + access_days * GUEST_DAY_MS;
    // A guest who owns the organization keeps an owner's protection: their sponsor alone cannot move their end.
    assert_owner_expiry_control(ctx, tx, principal, &typed, Some(expires_at)).await?;
    let previous = identity.get("expiresAt").cloned();
    let mut next_identity = identity.clone();
    next_identity.insert("expiresAt".into(), number(expires_at));
    let updated = tx.put("identities", &next_identity).await?;
    follow_access_end(
        ctx,
        tx,
        &account,
        num(&account, "grantsEndAt"),
        Some(expires_at),
        &principal.identity.id,
        None,
    )
    .await?;
    let review_due_at = (now + settings.review_every_days * GUEST_DAY_MS).min(expires_at);
    let mut renewed = account.clone();
    renewed.insert("attestedAt".into(), number(now));
    renewed.insert(
        "attestedBy".into(),
        Value::String(principal.identity.id.clone()),
    );
    renewed.insert("reviewDueAt".into(), number(review_due_at));
    renewed.insert("grantsEndAt".into(), number(expires_at));
    let renewed = tx.put(ACCOUNTS, &renewed).await?;
    let mut metadata = Map::new();
    metadata.insert("days".into(), number(access_days));
    metadata.insert("expiresAt".into(), number(expires_at));
    metadata.insert("reviewDueAt".into(), number(review_due_at));
    metadata.insert("asSponsor".into(), Value::Bool(as_sponsor));
    if let Some(previous) = previous {
        metadata.insert("previousExpiresAt".into(), previous);
    }
    ctx.events()?
        .audit(
            tx,
            principal,
            "guest:attest",
            tenant_id,
            s(&identity, "id"),
            AuditOutcome::Allow,
            false,
            Some(metadata),
        )
        .await?;
    Ok(guest_view(ctx, tx, &renewed, &updated, &mut NameReader::new(tx)).await?)
}

/// The `guests` API group (`createGuestsApi(ctx)`): one method per route `guests/{method}`.
pub struct GuestsApi {
    ctx: Arc<ServerContext>,
}

/// `createGuestsApi(ctx)`.
pub fn create_guests_api(ctx: &Arc<ServerContext>) -> IamResult<GuestsApi> {
    Ok(GuestsApi { ctx: ctx.clone() })
}

async fn invite_mutation(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant: &Tenant,
    input: &Map<String, Value>,
) -> OperationResult<Value> {
    if !sends_email(ctx) {
        return Err(IamError::new(
            "DELIVERY_REQUIRED",
            "Guest invitations require an email delivery callback",
        )
        .into());
    }
    if tenant.status != better_iam_core::TenantStatus::Active {
        return Err(IamError::new("TENANT_INACTIVE", "Tenant must be active").into());
    }
    if tenant.parent_id.is_none() {
        return Err(invalid("The platform tenant does not take guests").into());
    }
    if impersonating(principal) {
        return Err(IamError::with_status(
            "IMPERSONATION_RESTRICTED",
            "Guests cannot be invited while impersonating",
            403,
        )
        .into());
    }
    // Redemption re-checks the inviter's rights as the inviter acting in their own right (inviterStillGrants); an
    // assumed role is not there to re-check, so an invitation sent from one could never be redeemed.
    if principal.session.kind == SessionKind::Role {
        return Err(OperationDenied::new(Some(
            "Guests are invited from your own session, not an assumed role",
        )));
    }
    let to = guest_address(input.get("email"))?;
    let settings = guest_settings(tx, &tenant.id).await?;
    let access_fallback = number(settings.access_days);
    let access_days = integer(
        Some(nullish(input.get("accessDays"), &access_fallback)),
        "accessDays",
        1.0,
        limits::MAX_ACCESS_DAYS,
    )?;
    let lifetime_fallback = number(limits::INVITATION_DAYS);
    let lifetime = integer(
        Some(nullish(input.get("expiresInDays"), &lifetime_fallback)),
        "expiresInDays",
        1.0,
        limits::MAX_INVITATION_DAYS,
    )?;
    let message = match input.get("message") {
        Some(message) => Some(trim(&text(Some(message), "message", 1000)?).to_owned()),
        None => None,
    };
    let empty = json!([]);
    let role_ids = unique(strings(
        Some(nullish(input.get("roleIds"), &empty)),
        "roleIds",
    )?);
    let group_ids = unique(strings(
        Some(nullish(input.get("groupIds"), &empty)),
        "groupIds",
    )?);
    let package_ids = unique(strings(
        Some(nullish(input.get("packageIds"), &empty)),
        "packageIds",
    )?);
    assert_newcomer(tx, &tenant.id, &to).await?;
    let origin = guest_origin(tx, &tenant.id, &to).await?;
    assert_guest_admitted(tx, &settings, &tenant.id, &origin).await?;
    if input.contains_key("sponsorId") {
        authorize_other_sponsor(ctx, tx, principal, &tenant.id, input.get("sponsorId")).await?;
    }
    let sponsor = if input.contains_key("sponsorId") {
        guest_sponsor(ctx, tx, &tenant.id, input.get("sponsorId")).await?
    } else {
        caller_sponsor(ctx, principal, &tenant.id)?
    };
    let authority_id = authorize_grants(
        ctx,
        tx,
        principal,
        &tenant.id,
        &role_ids,
        &group_ids,
        &package_ids,
    )
    .await?;
    let now = ctx.now();
    claim_pending_key(tx, &tenant.id, &to, now, None).await?;
    let secret = invitation_token();
    let expires_at = now + lifetime * GUEST_DAY_MS;
    let mut invitation = Record::new();
    invitation.insert("id".into(), Value::String(id()));
    invitation.insert("tenantId".into(), Value::String(tenant.id.clone()));
    invitation.insert("uniqueKey".into(), Value::String(pending_key(&to)));
    invitation.insert("email".into(), Value::String(to.clone()));
    invitation.insert("tokenHash".into(), Value::String(hash(&secret)));
    invitation.insert("sponsorId".into(), Value::String(sponsor.id.clone()));
    invitation.insert(
        "invitedBy".into(),
        Value::String(principal.identity.id.clone()),
    );
    if let Some(message) = message.as_ref().filter(|message| !message.is_empty()) {
        invitation.insert("message".into(), Value::String(message.clone()));
    }
    invitation.insert("roleIds".into(), strings_value(&role_ids));
    invitation.insert("groupIds".into(), strings_value(&group_ids));
    invitation.insert("packageIds".into(), strings_value(&package_ids));
    if let Some(authority_id) = &authority_id {
        invitation.insert("authorityId".into(), Value::String(authority_id.clone()));
    }
    invitation.insert("accessDays".into(), number(access_days));
    if let Some(home) = origin
        .home_tenant_id
        .as_ref()
        .filter(|home| !home.is_empty())
    {
        invitation.insert("homeTenantId".into(), Value::String(home.clone()));
    }
    invitation.insert("expiresAt".into(), number(expires_at));
    invitation.insert("createdAt".into(), number(now));
    invitation.insert("sentAt".into(), number(now));
    invitation.insert("status".into(), Value::String("pending".into()));
    tx.insert(INVITATIONS, &invitation).await?;
    let mut names = NameReader::new(tx);
    send_invitation(ctx, tx, tenant, &invitation, &secret, &mut names).await?;
    let mut metadata = Map::new();
    metadata.insert("email".into(), Value::String(to.clone()));
    metadata.insert("sponsorId".into(), Value::String(sponsor.id.clone()));
    metadata.insert("roleIds".into(), strings_value(&role_ids));
    metadata.insert("groupIds".into(), strings_value(&group_ids));
    metadata.insert("packageIds".into(), strings_value(&package_ids));
    metadata.insert("accessDays".into(), number(access_days));
    metadata.insert("expiresAt".into(), number(expires_at));
    if let Some(home) = origin
        .home_tenant_id
        .as_ref()
        .filter(|home| !home.is_empty())
    {
        metadata.insert("homeTenantId".into(), Value::String(home.clone()));
    }
    ctx.events()?
        .audit(
            tx,
            principal,
            "guest:invite",
            &tenant.id,
            s(&invitation, "id"),
            AuditOutcome::Allow,
            false,
            Some(metadata),
        )
        .await?;
    Ok(invitation_view(ctx, &invitation, &mut names).await?)
}

async fn resend_mutation(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant: &Tenant,
    invitation_id: &str,
    lifetime: f64,
) -> OperationResult<Value> {
    if !sends_email(ctx) {
        return Err(IamError::new(
            "DELIVERY_REQUIRED",
            "Guest invitations require an email delivery callback",
        )
        .into());
    }
    if tenant.status != better_iam_core::TenantStatus::Active {
        return Err(IamError::new("TENANT_INACTIVE", "Tenant must be active").into());
    }
    let invitation = ctx
        .scoped(
            tx,
            INVITATIONS,
            Some(&Value::String(invitation_id.to_owned())),
            &tenant.id,
        )
        .await?;
    let status = s(&invitation, "status");
    if status != "pending" && status != "expired" {
        return Err(IamError::with_status(
            "INVALID_TRANSITION",
            "Only a pending or lapsed invitation can be sent again",
            409,
        )
        .into());
    }
    let address = s(&invitation, "email").to_owned();
    assert_newcomer(tx, &tenant.id, &address).await?;
    let origin = guest_origin(tx, &tenant.id, &address).await?;
    assert_guest_admitted(
        tx,
        &guest_settings(tx, &tenant.id).await?,
        &tenant.id,
        &origin,
    )
    .await?;
    // Only an invitation that can still be redeemed goes out: its sponsor must still be able to sponsor, and its
    // inviter still grant what it grants (INVITATION_INVALID), as redemption checks again.
    guest_sponsor(ctx, tx, &tenant.id, invitation.get("sponsorId")).await?;
    inviter_still_grants(ctx, tx, &invitation, &tenant.id).await?;
    let now = ctx.now();
    claim_pending_key(tx, &tenant.id, &address, now, Some(s(&invitation, "id"))).await?;
    let secret = invitation_token();
    let mut rest = invitation.clone();
    rest.shift_remove("homeTenantId");
    rest.insert("uniqueKey".into(), Value::String(pending_key(&address)));
    rest.insert("tokenHash".into(), Value::String(hash(&secret)));
    rest.insert("status".into(), Value::String("pending".into()));
    rest.insert("expiresAt".into(), number(now + lifetime * GUEST_DAY_MS));
    rest.insert("sentAt".into(), number(now));
    if let Some(home) = origin
        .home_tenant_id
        .as_ref()
        .filter(|home| !home.is_empty())
    {
        rest.insert("homeTenantId".into(), Value::String(home.clone()));
    }
    let renewed = tx.put(INVITATIONS, &rest).await?;
    let mut names = NameReader::new(tx);
    send_invitation(ctx, tx, tenant, &renewed, &secret, &mut names).await?;
    let mut metadata = Map::new();
    metadata.insert("email".into(), Value::String(address));
    copy(&mut metadata, &renewed, "expiresAt");
    ctx.events()?
        .audit(
            tx,
            principal,
            "guest:invitation-resend",
            &tenant.id,
            s(&invitation, "id"),
            AuditOutcome::Allow,
            false,
            Some(metadata),
        )
        .await?;
    Ok(invitation_view(ctx, &renewed, &mut names).await?)
}

/// The redemption transaction of `guests.redeem`.
async fn redeem_transaction(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    presented: &str,
    name: &str,
    password: &str,
) -> IamResult<Value> {
    let auth = &ctx.auth;
    let realm = boxed(|| ctx.tenant(tx, tenant_id)).await?;
    boxed(|| auth.assert_tenant_active(tx, &realm.id)).await?;
    let invitation = boxed(|| {
        find(
            tx,
            INVITATIONS,
            Filter::new()
                .eq("tenantId", realm.id.clone())
                .eq("tokenHash", hash(presented)),
        )
    })
    .await?
    .into_iter()
    .next();
    let now = ctx.now();
    let Some(invitation) = invitation.filter(|invitation| {
        s(invitation, "status") == "pending"
            && num(invitation, "expiresAt").is_some_and(|expires| expires > now)
    }) else {
        return Err(IamError::new("INVITATION_INVALID", "Invitation is invalid"));
    };
    // Either side may have changed its settings (or verified the domain) since the invitation was sent.
    let settings = boxed(|| guest_settings(tx, &realm.id)).await?;
    let origin: GuestOrigin =
        boxed(|| guest_origin(tx, &realm.id, s(&invitation, "email"))).await?;
    boxed(|| assert_guest_admitted(tx, &settings, &realm.id, &origin)).await?;
    let as_inviter = boxed(|| inviter_still_grants(ctx, tx, &invitation, &realm.id)).await?;
    let sponsor: Option<Identity> =
        match boxed(|| tx.get("identities", s(&invitation, "sponsorId"))).await? {
            Some(record) => Some(decode(record)?),
            None => None,
        };
    let Some(sponsor) = sponsor.filter(|sponsor| can_sponsor(ctx, Some(sponsor), &realm.id)) else {
        return Err(IamError::new(
            "INVITATION_INVALID",
            "The sponsor can no longer sponsor guests",
        ));
    };
    let guardrails =
        boxed(|| invariant_snapshot(ctx, tx, &realm.id, "iam:identities:create")).await?;
    let created = boxed(|| {
        auth.create_identity(
            tx,
            CreateIdentityInput {
                tenant_id: realm.id.clone(),
                email: js_string(invitation.get("email")),
                name: name.to_owned(),
                password: Some(password.to_owned()),
                owner: None,
                root_admin: None,
                email_verified: Some(true),
            },
        )
    })
    .await?;
    let access_days = num(&invitation, "accessDays").unwrap_or(f64::NAN);
    let expires_at = now + access_days * GUEST_DAY_MS;
    let mut marker = Map::new();
    marker.insert("sponsorId".into(), Value::String(sponsor.id.clone()));
    marker.insert("since".into(), number(now));
    marker.insert("homeDomain".into(), Value::String(origin.domain.clone()));
    if let Some(home) = origin
        .home_tenant_id
        .as_ref()
        .filter(|home| !home.is_empty())
    {
        marker.insert("homeTenantId".into(), Value::String(home.clone()));
    }
    let mut identity = match boxed(|| tx.get("identities", &created.id)).await? {
        Some(record) => record,
        None => crate::port::encode(&created),
    };
    identity.insert("expiresAt".into(), number(expires_at));
    identity.insert("guest".into(), Value::Object(marker));
    let identity = boxed(|| tx.put("identities", &identity)).await?;
    let identity_id = s(&identity, "id").to_owned();
    let mut binding_ids = Vec::new();
    let mut membership_ids = Vec::new();
    let mut package_assignment_ids = Vec::new();
    let mut package_membership_ids = Vec::new();
    for role_id in list(invitation.get("roleIds")) {
        let mut binding = Record::new();
        binding.insert("id".into(), Value::String(id()));
        binding.insert("tenantId".into(), Value::String(realm.id.clone()));
        binding.insert(
            "uniqueKey".into(),
            Value::String(format!(
                "identity:{identity_id}:{role_id}:{}",
                js_string(invitation.get("authorityId"))
            )),
        );
        binding.insert("subjectType".into(), Value::String("identity".into()));
        binding.insert("subjectId".into(), Value::String(identity_id.clone()));
        binding.insert("roleId".into(), Value::String(role_id.clone()));
        copy(&mut binding, &invitation, "authorityId");
        binding.insert("expiresAt".into(), number(expires_at));
        let binding = boxed(|| tx.insert("bindings", &binding)).await?;
        binding_ids.push(js_string(binding.get("id")));
    }
    let invited_by = js_string(invitation.get("invitedBy"));
    for group_id in list(invitation.get("groupIds")) {
        let mut member = Record::new();
        member.insert("id".into(), Value::String(id()));
        member.insert("tenantId".into(), Value::String(realm.id.clone()));
        member.insert(
            "uniqueKey".into(),
            Value::String(format!("{group_id}:{identity_id}")),
        );
        member.insert("groupId".into(), Value::String(group_id.clone()));
        member.insert("identityId".into(), Value::String(identity_id.clone()));
        member.insert("expiresAt".into(), number(expires_at));
        let member = boxed(|| tx.insert("groupMembers", &member)).await?;
        membership_ids.push(js_string(member.get("id")));
        boxed(|| async {
            sync_teams_from_groups(
                ctx,
                tx,
                &realm.id,
                &json!({ "groupId": group_id, "actorId": invited_by }),
            )
            .await
        })
        .await?;
    }
    for package_id in list(invitation.get("packageIds")) {
        let pkg: AccessPackage = decode(
            boxed(|| async {
                ctx.scoped(
                    tx,
                    "accessPackages",
                    Some(&Value::String(package_id.clone())),
                    &realm.id,
                )
                .await
            })
            .await?,
        )?;
        // A package's maximum duration can end its assignment before the guest's access.
        let assignment_end = match pkg.max_duration_ms {
            Some(max) => expires_at.min(now + max),
            None => expires_at,
        };
        let assigned = boxed(|| async {
            assign_package(
                ctx,
                tx,
                &as_inviter,
                &pkg,
                &json!({
                    "identityId": identity_id,
                    "expiresAt": number(assignment_end),
                    "justification": format!("Guest invitation {}", s(&invitation, "id")),
                }),
                None,
            )
            .await
        })
        .await?;
        let assignment = assigned.get("assignment");
        package_assignment_ids.push(js_string(assignment.and_then(|a| a.get("id"))));
        package_membership_ids.extend(list(assignment.and_then(|a| a.get("membershipIds"))));
    }
    boxed(|| sod_assert_identity(ctx, tx, &realm.id, &identity_id)).await?;
    boxed(|| invariant_verify(ctx, tx, &realm.id, guardrails.as_ref())).await?;
    let mut account = Record::new();
    account.insert("id".into(), Value::String(identity_id.clone()));
    account.insert("tenantId".into(), Value::String(realm.id.clone()));
    account.insert("identityId".into(), Value::String(identity_id.clone()));
    account.insert("sponsorId".into(), Value::String(sponsor.id.clone()));
    copy(&mut account, &invitation, "email");
    if let Some(home) = origin
        .home_tenant_id
        .as_ref()
        .filter(|home| !home.is_empty())
    {
        account.insert("homeTenantId".into(), Value::String(home.clone()));
    }
    account.insert("source".into(), Value::String("invitation".into()));
    if let Some(invitation_id) = invitation.get("id") {
        account.insert("invitationId".into(), invitation_id.clone());
    }
    account.insert("invitedBy".into(), Value::String(invited_by.clone()));
    account.insert("redeemedAt".into(), number(now));
    account.insert(
        "reviewDueAt".into(),
        number((now + settings.review_every_days * GUEST_DAY_MS).min(expires_at)),
    );
    account.insert("status".into(), Value::String("active".into()));
    account.insert(
        "grants".into(),
        json!({
            "bindingIds": binding_ids,
            "membershipIds": membership_ids,
            "packageAssignmentIds": package_assignment_ids,
            "packageMembershipIds": package_membership_ids,
        }),
    );
    account.insert("grantsEndAt".into(), number(expires_at));
    boxed(|| tx.insert(ACCOUNTS, &account)).await?;
    let mut redeemed = invitation.clone();
    redeemed.shift_remove("uniqueKey");
    redeemed.insert("status".into(), Value::String("redeemed".into()));
    redeemed.insert("redeemedAt".into(), number(now));
    redeemed.insert("identityId".into(), Value::String(identity_id.clone()));
    boxed(|| tx.put(INVITATIONS, &redeemed)).await?;
    let mut metadata = Map::new();
    if let Some(invitation_id) = invitation.get("id") {
        metadata.insert("invitationId".into(), invitation_id.clone());
    }
    metadata.insert("invitedBy".into(), Value::String(invited_by));
    metadata.insert("sponsorId".into(), Value::String(sponsor.id.clone()));
    for key in ["roleIds", "groupIds", "packageIds"] {
        copy(&mut metadata, &invitation, key);
    }
    metadata.insert("expiresAt".into(), number(expires_at));
    if let Some(home) = origin
        .home_tenant_id
        .as_ref()
        .filter(|home| !home.is_empty())
    {
        metadata.insert("homeTenantId".into(), Value::String(home.clone()));
    }
    let mut event = Record::new();
    event.insert("id".into(), Value::String(id()));
    event.insert("tenantId".into(), Value::String(realm.id.clone()));
    event.insert("actorId".into(), Value::String(identity_id.clone()));
    event.insert("action".into(), Value::String("guest:redeem".into()));
    event.insert("resourceId".into(), Value::String(identity_id.clone()));
    event.insert("timestamp".into(), number(now));
    event.insert("outcome".into(), Value::String("allow".into()));
    event.insert("metadata".into(), Value::Object(metadata));
    ctx.events()?.record_audit(tx, &event).await?;
    // The guest just set a password: a password sign-in, refused like one where the tenant does not accept them.
    let typed: Identity = decode(identity.clone())?;
    let issued =
        boxed(|| auth.complete_authentication(tx, &typed, Some(AuthMethod::Password), None))
            .await?;
    let mut result = Map::new();
    result.insert(
        "identity".into(),
        Value::Object(public_identity_record(&identity)),
    );
    if let Ok(Value::Object(issued)) = serde_json::to_value(&issued) {
        for (key, value) in issued {
            result.insert(key, value);
        }
    }
    Ok(Value::Object(result))
}

async fn remove_mutation(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant: &Tenant,
    identity_id: &str,
    input: &Map<String, Value>,
) -> OperationResult<Value> {
    ctx.auth.require_recent(principal)?;
    let reason = trim(&text(input.get("reason"), "reason", 512)?).to_owned();
    let LoadedGuest {
        account, identity, ..
    } = boxed(|| load_guest(tx, &tenant.id, identity_id)).await?;
    let status = s(&account, "status");
    if status == "removed" || status == "converted" {
        return Err(IamError::with_status(
            "INVALID_TRANSITION",
            "This guest was already removed or became a member",
            409,
        )
        .into());
    }
    let guest_id = s(&identity, "id").to_owned();
    if guest_id == principal.identity.id {
        return Err(invalid("You cannot remove yourself").into());
    }
    if truthy(identity.get("owner")) {
        return Err(invalid("This guest owns the organization: transfer ownership first").into());
    }
    let tenant_id = tenant.id.as_str();
    let now = ctx.now();
    let sessions = boxed(|| {
        find(
            tx,
            "sessions",
            Filter::new().eq("identityId", guest_id.clone()),
        )
    })
    .await?
    .len() as f64;
    let mut bindings = 0.0;
    let mut memberships = 0.0;
    let mut packages = 0.0;
    // Package assignments first: they own their bindings and memberships, whichever authority issued them.
    for assignment in boxed(|| {
        find(
            tx,
            "packageAssignments",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("identityId", guest_id.clone()),
        )
    })
    .await?
    {
        let assignment: PackageAssignment = decode(assignment)?;
        let removed = boxed(|| revoke_assignment(ctx, tx, &assignment)).await?;
        bindings += removed
            .get("bindings")
            .and_then(Value::as_f64)
            .unwrap_or(f64::NAN);
        memberships += removed
            .get("memberships")
            .and_then(Value::as_f64)
            .unwrap_or(f64::NAN);
        packages += 1.0;
    }
    for activation in boxed(|| {
        find(
            tx,
            "bindingActivations",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("identityId", guest_id.clone()),
        )
    })
    .await?
    {
        boxed(|| tx.delete("bindingActivations", s(&activation, "id"))).await?;
    }
    for binding in boxed(|| {
        find(
            tx,
            "bindings",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("subjectType", "identity")
                .eq("subjectId", guest_id.clone()),
        )
    })
    .await?
    {
        boxed(|| tx.delete("bindings", s(&binding, "id"))).await?;
        bindings += 1.0;
    }
    // Team memberships go first, taking the team-managed group memberships with them (teams.ts).
    boxed(|| remove_from_all_teams(tx, tenant_id, &guest_id, now)).await?;
    boxed(|| release_departments(tx, tenant_id, &guest_id, now, None)).await?;
    let mut groups: IndexSet<String> = IndexSet::new();
    for membership in boxed(|| {
        find(
            tx,
            "groupMembers",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("identityId", guest_id.clone()),
        )
    })
    .await?
    {
        boxed(|| tx.delete("groupMembers", s(&membership, "id"))).await?;
        groups.insert(js_string(membership.get("groupId")));
        memberships += 1.0;
    }
    for group_id in groups {
        boxed(|| async {
            sync_teams_from_groups(
                ctx,
                tx,
                tenant_id,
                &json!({ "groupId": group_id, "actorId": principal.identity.id }),
            )
            .await
        })
        .await?;
    }
    for tuple in boxed(|| {
        find(
            tx,
            "relationships",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("subjectType", "identity")
                .eq("subjectId", guest_id.clone()),
        )
    })
    .await?
    {
        boxed(|| tx.delete("relationships", s(&tuple, "id"))).await?;
    }
    for mut request in boxed(|| {
        find(
            tx,
            "accessRequests",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("requesterId", guest_id.clone())
                .eq("status", "pending"),
        )
    })
    .await?
    {
        request.insert("status".into(), Value::String("cancelled".into()));
        request.insert("reviewedAt".into(), number(now));
        boxed(|| tx.put("accessRequests", &request)).await?;
    }
    for mut request in boxed(|| {
        find(
            tx,
            "packageRequests",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("identityId", guest_id.clone())
                .eq("status", "pending"),
        )
    })
    .await?
    {
        request.insert("status".into(), Value::String("cancelled".into()));
        request.insert("decidedAt".into(), number(now));
        boxed(|| tx.put("packageRequests", &request)).await?;
    }
    for mut authority in boxed(|| {
        find(
            tx,
            "grantAuthorities",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("identityId", guest_id.clone()),
        )
    })
    .await?
    {
        if !truthy(authority.get("revoked")) {
            authority.insert("revoked".into(), Value::Bool(true));
            boxed(|| tx.put("grantAuthorities", &authority)).await?;
        }
    }
    boxed(|| async {
        revoke_delegations_of(
            ctx,
            tx,
            &Value::Object(identity.clone()),
            &principal.identity.id,
        )
        .await
    })
    .await?;
    boxed(|| ctx.revoke_all(tx, &guest_id)).await?;
    boxed(|| revoke_invitations_by(tx, &guest_id)).await?;
    let mut disabled = identity.clone();
    disabled.insert("status".into(), Value::String("disabled".into()));
    let disabled = boxed(|| tx.put("identities", &disabled)).await?;
    // A removed guest stays disabled: a threats containment of it can no longer be released.
    boxed(|| end_containment(tx, &guest_id, now)).await?;
    let mut removed = account.clone();
    removed.insert("status".into(), Value::String("removed".into()));
    removed.insert("endedAt".into(), number(now));
    removed.insert(
        "endedBy".into(),
        Value::String(principal.identity.id.clone()),
    );
    removed.insert("removalReason".into(), Value::String(reason.clone()));
    let removed = boxed(|| tx.put(ACCOUNTS, &removed)).await?;
    let mut metadata = Map::new();
    metadata.insert("reason".into(), Value::String(reason));
    copy(&mut metadata, &account, "sponsorId");
    metadata.insert("sessions".into(), number(sessions));
    metadata.insert("bindings".into(), number(bindings));
    metadata.insert("memberships".into(), number(memberships));
    metadata.insert("packages".into(), number(packages));
    ctx.events()?
        .audit(
            tx,
            principal,
            "guest:remove",
            tenant_id,
            &guest_id,
            AuditOutcome::Allow,
            false,
            Some(metadata),
        )
        .await?;
    let guest = boxed(|| async {
        guest_view(ctx, tx, &removed, &disabled, &mut NameReader::new(tx)).await
    })
    .await?;
    Ok(json!({
        "guest": guest,
        "sessions": number(sessions),
        "bindings": number(bindings),
        "memberships": number(memberships),
        "packages": number(packages),
    }))
}

async fn convert_mutation(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant: &Tenant,
    identity_id: &str,
    clear_expiry: bool,
) -> OperationResult<Value> {
    ctx.auth.require_recent(principal)?;
    // Becoming a member lifts the guest boundary (and, with clearExpiry, the end): guests never make anyone a
    // member, themselves included, as they never renew anyone (attest).
    if identity_id == principal.identity.id {
        return Err(OperationDenied::new(Some(
            "Guests cannot make themselves members",
        )));
    }
    if is_guest_identity(&principal.identity) {
        return Err(OperationDenied::new(Some(
            "Guests cannot make guests members",
        )));
    }
    let LoadedGuest {
        account,
        identity,
        typed,
    } = load_guest(tx, &tenant.id, identity_id).await?;
    if s(&account, "status") != "active"
        || !truthy(identity.get("guest"))
        || s(&identity, "status") != "active"
        || expired_record(ctx, &identity)
    {
        return Err(IamError::with_status(
            "INVALID_TRANSITION",
            "Only an active guest can become a member",
            409,
        )
        .into());
    }
    // Clearing an owner's end changes an owner's expiry.
    if clear_expiry && identity.contains_key("expiresAt") {
        assert_owner_expiry_control(ctx, tx, principal, &typed, None).await?;
    }
    let mut member = identity.clone();
    member.shift_remove("guest");
    let previous = member.shift_remove("expiresAt");
    if !clear_expiry && let Some(previous) = &previous {
        member.insert("expiresAt".into(), previous.clone());
    }
    let updated = tx.put("identities", &member).await?;
    // Keeping the guest in a licensed group for good is a claim on its seats, as clearing a membership's end is in
    // the groups API: unlike a renewal, which ends again, it needs iam:licenses:assign (api/groups.ts).
    if clear_expiry {
        follow_access_end(
            ctx,
            tx,
            &account,
            num(&account, "grantsEndAt"),
            None,
            &principal.identity.id,
            Some(LicenseClaim {
                principal,
                tenant_id: &tenant.id,
                message: "A group the guest would stay in for good carries license seats; clearing the end needs iam:licenses:assign",
            }),
        )
        .await?;
    }
    let mut closed = account.clone();
    if clear_expiry {
        closed.shift_remove("grantsEndAt");
    }
    closed.insert("status".into(), Value::String("converted".into()));
    closed.insert("endedAt".into(), number(ctx.now()));
    closed.insert(
        "endedBy".into(),
        Value::String(principal.identity.id.clone()),
    );
    tx.put(ACCOUNTS, &closed).await?;
    let mut metadata = Map::new();
    copy(&mut metadata, &account, "sponsorId");
    metadata.insert("clearExpiry".into(), Value::Bool(clear_expiry));
    if let Some(previous) = previous {
        metadata.insert("expiresAt".into(), previous);
    }
    ctx.events()?
        .audit(
            tx,
            principal,
            "guest:convert",
            &tenant.id,
            s(&identity, "id"),
            AuditOutcome::Allow,
            false,
            Some(metadata),
        )
        .await?;
    Ok(Value::Object(public_identity_record(&updated)))
}

async fn configure_mutation(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant: &Tenant,
    input: &Map<String, Value>,
) -> OperationResult<Value> {
    ctx.auth.require_recent(principal)?;
    // A misspelled setting (a `guestBoundry`) must fail rather than leave the tenant as it was.
    let whole = Value::Object(input.clone());
    fields(
        Some(&whole),
        "guest",
        &[
            "tenantId",
            "inbound",
            "outbound",
            "accessDays",
            "reviewEveryDays",
            "guestBoundary",
        ],
    )?;
    let stored = read_guest_settings_record(tx, &tenant.id).await?;
    let current = guest_settings_value(stored.as_ref());
    let spread = |key: &str| match current.get(key) {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    };
    let mut inbound_next = spread("inbound");
    let mut outbound_next = spread("outbound");
    let mut access_days = current.get("accessDays").cloned();
    let mut review_every_days = current.get("reviewEveryDays").cloned();
    let mut boundary = current
        .get("guestBoundary")
        .filter(|boundary| truthy(Some(boundary)))
        .cloned();
    let mut changed: Vec<String> = Vec::new();
    if let Some(value) = input.get("inbound") {
        let inbound = fields(
            Some(value),
            "inbound",
            &[
                "allowGuests",
                "allowedDomains",
                "blockedDomains",
                "partners",
            ],
        )?;
        if let Some(value) = inbound.get("allowGuests") {
            inbound_next.insert(
                "allowGuests".into(),
                Value::Bool(flag(Some(value), "inbound.allowGuests")?),
            );
        }
        if let Some(value) = inbound.get("allowedDomains") {
            inbound_next.insert(
                "allowedDomains".into(),
                strings_value(&domain_list(Some(value), "inbound.allowedDomains")?),
            );
        }
        if let Some(value) = inbound.get("blockedDomains") {
            inbound_next.insert(
                "blockedDomains".into(),
                strings_value(&domain_list(Some(value), "inbound.blockedDomains")?),
            );
        }
        if let Some(value) = inbound.get("partners") {
            let partners = partner_list(tx, &tenant.id, Some(value), "inbound.partners").await?;
            inbound_next.insert("partners".into(), partners_value(&partners));
        }
        changed.extend(inbound.keys().map(|key| format!("inbound.{key}")));
    }
    if let Some(value) = input.get("outbound") {
        let outbound = fields(
            Some(value),
            "outbound",
            &["allowGuestInvitations", "partners"],
        )?;
        if let Some(value) = outbound.get("allowGuestInvitations") {
            outbound_next.insert(
                "allowGuestInvitations".into(),
                Value::Bool(flag(Some(value), "outbound.allowGuestInvitations")?),
            );
        }
        if let Some(value) = outbound.get("partners") {
            let partners = partner_list(tx, &tenant.id, Some(value), "outbound.partners").await?;
            outbound_next.insert("partners".into(), partners_value(&partners));
        }
        changed.extend(outbound.keys().map(|key| format!("outbound.{key}")));
    }
    if let Some(value) = input.get("accessDays") {
        access_days = Some(number(integer(
            Some(value),
            "accessDays",
            1.0,
            limits::MAX_ACCESS_DAYS,
        )?));
        changed.push("accessDays".into());
    }
    if let Some(value) = input.get("reviewEveryDays") {
        review_every_days = Some(number(integer(
            Some(value),
            "reviewEveryDays",
            limits::MIN_REVIEW_EVERY_DAYS,
            limits::MAX_REVIEW_EVERY_DAYS,
        )?));
        changed.push("reviewEveryDays".into());
    }
    if let Some(value) = input.get("guestBoundary") {
        if value.is_null() {
            boundary = None;
        } else {
            ctx.catalog.validate(tx.as_ref(), &tenant.id, value).await?;
            boundary = Some(value.clone());
        }
        changed.push("guestBoundary".into());
    }
    if changed.is_empty() {
        return Err(invalid("Nothing to change").into());
    }
    let mut next = Map::new();
    next.insert("inbound".into(), Value::Object(inbound_next));
    next.insert("outbound".into(), Value::Object(outbound_next));
    if let Some(days) = access_days {
        next.insert("accessDays".into(), days);
    }
    if let Some(days) = review_every_days {
        next.insert("reviewEveryDays".into(), days);
    }
    if let Some(boundary) = &boundary {
        next.insert("guestBoundary".into(), boundary.clone());
    }
    let mut record = Record::new();
    record.insert("id".into(), Value::String(tenant.id.clone()));
    record.insert("tenantId".into(), Value::String(tenant.id.clone()));
    for (key, value) in &next {
        record.insert(key.clone(), value.clone());
    }
    record.insert("updatedAt".into(), number(ctx.now()));
    record.insert(
        "updatedBy".into(),
        Value::String(principal.identity.id.clone()),
    );
    if stored.is_some() {
        tx.put(SETTINGS, &record).await?;
    } else {
        tx.insert(SETTINGS, &record).await?;
    }
    let partners = |settings: &Value| -> Value {
        match settings.get("partners") {
            Some(Value::Array(items)) => Value::Array(
                items
                    .iter()
                    .map(|partner| {
                        let mut entry = Map::new();
                        if let Some(Value::Object(partner)) = Some(partner) {
                            copy(&mut entry, partner, "tenantId");
                            copy(&mut entry, partner, "allow");
                        }
                        Value::Object(entry)
                    })
                    .collect(),
            ),
            _ => Value::Array(Vec::new()),
        }
    };
    let inbound = &next["inbound"];
    let outbound = &next["outbound"];
    let mut metadata = Map::new();
    metadata.insert(
        "changed".into(),
        Value::Array(changed.into_iter().map(Value::String).collect()),
    );
    for (to, key) in [
        ("allowGuests", "allowGuests"),
        ("allowedDomains", "allowedDomains"),
        ("blockedDomains", "blockedDomains"),
    ] {
        if let Some(value) = inbound.get(key) {
            metadata.insert(to.into(), value.clone());
        }
    }
    metadata.insert("inboundPartners".into(), partners(inbound));
    if let Some(value) = outbound.get("allowGuestInvitations") {
        metadata.insert("allowGuestInvitations".into(), value.clone());
    }
    metadata.insert("outboundPartners".into(), partners(outbound));
    copy(&mut metadata, &next, "accessDays");
    copy(&mut metadata, &next, "reviewEveryDays");
    metadata.insert("guestBoundary".into(), Value::Bool(boundary.is_some()));
    ctx.events()?
        .audit(
            tx,
            principal,
            "guest:settings",
            &tenant.id,
            &tenant.id,
            AuditOutcome::Allow,
            false,
            Some(metadata),
        )
        .await?;
    Ok(settings_view(&tenant.id, &next, Some(&record)))
}

/// The JavaScript comparator `a.name.localeCompare(b.name, 'en') || (a.id < b.id ? -1 : 1)`.
fn by_name_then_id(a_name: &str, a_id: &str, b_name: &str, b_id: &str) -> Ordering {
    locale_compare(a_name, b_name).then_with(|| cmp_utf16(a_id, b_id))
}

impl GuestsApi {
    /// `guests/attest`: renews a guest's access: their access (and what the invitation granted with it) now ends
    /// `days` from now (1 to 365, default the tenant's `accessDays`), and the next review is due after the tenant's
    /// `reviewEveryDays`. The guest's sponsor may do it without any permission; anyone else needs iam:guests:manage on
    /// iam/guests/{identityId}. Audited as `guest:attest`.
    pub async fn attest(
        &self,
        credential: &CredentialInput,
        input: Body<guests::AttestInput>,
    ) -> IamResult<Reply<guests::AttestOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let identity_id = text(input.get("identityId"), "identityId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let sponsoring = {
            let tenant_id = tenant_id.clone();
            let identity_id = identity_id.clone();
            let sponsor = authenticated.identity.id.clone();
            ctx.store
                .transaction(|tx| async move {
                    let account = tx.get(ACCOUNTS, &identity_id).await?;
                    Ok(account.is_some_and(|account| {
                        account.get("tenantId").and_then(Value::as_str) == Some(tenant_id.as_str())
                            && account.get("sponsorId").and_then(Value::as_str)
                                == Some(sponsor.as_str())
                    }))
                })
                .await?
        };
        let days = input.get("days").cloned();
        // Anyone but the sponsor goes through the permission check (and its audit).
        if !sponsoring {
            let tenant_ref = &tenant_id;
            let identity_ref = &identity_id;
            let days_ref = &days;
            let mutation: Mutation<'_> =
                Box::new(move |MutationContext { tx, principal, .. }| {
                    Box::pin(async move {
                        attest_guest(
                            ctx,
                            &tx,
                            &principal,
                            tenant_ref,
                            identity_ref,
                            days_ref.as_ref(),
                            false,
                        )
                        .await
                    })
                });
            let result = ctx
                .operations()?
                .operation(
                    credential,
                    Some(&Value::String(tenant_id.clone())),
                    "iam:guests:manage",
                    &guest_resource(&identity_id),
                    mutation,
                    false,
                )
                .await?;
            return Ok(Reply::json(result));
        }
        let result = ctx
            .store
            .transaction(|tx| {
                let authenticated = &authenticated;
                let tenant_id = &tenant_id;
                let identity_id = &identity_id;
                let days = &days;
                async move {
                    ctx.auth.assert_tenant_active(&tx, tenant_id).await?;
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    own_session(
                        &principal,
                        tenant_id,
                        "Sponsors renew their guests\u{2019} access",
                    )?;
                    if impersonating(&principal) {
                        return Err(IamError::with_status(
                            "IMPERSONATION_RESTRICTED",
                            "A guest\u{2019}s access cannot be renewed while impersonating",
                            403,
                        ));
                    }
                    attest_guest(
                        ctx,
                        &tx,
                        &principal,
                        tenant_id,
                        identity_id,
                        days.as_ref(),
                        true,
                    )
                    .await
                    .map_err(IamError::from)
                }
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `guests/configure`: changes the tenant's cross-tenant access settings; only the fields given change (inside
    /// `inbound` and `outbound` too). Requires recent authentication and iam:guests:settings on iam/guests/settings;
    /// audited as `guest:settings`.
    pub async fn configure(
        &self,
        credential: &CredentialInput,
        input: Body<guests::ConfigureInput>,
    ) -> IamResult<Reply<guests::ConfigureOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(
                    async move { configure_mutation(ctx, &tx, &principal, &tenant, body).await },
                )
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:guests:settings",
                "guests/settings",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `guests/convertToMember`: makes an active guest an ordinary member: the `guest` marker goes, the guest account
    /// closes as `converted`, and the access end stays unless `clearExpiry` removes it together with the end of what
    /// the invitation granted. Audited as `guest:convert`.
    pub async fn convert_to_member(
        &self,
        credential: &CredentialInput,
        input: Body<guests::ConvertToMemberInput>,
    ) -> IamResult<Reply<guests::ConvertToMemberOutput>> {
        let ctx = &self.ctx;
        let identity_id = text(input.get("identityId"), "identityId", 256)?;
        let clear_expiry = match input.get("clearExpiry") {
            None => false,
            Some(value) => flag(Some(value), "clearExpiry")?,
        };
        let identity_ref = &identity_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    convert_mutation(ctx, &tx, &principal, &tenant, identity_ref, clear_expiry)
                        .await
                })
            },
        );
        let converted = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:guests:manage",
                &guest_resource(&identity_id),
                mutation,
                false,
            )
            .await?;
        let converted_id = js_string(converted.get("id"));
        let result = after_identity_change(
            ctx,
            &string_member(&input, "tenantId"),
            &[converted_id],
            &converted,
        )
        .await?;
        Ok(Reply::json(result))
    }

    /// `guests/get`: one guest. Requires iam:guests:read on iam/guests/{identityId}.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<guests::GetInput>,
    ) -> IamResult<Reply<guests::GetOutput>> {
        let ctx = &self.ctx;
        let identity_id = text(input.get("identityId"), "identityId", 256)?;
        let identity_ref = &identity_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let LoadedGuest {
                    account, identity, ..
                } = load_guest(&tx, &tenant.id, identity_ref).await?;
                Ok(guest_view(ctx, &tx, &account, &identity, &mut NameReader::new(&tx)).await?)
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:guests:read",
                &guest_resource(&identity_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `guests/getSettings`: the tenant's cross-tenant access settings (the defaults until configured). Requires
    /// iam:guests:read on iam/guests/settings.
    pub async fn get_settings(
        &self,
        credential: &CredentialInput,
        input: Body<guests::GetSettingsInput>,
    ) -> IamResult<Reply<guests::GetSettingsOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                // `guestSettings` and `readGuestSettings` read the same stored record.
                let stored = read_guest_settings_record(&tx, &tenant.id).await?;
                Ok(settings_view(
                    &tenant.id,
                    &guest_settings_value(stored.as_ref()),
                    stored.as_ref(),
                ))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:guests:read",
                "guests/settings",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `guests/invite`: invites a person from outside the organization (or from another tenant) as a guest: emails
    /// them a personal invitation (template `guest-invitation`) to redeem within `expiresInDays`. Requires
    /// iam:guests:invite on iam/guests/invitations and an email delivery callback; audited as `guest:invite`.
    pub async fn invite(
        &self,
        credential: &CredentialInput,
        input: Body<guests::InviteInput>,
    ) -> IamResult<Reply<guests::InviteOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move { invite_mutation(ctx, &tx, &principal, &tenant, body).await })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:guests:invite",
                "guests/invitations",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `guests/list`: the tenant's guests by name, optionally those of one sponsor, one account `status`, or whose
    /// access ends within `expiringWithinDays`; `limit`/`offset` page through them. Requires iam:guests:read on
    /// iam/guests.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<guests::ListInput>,
    ) -> IamResult<Reply<guests::ListOutput>> {
        let ctx = &self.ctx;
        let limit_fallback = number(100.0);
        let limit = integer(
            Some(nullish(input.get("limit"), &limit_fallback)),
            "limit",
            1.0,
            1000.0,
        )?;
        let offset_fallback = number(0.0);
        let offset = integer(
            Some(nullish(input.get("offset"), &offset_fallback)),
            "offset",
            0.0,
            1_000_000.0,
        )?;
        let status = input.get("status").cloned();
        if let Some(status) = &status
            && !status
                .as_str()
                .is_some_and(|status| ACCOUNT_STATUSES.contains(&status))
        {
            return Err(invalid(
                "status must be active, expired, removed or converted",
            ));
        }
        let sponsor_id = match input.get("sponsorId") {
            Some(value) => Some(text(Some(value), "sponsorId", 256)?),
            None => None,
        };
        let within = match input.get("expiringWithinDays") {
            Some(value) => Some(integer(Some(value), "expiringWithinDays", 0.0, 3650.0)?),
            None => None,
        };
        let status_ref = &status;
        let sponsor_ref = &sponsor_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let horizon = within.map(|within| ctx.now() + within * GUEST_DAY_MS);
                let mut filter = Filter::new().eq("tenantId", tenant.id.clone());
                if let Some(sponsor_id) = sponsor_ref {
                    filter = filter.eq("sponsorId", sponsor_id.clone());
                }
                let mut rows: Vec<(Record, Record)> = Vec::new();
                for account in find(&tx, ACCOUNTS, filter).await? {
                    let Some(identity) = tx
                        .get("identities", &js_string(account.get("identityId")))
                        .await?
                    else {
                        continue;
                    };
                    if identity.get("tenantId").and_then(Value::as_str) != Some(tenant.id.as_str())
                        || s(&identity, "status") == "deleted"
                    {
                        continue;
                    }
                    if let Some(status) = status_ref
                        && &account_status(ctx, &account, &identity) != status
                    {
                        continue;
                    }
                    if let Some(horizon) = horizon {
                        let ends = identity.get("expiresAt");
                        let skip = match ends {
                            None => true,
                            Some(end) => end.as_f64().is_some_and(|end| end > horizon),
                        };
                        if skip {
                            continue;
                        }
                    }
                    rows.push((account, identity));
                }
                rows.sort_by(|(_, a), (_, b)| {
                    by_name_then_id(s(a, "name"), s(a, "id"), s(b, "name"), s(b, "id"))
                });
                let total = rows.len();
                let mut names = NameReader::new(&tx);
                let mut guests = Vec::new();
                for (account, identity) in rows.iter().skip(offset as usize).take(limit as usize) {
                    guests.push(guest_view(ctx, &tx, account, identity, &mut names).await?);
                }
                Ok(json!({ "guests": guests, "total": number(total as f64) }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:guests:read",
                "guests",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `guests/listInvitations`: the tenant's guest invitations, newest first, optionally one `status` (a lapsed
    /// pending invitation counts as expired). Tokens are never returned. Requires iam:guests:read on
    /// iam/guests/invitations.
    pub async fn list_invitations(
        &self,
        credential: &CredentialInput,
        input: Body<guests::ListInvitationsInput>,
    ) -> IamResult<Reply<guests::ListInvitationsOutput>> {
        let ctx = &self.ctx;
        let status = input.get("status").cloned();
        if let Some(status) = &status
            && !status
                .as_str()
                .is_some_and(|status| INVITATION_STATUSES.contains(&status))
        {
            return Err(invalid(
                "status must be pending, redeemed, revoked or expired",
            ));
        }
        let status_ref = &status;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let mut names = NameReader::new(&tx);
                let mut invitations = find(
                    &tx,
                    INVITATIONS,
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?;
                invitations.sort_by(by_newest_records);
                let mut views = Vec::new();
                for invitation in &invitations {
                    let view = invitation_view(ctx, invitation, &mut names).await?;
                    if status_ref
                        .as_ref()
                        .is_none_or(|status| view.get("status") == Some(status))
                    {
                        views.push(view);
                    }
                }
                Ok(Value::Array(views))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:guests:read",
                "guests/invitations",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `guests/mine`: the active guests the caller sponsors, the soonest review first; needs only an ordinary session
    /// of the tenant (no permission).
    pub async fn mine(
        &self,
        credential: &CredentialInput,
        input: Body<guests::MineInput>,
    ) -> IamResult<Reply<guests::MineOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let result = ctx
            .store
            .transaction(|tx| {
                let authenticated = &authenticated;
                let tenant_id = &tenant_id;
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    own_session(&principal, tenant_id, "The guests you sponsor are listed")?;
                    let mut names = NameReader::new(&tx);
                    let mut views = Vec::new();
                    for account in find(
                        &tx,
                        ACCOUNTS,
                        Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("sponsorId", principal.identity.id.clone())
                            .eq("status", "active"),
                    )
                    .await?
                    {
                        let Some(identity) = tx
                            .get("identities", &js_string(account.get("identityId")))
                            .await?
                        else {
                            continue;
                        };
                        if identity.get("tenantId").and_then(Value::as_str)
                            != Some(tenant_id.as_str())
                            || s(&identity, "status") == "deleted"
                        {
                            continue;
                        }
                        views.push(guest_view(ctx, &tx, &account, &identity, &mut names).await?);
                    }
                    views.sort_by(|a, b| {
                        let due = |view: &Value| {
                            view.get("reviewDueAt")
                                .and_then(Value::as_f64)
                                .unwrap_or(f64::NAN)
                        };
                        let difference = due(a) - due(b);
                        if difference != 0.0 && !difference.is_nan() {
                            return if difference < 0.0 {
                                Ordering::Less
                            } else {
                                Ordering::Greater
                            };
                        }
                        let text_of = |view: &Value, key: &str| {
                            view.get(key)
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned()
                        };
                        by_name_then_id(
                            &text_of(a, "name"),
                            &text_of(a, "identityId"),
                            &text_of(b, "name"),
                            &text_of(b, "identityId"),
                        )
                    });
                    Ok(Value::Array(views))
                }
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `guests/redeem` (public: no credential): redeems a guest invitation with the invitee's name and a new
    /// password, creates the guest identity (email verified), and signs them in with a password session. Rate limited
    /// per tenant, client address and token; audited as `guest:redeem`.
    pub async fn redeem(
        &self,
        input: Body<guests::RedeemInput>,
    ) -> IamResult<Reply<guests::RedeemOutput>> {
        let ctx = &self.ctx;
        let auth = &ctx.auth;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let presented = text(input.get("token"), "token", 512)?;
        let name = text(input.get("name"), "name", 256)?;
        // The guest signs in with this password from now on (the tenant's password rules apply when it is set).
        let Some(Value::String(password)) = input.get("password") else {
            return Err(invalid("A password is required"));
        };
        let password = password.clone();
        // Counted outside the transaction, so a refusal cannot roll the counters back. The client's own budget comes
        // first (with the network steps): a client refused there spends none of the budget every invitee shares.
        let ip = auth
            .current_client()
            .and_then(|client| client.ip)
            .filter(|ip| !ip.is_empty());
        if let Some(ip) = &ip {
            let key = ip_counter_key(ip).unwrap_or_else(|| ip.clone());
            auth.limit_attempt(
                &tenant_id,
                &format!("guest-redeem:ip:{key}"),
                LimitAttemptOptions {
                    limit: Some(20.0),
                    ..LimitAttemptOptions::default()
                },
            )
            .await?;
        }
        auth.limit_attempt(
            &tenant_id,
            "guest-redeem",
            LimitAttemptOptions {
                limit: Some(500.0),
                count_client: ip.as_ref().map(|_| false),
                ..LimitAttemptOptions::default()
            },
        )
        .await?;
        auth.limit_attempt(
            &tenant_id,
            &format!("guest-redeem:{}", hash(&presented)),
            LimitAttemptOptions {
                limit: Some(10.0),
                count_client: Some(false),
                ..LimitAttemptOptions::default()
            },
        )
        .await?;
        let result =
            ctx.store
                .transaction(|tx| {
                    let tenant_id = &tenant_id;
                    let presented = &presented;
                    let name = &name;
                    let password = &password;
                    async move {
                        redeem_transaction(ctx, &tx, tenant_id, presented, name, password).await
                    }
                })
                .await?;
        // Birthright rules that test identity.guest apply now rather than at the next scheduled reconcile.
        let identity_id = js_string(
            result
                .get("identity")
                .and_then(|identity| identity.get("id")),
        );
        let result = after_identity_change(ctx, &tenant_id, &[identity_id], &result).await?;
        Ok(Reply::json(result))
    }

    /// `guests/remove`: removes a guest in one transaction: disables the identity, ends its sessions, keys and
    /// delegations, removes every grant it holds, cancels its pending requests and invitations, revokes the grant
    /// authorities it holds, and closes the guest account as `removed`. Audited as `guest:remove`.
    pub async fn remove(
        &self,
        credential: &CredentialInput,
        input: Body<guests::RemoveInput>,
    ) -> IamResult<Reply<guests::RemoveOutput>> {
        let ctx = &self.ctx;
        let identity_id = text(input.get("identityId"), "identityId", 256)?;
        let identity_ref = &identity_id;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    remove_mutation(ctx, &tx, &principal, &tenant, identity_ref, body).await
                })
            },
        );
        let removed = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:guests:manage",
                &guest_resource(&identity_id),
                mutation,
                false,
            )
            .await?;
        // A disabled identity claims no license seat: reconciling releases the guest's seats (licenses.ts), as
        // identities.setStatus does.
        let result = after_identity_change(
            ctx,
            &string_member(&input, "tenantId"),
            std::slice::from_ref(&identity_id),
            &removed,
        )
        .await?;
        Ok(Reply::json(result))
    }

    /// `guests/resendInvitation`: sends a pending or lapsed guest invitation again with a new token (the earlier one
    /// stops working) and a new lifetime (`expiresInDays`, default 14). Requires iam:guests:invite on
    /// iam/guests/invitations/{id}; audited as `guest:invitation-resend`.
    pub async fn resend_invitation(
        &self,
        credential: &CredentialInput,
        input: Body<guests::ResendInvitationInput>,
    ) -> IamResult<Reply<guests::ResendInvitationOutput>> {
        let ctx = &self.ctx;
        let invitation_id = text(input.get("invitationId"), "invitationId", 256)?;
        let lifetime_fallback = number(limits::INVITATION_DAYS);
        let lifetime = integer(
            Some(nullish(input.get("expiresInDays"), &lifetime_fallback)),
            "expiresInDays",
            1.0,
            limits::MAX_INVITATION_DAYS,
        )?;
        let invitation_ref = &invitation_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    resend_mutation(ctx, &tx, &principal, &tenant, invitation_ref, lifetime).await
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:guests:invite",
                &invitation_resource(&invitation_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `guests/revokeInvitation`: revokes a pending guest invitation; its token stops working. Requires
    /// iam:guests:manage on iam/guests/invitations/{id}; audited as `guest:invitation-revoke`.
    pub async fn revoke_invitation(
        &self,
        credential: &CredentialInput,
        input: Body<guests::RevokeInvitationInput>,
    ) -> IamResult<Reply<guests::RevokeInvitationOutput>> {
        let ctx = &self.ctx;
        let invitation_id = text(input.get("invitationId"), "invitationId", 256)?;
        let invitation_ref = &invitation_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    let invitation = ctx
                        .scoped(
                            &tx,
                            INVITATIONS,
                            Some(&Value::String(invitation_ref.clone())),
                            &tenant.id,
                        )
                        .await?;
                    if s(&invitation, "status") != "pending" {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "Only a pending invitation can be revoked",
                            409,
                        )
                        .into());
                    }
                    let mut rest = invitation.clone();
                    rest.shift_remove("uniqueKey");
                    rest.insert("status".into(), Value::String("revoked".into()));
                    rest.insert("revokedAt".into(), number(ctx.now()));
                    rest.insert(
                        "revokedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let revoked = tx.put(INVITATIONS, &rest).await?;
                    let mut metadata = Map::new();
                    copy(&mut metadata, &invitation, "email");
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "guest:invitation-revoke",
                            &tenant.id,
                            s(&invitation, "id"),
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(invitation_view(ctx, &revoked, &mut NameReader::new(&tx)).await?)
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:guests:manage",
                &invitation_resource(&invitation_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `guests/setSponsor`: gives an active guest a new sponsor (an active member who is not a guest), clearing a
    /// missing-sponsor flag. Requires recent authentication and iam:guests:manage on iam/guests/{identityId}; audited
    /// as `guest:sponsor-change`.
    pub async fn set_sponsor(
        &self,
        credential: &CredentialInput,
        input: Body<guests::SetSponsorInput>,
    ) -> IamResult<Reply<guests::SetSponsorOutput>> {
        let ctx = &self.ctx;
        let identity_id = text(input.get("identityId"), "identityId", 256)?;
        let identity_ref = &identity_id;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    // The sponsor renews the guest and policies grant on principal.guestSponsorId: guests never choose
                    // one, their own included, as they never renew anyone (attest).
                    if identity_ref == &principal.identity.id
                        || is_guest_identity(&principal.identity)
                    {
                        return Err(OperationDenied::new(Some(
                            "Guests cannot change a guest\u{2019}s sponsor",
                        )));
                    }
                    let LoadedGuest {
                        account, identity, ..
                    } = load_guest(&tx, &tenant.id, identity_ref).await?;
                    if s(&account, "status") != "active" || !truthy(identity.get("guest")) {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "Only an active guest has a sponsor to change",
                            409,
                        )
                        .into());
                    }
                    let sponsor =
                        guest_sponsor(ctx, &tx, &tenant.id, body.get("sponsorId")).await?;
                    let (moved_account, moved_identity) =
                        set_guest_sponsor(&tx, &account, &identity, &sponsor.id).await?;
                    let mut metadata = Map::new();
                    if let Some(from) = account.get("sponsorId") {
                        metadata.insert("from".into(), from.clone());
                    }
                    metadata.insert("to".into(), Value::String(sponsor.id.clone()));
                    metadata.insert("reason".into(), Value::String("administrator".into()));
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "guest:sponsor-change",
                            &tenant.id,
                            s(&identity, "id"),
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(guest_view(
                        ctx,
                        &tx,
                        &moved_account,
                        &moved_identity,
                        &mut NameReader::new(&tx),
                    )
                    .await?)
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:guests:manage",
                &guest_resource(&identity_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// What one tenant's reminder transaction did.
enum ReminderOutcome {
    Inactive,
    Sent(Vec<Value>),
}

/// One due event of a guest: the review or the access end.
struct DueEvent {
    key: String,
    at: f64,
    until: f64,
}

/// Reminds sponsors of guests whose review is due or whose access ends soon (see `IamGuests.sendReviewReminders`).
async fn send_review_reminders(ctx: &Arc<ServerContext>, input: &Value) -> IamResult<Value> {
    let fallback = number(limits::REMINDER_DAYS);
    let within_days = integer(
        Some(nullish(input.get("withinDays"), &fallback)),
        "withinDays",
        1.0,
        90.0,
    )?;
    if !sends_email(ctx) {
        return Err(IamError::new(
            "DELIVERY_REQUIRED",
            "Guest review reminders require an email delivery callback",
        ));
    }
    let tenant_ids: Vec<String> = match input.get("tenantId") {
        Some(value) => vec![text(Some(value), "tenantId", 256)?],
        None => {
            let accounts = ctx
                .store
                .find(ACCOUNTS, &Filter::new().eq("status", "active"), &find_all())
                .await?;
            let mut ids = unique(
                accounts
                    .iter()
                    .map(|account| js_string(account.get("tenantId"))),
            );
            ids.sort_by(|a, b| cmp_utf16(a, b));
            ids
        }
    };
    let mut sent: Vec<Value> = Vec::new();
    let mut inactive = 0.0;
    let mut quiet = 0.0;
    for tenant_id in tenant_ids {
        // Counted once the tenant's transaction committed.
        let outcome = ctx
            .store
            .transaction(|tx| {
                let tenant_id = tenant_id.clone();
                async move { remind_tenant(ctx, &tx, &tenant_id, within_days).await }
            })
            .await?;
        match outcome {
            ReminderOutcome::Inactive => inactive += 1.0,
            ReminderOutcome::Sent(entries) if entries.is_empty() => quiet += 1.0,
            ReminderOutcome::Sent(entries) => sent.extend(entries),
        }
    }
    Ok(json!({
        "sent": sent,
        "skipped": { "inactive": number(inactive), "quiet": number(quiet) },
    }))
}

async fn remind_tenant(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    within_days: f64,
) -> IamResult<ReminderOutcome> {
    let mut sent = Vec::new();
    let Some(tenant) = tx.get("tenants", tenant_id).await? else {
        return Ok(ReminderOutcome::Inactive);
    };
    if s(&tenant, "status") != "active" {
        return Ok(ReminderOutcome::Inactive);
    }
    let now = ctx.now();
    let horizon = now + within_days * GUEST_DAY_MS;
    // Reminder marks (lifecycle.ts) remember each guest and due date reminded; they outlive the due date.
    let mut reminded: HashMap<String, Record> = HashMap::new();
    for mark in find(
        tx,
        "expiryReminderMarks",
        Filter::new().eq("tenantId", tenant_id),
    )
    .await?
    {
        reminded.insert(js_string(mark.get("uniqueKey")), mark);
    }
    let mut accounts = find(
        tx,
        ACCOUNTS,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("status", "active"),
    )
    .await?;
    accounts.sort_by(|a, b| cmp_utf16(s(a, "id"), s(b, "id")));
    for account in accounts {
        let Some(guest) = tx
            .get("identities", &js_string(account.get("identityId")))
            .await?
        else {
            continue;
        };
        if guest.get("tenantId").and_then(Value::as_str) != Some(tenant_id)
            || s(&guest, "status") != "active"
            || expired_record(ctx, &guest)
            || !is_guest(&Value::Object(guest.clone()))
        {
            continue;
        }
        let guest_id = js_string(guest.get("id"));
        let review_due_at = num(&account, "reviewDueAt").unwrap_or(f64::NAN);
        let review_key = format!(
            "guest-review:{guest_id}:{}",
            match account.get("reviewDueAt") {
                Some(Value::Number(_)) => number_to_string(review_due_at),
                other => js_string(other),
            }
        );
        // A reminded review stays reminded while it is outstanding: its mark is kept alive past the end it was given,
        // so the purge cannot let it go out again.
        if let Some(mark) = reminded.get(&review_key)
            && num(mark, "expiresAt").is_some_and(|expires| expires <= horizon)
        {
            let mut kept = mark.clone();
            kept.insert(
                "expiresAt".into(),
                number(horizon + within_days * GUEST_DAY_MS),
            );
            tx.put("expiryReminderMarks", &kept).await?;
        }
        // The review and the access end are each reminded once per date; one email covers whatever is due.
        let guest_end = num(&guest, "expiresAt");
        let mut due = vec![DueEvent {
            key: review_key,
            at: review_due_at,
            // Kept while the review stays overdue (until the access ends), so it is not reminded again.
            until: review_due_at.max(guest_end.unwrap_or(review_due_at)),
        }];
        if let Some(end) = guest_end {
            due.push(DueEvent {
                key: format!("guest-end:{guest_id}:{}", number_to_string(end)),
                at: end,
                until: end,
            });
        }
        due.retain(|event| event.at <= horizon && !reminded.contains_key(&event.key));
        if due.is_empty() {
            continue;
        }
        let due_at = due
            .iter()
            .map(|event| event.at)
            .fold(f64::INFINITY, f64::min);
        let sponsor: Option<Identity> = match tx
            .get("identities", &js_string(account.get("sponsorId")))
            .await?
        {
            Some(record) => Some(decode(record)?),
            None => None,
        };
        let Some(sponsor) = sponsor.filter(|sponsor| can_sponsor(ctx, Some(sponsor), tenant_id))
        else {
            continue;
        };
        let Some(sponsor_email) = sponsor.email.clone().filter(|email| !email.is_empty()) else {
            continue;
        };
        let mut payload = Map::new();
        payload.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
        copy(&mut payload, &tenant, "name");
        if let Some(name) = payload.shift_remove("name") {
            payload.insert("tenantName".into(), name);
        }
        payload.insert("guestId".into(), Value::String(guest_id.clone()));
        if let Some(name) = guest.get("name") {
            payload.insert("guestName".into(), name.clone());
        }
        if truthy(guest.get("email")) {
            payload.insert("guestEmail".into(), guest["email"].clone());
        }
        payload.insert("dueAt".into(), Value::String(iso(due_at)?));
        payload.insert("reviewDueAt".into(), Value::String(iso(review_due_at)?));
        if let Some(end) = guest_end {
            payload.insert("expiresAt".into(), Value::String(iso(end)?));
        }
        ctx.auth
            .enqueue_delivery(
                tx,
                EnqueueInput {
                    tenant_id: tenant_id.to_owned(),
                    kind: OutboxKind::Email,
                    to: sponsor_email,
                    template: "guest-review".into(),
                    payload,
                    reference: None,
                },
            )
            .await?;
        for event in &due {
            let mut mark = Record::new();
            mark.insert("id".into(), Value::String(id()));
            mark.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
            mark.insert("uniqueKey".into(), Value::String(event.key.clone()));
            mark.insert("identityId".into(), Value::String(guest_id.clone()));
            mark.insert(
                "expiresAt".into(),
                number(event.until + within_days * GUEST_DAY_MS),
            );
            tx.insert("expiryReminderMarks", &mark).await?;
        }
        let mut metadata = Map::new();
        metadata.insert("sponsorId".into(), Value::String(sponsor.id.clone()));
        metadata.insert("dueAt".into(), number(due_at));
        if let Some(end) = guest_end {
            metadata.insert("expiresAt".into(), number(end));
        }
        record_system(
            ctx,
            tx,
            tenant_id,
            "guest:review-reminder",
            &guest_id,
            now,
            metadata,
        )
        .await?;
        sent.push(json!({
            "tenantId": tenant_id,
            "guestId": guest_id,
            "sponsorId": sponsor.id,
            "dueAt": number(due_at),
        }));
    }
    Ok(ReminderOutcome::Sent(sent))
}

/// A system audit event of the guest jobs (`actorId: 'deployment-operator'`).
async fn record_system(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    action: &str,
    resource_id: &str,
    now: f64,
    metadata: Map<String, Value>,
) -> IamResult<()> {
    let mut event = Record::new();
    event.insert("id".into(), Value::String(id()));
    event.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    event.insert(
        "actorId".into(),
        Value::String("deployment-operator".into()),
    );
    event.insert("action".into(), Value::String(action.to_owned()));
    event.insert("resourceId".into(), Value::String(resource_id.to_owned()));
    event.insert("timestamp".into(), number(now));
    event.insert("outcome".into(), Value::String("allow".into()));
    event.insert("metadata".into(), Value::Object(metadata));
    ctx.events()?.record_audit(tx, &event).await
}

/// What `iam.guests.sweep` changed.
#[derive(Debug, Clone, Copy, Default)]
struct SweepResult {
    invitations_expired: f64,
    accounts_expired: f64,
    accounts_restored: f64,
    sponsors_missing: f64,
    owners_notified: f64,
    partners_removed: f64,
}

impl SweepResult {
    fn add(&mut self, other: &SweepResult) {
        self.invitations_expired += other.invitations_expired;
        self.accounts_expired += other.accounts_expired;
        self.accounts_restored += other.accounts_restored;
        self.sponsors_missing += other.sponsors_missing;
        self.owners_notified += other.owners_notified;
        self.partners_removed += other.partners_removed;
    }

    fn to_value(self) -> Value {
        json!({
            "invitationsExpired": number(self.invitations_expired),
            "accountsExpired": number(self.accounts_expired),
            "accountsRestored": number(self.accounts_restored),
            "sponsorsMissing": number(self.sponsors_missing),
            "ownersNotified": number(self.owners_notified),
            "partnersRemoved": number(self.partners_removed),
        })
    }
}

/// One tenant's guest bookkeeping (see `IamGuests.sweep`); returns what it changed.
async fn sweep_tenant(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
) -> IamResult<SweepResult> {
    let mut result = SweepResult::default();
    let now = ctx.now();
    let tenant = tx.get("tenants", tenant_id).await?;
    for invitation in find(
        tx,
        INVITATIONS,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("status", "pending"),
    )
    .await?
    {
        if num(&invitation, "expiresAt").is_some_and(|expires| expires <= now) {
            let mut rest = invitation;
            rest.shift_remove("uniqueKey");
            rest.insert("status".into(), Value::String("expired".into()));
            tx.put(INVITATIONS, &rest).await?;
            result.invitations_expired += 1.0;
        }
    }
    let mut owners: Option<Vec<Record>> = None;
    let mut accounts = find(
        tx,
        ACCOUNTS,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("status", "active"),
    )
    .await?;
    accounts.extend(
        find(
            tx,
            ACCOUNTS,
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("status", "expired"),
        )
        .await?,
    );
    for mut account in accounts {
        let identity = tx
            .get("identities", &js_string(account.get("identityId")))
            .await?;
        let Some(identity) = identity.filter(|identity| {
            identity.get("tenantId").and_then(Value::as_str) == Some(tenant_id)
                && s(identity, "status") != "deleted"
        }) else {
            // The identity is gone: its account goes with it (deleteIdentity removes it too).
            tx.delete(ACCOUNTS, s(&account, "id")).await?;
            continue;
        };
        let identity_id = js_string(identity.get("id"));
        if s(&account, "status") == "active" && expired_record(ctx, &identity) {
            let ended = identity
                .get("expiresAt")
                .cloned()
                .unwrap_or_else(|| number(now));
            account.insert("status".into(), Value::String("expired".into()));
            account.insert("endedAt".into(), ended.clone());
            account = tx.put(ACCOUNTS, &account).await?;
            let mut metadata = Map::new();
            copy(&mut metadata, &account, "sponsorId");
            metadata.insert("expiresAt".into(), ended);
            record_system(
                ctx,
                tx,
                tenant_id,
                "guest:expire",
                &identity_id,
                now,
                metadata,
            )
            .await?;
            result.accounts_expired += 1.0;
        } else if s(&account, "status") == "expired"
            && s(&identity, "status") == "active"
            && !expired_record(ctx, &identity)
            && is_guest(&Value::Object(identity.clone()))
        {
            // An administrator gave the guest a later end and enabled them again.
            account.shift_remove("endedAt");
            account.shift_remove("endedBy");
            account.insert("status".into(), Value::String("active".into()));
            account = tx.put(ACCOUNTS, &account).await?;
            result.accounts_restored += 1.0;
        }
        if s(&account, "status") != "active" {
            continue;
        }
        let sponsor_record = tx
            .get("identities", &js_string(account.get("sponsorId")))
            .await?;
        let sponsor_name = sponsor_record
            .as_ref()
            .filter(|sponsor| sponsor.get("tenantId").and_then(Value::as_str) == Some(tenant_id))
            .and_then(|sponsor| sponsor.get("name").cloned());
        let sponsor: Option<Identity> = match sponsor_record {
            Some(record) => Some(decode(record)?),
            None => None,
        };
        if can_sponsor(ctx, sponsor.as_ref(), tenant_id) {
            if truthy(account.get("sponsorMissing"))
                || account.contains_key("sponsorMissingNotifiedAt")
            {
                let mut rest = account.clone();
                rest.shift_remove("sponsorMissing");
                rest.shift_remove("sponsorMissingNotifiedAt");
                tx.put(ACCOUNTS, &rest).await?;
            }
            continue;
        }
        if !truthy(account.get("sponsorMissing")) {
            account.insert("sponsorMissing".into(), Value::Bool(true));
            account = tx.put(ACCOUNTS, &account).await?;
            let mut metadata = Map::new();
            copy(&mut metadata, &account, "sponsorId");
            record_system(
                ctx,
                tx,
                tenant_id,
                "guest:sponsor-missing",
                &identity_id,
                now,
                metadata,
            )
            .await?;
            result.sponsors_missing += 1.0;
        }
        // The owners hear about each guest once per loss, when the deployment can email and the tenant is active.
        let tenant_active = tenant
            .as_ref()
            .is_some_and(|tenant| s(tenant, "status") == "active");
        if !account.contains_key("sponsorMissingNotifiedAt") && tenant_active && sends_email(ctx) {
            if owners.is_none() {
                let found = find(
                    tx,
                    "identities",
                    Filter::new()
                        .eq("tenantId", tenant_id)
                        .eq("owner", true)
                        .eq("status", "active"),
                )
                .await?;
                owners = Some(
                    found
                        .into_iter()
                        .filter(|owner| truthy(owner.get("email")) && !expired_record(ctx, owner))
                        .collect(),
                );
            }
            let owners = owners.as_deref().unwrap_or_default();
            for owner in owners {
                let mut payload = Map::new();
                payload.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
                if let Some(name) = tenant.as_ref().and_then(|tenant| tenant.get("name")) {
                    payload.insert("tenantName".into(), name.clone());
                }
                payload.insert("guestId".into(), Value::String(identity_id.clone()));
                if let Some(name) = identity.get("name") {
                    payload.insert("guestName".into(), name.clone());
                }
                if truthy(identity.get("email")) {
                    payload.insert("guestEmail".into(), identity["email"].clone());
                }
                if let Some(name) = sponsor_name.as_ref().filter(|name| truthy(Some(name))) {
                    payload.insert("sponsorName".into(), name.clone());
                }
                ctx.auth
                    .enqueue_delivery(
                        tx,
                        EnqueueInput {
                            tenant_id: tenant_id.to_owned(),
                            kind: OutboxKind::Email,
                            to: js_string(owner.get("email")),
                            template: "guest-sponsor-missing".into(),
                            payload,
                            reference: None,
                        },
                    )
                    .await?;
                result.owners_notified += 1.0;
            }
            if !owners.is_empty() {
                let mut notified = account.clone();
                notified.insert("sponsorMissingNotifiedAt".into(), number(now));
                tx.put(ACCOUNTS, &notified).await?;
            }
        }
    }
    // Partner entries naming tenants that were purged since can never match again.
    if let Some(stored) = read_guest_settings_record(tx, tenant_id).await? {
        let partners_of = |key: &str| match stored.get(key).and_then(|side| side.get("partners")) {
            Some(Value::Array(items)) => items.clone(),
            _ => Vec::new(),
        };
        let mut kept_sides = Vec::new();
        let mut removed = 0.0;
        for key in ["inbound", "outbound"] {
            let partners = partners_of(key);
            let mut kept = Vec::new();
            for partner in &partners {
                if tx
                    .get("tenants", &js_string(partner.get("tenantId")))
                    .await?
                    .is_some()
                {
                    kept.push(partner.clone());
                }
            }
            removed += (partners.len() - kept.len()) as f64;
            kept_sides.push(kept);
        }
        if removed != 0.0 {
            let mut next = stored.clone();
            for (key, kept) in ["inbound", "outbound"].into_iter().zip(kept_sides) {
                let mut side = match stored.get(key) {
                    Some(Value::Object(map)) => map.clone(),
                    _ => Map::new(),
                };
                side.insert("partners".into(), Value::Array(kept));
                next.insert(key.into(), Value::Object(side));
            }
            tx.put(SETTINGS, &next).await?;
            let mut metadata = Map::new();
            metadata.insert("partnersRemoved".into(), number(removed));
            record_system(
                ctx,
                tx,
                tenant_id,
                "guest:settings",
                tenant_id,
                now,
                metadata,
            )
            .await?;
            result.partners_removed += removed;
        }
    }
    Ok(result)
}

/// Guest bookkeeping across tenants, one transaction per tenant (see `IamGuests.sweep`).
async fn sweep_guests(ctx: &Arc<ServerContext>, input: &Value) -> IamResult<Value> {
    let tenant_filter = match input.get("tenantId") {
        Some(value) => Some(text(Some(value), "tenantId", 256)?),
        None => None,
    };
    let filter = || {
        let mut filter = Filter::new();
        if let Some(tenant_id) = &tenant_filter {
            filter = filter.eq("tenantId", tenant_id.clone());
        }
        filter
    };
    let mut result = SweepResult::default();
    let mut tenant_ids: IndexSet<String> = IndexSet::new();
    for invitation in ctx
        .store
        .find(INVITATIONS, &filter().eq("status", "pending"), &find_all())
        .await?
    {
        tenant_ids.insert(js_string(invitation.get("tenantId")));
    }
    for status in ["active", "expired"] {
        for account in ctx
            .store
            .find(ACCOUNTS, &filter().eq("status", status), &find_all())
            .await?
        {
            tenant_ids.insert(js_string(account.get("tenantId")));
        }
    }
    for settings in ctx.store.find(SETTINGS, &filter(), &find_all()).await? {
        tenant_ids.insert(js_string(settings.get("tenantId")));
    }
    let mut tenant_ids: Vec<String> = tenant_ids.into_iter().collect();
    tenant_ids.sort_by(|a, b| cmp_utf16(a, b));
    for tenant_id in tenant_ids {
        // Counted once the tenant's transaction committed.
        let swept = ctx
            .store
            .transaction(|tx| {
                let tenant_id = tenant_id.clone();
                async move { sweep_tenant(ctx, &tx, &tenant_id).await }
            })
            .await?;
        result.add(&swept);
    }
    Ok(result.to_value())
}

/// The guest scheduler jobs on the instance (`iam.guests`).
pub struct GuestsRuntime {
    ctx: Arc<ServerContext>,
}

/// `createGuestsRuntime(...)`.
pub fn create_guests_runtime(ctx: &Arc<ServerContext>) -> IamResult<GuestsRuntime> {
    Ok(GuestsRuntime { ctx: ctx.clone() })
}

impl GuestsRuntime {
    /// Emails each sponsor (template `guest-review`) about guests whose review is due or whose access ends within
    /// `withinDays` (default 14): each review date and each access end once, one email covering whatever is due.
    /// Requires an email delivery callback.
    pub async fn send_review_reminders(&self, input: Option<&Value>) -> IamResult<Value> {
        let empty = json!({});
        send_review_reminders(&self.ctx, input.unwrap_or(&empty)).await
    }
    /// Bookkeeping: marks lapsed invitations and ended guest accounts expired, flags guests whose sponsor left (and
    /// emails the tenant's owners once, template `guest-sponsor-missing`), and drops partner entries naming purged
    /// tenants.
    pub async fn sweep(&self, input: Option<&Value>) -> IamResult<Value> {
        let empty = json!({});
        sweep_guests(&self.ctx, input.unwrap_or(&empty)).await
    }
    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        let input = args.first().filter(|value| !value.is_null());
        match method {
            "sendReviewReminders" => Some(self.send_review_reminders(input).await),
            "sweep" => Some(self.sweep(input).await),
            _ => None,
        }
    }
}
