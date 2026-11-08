//! Port of `packages/server/src/api/identities.ts`: the `identities` API group (people and their lifecycle: creation,
//! bulk onboarding, invitations, impersonation, linked external sign-ins, offboarding, ownership, boundaries) and the
//! identity helpers other modules share (`deleteIdentity`, `assertOwnerControl`, `revokeInvitationsBy`).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use better_iam_auth::crypto::encrypt_secret;
use better_iam_auth::service::base::CreateIdentityRaw;
use better_iam_core::boxed;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, Identity, IdentityKind, IdentityStatus, Record, SessionKind, TenantStatus,
    js as core_js,
};
use better_iam_types::api::identities;
use indexmap::IndexSet;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply, string_member};
use crate::catalog::attribute_values;
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, OperationDenied, OperationResult};
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::port::{decode, encode};
use crate::utils::{all_value, date_now, hash, id, public_identity, public_identity_record, token};
use crate::validation::{email, integer, object, strings, text};

/// The refusal of `createMany` and `invite` when a group they fill carries license seats (groups.ts).
const SEATS_MESSAGE: &str =
    "A group you add people to carries license seats; adding them needs iam:licenses:assign";

/// An external sign-in an administrator links to an account ahead of its first federated sign-in
/// (`ProviderLinkInput`).
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderLinkInput {
    /// The connection's provider key: an OAuth connection's `id`, a SAML connection's `providerId`.
    pub provider_id: String,
    /// The IdP's issuer exactly as the protocol reports it (OIDC `iss`, SAML IdP entity ID).
    pub issuer: String,
    /// The person's stable ID at the IdP (OIDC `sub`, SAML NameID).
    pub subject: String,
}

// --- small record helpers ------------------------------------------------------------------------------------------

fn str_of<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

fn record_id(record: &Record) -> String {
    str_of(record, "id").unwrap_or_default().to_owned()
}

fn number_of(record: &Record, key: &str) -> Option<f64> {
    record.get(key).and_then(core_js::as_number)
}

/// JavaScript truthiness of a record member.
fn truthy(record: &Record, key: &str) -> bool {
    crate::js::truthy(record.get(key))
}

async fn find(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

/// `{ tokenHash: _hash, uniqueKey: _key, ...safe }`.
fn without_secrets(mut record: Record) -> Value {
    record.shift_remove("tokenHash");
    record.shift_remove("uniqueKey");
    Value::Object(record)
}

/// `(a.id < b.id ? -1 : 1)` as an ordering (IDs are unique).
fn id_order(a: &Record, b: &Record) -> std::cmp::Ordering {
    let (a, b) = (str_of(a, "id").unwrap_or(""), str_of(b, "id").unwrap_or(""));
    if core_js::cmp_utf16(a, b) == std::cmp::Ordering::Less {
        std::cmp::Ordering::Less
    } else {
        std::cmp::Ordering::Greater
    }
}

/// `b[key] - a[key] || (a.id < b.id ? -1 : 1)`: newest first by a numeric member.
fn newest_by(key: &str, a: &Record, b: &Record) -> std::cmp::Ordering {
    let value = |record: &Record| number_of(record, key).unwrap_or(f64::NAN);
    let difference = value(b) - value(a);
    if difference != 0.0 && !difference.is_nan() {
        return if difference > 0.0 {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Less
        };
    }
    id_order(a, b)
}

/// `a.name.localeCompare(b.name, 'en') || <id order>`.
fn by_name(
    a: &Record,
    b: &Record,
    ids: impl Fn(&Record, &Record) -> std::cmp::Ordering,
) -> std::cmp::Ordering {
    crate::metrics::locale_compare(
        str_of(a, "name").unwrap_or(""),
        str_of(b, "name").unwrap_or(""),
    )
    .then_with(|| ids(a, b))
}

/// A stored identity with its typed view: the raw record keeps member order and members this port does not know
/// (a mixed fleet shares the database), the typed one answers the checks.
struct Loaded {
    raw: Record,
    identity: Identity,
}

impl Loaded {
    fn new(raw: Record) -> IamResult<Self> {
        Ok(Self {
            identity: decode(raw.clone())?,
            raw,
        })
    }
}

/// `ctx.scoped<Identity>(tx, 'identities', identityId, tenantId)`.
async fn scoped_identity(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    identity_id: Option<&Value>,
    tenant_id: &str,
) -> IamResult<Loaded> {
    Loaded::new(ctx.scoped(tx, "identities", identity_id, tenant_id).await?)
}

/// `ctx.activeIdentity(tx, identityId, tenantId)`: deleted identities remain readable as historical principals only.
async fn active_identity(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    identity_id: Option<&Value>,
    tenant_id: &str,
) -> IamResult<Loaded> {
    let loaded = scoped_identity(ctx, tx, identity_id, tenant_id).await?;
    if loaded.identity.status == IdentityStatus::Deleted {
        return Err(IamError::with_status(
            "NOT_FOUND",
            "Identity has been deleted",
            404,
        ));
    }
    Ok(loaded)
}

/// `ctx.decisions.decide(tx, principal, { tenantId, action, resource: { type: 'iam', id } }, true).allowed`.
async fn allowed(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    action: &str,
    resource_id: &str,
) -> IamResult<bool> {
    Ok(ctx
        .decisions()?
        .decide(
            tx,
            principal,
            &AuthorizationRequest {
                credential: CredentialInput::default(),
                tenant_id: tenant_id.to_owned(),
                action: action.to_owned(),
                resource: ResourceTarget {
                    kind: "iam".into(),
                    id: resource_id.to_owned(),
                },
            },
            true,
        )
        .await?
        .allowed)
}

/// `flag(value, name)`: an optional boolean.
fn flag(value: Option<&Value>, name: &str) -> IamResult<bool> {
    match value {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(IamError::new(
            "INVALID_INPUT",
            format!("{name} must be a boolean"),
        )),
    }
}

/// `providerLinks(value)`: up to 10 links per person, each a distinct provider.
fn provider_links(value: Option<&Value>) -> IamResult<Vec<ProviderLinkInput>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let items = match value {
        Value::Array(items) if items.len() <= 10 => items,
        _ => {
            return Err(IamError::new(
                "INVALID_INPUT",
                "providers must list at most 10 external sign-ins",
            ));
        }
    };
    let links = items
        .iter()
        .map(|item| provider_link_input(Some(item)))
        .collect::<IamResult<Vec<_>>>()?;
    let distinct: IndexSet<&str> = links.iter().map(|link| link.provider_id.as_str()).collect();
    if distinct.len() != links.len() {
        return Err(IamError::new(
            "INVALID_INPUT",
            "providers must name each provider once",
        ));
    }
    Ok(links)
}

/// `providerLinkInput(value)`.
fn provider_link_input(value: Option<&Value>) -> IamResult<ProviderLinkInput> {
    let link = object(value)?;
    Ok(ProviderLinkInput {
        provider_id: text(link.get("providerId"), "providerId", 256)?,
        issuer: text(link.get("issuer"), "issuer", 1024)?,
        subject: text(link.get("subject"), "subject", 512)?,
    })
}

/// `providerLinkView(row)`: a linked external sign-in as administrators see it.
fn provider_link_view(row: &Record) -> Value {
    let mut out = Map::new();
    for key in ["id", "identityId", "providerId", "issuer", "subject"] {
        out.insert(
            key.into(),
            Value::String(crate::js::js_string(row.get(key))),
        );
    }
    if let Some(created) = row.get("createdAt").filter(|value| value.is_number()) {
        out.insert("createdAt".into(), created.clone());
    }
    Value::Object(out)
}

/// `insertProviderLink(tx, tenantId, identityId, link, now)`: records a link the federation callback (federation.ts)
/// finds by `[providerId, issuer, subject]`. An external account signs in to one identity only, and an identity has
/// at most one link per provider (unlink before relinking).
async fn insert_provider_link(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    link: &ProviderLinkInput,
    now: f64,
) -> IamResult<Value> {
    let unique_key = core_js::stringify(&json!([link.provider_id, link.issuer, link.subject]));
    if !find(
        tx,
        "externalIdentities",
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("uniqueKey", unique_key.clone()),
    )
    .await?
    .is_empty()
    {
        return Err(IamError::with_status(
            "ACCOUNT_LINK_CONFLICT",
            "External identity is already linked to another account",
            409,
        ));
    }
    if find(
        tx,
        "externalIdentities",
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("identityId", identity_id),
    )
    .await?
    .iter()
    .any(|row| str_of(row, "providerId") == Some(link.provider_id.as_str()))
    {
        return Err(IamError::with_status(
            "ACCOUNT_LINK_CONFLICT",
            "This account is already linked through that provider; unlink it first",
            409,
        ));
    }
    let mut record = Map::new();
    record.insert("id".into(), Value::String(id()));
    record.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    record.insert("uniqueKey".into(), Value::String(unique_key));
    record.insert("identityId".into(), Value::String(identity_id.to_owned()));
    record.insert("providerId".into(), Value::String(link.provider_id.clone()));
    record.insert("issuer".into(), Value::String(link.issuer.clone()));
    record.insert("subject".into(), Value::String(link.subject.clone()));
    record.insert("createdAt".into(), crate::js::number(now));
    Ok(provider_link_view(
        &tx.insert("externalIdentities", &record).await?,
    ))
}

/// Deletes an identity: every credential, factor, binding, membership, boundary, and link is removed or revoked in
/// the same transaction, and a tombstone without email or secrets remains so audit records keep a resolvable
/// principal. Refusals of `assertOwnerControl` stay `OperationDenied` (an operation audits them as denials).
pub async fn delete_identity(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    identity: &Identity,
) -> OperationResult<Value> {
    if identity.status == IdentityStatus::Deleted {
        return Err(IamError::with_status("CONFLICT", "Identity is already deleted", 409).into());
    }
    if identity.id == principal.identity.id {
        return Err(IamError::new("INVALID_INPUT", "An identity cannot delete itself").into());
    }
    if identity.root_admin && !boxed(|| ctx.root_principal(tx, principal)).await? {
        return Err(
            IamError::with_status("ACCESS_DENIED", "Root capability is protected", 403).into(),
        );
    }
    boxed(|| {
        assert_owner_control(
            ctx,
            tx,
            principal,
            identity,
            "Only an owner can delete an owner",
        )
    })
    .await?;
    boxed(|| ctx.protect_last_owner(tx, identity)).await?;
    // A legal hold (privacy.ts) keeps the person: no deletion path removes what litigation needs kept.
    boxed(|| crate::privacy::assert_no_legal_hold(tx, identity, ctx.now())).await?;
    boxed(|| ctx.revoke_all(tx, &identity.id)).await?;
    boxed(|| revoke_invitations_by(tx, &identity.id)).await?;
    let tenant_id = identity.tenant_id.as_str();
    let mine = || {
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("identityId", identity.id.clone())
    };
    async fn remove(tx: &Store, collection: &str, filter: Filter) -> IamResult<()> {
        for row in boxed(|| find(tx, collection, filter)).await? {
            boxed(|| async { tx.delete(collection, &record_id(&row)).await }).await?;
        }
        Ok(())
    }
    boxed(|| {
        remove(
            tx,
            "bindings",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("subjectType", "identity")
                .eq("subjectId", identity.id.clone()),
        )
    })
    .await?;
    boxed(|| remove(tx, "groupMembers", mine())).await?;
    boxed(|| remove(tx, "bindingActivations", mine())).await?;
    boxed(|| remove(tx, "packageAssignments", mine())).await?;
    boxed(|| remove(tx, "packageRequests", mine())).await?;
    // A tombstone is nobody's manager.
    for mut report in boxed(|| {
        find(
            tx,
            "identities",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("managerId", identity.id.clone()),
        )
    })
    .await?
    {
        report.shift_remove("managerId");
        boxed(|| tx.put("identities", &report)).await?;
    }
    boxed(|| remove(tx, "principalBoundaries", mine())).await?;
    boxed(|| remove(tx, "authPasskeys", mine())).await?;
    boxed(|| remove(tx, "passwordHistory", mine())).await?;
    boxed(|| remove(tx, "externalIdentities", mine())).await?;
    // Onboarding progress carries the person's form answers.
    boxed(|| {
        remove(
            tx,
            "onboardingProgress",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("subjectId", identity.id.clone()),
        )
    })
    .await?;
    // Threat detection (threats.ts): the sign-in baseline (networks, user agents) and the risk record go with the
    // person; detections and incidents stay as the investigation record.
    boxed(|| remove(tx, "threatBaselines", mine())).await?;
    boxed(|| remove(tx, "identityRisk", mine())).await?;
    // Device posture (devices.ts): self-enrolled devices retire with their keys, managed ones lose their owner.
    boxed(|| crate::devices::release_devices_of(tx, identity, ctx.now())).await?;
    // Teams and departments (teams.ts, departments.ts): memberships end, departments they head lose their head.
    boxed(|| crate::teams::remove_from_all_teams(tx, tenant_id, &identity.id, ctx.now())).await?;
    boxed(|| crate::departments::release_departments(tx, tenant_id, &identity.id, ctx.now(), None))
        .await?;
    boxed(|| {
        remove(
            tx,
            "relationships",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("subjectType", "identity")
                .eq("subjectId", identity.id.clone()),
        )
    })
    .await?;
    let identity_value = Value::Object(encode(identity));
    // Delegations the person gave AI agents (or an agent held) end with the identity (delegations.ts).
    boxed(|| {
        crate::delegations::revoke_delegations_of(ctx, tx, &identity_value, &principal.identity.id)
    })
    .await?;
    // Current consent decisions and restrictions go; their history stays as proof (privacy.ts).
    boxed(|| crate::privacy::release_privacy_records(tx, identity)).await?;
    // App assignments and launch history go; apps they owned lose them as an owner (applications.ts).
    boxed(|| crate::applications::release_app_records_of(tx, identity)).await?;
    // Direct license assignments go and seats are released; waiting people move up (licenses.ts).
    boxed(|| async {
        crate::licenses::release_licenses_of(
            ctx,
            tx,
            identity,
            &crate::conformance::principal_json(principal),
        )
        .await
    })
    .await?;
    // A deleted guest's account row goes; guests the person sponsored are flagged for a new sponsor (guests.ts).
    boxed(|| crate::guests::release_guest_records(ctx, tx, principal, &identity_value)).await?;
    // A clearance ends as terminated history, its read-ins released (clearances.ts; only with the `clearances` option).
    if ctx.options.clearances.is_some() {
        boxed(|| {
            crate::clearances::release_clearances_of(
                tx,
                identity,
                Some(ctx.now()),
                Some(&principal.identity.id),
            )
        })
        .await?;
    }
    if boxed(|| tx.get("authMfa", &identity.id)).await?.is_some() {
        boxed(|| tx.delete("authMfa", &identity.id)).await?;
    }
    for mut authority in boxed(|| find(tx, "grantAuthorities", mine())).await? {
        if !truthy(&authority, "revoked") {
            authority.insert("revoked".into(), Value::Bool(true));
            boxed(|| tx.put("grantAuthorities", &authority)).await?;
        }
    }
    let mut links = boxed(|| {
        find(
            tx,
            "identityLinks",
            Filter::new().eq("leftId", identity.id.clone()),
        )
    })
    .await?;
    links.extend(
        boxed(|| {
            find(
                tx,
                "identityLinks",
                Filter::new().eq("rightId", identity.id.clone()),
            )
        })
        .await?,
    );
    for mut link in links {
        if !truthy(&link, "revoked") {
            link.insert("revoked".into(), Value::Bool(true));
            boxed(|| tx.put("identityLinks", &link)).await?;
        }
    }
    for mut request in boxed(|| {
        find(
            tx,
            "accessRequests",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("requesterId", identity.id.clone())
                .eq("status", "pending"),
        )
    })
    .await?
    {
        request.insert("status".into(), Value::String("cancelled".into()));
        request.insert("reviewedAt".into(), crate::js::number(ctx.now()));
        boxed(|| tx.put("accessRequests", &request)).await?;
    }
    let mut tombstone = encode(identity);
    tombstone.shift_remove("passwordHash");
    let deleted_email = tombstone.shift_remove("email");
    tombstone.shift_remove("phone");
    tombstone.shift_remove("managerId");
    tombstone.insert(
        "uniqueKey".into(),
        Value::String(format!("deleted:{}", identity.id)),
    );
    tombstone.insert("status".into(), Value::String("deleted".into()));
    tombstone.insert("owner".into(), Value::Bool(false));
    tombstone.insert("rootAdmin".into(), Value::Bool(false));
    tombstone.insert("emailVerified".into(), Value::Bool(false));
    tombstone.insert("deletedAt".into(), crate::js::number(ctx.now()));
    if let Some(deleted_email) = deleted_email {
        tombstone.insert("deletedEmail".into(), deleted_email);
    }
    Ok(Value::Object(public_identity_record(
        &boxed(|| tx.put("identities", &tombstone)).await?,
    )))
}

/// Whoever controls an account's sign-in address or triggers its password reset controls the account, so
/// iam:identities:update alone must not reach an owner or a root administrator (that would be a takeover, and it
/// would bypass the ban on impersonating them). An owner's needs another owner of the same tenant or a root
/// principal; a root administrator's needs a root principal. The refusal is audited as a denial.
async fn assert_account_control(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    identity: &Identity,
) -> OperationResult<()> {
    if !identity.owner && !identity.root_admin {
        return Ok(());
    }
    if ctx.root_principal(tx, principal).await? {
        return Ok(());
    }
    if !identity.root_admin
        && principal.identity.owner
        && principal.identity.tenant_id == identity.tenant_id
    {
        return Ok(());
    }
    Err(OperationDenied::new(Some(if identity.root_admin {
        "Only a root administrator can change a root administrator\u{2019}s sign-in address or password"
    } else {
        "Only an owner can change an owner\u{2019}s sign-in address or password"
    })))
}

/// The caller is an owner of this tenant in person: the tenant's own owner account on an ordinary session. An assumed
/// role never counts, even when its source account owns another tenant, because a role session carries only the
/// role's grants.
fn owns_tenant(principal: &AuthenticatedPrincipal, tenant_id: &str) -> bool {
    principal.session.kind == SessionKind::User
        && principal.identity.owner
        && principal.identity.tenant_id == tenant_id
        && principal.session.tenant_id == tenant_id
}

/// Deleting, disabling, or scheduling the deactivation of an owner removes an owner as surely as `setOwner(false)`
/// or `offboard` does, so it needs the same caller: an owner of the tenant in person or a root principal, never
/// iam:identities:update or iam:identities:delete alone. The refusal is audited as a denial (`OperationDenied`).
pub async fn assert_owner_control(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    identity: &Identity,
    message: &str,
) -> OperationResult<()> {
    if !identity.owner {
        return Ok(());
    }
    if owns_tenant(principal, &identity.tenant_id) || ctx.root_principal(tx, principal).await? {
        return Ok(());
    }
    Err(OperationDenied::new(Some(message)))
}

/// Attributes and a manager feed birthright package rules and policy conditions, so choosing them when creating an
/// identity is an update: it needs iam:identities:update on the tenant besides iam:identities:create.
async fn assert_may_set_profile(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
) -> OperationResult<()> {
    if !allowed(
        ctx,
        tx,
        principal,
        tenant_id,
        "iam:identities:update",
        tenant_id,
    )
    .await?
    {
        return Err(OperationDenied::new(Some(
            "Setting attributes or a manager requires iam:identities:update",
        )));
    }
    Ok(())
}

/// Attribute maps compared by content, whatever order their keys were written in (`sameAttributes`).
fn same_attributes(a: Option<&Value>, b: Option<&Value>) -> bool {
    let canonical = |value: Option<&Value>| {
        let empty = Map::new();
        let map = match value {
            Some(Value::Object(map)) => map,
            _ => &empty,
        };
        let mut keys: Vec<&String> = map.keys().collect();
        keys.sort_by(|a, b| core_js::cmp_utf16(a, b));
        core_js::stringify(&Value::Array(
            keys.into_iter()
                .map(|key| json!([key, map[key.as_str()]]))
                .collect(),
        ))
    };
    canonical(a) == canonical(b)
}

/// `a !== b` for optional members (`undefined` when absent).
fn differs(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => false,
        (Some(a), Some(b)) => !core_js::strict_equal(a, b),
        _ => true,
    }
}

/// The member invitations an identity sent and nobody redeemed yet are revoked when it is disabled or leaves
/// (redemption refuses an inactive inviter anyway; this keeps `listInvitations` truthful and the tokens dead if it
/// comes back).
pub async fn revoke_invitations_by(tx: &Store, identity_id: &str) -> IamResult<()> {
    for mut invitation in find(
        tx,
        "memberInvitations",
        Filter::new().eq("inviterId", identity_id),
    )
    .await?
    {
        if !truthy(&invitation, "consumed") && !truthy(&invitation, "revoked") {
            invitation.insert("revoked".into(), Value::Bool(true));
            tx.put("memberInvitations", &invitation).await?;
        }
    }
    // Guest invitations they sent or sponsor, likewise (guests.ts).
    crate::guests::revoke_guest_invitations_by(tx, identity_id).await
}

/// `managerFor(ctx, tx, identity, managerId)`: a manager is another active identity of the tenant, never the person
/// or one of their own reports (no cycles).
async fn manager_for(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    identity_id: &str,
    tenant_id: &str,
    manager_id: Option<&Value>,
) -> IamResult<String> {
    let manager_id = text(manager_id, "managerId", 256)?;
    let manager = active_identity(ctx, tx, Some(&Value::String(manager_id)), tenant_id).await?;
    if manager.identity.id == identity_id {
        return Err(IamError::new(
            "INVALID_INPUT",
            "An identity cannot be its own manager",
        ));
    }
    if manager.identity.status != IdentityStatus::Active {
        return Err(IamError::new(
            "INVALID_INPUT",
            "A manager must be an active identity",
        ));
    }
    let mut cursor: Option<Record> = Some(manager.raw.clone());
    let mut depth = 0;
    while let Some(current) = &cursor {
        let Some(next) = str_of(current, "managerId").filter(|next| !next.is_empty()) else {
            break;
        };
        if depth >= 100 {
            break;
        }
        if next == identity_id {
            return Err(IamError::new(
                "INVALID_INPUT",
                "That would make the reporting line circular",
            ));
        }
        let next = next.to_owned();
        cursor = tx.get("identities", &next).await?;
        depth += 1;
    }
    Ok(manager.identity.id)
}

/// `roleIds ?? []` read as a string list.
fn optional_strings(value: Option<&Value>, name: &str) -> IamResult<Vec<String>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        value => strings(value, name),
    }
}

/// The member invitation email of `invite` and `resendInvitation`: the token sealed for the outbox.
async fn queue_invitation_email(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    realm: &better_iam_core::Tenant,
    to: &Value,
    invite_token: &str,
    inviter_name: &str,
    now: f64,
) -> IamResult<()> {
    let outbox_id = id();
    let sealed = encrypt_secret(
        &core_js::stringify(&json!({
            "token": invite_token,
            "tenantId": realm.id,
            "tenantName": realm.name,
            "inviterName": inviter_name,
        })),
        &ctx.options.secret,
        &format!("outbox:{outbox_id}"),
    );
    let mut message = Map::new();
    message.insert("id".into(), Value::String(outbox_id));
    message.insert("tenantId".into(), Value::String(realm.id.clone()));
    message.insert("kind".into(), Value::String("email".into()));
    message.insert("to".into(), to.clone());
    message.insert("template".into(), Value::String("member-invitation".into()));
    message.insert("payload".into(), json!({ "sealed": sealed }));
    message.insert("createdAt".into(), crate::js::number(now));
    message.insert("attempts".into(), json!(0));
    tx.insert("outbox", &message).await?;
    Ok(())
}

/// Roles and groups granted at once (`createMany`, `invite`): each role under the caller's grant authority with
/// iam:bindings:create on it, each group with iam:groups:update and the authorities of its bindings.
async fn assert_may_grant(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    role_ids: &[String],
    group_ids: &[String],
) -> IamResult<()> {
    for role_id in role_ids {
        let role = ctx
            .scoped(
                tx,
                "roles",
                Some(&Value::String(role_id.clone())),
                tenant_id,
            )
            .await?;
        if truthy(&role, "protected") {
            return Err(IamError::with_status(
                "PROTECTED_RESOURCE",
                "Use owner transfer for protected roles",
                403,
            ));
        }
        if !allowed(
            ctx,
            tx,
            principal,
            tenant_id,
            "iam:bindings:create",
            &record_id(&role),
        )
        .await?
        {
            return Err(IamError::with_status(
                "ACCESS_DENIED",
                "Cannot grant this role",
                403,
            ));
        }
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
        crate::teams::assert_not_team_group(Some(&Value::Object(group)))?;
        if !allowed(ctx, tx, principal, tenant_id, "iam:groups:update", group_id).await? {
            return Err(IamError::with_status(
                "ACCESS_DENIED",
                "Cannot add members to this group",
                403,
            ));
        }
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
            ctx.granting_authority(tx, principal, tenant_id, str_of(&binding, "authorityId"))
                .await?;
        }
    }
    Ok(())
}

/// One person of `createMany`, validated.
struct BulkItem<'a> {
    email: String,
    name: String,
    password: Option<&'a Value>,
    attributes: Map<String, Value>,
    role_ids: Vec<String>,
    group_ids: Vec<String>,
    expires_at: Option<f64>,
    email_verified: bool,
    providers: Vec<ProviderLinkInput>,
}

/// The `identities` API group (`createIdentitiesApi(ctx)`): one method per route `identities/{method}`.
pub struct IdentitiesApi {
    ctx: Arc<ServerContext>,
}

/// `createIdentitiesApi(ctx)`.
pub fn create_identities_api(ctx: &Arc<ServerContext>) -> IamResult<IdentitiesApi> {
    Ok(IdentitiesApi { ctx: ctx.clone() })
}

impl IdentitiesApi {
    /// `operation(credential, input.tenantId, action, resourceId, mutation)`.
    async fn run(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        action: &str,
        resource_id: &str,
        mutation: Mutation<'_>,
    ) -> IamResult<Value> {
        self.ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                action,
                resource_id,
                mutation,
                false,
            )
            .await
    }

    /// `.then((result) => afterIdentityChange(ctx, input.tenantId, identityIds, result))`.
    async fn after_change(
        &self,
        input: &Map<String, Value>,
        identity_ids: Vec<String>,
        result: Value,
    ) -> IamResult<Value> {
        crate::api::package_automation::after_identity_change(
            &self.ctx,
            &string_member(input, "tenantId"),
            &identity_ids,
            &result,
        )
        .await
    }

    /// `identities/acceptInvitation` (public: no credential).
    pub async fn accept_invitation(
        &self,
        input: Body<identities::AcceptInvitationInput>,
    ) -> IamResult<Reply<identities::AcceptInvitationOutput>> {
        Ok(Reply::json(
            self.ctx.flows()?.accept_member_invitation(&input).await?,
        ))
    }

    /// `identities/create`: `expiresAt` schedules deactivation (contractors). A `managerId` also needs
    /// iam:identities:update on the tenant. `emailVerified` records an address another system already verified (a
    /// migration); `providers` links external sign-ins ahead of the first one.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<identities::CreateInput>,
    ) -> IamResult<Reply<identities::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let expires_at = match body.get("expiresAt") {
                    Some(value) => Some(ctx.binding_expiry(Some(value))?),
                    None => None,
                };
                if body.contains_key("managerId") {
                    assert_may_set_profile(ctx, &tx, &principal, tenant).await?;
                }
                let email_verified = flag(body.get("emailVerified"), "emailVerified")?;
                let providers = provider_links(body.get("providers"))?;
                let address = Value::String(email(body.get("email"))?);
                let name = Value::String(text(body.get("name"), "name", 256)?);
                let identity = ctx
                    .auth
                    .create_identity_raw(
                        &tx,
                        CreateIdentityRaw {
                            tenant_id: body.get("tenantId"),
                            email: Some(&address),
                            name: Some(&name),
                            password: body.get("password"),
                            owner: false,
                            root_admin: false,
                            email_verified,
                        },
                    )
                    .await?;
                for link in &providers {
                    insert_provider_link(&tx, tenant, &identity.id, link, ctx.now()).await?;
                }
                let manager_id = if body.contains_key("managerId") {
                    Some(manager_for(ctx, &tx, &identity.id, tenant, body.get("managerId")).await?)
                } else {
                    None
                };
                if expires_at.is_none() && manager_id.is_none() {
                    return Ok(Value::Object(public_identity(&identity)));
                }
                let mut next = encode(&identity);
                if let Some(expires_at) = expires_at {
                    next.insert("expiresAt".into(), crate::js::number(expires_at));
                }
                if let Some(manager_id) = manager_id {
                    next.insert("managerId".into(), Value::String(manager_id));
                }
                Ok(Value::Object(public_identity_record(
                    &tx.put("identities", &next).await?,
                )))
            })
        });
        let created = self
            .run(
                credential,
                &input,
                "iam:identities:create",
                &tenant_id,
                mutation,
            )
            .await?;
        let created_id = crate::js::js_string(created.get("id"));
        Ok(Reply::json(
            self.after_change(&input, vec![created_id], created).await?,
        ))
    }

    /// `identities/createMany`: up to 100 identities atomically with optional attributes, roles, and groups (bulk
    /// onboarding). One failure rejects the whole batch.
    pub async fn create_many(
        &self,
        credential: &CredentialInput,
        input: Body<identities::CreateManyInput>,
    ) -> IamResult<Reply<identities::CreateManyOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: realm,
             }| {
                Box::pin(async move {
                    let entries = match body.get("identities") {
                        Some(Value::Array(entries))
                            if !entries.is_empty() && entries.len() <= 100 =>
                        {
                            entries
                        }
                        _ => {
                            return Err(
                                IamError::new("INVALID_INPUT", "Provide 1-100 identities").into()
                            );
                        }
                    };
                    if realm.status != TenantStatus::Active {
                        return Err(
                            IamError::new("TENANT_INACTIVE", "Tenant must be active").into()
                        );
                    }
                    let mut items: Vec<BulkItem<'_>> = Vec::new();
                    for entry in entries {
                        let value = object(Some(entry))?;
                        items.push(BulkItem {
                            email: email(value.get("email"))?,
                            name: text(value.get("name"), "name", 256)?,
                            password: value.get("password"),
                            attributes: attribute_values(
                                &ctx.catalog.identity_attributes,
                                value.get("attributes"),
                            )?,
                            role_ids: crate::js::unique(optional_strings(
                                value.get("roleIds"),
                                "roleIds",
                            )?),
                            group_ids: crate::js::unique(optional_strings(
                                value.get("groupIds"),
                                "groupIds",
                            )?),
                            expires_at: match value.get("expiresAt") {
                                Some(expires) => Some(ctx.binding_expiry(Some(expires))?),
                                None => None,
                            },
                            email_verified: flag(value.get("emailVerified"), "emailVerified")?,
                            providers: provider_links(value.get("providers"))?,
                        });
                    }
                    if items.iter().any(|item| !item.attributes.is_empty()) {
                        assert_may_set_profile(ctx, &tx, &principal, &realm.id).await?;
                    }
                    let role_ids: Vec<String> = items
                        .iter()
                        .flat_map(|item| item.role_ids.iter().cloned())
                        .collect::<IndexSet<String>>()
                        .into_iter()
                        .collect();
                    let group_ids: Vec<String> = items
                        .iter()
                        .flat_map(|item| item.group_ids.iter().cloned())
                        .collect::<IndexSet<String>>()
                        .into_iter()
                        .collect();
                    let authority = if role_ids.is_empty() {
                        None
                    } else {
                        Some(
                            ctx.granting_authority(&tx, &principal, &realm.id, None)
                                .await?,
                        )
                    };
                    assert_may_grant(ctx, &tx, &principal, &realm.id, &role_ids, &group_ids)
                        .await?;
                    // New members of a licensed group claim its seats: that needs iam:licenses:assign (groups.ts).
                    crate::api::groups::assert_may_claim_licenses(
                        ctx,
                        &tx,
                        &principal,
                        &realm.id,
                        &json!(group_ids),
                        Some(SEATS_MESSAGE),
                    )
                    .await?;
                    let mut created: Vec<Value> = Vec::new();
                    for item in &items {
                        let address = Value::String(item.email.clone());
                        let name = Value::String(item.name.clone());
                        let realm_id = Value::String(realm.id.clone());
                        let identity = ctx
                            .auth
                            .create_identity_raw(
                                &tx,
                                CreateIdentityRaw {
                                    tenant_id: Some(&realm_id),
                                    email: Some(&address),
                                    name: Some(&name),
                                    password: item.password,
                                    owner: false,
                                    root_admin: false,
                                    email_verified: item.email_verified,
                                },
                            )
                            .await?;
                        for link in &item.providers {
                            insert_provider_link(&tx, &realm.id, &identity.id, link, ctx.now())
                                .await?;
                        }
                        let mut record = encode(&identity);
                        if !item.attributes.is_empty() || item.expires_at.is_some() {
                            if !item.attributes.is_empty() {
                                record.insert(
                                    "attributes".into(),
                                    Value::Object(item.attributes.clone()),
                                );
                            }
                            if let Some(expires_at) = item.expires_at {
                                record.insert("expiresAt".into(), crate::js::number(expires_at));
                            }
                            record = tx.put("identities", &record).await?;
                        }
                        for role_id in &item.role_ids {
                            let authority_id = authority
                                .as_ref()
                                .map(|authority| authority.id.clone())
                                .unwrap_or_default();
                            let mut binding = Map::new();
                            binding.insert("id".into(), Value::String(id()));
                            binding.insert("tenantId".into(), Value::String(realm.id.clone()));
                            binding.insert(
                                "uniqueKey".into(),
                                Value::String(format!(
                                    "identity:{}:{role_id}:{authority_id}",
                                    identity.id
                                )),
                            );
                            binding.insert("subjectType".into(), Value::String("identity".into()));
                            binding.insert("subjectId".into(), Value::String(identity.id.clone()));
                            binding.insert("roleId".into(), Value::String(role_id.clone()));
                            binding.insert("authorityId".into(), Value::String(authority_id));
                            tx.insert("bindings", &binding).await?;
                        }
                        for group_id in &item.group_ids {
                            let mut member = Map::new();
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
                        created.push(Value::Object(public_identity_record(&record)));
                    }
                    Ok(json!({ "identities": created }))
                })
            },
        );
        let result = self
            .run(
                credential,
                &input,
                "iam:identities:create",
                &tenant_id,
                mutation,
            )
            .await?;
        let ids = result
            .get("identities")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| crate::js::js_string(item.get("id")))
                    .collect()
            })
            .unwrap_or_default();
        Ok(Reply::json(self.after_change(&input, ids, result).await?))
    }

    /// `identities/delete`: removes a person or service account. Requires recent authentication and
    /// iam:identities:delete; the last owner and last root administrator are protected.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<identities::DeleteInput>,
    ) -> IamResult<Reply<identities::DeleteOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let loaded = scoped_identity(ctx, &tx, body.get("identityId"), tenant).await?;
                let result = delete_identity(ctx, &tx, &principal, &loaded.identity).await?;
                let mut metadata = Map::new();
                metadata.insert(
                    "kind".into(),
                    loaded.raw.get("kind").cloned().unwrap_or(Value::Null),
                );
                if truthy(&loaded.raw, "email") {
                    metadata.insert("email".into(), loaded.raw["email"].clone());
                }
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "identity:delete",
                        tenant,
                        &loaded.identity.id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(result)
            })
        });
        let resource_id = string_member(&input, "identityId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:delete",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/export`: data-subject export, everything this tenant stores about one identity, as JSON. Audit
    /// events the identity performed are included only when the caller also holds iam:audit:read (newest first, at
    /// most 5000). Secrets, hashes, and tokens are never included.
    pub async fn export(
        &self,
        credential: &CredentialInput,
        input: Body<identities::ExportInput>,
    ) -> IamResult<Reply<identities::ExportOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let loaded = scoped_identity(ctx, &tx, body.get("identityId"), tenant).await?;
                let identity_id = loaded.identity.id.clone();
                let mine = || {
                    Filter::new()
                        .eq("tenantId", tenant.as_str())
                        .eq("identityId", identity_id.clone())
                };
                let mut groups: Vec<Value> = Vec::new();
                for membership in find(&tx, "groupMembers", mine()).await? {
                    let group_id = crate::js::js_string(membership.get("groupId"));
                    if let Some(group) = tx.get("groups", &group_id).await?
                        && str_of(&group, "tenantId") == Some(tenant.as_str())
                    {
                        groups.push(Value::Object(group));
                    }
                }
                let mut link_rows = find(
                    &tx,
                    "identityLinks",
                    Filter::new().eq("leftId", identity_id.clone()),
                )
                .await?;
                link_rows.extend(
                    find(
                        &tx,
                        "identityLinks",
                        Filter::new().eq("rightId", identity_id.clone()),
                    )
                    .await?,
                );
                let links: Vec<Value> = link_rows
                    .iter()
                    .map(|link| {
                        let mut out = Map::new();
                        if let Some(id) = link.get("id") {
                            out.insert("id".into(), id.clone());
                        }
                        let linked = if str_of(link, "leftId") == Some(identity_id.as_str()) {
                            link.get("rightId")
                        } else {
                            link.get("leftId")
                        };
                        if let Some(linked) = linked {
                            out.insert("linkedIdentityId".into(), linked.clone());
                        }
                        if let Some(revoked) = link.get("revoked") {
                            out.insert("revoked".into(), revoked.clone());
                        }
                        Value::Object(out)
                    })
                    .collect();
                let audit_allowed =
                    allowed(ctx, &tx, &principal, tenant, "iam:audit:read", tenant).await?;
                let audit = if audit_allowed {
                    let mut events = find(
                        &tx,
                        "audit",
                        Filter::new()
                            .eq("tenantId", tenant.as_str())
                            .eq("actorId", identity_id.clone()),
                    )
                    .await?;
                    events.sort_by(|a, b| newest_by("timestamp", a, b));
                    events.truncate(5000);
                    Some(Value::Array(
                        events.into_iter().map(Value::Object).collect(),
                    ))
                } else {
                    None
                };
                let mut metadata = Map::new();
                metadata.insert(
                    "kind".into(),
                    loaded.raw.get("kind").cloned().unwrap_or(Value::Null),
                );
                metadata.insert("auditIncluded".into(), Value::Bool(audit_allowed));
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "identity:export",
                        tenant,
                        &identity_id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                /// The listed members of a record, leaving out those it does not have (`undefined`).
                fn pick(record: &Record, keys: &[&str]) -> Value {
                    let mut out = Map::new();
                    for key in keys {
                        if let Some(value) = record.get(*key) {
                            out.insert((*key).into(), value.clone());
                        }
                    }
                    Value::Object(out)
                }
                let rows =
                    |rows: Vec<Record>| Value::Array(rows.into_iter().map(Value::Object).collect());
                let mut out = Map::new();
                out.insert("exportedAt".into(), crate::js::number(ctx.now()));
                out.insert("tenantId".into(), Value::String(tenant.clone()));
                out.insert(
                    "identity".into(),
                    Value::Object(public_identity_record(&loaded.raw)),
                );
                out.insert(
                    "sessions".into(),
                    Value::Array(
                        find(&tx, "sessions", mine())
                            .await?
                            .into_iter()
                            .map(without_secrets)
                            .collect(),
                    ),
                );
                let mfa = tx.get("authMfa", &identity_id).await?;
                out.insert(
                    "mfa".into(),
                    json!({
                        "enabled": mfa.as_ref().is_some_and(|mfa| truthy(mfa, "enabled")),
                    }),
                );
                out.insert(
                    "passkeys".into(),
                    Value::Array(
                        find(&tx, "authPasskeys", mine())
                            .await?
                            .iter()
                            .map(|key| pick(key, &["id", "credentialId", "transports"]))
                            .collect(),
                    ),
                );
                out.insert(
                    "externalIdentities".into(),
                    Value::Array(
                        find(&tx, "externalIdentities", mine())
                            .await?
                            .iter()
                            .map(|mapping| pick(mapping, &["providerId", "issuer", "subject"]))
                            .collect(),
                    ),
                );
                out.insert(
                    "bindings".into(),
                    Value::Array(
                        ctx.decisions()?
                            .effective_bindings(&tx, tenant, &identity_id)
                            .await?
                            .iter()
                            .map(|binding| binding.to_json())
                            .collect(),
                    ),
                );
                out.insert("groups".into(), Value::Array(groups));
                out.insert(
                    "relationships".into(),
                    rows(
                        find(
                            &tx,
                            "relationships",
                            Filter::new()
                                .eq("tenantId", tenant.as_str())
                                .eq("subjectType", "identity")
                                .eq("subjectId", identity_id.clone()),
                        )
                        .await?,
                    ),
                );
                out.insert(
                    "accessRequests".into(),
                    rows(
                        find(
                            &tx,
                            "accessRequests",
                            Filter::new()
                                .eq("tenantId", tenant.as_str())
                                .eq("requesterId", identity_id.clone()),
                        )
                        .await?,
                    ),
                );
                out.insert(
                    "boundaries".into(),
                    Value::Array(
                        find(&tx, "principalBoundaries", mine())
                            .await?
                            .iter()
                            // `[undefined]` serializes as `[null]`.
                            .map(|boundary| {
                                boundary.get("document").cloned().unwrap_or(Value::Null)
                            })
                            .collect(),
                    ),
                );
                out.insert(
                    "grantAuthorities".into(),
                    Value::Array(
                        find(&tx, "grantAuthorities", mine())
                            .await?
                            .iter()
                            .map(|authority| {
                                pick(authority, &["id", "revoked", "parentAuthorityId"])
                            })
                            .collect(),
                    ),
                );
                out.insert("links".into(), Value::Array(links));
                out.insert(
                    "scim".into(),
                    Value::Array(
                        find(&tx, "scimUsers", mine())
                            .await?
                            .iter()
                            .map(|row| {
                                pick(row, &["connectionId", "externalId", "userName", "active"])
                            })
                            .collect(),
                    ),
                );
                out.insert("auditIncluded".into(), Value::Bool(audit_allowed));
                if let Some(audit) = audit {
                    out.insert("audit".into(), audit);
                }
                Ok(Value::Object(out))
            })
        });
        let resource_id = string_member(&input, "identityId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:read",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/get`.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<identities::GetInput>,
    ) -> IamResult<Reply<identities::GetOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let identity = ctx
                    .scoped(&tx, "identities", body.get("identityId"), tenant)
                    .await?;
                Ok(Value::Object(public_identity_record(&identity)))
            })
        });
        let resource_id = string_member(&input, "identityId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:read",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/impersonate`: opens a session as a member ("view as") for support and troubleshooting. The token
    /// is returned in the body only, never as a cookie.
    pub async fn impersonate(
        &self,
        credential: &CredentialInput,
        input: Body<identities::ImpersonateInput>,
    ) -> IamResult<Reply<identities::ImpersonateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let reason = text(body.get("reason"), "reason", 512)?;
                let duration = match body.get("durationMs") {
                    None | Some(Value::Null) => json!(3_600_000),
                    Some(value) => value.clone(),
                };
                let duration_ms =
                    integer(Some(&duration), "durationMs", 60_000.0, 8.0 * 3_600_000.0)?;
                let loaded = active_identity(ctx, &tx, body.get("identityId"), tenant).await?;
                let identity = &loaded.identity;
                if identity.id == principal.identity.id {
                    return Err(
                        IamError::new("INVALID_INPUT", "You cannot impersonate yourself").into(),
                    );
                }
                if identity.kind != IdentityKind::User {
                    return Err(
                        IamError::new("INVALID_INPUT", "Only people can be impersonated").into(),
                    );
                }
                if identity.root_admin || identity.owner {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Owners and root administrators cannot be impersonated",
                        403,
                    )
                    .into());
                }
                let result = ctx
                    .auth
                    .issue_impersonation_session(&tx, &principal, identity, duration_ms)
                    .await?;
                let mut metadata = Map::new();
                metadata.insert("reason".into(), Value::String(reason));
                metadata.insert("sessionId".into(), Value::String(result.session.id.clone()));
                metadata.insert(
                    "expiresAt".into(),
                    crate::js::number(result.session.expires_at),
                );
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "identity:impersonate",
                        tenant,
                        &identity.id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                let session = serde_json::to_value(&result.session)
                    .map_err(|_| crate::js::internal_error())?;
                Ok(json!({
                    "token": result.token,
                    "session": session,
                    "identity": Value::Object(public_identity_record(&loaded.raw)),
                }))
            })
        });
        let resource_id = string_member(&input, "identityId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:impersonate",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/invite`: invites a person into an existing tenant. Roles and groups are applied when the
    /// invitation is accepted, under the inviter's authority; groups a license product is assigned to need
    /// iam:licenses:assign, now and at acceptance.
    pub async fn invite(
        &self,
        credential: &CredentialInput,
        input: Body<identities::InviteInput>,
    ) -> IamResult<Reply<identities::InviteOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: realm,
             }| {
                Box::pin(async move {
                    if !has_email_delivery(ctx) {
                        return Err(IamError::new(
                            "DELIVERY_REQUIRED",
                            "Member invitations require an email delivery callback",
                        )
                        .into());
                    }
                    if realm.status != TenantStatus::Active {
                        return Err(
                            IamError::new("TENANT_INACTIVE", "Tenant must be active").into()
                        );
                    }
                    let to = email(body.get("email"))?;
                    if !find(
                        &tx,
                        "identities",
                        Filter::new()
                            .eq("tenantId", realm.id.clone())
                            .eq("email", to.clone()),
                    )
                    .await?
                    .is_empty()
                    {
                        return Err(IamError::with_status(
                            "IDENTITY_EXISTS",
                            "An identity with this email already exists in this tenant",
                            409,
                        )
                        .into());
                    }
                    let role_ids = optional_strings(body.get("roleIds"), "roleIds")?;
                    let group_ids = optional_strings(body.get("groupIds"), "groupIds")?;
                    let authority_id = if !role_ids.is_empty() || !group_ids.is_empty() {
                        Some(
                            ctx.granting_authority(&tx, &principal, &realm.id, None)
                                .await?
                                .id,
                        )
                    } else {
                        None
                    };
                    assert_may_grant(ctx, &tx, &principal, &realm.id, &role_ids, &group_ids)
                        .await?;
                    // The invitee claims the seats of licensed groups: iam:licenses:assign, checked again at acceptance
                    // (flows.ts).
                    crate::api::groups::assert_may_claim_licenses(
                        ctx,
                        &tx,
                        &principal,
                        &realm.id,
                        &json!(group_ids),
                        Some(SEATS_MESSAGE),
                    )
                    .await?;
                    let invite_token = token();
                    let now = date_now();
                    let invitation_id = id();
                    let expires_at = now + ctx.config.invitation_lifetime_ms;
                    let mut invitation = Map::new();
                    invitation.insert("id".into(), Value::String(invitation_id.clone()));
                    invitation.insert("tenantId".into(), Value::String(realm.id.clone()));
                    invitation.insert("email".into(), Value::String(to.clone()));
                    invitation.insert("tokenHash".into(), Value::String(hash(&invite_token)));
                    invitation.insert("uniqueKey".into(), Value::String(hash(&invite_token)));
                    invitation.insert("roleIds".into(), json!(role_ids));
                    invitation.insert("groupIds".into(), json!(group_ids));
                    invitation.insert(
                        "inviterId".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    invitation.insert("createdAt".into(), crate::js::number(now));
                    invitation.insert("expiresAt".into(), crate::js::number(expires_at));
                    invitation.insert("consumed".into(), Value::Bool(false));
                    if let Some(name) = body.get("name") {
                        invitation
                            .insert("name".into(), Value::String(text(Some(name), "name", 256)?));
                    }
                    if let Some(authority_id) = authority_id {
                        invitation.insert("authorityId".into(), Value::String(authority_id));
                    }
                    tx.insert("memberInvitations", &invitation).await?;
                    queue_invitation_email(
                        ctx,
                        &tx,
                        &realm,
                        &Value::String(to.clone()),
                        &invite_token,
                        &principal.identity.name,
                        now,
                    )
                    .await?;
                    Ok(json!({
                        "invitationId": invitation_id,
                        "email": to,
                        "expiresAt": crate::js::number(expires_at),
                        "roleIds": role_ids,
                        "groupIds": group_ids,
                    }))
                })
            },
        );
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:create",
                &tenant_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/linkProvider`: links an external sign-in (OAuth/OIDC or SAML) to an existing account, so that IdP
    /// account signs in to it with no account-linking step. Audited as `identity:link-provider`.
    pub async fn link_provider(
        &self,
        credential: &CredentialInput,
        input: Body<identities::LinkProviderInput>,
    ) -> IamResult<Reply<identities::LinkProviderOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let link = provider_link_input(Some(&body.value()))?;
                let loaded = active_identity(ctx, &tx, body.get("identityId"), tenant).await?;
                let identity = &loaded.identity;
                if identity.kind != IdentityKind::User {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "Only people sign in through external providers",
                    )
                    .into());
                }
                assert_account_control(ctx, &tx, &principal, identity).await?;
                let created =
                    insert_provider_link(&tx, tenant, &identity.id, &link, ctx.now()).await?;
                let mut metadata = Map::new();
                metadata.insert("providerId".into(), Value::String(link.provider_id.clone()));
                metadata.insert(
                    "linkId".into(),
                    created.get("id").cloned().unwrap_or(Value::Null),
                );
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "identity:link-provider",
                        tenant,
                        &identity.id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(created)
            })
        });
        let resource_id = string_member(&input, "identityId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:update",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/list`: deleted identities are omitted unless includeDeleted is set; kind and status narrow the
    /// list, `query` matches the name or email case-insensitively, `expiresBefore` keeps identities scheduled to
    /// deactivate before that time, `limit`/`offset` page through the result ordered by name then ID.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<identities::ListInput>,
    ) -> IamResult<Reply<identities::ListOutput>> {
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let mut filter = Filter::new().eq("tenantId", tenant.as_str());
                if let Some(kind) = body.get("kind") {
                    let Some(kind) = kind
                        .as_str()
                        .filter(|kind| ["user", "service", "agent"].contains(kind))
                    else {
                        return Err(IamError::new("INVALID_INPUT", "Invalid identity kind").into());
                    };
                    filter = filter.eq("kind", kind);
                }
                if let Some(status) = body.get("status") {
                    let Some(status) = status
                        .as_str()
                        .filter(|status| ["active", "disabled", "deleted"].contains(status))
                    else {
                        return Err(
                            IamError::new("INVALID_INPUT", "Invalid identity status").into()
                        );
                    };
                    filter = filter.eq("status", status);
                }
                let query = match body.get("query") {
                    Some(query) => Some(core_js::to_lower(&text(Some(query), "query", 256)?)),
                    None => None,
                };
                let expires_before = match body.get("expiresBefore") {
                    Some(value) => Some(integer(
                        Some(value),
                        "expiresBefore",
                        0.0,
                        core_js::MAX_SAFE_INTEGER,
                    )?),
                    None => None,
                };
                let limit = match body.get("limit") {
                    Some(value) => Some(integer(Some(value), "limit", 1.0, 1000.0)?),
                    None => None,
                };
                let offset = match body.get("offset") {
                    None | Some(Value::Null) => 0.0,
                    value => integer(value, "offset", 0.0, 1_000_000.0)?,
                };
                let include_deleted = body.get("includeDeleted") == Some(&Value::Bool(true))
                    || body.get("status").and_then(Value::as_str) == Some("deleted");
                let mut matches: Vec<Record> = find(&tx, "identities", filter)
                    .await?
                    .into_iter()
                    .filter(|identity| {
                        (include_deleted || str_of(identity, "status") != Some("deleted"))
                            && query.as_ref().is_none_or(|query| {
                                core_js::to_lower(str_of(identity, "name").unwrap_or(""))
                                    .contains(query.as_str())
                                    || str_of(identity, "email").is_some_and(|address| {
                                        core_js::to_lower(address).contains(query.as_str())
                                    })
                            })
                            && expires_before.is_none_or(|before| {
                                number_of(identity, "expiresAt")
                                    .is_some_and(|expires| expires <= before)
                            })
                    })
                    .collect();
                matches.sort_by(|a, b| {
                    by_name(a, b, |a, b| {
                        core_js::cmp_utf16(
                            str_of(a, "id").unwrap_or(""),
                            str_of(b, "id").unwrap_or(""),
                        )
                    })
                });
                let start = (offset as usize).min(matches.len());
                let end = match limit {
                    Some(limit) => (start + limit as usize).min(matches.len()),
                    None => matches.len(),
                };
                Ok(Value::Array(
                    matches[start..end]
                        .iter()
                        .map(|identity| Value::Object(public_identity_record(identity)))
                        .collect(),
                ))
            })
        });
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:read",
                &tenant_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/listBindings`: direct and group-derived role bindings, the effective role set of an identity.
    pub async fn list_bindings(
        &self,
        credential: &CredentialInput,
        input: Body<identities::ListBindingsInput>,
    ) -> IamResult<Reply<identities::ListBindingsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let identity_id = string_member(&input, "identityId");
        let target = &identity_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                ctx.scoped(&tx, "identities", body.get("identityId"), tenant)
                    .await?;
                Ok(Value::Array(
                    ctx.decisions()?
                        .effective_bindings(&tx, tenant, target)
                        .await?
                        .iter()
                        .map(|binding| binding.to_json())
                        .collect(),
                ))
            })
        });
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:bindings:read",
                &identity_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/listGroups`: current groups of an identity (expired memberships omitted), each with
    /// `membershipExpiresAt` when temporary.
    pub async fn list_groups(
        &self,
        credential: &CredentialInput,
        input: Body<identities::ListGroupsInput>,
    ) -> IamResult<Reply<identities::ListGroupsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let identity_id = string_member(&input, "identityId");
        let target = &identity_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                ctx.scoped(&tx, "identities", body.get("identityId"), tenant)
                    .await?;
                let mut groups: Vec<Value> = Vec::new();
                for membership in find(
                    &tx,
                    "groupMembers",
                    Filter::new()
                        .eq("tenantId", tenant.as_str())
                        .eq("identityId", target.as_str()),
                )
                .await?
                {
                    // `liveMembership`: no expiry, or one still ahead.
                    let expires_at = membership.get("expiresAt");
                    if let Some(expires_at) = expires_at
                        && !core_js::as_number(expires_at)
                            .is_some_and(|expires| expires > ctx.now())
                    {
                        continue;
                    }
                    let group_id = crate::js::js_string(membership.get("groupId"));
                    if let Some(mut group) = tx.get("groups", &group_id).await?
                        && str_of(&group, "tenantId") == Some(tenant.as_str())
                    {
                        if let Some(expires_at) = expires_at {
                            group.insert("membershipExpiresAt".into(), expires_at.clone());
                        }
                        groups.push(Value::Object(group));
                    }
                }
                Ok(Value::Array(groups))
            })
        });
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:groups:read",
                &identity_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/listInvitations`.
    pub async fn list_invitations(
        &self,
        credential: &CredentialInput,
        input: Body<identities::ListInvitationsInput>,
    ) -> IamResult<Reply<identities::ListInvitationsOutput>> {
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                Ok(Value::Array(
                    find(
                        &tx,
                        "memberInvitations",
                        Filter::new().eq("tenantId", tenant.as_str()),
                    )
                    .await?
                    .into_iter()
                    .map(without_secrets)
                    .collect(),
                ))
            })
        });
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:read",
                &tenant_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/listProviders`: the external sign-ins linked to an account (iam:identities:read).
    pub async fn list_providers(
        &self,
        credential: &CredentialInput,
        input: Body<identities::ListProvidersInput>,
    ) -> IamResult<Reply<identities::ListProvidersOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let identity = ctx
                    .scoped(&tx, "identities", body.get("identityId"), tenant)
                    .await?;
                let mut links: Vec<Value> = find(
                    &tx,
                    "externalIdentities",
                    Filter::new()
                        .eq("tenantId", tenant.as_str())
                        .eq("identityId", record_id(&identity)),
                )
                .await?
                .iter()
                .map(provider_link_view)
                .collect();
                let provider = |link: &Value| crate::js::js_string(link.get("providerId"));
                links.sort_by(|a, b| core_js::cmp_utf16(&provider(a), &provider(b)));
                Ok(Value::Array(links))
            })
        });
        let resource_id = string_member(&input, "identityId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:read",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/listReports`: the active identities that report to this one (`managerId`), by name.
    pub async fn list_reports(
        &self,
        credential: &CredentialInput,
        input: Body<identities::ListReportsInput>,
    ) -> IamResult<Reply<identities::ListReportsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let identity_id = string_member(&input, "identityId");
        let target = &identity_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                ctx.scoped(&tx, "identities", body.get("identityId"), tenant)
                    .await?;
                let mut reports: Vec<Record> = find(
                    &tx,
                    "identities",
                    Filter::new()
                        .eq("tenantId", tenant.as_str())
                        .eq("managerId", target.as_str()),
                )
                .await?
                .into_iter()
                .filter(|report| str_of(report, "status") == Some("active"))
                .collect();
                reports.sort_by(|a, b| by_name(a, b, id_order));
                Ok(Value::Array(
                    reports
                        .iter()
                        .map(|report| Value::Object(public_identity_record(report)))
                        .collect(),
                ))
            })
        });
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:read",
                &identity_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/listSessions`: sessions of one identity for administrators (device lists, support); token hashes
    /// are never returned.
    pub async fn list_sessions(
        &self,
        credential: &CredentialInput,
        input: Body<identities::ListSessionsInput>,
    ) -> IamResult<Reply<identities::ListSessionsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let identity_id = string_member(&input, "identityId");
        let target = &identity_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                ctx.scoped(&tx, "identities", body.get("identityId"), tenant)
                    .await?;
                let now = ctx.now();
                let mut sessions: Vec<Record> = find(
                    &tx,
                    "sessions",
                    Filter::new()
                        .eq("tenantId", tenant.as_str())
                        .eq("identityId", target.as_str()),
                )
                .await?
                .into_iter()
                .filter(|session| {
                    number_of(session, "expiresAt").is_some_and(|expires| expires > now)
                })
                .collect();
                sessions.sort_by(|a, b| newest_by("lastSeenAt", a, b));
                Ok(Value::Array(
                    sessions.into_iter().map(without_secrets).collect(),
                ))
            })
        });
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:read",
                &identity_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/offboard`: offboarding in one transaction. Disables the identity, ends every session and key,
    /// removes its role bindings, group memberships, activations, relationships, pending access requests and member
    /// invitations, revokes the grant authorities it holds, and hands the managed resources it owns to `successorId`
    /// (or reports them). Audited as `identity:offboard` with the reason and counts.
    pub async fn offboard(
        &self,
        credential: &CredentialInput,
        input: Body<identities::OffboardInput>,
    ) -> IamResult<Reply<identities::OffboardOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let reason = text(body.get("reason"), "reason", 512)?;
                let loaded =
                    boxed(|| active_identity(ctx, &tx, body.get("identityId"), tenant)).await?;
                let identity = &loaded.identity;
                if identity.id == principal.identity.id {
                    return Err(
                        IamError::new("INVALID_INPUT", "You cannot offboard yourself").into(),
                    );
                }
                if identity.root_admin && !boxed(|| ctx.root_principal(&tx, &principal)).await? {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Root capability is protected",
                        403,
                    )
                    .into());
                }
                boxed(|| ctx.protect_last_owner(&tx, identity)).await?;
                let successor = match body.get("successorId") {
                    Some(successor_id) => {
                        Some(boxed(|| active_identity(ctx, &tx, Some(successor_id), tenant)).await?)
                    }
                    None => None,
                };
                if let Some(successor) = &successor
                    && (successor.identity.id == identity.id
                        || successor.identity.status != IdentityStatus::Active)
                {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "Successor must be another active identity",
                    )
                    .into());
                }
                let successor_identity = successor.as_ref().map(|successor| &successor.identity);
                let sessions = boxed(|| {
                    find(
                        &tx,
                        "sessions",
                        Filter::new().eq("identityId", identity.id.clone()),
                    )
                })
                .await?
                .len() as f64;
                let mut bindings = 0.0;
                let mut memberships = 0.0;
                let mut activations = 0.0;
                let mut packages = 0.0;
                let mut relationships = 0.0;
                let mut access_requests = 0.0;
                let mut authorities = 0.0;
                let mut resources_reassigned = 0.0;
                let mut resources_owned = 0.0;
                let mut reports_reassigned = 0.0;
                let mine = || {
                    Filter::new()
                        .eq("tenantId", tenant.as_str())
                        .eq("identityId", identity.id.clone())
                };
                // Ownership goes first: the protected Owner binding is removed like setOwner(false).
                if identity.owner {
                    if !owns_tenant(&principal, tenant)
                        && !boxed(|| ctx.root_principal(&tx, &principal)).await?
                    {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "Only an owner can offboard an owner",
                            403,
                        )
                        .into());
                    }
                    let owner_role = boxed(|| {
                        find(
                            &tx,
                            "roles",
                            Filter::new()
                                .eq("tenantId", tenant.as_str())
                                .eq("uniqueKey", "system:owner"),
                        )
                    })
                    .await?
                    .into_iter()
                    .next();
                    let owner_role_id = owner_role.as_ref().map(record_id).unwrap_or_default();
                    for binding in boxed(|| {
                        find(
                            &tx,
                            "bindings",
                            Filter::new()
                                .eq("tenantId", tenant.as_str())
                                .eq("subjectType", "identity")
                                .eq("subjectId", identity.id.clone())
                                .eq("roleId", owner_role_id),
                        )
                    })
                    .await?
                    {
                        boxed(|| async { tx.delete("bindings", &record_id(&binding)).await })
                            .await?;
                        bindings += 1.0;
                    }
                }
                // Activations are counted before the bindings and memberships that would remove them.
                for activation in boxed(|| find(&tx, "bindingActivations", mine())).await? {
                    boxed(|| async {
                        tx.delete("bindingActivations", &record_id(&activation))
                            .await
                    })
                    .await?;
                    activations += 1.0;
                }
                // Package assignments are revoked first, under package ownership: their bindings may come from
                // another administrator's authority, which the generic binding removal below would refuse.
                for assignment in boxed(|| find(&tx, "packageAssignments", mine())).await? {
                    let assignment: crate::models::PackageAssignment = decode(assignment)?;
                    let removed =
                        boxed(|| crate::api::packages::revoke_assignment(ctx, &tx, &assignment))
                            .await?;
                    bindings += removed
                        .get("bindings")
                        .and_then(core_js::as_number)
                        .unwrap_or(0.0);
                    memberships += removed
                        .get("memberships")
                        .and_then(core_js::as_number)
                        .unwrap_or(0.0);
                    packages += 1.0;
                }
                for binding in boxed(|| {
                    find(
                        &tx,
                        "bindings",
                        Filter::new()
                            .eq("tenantId", tenant.as_str())
                            .eq("subjectType", "identity")
                            .eq("subjectId", identity.id.clone()),
                    )
                })
                .await?
                {
                    let binding: crate::models::Binding = decode(binding)?;
                    boxed(|| crate::api::bindings::delete_binding(ctx, &tx, &principal, &binding))
                        .await?;
                    bindings += 1.0;
                }
                // Teams and departments (teams.ts, departments.ts): team memberships go first, taking the
                // team-managed group memberships with them; departments they head pass to the successor. Reported
                // only when non-zero.
                let teams_left = boxed(|| {
                    crate::teams::remove_from_all_teams(&tx, tenant, &identity.id, ctx.now())
                })
                .await?;
                let departments = boxed(|| {
                    crate::departments::release_departments(
                        &tx,
                        tenant,
                        &identity.id,
                        ctx.now(),
                        successor_identity.map(|successor| successor.id.as_str()),
                    )
                })
                .await?;
                let mut org_counts = Map::new();
                if teams_left != 0.0 && !teams_left.is_nan() {
                    org_counts.insert("teamsLeft".into(), crate::js::number(teams_left));
                }
                if crate::js::truthy(departments.get("headsReassigned")) {
                    org_counts.insert(
                        "departmentsReassigned".into(),
                        departments["headsReassigned"].clone(),
                    );
                }
                // Seats of the groups' license products are reconciled once, after every membership is gone.
                let removed_memberships = Arc::new(AtomicU64::new(0));
                let run: crate::port::Callback = {
                    let ctx = ctx.clone();
                    let tx = tx.clone();
                    let principal = principal.clone();
                    let tenant = tenant.clone();
                    let identity_id = identity.id.clone();
                    let removed = removed_memberships.clone();
                    Arc::new(move |_| {
                        let ctx = ctx.clone();
                        let tx = tx.clone();
                        let principal = principal.clone();
                        let tenant = tenant.clone();
                        let identity_id = identity_id.clone();
                        let removed = removed.clone();
                        let future: futures::future::BoxFuture<'static, IamResult<Value>> =
                            Box::pin(async move {
                                for membership in boxed(|| {
                                    find(
                                        &tx,
                                        "groupMembers",
                                        Filter::new()
                                            .eq("tenantId", tenant.clone())
                                            .eq("identityId", identity_id.clone()),
                                    )
                                })
                                .await?
                                {
                                    boxed(|| async { crate::api::groups::remove_group_member(
                                    &ctx,
                                    &tx,
                                    &principal,
                                    &json!({
                                        "tenantId": tenant,
                                        "groupId": membership.get("groupId").cloned().unwrap_or(Value::Null),
                                        "identityId": identity_id,
                                    }),
                                ).await })
                                .await?;
                                    removed.fetch_add(1, AtomicOrdering::SeqCst);
                                }
                                Ok(crate::port::undefined())
                            });
                        future
                    })
                };
                boxed(|| crate::licenses::batch_group_licenses(ctx, &tx, &run)).await?;
                memberships += removed_memberships.load(AtomicOrdering::SeqCst) as f64;
                for tuple in boxed(|| {
                    find(
                        &tx,
                        "relationships",
                        Filter::new()
                            .eq("tenantId", tenant.as_str())
                            .eq("subjectType", "identity")
                            .eq("subjectId", identity.id.clone()),
                    )
                })
                .await?
                {
                    boxed(|| async { tx.delete("relationships", &record_id(&tuple)).await })
                        .await?;
                    relationships += 1.0;
                }
                for mut request in boxed(|| {
                    find(
                        &tx,
                        "accessRequests",
                        Filter::new()
                            .eq("tenantId", tenant.as_str())
                            .eq("requesterId", identity.id.clone())
                            .eq("status", "pending"),
                    )
                })
                .await?
                {
                    request.insert("status".into(), Value::String("cancelled".into()));
                    request.insert("reviewedAt".into(), crate::js::number(ctx.now()));
                    boxed(|| tx.put("accessRequests", &request)).await?;
                    access_requests += 1.0;
                }
                for mut request in
                    boxed(|| find(&tx, "packageRequests", mine().eq("status", "pending"))).await?
                {
                    request.insert("status".into(), Value::String("cancelled".into()));
                    request.insert("decidedAt".into(), crate::js::number(ctx.now()));
                    boxed(|| tx.put("packageRequests", &request)).await?;
                    access_requests += 1.0;
                }
                for mut authority in boxed(|| find(&tx, "grantAuthorities", mine())).await? {
                    if !truthy(&authority, "revoked") {
                        authority.insert("revoked".into(), Value::Bool(true));
                        boxed(|| tx.put("grantAuthorities", &authority)).await?;
                        authorities += 1.0;
                    }
                }
                // Their reports move to the successor, or are left without a manager. The successor, if one of them,
                // moves up to the leaver's own manager; a report above the successor in the same line would close a
                // cycle and is left without a manager instead.
                let mut successor_line: IndexSet<String> = IndexSet::new();
                let mut cursor: Option<Record> =
                    successor.as_ref().map(|successor| successor.raw.clone());
                let mut depth = 0;
                while let Some(current) = &cursor {
                    let Some(next) = str_of(current, "managerId").filter(|next| !next.is_empty())
                    else {
                        break;
                    };
                    if depth >= 100 {
                        break;
                    }
                    let next = next.to_owned();
                    successor_line.insert(next.clone());
                    cursor = boxed(|| tx.get("identities", &next)).await?;
                    depth += 1;
                }
                for mut report in boxed(|| {
                    find(
                        &tx,
                        "identities",
                        Filter::new()
                            .eq("tenantId", tenant.as_str())
                            .eq("managerId", identity.id.clone()),
                    )
                })
                .await?
                {
                    if str_of(&report, "status") == Some("deleted") {
                        continue;
                    }
                    report.shift_remove("managerId");
                    let report_id = record_id(&report);
                    let manager_id: Option<Value> = match successor_identity {
                        Some(successor) if report_id == successor.id => loaded
                            .raw
                            .get("managerId")
                            .filter(|manager| manager.as_str() != Some(report_id.as_str()))
                            .cloned(),
                        Some(successor) if !successor_line.contains(&report_id) => {
                            Some(Value::String(successor.id.clone()))
                        }
                        _ => None,
                    };
                    if let Some(manager_id) = manager_id {
                        report.insert("managerId".into(), manager_id);
                    }
                    boxed(|| tx.put("identities", &report)).await?;
                    reports_reassigned += 1.0;
                }
                for mut resource in boxed(|| {
                    find(
                        &tx,
                        "resources",
                        Filter::new()
                            .eq("tenantId", tenant.as_str())
                            .eq("ownerId", identity.id.clone()),
                    )
                })
                .await?
                {
                    if let Some(successor) = successor_identity {
                        resource.insert("ownerId".into(), Value::String(successor.id.clone()));
                        resource.insert("updatedAt".into(), crate::js::number(ctx.now()));
                        boxed(|| tx.put("resources", &resource)).await?;
                        resources_reassigned += 1.0;
                    } else {
                        resources_owned += 1.0;
                    }
                }
                // AI agents (agents.ts): the agents they sponsor move to the successor, and every delegation they
                // gave (or, for an agent, hold) ends. Reported only when there was something to do, so other results
                // keep their shape.
                let handover = boxed(|| {
                    crate::agents::hand_over_agents(
                        ctx,
                        &tx,
                        &principal,
                        identity,
                        successor_identity,
                    )
                })
                .await?;
                let delegations_revoked = boxed(|| async {
                    crate::delegations::revoke_delegations_of(
                        ctx,
                        &tx,
                        &Value::Object(loaded.raw.clone()),
                        &principal.identity.id,
                    )
                    .await
                })
                .await?;
                // Guests (guests.ts): the guests they sponsor move to the successor or are flagged for a new
                // sponsor, and a leaver who is a guest has their guest account closed. Reported only when non-zero.
                let guest_handover = boxed(|| {
                    crate::guests::hand_over_guests(
                        ctx,
                        &tx,
                        &principal,
                        identity,
                        successor_identity,
                    )
                })
                .await?;
                // Security clearances (clearances.ts): the leaver's clearance is terminated and every compartment
                // debriefed.
                let clearances_terminated = boxed(|| {
                    crate::clearances::terminate_clearances_of(
                        ctx, &tx, &principal, identity, &reason,
                    )
                })
                .await?;
                let mut agent_counts = Map::new();
                let mut count_if = |name: &str, value: Option<&Value>| {
                    if crate::js::truthy(value) {
                        agent_counts.insert(name.into(), value.cloned().unwrap_or(Value::Null));
                    }
                };
                count_if("agentsReassigned", handover.get("reassigned"));
                count_if("agentsUnsponsored", handover.get("unsponsored"));
                count_if(
                    "delegationsRevoked",
                    Some(&crate::js::number(delegations_revoked)),
                );
                count_if("guestsReassigned", guest_handover.get("reassigned"));
                count_if("guestsUnsponsored", guest_handover.get("unsponsored"));
                count_if(
                    "clearancesTerminated",
                    Some(&crate::js::number(clearances_terminated)),
                );
                boxed(|| ctx.revoke_all(&tx, &identity.id)).await?;
                boxed(|| revoke_invitations_by(&tx, &identity.id)).await?;
                let mut disabled = loaded.raw.clone();
                disabled.insert("status".into(), Value::String("disabled".into()));
                disabled.insert("owner".into(), Value::Bool(false));
                let disabled = boxed(|| tx.put("identities", &disabled)).await?;
                // An offboarded identity stays disabled: a threats containment of it can no longer be released.
                boxed(|| crate::threats::end_containment(&tx, &identity.id, ctx.now())).await?;
                let mut counts = Map::new();
                for (name, value) in [
                    ("sessions", sessions),
                    ("bindings", bindings),
                    ("memberships", memberships),
                    ("activations", activations),
                    ("packages", packages),
                    ("relationships", relationships),
                    ("accessRequests", access_requests),
                    ("authorities", authorities),
                    ("resourcesReassigned", resources_reassigned),
                    ("resourcesOwned", resources_owned),
                    ("reportsReassigned", reports_reassigned),
                ] {
                    counts.insert(name.into(), crate::js::number(value));
                }
                let mut metadata = Map::new();
                metadata.insert("reason".into(), Value::String(reason.clone()));
                metadata.insert(
                    "kind".into(),
                    loaded.raw.get("kind").cloned().unwrap_or(Value::Null),
                );
                if let Some(successor) = successor_identity {
                    metadata.insert("successorId".into(), Value::String(successor.id.clone()));
                }
                for part in [&counts, &agent_counts, &org_counts] {
                    for (key, value) in part {
                        metadata.insert(key.clone(), value.clone());
                    }
                }
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "identity:offboard",
                        tenant,
                        &identity.id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                let mut out = Map::new();
                out.insert(
                    "identity".into(),
                    Value::Object(public_identity_record(&disabled)),
                );
                for part in [counts, agent_counts, org_counts] {
                    for (key, value) in part {
                        out.insert(key, value);
                    }
                }
                Ok(Value::Object(out))
            })
        });
        let resource_id = string_member(&input, "identityId");
        let result = boxed(|| {
            self.run(
                credential,
                &input,
                "iam:identities:update",
                &resource_id,
                mutation,
            )
        })
        .await?;
        // A disabled identity claims no license seat: reconciling releases its seats (licenses.ts).
        Ok(Reply::json(
            boxed(|| self.after_change(&input, vec![resource_id], result)).await?,
        ))
    }

    /// `identities/requestPasswordReset`: queues a password-reset email for a member on an administrator's behalf.
    /// Audited as `identity:password-reset`.
    pub async fn request_password_reset(
        &self,
        credential: &CredentialInput,
        input: Body<identities::RequestPasswordResetInput>,
    ) -> IamResult<Reply<identities::RequestPasswordResetOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let loaded = active_identity(ctx, &tx, body.get("identityId"), tenant).await?;
                assert_account_control(ctx, &tx, &principal, &loaded.identity).await?;
                ctx.auth.issue_password_reset(&tx, &loaded.identity).await?;
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "identity:password-reset",
                        tenant,
                        &loaded.identity.id,
                        AuditOutcome::Allow,
                        false,
                        None,
                    )
                    .await?;
                let mut out = Map::new();
                out.insert("queued".into(), Value::Bool(true));
                if let Some(address) = loaded.raw.get("email") {
                    out.insert("email".into(), address.clone());
                }
                Ok(Value::Object(out))
            })
        });
        let resource_id = string_member(&input, "identityId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:update",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/resendInvitation`: re-sends a member invitation with a fresh token and lifetime; the earlier token
    /// stops working. Only an invitation that can still be accepted goes out.
    pub async fn resend_invitation(
        &self,
        credential: &CredentialInput,
        input: Body<identities::ResendInvitationInput>,
    ) -> IamResult<Reply<identities::ResendInvitationOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: realm,
             }| {
                Box::pin(async move {
                    if !has_email_delivery(ctx) {
                        return Err(IamError::new(
                            "DELIVERY_REQUIRED",
                            "Member invitations require an email delivery callback",
                        )
                        .into());
                    }
                    if realm.status != TenantStatus::Active {
                        return Err(
                            IamError::new("TENANT_INACTIVE", "Tenant must be active").into()
                        );
                    }
                    let mut invitation = ctx
                        .scoped(&tx, "memberInvitations", body.get("invitationId"), tenant)
                        .await?;
                    if truthy(&invitation, "consumed") || truthy(&invitation, "revoked") {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "Invitation is already consumed or revoked",
                            409,
                        )
                        .into());
                    }
                    // Acceptance would refuse an invitation its inviter can no longer grant (flows.ts): send none.
                    let typed: crate::models::MemberInvitation = decode(invitation.clone())?;
                    if let Err(error) = crate::flows::assert_member_invitation_grantable(
                        ctx, &tx, &typed, &realm.id,
                    )
                    .await
                    {
                        if error.code != "INVITATION_INVALID" {
                            return Err(error.into());
                        }
                        return Err(IamError::new(
                            "INVITATION_INVALID",
                            format!(
                                "{}: revoke this invitation and invite the person again",
                                error.message
                            ),
                        )
                        .into());
                    }
                    let invite_token = token();
                    let now = date_now();
                    invitation.insert("tokenHash".into(), Value::String(hash(&invite_token)));
                    invitation.insert("uniqueKey".into(), Value::String(hash(&invite_token)));
                    invitation.insert(
                        "expiresAt".into(),
                        crate::js::number(now + ctx.config.invitation_lifetime_ms),
                    );
                    let renewed = tx.put("memberInvitations", &invitation).await?;
                    queue_invitation_email(
                        ctx,
                        &tx,
                        &realm,
                        invitation.get("email").unwrap_or(&Value::Null),
                        &invite_token,
                        &principal.identity.name,
                        now,
                    )
                    .await?;
                    let mut out = Map::new();
                    for (to, from) in [
                        ("invitationId", "id"),
                        ("email", "email"),
                        ("expiresAt", "expiresAt"),
                    ] {
                        if let Some(value) = renewed.get(from) {
                            out.insert(to.into(), value.clone());
                        }
                    }
                    Ok(Value::Object(out))
                })
            },
        );
        let resource_id = string_member(&input, "invitationId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:update",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/revokeInvitation`.
    pub async fn revoke_invitation(
        &self,
        credential: &CredentialInput,
        input: Body<identities::RevokeInvitationInput>,
    ) -> IamResult<Reply<identities::RevokeInvitationOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let mut invitation = ctx
                    .scoped(&tx, "memberInvitations", body.get("invitationId"), tenant)
                    .await?;
                if truthy(&invitation, "consumed") || truthy(&invitation, "revoked") {
                    return Err(IamError::with_status(
                        "CONFLICT",
                        "Invitation is already consumed or revoked",
                        409,
                    )
                    .into());
                }
                invitation.insert("revoked".into(), Value::Bool(true));
                Ok(without_secrets(
                    tx.put("memberInvitations", &invitation).await?,
                ))
            })
        });
        let resource_id = string_member(&input, "invitationId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:update",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/revokeSessions`: ends every session of an identity without disabling it (incident response, lost
    /// device). With `keepApiKeys: true` the API keys stay valid. Audited as `identity:revoke-sessions`.
    pub async fn revoke_sessions(
        &self,
        credential: &CredentialInput,
        input: Body<identities::RevokeSessionsInput>,
    ) -> IamResult<Reply<identities::RevokeSessionsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                if let Some(keep) = body.get("keepApiKeys")
                    && !keep.is_boolean()
                {
                    return Err(
                        IamError::new("INVALID_INPUT", "keepApiKeys must be a boolean").into(),
                    );
                }
                let keep_api_keys = body.get("keepApiKeys") == Some(&Value::Bool(true));
                let loaded = scoped_identity(ctx, &tx, body.get("identityId"), tenant).await?;
                let identity = &loaded.identity;
                if identity.root_admin && !ctx.root_principal(&tx, &principal).await? {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Root capability is protected",
                        403,
                    )
                    .into());
                }
                let by_identity = || Filter::new().eq("identityId", identity.id.clone());
                let revoked: f64;
                if !keep_api_keys {
                    revoked = find(&tx, "sessions", by_identity()).await?.len() as f64;
                    ctx.revoke_all(&tx, &identity.id).await?;
                } else {
                    // As revokeAll, minus the API keys: sessions by identity (with the impersonations opened through
                    // them), remembered devices, challenges, then role sessions the identity assumed in other
                    // tenants.
                    let mut count = 0.0;
                    for session in find(&tx, "sessions", by_identity()).await? {
                        if str_of(&session, "kind") == Some("api-key") {
                            continue;
                        }
                        ctx.auth.end_session(&tx, &record_id(&session)).await?;
                        count += 1.0;
                    }
                    revoked = count;
                    for device in find(&tx, "authDevices", by_identity()).await? {
                        tx.delete("authDevices", &record_id(&device)).await?;
                    }
                    for challenge in find(&tx, "authChallenges", by_identity()).await? {
                        tx.delete("authChallenges", &record_id(&challenge)).await?;
                    }
                    for session in find(
                        &tx,
                        "sessions",
                        Filter::new().eq("originalIdentityId", identity.id.clone()),
                    )
                    .await?
                    {
                        if str_of(&session, "kind") != Some("api-key") {
                            tx.delete("sessions", &record_id(&session)).await?;
                        }
                    }
                }
                let mut metadata = Map::new();
                metadata.insert("revoked".into(), crate::js::number(revoked));
                metadata.insert("keptApiKeys".into(), Value::Bool(keep_api_keys));
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "identity:revoke-sessions",
                        tenant,
                        &identity.id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(json!({ "revoked": crate::js::number(revoked) }))
            })
        });
        let resource_id = string_member(&input, "identityId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:update",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/setBoundary`: a principal ceiling (platform controlled: root only).
    pub async fn set_boundary(
        &self,
        credential: &CredentialInput,
        input: Body<identities::SetBoundaryInput>,
    ) -> IamResult<Reply<identities::SetBoundaryOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.catalog
                    .validate(
                        tx.as_ref(),
                        tenant,
                        body.get("document").unwrap_or(&Value::Null),
                    )
                    .await?;
                ctx.scoped(&tx, "identities", body.get("identityId"), tenant)
                    .await?;
                if !ctx.root_principal(&tx, &principal).await? {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Principal ceilings are platform controlled",
                        403,
                    )
                    .into());
                }
                let identity_id = body.get("identityId").cloned().unwrap_or(Value::Null);
                let existing = find(
                    &tx,
                    "principalBoundaries",
                    Filter::new()
                        .eq("tenantId", tenant.as_str())
                        .eq("identityId", identity_id.clone()),
                )
                .await?
                .into_iter()
                .next();
                let mut record = Map::new();
                record.insert(
                    "id".into(),
                    existing
                        .as_ref()
                        .and_then(|existing| existing.get("id").cloned())
                        .unwrap_or_else(|| Value::String(id())),
                );
                record.insert("tenantId".into(), Value::String(tenant.clone()));
                record.insert("uniqueKey".into(), identity_id.clone());
                record.insert("identityId".into(), identity_id);
                if let Some(document) = body.get("document") {
                    record.insert("document".into(), document.clone());
                }
                let stored = if existing.is_some() {
                    tx.put("principalBoundaries", &record).await?
                } else {
                    tx.insert("principalBoundaries", &record).await?
                };
                Ok(Value::Object(stored))
            })
        });
        let resource_id = string_member(&input, "identityId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:boundaries:update",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/setOwner`: ownership transfer, granting or removing the protected Owner role; the last active
    /// owner is protected. A former owner's owner grant authority passes to a remaining owner.
    pub async fn set_owner(
        &self,
        credential: &CredentialInput,
        input: Body<identities::SetOwnerInput>,
    ) -> IamResult<Reply<identities::SetOwnerOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                if !owns_tenant(&principal, tenant) && !ctx.root_principal(&tx, &principal).await? {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Only an owner can transfer ownership",
                        403,
                    )
                    .into());
                }
                let loaded = active_identity(ctx, &tx, body.get("identityId"), tenant).await?;
                let identity = &loaded.identity;
                let owner = match body.get("owner") {
                    Some(Value::Bool(owner))
                        if identity.kind == IdentityKind::User
                            && identity.status == IdentityStatus::Active =>
                    {
                        *owner
                    }
                    _ => return Err(IamError::new("INVALID_INPUT", "Invalid owner").into()),
                };
                if !owner {
                    ctx.protect_last_owner(&tx, identity).await?;
                }
                let Some(owner_role) = find(
                    &tx,
                    "roles",
                    Filter::new()
                        .eq("tenantId", tenant.as_str())
                        .eq("uniqueKey", "system:owner"),
                )
                .await?
                .into_iter()
                .next() else {
                    return Err(
                        IamError::with_status("NOT_FOUND", "Owner role missing", 404).into(),
                    );
                };
                let owner_role_id = record_id(&owner_role);
                if owner && !identity.owner {
                    let parent = ctx
                        .granting_authority(&tx, &principal, tenant, None)
                        .await?;
                    let mut authority = Map::new();
                    authority.insert("id".into(), Value::String(id()));
                    authority.insert("tenantId".into(), Value::String(tenant.clone()));
                    authority.insert("identityId".into(), Value::String(identity.id.clone()));
                    authority.insert("ceiling".into(), all_value());
                    authority.insert("parentAuthorityId".into(), Value::String(parent.id.clone()));
                    authority.insert("revoked".into(), Value::Bool(false));
                    let authority = tx.insert("grantAuthorities", &authority).await?;
                    let mut binding = Map::new();
                    binding.insert("id".into(), Value::String(id()));
                    binding.insert("tenantId".into(), Value::String(tenant.clone()));
                    binding.insert("subjectType".into(), Value::String("identity".into()));
                    binding.insert("subjectId".into(), Value::String(identity.id.clone()));
                    binding.insert("roleId".into(), Value::String(owner_role_id.clone()));
                    binding.insert(
                        "authorityId".into(),
                        authority.get("id").cloned().unwrap_or(Value::Null),
                    );
                    tx.insert("bindings", &binding).await?;
                }
                if !owner {
                    // The unlimited grant authority the Owner role came with (from setOwner or the owner invitation)
                    // leaves the former owner too. It passes to an owner who stays (the caller, or else the
                    // longest-standing other owner) instead of being revoked: revoking it would also end every grant
                    // made under it, including the authorities of owners promoted through it.
                    let successor_id = if owns_tenant(&principal, tenant)
                        && principal.identity.id != identity.id
                    {
                        Some(principal.identity.id.clone())
                    } else {
                        let mut owners: Vec<Record> = find(
                            &tx,
                            "identities",
                            Filter::new()
                                .eq("tenantId", tenant.as_str())
                                .eq("owner", true)
                                .eq("status", "active"),
                        )
                        .await?
                        .into_iter()
                        .filter(|other| str_of(other, "id") != Some(identity.id.as_str()))
                        .collect();
                        owners.sort_by(|a, b| {
                            let created = |record: &Record| {
                                number_of(record, "createdAt").unwrap_or(f64::NAN)
                            };
                            let difference = created(a) - created(b);
                            if difference != 0.0 && !difference.is_nan() {
                                return if difference > 0.0 {
                                    std::cmp::Ordering::Greater
                                } else {
                                    std::cmp::Ordering::Less
                                };
                            }
                            id_order(a, b)
                        });
                        owners.first().map(record_id)
                    };
                    for binding in find(
                        &tx,
                        "bindings",
                        Filter::new()
                            .eq("tenantId", tenant.as_str())
                            .eq("subjectType", "identity")
                            .eq("subjectId", identity.id.clone())
                            .eq("roleId", owner_role_id.clone()),
                    )
                    .await?
                    {
                        tx.delete("bindings", &record_id(&binding)).await?;
                        let authority_id = crate::js::js_string(binding.get("authorityId"));
                        if let Some(mut authority) =
                            tx.get("grantAuthorities", &authority_id).await?
                            && str_of(&authority, "identityId") == Some(identity.id.as_str())
                            && let Some(successor_id) = &successor_id
                        {
                            authority
                                .insert("identityId".into(), Value::String(successor_id.clone()));
                            tx.put("grantAuthorities", &authority).await?;
                        }
                    }
                }
                let mut next = loaded.raw.clone();
                next.insert("owner".into(), Value::Bool(owner));
                Ok(Value::Object(public_identity_record(
                    &tx.put("identities", &next).await?,
                )))
            })
        });
        let resource_id = string_member(&input, "identityId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:update",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/setStatus`: disables (ending its sessions, keys and pending invitations) or re-enables an
    /// identity. Disabling an owner needs an owner or root caller; agents use `agents.suspend` and `agents.resume`.
    pub async fn set_status(
        &self,
        credential: &CredentialInput,
        input: Body<identities::SetStatusInput>,
    ) -> IamResult<Reply<identities::SetStatusOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let Some(status) = body
                    .get("status")
                    .and_then(Value::as_str)
                    .filter(|status| ["active", "disabled"].contains(status))
                else {
                    return Err(IamError::new("INVALID_INPUT", "Invalid identity status").into());
                };
                let loaded = active_identity(ctx, &tx, body.get("identityId"), tenant).await?;
                let identity = &loaded.identity;
                // An agent's status follows its own rules (agents.ts): re-enabling it here would lift a suspension
                // that only agents.resume, with its own permission and recent sign-in, may lift.
                if identity.kind == IdentityKind::Agent {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "Use agents.suspend and agents.resume to stop or restart an agent",
                    )
                    .into());
                }
                if identity.root_admin && !ctx.root_principal(&tx, &principal).await? {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Root capability is protected",
                        403,
                    )
                    .into());
                }
                if status == "disabled" {
                    assert_owner_control(
                        ctx,
                        &tx,
                        &principal,
                        identity,
                        "Only an owner can disable an owner",
                    )
                    .await?;
                    ctx.protect_last_owner(&tx, identity).await?;
                }
                if status == "active" && ctx.identity_expired(identity) {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "Extend or clear expiresAt before re-enabling an expired identity",
                        409,
                    )
                    .into());
                }
                let mut next = loaded.raw.clone();
                next.insert("status".into(), Value::String(status.to_owned()));
                let updated = tx.put("identities", &next).await?;
                // The status is now this call's: a threats containment is over (released here, or held by this
                // disable).
                crate::threats::end_containment(&tx, &identity.id, ctx.now()).await?;
                if status == "disabled" {
                    ctx.revoke_all(&tx, &identity.id).await?;
                    revoke_invitations_by(&tx, &identity.id).await?;
                }
                Ok(Value::Object(public_identity_record(&updated)))
            })
        });
        let resource_id = string_member(&input, "identityId");
        let updated = self
            .run(
                credential,
                &input,
                "iam:identities:update",
                &resource_id,
                mutation,
            )
            .await?;
        let updated_id = crate::js::js_string(updated.get("id"));
        Ok(Reply::json(
            self.after_change(&input, vec![updated_id], updated).await?,
        ))
    }

    /// `identities/unlinkProvider`: removes a linked external sign-in; that IdP account no longer signs in to this
    /// account. Audited as `identity:unlink-provider`.
    pub async fn unlink_provider(
        &self,
        credential: &CredentialInput,
        input: Body<identities::UnlinkProviderInput>,
    ) -> IamResult<Reply<identities::UnlinkProviderOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let loaded = scoped_identity(ctx, &tx, body.get("identityId"), tenant).await?;
                let identity = &loaded.identity;
                assert_account_control(ctx, &tx, &principal, identity).await?;
                let link_id = text(body.get("linkId"), "linkId", 256)?;
                let link = tx.get("externalIdentities", &link_id).await?;
                let Some(link) = link.filter(|link| {
                    str_of(link, "tenantId") == Some(tenant.as_str())
                        && str_of(link, "identityId") == Some(identity.id.as_str())
                }) else {
                    return Err(IamError::with_status(
                        "NOT_FOUND",
                        "Linked sign-in not found",
                        404,
                    )
                    .into());
                };
                tx.delete("externalIdentities", &record_id(&link)).await?;
                let mut metadata = Map::new();
                metadata.insert(
                    "providerId".into(),
                    Value::String(crate::js::js_string(link.get("providerId"))),
                );
                metadata.insert(
                    "linkId".into(),
                    link.get("id").cloned().unwrap_or(Value::Null),
                );
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "identity:unlink-provider",
                        tenant,
                        &identity.id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(provider_link_view(&link))
            })
        });
        let resource_id = string_member(&input, "identityId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:update",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/unlock`: clears the sign-in, recovery, and MFA rate-limit counters for the identity's email,
    /// phone, and ID; custom limiters without `reset` report `supported: false`.
    pub async fn unlock(
        &self,
        credential: &CredentialInput,
        input: Body<identities::UnlockInput>,
    ) -> IamResult<Reply<identities::UnlockOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let loaded = active_identity(ctx, &tx, body.get("identityId"), tenant).await?;
                let result = ctx.auth.reset_rate_limits(&loaded.identity).await?;
                let cleared = crate::js::number(result.cleared as f64);
                let mut metadata = Map::new();
                metadata.insert("supported".into(), Value::Bool(result.supported));
                metadata.insert("cleared".into(), cleared.clone());
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "identity:unlock",
                        tenant,
                        &loaded.identity.id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(json!({ "supported": result.supported, "cleared": cleared }))
            })
        });
        let resource_id = string_member(&input, "identityId");
        Ok(Reply::json(
            self.run(
                credential,
                &input,
                "iam:identities:update",
                &resource_id,
                mutation,
            )
            .await?,
        ))
    }

    /// `identities/update`: renames an identity, replaces its declared attributes, changes its email, sets its
    /// manager, or schedules/clears its deactivation (`expiresAt`, null to clear). An email change requires recent
    /// authentication, marks the address unverified, revokes the identity's sessions, and is audited as
    /// `identity:email-change`. Changing your own attributes, manager, or expiry needs an owner or root caller.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<identities::UpdateInput>,
    ) -> IamResult<Reply<identities::UpdateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let tenant = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let loaded = active_identity(ctx, &tx, body.get("identityId"), tenant).await?;
                let identity = &loaded.identity;
                if ["name", "attributes", "email", "expiresAt", "managerId"]
                    .iter()
                    .all(|key| !body.contains_key(*key))
                {
                    return Err(IamError::new("INVALID_INPUT", "Nothing to update").into());
                }
                let mut next = loaded.raw.clone();
                if let Some(name) = body.get("name") {
                    next.insert("name".into(), Value::String(text(Some(name), "name", 256)?));
                }
                if let Some(attributes) = body.get("attributes") {
                    next.insert(
                        "attributes".into(),
                        Value::Object(attribute_values(
                            &ctx.catalog.identity_attributes,
                            Some(attributes),
                        )?),
                    );
                }
                if let Some(expires_at) = body.get("expiresAt") {
                    if identity.root_admin && !ctx.root_principal(&tx, &principal).await? {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "Root capability is protected",
                            403,
                        )
                        .into());
                    }
                    assert_owner_control(
                        ctx,
                        &tx,
                        &principal,
                        identity,
                        "Only an owner can change an owner\u{2019}s expiry",
                    )
                    .await?;
                    if expires_at.is_null() {
                        next.shift_remove("expiresAt");
                    } else {
                        if identity.owner {
                            ctx.protect_last_owner(&tx, identity).await?;
                            // An owner past their expiry is locked out like a disabled one: the last owner without an
                            // expiry keeps none, or every owner could be scheduled away with nobody left to undo it.
                            if !loaded.raw.get("expiresAt").is_some_and(Value::is_number)
                                && !find(
                                    &tx,
                                    "identities",
                                    Filter::new()
                                        .eq("tenantId", identity.tenant_id.clone())
                                        .eq("owner", true)
                                        .eq("status", "active"),
                                )
                                .await?
                                .iter()
                                .any(|other| {
                                    str_of(other, "id") != Some(identity.id.as_str())
                                        && !other.get("expiresAt").is_some_and(Value::is_number)
                                })
                            {
                                return Err(IamError::with_status(
                                    "LAST_OWNER",
                                    "The last owner without an expiry cannot be given one",
                                    409,
                                )
                                .into());
                            }
                        }
                        next.insert(
                            "expiresAt".into(),
                            crate::js::number(ctx.binding_expiry(Some(expires_at))?),
                        );
                    }
                }
                match body.get("managerId") {
                    Some(Value::Null) => {
                        next.shift_remove("managerId");
                    }
                    Some(manager_id) if differs(Some(manager_id), loaded.raw.get("managerId")) => {
                        let manager = manager_for(
                            ctx,
                            &tx,
                            &identity.id,
                            &identity.tenant_id,
                            Some(manager_id),
                        )
                        .await?;
                        next.insert("managerId".into(), Value::String(manager));
                    }
                    _ => {}
                }
                // Attributes, the reporting line and the expiry feed birthright package rules and policy conditions,
                // so changing your own would grant you access: only an owner of the tenant or root may. Re-sending the
                // current values is not a change.
                if identity.id == principal.identity.id
                    && (!same_attributes(next.get("attributes"), loaded.raw.get("attributes"))
                        || differs(next.get("managerId"), loaded.raw.get("managerId"))
                        || differs(next.get("expiresAt"), loaded.raw.get("expiresAt")))
                    && !owns_tenant(&principal, tenant)
                    && !ctx.root_principal(&tx, &principal).await?
                {
                    return Err(OperationDenied::new(Some(
                        "Your own attributes, manager and expiry are changed by another administrator",
                    )));
                }
                let mut previous_email: Option<Value> = None;
                if let Some(address) = body.get("email") {
                    ctx.auth.require_recent(&principal)?;
                    if identity.kind != IdentityKind::User {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "Service accounts have no email",
                        )
                        .into());
                    }
                    let address = email(Some(address))?;
                    if identity.email.as_deref() != Some(address.as_str()) {
                        // A guest's address is the one their invitation proved and the cross-tenant settings admitted
                        // (guests.ts).
                        if truthy(&loaded.raw, "guest") {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "A guest\u{2019}s email address cannot change: invite the new address instead",
                            )
                            .into());
                        }
                        assert_account_control(ctx, &tx, &principal, identity).await?;
                        if find(
                            &tx,
                            "identities",
                            Filter::new()
                                .eq("tenantId", tenant.as_str())
                                .eq("email", address.clone()),
                        )
                        .await?
                        .iter()
                        .any(|other| str_of(other, "id") != Some(identity.id.as_str()))
                        {
                            return Err(IamError::with_status(
                                "IDENTITY_EXISTS",
                                "Email is already in use in this tenant",
                                409,
                            )
                            .into());
                        }
                        previous_email = loaded.raw.get("email").cloned();
                        next.insert("email".into(), Value::String(address.clone()));
                        next.insert(
                            "uniqueKey".into(),
                            Value::String(format!("email:{address}")),
                        );
                        next.insert("emailVerified".into(), Value::Bool(false));
                    }
                }
                let updated = tx.put("identities", &next).await?;
                if previous_email.is_some()
                    || (body.contains_key("email") && !truthy(&loaded.raw, "email"))
                {
                    ctx.revoke_all(&tx, &identity.id).await?;
                    let mut metadata = Map::new();
                    metadata.insert("from".into(), previous_email.unwrap_or(Value::Null));
                    metadata.insert(
                        "to".into(),
                        updated.get("email").cloned().unwrap_or(Value::Null),
                    );
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "identity:email-change",
                            tenant,
                            &identity.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                }
                Ok(Value::Object(public_identity_record(&updated)))
            })
        });
        let resource_id = string_member(&input, "identityId");
        let updated = self
            .run(
                credential,
                &input,
                "iam:identities:update",
                &resource_id,
                mutation,
            )
            .await?;
        let updated_id = crate::js::js_string(updated.get("id"));
        Ok(Reply::json(
            self.after_change(&input, vec![updated_id], updated).await?,
        ))
    }
}

/// `options.authentication?.sendEmail`: member invitations need an email delivery callback.
fn has_email_delivery(ctx: &ServerContext) -> bool {
    ctx.options
        .authentication
        .as_ref()
        .is_some_and(|authentication| authentication.send_email.is_some())
}
