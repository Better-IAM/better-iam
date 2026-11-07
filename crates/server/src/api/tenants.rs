//! Port of `packages/server/src/api/tenants.ts`: the `tenants` API group (creation with an owner invitation or
//! activated at once, sign-in discovery, regions, aliases, policies, plan limits, usage, incident response, moving,
//! status transitions, and owner invitations).

use std::sync::Arc;

use better_iam_auth::encrypt_secret;
use better_iam_auth::service::base::CreateIdentityInput;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, Record, Tenant, TenantStatus, ip_matches,
};
use better_iam_types::api::tenants;
use indexmap::IndexSet;
use serde_json::{Map, Value, json};

use crate::access_policy::tenant_access_policy;
use crate::api::{Body, Reply, string_member};
use crate::clearances::assert_scheme_kept;
use crate::context::{ServerContext, Store, slug};
use crate::contracts::{Mutation, MutationContext};
use crate::js::{invalid_input, truthy};
use crate::models::GrantAuthority;
use crate::port::{decode, encode};
use crate::privacy::assert_no_tenant_legal_hold;
use crate::utils::{all_value, date_now, hash, id, public_identity, token};
use crate::validation::{email, text};

pub use crate::tenant_policy::{tenant_auth_policy, tenant_limits};

/// The `tenants` API group (`createTenantsApi(ctx)`): one method per route `tenants/{method}`.
pub struct TenantsApi {
    ctx: Arc<ServerContext>,
}

/// `createTenantsApi(ctx)`.
pub fn create_tenants_api(ctx: &Arc<ServerContext>) -> IamResult<TenantsApi> {
    Ok(TenantsApi { ctx: ctx.clone() })
}

/// `stricterLimits(a = {}, b = {})`: per key, the stricter of two sets of plan limits (a key either one sets
/// applies); None when neither sets any.
fn stricter_limits(
    a: Option<&Map<String, Value>>,
    b: Option<&Map<String, Value>>,
) -> Option<Value> {
    let mut merged: Map<String, Value> = a.cloned().unwrap_or_default();
    if let Some(b) = b {
        for (key, value) in b {
            let replace = match merged.get(key) {
                None => true,
                Some(current) => match (
                    better_iam_core::js::as_number(value),
                    better_iam_core::js::as_number(current),
                ) {
                    (Some(value), Some(current)) => value < current,
                    _ => false,
                },
            };
            if replace {
                merged.insert(key.clone(), value.clone());
            }
        }
    }
    if merged.is_empty() {
        None
    } else {
        Some(Value::Object(merged))
    }
}

/// The stored record of a tenant the operation already loaded: `{ ...target }` keeps its member order and the
/// members this port does not declare.
async fn raw_tenant(tx: &Store, tenant: &Tenant) -> IamResult<Record> {
    match tx.get("tenants", &tenant.id).await? {
        Some(record) => Ok(record),
        None => Err(IamError::with_status("NOT_FOUND", "Tenant not found", 404)),
    }
}

fn deleted_guard(target: &Tenant) -> IamResult<()> {
    if target.status == TenantStatus::Deleted {
        return Err(IamError::new(
            "INVALID_TRANSITION",
            "Deleted tenants cannot be updated",
        ));
    }
    Ok(())
}

fn send_email_configured(ctx: &ServerContext) -> bool {
    ctx.options
        .authentication
        .as_ref()
        .is_some_and(|authentication| authentication.send_email.is_some())
}

fn delivery_required() -> IamError {
    IamError::new(
        "DELIVERY_REQUIRED",
        "Organization invitations require an email delivery callback",
    )
}

/// `({ tokenHash, uniqueKey, ...safe }) => safe`.
fn safe_invitation(mut record: Record) -> Value {
    record.shift_remove("tokenHash");
    record.shift_remove("uniqueKey");
    Value::Object(record)
}

fn str_member<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

/// `ctx.grantingAuthority(tx, principal, tenantId, input.authorityId)` for an unvalidated `authorityId`: a truthy
/// non-string value fails the record lookup's ID validation as it does in TypeScript.
async fn granting_authority(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    authority_id: Option<&Value>,
) -> IamResult<GrantAuthority> {
    match authority_id {
        Some(Value::String(authority)) => {
            ctx.granting_authority(tx, principal, tenant_id, Some(authority))
                .await
        }
        Some(value) if truthy(Some(value)) => {
            if principal
                .session
                .impersonator_id
                .as_deref()
                .is_some_and(|id| !id.is_empty())
            {
                return ctx.granting_authority(tx, principal, tenant_id, None).await;
            }
            Err(invalid_input("Invalid id"))
        }
        _ => ctx.granting_authority(tx, principal, tenant_id, None).await,
    }
}

/// The owner invitation email (`owner-invitation`) with the sealed token, in the tenant's outbox.
async fn queue_owner_invitation(
    ctx: &ServerContext,
    tx: &Store,
    realm_id: &str,
    realm_name: &str,
    to: &str,
    invite_token: &str,
    created_at: f64,
) -> IamResult<()> {
    let outbox_id = id();
    let mut sealed_payload = Map::new();
    sealed_payload.insert("token".into(), Value::String(invite_token.to_owned()));
    sealed_payload.insert("tenantId".into(), Value::String(realm_id.to_owned()));
    sealed_payload.insert("tenantName".into(), Value::String(realm_name.to_owned()));
    let sealed = encrypt_secret(
        &better_iam_core::js::stringify_object(&sealed_payload),
        &ctx.options.secret,
        &format!("outbox:{outbox_id}"),
    );
    let mut message = Map::new();
    message.insert("id".into(), Value::String(outbox_id));
    message.insert("tenantId".into(), Value::String(realm_id.to_owned()));
    message.insert("kind".into(), json!("email"));
    message.insert("to".into(), Value::String(to.to_owned()));
    message.insert("template".into(), json!("owner-invitation"));
    message.insert("payload".into(), json!({ "sealed": sealed }));
    message.insert("createdAt".into(), crate::js::number(created_at));
    message.insert("attempts".into(), crate::js::number(0.0));
    tx.insert("outbox", &message).await?;
    Ok(())
}

/// The IDs of `root` and every tenant below it, found level by level up to `maxDepth`.
fn subtree_of(realms: &[Tenant], root: &str, max_depth: f64) -> IndexSet<String> {
    let mut below: IndexSet<String> = IndexSet::new();
    below.insert(root.to_owned());
    let mut depth = 0.0;
    while depth < max_depth {
        for realm in realms {
            if let Some(parent) = realm
                .parent_id
                .as_deref()
                .filter(|parent| !parent.is_empty())
                && below.contains(parent)
            {
                below.insert(realm.id.clone());
            }
        }
        depth += 1.0;
    }
    below
}

/// Every tenant, as stored and typed.
async fn all_tenants(tx: &Store) -> IamResult<(Vec<Record>, Vec<Tenant>)> {
    let records = tx
        .find("tenants", &Filter::new(), &FindOptions::default())
        .await?;
    let mut typed = Vec::with_capacity(records.len());
    for record in &records {
        typed.push(decode::<Tenant>(record.clone())?);
    }
    Ok((records, typed))
}

impl TenantsApi {
    /// `discovery(tx, realm)`: what a sign-in screen learns about an organization (`TenantDiscovery`).
    async fn discovery(&self, tx: &Store, realm: &Tenant) -> IamResult<Value> {
        let hosts = self.ctx.hosts()?;
        let region = hosts.region_of(tx, realm).await?;
        let sign_in_url = hosts.sign_in_url_of(realm, Some(tx)).await?;
        let mut out = Map::new();
        out.insert("tenantId".into(), Value::String(realm.id.clone()));
        out.insert("name".into(), Value::String(realm.name.clone()));
        out.insert("type".into(), Value::String(realm.kind.clone()));
        out.insert(
            "slug".into(),
            Value::String(realm.slug.clone().unwrap_or_default()),
        );
        if let Some(region) = region.filter(|region| !region.is_empty()) {
            out.insert("region".into(), Value::String(region));
        }
        if let Some(url) = sign_in_url.filter(|url| !url.is_empty()) {
            out.insert("signInUrl".into(), Value::String(url));
        }
        Ok(Value::Object(out))
    }

    /// `tenants/acceptInvitation` (public: no credential).
    pub async fn accept_invitation(
        &self,
        input: Body<tenants::AcceptInvitationInput>,
    ) -> IamResult<Reply<tenants::AcceptInvitationOutput>> {
        Ok(Reply::json(
            self.ctx.flows()?.accept_owner_invitation(&input).await?,
        ))
    }

    /// `tenants/create`: a pending child tenant with an owner invitation, or (root only, `activate: true`) an active
    /// tenant with its owner account.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::CreateInput>,
    ) -> IamResult<Reply<tenants::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: parent,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let kind = text(body.get("type"), "type", 256)?;
                    let name = text(body.get("name"), "name", 256)?;
                    let owner_email = email(body.get("ownerEmail"))?;
                    for field in ["activate", "ownerEmailVerified"] {
                        if let Some(value) = body.get(field)
                            && !value.is_boolean()
                        {
                            return Err(invalid_input(format!("{field} must be a boolean")).into());
                        }
                    }
                    let activate = body.get("activate") == Some(&Value::Bool(true));
                    if !activate
                        && (body.get("ownerName").is_some()
                            || body.get("ownerEmailVerified").is_some())
                    {
                        return Err(invalid_input(
                            "ownerName and ownerEmailVerified need activate: true",
                        )
                        .into());
                    }
                    let owner_name = match body.get("ownerName") {
                        Some(value) => text(Some(value), "ownerName", 256)?,
                        None => owner_email.clone(),
                    };
                    // The invitation is the owner's consent to own the organization; skipping it is a platform
                    // decision.
                    if activate && !ctx.root_principal(&tx, &principal).await? {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "Only a root principal can create an active tenant without an owner invitation",
                            403,
                        )
                        .into());
                    }
                    if !activate && !send_email_configured(ctx) {
                        return Err(delivery_required().into());
                    }
                    if !ctx
                        .config
                        .hierarchy
                        .types
                        .get(&parent.kind)
                        .is_some_and(|definition| definition.allowed_children.contains(&kind))
                    {
                        return Err(IamError::new(
                            "INVALID_HIERARCHY",
                            "Child type is not permitted",
                        )
                        .into());
                    }
                    if ctx.ancestry(&tx, &parent).await?.len() as f64 >= ctx.config.max_depth {
                        return Err(
                            IamError::new("MAX_DEPTH", "Maximum tenant depth reached").into()
                        );
                    }
                    let parent_authority = granting_authority(
                        ctx,
                        &tx,
                        &principal,
                        &parent.id,
                        body.get("authorityId"),
                    )
                    .await?;
                    let realm_id = id();
                    let mut realm = Map::new();
                    realm.insert("id".into(), Value::String(realm_id.clone()));
                    realm.insert("tenantId".into(), Value::String(realm_id.clone()));
                    realm.insert("name".into(), Value::String(name));
                    realm.insert("type".into(), Value::String(kind));
                    realm.insert("parentId".into(), Value::String(parent.id.clone()));
                    realm.insert(
                        "status".into(),
                        json!(if activate { "active" } else { "pending" }),
                    );
                    if let Some(boundary) = body.get("boundary") {
                        realm.insert("boundary".into(), boundary.clone());
                    }
                    realm.insert("createdAt".into(), crate::js::number(date_now()));
                    // Plan defaults for every new tenant, never looser than its parent's own plan (the stricter
                    // value wins per key), so an organization cannot escape its limits through child projects. The
                    // root tenant's limits are the platform's own and are not passed on.
                    let defaults = ctx.config.tenant_defaults.limits.as_ref().map(encode);
                    let parent_limits = if parent.parent_id.is_some() {
                        parent.limits.as_ref().map(encode)
                    } else {
                        None
                    };
                    if let Some(limits) = stricter_limits(defaults.as_ref(), parent_limits.as_ref())
                    {
                        realm.insert("limits".into(), limits);
                    }
                    if let Some(policy) = &ctx.config.tenant_defaults.auth_policy {
                        realm.insert("authPolicy".into(), Value::Object(encode(policy)));
                    }
                    if let Some(boundary) = body.get("boundary")
                        && truthy(Some(boundary))
                    {
                        ctx.catalog
                            .validate(tx.as_ref(), &realm_id, boundary)
                            .await?;
                    }
                    if body.get("slug").is_some() {
                        let alias = ctx.claim_slug(&tx, &realm_id, body.get("slug")).await?;
                        realm.insert("slug".into(), Value::String(alias));
                    }
                    if let Some(region) = ctx
                        .hosts()?
                        .region_for_new(&tx, &parent, body.get("region"))
                        .await?
                        .filter(|region| !region.is_empty())
                    {
                        realm.insert("region".into(), Value::String(region));
                    }
                    tx.insert("tenants", &realm).await?;
                    let mut authority = Map::new();
                    authority.insert("id".into(), Value::String(id()));
                    authority.insert("tenantId".into(), Value::String(realm_id.clone()));
                    authority.insert("identityId".into(), json!("pending"));
                    authority.insert(
                        "parentAuthorityId".into(),
                        Value::String(parent_authority.id.clone()),
                    );
                    authority.insert("ceiling".into(), all_value());
                    authority.insert("revoked".into(), Value::Bool(false));
                    let authority: GrantAuthority =
                        decode(tx.insert("grantAuthorities", &authority).await?)?;
                    if activate {
                        let owner = ctx
                            .auth
                            .create_identity(
                                &tx,
                                CreateIdentityInput {
                                    tenant_id: realm_id.clone(),
                                    email: owner_email.clone(),
                                    name: owner_name,
                                    password: None,
                                    owner: Some(true),
                                    root_admin: None,
                                    email_verified: Some(
                                        body.get("ownerEmailVerified") == Some(&Value::Bool(true)),
                                    ),
                                },
                            )
                            .await?;
                        let typed: Tenant = decode(realm.clone())?;
                        ctx.owner_setup(&tx, &typed, &owner, &authority).await?;
                        let mut metadata = Map::new();
                        metadata.insert("ownerId".into(), Value::String(owner.id.clone()));
                        metadata.insert("invitation".into(), Value::Bool(false));
                        ctx.events()?
                            .audit(
                                &tx,
                                &principal,
                                "tenant:activate",
                                &realm_id,
                                &realm_id,
                                AuditOutcome::Allow,
                                false,
                                Some(metadata),
                            )
                            .await?;
                        let mut out = Map::new();
                        out.insert("tenant".into(), Value::Object(realm));
                        out.insert("ownerEmail".into(), Value::String(owner_email));
                        out.insert("owner".into(), Value::Object(public_identity(&owner)));
                        return Ok(Value::Object(out));
                    }
                    let invite_token = token();
                    let mut invitation = Map::new();
                    invitation.insert("id".into(), Value::String(id()));
                    invitation.insert("tenantId".into(), Value::String(realm_id.clone()));
                    invitation.insert("email".into(), Value::String(owner_email.clone()));
                    invitation.insert("tokenHash".into(), Value::String(hash(&invite_token)));
                    invitation.insert("uniqueKey".into(), Value::String(hash(&invite_token)));
                    invitation.insert("authorityId".into(), Value::String(authority.id.clone()));
                    invitation.insert("createdAt".into(), crate::js::number(date_now()));
                    invitation.insert(
                        "expiresAt".into(),
                        crate::js::number(date_now() + ctx.config.invitation_lifetime_ms),
                    );
                    invitation.insert("consumed".into(), Value::Bool(false));
                    invitation.insert(
                        "creatorId".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let invitation = tx.insert("ownerInvitations", &invitation).await?;
                    let realm_name = str_member(&realm, "name").unwrap_or_default().to_owned();
                    queue_owner_invitation(
                        ctx,
                        &tx,
                        &realm_id,
                        &realm_name,
                        &owner_email,
                        &invite_token,
                        date_now(),
                    )
                    .await?;
                    let mut out = Map::new();
                    out.insert("tenant".into(), Value::Object(realm));
                    out.insert(
                        "invitationId".into(),
                        invitation.get("id").cloned().unwrap_or(Value::Null),
                    );
                    out.insert("ownerEmail".into(), Value::String(owner_email));
                    Ok(Value::Object(out))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("parentId"),
                "iam:tenants:create",
                &string_member(&input, "parentId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `tenants/get`.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::GetInput>,
    ) -> IamResult<Reply<tenants::GetOutput>> {
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move { Ok(Value::Object(raw_tenant(&tx, &tenant).await?)) })
        });
        let result = self
            .ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:tenants:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `tenants/listChildren`.
    pub async fn list_children(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::ListChildrenInput>,
    ) -> IamResult<Reply<tenants::ListChildrenOutput>> {
        let tenant_id = input.get("tenantId").cloned().unwrap_or(Value::Null);
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let children = tx
                    .find(
                        "tenants",
                        &Filter::new().eq("parentId", tenant_id),
                        &FindOptions::default(),
                    )
                    .await?;
                Ok(Value::Array(
                    children.into_iter().map(Value::Object).collect(),
                ))
            })
        });
        let result = self
            .ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:tenants:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `tenants/listInvitations`: the tenant's owner invitations without their token hashes.
    pub async fn list_invitations(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::ListInvitationsInput>,
    ) -> IamResult<Reply<tenants::ListInvitationsOutput>> {
        let tenant_id = input.get("tenantId").cloned().unwrap_or(Value::Null);
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let invitations = tx
                    .find(
                        "ownerInvitations",
                        &Filter::new().eq("tenantId", tenant_id),
                        &FindOptions::default(),
                    )
                    .await?;
                Ok(Value::Array(
                    invitations.into_iter().map(safe_invitation).collect(),
                ))
            })
        });
        let result = self
            .ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:tenants:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `tenants/lookup` (public: no credential): resolves an active tenant by its alias or by an address it signs in
    /// at; an organization homed in another region answers `WRONG_REGION`.
    pub async fn lookup(
        &self,
        input: Body<tenants::LookupInput>,
    ) -> IamResult<Reply<tenants::LookupOutput>> {
        let ctx = &self.ctx;
        if input.get("host").is_some() {
            let host = text(input.get("host"), "host", 260)?;
            let found = ctx
                .store
                .transaction(|tx| {
                    let host = &host;
                    async move {
                        let hosts = ctx.hosts()?;
                        let Some(matched) = hosts.resolve(host, Some(&tx)).await? else {
                            return Err(IamError::with_status(
                                "NOT_FOUND",
                                "Organization not found",
                                404,
                            ));
                        };
                        let realm = ctx.tenant(&tx, &matched.tenant_id).await?;
                        hosts
                            .assert_served_here(&tx, &realm, matched.host_region.as_deref())
                            .await?;
                        self.discovery(&tx, &realm).await
                    }
                })
                .await?;
            return Ok(Reply::json(found));
        }
        let alias = slug(input.get("slug"))?;
        // Some(Some(discovery)) for an active organization, Some(None) for an inactive one, None for an unknown alias.
        let found: Option<Option<Value>> = ctx
            .store
            .transaction(|tx| {
                let alias = &alias;
                async move {
                    let record = tx.get("tenantAliases", alias).await?;
                    let realm = match record
                        .as_ref()
                        .and_then(|record| str_member(record, "tenantId"))
                    {
                        Some(tenant_id) => tx.get("tenants", tenant_id).await?,
                        None => None,
                    };
                    let realm = match realm {
                        Some(realm) => Some(decode::<Tenant>(realm)?),
                        None => None,
                    };
                    let usable = match &realm {
                        Some(realm) if realm.status == TenantStatus::Active => !ctx
                            .ancestry(&tx, realm)
                            .await?
                            .iter()
                            .any(|item| item.status != TenantStatus::Active),
                        _ => false,
                    };
                    let Some(realm) = realm.filter(|_| usable) else {
                        return Ok(record.map(|_| None));
                    };
                    ctx.hosts()?.assert_served_here(&tx, &realm, None).await?;
                    Ok(Some(Some(self.discovery(&tx, &realm).await?)))
                }
            })
            .await?;
        if let Some(Some(discovery)) = found {
            return Ok(Reply::json(discovery));
        }
        // An alias this region's database does not know may live in another region (`regions.locate`).
        if found.is_none()
            && let Some(elsewhere) = ctx.hosts()?.remote_alias(&alias).await
        {
            return Err(elsewhere.into());
        }
        Err(IamError::with_status(
            "NOT_FOUND",
            "Organization not found",
            404,
        ))
    }

    /// `tenants/reparent`: moves a tenant under a new parent with hierarchy, depth, cycle, and destination-authority
    /// checks.
    pub async fn reparent(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::ReparentInput>,
    ) -> IamResult<Reply<tenants::ReparentOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: target,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let parent = ctx
                        .tenant(&tx, &text(body.get("parentId"), "parentId", 256)?)
                        .await?;
                    if target.parent_id.is_none()
                        || target.status == TenantStatus::Pending
                        || target.status == TenantStatus::Deleted
                    {
                        return Err(
                            IamError::new("INVALID_TRANSITION", "Tenant cannot be moved").into(),
                        );
                    }
                    if Some(&parent.id) == target.parent_id.as_ref() {
                        return Err(invalid_input("Tenant is already under this parent").into());
                    }
                    if parent.status != TenantStatus::Active
                        || ctx
                            .ancestry(&tx, &parent)
                            .await?
                            .iter()
                            .any(|item| item.status != TenantStatus::Active)
                    {
                        return Err(IamError::new(
                            "TENANT_INACTIVE",
                            "New parent ancestry must be active",
                        )
                        .into());
                    }
                    if !ctx
                        .config
                        .hierarchy
                        .types
                        .get(&parent.kind)
                        .is_some_and(|definition| {
                            definition.allowed_children.contains(&target.kind)
                        })
                    {
                        return Err(IamError::new(
                            "INVALID_HIERARCHY",
                            "Child type is not permitted under the new parent",
                        )
                        .into());
                    }
                    let (_, realms) = all_tenants(&tx).await?;
                    let mut subtree: IndexSet<String> = IndexSet::new();
                    subtree.insert(target.id.clone());
                    let mut frontier: Vec<String> = vec![target.id.clone()];
                    let mut height = 1.0;
                    let mut depth = 0.0;
                    while depth < ctx.config.max_depth && !frontier.is_empty() {
                        let next: Vec<String> = realms
                            .iter()
                            .filter(|realm| {
                                realm
                                    .parent_id
                                    .as_deref()
                                    .filter(|parent| !parent.is_empty())
                                    .is_some_and(|parent| frontier.iter().any(|id| id == parent))
                            })
                            .map(|realm| realm.id.clone())
                            .collect();
                        if !next.is_empty() {
                            height += 1.0;
                            for child in &next {
                                subtree.insert(child.clone());
                            }
                        }
                        frontier = next;
                        depth += 1.0;
                    }
                    if subtree.contains(&parent.id) {
                        return Err(IamError::new(
                            "INVALID_HIERARCHY",
                            "Cannot move a tenant under its own subtree",
                        )
                        .into());
                    }
                    if ctx.ancestry(&tx, &parent).await?.len() as f64 + height
                        > ctx.config.max_depth
                    {
                        return Err(
                            IamError::new("MAX_DEPTH", "Maximum tenant depth reached").into()
                        );
                    }
                    granting_authority(ctx, &tx, &principal, &parent.id, body.get("authorityId"))
                        .await?;
                    // Security clearances: never out from under the scheme its labels and clearances were written
                    // under.
                    let subtree_value =
                        Value::Array(subtree.iter().cloned().map(Value::String).collect());
                    assert_scheme_kept(ctx, &tx, &target, &parent, &subtree_value).await?;
                    let mut next = raw_tenant(&tx, &target).await?;
                    next.insert("parentId".into(), Value::String(parent.id.clone()));
                    let result = tx.put("tenants", &next).await?;
                    let mut metadata = Map::new();
                    metadata.insert(
                        "from".into(),
                        target
                            .parent_id
                            .clone()
                            .map(Value::String)
                            .unwrap_or(Value::Null),
                    );
                    metadata.insert("to".into(), Value::String(parent.id.clone()));
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "tenant:reparent",
                            &target.id,
                            &target.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(Value::Object(result))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:tenants:update",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `tenants/resendInvitation`: a fresh token and lifetime; the earlier token stops working.
    pub async fn resend_invitation(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::ResendInvitationInput>,
    ) -> IamResult<Reply<tenants::ResendInvitationOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: realm,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    if !send_email_configured(ctx) {
                        return Err(delivery_required().into());
                    }
                    let mut invitation = ctx
                        .scoped(
                            &tx,
                            "ownerInvitations",
                            body.get("invitationId"),
                            &string_member(body, "tenantId"),
                        )
                        .await?;
                    if truthy(invitation.get("consumed")) || truthy(invitation.get("revoked")) {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "Invitation is already consumed or revoked",
                            409,
                        )
                        .into());
                    }
                    let invite_token = token();
                    let now = date_now();
                    invitation.insert("tokenHash".into(), Value::String(hash(&invite_token)));
                    invitation.insert("uniqueKey".into(), Value::String(hash(&invite_token)));
                    invitation.insert("createdAt".into(), crate::js::number(now));
                    invitation.insert(
                        "expiresAt".into(),
                        crate::js::number(now + ctx.config.invitation_lifetime_ms),
                    );
                    let renewed = tx.put("ownerInvitations", &invitation).await?;
                    let to = str_member(&invitation, "email")
                        .unwrap_or_default()
                        .to_owned();
                    queue_owner_invitation(
                        ctx,
                        &tx,
                        &realm.id,
                        &realm.name,
                        &to,
                        &invite_token,
                        now,
                    )
                    .await?;
                    let mut out = Map::new();
                    out.insert(
                        "invitationId".into(),
                        renewed.get("id").cloned().unwrap_or(Value::Null),
                    );
                    if let Some(email) = renewed.get("email") {
                        out.insert("email".into(), email.clone());
                    }
                    if let Some(expires_at) = renewed.get("expiresAt") {
                        out.insert("expiresAt".into(), expires_at.clone());
                    }
                    Ok(Value::Object(out))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:tenants:update",
                &string_member(&input, "invitationId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `tenants/revokeInvitation`.
    pub async fn revoke_invitation(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::RevokeInvitationInput>,
    ) -> IamResult<Reply<tenants::RevokeInvitationOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let mut invitation = ctx
                    .scoped(
                        &tx,
                        "ownerInvitations",
                        body.get("invitationId"),
                        &string_member(body, "tenantId"),
                    )
                    .await?;
                if truthy(invitation.get("consumed")) || truthy(invitation.get("revoked")) {
                    return Err(IamError::with_status(
                        "CONFLICT",
                        "Invitation is already consumed or revoked",
                        409,
                    )
                    .into());
                }
                invitation.insert("revoked".into(), Value::Bool(true));
                Ok(safe_invitation(
                    tx.put("ownerInvitations", &invitation).await?,
                ))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:tenants:update",
                &string_member(&input, "invitationId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `tenants/revokeSessions`: incident response; ends every user session in the tenant (the caller's own is kept
    /// unless `includeSelf`) and forgets its remembered devices.
    pub async fn revoke_sessions(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::RevokeSessionsInput>,
    ) -> IamResult<Reply<tenants::RevokeSessionsOutput>> {
        let ctx = &self.ctx;
        let include_self = input.get("includeSelf") == Some(&Value::Bool(true));
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: target,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    if target.parent_id.is_none() && !ctx.root_principal(&tx, &principal).await? {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "Only root administrators can sign everyone out of the root tenant",
                            403,
                        )
                        .into());
                    }
                    let mut revoked = 0.0;
                    for session in tx
                        .find("sessions", &Filter::new(), &FindOptions::default())
                        .await?
                    {
                        let session_id = str_member(&session, "id").unwrap_or_default();
                        if (str_member(&session, "tenantId") == Some(target.id.as_str())
                            || str_member(&session, "sourceTenantId") == Some(target.id.as_str()))
                            && (include_self || session_id != principal.session.id)
                        {
                            // endSession also removes the impersonation sessions an administrator opened through
                            // this one.
                            ctx.auth.end_session(&tx, session_id).await?;
                            revoked += 1.0;
                        }
                    }
                    // Remembered devices are forgotten too, or a stolen password plus device cookie would still skip
                    // MFA after "sign everyone out". The caller keeps theirs when they keep their own session.
                    for device in tx
                        .find(
                            "authDevices",
                            &Filter::new().eq("tenantId", target.id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        if include_self
                            || str_member(&device, "identityId")
                                != Some(principal.identity.id.as_str())
                        {
                            tx.delete("authDevices", str_member(&device, "id").unwrap_or_default())
                                .await?;
                        }
                    }
                    let mut metadata = Map::new();
                    metadata.insert("revoked".into(), crate::js::number(revoked));
                    metadata.insert("includeSelf".into(), Value::Bool(include_self));
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "tenant:revoke-sessions",
                            &target.id,
                            &target.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(json!({ "revoked": crate::js::number(revoked) }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:tenants:update",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `tenants/setAccessPolicy`: organization-wide floors for just-in-time activation; `null` clears them.
    pub async fn set_access_policy(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::SetAccessPolicyInput>,
    ) -> IamResult<Reply<tenants::SetAccessPolicyOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: target,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    deleted_guard(&target)?;
                    let mut next = raw_tenant(&tx, &target).await?;
                    next.shift_remove("accessPolicy");
                    if body.get("accessPolicy") != Some(&Value::Null) {
                        let policy = encode(&tenant_access_policy(body.get("accessPolicy"))?);
                        if !policy.is_empty() {
                            next.insert("accessPolicy".into(), Value::Object(policy));
                        }
                    }
                    let result = tx.put("tenants", &next).await?;
                    let mut metadata = Map::new();
                    metadata.insert(
                        "accessPolicy".into(),
                        next.get("accessPolicy").cloned().unwrap_or(Value::Null),
                    );
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "tenant:access-policy",
                            &target.id,
                            &target.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(Value::Object(result))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:tenants:update",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `tenants/setAuthPolicy`: sets or clears (null) the tenant's authentication policy.
    pub async fn set_auth_policy(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::SetAuthPolicyInput>,
    ) -> IamResult<Reply<tenants::SetAuthPolicyOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: target,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    deleted_guard(&target)?;
                    // A platform staff member's allowlist or method restriction on the root tenant would lock every
                    // root administrator out, and bootstrap recovery signs in there too.
                    if target.parent_id.is_none() && !ctx.root_principal(&tx, &principal).await? {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "The root tenant\u{2019}s authentication policy is set by root administrators",
                            403,
                        )
                        .into());
                    }
                    let mut next = raw_tenant(&tx, &target).await?;
                    next.shift_remove("authPolicy");
                    let mut ranges: Vec<String> = Vec::new();
                    if body.get("authPolicy") != Some(&Value::Null) {
                        let policy = tenant_auth_policy(body.get("authPolicy"))?;
                        ranges = policy.allowed_ip_ranges.clone().unwrap_or_default();
                        next.insert("authPolicy".into(), Value::Object(encode(&policy)));
                    }
                    // Like blockNetwork's self-lockout guard: an allowlist that leaves out the address the caller's
                    // session was issued from, or the one this request comes from, is refused. Only the caller's
                    // own organization's allowlist judges them.
                    if !ranges.is_empty() && principal.session.tenant_id == target.id {
                        let addresses = [
                            principal
                                .session
                                .client
                                .as_ref()
                                .and_then(|client| client.ip.clone()),
                            ctx.auth.current_client().and_then(|client| client.ip),
                        ];
                        for ip in addresses.into_iter().flatten() {
                            if !ranges.iter().any(|range| ip_matches(&ip, range)) {
                                return Err(invalid_input(
                                    "allowedIpRanges must include your own address",
                                )
                                .into());
                            }
                        }
                    }
                    let result = tx.put("tenants", &next).await?;
                    let mut metadata = Map::new();
                    metadata.insert(
                        "authPolicy".into(),
                        next.get("authPolicy").cloned().unwrap_or(Value::Null),
                    );
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "tenant:auth-policy",
                            &target.id,
                            &target.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(Value::Object(result))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:tenants:update",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `tenants/setBoundary`: the tenant ceiling, platform controlled.
    pub async fn set_boundary(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::SetBoundaryInput>,
    ) -> IamResult<Reply<tenants::SetBoundaryOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: target,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let boundary = body.get("boundary");
                    ctx.catalog
                        .validate(tx.as_ref(), &target.id, boundary.unwrap_or(&Value::Null))
                        .await?;
                    if !ctx.root_principal(&tx, &principal).await? {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "Tenant ceilings are platform controlled",
                            403,
                        )
                        .into());
                    }
                    let mut next = raw_tenant(&tx, &target).await?;
                    match boundary {
                        Some(boundary) => {
                            next.insert("boundary".into(), boundary.clone());
                        }
                        None => {
                            next.shift_remove("boundary");
                        }
                    }
                    Ok(Value::Object(tx.put("tenants", &next).await?))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:boundaries:update",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `tenants/setLimits`: platform-controlled plan limits (root only); descendants are tightened per key.
    pub async fn set_limits(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::SetLimitsInput>,
    ) -> IamResult<Reply<tenants::SetLimitsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: target,
             }| {
                Box::pin(async move {
                    deleted_guard(&target)?;
                    let mut next = raw_tenant(&tx, &target).await?;
                    next.shift_remove("limits");
                    let mut limits: Option<Map<String, Value>> = None;
                    if body.get("limits") != Some(&Value::Null) {
                        let parsed = encode(&tenant_limits(body.get("limits"))?);
                        next.insert("limits".into(), Value::Object(parsed.clone()));
                        limits = Some(parsed);
                    }
                    let result = tx.put("tenants", &next).await?;
                    if let Some(limits) = &limits
                        && target.parent_id.is_some()
                    {
                        let (records, realms) = all_tenants(&tx).await?;
                        let below = subtree_of(&realms, &target.id, ctx.config.max_depth);
                        for record in records {
                            let realm_id = str_member(&record, "id").unwrap_or_default();
                            if realm_id == target.id || !below.contains(realm_id) {
                                continue;
                            }
                            let current = match record.get("limits") {
                                Some(Value::Object(current)) => Some(current.clone()),
                                _ => None,
                            };
                            let Some(tightened) = stricter_limits(current.as_ref(), Some(limits))
                            else {
                                continue;
                            };
                            let previous = Value::Object(current.unwrap_or_default());
                            if better_iam_core::js::stringify(&tightened)
                                != better_iam_core::js::stringify(&previous)
                            {
                                let mut updated = record.clone();
                                updated.insert("limits".into(), tightened);
                                tx.put("tenants", &updated).await?;
                            }
                        }
                    }
                    let mut metadata = Map::new();
                    metadata.insert(
                        "limits".into(),
                        limits.map(Value::Object).unwrap_or(Value::Null),
                    );
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "tenant:limits",
                            &target.id,
                            &target.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(Value::Object(result))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:tenants:update",
                &string_member(&input, "tenantId"),
                mutation,
                true,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `tenants/setRegion`: moves a tenant's home region (root administrators only); `null` inherits the parent's.
    pub async fn set_region(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::SetRegionInput>,
    ) -> IamResult<Reply<tenants::SetRegionOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: target,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    deleted_guard(&target)?;
                    let hosts = ctx.hosts()?;
                    let from = hosts.region_of(&tx, &target).await?;
                    let mut next = raw_tenant(&tx, &target).await?;
                    next.shift_remove("region");
                    if body.get("region") != Some(&Value::Null) {
                        next.insert(
                            "region".into(),
                            Value::String(hosts.region(body.get("region"))?),
                        );
                    } else if target.parent_id.is_none() {
                        return Err(invalid_input(
                            "The root tenant has no parent to inherit a region from",
                        )
                        .into());
                    }
                    let result = tx.put("tenants", &next).await?;
                    let typed: Tenant = decode(next)?;
                    let to = hosts.region_of(&tx, &typed).await?;
                    let mut metadata = Map::new();
                    metadata.insert(
                        "from".into(),
                        from.map(Value::String).unwrap_or(Value::Null),
                    );
                    metadata.insert("to".into(), to.map(Value::String).unwrap_or(Value::Null));
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "tenant:region",
                            &target.id,
                            &target.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(Value::Object(result))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:tenants:update",
                &string_member(&input, "tenantId"),
                mutation,
                true,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `tenants/setSlug`: changes or clears (null) the sign-in alias.
    pub async fn set_slug(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::SetSlugInput>,
    ) -> IamResult<Reply<tenants::SetSlugOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: target,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    deleted_guard(&target)?;
                    if let Some(previous) = &target.slug {
                        tx.delete("tenantAliases", previous).await?;
                    }
                    let mut next = raw_tenant(&tx, &target).await?;
                    next.shift_remove("slug");
                    if body.get("slug") != Some(&Value::Null) {
                        let alias = ctx.claim_slug(&tx, &target.id, body.get("slug")).await?;
                        next.insert("slug".into(), Value::String(alias));
                    }
                    Ok(Value::Object(tx.put("tenants", &next).await?))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:tenants:update",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `tenants/setStatus`: suspension and deletion cascade to descendants and revoke their sessions; deletion starts
    /// the retention window.
    pub async fn set_status(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::SetStatusInput>,
    ) -> IamResult<Reply<tenants::SetStatusOutput>> {
        let ctx = &self.ctx;
        let status = input.get("status").cloned();
        let deleting = status.as_ref().and_then(Value::as_str) == Some("deleted");
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: target,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let wanted = status
                        .as_ref()
                        .and_then(Value::as_str)
                        .filter(|status| ["active", "suspended", "deleted"].contains(status));
                    let Some(wanted) = wanted.filter(|wanted| {
                        target.parent_id.is_some()
                            && target.status != TenantStatus::Deleted
                            && (target.status != TenantStatus::Pending || *wanted == "deleted")
                    }) else {
                        return Err(IamError::new(
                            "INVALID_TRANSITION",
                            "Tenant cannot make this transition",
                        )
                        .into());
                    };
                    if wanted == "active"
                        && let Some(parent_id) = target
                            .parent_id
                            .as_deref()
                            .filter(|parent| !parent.is_empty())
                    {
                        let parent = ctx.tenant(&tx, parent_id).await?;
                        if ctx
                            .ancestry(&tx, &parent)
                            .await?
                            .iter()
                            .any(|item| item.status != TenantStatus::Active)
                        {
                            return Err(
                                IamError::new("TENANT_INACTIVE", "Parent must be active").into()
                            );
                        }
                    }
                    // Legal holds (privacy.ts) keep people's data: an organization with an active hold cannot be
                    // deleted.
                    if wanted == "deleted" {
                        assert_no_tenant_legal_hold(
                            &tx,
                            &target.id,
                            ctx.now(),
                            ctx.config.max_depth,
                        )
                        .await?;
                    }
                    let now = date_now();
                    let mut next = raw_tenant(&tx, &target).await?;
                    next.insert("status".into(), Value::String(wanted.to_owned()));
                    if wanted == "deleted" {
                        let deleted_at = next
                            .get("deletedAt")
                            .filter(|value| !value.is_null())
                            .cloned()
                            .unwrap_or_else(|| crate::js::number(now));
                        next.insert("deletedAt".into(), deleted_at);
                    }
                    let result = tx.put("tenants", &next).await?;
                    if wanted != "active" {
                        let (records, realms) = all_tenants(&tx).await?;
                        let affected = subtree_of(&realms, &target.id, ctx.config.max_depth);
                        for session in tx
                            .find("sessions", &Filter::new(), &FindOptions::default())
                            .await?
                        {
                            let in_tenant = str_member(&session, "tenantId")
                                .is_some_and(|tenant| affected.contains(tenant));
                            let sourced = str_member(&session, "sourceTenantId")
                                .filter(|source| !source.is_empty())
                                .is_some_and(|source| affected.contains(source));
                            if in_tenant || sourced {
                                tx.delete(
                                    "sessions",
                                    str_member(&session, "id").unwrap_or_default(),
                                )
                                .await?;
                            }
                        }
                        if wanted == "deleted" {
                            for mut realm in records {
                                let realm_id =
                                    str_member(&realm, "id").unwrap_or_default().to_owned();
                                if affected.contains(&realm_id) && realm_id != target.id {
                                    realm.insert("status".into(), json!("deleted"));
                                    let deleted_at = realm
                                        .get("deletedAt")
                                        .filter(|value| !value.is_null())
                                        .cloned()
                                        .unwrap_or_else(|| crate::js::number(now));
                                    realm.insert("deletedAt".into(), deleted_at);
                                    tx.put("tenants", &realm).await?;
                                }
                            }
                        }
                    }
                    Ok(Value::Object(result))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                if deleting {
                    "iam:tenants:delete"
                } else {
                    "iam:tenants:update"
                },
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `tenants/update`: renames the tenant.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::UpdateInput>,
    ) -> IamResult<Reply<tenants::UpdateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: target,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    deleted_guard(&target)?;
                    let mut next = raw_tenant(&tx, &target).await?;
                    next.insert(
                        "name".into(),
                        Value::String(text(body.get("name"), "name", 256)?),
                    );
                    Ok(Value::Object(tx.put("tenants", &next).await?))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:tenants:update",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `tenants/usage`: current record counts against the tenant's plan limits.
    pub async fn usage(
        &self,
        credential: &CredentialInput,
        input: Body<tenants::UsageInput>,
    ) -> IamResult<Reply<tenants::UsageOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx, tenant: target, ..
             }| {
                Box::pin(async move {
                    let of_tenant = || Filter::new().eq("tenantId", target.id.clone());
                    let all = FindOptions::default();
                    let identities = tx.find("identities", &of_tenant(), &all).await?;
                    let sessions = tx
                        .find("sessions", &of_tenant().eq("kind", "user"), &all)
                        .await?;
                    let deleted = |record: &Record| str_member(record, "status") == Some("deleted");
                    let people: Vec<&Record> = identities
                        .iter()
                        .filter(|identity| {
                            str_member(identity, "kind") == Some("user") && !deleted(identity)
                        })
                        .collect();
                    // MFA adoption: people with an enabled authenticator or at least one passkey.
                    let mut with_factor: IndexSet<String> = IndexSet::new();
                    for record in tx.find("authMfa", &of_tenant(), &all).await? {
                        if truthy(record.get("enabled")) {
                            with_factor.insert(
                                str_member(&record, "identityId")
                                    .unwrap_or_default()
                                    .to_owned(),
                            );
                        }
                    }
                    for key in tx.find("authPasskeys", &of_tenant(), &all).await? {
                        with_factor.insert(
                            str_member(&key, "identityId")
                                .unwrap_or_default()
                                .to_owned(),
                        );
                    }
                    let mfa_enrolled = people
                        .iter()
                        .filter(|identity| {
                            with_factor.contains(str_member(identity, "id").unwrap_or_default())
                        })
                        .count();
                    let service_accounts = identities
                        .iter()
                        .filter(|identity| {
                            str_member(identity, "kind") == Some("service") && !deleted(identity)
                        })
                        .count();
                    let mut out = Map::new();
                    out.insert("tenantId".into(), Value::String(target.id.clone()));
                    out.insert("identities".into(), crate::js::number(people.len() as f64));
                    out.insert("mfaEnrolled".into(), crate::js::number(mfa_enrolled as f64));
                    out.insert(
                        "serviceAccounts".into(),
                        crate::js::number(service_accounts as f64),
                    );
                    for collection in [
                        "groups",
                        "roles",
                        "policies",
                        "resources",
                        "relationships",
                        "webhooks",
                    ] {
                        let count = tx.find(collection, &of_tenant(), &all).await?.len();
                        out.insert(collection.into(), crate::js::number(count as f64));
                    }
                    let now = ctx.now();
                    let active = sessions
                        .iter()
                        .filter(|session| {
                            session
                                .get("expiresAt")
                                .and_then(better_iam_core::js::as_number)
                                .is_some_and(|expires_at| expires_at > now)
                        })
                        .count();
                    out.insert("activeSessions".into(), crate::js::number(active as f64));
                    let limits = raw_tenant(&tx, &target)
                        .await?
                        .get("limits")
                        .filter(|limits| !limits.is_null())
                        .cloned()
                        .unwrap_or_else(|| Value::Object(Map::new()));
                    out.insert("limits".into(), limits);
                    Ok(Value::Object(out))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:tenants:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stricter_limits_takes_the_lower_value_per_key() {
        let a = json!({ "identities": 5, "groups": 3 });
        let b = json!({ "identities": 2, "roles": 7, "groups": 4 });
        assert_eq!(
            stricter_limits(a.as_object(), b.as_object()),
            Some(json!({ "identities": 2, "groups": 3, "roles": 7 }))
        );
        assert_eq!(stricter_limits(None, None), None);
        assert_eq!(stricter_limits(None, b.as_object()), Some(b.clone()));
    }
}
