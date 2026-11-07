//! Port of `packages/server/src/federation.ts`: the trusted callbacks handed to protocol packages (OAuth, SAML,
//! SCIM), never HTTP endpoints. [`Federation`] is both the object `createFederation` returns
//! (`completeAuthentication`, `syncRoleMappings`) and its `protocolHost`, whose members are the methods of this struct.

use std::sync::Arc;

use better_iam_auth::service::base::CreateIdentityRaw;
use better_iam_core::{
    AuditOutcome, AuthMethod, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions,
    IamError, IamResult, IamStoreExt, IdentityKind, IdentityStatus, Record, SessionKind,
    js as core_js,
};
use serde_json::{Map, Value, json};

use crate::api::{Body, credential_from_json, string_member};
use crate::applications::app_client_allowed;
use crate::catalog::attribute_values;
use crate::context::{ServerContext, Store};
use crate::js::{js_string, truthy};
use crate::licenses::{reconcile_identity_licenses, release_group_licenses};
use crate::port::decode;
use crate::teams::sync_teams_from_groups;
use crate::utils::id;
use crate::validation::email;

/// Every record of a collection matching the filter.
async fn find_records(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

/// A member of a JSON object (`input.key`), None when absent or when `input` is not an object.
fn member<'a>(input: &'a Value, key: &str) -> Option<&'a Value> {
    input.as_object().and_then(|map| map.get(key))
}

/// `String(member)`.
fn member_text(input: &Value, key: &str) -> String {
    js_string(member(input, key))
}

/// A member as a filter value (`undefined` matches as `null`).
fn filter_value(input: &Value, key: &str) -> Value {
    member(input, key).cloned().unwrap_or(Value::Null)
}

/// Whether a first federated sign-in may link to `identity` because a trusted SCIM connection provisioned it: the
/// connection trusts SCIM (`trust`), the identity is an ordinary active person (never an owner or root administrator,
/// which SCIM never provisions anyway), and a SCIM user of a listed, unrevoked connection of the tenant is backed by it.
async fn scim_provisioned(
    tx: &Store,
    identity: &better_iam_core::Identity,
    trust: Option<&Value>,
) -> IamResult<bool> {
    let listed = match trust {
        Some(Value::Bool(true)) => None,
        Some(Value::Array(items)) if !items.is_empty() => Some(items),
        _ => return Ok(false),
    };
    if identity.kind != IdentityKind::User
        || identity.status != IdentityStatus::Active
        || identity.owner
        || identity.root_admin
    {
        return Ok(false);
    }
    for link in find_records(
        tx,
        "scimUsers",
        Filter::new()
            .eq("tenantId", identity.tenant_id.clone())
            .eq("identityId", identity.id.clone()),
    )
    .await?
    {
        let connection_id = js_string(link.get("connectionId"));
        if let Some(listed) = listed
            && !listed.contains(&Value::String(connection_id.clone()))
        {
            continue;
        }
        let connection = tx.get("scimConnections", &connection_id).await?;
        if let Some(connection) = connection
            && connection.get("tenantId").and_then(Value::as_str) == Some(&identity.tenant_id)
            && connection.get("revoked") != Some(&Value::Bool(true))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Trusted callbacks handed to protocol packages (OAuth, SAML, SCIM); never HTTP endpoints.
pub struct Federation {
    ctx: Arc<ServerContext>,
    bindings: Arc<crate::api::bindings::BindingsApi>,
}

/// `createFederation(ctx, bindings)`.
pub fn create_federation(
    ctx: &Arc<ServerContext>,
    bindings: Arc<crate::api::bindings::BindingsApi>,
) -> IamResult<Federation> {
    Ok(Federation {
        ctx: ctx.clone(),
        bindings,
    })
}

impl Federation {
    /// `completeAuthentication(input)`: a federated sign-in (`FederatedLogin` as JSON: `tenantId`, `providerId`,
    /// `issuer`, `subject`, `email?`, `name?`, `emailVerified?`, `linkingSessionId?`, `linkingIdentityId?`,
    /// `attributes?`, `trustScimProvisioned?`). Answers the sign-in result (`{ token, session }` or the MFA
    /// challenge).
    pub async fn complete_authentication(&self, input: &Value) -> IamResult<Value> {
        let ctx = &self.ctx;
        let auth = &ctx.auth;
        let result = ctx
            .store
            .transaction(|tx| async move {
                let tenant_id = member(input, "tenantId")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                auth.assert_tenant_active(&tx, &tenant_id).await?;
                // Directory-driven attributes: the provider's mapped values replace the stored ones on every sign-in.
                let with_attributes = |record: Record| {
                    let tx = tx.clone();
                    async move {
                        let record = match member(input, "attributes") {
                            None => record,
                            Some(attributes) => {
                                let mut next = record;
                                next.insert(
                                    "attributes".into(),
                                    Value::Object(attribute_values(
                                        &ctx.catalog.identity_attributes,
                                        Some(attributes),
                                    )?),
                                );
                                tx.put("identities", &next).await?
                            }
                        };
                        decode::<better_iam_core::Identity>(record)
                    }
                };
                let key = core_js::stringify(&json!([
                    filter_value(input, "providerId"),
                    filter_value(input, "issuer"),
                    filter_value(input, "subject"),
                ]));
                let external = |identity_id: &str| {
                    let mut record = Record::new();
                    record.insert("id".into(), Value::String(id()));
                    record.insert("tenantId".into(), filter_value(input, "tenantId"));
                    record.insert("uniqueKey".into(), Value::String(key.clone()));
                    record.insert("identityId".into(), Value::String(identity_id.to_owned()));
                    for member_key in ["providerId", "issuer", "subject"] {
                        if let Some(value) = member(input, member_key) {
                            record.insert(member_key.into(), value.clone());
                        }
                    }
                    record
                };
                let mapping = find_records(
                    &tx,
                    "externalIdentities",
                    Filter::new()
                        .eq("tenantId", filter_value(input, "tenantId"))
                        .eq("uniqueKey", key.clone()),
                )
                .await?
                .into_iter()
                .next();
                let mut identity = match &mapping {
                    Some(mapping) => {
                        tx.get("identities", &js_string(mapping.get("identityId")))
                            .await?
                    }
                    None => None,
                };
                if truthy(member(input, "linkingSessionId")) {
                    let linked_session = tx
                        .get("sessions", &member_text(input, "linkingSessionId"))
                        .await?;
                    let linked_identity = match &linked_session {
                        Some(session) => {
                            tx.get("identities", &js_string(session.get("identityId")))
                                .await?
                        }
                        None => None,
                    };
                    let (Some(linked_session), Some(linked_identity)) =
                        (linked_session, linked_identity)
                    else {
                        return Err(invalid_link());
                    };
                    if linked_identity.get("id") != member(input, "linkingIdentityId")
                        || linked_identity.get("tenantId") != member(input, "tenantId")
                        || truthy(linked_identity.get("rootAdmin"))
                        || linked_session.get("kind").and_then(Value::as_str) != Some("user")
                    {
                        return Err(invalid_link());
                    }
                    let verified = ctx
                        .principals()?
                        .current_principal(
                            &tx,
                            &AuthenticatedPrincipal {
                                identity: decode(linked_identity.clone())?,
                                session: decode(linked_session)?,
                                device_proof: None,
                            },
                        )
                        .await?;
                    auth.require_recent(&verified)?;
                    let linked_id = js_string(linked_identity.get("id"));
                    if mapping.is_some()
                        && identity.as_ref().and_then(|identity| identity.get("id"))
                            != linked_identity.get("id")
                    {
                        return Err(IamError::with_status(
                            "ACCOUNT_LINK_CONFLICT",
                            "External identity is already linked to another account",
                            409,
                        ));
                    }
                    if mapping.is_none() {
                        tx.insert("externalIdentities", &external(&linked_id))
                            .await?;
                        ctx.events()?
                            .audit(
                                &tx,
                                &verified,
                                "identity:link-provider",
                                &tenant_id,
                                &linked_id,
                                AuditOutcome::Allow,
                                false,
                                None,
                            )
                            .await?;
                    }
                    let linked = with_attributes(linked_identity).await?;
                    return auth
                        .complete_authentication(&tx, &linked, Some(AuthMethod::Federated), None)
                        .await;
                }
                if identity.is_none() {
                    if !truthy(member(input, "email")) || !truthy(member(input, "emailVerified")) {
                        return Err(IamError::new(
                            "VERIFIED_EMAIL_REQUIRED",
                            "Federation enrollment needs a verified email",
                        ));
                    }
                    // As with self sign-up, nobody joins the platform (root) tenant by signing in somewhere else:
                    // platform accounts are created by an administrator, then linked.
                    if ctx
                        .tenant_of(&tx, member(input, "tenantId"))
                        .await?
                        .parent_id
                        .is_none()
                    {
                        return Err(IamError::with_status(
                            "FORBIDDEN",
                            "Root identity provisioning requires an administrator",
                            403,
                        ));
                    }
                    let address = email(member(input, "email"))?;
                    let existing = find_records(
                        &tx,
                        "identities",
                        Filter::new()
                            .eq("tenantId", filter_value(input, "tenantId"))
                            .eq("email", address.clone()),
                    )
                    .await?
                    .into_iter()
                    .next();
                    // A directory that provisions people through SCIM and signs them in through SSO is one
                    // administrator's decision: with `trustScimProvisioned`, the IdP's verified email claims the
                    // account SCIM created for it. One link per provider: an account already linked through this
                    // connection under another subject is not re-linked (that would be a second IdP account taking
                    // it over).
                    if let Some(existing) = &existing {
                        let typed: better_iam_core::Identity = decode(existing.clone())?;
                        if scim_provisioned(&tx, &typed, member(input, "trustScimProvisioned"))
                            .await?
                            && !find_records(
                                &tx,
                                "externalIdentities",
                                Filter::new()
                                    .eq("tenantId", filter_value(input, "tenantId"))
                                    .eq("identityId", typed.id.clone()),
                            )
                            .await?
                            .iter()
                            .any(|link| link.get("providerId") == member(input, "providerId"))
                        {
                            tx.insert("externalIdentities", &external(&typed.id))
                                .await?;
                            // The IdP vouched for the address (a trusted domain), which SCIM alone never does.
                            let linked = if typed.email_verified {
                                existing.clone()
                            } else {
                                let mut next = existing.clone();
                                next.insert("emailVerified".into(), Value::Bool(true));
                                tx.put("identities", &next).await?
                            };
                            let linked_id = js_string(linked.get("id"));
                            let mut metadata = Map::new();
                            metadata.insert("providerId".into(), filter_value(input, "providerId"));
                            metadata.insert("via".into(), json!("scim"));
                            let mut event = Record::new();
                            event.insert("id".into(), Value::String(id()));
                            event.insert("tenantId".into(), filter_value(input, "tenantId"));
                            event.insert("actorId".into(), Value::String(linked_id.clone()));
                            event.insert("action".into(), json!("identity:link-provider"));
                            event.insert("resourceId".into(), Value::String(linked_id));
                            event.insert("timestamp".into(), crate::js::number(ctx.now()));
                            event.insert("outcome".into(), json!("allow"));
                            event.insert("metadata".into(), Value::Object(metadata));
                            ctx.events()?.record_audit(&tx, &event).await?;
                            let linked = with_attributes(linked).await?;
                            return auth
                                .complete_authentication(
                                    &tx,
                                    &linked,
                                    Some(AuthMethod::Federated),
                                    None,
                                )
                                .await;
                        }
                        return Err(IamError::with_status(
                            "ACCOUNT_LINK_REQUIRED",
                            "Authenticate the existing account before linking this provider",
                            409,
                        ));
                    }
                    let address_value = Value::String(address);
                    let name = member(input, "name")
                        .filter(|name| !name.is_null())
                        .or(member(input, "email"));
                    let created = auth
                        .create_identity_raw(
                            &tx,
                            CreateIdentityRaw {
                                tenant_id: member(input, "tenantId"),
                                email: Some(&address_value),
                                name,
                                password: None,
                                owner: false,
                                root_admin: false,
                                email_verified: true,
                            },
                        )
                        .await?;
                    tx.insert("externalIdentities", &external(&created.id))
                        .await?;
                    identity = Some(match tx.get("identities", &created.id).await? {
                        Some(record) => record,
                        None => crate::port::encode(&created),
                    });
                }
                let identity = with_attributes(identity.unwrap_or_default()).await?;
                auth.complete_authentication(&tx, &identity, Some(AuthMethod::Federated), None)
                    .await
            })
            .await?;
        serde_json::to_value(result).map_err(|_| crate::js::internal_error())
    }

    /// `syncRoleMappings(tx, input)` (`RoleMappingSync` as JSON: `tenantId`, `connectionId`, `groupId`,
    /// `identityIds`, `roleIds`, `credential?`): teams that follow the directory group follow every push; with an
    /// administrator's credential, the group's SCIM-managed bindings are brought in line with `roleIds`.
    pub async fn sync_role_mappings(&self, tx: &Store, input: &Value) -> IamResult<()> {
        let ctx = &self.ctx;
        let tenant_id = member(input, "tenantId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        // Teams that sync their members from this directory group follow every push (teams.ts).
        sync_teams_from_groups(
            ctx,
            tx,
            &tenant_id,
            &json!({ "groupId": filter_value(input, "groupId"), "actorId": "directory-sync" }),
        )
        .await?;
        // Ongoing directory updates change membership only. Grant configuration requires
        // an actual administrator credential and retains that administrator's ceiling.
        if !truthy(member(input, "credential")) {
            return Ok(());
        }
        let credential = credential_from_json(member(input, "credential"));
        ctx.scoped(tx, "groups", member(input, "groupId"), &tenant_id)
            .await?;
        let existing = find_records(
            tx,
            "bindings",
            Filter::new()
                .eq("tenantId", filter_value(input, "tenantId"))
                .eq("subjectType", "group")
                .eq("subjectId", filter_value(input, "groupId"))
                .eq("scimConnectionId", filter_value(input, "connectionId")),
        )
        .await?;
        let role_ids: Vec<Value> = match member(input, "roleIds") {
            Some(Value::Array(items)) => items.clone(),
            _ => Vec::new(),
        };
        for binding in &existing {
            if !role_ids.contains(binding.get("roleId").unwrap_or(&Value::Null)) {
                self.bindings
                    .delete(
                        &credential,
                        Body::from_value(json!({
                            "tenantId": filter_value(input, "tenantId"),
                            "bindingId": binding.get("id").cloned().unwrap_or(Value::Null),
                        })),
                    )
                    .await?;
            }
        }
        for role_id in &role_ids {
            if existing
                .iter()
                .any(|binding| binding.get("roleId") == Some(role_id))
            {
                continue;
            }
            let binding = self
                .bindings
                .create(
                    &credential,
                    Body::from_value(json!({
                        "tenantId": filter_value(input, "tenantId"),
                        "roleId": role_id,
                        "subjectType": "group",
                        "subjectId": filter_value(input, "groupId"),
                    })),
                )
                .await?
                .into_value()?;
            let mut record = binding.as_object().cloned().unwrap_or_default();
            record.insert(
                "scimConnectionId".into(),
                filter_value(input, "connectionId"),
            );
            tx.put("bindings", &record).await?;
        }
        Ok(())
    }

    /// `protocolHost`: the trusted callbacks for protocol packages. Its members are the methods of this struct
    /// (`store`, `authenticate`, `validateIdentityAttributes`, `validateSession`, `authorize`, `completeAuthentication`,
    /// `syncRoleMappings`, `identityStatusChanged`, `groupDeleted`, `recordAudit`, `liveGrants`, `clientAllowed`,
    /// `assertTrustChange`).
    pub fn protocol_host(&self) -> &Self {
        self
    }

    /// `protocolHost.store`.
    pub fn store(&self) -> &Store {
        &self.ctx.store
    }

    /// `protocolHost.authenticate(credential)`: `ctx.principals.authenticate`.
    pub async fn authenticate(
        &self,
        credential: &better_iam_core::CredentialInput,
    ) -> IamResult<better_iam_core::AuthenticatedPrincipal> {
        self.ctx.principals()?.authenticate(credential).await
    }

    /// `protocolHost.validateIdentityAttributes(value)`: validates identity attributes a protocol (SCIM) maps from
    /// its payload against `permissions.identityAttributes`.
    pub fn validate_identity_attributes(
        &self,
        value: Option<&Value>,
    ) -> IamResult<Map<String, Value>> {
        attribute_values(&self.ctx.catalog.identity_attributes, value)
    }

    /// `protocolHost.validateSession(sessionId)`.
    pub async fn validate_session(&self, session_id: &str) -> IamResult<AuthenticatedPrincipal> {
        self.ctx.auth.validate_session_id(session_id).await
    }

    /// `protocolHost.authorize(credential, action, resource)`: `ctx.operations.requireAccess` for the resource's
    /// tenant.
    pub async fn authorize(
        &self,
        credential: &better_iam_core::CredentialInput,
        action: &str,
        resource: &better_iam_core::ResourceRef,
    ) -> IamResult<()> {
        self.ctx
            .operations()?
            .require_access(&crate::options::AuthorizationRequest {
                credential: credential.clone(),
                tenant_id: resource.tenant_id.clone(),
                action: action.to_owned(),
                resource: crate::options::ResourceTarget {
                    kind: resource.kind.clone(),
                    id: resource.id.clone(),
                },
            })
            .await
    }

    /// `protocolHost.identityStatusChanged(tx, { tenantId, connectionId, identityId })`: after SCIM deactivated or
    /// reactivated a person (in its transaction), their license seats follow at once, as after an administrator's
    /// `identities.setStatus` (licenses.ts).
    pub async fn identity_status_changed(&self, tx: &Store, input: &Value) -> IamResult<()> {
        reconcile_identity_licenses(
            &self.ctx,
            tx,
            &string_member(input.as_object().unwrap_or(&Map::new()), "tenantId"),
            &[member_text(input, "identityId")],
            Some(&json!("directory-sync")),
        )
        .await?;
        Ok(())
    }

    /// `protocolHost.groupDeleted(tx, { tenantId, connectionId, groupId })`: before SCIM deletes a group's record (in
    /// its transaction), the group's license assignments go with it and the seats they carried are released, as
    /// `groups.delete` does (licenses.ts).
    pub async fn group_deleted(&self, tx: &Store, input: &Value) -> IamResult<()> {
        release_group_licenses(
            &self.ctx,
            tx,
            &string_member(input.as_object().unwrap_or(&Map::new()), "tenantId"),
            &member_text(input, "groupId"),
            &json!("directory-sync"),
        )
        .await?;
        Ok(())
    }

    /// `protocolHost.recordAudit(tx, event)`: records a protocol's audit event and fans it out (webhooks, plugins,
    /// `iam.events` subscribers).
    pub async fn record_audit(&self, tx: &Store, event: &Record) -> IamResult<()> {
        self.ctx.events()?.record_audit(tx, event).await
    }

    /// `protocolHost.liveGrants(identityId, tenantId)`: the groups and roles an identity holds right now, as
    /// decisions see them (`{ groupIds, roleIds }`), for claims protocols put in tokens.
    pub async fn live_grants(&self, identity_id: &str, tenant_id: &str) -> IamResult<Value> {
        let ctx = &self.ctx;
        ctx.store
            .transaction(|tx| async move {
                let sources = ctx
                    .decisions()?
                    .grant_sources(&tx, identity_id, tenant_id)
                    .await?;
                let role_ids = crate::js::unique(
                    sources
                        .bindings
                        .iter()
                        .map(|binding| binding.role_id.clone()),
                );
                Ok(json!({
                    "groupIds": sources.group_ids.iter().collect::<Vec<_>>(),
                    "roleIds": role_ids,
                }))
            })
            .await
    }

    /// `protocolHost.clientAllowed(identityId, tenantId, clientId)`: whether a person may get tokens for an OAuth
    /// client: false when an app of the catalog governs the client and the person does not have it
    /// (applications.ts). The OAuth provider asks on every code, token refresh and userinfo.
    pub async fn client_allowed(
        &self,
        identity_id: &str,
        tenant_id: &str,
        client_id: &str,
    ) -> IamResult<bool> {
        app_client_allowed(&self.ctx, identity_id, tenant_id, client_id).await
    }

    /// `protocolHost.assertTrustChange(credential, { tenantId, providerId })`: before a tenant-managed sign-in
    /// connection trusts something new, the change needs a recent sign-in in person, and when owners or root
    /// administrators are linked through it, a caller who could control those accounts anyway. Refusals are 403
    /// ACCESS_DENIED.
    pub async fn assert_trust_change(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<()> {
        let ctx = &self.ctx;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let authenticated = &authenticated;
        ctx.store
            .transaction(|tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, authenticated)
                    .await?;
                ctx.auth.require_recent(&principal)?;
                let root = ctx.root_principal(&tx, &principal).await?;
                let tenant = member(input, "tenantId");
                let owner = principal.session.kind == SessionKind::User
                    && principal.identity.owner
                    && tenant.and_then(Value::as_str) == Some(principal.identity.tenant_id.as_str())
                    && tenant.and_then(Value::as_str) == Some(principal.session.tenant_id.as_str());
                for link in find_records(
                    &tx,
                    "externalIdentities",
                    Filter::new()
                        .eq("tenantId", filter_value(input, "tenantId"))
                        .eq("providerId", filter_value(input, "providerId")),
                )
                .await?
                {
                    let Some(linked) = tx
                        .get("identities", &js_string(link.get("identityId")))
                        .await?
                    else {
                        continue;
                    };
                    let linked_owner = truthy(linked.get("owner"));
                    let linked_root = truthy(linked.get("rootAdmin"));
                    if (!linked_owner && !linked_root) || root {
                        continue;
                    }
                    if !linked_root && owner {
                        continue;
                    }
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        if linked_root {
                            "A root administrator signs in through this connection; only a root administrator can change what it trusts"
                        } else {
                            "An owner signs in through this connection; only an owner can change what it trusts"
                        },
                        403,
                    ));
                }
                Ok(())
            })
            .await
    }

    /// The conformance server's `call` for a member of this object (`completeAuthentication`, `syncRoleMappings`,
    /// `protocolHost.<member>`): JSON arguments in, the JSON result out; None for a name it does not have. Members
    /// that take a transaction receive `{"$tx": true}` from the conformance server, which runs the call inside the
    /// open transaction: the root store joins it there.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        let credential = || crate::conformance::credential_arg(args.first());
        let arg = |index: usize| args.get(index).cloned().unwrap_or(Value::Null);
        let text_arg = |index: usize| js_string(args.get(index));
        let tx = self.ctx.store.clone();
        let member_name = method.strip_prefix("protocolHost.").unwrap_or(method);
        let undefined = |result: IamResult<()>| result.map(|()| crate::port::undefined());
        Some(match member_name {
            "authenticate" if method.starts_with("protocolHost.") => self
                .authenticate(&credential())
                .await
                .map(|principal| crate::conformance::principal_json(&principal)),
            "authorize" if method.starts_with("protocolHost.") => {
                let action = args
                    .get(1)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let resource = arg(2);
                let text = |key: &str| {
                    resource
                        .get(key)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                let reference = better_iam_core::ResourceRef {
                    tenant_id: text("tenantId"),
                    kind: text("type"),
                    id: text("id"),
                };
                undefined(self.authorize(&credential(), &action, &reference).await)
            }
            "validateIdentityAttributes" if method.starts_with("protocolHost.") => self
                .validate_identity_attributes(args.first())
                .map(Value::Object),
            "validateSession" if method.starts_with("protocolHost.") => self
                .validate_session(&text_arg(0))
                .await
                .map(|principal| crate::conformance::principal_json(&principal)),
            "completeAuthentication" => self.complete_authentication(&arg(0)).await,
            "syncRoleMappings" => undefined(self.sync_role_mappings(&tx, &arg(1)).await),
            "identityStatusChanged" if method.starts_with("protocolHost.") => {
                undefined(self.identity_status_changed(&tx, &arg(1)).await)
            }
            "groupDeleted" if method.starts_with("protocolHost.") => {
                undefined(self.group_deleted(&tx, &arg(1)).await)
            }
            "recordAudit" if method.starts_with("protocolHost.") => {
                let event = arg(1).as_object().cloned().unwrap_or_default();
                undefined(self.record_audit(&tx, &event).await)
            }
            "liveGrants" if method.starts_with("protocolHost.") => {
                self.live_grants(&text_arg(0), &text_arg(1)).await
            }
            "clientAllowed" if method.starts_with("protocolHost.") => self
                .client_allowed(&text_arg(0), &text_arg(1), &text_arg(2))
                .await
                .map(Value::Bool),
            "assertTrustChange" if method.starts_with("protocolHost.") => {
                undefined(self.assert_trust_change(&credential(), &arg(1)).await)
            }
            _ => return None,
        })
    }
}

fn invalid_link() -> IamError {
    IamError::with_status(
        "INVALID_LINK",
        "Invalid verified account-linking proof",
        403,
    )
}
