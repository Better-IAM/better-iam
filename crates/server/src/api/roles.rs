//! Port of `packages/server/src/api/roles.ts`: the `roles` API group and the role helpers configuration sync, impact
//! previews and policies share (creating, editing and deleting roles under a grant authority, the role hierarchy,
//! and the rule that keeps the denies other administrators rely on).

use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;

use better_iam_core::{
    AuditOutcome, CredentialInput, Filter, FindOptions, IamError, IamResult, Record,
};
use better_iam_types::api::roles;
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::decisions::role_deny_statements;
use crate::js::{as_number, truthy};
use crate::port::{Callback, decode, encode};
use crate::session_kinds::{next_watermark, revoked_by_watermark_values};
use crate::temporary_credentials::{delete_temporary_sessions, role_session_summary};
use crate::utils::id;
use crate::validation::{integer, strings, text};
use better_iam_core::js::strict_equal;

/// Every record of a find (no pagination).
pub(crate) fn find_all() -> FindOptions {
    FindOptions::default()
}

/// JavaScript `a === b` for two possibly-undefined members.
pub(crate) fn same_member(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => strict_equal(a, b),
        _ => false,
    }
}

/// The string members of a stored list member (`record.roleIds`, `role.inherits`), empty when absent.
pub(crate) fn string_list(record: &Record, key: &str) -> Vec<String> {
    record
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// A string member of a stored record, "" when absent.
pub(crate) fn member_str<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// `input.member !== undefined` for a request body member (null counts as defined).
pub(crate) fn defined<'a>(input: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    input.get(key)
}

/// `input.member ?? fallback`: absent and null both take the fallback.
pub(crate) fn or_default<'a>(value: Option<&'a Value>, fallback: &'a Value) -> &'a Value {
    match value {
        None | Some(Value::Null) => fallback,
        Some(value) => value,
    }
}

/// The `roles` API group (`createRolesApi(ctx)`): one method per route `roles/{method}`.
pub struct RolesApi {
    ctx: Arc<ServerContext>,
}

/// `createRolesApi(ctx)`.
pub fn create_roles_api(ctx: &Arc<ServerContext>) -> IamResult<RolesApi> {
    Ok(RolesApi { ctx: ctx.clone() })
}

impl RolesApi {
    /// `roles/assume`: AssumeRole through an identity trust: a temporary role session (`biam_rol_…`, or a session
    /// JWT with `format: 'jwt'`) with an optional session name, source identity and tags the trust admits. See
    /// FlowService.
    pub async fn assume(
        &self,
        credential: &CredentialInput,
        input: Body<roles::AssumeInput>,
    ) -> IamResult<Reply<roles::AssumeOutput>> {
        let result = self.ctx.flows()?.assume_role(credential, &input).await?;
        Ok(Reply::json(result))
    }

    /// `roles/create`: a role carries attached policies, an inline document, or a plain permissions list (an inline
    /// allow over every tenant resource).
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<roles::CreateInput>,
    ) -> IamResult<Reply<roles::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let role = create_role_record(ctx, &tx, &principal, &tenant, body).await?;
                    Ok(Value::Object(role))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:roles:create",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `roles/delete`.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<roles::DeleteInput>,
    ) -> IamResult<Reply<roles::DeleteOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let role = ctx
                    .scoped(&tx, "roles", body.get("roleId"), &tenant_id)
                    .await?;
                delete_role_record(ctx, &tx, &principal, &role).await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:roles:delete",
                &string_member(&input, "roleId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `roles/get`.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<roles::GetInput>,
    ) -> IamResult<Reply<roles::GetOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let role = ctx
                    .scoped(&tx, "roles", body.get("roleId"), &tenant_id)
                    .await?;
                Ok(Value::Object(role))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:roles:read",
                &string_member(&input, "roleId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `roles/list`.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<roles::ListInput>,
    ) -> IamResult<Reply<roles::ListOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let roles = tx
                    .find(
                        "roles",
                        &Filter::new().eq("tenantId", string_member(body, "tenantId")),
                        &find_all(),
                    )
                    .await?;
                Ok(Value::Array(roles.into_iter().map(Value::Object).collect()))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:roles:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `roles/listBindings`: who holds a role, live bindings with their identity or group summary.
    pub async fn list_bindings(
        &self,
        credential: &CredentialInput,
        input: Body<roles::ListBindingsInput>,
    ) -> IamResult<Reply<roles::ListBindingsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                ctx.scoped(&tx, "roles", body.get("roleId"), &tenant_id)
                    .await?;
                let bindings = tx
                    .find(
                        "bindings",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("roleId", body.get("roleId").cloned().unwrap_or(Value::Null)),
                        &find_all(),
                    )
                    .await?;
                let now = ctx.now();
                let mut result = Vec::new();
                for binding in bindings {
                    // `ctx.expiredBinding(binding)`: a temporary binding past its end.
                    if binding
                        .get("expiresAt")
                        .and_then(as_number)
                        .is_some_and(|expires| expires <= now)
                    {
                        continue;
                    }
                    let subject_id = binding.get("subjectId").and_then(Value::as_str);
                    let subject =
                        if binding.get("subjectType").and_then(Value::as_str) == Some("identity") {
                            let identity = match subject_id {
                                Some(subject_id) => tx.get("identities", subject_id).await?,
                                None => None,
                            };
                            identity
                                .filter(|identity| {
                                    identity.get("tenantId").and_then(Value::as_str)
                                        == Some(tenant_id.as_str())
                                })
                                .map(|identity| {
                                    let mut subject = Map::new();
                                    for key in ["id", "name", "email", "kind"] {
                                        if let Some(value) = identity.get(key) {
                                            subject.insert(key.into(), value.clone());
                                        }
                                    }
                                    subject
                                })
                        } else {
                            let group = match subject_id {
                                Some(subject_id) => tx.get("groups", subject_id).await?,
                                None => None,
                            };
                            group
                                .filter(|group| {
                                    group.get("tenantId").and_then(Value::as_str)
                                        == Some(tenant_id.as_str())
                                })
                                .map(|group| {
                                    let mut subject = Map::new();
                                    for key in ["id", "name"] {
                                        if let Some(value) = group.get(key) {
                                            subject.insert(key.into(), value.clone());
                                        }
                                    }
                                    subject
                                })
                        };
                    let mut entry = binding;
                    match subject {
                        Some(subject) => {
                            entry.insert("subject".into(), Value::Object(subject));
                        }
                        // `subject: undefined` replaces any stored member and is left out of the JSON.
                        None => {
                            entry.shift_remove("subject");
                        }
                    }
                    result.push(Value::Object(entry));
                }
                Ok(Value::Array(result))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:bindings:read",
                &string_member(&input, "roleId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `roles/listSessions`: live role sessions in the tenant (of one role or trust when given), newest first, as
    /// allowlist summaries that never carry tokens, hashes, policies or authority ids. Expired sessions, sessions
    /// under a revoked or missing trust, and sessions below a role, trust or provider watermark are left out.
    /// Requires iam:trust:read on the role (or the tenant); `limit` is 1-500 (default 100).
    pub async fn list_sessions(
        &self,
        credential: &CredentialInput,
        input: Body<roles::ListSessionsInput>,
    ) -> IamResult<Reply<roles::ListSessionsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let limit = integer(
                    Some(or_default(body.get("limit"), &json!(100))),
                    "limit",
                    1.0,
                    500.0,
                )?;
                let role_id = defined(body, "roleId");
                if let Some(role_id) = role_id {
                    let role_id = text(Some(role_id), "roleId", 256)?;
                    ctx.scoped(&tx, "roles", Some(&Value::String(role_id)), &tenant_id)
                        .await?;
                }
                let trust_id = match defined(body, "trustId") {
                    None => None,
                    Some(trust_id) => Some(text(Some(trust_id), "trustId", 256)?),
                };
                let now = ctx.now();
                let rows = match role_id {
                    Some(role_id) => {
                        tx.find(
                            "sessions",
                            &Filter::new().eq("roleId", role_id.clone()),
                            &find_all(),
                        )
                        .await?
                    }
                    None => {
                        tx.find(
                            "sessions",
                            &Filter::new()
                                .eq("tenantId", tenant_id.clone())
                                .eq("kind", "role"),
                            &find_all(),
                        )
                        .await?
                    }
                };
                // Each trust, role and provider is read once, however many sessions share it.
                let mut records: IndexMap<String, Option<Record>> = IndexMap::new();
                let mut live: Vec<Record> = Vec::new();
                for session in rows {
                    let expires_at = session
                        .get("expiresAt")
                        .and_then(as_number)
                        .unwrap_or(f64::NAN);
                    if session.get("kind").and_then(Value::as_str) != Some("role")
                        || session.get("tenantId").and_then(Value::as_str)
                            != Some(tenant_id.as_str())
                        || trust_id.as_deref().is_some_and(|trust_id| {
                            session.get("trustId").and_then(Value::as_str) != Some(trust_id)
                        })
                        || expires_at.partial_cmp(&now) != Some(std::cmp::Ordering::Greater)
                    {
                        continue;
                    }
                    let trust = cached(&tx, &mut records, "trusts", session.get("trustId")).await?;
                    let role = cached(&tx, &mut records, "roles", session.get("roleId")).await?;
                    let provider = if truthy(session.get("webIdentity")) {
                        cached(
                            &tx,
                            &mut records,
                            "oidcProviders",
                            session
                                .get("webIdentity")
                                .and_then(|web| web.get("providerId")),
                        )
                        .await?
                    } else {
                        None
                    };
                    let (Some(trust), Some(role)) = (trust, role) else {
                        continue;
                    };
                    let created_at = session
                        .get("createdAt")
                        .and_then(as_number)
                        .unwrap_or(f64::NAN);
                    if truthy(trust.get("revoked"))
                        || trust.get("tenantId").and_then(Value::as_str) != Some(tenant_id.as_str())
                        || role.get("tenantId").and_then(Value::as_str) != Some(tenant_id.as_str())
                        || revoked_by_watermark_values(
                            created_at,
                            &[
                                trust.get("sessionsRevokedBefore"),
                                role.get("sessionsRevokedBefore"),
                                provider
                                    .as_ref()
                                    .and_then(|provider| provider.get("sessionsRevokedBefore")),
                            ],
                        )
                    {
                        continue;
                    }
                    live.push(session);
                }
                let created = |session: &Record| {
                    session
                        .get("createdAt")
                        .and_then(as_number)
                        .unwrap_or(f64::NAN)
                };
                live.sort_by(|a, b| {
                    let difference = created(b) - created(a);
                    if difference != 0.0 && !difference.is_nan() {
                        return difference
                            .partial_cmp(&0.0)
                            .unwrap_or(std::cmp::Ordering::Equal);
                    }
                    member_str(a, "id").cmp(member_str(b, "id"))
                });
                let mut summaries = Vec::new();
                for session in live.into_iter().take(limit as usize) {
                    let session: better_iam_core::Session = decode(session)?;
                    summaries.push(Value::Object(encode(&role_session_summary(&session)?)));
                }
                Ok(Value::Array(summaries))
            })
        });
        let resource = match input.get("roleId") {
            None | Some(Value::Null) => string_member(&input, "tenantId"),
            Some(_) => string_member(&input, "roleId"),
        };
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:trust:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `roles/revokeSessions`: revokes the role's sessions (classic and web identity) issued before `before`
    /// (default: every session so far): moves the role's `sessionsRevokedBefore` watermark forward, so older
    /// sessions are refused on their next use, and deletes the matching rows. Requires iam:roles:revoke-sessions on
    /// the role and recent authentication; it only removes access, so it is delegable. Audited as
    /// `role:sessions-revoked`.
    pub async fn revoke_sessions(
        &self,
        credential: &CredentialInput,
        input: Body<roles::RevokeSessionsInput>,
    ) -> IamResult<Reply<roles::RevokeSessionsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let tenant_id = string_member(body, "tenantId");
                let mut role = ctx
                    .scoped(&tx, "roles", body.get("roleId"), &tenant_id)
                    .await?;
                let sessions_revoked_before = next_watermark(
                    role.get("sessionsRevokedBefore").and_then(as_number),
                    body.get("before"),
                    ctx.now(),
                )?;
                role.insert(
                    "sessionsRevokedBefore".into(),
                    crate::js::number(sessions_revoked_before),
                );
                tx.put("roles", &role).await?;
                let role_id = member_str(&role, "id").to_owned();
                let revoked = delete_temporary_sessions(
                    &tx,
                    &json!({
                        "tenantId": member_str(&role, "tenantId"),
                        "roleId": role_id,
                        "createdBefore": crate::js::number(sessions_revoked_before),
                    }),
                )
                .await?;
                let mut metadata = Map::new();
                metadata.insert(
                    "sessionsRevokedBefore".into(),
                    crate::js::number(sessions_revoked_before),
                );
                metadata.insert("revoked".into(), crate::js::number(revoked));
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "role:sessions-revoked",
                        &tenant_id,
                        &role_id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(json!({
                    "roleId": role_id,
                    "sessionsRevokedBefore": crate::js::number(sessions_revoked_before),
                    "revoked": crate::js::number(revoked),
                }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:roles:revoke-sessions",
                &string_member(&input, "roleId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `roles/update`.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<roles::UpdateInput>,
    ) -> IamResult<Reply<roles::UpdateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let role = update_role_record(ctx, &tx, &principal, body).await?;
                Ok(Value::Object(role))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:roles:update",
                &string_member(&input, "roleId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// `record(collection, recordId)` of `roles.listSessions`: a record read once per key, None for a non-string ID.
async fn cached(
    tx: &Store,
    records: &mut IndexMap<String, Option<Record>>,
    collection: &str,
    record_id: Option<&Value>,
) -> IamResult<Option<Record>> {
    let Some(Value::String(record_id)) = record_id else {
        return Ok(None);
    };
    let key = format!("{collection}/{record_id}");
    if let Some(record) = records.get(&key) {
        return Ok(record.clone());
    }
    let record = tx.get(collection, record_id).await?;
    records.insert(key, record.clone());
    Ok(record)
}

/// `RoleUpdate.document`: absent (unchanged), null (removed), or a document (replaces the inline document).
mod nullable_document {
    use better_iam_core::PolicyDocument;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        value: &Option<Option<PolicyDocument>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(Some(document)) => document.serialize(serializer),
            _ => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Option<PolicyDocument>>, D::Error> {
        Ok(Some(Option::<PolicyDocument>::deserialize(deserializer)?))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoleUpdate {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "roleId")]
    pub role_id: String,
    #[serde(rename = "name", default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(rename = "policyIds", default, skip_serializing_if = "Option::is_none")]
    pub policy_ids: Option<Vec<String>>,
    #[serde(
        rename = "permissions",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub permissions: Option<Vec<String>>,
    /// `document?: PolicyDocument | null`: `Some(None)` (null) removes the inline document.
    #[serde(
        rename = "document",
        default,
        skip_serializing_if = "Option::is_none",
        with = "nullable_document"
    )]
    pub document: Option<Option<better_iam_core::PolicyDocument>>,
    /// Replaces the inherited roles; an empty list clears inheritance.
    #[serde(rename = "inherits", default, skip_serializing_if = "Option::is_none")]
    pub inherits: Option<Vec<String>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// [`assert_denies_kept`] with the reliance check as an async function.
pub async fn assert_denies_kept_with<F, Fut>(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    before: &IndexSet<String>,
    after: &IndexSet<String>,
    relied: F,
) -> IamResult<()>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = IamResult<bool>>,
{
    if before.iter().all(|statement| after.contains(statement)) {
        return Ok(());
    }
    if ctx.root_principal(tx, principal).await? || !relied().await? {
        return Ok(());
    }
    Err(IamError::with_status(
        "PROTECTED_RESOURCE",
        "Other administrators rely on its deny statements (they bound it, or attached or inherit it); they must detach it before a deny is removed or changed",
        403,
    ))
}

/// An editor may add denies to a role or policy, but once another authority relies on it (see reliedOnByOthers),
/// may not remove or change one: that would widen what the other authority's grants allow, beyond the editor's own
/// ceiling. Root may.
pub async fn assert_denies_kept(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    before: &IndexSet<String>,
    after: &IndexSet<String>,
    relied: &Callback,
) -> IamResult<()> {
    assert_denies_kept_with(ctx, tx, principal, before, after, || async {
        Ok(truthy(Some(&relied(Vec::new()).await?)))
    })
    .await
}

/// Validates a role hierarchy edge set: existing, unprotected, distinct roles of the tenant that do not lead back to
/// `roleId`.
async fn inheritance(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    role_id: Option<&str>,
    value: Option<&Value>,
) -> IamResult<Vec<String>> {
    let inherits = crate::js::unique(strings(value, "inherits")?);
    if inherits.len() > 20 {
        return Err(IamError::new(
            "INVALID_INPUT",
            "A role may inherit at most 20 roles",
        ));
    }
    for inherited_id in &inherits {
        if Some(inherited_id.as_str()) == role_id {
            return Err(IamError::new(
                "INVALID_INPUT",
                "A role cannot inherit itself",
            ));
        }
        let inherited = ctx
            .scoped(
                tx,
                "roles",
                Some(&Value::String(inherited_id.clone())),
                tenant_id,
            )
            .await?;
        if truthy(inherited.get("protected")) {
            return Err(IamError::with_status(
                "PROTECTED_RESOURCE",
                "Protected roles cannot be inherited",
                403,
            ));
        }
    }
    // Walk the hierarchy from the new parents; reaching this role again would close a cycle.
    if let Some(role_id) = role_id {
        let mut queue: VecDeque<String> = inherits.iter().cloned().collect();
        let mut visited: IndexSet<String> = IndexSet::new();
        while let Some(current) = queue.pop_front() {
            if current == role_id {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "Role inheritance must not form a cycle",
                ));
            }
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());
            if visited.len() > 200 {
                return Err(IamError::new("INVALID_INPUT", "Role hierarchy is too deep"));
            }
            if let Some(parent) = tx.get("roles", &current).await? {
                queue.extend(string_list(&parent, "inherits"));
            }
        }
    }
    Ok(inherits)
}

/// What `roleDocument` decides: no change (`undefined`), removal (`null`), or a validated document.
enum RoleDocument {
    Unchanged,
    Removed,
    Document(Value),
}

/// A permissions list compiles to an inline allow statement over every resource; a document is used as given.
async fn role_document(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    input: &Map<String, Value>,
) -> IamResult<RoleDocument> {
    let permissions = defined(input, "permissions");
    let document = defined(input, "document");
    if permissions.is_some() && document.is_some() {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Provide either permissions or an inline document",
        ));
    }
    if matches!(document, Some(Value::Null)) {
        return Ok(RoleDocument::Removed);
    }
    let mut document = document.cloned();
    if let Some(permissions) = permissions {
        let permissions = strings(Some(permissions), "permissions")?;
        if permissions.is_empty() {
            return Err(IamError::new(
                "INVALID_INPUT",
                "permissions must name at least one action",
            ));
        }
        document = Some(json!({
            "version": 1,
            "statements": [
                { "sid": "RolePermissions", "effect": "allow", "actions": permissions, "resources": ["*"] },
            ],
        }));
    }
    match document {
        Some(document) => {
            ctx.catalog
                .validate(tx.as_ref(), tenant_id, &document)
                .await?;
            Ok(RoleDocument::Document(document))
        }
        None => Ok(RoleDocument::Unchanged),
    }
}

/// [`create_role`] on a raw input, answering the stored record.
pub async fn create_role_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    tenant: &better_iam_core::Tenant,
    input: &Map<String, Value>,
) -> IamResult<Record> {
    let tenant_id = string_member(input, "tenantId");
    let authority = ctx
        .granting_authority(tx, principal, &tenant_id, None)
        .await?;
    ctx.enforce_limit(
        tenant,
        "roles",
        || async {
            Ok(tx
                .find(
                    "roles",
                    &Filter::new().eq("tenantId", tenant_id.clone()),
                    &find_all(),
                )
                .await?
                .len() as f64)
        },
        None,
    )
    .await?;
    let policy_ids = strings(
        Some(or_default(input.get("policyIds"), &json!([]))),
        "policyIds",
    )?;
    for policy_id in &policy_ids {
        ctx.scoped(
            tx,
            "policies",
            Some(&Value::String(policy_id.clone())),
            &tenant_id,
        )
        .await?;
    }
    let document = role_document(ctx, tx, &tenant_id, input).await?;
    let mut role = Record::new();
    role.insert("id".into(), Value::String(id()));
    role.insert("tenantId".into(), Value::String(tenant_id.clone()));
    role.insert(
        "name".into(),
        Value::String(text(input.get("name"), "name", 256)?),
    );
    role.insert("policyIds".into(), json!(policy_ids));
    role.insert("protected".into(), Value::Bool(false));
    role.insert("authorityId".into(), Value::String(authority.id.clone()));
    if let Some(description) = defined(input, "description") {
        role.insert(
            "description".into(),
            Value::String(text(Some(description), "description", 512)?),
        );
    }
    if let RoleDocument::Document(document) = document {
        role.insert("document".into(), document);
    }
    if let Some(inherits) = defined(input, "inherits") {
        let inherits = inheritance(ctx, tx, &tenant_id, None, Some(inherits)).await?;
        if !inherits.is_empty() {
            role.insert("inherits".into(), json!(inherits));
        }
    }
    tx.insert("roles", &role).await
}

/// Creates a role under the caller's grant authority; shared by `roles.create` and configuration sync.
pub async fn create_role(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    tenant: &better_iam_core::Tenant,
    input: &Value,
) -> IamResult<crate::models::Role> {
    let input = input.as_object().cloned().unwrap_or_default();
    decode(create_role_record(ctx, tx, principal, tenant, &input).await?)
}

/// The reliance check of a role's denies: whether another authority relies on the role.
fn role_reliance(
    tx: &Store,
    role: &Record,
) -> impl FnOnce() -> std::pin::Pin<Box<dyn Future<Output = IamResult<bool>> + Send>> {
    let tx = tx.clone();
    let tenant_id = member_str(role, "tenantId").to_owned();
    let authority_id = role.get("authorityId").cloned();
    let role_id = member_str(role, "id").to_owned();
    move || {
        Box::pin(
            async move { relied_on(&tx, &tenant_id, authority_id.as_ref(), vec![role_id]).await },
        )
    }
}

/// [`update_role`] on a raw input (`roles.update`, impact previews), answering the stored record.
pub async fn update_role_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    input: &Map<String, Value>,
) -> IamResult<Record> {
    let tenant_id = string_member(input, "tenantId");
    ctx.granting_authority(tx, principal, &tenant_id, None)
        .await?;
    let role = ctx
        .scoped(tx, "roles", input.get("roleId"), &tenant_id)
        .await?;
    if truthy(role.get("protected")) {
        return Err(IamError::with_status(
            "PROTECTED_RESOURCE",
            "Role is protected",
            403,
        ));
    }
    ctx.can_edit_grant_resource(tx, principal, &role).await?;
    let mut next = role.clone();
    if let Some(policy_ids) = defined(input, "policyIds") {
        let policy_ids = strings(Some(policy_ids), "policyIds")?;
        next.insert("policyIds".into(), json!(policy_ids));
        for policy_id in &policy_ids {
            ctx.scoped(
                tx,
                "policies",
                Some(&Value::String(policy_id.clone())),
                &tenant_id,
            )
            .await?;
        }
    }
    match role_document(ctx, tx, &tenant_id, input).await? {
        RoleDocument::Removed => {
            next.shift_remove("document");
        }
        RoleDocument::Document(document) => {
            next.insert("document".into(), document);
        }
        RoleDocument::Unchanged => {}
    }
    if let Some(name) = defined(input, "name") {
        next.insert("name".into(), Value::String(text(Some(name), "name", 256)?));
    }
    if let Some(description) = defined(input, "description") {
        next.insert(
            "description".into(),
            Value::String(text(Some(description), "description", 512)?),
        );
    }
    if let Some(inherits) = defined(input, "inherits") {
        let role_id = member_str(&role, "id").to_owned();
        let inherits = inheritance(ctx, tx, &tenant_id, Some(&role_id), Some(inherits)).await?;
        if inherits.is_empty() {
            next.shift_remove("inherits");
        } else {
            next.insert("inherits".into(), json!(inherits));
        }
    }
    let before = role_deny_statements(tx, &decode(role.clone())?).await?;
    let after = role_deny_statements(tx, &decode(next.clone())?).await?;
    assert_denies_kept_with(
        ctx,
        tx,
        principal,
        &before,
        &after,
        role_reliance(tx, &role),
    )
    .await?;
    tx.put("roles", &next).await
}

/// Edits a role the caller's authority issued (or any role, for root); protected roles are refused.
pub async fn update_role(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    input: &crate::api::roles::RoleUpdate,
) -> IamResult<crate::models::Role> {
    decode(update_role_record(ctx, tx, principal, &encode(input)).await?)
}

/// Roles that inherit from the given role, directly.
pub async fn inheriting_roles(tx: &Store, role: &Record) -> IamResult<Vec<Record>> {
    let role_id = member_str(role, "id");
    Ok(tx
        .find(
            "roles",
            &Filter::new().eq("tenantId", member_str(role, "tenantId")),
            &find_all(),
        )
        .await?
        .into_iter()
        .filter(|other| {
            string_list(other, "inherits")
                .iter()
                .any(|id| id == role_id)
        })
        .collect())
}

/// [`delete_role`] for a stored record.
pub async fn delete_role_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    role: &Record,
) -> IamResult<()> {
    if truthy(role.get("protected")) {
        return Err(IamError::with_status(
            "PROTECTED_RESOURCE",
            "Role is protected",
            403,
        ));
    }
    ctx.can_edit_grant_resource(tx, principal, role).await?;
    let role_id = member_str(role, "id").to_owned();
    let tenant_id = member_str(role, "tenantId").to_owned();
    let children = inheriting_roles(tx, role).await?;
    if !children.is_empty() {
        return Err(IamError::with_status(
            "RESOURCE_IN_USE",
            format!(
                "Roles still inherit it: {}",
                children
                    .iter()
                    .map(|child| crate::js::js_string(child.get("name")))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            409,
        ));
    }
    let packaged: Vec<Record> = tx
        .find(
            "accessPackages",
            &Filter::new().eq("tenantId", tenant_id.clone()),
            &find_all(),
        )
        .await?
        .into_iter()
        .filter(|pkg| string_list(pkg, "roleIds").contains(&role_id))
        .collect();
    if !packaged.is_empty() {
        return Err(IamError::with_status(
            "RESOURCE_IN_USE",
            format!(
                "Access packages still include it: {}",
                packaged
                    .iter()
                    .map(|pkg| crate::js::js_string(pkg.get("name")))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            409,
        ));
    }
    // Deleting a role deletes its bindings; one another administrator bound carries its denies for them.
    let before = role_deny_statements(tx, &decode(role.clone())?).await?;
    assert_denies_kept_with(
        ctx,
        tx,
        principal,
        &before,
        &IndexSet::new(),
        role_reliance(tx, role),
    )
    .await?;
    for binding in tx
        .find(
            "bindings",
            &Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("roleId", role_id.clone()),
            &find_all(),
        )
        .await?
    {
        tx.delete("bindings", member_str(&binding, "id")).await?;
    }
    for activation in tx
        .find(
            "bindingActivations",
            &Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("roleId", role_id.clone()),
            &find_all(),
        )
        .await?
    {
        tx.delete("bindingActivations", member_str(&activation, "id"))
            .await?;
    }
    tx.delete("roles", &role_id).await
}

/// Deletes a role with its bindings and activations; protected roles are refused.
pub async fn delete_role(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    role: &crate::models::Role,
) -> IamResult<()> {
    delete_role_record(ctx, tx, principal, &encode(role)).await
}

/// [`relied_on_by_others`] with typed arguments.
pub async fn relied_on(
    tx: &Store,
    tenant_id: &str,
    authority_id: Option<&Value>,
    role_ids: Vec<String>,
) -> IamResult<bool> {
    let roles = tx
        .find(
            "roles",
            &Filter::new().eq("tenantId", tenant_id),
            &find_all(),
        )
        .await?;
    let mut covered: IndexSet<String> = role_ids.into_iter().collect();
    let mut grew = true;
    while grew {
        grew = false;
        for role in &roles {
            let role_id = member_str(role, "id");
            if !covered.contains(role_id)
                && string_list(role, "inherits")
                    .iter()
                    .any(|inherited| covered.contains(inherited))
            {
                covered.insert(role_id.to_owned());
                grew = true;
            }
        }
    }
    if roles.iter().any(|role| {
        covered.contains(member_str(role, "id"))
            && !same_member(role.get("authorityId"), authority_id)
    }) {
        return Ok(true);
    }
    for role_id in &covered {
        if tx
            .find(
                "bindings",
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("roleId", role_id.clone()),
                &find_all(),
            )
            .await?
            .iter()
            .any(|binding| !same_member(binding.get("authorityId"), authority_id))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether an authority other than `authorityId` relies on these roles: it issued one of them or a role inheriting
/// one of them, or bound one of those roles to someone. Their denies then restrict what that authority granted.
pub async fn relied_on_by_others(
    tx: &Store,
    tenant_id: &str,
    authority_id: Option<&Value>,
    role_ids: &Value,
) -> IamResult<bool> {
    let role_ids = role_ids
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    relied_on(tx, tenant_id, authority_id, role_ids).await
}
