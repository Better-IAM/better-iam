//! Port of `packages/scim/src/provisioning.ts`: provisioning logic shared by the connection API and the HTTP handler:
//! connection authentication, user and group persistence, membership and role-mapping synchronization, and PATCH
//! application.

use std::collections::{HashMap, HashSet};

use better_iam_core::{
    CredentialInput, Filter, FindOptions, IamError, IamResult, IamStore, Record, append_audit_event,
};
use serde_json::{Map, Value, json};
use subtle::ConstantTimeEq;

use crate::attributes::{ignored_attribute, without_ignored};
use crate::js::{as_object, date_now, js_string, number, random_uuid, truthy, unexpected};
use crate::patch::apply_patch_operation;
use crate::types::{
    ENTERPRISE_SCHEMA, GROUP_SCHEMA, GroupDeletion, IdentityStatusChange, ObjectValue,
    PATCH_SCHEMA, ProvisionedUser, ResourceType, RoleMappingSync, ScimConfig, Store, USER_SCHEMA,
};
use crate::validation::{active_tenant, bool_value, fields, hash, object, required_text, text};

/// Every record of a collection matching the filter.
pub(crate) async fn find(
    tx: &dyn IamStore,
    collection: &str,
    filter: Filter,
) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

fn str_member<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

/// A member as a filter value (`undefined` matches as absent).
fn filter_value(record: &Record, key: &str) -> Value {
    record.get(key).cloned().unwrap_or(Value::Null)
}

fn filter_eq(filter: Filter, key: &str, value: Option<&Value>) -> Filter {
    let mut filter = filter;
    filter.set(key, value.cloned());
    filter
}

/// The enterprise extension's `manager.value`, trimmed, if any.
fn manager_value(enterprise: Option<&Value>) -> Option<String> {
    let manager = as_object(enterprise)?.get("manager")?;
    let value = match manager {
        Value::Object(map) => map.get("value"),
        Value::Array(_) => None,
        _ => None,
    }?;
    let text = value.as_str()?;
    let trimmed = better_iam_core::js::trim(text);
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Indexes a connection's users once, so resolving any number of manager references stays linear. A reference
/// names the user with that SCIM ID, else the case-exact `externalId`, else the `userName` ignoring case. At each
/// step `self` wins over other users (naming oneself names no manager, so resolution never falls through to someone
/// else), then the first matching user in `users`.
struct ManagerIndex {
    by_id: HashMap<String, Record>,
    by_external_id: HashMap<String, Record>,
    by_user_name: HashMap<String, Record>,
}

impl ManagerIndex {
    fn new(users: &[Record]) -> Self {
        let mut index = ManagerIndex {
            by_id: HashMap::new(),
            by_external_id: HashMap::new(),
            by_user_name: HashMap::new(),
        };
        for row in users {
            index
                .by_id
                .entry(js_string(row.get("id")))
                .or_insert_with(|| row.clone());
            if let Some(Value::String(external)) = row.get("externalId") {
                index
                    .by_external_id
                    .entry(external.clone())
                    .or_insert_with(|| row.clone());
            }
            index
                .by_user_name
                .entry(js_string(row.get("userName")).to_lowercase())
                .or_insert_with(|| row.clone());
        }
        index
    }

    fn resolve(&self, value: &str, me: Option<&Record>) -> Option<Record> {
        let lower = value.to_lowercase();
        if let Some(me) = me
            && str_member(me, "id") == Some(value)
        {
            return Some(me.clone());
        }
        if let Some(found) = self.by_id.get(value) {
            return Some(found.clone());
        }
        if let Some(me) = me
            && str_member(me, "externalId") == Some(value)
        {
            return Some(me.clone());
        }
        if let Some(found) = self.by_external_id.get(value) {
            return Some(found.clone());
        }
        if let Some(me) = me
            && js_string(me.get("userName")).to_lowercase() == lower
        {
            return Some(me.clone());
        }
        self.by_user_name.get(&lower).cloned()
    }
}

/// `createProvisioning(config)`.
pub struct Provisioning {
    config: ScimConfig,
    lenient: bool,
}

/// `createProvisioning(config)`.
pub fn create_provisioning(config: &ScimConfig) -> IamResult<Provisioning> {
    if let Some(value) = &config.unsupported_attributes
        && value != "ignore"
        && value != "reject"
    {
        return Err(IamError::new(
            "configuration",
            "SCIM unsupportedAttributes must be 'ignore' or 'reject'.",
        ));
    }
    Ok(Provisioning {
        config: config.clone(),
        lenient: config.unsupported_attributes.as_deref() != Some("reject"),
    })
}

fn identity_filter_tenant(tenant_id: &str) -> Filter {
    Filter::new().eq("tenantId", tenant_id.to_owned())
}

impl Provisioning {
    fn map_manager(&self) -> bool {
        self.config.map_manager != Some(false)
    }

    /// `audit(tx, connection, action, resourceId, actorId)`.
    pub async fn audit(
        &self,
        tx: &Store,
        connection: &Record,
        action: &str,
        resource_id: &str,
        actor_id: Option<&str>,
    ) -> IamResult<()> {
        let mut event = Map::new();
        event.insert("id".into(), json!(random_uuid()));
        put_member(&mut event, "tenantId", connection.get("tenantId"));
        event.insert(
            "actorId".into(),
            json!(match actor_id {
                Some(actor) => actor.to_owned(),
                None => format!("scim:{}", js_string(connection.get("id"))),
            }),
        );
        event.insert("action".into(), json!(action));
        event.insert("resourceId".into(), json!(resource_id));
        event.insert("timestamp".into(), number(date_now()));
        event.insert("outcome".into(), json!("allow"));
        // Through the host when it can fan events out (webhooks, subscribers such as an outbound provisioner).
        match &self.config.record_audit {
            Some(record_audit) => record_audit(tx.clone(), event).await,
            None => append_audit_event(tx.as_ref(), &event).await.map(|_| ()),
        }
    }

    /// `authenticate(tx, request, connectionId)`: the connection a bearer token opens.
    pub async fn authenticate(
        &self,
        tx: &Store,
        authorization: Option<&str>,
        connection_id: &str,
    ) -> IamResult<Record> {
        let connection = tx.get("scimConnections", connection_id).await?;
        let token = authorization.and_then(bearer_token);
        let denied = || IamError::with_status("unauthorized", "Invalid SCIM credential.", 401);
        let (Some(mut connection), Some(token)) = (connection, token) else {
            return Err(denied());
        };
        if truthy(connection.get("revoked")) {
            return Err(denied());
        }
        // `connection.expiresAt <= Date.now()` (a missing or non-numeric expiry compares false).
        let expires_at = connection.get("expiresAt");
        let expired = match expires_at {
            Some(Value::Number(value)) => better_iam_core::js::number_value(value) <= date_now(),
            Some(Value::Null) => 0.0 <= date_now(),
            Some(Value::Bool(flag)) => (if *flag { 1.0 } else { 0.0 }) <= date_now(),
            Some(Value::String(text)) => better_iam_core::js::string_to_number(text) <= date_now(),
            _ => false,
        };
        if expired {
            return Err(denied());
        }
        let presented = hash(&token);
        let stored = js_string(connection.get("tokenHash"));
        if presented.len() != stored.len() {
            // timingSafeEqual throws a RangeError on buffers of different lengths.
            return Err(unexpected("Input buffers must have the same byte length"));
        }
        if !bool::from(presented.as_bytes().ct_eq(stored.as_bytes())) {
            return Err(denied());
        }
        let tenant_id = js_string(connection.get("tenantId"));
        active_tenant(tx.as_ref(), &tenant_id).await?;
        let now = date_now();
        let last_used = connection.get("lastUsedAt");
        let stale = match last_used {
            None => true,
            Some(value) if !truthy(Some(value)) => true,
            Some(Value::Number(value)) => {
                now - better_iam_core::js::number_value(value) >= 60_000.0
            }
            Some(_) => false,
        };
        if stale {
            connection.insert("lastUsedAt".into(), number(now));
            tx.put("scimConnections", &connection).await?;
        }
        Ok(connection)
    }

    /// Ends everything that keeps a person signed in or lets them skip a step, as an administrator's disable does:
    /// sessions (and those acting as them), remembered MFA devices and pending sign-in challenges.
    async fn revoke_sessions(&self, tx: &Store, identity_id: &str) -> IamResult<()> {
        for session in find(
            tx.as_ref(),
            "sessions",
            Filter::new().eq("identityId", identity_id),
        )
        .await?
        {
            tx.delete("sessions", &js_string(session.get("id"))).await?;
        }
        for session in find(
            tx.as_ref(),
            "sessions",
            Filter::new().eq("originalIdentityId", identity_id),
        )
        .await?
        {
            tx.delete("sessions", &js_string(session.get("id"))).await?;
        }
        for device in find(
            tx.as_ref(),
            "authDevices",
            Filter::new().eq("identityId", identity_id),
        )
        .await?
        {
            tx.delete("authDevices", &js_string(device.get("id")))
                .await?;
        }
        for challenge in find(
            tx.as_ref(),
            "authChallenges",
            Filter::new().eq("identityId", identity_id),
        )
        .await?
        {
            tx.delete("authChallenges", &js_string(challenge.get("id")))
                .await?;
        }
        Ok(())
    }

    /// The tenant's plan limit (`Tenant.limits`) holds for SCIM as for every other way people and groups are added.
    async fn within_limit(&self, tx: &Store, tenant_id: &str, key: &str) -> IamResult<()> {
        let tenant = tx.get("tenants", tenant_id).await?;
        let limit = tenant
            .as_ref()
            .and_then(|tenant| as_object(tenant.get("limits")))
            .and_then(|limits| limits.get(key))
            .cloned();
        let Some(limit) = limit else {
            return Ok(());
        };
        let count = if key == "identities" {
            find(
                tx.as_ref(),
                "identities",
                identity_filter_tenant(tenant_id).eq("kind", "user"),
            )
            .await?
            .iter()
            .filter(|item| str_member(item, "status") != Some("deleted"))
            .count()
        } else {
            find(tx.as_ref(), "groups", identity_filter_tenant(tenant_id))
                .await?
                .len()
        };
        let reached = match &limit {
            Value::Number(value) => count as f64 >= better_iam_core::js::number_value(value),
            Value::Null => count as f64 >= 0.0,
            Value::Bool(flag) => count as f64 >= if *flag { 1.0 } else { 0.0 },
            Value::String(text) => count as f64 >= better_iam_core::js::string_to_number(text),
            _ => false,
        };
        if reached {
            return Err(IamError::with_status(
                "LIMIT_EXCEEDED",
                format!(
                    "This tenant has reached its {} limit ({}).",
                    if key == "identities" {
                        "member"
                    } else {
                        "group"
                    },
                    js_string(Some(&limit))
                ),
                409,
            ));
        }
        Ok(())
    }

    /// The local identity behind a SCIM user; owners and root administrators are never provisioning targets.
    async fn identity(&self, tx: &Store, link: &Record) -> IamResult<Record> {
        let found = tx
            .get("identities", &js_string(link.get("identityId")))
            .await?;
        match found {
            Some(found)
                if found.get("tenantId") == link.get("tenantId")
                    && !truthy(found.get("rootAdmin"))
                    && !truthy(found.get("owner")) =>
            {
                Ok(found)
            }
            _ => Err(IamError::with_status(
                "mutability",
                "SCIM cannot modify a protected identity.",
                403,
            )),
        }
    }

    /// The identity a SCIM user update writes; one an administrator deleted stays a tombstone and is never revived.
    async fn updatable(&self, tx: &Store, link: &Record) -> IamResult<Record> {
        let found = self.identity(tx, link).await?;
        if str_member(&found, "status") == Some("deleted") {
            return Err(IamError::with_status(
                "mutability",
                "SCIM cannot modify a deleted identity.",
                403,
            ));
        }
        Ok(found)
    }

    /// The identity SCIM may make `report`'s manager: another identity of the tenant that is not deleted and does not
    /// already report to `report` (directly or up to 100 levels up). None skips the assignment; it is never an error.
    async fn assignable_manager(
        &self,
        tx: &Store,
        report: &Record,
        manager: &Record,
    ) -> IamResult<Option<String>> {
        let found = tx
            .get("identities", &js_string(manager.get("identityId")))
            .await?;
        let Some(found) = found else {
            return Ok(None);
        };
        if found.get("tenantId") != report.get("tenantId")
            || str_member(&found, "status") == Some("deleted")
            || found.get("id") == report.get("id")
        {
            return Ok(None);
        }
        let mut cursor = Some(found.clone());
        let mut depth = 0;
        while let Some(current) = &cursor {
            let Some(manager_id) = current.get("managerId").filter(|value| truthy(Some(value)))
            else {
                break;
            };
            if depth >= 100 {
                break;
            }
            if Some(manager_id) == report.get("id") {
                return Ok(None);
            }
            let next = js_string(Some(manager_id));
            cursor = tx.get("identities", &next).await?;
            depth += 1;
        }
        Ok(Some(js_string(found.get("id"))))
    }

    /// Identities of reports whose provisioned `manager.value` resolves to `manager`, excluding protected ones.
    async fn reports_of(
        &self,
        tx: &Store,
        users: &[Record],
        manager: &Record,
    ) -> IamResult<Vec<Record>> {
        let mut result = Vec::new();
        let index = ManagerIndex::new(users);
        for row in users {
            let value = manager_value(row.get("enterprise"));
            let Some(value) = value else {
                continue;
            };
            if row.get("id") == manager.get("id") {
                continue;
            }
            let resolved = index.resolve(&value, Some(row));
            if resolved.as_ref().and_then(|found| found.get("id")) != manager.get("id") {
                continue;
            }
            let report = tx
                .get("identities", &js_string(row.get("identityId")))
                .await?;
            if let Some(report) = report
                && report.get("tenantId") == manager.get("tenantId")
                && str_member(&report, "status") != Some("deleted")
                && !truthy(report.get("owner"))
                && !truthy(report.get("rootAdmin"))
            {
                result.push(report);
            }
        }
        Ok(result)
    }

    /// Back-fills the manager of reports provisioned before `manager`, unless they already have one.
    async fn adopt_reports(
        &self,
        tx: &Store,
        connection: &Record,
        users: &[Record],
        manager: &Record,
    ) -> IamResult<()> {
        for mut report in self.reports_of(tx, users, manager).await? {
            if truthy(report.get("managerId")) {
                continue;
            }
            let Some(manager_id) = self.assignable_manager(tx, &report, manager).await? else {
                continue;
            };
            report.insert("managerId".into(), json!(manager_id));
            tx.put("identities", &report).await?;
            self.audit(
                tx,
                connection,
                "iam:scim:UpdateUser",
                &js_string(report.get("id")),
                None,
            )
            .await?;
        }
        Ok(())
    }

    async fn members(
        &self,
        tx: &Store,
        connection: &Record,
        value: &Value,
    ) -> IamResult<Vec<String>> {
        let items = match value {
            Value::Array(items) if items.len() <= 1000 => items,
            _ => {
                return Err(IamError::new(
                    "invalidValue",
                    "members must contain at most 1000 User references.",
                ));
            }
        };
        let mut result: Vec<String> = Vec::new();
        for item in items {
            let data = object(Some(item))?;
            fields(data, &["value", "$ref", "display", "type"])?;
            if let Some(kind) = data.get("type")
                && kind != &json!("User")
            {
                return Err(IamError::new(
                    "invalidValue",
                    "Nested groups are not supported.",
                ));
            }
            let id = required_text(data.get("value"), "member.value")?;
            let user = tx.get("scimUsers", &id).await?;
            let Some(user) = user.filter(|user| {
                user.get("connectionId") == connection.get("id")
                    && user.get("tenantId") == connection.get("tenantId")
            }) else {
                return Err(IamError::new(
                    "invalidValue",
                    "Member is outside this SCIM connection.",
                ));
            };
            self.identity(tx, &user).await?;
            result.push(id);
        }
        let mut seen = HashSet::new();
        result.retain(|id| seen.insert(id.clone()));
        Ok(result)
    }

    /// Reconciles local group membership with the SCIM group and applies administrator-configured role mappings.
    pub async fn sync_group(
        &self,
        tx: &Store,
        connection: &Record,
        link: &Record,
        credential: Option<&CredentialInput>,
    ) -> IamResult<()> {
        let tenant_id = js_string(connection.get("tenantId"));
        let group_id = link.get("groupId").cloned().unwrap_or(Value::Null);
        let mut desired: Vec<String> = Vec::new();
        if let Some(Value::Array(members)) = link.get("members") {
            for member_id in members {
                let user = tx.get("scimUsers", &js_string(Some(member_id))).await?;
                let Some(user) = user.filter(|user| {
                    user.get("connectionId") == connection.get("id")
                        && user.get("tenantId") == connection.get("tenantId")
                }) else {
                    continue;
                };
                // An identity an administrator deleted never regains memberships, nor the roles mapped to them.
                let identity_id = js_string(user.get("identityId"));
                let local = tx.get("identities", &identity_id).await?;
                if local.as_ref().and_then(|local| str_member(local, "status")) != Some("deleted")
                    && !desired.contains(&identity_id)
                {
                    desired.push(identity_id);
                }
            }
        }
        let member_filter = || {
            Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("groupId", group_id.clone())
        };
        for row in find(tx.as_ref(), "groupMembers", member_filter()).await? {
            let identity_id = js_string(row.get("identityId"));
            if let Some(position) = desired.iter().position(|id| *id == identity_id) {
                desired.remove(position);
            } else {
                tx.delete("groupMembers", &js_string(row.get("id"))).await?;
            }
        }
        for identity_id in desired {
            let mut record = Map::new();
            record.insert("id".into(), json!(random_uuid()));
            record.insert("tenantId".into(), json!(tenant_id));
            record.insert("groupId".into(), group_id.clone());
            record.insert("identityId".into(), json!(identity_id));
            record.insert(
                "uniqueKey".into(),
                json!(format!("{}:{identity_id}", js_string(Some(&group_id)))),
            );
            tx.insert("groupMembers", &record).await?;
        }
        let role_ids: Vec<String> = as_object(connection.get("roleMappings"))
            .and_then(|mappings| mappings.get(&js_string(link.get("id"))))
            .and_then(Value::as_array)
            .map(|items| items.iter().map(|item| js_string(Some(item))).collect())
            .unwrap_or_default();
        if !role_ids.is_empty() && self.config.sync_role_mappings.is_none() {
            return Err(IamError::new(
                "configuration",
                "Role mapping callback is missing.",
            ));
        }
        if let Some(sync) = &self.config.sync_role_mappings {
            let all_members = find(tx.as_ref(), "groupMembers", member_filter()).await?;
            sync(
                tx.clone(),
                RoleMappingSync {
                    tenant_id: tenant_id.clone(),
                    connection_id: js_string(connection.get("id")),
                    group_id: js_string(Some(&group_id)),
                    identity_ids: all_members
                        .iter()
                        .map(|row| js_string(row.get("identityId")))
                        .collect(),
                    role_ids,
                    credential: credential.cloned(),
                },
            )
            .await?;
        }
        Ok(())
    }

    fn validate_emails(&self, emails: Option<&Value>) -> IamResult<()> {
        let Some(emails) = emails else {
            return Ok(());
        };
        let items = match emails {
            Value::Array(items) if items.len() <= 20 => items,
            _ => {
                return Err(IamError::new(
                    "invalidValue",
                    "emails must contain at most 20 email values.",
                ));
            }
        };
        for entry in items {
            let email = object(Some(entry))?;
            fields(email, &["value", "type", "primary", "display"])?;
            let value = required_text(email.get("value"), "email")?;
            if better_iam_core::js::utf16_len(&value) > 320 || !email_shape(&value, true) {
                return Err(IamError::new("invalidValue", "Invalid email address."));
            }
            if let Some(primary) = email.get("primary")
                && !primary.is_boolean()
            {
                return Err(IamError::new(
                    "invalidValue",
                    "email.primary must be a boolean.",
                ));
            }
        }
        let primaries = items
            .iter()
            .filter(|item| item.get("primary") == Some(&Value::Bool(true)))
            .count();
        if primaries > 1 {
            return Err(IamError::new(
                "invalidValue",
                "Only one primary email is allowed.",
            ));
        }
        Ok(())
    }

    /// `saveUser(tx, connection, body, existing)`.
    pub async fn save_user(
        &self,
        tx: &Store,
        connection: &Record,
        body: &ObjectValue,
        existing: Option<&Record>,
    ) -> IamResult<Record> {
        let data = without_ignored(body, ResourceType::Users, self.lenient);
        fields(
            &data,
            &[
                "schemas",
                "userName",
                "displayName",
                "externalId",
                "active",
                "emails",
                "name",
                "title",
                ENTERPRISE_SCHEMA,
            ],
        )?;
        if let Some(schemas) = data.get("schemas") {
            let valid = match schemas {
                Value::Array(items) => items
                    .iter()
                    .all(|item| item == &json!(USER_SCHEMA) || item == &json!(ENTERPRISE_SCHEMA)),
                _ => false,
            };
            if !valid {
                return Err(IamError::new("invalidValue", "Unsupported User schema."));
            }
        }
        let user_name = required_text(data.get("userName"), "userName")?;
        let display_name = text(data.get("displayName"), "displayName", true)?
            .unwrap_or_else(|| user_name.clone());
        let external_id = text(data.get("externalId"), "externalId", true)?;
        let active = bool_value(data.get("active"), true)?;
        let title = text(data.get("title"), "title", true)?;
        let mut enterprise: Option<ObjectValue> = None;
        if let Some(value) = data.get(ENTERPRISE_SCHEMA) {
            let mut extension = object(Some(value))?.clone();
            fields(
                &extension,
                &[
                    "employeeNumber",
                    "costCenter",
                    "organization",
                    "division",
                    "department",
                    "manager",
                ],
            )?;
            // Entra ID adds the manager as a bare ID (`path: "…:manager", value: "<id>"`).
            if let Some(Value::String(manager)) = extension.get("manager") {
                let manager = manager.clone();
                extension.insert("manager".into(), json!({ "value": manager }));
            }
            for (field, value) in &extension {
                if field == "manager" {
                    let manager = object(Some(value))?;
                    fields(manager, &["value", "displayName", "$ref"])?;
                    for (key, item) in manager {
                        text(Some(item), &format!("manager.{key}"), true)?;
                    }
                } else {
                    text(Some(value), field, true)?;
                }
            }
            enterprise = Some(extension);
        }
        let normalized = user_name.to_lowercase();
        let tenant_id = js_string(connection.get("tenantId"));
        let connection_id = js_string(connection.get("id"));
        let others: Vec<Record> = find(
            tx.as_ref(),
            "scimUsers",
            Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("connectionId", connection_id.clone()),
        )
        .await?
        .into_iter()
        .filter(|row| existing.is_none_or(|existing| row.get("id") != existing.get("id")))
        .collect();
        if others
            .iter()
            .any(|row| js_string(row.get("userName")).to_lowercase() == normalized)
        {
            return Err(IamError::with_status(
                "uniqueness",
                "userName already exists.",
                409,
            ));
        }
        // Provisioning never implicitly takes over an account based on email or name.
        let mut record: Record = match existing {
            Some(existing) => self.updatable(tx, existing).await?,
            None => {
                let mut record = Map::new();
                record.insert("id".into(), json!(random_uuid()));
                record.insert("tenantId".into(), json!(tenant_id));
                record.insert("kind".into(), json!("user"));
                record.insert("name".into(), json!(display_name));
                record.insert(
                    "status".into(),
                    json!(if active { "active" } else { "disabled" }),
                );
                record.insert("emailVerified".into(), json!(false));
                record.insert("rootAdmin".into(), json!(false));
                record.insert("owner".into(), json!(false));
                record.insert("createdAt".into(), number(date_now()));
                record
            }
        };
        let previous_status = existing.map(|_| record.get("status").cloned());
        let emails = data.get("emails");
        self.validate_emails(emails)?;
        let mut name: Option<ObjectValue> = None;
        if let Some(value) = data.get("name") {
            let entries = object(Some(value))?;
            fields(
                entries,
                &[
                    "formatted",
                    "familyName",
                    "givenName",
                    "middleName",
                    "honorificPrefix",
                    "honorificSuffix",
                ],
            )?;
            for (field, value) in entries {
                text(Some(value), &format!("name.{field}"), false)?;
            }
            name = Some(entries.clone());
        }
        let mut address_changed = false;
        let email_items: Option<&Vec<Value>> = emails.and_then(Value::as_array);
        let primary_email = email_items.and_then(|items| {
            items
                .iter()
                .find(|item| item.get("primary") == Some(&Value::Bool(true)))
                .or_else(|| items.first())
        });
        let email = match primary_email {
            Some(primary) => {
                Some(required_text(object(Some(primary))?.get("value"), "email")?.to_lowercase())
            }
            None => email_shape(&user_name, false).then(|| normalized.clone()),
        };
        if let Some(email) = &email {
            let record_id = record.get("id").cloned();
            let collision = find(
                tx.as_ref(),
                "identities",
                Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("email", email.clone()),
            )
            .await?
            .into_iter()
            .find(|row| row.get("id") != record_id.as_ref());
            if collision.is_some() {
                return Err(IamError::with_status(
                    "uniqueness",
                    "Email belongs to an existing identity; automatic linking is disabled.",
                    409,
                ));
            }
            // A new sign-in address ends what the old one opened, as an administrator's email change does.
            let current = record.get("email");
            if existing.is_some() && current.is_some() && current != Some(&json!(email)) {
                address_changed = true;
            }
            if record.get("email") != Some(&json!(email)) {
                record.insert("emailVerified".into(), json!(false));
            }
            record.insert("email".into(), json!(email));
            record.insert("uniqueKey".into(), json!(format!("email:{email}")));
        }
        record.insert("name".into(), json!(display_name));
        // SCIM owns `active` only when the IdP changes it: an update that leaves it alone never re-enables someone an
        // administrator disabled, and the IdP re-enables only an identity it disabled itself.
        match existing {
            None => {
                record.insert(
                    "status".into(),
                    json!(if active { "active" } else { "disabled" }),
                );
            }
            Some(_) if !active => {
                record.insert("status".into(), json!("disabled"));
            }
            Some(existing)
                if existing.get("active") == Some(&Value::Bool(false))
                    && str_member(&record, "status") == Some("disabled") =>
            {
                record.insert("status".into(), json!("active"));
            }
            Some(_) => {}
        }
        if let Some(map_attributes) = &self.config.map_attributes {
            let mapped = map_attributes(&ProvisionedUser {
                user_name: user_name.clone(),
                display_name: display_name.clone(),
                external_id: external_id.clone(),
                active,
                title: title.clone(),
                enterprise: enterprise.clone(),
                emails: email_items.cloned(),
                name: name.clone(),
            })?;
            if let Some(mapped) = mapped {
                let attributes = match &self.config.validate_identity_attributes {
                    Some(validate) => validate(&mapped)?,
                    None => mapped,
                };
                record.insert("attributes".into(), Value::Object(attributes));
            }
        }
        let now = date_now();
        let mut link = Map::new();
        link.insert(
            "id".into(),
            match existing {
                Some(existing) => existing.get("id").cloned().unwrap_or(Value::Null),
                None => json!(random_uuid()),
            },
        );
        link.insert("tenantId".into(), json!(tenant_id));
        link.insert("connectionId".into(), json!(connection_id));
        put_member(&mut link, "identityId", record.get("id"));
        link.insert(
            "uniqueKey".into(),
            json!(hash(&format!("{connection_id}:{normalized}"))),
        );
        link.insert("userName".into(), json!(user_name));
        link.insert("displayName".into(), json!(display_name));
        if let Some(external_id) = &external_id {
            link.insert("externalId".into(), json!(external_id));
        }
        link.insert("active".into(), json!(active));
        put_member(&mut link, "emails", emails);
        if let Some(name) = &name {
            link.insert("name".into(), Value::Object(name.clone()));
        }
        let version = existing
            .and_then(|existing| existing.get("version"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0)
            + 1.0;
        link.insert("version".into(), number(version));
        link.insert(
            "createdAt".into(),
            existing
                .and_then(|existing| existing.get("createdAt").cloned())
                .unwrap_or_else(|| number(now)),
        );
        link.insert("updatedAt".into(), number(now));
        if let Some(title) = &title {
            link.insert("title".into(), json!(title));
        }
        if let Some(enterprise) = &enterprise {
            link.insert("enterprise".into(), Value::Object(enterprise.clone()));
        }
        let value = manager_value(
            enterprise
                .as_ref()
                .map(|map| Value::Object(map.clone()))
                .as_ref(),
        );
        let previous = manager_value(existing.and_then(|existing| existing.get("enterprise")));
        if self.map_manager() && (value.is_some() || previous.is_some()) {
            // References resolve over all of the connection's users: the others plus this one as saved or as it was.
            let index = ManagerIndex::new(&others);
            // SCIM owns the manager only while its previous reference still names it; admin-set managers stay.
            let owned = match (&previous, record.get("managerId")) {
                (Some(previous), Some(manager_id)) => {
                    index
                        .resolve(previous, existing)
                        .and_then(|found| found.get("identityId").cloned())
                        .as_ref()
                        == Some(manager_id)
                }
                _ => false,
            };
            let manager = value
                .as_ref()
                .and_then(|value| index.resolve(value, Some(&link)));
            // A user naming themself resolves to themself, which `assignable_manager` skips.
            let manager_id = match &manager {
                Some(manager) => self.assignable_manager(tx, &record, manager).await?,
                None => None,
            };
            // A manager not provisioned yet is back-filled later; a SCIM-set one the IdP stopped naming is cleared.
            if let Some(manager_id) = manager_id {
                record.insert("managerId".into(), json!(manager_id));
            } else if owned && value != previous {
                record.shift_remove("managerId");
            }
        }
        if existing.is_some() {
            tx.put("identities", &record).await?;
        } else {
            self.within_limit(tx, &tenant_id, "identities").await?;
            tx.insert("identities", &record).await?;
        }
        let record_id = js_string(record.get("id"));
        if str_member(&record, "status") != Some("active") || address_changed {
            self.revoke_sessions(tx, &record_id).await?;
        }
        // A deactivation or reactivation moves what follows the status (license seats) at once; new users hold
        // nothing.
        if let Some(previous_status) = &previous_status
            && record.get("status") != previous_status.as_ref()
            && let Some(changed) = &self.config.identity_status_changed
        {
            changed(
                tx.clone(),
                IdentityStatusChange {
                    tenant_id: tenant_id.clone(),
                    connection_id: connection_id.clone(),
                    identity_id: record_id.clone(),
                },
            )
            .await?;
        }
        if existing.is_some() {
            tx.put("scimUsers", &link).await?;
        } else {
            tx.insert("scimUsers", &link).await?;
        }
        self.audit(
            tx,
            connection,
            if existing.is_some() {
                "iam:scim:UpdateUser"
            } else {
                "iam:scim:CreateUser"
            },
            &record_id,
            None,
        )
        .await?;
        if self.map_manager() {
            let mut users = others.clone();
            users.push(link.clone());
            self.adopt_reports(tx, connection, &users, &link).await?;
        }
        Ok(link)
    }

    /// `saveGroup(tx, connection, data, existing)`.
    pub async fn save_group(
        &self,
        tx: &Store,
        connection: &Record,
        body: &ObjectValue,
        existing: Option<&Record>,
    ) -> IamResult<Record> {
        let data = without_ignored(body, ResourceType::Groups, self.lenient);
        fields(&data, &["schemas", "displayName", "externalId", "members"])?;
        if let Some(schemas) = data.get("schemas") {
            let valid = match schemas {
                Value::Array(items) => items.iter().all(|item| item == &json!(GROUP_SCHEMA)),
                _ => false,
            };
            if !valid {
                return Err(IamError::new("invalidValue", "Unsupported Group schema."));
            }
        }
        let display_name = required_text(data.get("displayName"), "displayName")?;
        let external_id = text(data.get("externalId"), "externalId", true)?;
        let empty = Value::Array(Vec::new());
        let member_ids = self
            .members(
                tx,
                connection,
                data.get("members")
                    .filter(|value| !value.is_null())
                    .unwrap_or(&empty),
            )
            .await?;
        let now = date_now();
        let tenant_id = js_string(connection.get("tenantId"));
        let mut link = Map::new();
        link.insert(
            "id".into(),
            match existing {
                Some(existing) => existing.get("id").cloned().unwrap_or(Value::Null),
                None => json!(random_uuid()),
            },
        );
        link.insert("tenantId".into(), json!(tenant_id));
        put_member(&mut link, "connectionId", connection.get("id"));
        link.insert(
            "groupId".into(),
            match existing
                .and_then(|existing| existing.get("groupId"))
                .filter(|value| !value.is_null())
            {
                Some(group_id) => group_id.clone(),
                None => json!(random_uuid()),
            },
        );
        link.insert("displayName".into(), json!(display_name));
        if let Some(external_id) = &external_id {
            link.insert("externalId".into(), json!(external_id));
        }
        link.insert("members".into(), json!(member_ids));
        let version = existing
            .and_then(|existing| existing.get("version"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0)
            + 1.0;
        link.insert("version".into(), number(version));
        link.insert(
            "createdAt".into(),
            existing
                .and_then(|existing| existing.get("createdAt").cloned())
                .unwrap_or_else(|| number(now)),
        );
        link.insert("updatedAt".into(), number(now));
        let group_id = js_string(link.get("groupId"));
        if existing.is_some() {
            let mut group = tx.get("groups", &group_id).await?.unwrap_or_default();
            group.insert("id".into(), json!(group_id));
            group.insert("tenantId".into(), json!(tenant_id));
            group.insert("name".into(), json!(display_name));
            tx.put("groups", &group).await?;
        } else {
            self.within_limit(tx, &tenant_id, "groups").await?;
            let mut group = Map::new();
            group.insert("id".into(), json!(group_id));
            group.insert("tenantId".into(), json!(tenant_id));
            group.insert("name".into(), json!(display_name));
            group.insert("createdAt".into(), number(now));
            tx.insert("groups", &group).await?;
        }
        if existing.is_some() {
            tx.put("scimGroups", &link).await?;
        } else {
            tx.insert("scimGroups", &link).await?;
        }
        self.sync_group(tx, connection, &link, None).await?;
        self.audit(
            tx,
            connection,
            if existing.is_some() {
                "iam:scim:UpdateGroup"
            } else {
                "iam:scim:CreateGroup"
            },
            &group_id,
            None,
        )
        .await?;
        Ok(link)
    }

    /// `patch(tx, connection, type, row, input)`: applies a PatchOp to a materialized resource and saves it through
    /// the same validation as PUT.
    pub async fn patch(
        &self,
        tx: &Store,
        connection: &Record,
        kind: ResourceType,
        row: &Record,
        input: &ObjectValue,
    ) -> IamResult<Record> {
        fields(input, &["schemas", "Operations"])?;
        let operations = match (input.get("schemas"), input.get("Operations")) {
            (Some(Value::Array(schemas)), Some(Value::Array(operations)))
                if schemas.len() == 1
                    && schemas[0] == json!(PATCH_SCHEMA)
                    && !operations.is_empty()
                    && operations.len() <= 100 =>
            {
                operations
            }
            _ => {
                return Err(IamError::new(
                    "invalidSyntax",
                    "PATCH requires the PatchOp schema and 1–100 operations.",
                ));
            }
        };
        // Cloned so a failed operation never mutates the stored row; every writable attribute round-trips.
        let mut data = ObjectValue::new();
        match kind {
            ResourceType::Users => {
                for key in [
                    "userName",
                    "displayName",
                    "externalId",
                    "active",
                    "emails",
                    "name",
                    "title",
                ] {
                    put_member(&mut data, key, row.get(key));
                }
                if let Some(enterprise) = row.get("enterprise").filter(|value| truthy(Some(value)))
                {
                    data.insert(ENTERPRISE_SCHEMA.into(), enterprise.clone());
                }
            }
            ResourceType::Groups => {
                put_member(&mut data, "displayName", row.get("displayName"));
                put_member(&mut data, "externalId", row.get("externalId"));
                let members: Vec<Value> = match row.get("members") {
                    Some(Value::Array(items)) => items
                        .iter()
                        .map(|value| json!({ "value": value }))
                        .collect(),
                    _ => Vec::new(),
                };
                data.insert("members".into(), Value::Array(members));
            }
        }
        let lenient = self.lenient;
        for item in operations {
            let op = object(Some(item))?;
            fields(op, &["op", "path", "value"])?;
            let operation = match op.get("op") {
                Some(Value::String(text)) => text.to_lowercase(),
                _ => String::new(),
            };
            if !["add", "replace", "remove"].contains(&operation.as_str()) {
                return Err(IamError::new(
                    "invalidSyntax",
                    "Unsupported PATCH operation.",
                ));
            }
            let path = match op.get("path") {
                None => None,
                Some(value) => Some(required_text(Some(value), "path")?),
            };
            let ignored = |name: &str, explicit_path: bool| {
                ignored_attribute(name, kind, lenient, !explicit_path)
            };
            apply_patch_operation(
                &mut data,
                kind,
                &operation,
                path.as_deref(),
                op.get("value"),
                &ignored,
            )?;
        }
        if kind == ResourceType::Users && data.contains_key(ENTERPRISE_SCHEMA) {
            let extension = object(data.get(ENTERPRISE_SCHEMA))?;
            if extension.is_empty() {
                data.shift_remove(ENTERPRISE_SCHEMA);
            }
        }
        match kind {
            ResourceType::Users => self.save_user(tx, connection, &data, Some(row)).await,
            ResourceType::Groups => self.save_group(tx, connection, &data, Some(row)).await,
        }
    }

    /// Deactivates the local identity and removes the user from every SCIM group of the connection. Reports whose
    /// manager SCIM set from this user lose it (it is back-filled if the user is provisioned again). An identity an
    /// administrator deleted stays a tombstone; deletion already revoked its sessions and released its reports.
    pub async fn delete_user(
        &self,
        tx: &Store,
        connection: &Record,
        row: &Record,
    ) -> IamResult<()> {
        let local = self.identity(tx, row).await?;
        let local_id = js_string(local.get("id"));
        let deleted = str_member(&local, "status") == Some("deleted");
        if !deleted {
            let mut disabled = local.clone();
            disabled.insert("status".into(), json!("disabled"));
            tx.put("identities", &disabled).await?;
            self.revoke_sessions(tx, &local_id).await?;
        }
        let tenant_id = js_string(connection.get("tenantId"));
        let connection_filter = || {
            Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("connectionId", filter_value(connection, "id"))
        };
        if self.map_manager() && !deleted {
            let users = find(tx.as_ref(), "scimUsers", connection_filter()).await?;
            for mut report in self.reports_of(tx, &users, row).await? {
                if report.get("managerId") != Some(&json!(local_id)) {
                    continue;
                }
                report.shift_remove("managerId");
                tx.put("identities", &report).await?;
                self.audit(
                    tx,
                    connection,
                    "iam:scim:UpdateUser",
                    &js_string(report.get("id")),
                    None,
                )
                .await?;
            }
        }
        let row_id = row.get("id").cloned().unwrap_or(Value::Null);
        for mut group in find(tx.as_ref(), "scimGroups", connection_filter()).await? {
            let Some(Value::Array(members)) = group.get("members") else {
                continue;
            };
            if !members.contains(&row_id) {
                continue;
            }
            let kept: Vec<Value> = members
                .iter()
                .filter(|id| **id != row_id)
                .cloned()
                .collect();
            group.insert("members".into(), Value::Array(kept));
            let version = group
                .get("version")
                .and_then(Value::as_f64)
                .unwrap_or(f64::NAN)
                + 1.0;
            group.insert("version".into(), number(version));
            group.insert("updatedAt".into(), number(date_now()));
            tx.put("scimGroups", &group).await?;
            self.sync_group(tx, connection, &group, None).await?;
        }
        // Seats held through a direct assignment go with the deactivation too, not only those of the SCIM groups.
        if str_member(&local, "status") == Some("active")
            && let Some(changed) = &self.config.identity_status_changed
        {
            changed(
                tx.clone(),
                IdentityStatusChange {
                    tenant_id: tenant_id.clone(),
                    connection_id: js_string(connection.get("id")),
                    identity_id: local_id,
                },
            )
            .await?;
        }
        Ok(())
    }

    /// `deleteGroup(tx, connection, row)`.
    pub async fn delete_group(
        &self,
        tx: &Store,
        connection: &Record,
        row: &Record,
    ) -> IamResult<()> {
        let mut emptied = row.clone();
        emptied.insert("members".into(), Value::Array(Vec::new()));
        self.sync_group(tx, connection, &emptied, None).await?;
        let tenant_id = js_string(connection.get("tenantId"));
        let filter = filter_eq(
            Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("subjectType", "group"),
            "subjectId",
            row.get("groupId"),
        );
        let filter = filter_eq(filter, "scimConnectionId", connection.get("id"));
        for binding in find(tx.as_ref(), "bindings", filter).await? {
            tx.delete("bindings", &js_string(binding.get("id"))).await?;
        }
        let group_id = js_string(row.get("groupId"));
        // What the server gave the group (license assignments) must not outlive its record.
        if let Some(deleted) = &self.config.group_deleted {
            deleted(
                tx.clone(),
                GroupDeletion {
                    tenant_id,
                    connection_id: js_string(connection.get("id")),
                    group_id: group_id.clone(),
                },
            )
            .await?;
        }
        tx.delete("groups", &group_id).await
    }
}

/// `record[key] = value` when the value is defined (JSON drops `undefined` members).
pub(crate) fn put_member(record: &mut Map<String, Value>, key: &str, value: Option<&Value>) {
    if let Some(value) = value {
        record.insert(key.to_owned(), value.clone());
    }
}

/// `authorization.match(/^Bearer (\S+)$/i)?.[1]`.
fn bearer_token(header: &str) -> Option<String> {
    let scheme = header.get(..7)?;
    if !scheme.eq_ignore_ascii_case("bearer ") {
        return None;
    }
    let token = &header[7..];
    (!token.is_empty() && !token.chars().any(better_iam_core::js::is_js_whitespace))
        .then(|| token.to_owned())
}

/// `/^[^\s@]+@[^\s@]+\.[^\s@]+$/` (with `dotted`) or `/^[^\s@]+@[^\s@]+$/`.
fn email_shape(value: &str, dotted: bool) -> bool {
    let bad = |c: char| c == '@' || better_iam_core::js::is_js_whitespace(c);
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    if local.is_empty() || local.chars().any(bad) || domain.is_empty() || domain.chars().any(bad) {
        return false;
    }
    if !dotted {
        return true;
    }
    // `[^\s@]+\.[^\s@]+`: some dot with at least one character on each side.
    domain
        .char_indices()
        .any(|(index, c)| c == '.' && index > 0 && index + 1 < domain.len())
}
