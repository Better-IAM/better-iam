//! Port of `packages/server/src/ldap.ts`: the server side of the LDAP directory gateway (`@better-iam/ldap`).
//!
//! Each tenant can publish its directory under a base DN of its own, so applications that only speak LDAP (VPNs,
//! NAS devices, CI servers, wikis) look people and groups up and check passwords against Better IAM. The gateway
//! decodes LDAP; this module holds the settings, the deployment-wide base DN index, and the directory view a bound
//! account may read.

use std::sync::{Arc, LazyLock};

use better_iam_core::{
    AuthenticatedPrincipal, Filter, FindOptions, IamError, IamResult, Identity, IdentityKind,
    IdentityStatus, Record, Tenant, TenantStatus, js as core_js,
};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::models::{Group, GroupMember};
use crate::port::decode;

/// What a bound account may read: everyone (`full`, with `iam:ldap:read`) or only itself (`self`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LdapDirectory {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "tenantName")]
    pub tenant_name: String,
    #[serde(rename = "baseDn")]
    pub base_dn: String,
    #[serde(rename = "uid")]
    pub uid: crate::ldap::LdapUidMode,
    /// `'full' | 'self'`.
    #[serde(rename = "scope")]
    pub scope: String,
    /// `LdapPerson[]`.
    #[serde(rename = "people")]
    pub people: Vec<Value>,
    /// `LdapGroupView[]`.
    #[serde(rename = "groups")]
    pub groups: Vec<Value>,
    /// `LdapService[]`.
    #[serde(rename = "services")]
    pub services: Vec<Value>,
    #[serde(rename = "generatedAt")]
    pub generated_at: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl LdapDirectory {
    /// The directory as the TypeScript object (numbers in JavaScript form).
    pub fn to_json(&self) -> Value {
        json!({
            "tenantId": self.tenant_id,
            "tenantName": self.tenant_name,
            "baseDn": self.base_dn,
            "uid": self.uid,
            "scope": self.scope,
            "people": self.people,
            "groups": self.groups,
            "services": self.services,
            "generatedAt": crate::js::number(self.generated_at),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LdapSettings {
    #[serde(rename = "enabled")]
    pub enabled: bool,
    /// As entered (`dc=acme,dc=com`); `normalizedBaseDn` is the lowercased comparison form.
    #[serde(rename = "baseDn")]
    pub base_dn: String,
    #[serde(rename = "normalizedBaseDn")]
    pub normalized_base_dn: String,
    /// What `uid` (and the people RDN) holds: the email (default), its local part (when unique), or the identity ID.
    #[serde(rename = "uid")]
    pub uid: crate::ldap::LdapUidMode,
    /// People may bind with their password (default true).
    #[serde(rename = "peopleBind")]
    pub people_bind: bool,
    /// Service accounts and agents may bind with an API key as the password (default true).
    #[serde(rename = "serviceBind")]
    pub service_bind: bool,
    /// Binds over a connection without TLS are refused, except from loopback (default true).
    #[serde(rename = "requireTls")]
    pub require_tls: bool,
    /// With `auto`, a password ending in six digits is also tried as password + one-time code when MFA is required.
    #[serde(rename = "mfaSuffix")]
    pub mfa_suffix: String,
    /// List service accounts under `ou=services` (default false; they can always bind).
    #[serde(rename = "includeServiceAccounts")]
    pub include_service_accounts: bool,
    /// Declared identity attributes published on people's entries (default none: attributes may be sensitive).
    #[serde(rename = "attributes")]
    pub attributes: Vec<String>,
    /// Groups to publish: every group, or `groupIds` only.
    #[serde(rename = "groups")]
    pub groups: String,
    #[serde(rename = "groupIds")]
    pub group_ids: Vec<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "updatedBy")]
    pub updated_by: String,
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

impl LdapSettings {
    /// The stored record, in the member order TypeScript writes (`defaultLdapSettings` then unknown members).
    pub fn to_record(&self) -> Record {
        let number = crate::js::number;
        let mut record = Record::new();
        record.insert("id".into(), Value::String(self.id.clone()));
        record.insert("tenantId".into(), Value::String(self.tenant_id.clone()));
        record.insert("enabled".into(), Value::Bool(self.enabled));
        record.insert("baseDn".into(), Value::String(self.base_dn.clone()));
        record.insert(
            "normalizedBaseDn".into(),
            Value::String(self.normalized_base_dn.clone()),
        );
        record.insert("uid".into(), Value::String(self.uid.clone()));
        record.insert("peopleBind".into(), Value::Bool(self.people_bind));
        record.insert("serviceBind".into(), Value::Bool(self.service_bind));
        record.insert("requireTls".into(), Value::Bool(self.require_tls));
        record.insert("mfaSuffix".into(), Value::String(self.mfa_suffix.clone()));
        record.insert(
            "includeServiceAccounts".into(),
            Value::Bool(self.include_service_accounts),
        );
        record.insert("attributes".into(), json!(self.attributes));
        record.insert("groups".into(), Value::String(self.groups.clone()));
        record.insert("groupIds".into(), json!(self.group_ids));
        record.insert("updatedAt".into(), number(self.updated_at));
        record.insert("updatedBy".into(), Value::String(self.updated_by.clone()));
        if let Some(unique_key) = &self.unique_key {
            record.insert("uniqueKey".into(), Value::String(unique_key.clone()));
        }
        for (key, value) in &self.extra {
            record.insert(key.clone(), value.clone());
        }
        record
    }
}

/// What `uid` (and the people RDN) holds: `'email' | 'localPart' | 'id'`.
pub type LdapUidMode = String;

/// The collections this module owns.
pub const LDAP_COLLECTIONS: [&str; 2] = ["ldapSettings", "ldapBases"];

static COMPONENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*([a-zA-Z][a-zA-Z0-9-]{0,31})\s*=\s*([a-zA-Z0-9](?:[a-zA-Z0-9 ._-]{0,126}[a-zA-Z0-9])?)\s*$",
    )
    .expect("valid base DN component pattern")
});
static WHITESPACE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s+").expect("valid whitespace pattern"));

/// A validated base DN: as entered (components trimmed) and its comparison form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedBaseDn {
    pub base_dn: String,
    pub normalized: String,
}

/// Validates a base DN and returns its comparison form: `attr=value` components of letters, digits, spaces, `.`,
/// `_` and `-` (no escapes), lowercased with spaces collapsed, exactly as `@better-iam/ldap` normalizes DNs.
pub fn normalize_base_dn(value: Option<&Value>) -> IamResult<NormalizedBaseDn> {
    let value = match value {
        Some(Value::String(value))
            if !core_js::trim(value).is_empty() && core_js::utf16_len(value) <= 512 =>
        {
            value
        }
        _ => {
            return Err(IamError::new(
                "INVALID_INPUT",
                "Enter a base DN such as dc=acme,dc=com",
            ));
        }
    };
    let parts: Vec<&str> = value.split(',').collect();
    if parts.len() > 10 {
        return Err(IamError::new(
            "INVALID_INPUT",
            "A base DN has at most 10 components",
        ));
    }
    let mut normalized = Vec::with_capacity(parts.len());
    for part in &parts {
        let Some(found) = COMPONENT.captures(part) else {
            return Err(IamError::new(
                "INVALID_INPUT",
                "Base DN components are attr=value with letters, digits, spaces, \".\", \"_\" or \"-\"",
            ));
        };
        normalized.push(format!(
            "{}={}",
            found[1].to_ascii_lowercase(),
            WHITESPACE.replace_all(&found[2], " ").to_ascii_lowercase()
        ));
    }
    if ["ou=people", "ou=groups", "ou=services"].contains(&normalized[0].as_str()) {
        return Err(IamError::new(
            "INVALID_INPUT",
            "The base DN cannot itself be ou=people, ou=groups or ou=services",
        ));
    }
    Ok(NormalizedBaseDn {
        base_dn: parts
            .iter()
            .map(|part| core_js::trim(part))
            .collect::<Vec<_>>()
            .join(","),
        normalized: normalized.join(","),
    })
}

/// `(tenant.slug ?? tenant.id).toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/^-+|-+$/g, '') || 'tenant'`.
fn tenant_slug(tenant: &Tenant) -> String {
    let source = core_js::to_lower(tenant.slug.as_deref().unwrap_or(&tenant.id));
    let mut slug = String::new();
    for c in source.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' {
            slug.push(c);
        } else {
            // The pattern has no `u` flag: each UTF-16 code unit is replaced.
            for _ in 0..c.len_utf16() {
                slug.push('-');
            }
        }
    }
    let trimmed = slug.trim_matches('-');
    if trimmed.is_empty() {
        "tenant".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// The settings of a tenant that never configured the gateway.
pub fn default_ldap_settings(tenant: &Tenant) -> LdapSettings {
    let base_dn = format!("o={}", tenant_slug(tenant));
    LdapSettings {
        id: tenant.id.clone(),
        tenant_id: tenant.id.clone(),
        unique_key: None,
        enabled: false,
        base_dn: base_dn.clone(),
        normalized_base_dn: base_dn,
        uid: "email".into(),
        people_bind: true,
        service_bind: true,
        require_tls: true,
        mfa_suffix: "auto".into(),
        include_service_accounts: false,
        attributes: Vec::new(),
        groups: "all".into(),
        group_ids: Vec::new(),
        updated_at: 0.0,
        updated_by: String::new(),
        extra: Map::new(),
    }
}

/// The tenant's gateway settings: the stored record over the defaults, or the defaults.
pub async fn load_ldap_settings(tx: &Store, tenant: &Tenant) -> IamResult<LdapSettings> {
    let defaults = default_ldap_settings(tenant);
    match tx.get("ldapSettings", &tenant.id).await? {
        Some(stored)
            if stored.get("tenantId").and_then(Value::as_str) == Some(tenant.id.as_str()) =>
        {
            let mut merged = defaults.to_record();
            for (key, value) in stored {
                merged.insert(key, value);
            }
            decode(merged)
        }
        _ => Ok(defaults),
    }
}

/// Stores settings and keeps the base DN index in step (a base DN belongs to one tenant).
pub async fn save_ldap_settings(
    tx: &Store,
    settings: &LdapSettings,
    previous: Option<&LdapSettings>,
) -> IamResult<LdapSettings> {
    if let Some(previous) = previous
        && previous.normalized_base_dn != settings.normalized_base_dn
        && let Some(old) = tx.get("ldapBases", &previous.normalized_base_dn).await?
        && old.get("tenantId").and_then(Value::as_str) == Some(settings.tenant_id.as_str())
    {
        tx.delete("ldapBases", better_iam_core::record_id(&old))
            .await?;
    }
    let owner = tx.get("ldapBases", &settings.normalized_base_dn).await?;
    let owned_here = |owner: &Record| {
        owner.get("tenantId").and_then(Value::as_str) == Some(settings.tenant_id.as_str())
    };
    if settings.enabled {
        if let Some(owner) = &owner
            && !owned_here(owner)
        {
            return Err(IamError::with_status(
                "LDAP_BASE_TAKEN",
                "Another organization publishes its directory under this base DN",
                409,
            ));
        }
        if owner.is_none() {
            let mut base = Record::new();
            base.insert(
                "id".into(),
                Value::String(settings.normalized_base_dn.clone()),
            );
            base.insert("tenantId".into(), Value::String(settings.tenant_id.clone()));
            base.insert("settingsId".into(), Value::String(settings.id.clone()));
            tx.insert("ldapBases", &base).await?;
        }
    } else if let Some(owner) = &owner
        && owned_here(owner)
    {
        tx.delete("ldapBases", better_iam_core::record_id(owner))
            .await?;
    }
    let record = settings.to_record();
    let stored = if tx.get("ldapSettings", &settings.id).await?.is_some() {
        tx.put("ldapSettings", &record).await?
    } else {
        tx.insert("ldapSettings", &record).await?
    };
    decode(stored)
}

fn live(ctx: &ServerContext, identity: &Identity) -> bool {
    identity.status == IdentityStatus::Active && !ctx.identity_expired(identity)
}

/// Each person's `uid`: email, local part (the email where local parts collide), or identity ID.
fn uids(people: &[Identity], mode: &str) -> IndexMap<String, String> {
    let local = |identity: &Identity| {
        let source = identity.email.as_deref().unwrap_or(&identity.id);
        core_js::to_lower(source.split('@').next().unwrap_or_default())
    };
    let mut counts: IndexMap<String, usize> = IndexMap::new();
    if mode == "localPart" {
        for person in people {
            *counts.entry(local(person)).or_insert(0) += 1;
        }
    }
    people
        .iter()
        .map(|person| {
            let uid = if mode == "id" {
                person.id.clone()
            } else if mode == "localPart" && counts.get(&local(person)) == Some(&1) {
                local(person)
            } else {
                core_js::to_lower(person.email.as_deref().unwrap_or(&person.id))
            };
            (person.id.clone(), uid)
        })
        .collect()
}

fn kind_name(kind: IdentityKind) -> String {
    match serde_json::to_value(kind) {
        Ok(Value::String(kind)) => kind,
        _ => String::new(),
    }
}

async fn tenant_identities(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
) -> IamResult<Vec<Identity>> {
    let mut identities = Vec::new();
    for record in tx
        .find(
            "identities",
            &Filter::new().eq("tenantId", tenant_id),
            &FindOptions::default(),
        )
        .await?
    {
        let identity: Identity = decode(record)?;
        if live(ctx, &identity) {
            identities.push(identity);
        }
    }
    Ok(identities)
}

fn string_member<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// Builds the directory view of a tenant: active people, published groups and (optionally) service accounts.
pub async fn build_ldap_directory(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant: &Tenant,
    settings: &LdapSettings,
    self_: Option<&AuthenticatedPrincipal>,
) -> IamResult<LdapDirectory> {
    let identities = tenant_identities(ctx, tx, &tenant.id).await?;
    let (people, machines): (Vec<&Identity>, Vec<&Identity>) = identities
        .iter()
        .partition(|identity| identity.kind == IdentityKind::User);
    let people_owned: Vec<Identity> = people.iter().map(|person| (*person).clone()).collect();
    let uid_of = uids(&people_owned, &settings.uid);
    let mut groups: Vec<Group> = tx
        .find(
            "groups",
            &Filter::new().eq("tenantId", tenant.id.clone()),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .map(decode::<Group>)
        .collect::<IamResult<_>>()?;
    if settings.groups == "selected" {
        groups.retain(|group| settings.group_ids.contains(&group.id));
    }
    let mut members: IndexMap<String, Vec<String>> = IndexMap::new();
    let mut memberships: IndexMap<String, Vec<String>> = IndexMap::new();
    for group in &groups {
        let mut ids = Vec::new();
        for member in tx
            .find(
                "groupMembers",
                &Filter::new().eq("groupId", group.id.clone()),
                &FindOptions::default(),
            )
            .await?
        {
            let member: GroupMember = decode(member)?;
            if ctx.live_membership(&member) {
                ids.push(member.identity_id);
            }
        }
        for identity_id in &ids {
            memberships
                .entry(identity_id.clone())
                .or_default()
                .push(group.id.clone());
        }
        members.insert(group.id.clone(), ids);
    }
    let alive: IndexSet<&str> = identities
        .iter()
        .map(|identity| identity.id.as_str())
        .collect();
    let mut person_views: Vec<Value> = people
        .iter()
        .map(|person| {
            let mut view = Map::new();
            view.insert("id".into(), Value::String(person.id.clone()));
            view.insert(
                "uid".into(),
                Value::String(uid_of.get(&person.id).cloned().unwrap_or_default()),
            );
            if let Some(email) = person.email.as_ref().filter(|email| !email.is_empty()) {
                view.insert("email".into(), Value::String(email.clone()));
            }
            if !person.name.is_empty() {
                view.insert("name".into(), Value::String(person.name.clone()));
            }
            view.insert("emailVerified".into(), Value::Bool(person.email_verified));
            let attributes: Map<String, Value> = settings
                .attributes
                .iter()
                .filter_map(|name| {
                    let value = person
                        .attributes
                        .as_ref()
                        .and_then(|attributes| attributes.get(name))?;
                    (!value.is_null()).then(|| (name.clone(), value.clone()))
                })
                .collect();
            view.insert("attributes".into(), Value::Object(attributes));
            view.insert(
                "groupIds".into(),
                json!(memberships.get(&person.id).cloned().unwrap_or_default()),
            );
            Value::Object(view)
        })
        .collect();
    let mut group_views: Vec<Value> = groups
        .iter()
        .map(|group| {
            let mut view = Map::new();
            view.insert("id".into(), Value::String(group.id.clone()));
            view.insert("name".into(), Value::String(group.name.clone()));
            if let Some(description) = &group.description {
                view.insert("description".into(), Value::String(description.clone()));
            }
            let member_ids: Vec<String> = members
                .get(&group.id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|identity_id| alive.contains(identity_id.as_str()))
                .collect();
            view.insert("memberIds".into(), json!(member_ids));
            Value::Object(view)
        })
        .collect();
    let mut services: Vec<Value> = if settings.include_service_accounts {
        machines
            .iter()
            .map(|machine| {
                json!({
                    "id": machine.id,
                    "name": machine.name,
                    "kind": kind_name(machine.kind),
                    "groupIds": memberships.get(&machine.id).cloned().unwrap_or_default(),
                })
            })
            .collect()
    } else {
        Vec::new()
    };
    if let Some(me) = self_ {
        // Only the caller's own entry, and their groups with only themselves as a member.
        let me = me.identity.id.as_str();
        person_views.retain(|person| string_member(person, "id") == me);
        services.retain(|service| string_member(service, "id") == me);
        group_views = group_views
            .into_iter()
            .filter(|group| {
                group
                    .get("memberIds")
                    .and_then(Value::as_array)
                    .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(me)))
            })
            .map(|mut group| {
                if let Value::Object(view) = &mut group {
                    view.insert("memberIds".into(), json!([me]));
                }
                group
            })
            .collect();
    }
    let by = |key: &'static str| {
        move |a: &Value, b: &Value| core_js::cmp_utf16(string_member(a, key), string_member(b, key))
    };
    person_views.sort_by(by("uid"));
    group_views.sort_by(by("name"));
    services.sort_by(by("name"));
    Ok(LdapDirectory {
        tenant_id: tenant.id.clone(),
        tenant_name: tenant.name.clone(),
        base_dn: settings.base_dn.clone(),
        uid: settings.uid.clone(),
        scope: if self_.is_some() { "self" } else { "full" }.into(),
        people: person_views,
        groups: group_views,
        services,
        generated_at: ctx.now(),
        extra: Map::new(),
    })
}

/// The deployment-side lookups the gateway needs before anyone is bound (no credential; no secrets).
pub struct LdapRuntime {
    ctx: Arc<ServerContext>,
}

/// `createLdapRuntime(ctx)`.
pub fn create_ldap_runtime(ctx: &Arc<ServerContext>) -> IamResult<LdapRuntime> {
    Ok(LdapRuntime { ctx: ctx.clone() })
}

impl LdapRuntime {
    async fn tenant_for(
        &self,
        tx: &Store,
        normalized_base_dn: &str,
    ) -> IamResult<Option<(Tenant, LdapSettings)>> {
        let ctx = &self.ctx;
        let Some(base) = tx.get("ldapBases", normalized_base_dn).await? else {
            return Ok(None);
        };
        let Some(tenant_id) = base.get("tenantId").and_then(Value::as_str) else {
            return Ok(None);
        };
        let Some(tenant) = tx.get("tenants", tenant_id).await? else {
            return Ok(None);
        };
        let tenant: Tenant = decode(tenant)?;
        if ctx
            .ancestry(tx, &tenant)
            .await?
            .iter()
            .any(|item| item.status != TenantStatus::Active)
        {
            return Ok(None);
        }
        let settings = load_ldap_settings(tx, &tenant).await?;
        Ok(
            (settings.enabled && settings.normalized_base_dn == normalized_base_dn)
                .then_some((tenant, settings)),
        )
    }

    /// The tenant publishing its directory under a normalized base DN, with its gateway settings; undefined when none
    /// does, it is off, or the organization is not active.
    pub async fn tenant_for_base(&self, normalized_base_dn: &str) -> IamResult<Option<Value>> {
        let found = self.tenant_for(&self.ctx.store, normalized_base_dn).await?;
        Ok(found.map(|(tenant, settings)| {
            json!({
                "tenantId": tenant.id,
                "tenantName": tenant.name,
                "baseDn": settings.base_dn,
                "normalizedBaseDn": settings.normalized_base_dn,
                "uid": settings.uid,
                "peopleBind": settings.people_bind,
                "serviceBind": settings.service_bind,
                "requireTls": settings.require_tls,
                "mfaSuffix": settings.mfa_suffix,
            })
        }))
    }

    /// The sign-in email of the person a people RDN value names (`uid` as the tenant configured it), or the service
    /// account a name (or, when names collide, an ID) names; undefined when nobody matches. Only active members
    /// resolve. `mfa` says how a person's bind must authenticate: `none` (the password), `totp` (the password followed
    /// by the current authenticator code) or `unavailable` (MFA is required but no authenticator is enrolled, which
    /// LDAP cannot satisfy), so the gateway makes exactly one sign-in attempt per bind.
    pub async fn resolve_bind_name(
        &self,
        tenant_id: &str,
        kind: &str,
        value: &str,
    ) -> IamResult<Option<Value>> {
        let ctx = &self.ctx;
        let store = &ctx.store;
        let Some(tenant) = store.get("tenants", tenant_id).await? else {
            return Ok(None);
        };
        let tenant: Tenant = decode(tenant)?;
        let settings = load_ldap_settings(store, &tenant).await?;
        let wanted = core_js::to_lower(value);
        let identities = tenant_identities(ctx, store, tenant_id).await?;
        if kind == "service" {
            let machines: Vec<&Identity> = identities
                .iter()
                .filter(|identity| identity.kind != IdentityKind::User)
                .collect();
            let named: Vec<&&Identity> = machines
                .iter()
                .filter(|identity| core_js::to_lower(&identity.name) == wanted)
                .collect();
            if named.len() == 1 {
                return Ok(Some(json!({ "identityId": named[0].id })));
            }
            let by_id = machines
                .iter()
                .find(|identity| core_js::to_lower(&identity.id) == wanted);
            return Ok(by_id.map(|identity| json!({ "identityId": identity.id })));
        }
        let people: Vec<Identity> = identities
            .into_iter()
            .filter(|identity| identity.kind == IdentityKind::User)
            .collect();
        let uid_of = uids(&people, &settings.uid);
        let Some(person) = people
            .iter()
            .find(|identity| uid_of.get(&identity.id) == Some(&wanted))
        else {
            return Ok(None);
        };
        let mut mfa = "none";
        if ctx.auth.mfa_required(store, person).await? {
            let enrolled = store
                .get("authMfa", &person.id)
                .await?
                .is_some_and(|record| crate::js::truthy(record.get("enabled")));
            mfa = if enrolled { "totp" } else { "unavailable" };
        }
        let mut out = Map::new();
        out.insert("identityId".into(), Value::String(person.id.clone()));
        if let Some(email) = person.email.as_ref().filter(|email| !email.is_empty()) {
            out.insert("email".into(), Value::String(email.clone()));
        }
        out.insert("mfa".into(), Value::String(mfa.into()));
        Ok(Some(Value::Object(out)))
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        let argument = |index: usize| -> String { crate::js::js_string(args.get(index)) };
        let answer = |found: Option<Value>| found.unwrap_or_else(crate::port::undefined);
        match method {
            "tenantForBase" => Some(self.tenant_for_base(&argument(0)).await.map(answer)),
            "resolveBindName" => Some(
                self.resolve_bind_name(&argument(0), &argument(1), &argument(2))
                    .await
                    .map(answer),
            ),
            _ => None,
        }
    }
}
