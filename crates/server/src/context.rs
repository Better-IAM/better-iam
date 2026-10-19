//! Port of `packages/server/src/context.ts`: the [`ServerContext`] every service module shares (configuration,
//! storage, authentication, the catalog) and the record helpers.
//!
//! Service modules are attached after construction and reached through the context at call time, which keeps the
//! modules free of import cycles. In Rust the attached services hold a `Weak` reference back to the context.

use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};

use better_iam_auth::AuthService;
use better_iam_core::{
    AuthenticatedPrincipal, Filter, FindOptions, IamError, IamPlugin, IamResult, IamStore,
    Identity, IdentityKind, IdentityStatus, PolicyDocument, Record, SessionKind, Tenant,
    TenantLimits, js as core_js,
};
use futures::future::BoxFuture;
use indexmap::IndexSet;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::catalog::Catalog;
use crate::contracts::{
    BillingHooks, DecisionService, FlowService, HostService, OperationService, PrincipalService,
    SessionTokenSigner, UsageRecorder, WebIdentityVerifier,
};
use crate::events::EventService;
use crate::js::{ThrownError, invalid_input, number_to_string};
use crate::models::{AccessWindow, Binding, GrantAuthority, GroupMember};
use crate::observe::Observer;
use crate::options::{BetterIamOptions, ProtocolMount, ServerConfig};
use crate::tenant_policy::limit_value;
use crate::timezones;
use crate::utils::{all_value, date_now, id};
use crate::validation::{integer, object, text};

/// A shared store handle (a transaction inside `transaction` callbacks).
pub type Store = Arc<dyn IamStore>;

/// An in-process audit event handler (`EventSubscriber.handler`); it receives the stored audit event record.
pub type SubscriberFn = Arc<dyn Fn(Record) -> BoxFuture<'static, IamResult<()>> + Send + Sync>;

/// `EventSubscriber`.
pub struct EventSubscriber {
    pub patterns: Vec<String>,
    pub handler: SubscriberFn,
}

/// `now()`: epoch milliseconds (the injected clock).
pub type NowFn = Arc<dyn Fn() -> f64 + Send + Sync>;

/// What `createContext` takes (`Pick<ServerContext, 'options' | 'config' | 'store' | 'auth' | 'plugins' | 'catalog' |
/// 'now' | 'observe'>`).
pub struct ContextBase {
    pub options: Arc<BetterIamOptions>,
    pub config: Arc<ServerConfig>,
    pub store: Store,
    pub auth: AuthService,
    pub plugins: Vec<Arc<dyn IamPlugin>>,
    pub catalog: Arc<Catalog>,
    pub now: NowFn,
    pub observe: Observer,
}

/// `ServerContext`.
pub struct ServerContext {
    pub options: Arc<BetterIamOptions>,
    pub config: Arc<ServerConfig>,
    pub store: Store,
    pub auth: AuthService,
    pub plugins: Vec<Arc<dyn IamPlugin>>,
    pub catalog: Arc<Catalog>,
    /// In-process audit subscribers (a `Set` keyed by identity in TypeScript).
    pub subscribers: Mutex<Vec<Arc<EventSubscriber>>>,
    pub mounted_protocols: Mutex<Vec<Arc<dyn ProtocolMount>>>,
    pub observe: Observer,
    now: NowFn,
    events: OnceLock<Arc<EventService>>,
    decisions: OnceLock<Arc<dyn DecisionService>>,
    principals: OnceLock<Arc<dyn PrincipalService>>,
    operations: OnceLock<Arc<dyn OperationService>>,
    flows: OnceLock<Arc<dyn FlowService>>,
    usage: OnceLock<Arc<dyn UsageRecorder>>,
    session_tokens: OnceLock<Arc<dyn SessionTokenSigner>>,
    web_identity: OnceLock<Arc<dyn WebIdentityVerifier>>,
    hosts: OnceLock<Arc<dyn HostService>>,
    billing: OnceLock<Arc<dyn BillingHooks>>,
}

/// `createContext(base)`.
pub fn create_context(base: ContextBase) -> Arc<ServerContext> {
    let protocols = base.options.protocols.clone().unwrap_or_default();
    Arc::new(ServerContext {
        options: base.options,
        config: base.config,
        store: base.store,
        auth: base.auth,
        plugins: base.plugins,
        catalog: base.catalog,
        subscribers: Mutex::new(Vec::new()),
        mounted_protocols: Mutex::new(protocols),
        observe: base.observe,
        now: base.now,
        events: OnceLock::new(),
        decisions: OnceLock::new(),
        principals: OnceLock::new(),
        operations: OnceLock::new(),
        flows: OnceLock::new(),
        usage: OnceLock::new(),
        session_tokens: OnceLock::new(),
        web_identity: OnceLock::new(),
        hosts: OnceLock::new(),
        billing: OnceLock::new(),
    })
}

fn not_attached(name: &str) -> IamError {
    IamError::not_implemented(format!(
        "The {name} service is not attached to this server context"
    ))
}

const WEEKDAY_ALL: [f64; 7] = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0];

/// `HH:MM` → minutes (`minutesOf`).
fn minutes_of(value: &str) -> IamResult<u32> {
    let bytes = value.as_bytes();
    let digit = |index: usize| (bytes[index] as char).to_digit(10);
    let valid = bytes.len() == 5
        && bytes[2] == b':'
        && matches!(
            (digit(0), digit(1)),
            (Some(0 | 1), Some(_)) | (Some(2), Some(0..=3))
        )
        && matches!((digit(3), digit(4)), (Some(0..=5), Some(_)));
    if !valid {
        return Err(invalid_input("Window times must be HH:MM"));
    }
    let number = |a: usize, b: usize| digit(a).unwrap_or(0) * 10 + digit(b).unwrap_or(0);
    Ok(number(0, 1) * 60 + number(3, 4))
}

/// `insideWindow(window, at)`: whether an instant lies inside a recurring window; overnight windows count as the day
/// they start on. Fails like the TypeScript (a `RangeError`, or IamError for malformed bounds) for windows no
/// validator would write.
pub fn inside_window(window: &AccessWindow, at: f64) -> Result<bool, IamError> {
    let (day, minutes) =
        timezones::local_time(at, &window.time_zone).map_err(ThrownError::into_iam)?;
    let from = minutes_of(&window.from)?;
    let to = minutes_of(&window.to)?;
    let days = window.days.as_deref().unwrap_or(&WEEKDAY_ALL);
    let includes = |day: u8| days.contains(&f64::from(day));
    if from < to {
        return Ok(minutes >= from && minutes < to && includes(day));
    }
    // Wraps past midnight: the evening part belongs to today, the early part to the day the window started.
    if minutes >= from {
        return Ok(includes(day));
    }
    if minutes < to {
        return Ok(includes((day + 6) % 7));
    }
    Ok(false)
}

const LIMIT_LABELS: [(&str, &str); 8] = [
    ("identities", "member"),
    ("serviceAccounts", "service account"),
    ("agents", "agent"),
    ("groups", "group"),
    ("roles", "role"),
    ("policies", "policy"),
    ("resources", "resource"),
    ("webhooks", "webhook"),
];

/// `slug(value)`: 1-63 lowercase letters, digits, or hyphens, not starting or ending with a hyphen.
pub fn slug(value: Option<&Value>) -> IamResult<String> {
    let result = core_js::to_lower(&text(value, "slug", 63)?);
    let bytes = result.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= 63
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-';
    if !valid {
        return Err(invalid_input(
            "Slug must use 1-63 lowercase letters, digits, or hyphens",
        ));
    }
    Ok(result)
}

fn decode<T: DeserializeOwned>(record: Record) -> IamResult<T> {
    serde_json::from_value(Value::Object(record)).map_err(|_| {
        IamError::with_status("STORAGE_CORRUPT", "Record does not match its type", 500)
    })
}

fn encode<T: serde::Serialize>(value: &T) -> Record {
    match serde_json::to_value(value) {
        Ok(Value::Object(map)) => map,
        _ => Record::new(),
    }
}

fn find_all() -> FindOptions {
    FindOptions::default()
}

impl ServerContext {
    /// `ctx.now()`: the injected clock.
    pub fn now(&self) -> f64 {
        (self.now)()
    }

    /// The clock function itself.
    pub fn clock(&self) -> NowFn {
        self.now.clone()
    }

    pub fn attach_events(&self, service: Arc<EventService>) {
        let _ = self.events.set(service);
    }
    pub fn attach_decisions(&self, service: Arc<dyn DecisionService>) {
        let _ = self.decisions.set(service);
    }
    pub fn attach_principals(&self, service: Arc<dyn PrincipalService>) {
        let _ = self.principals.set(service);
    }
    pub fn attach_operations(&self, service: Arc<dyn OperationService>) {
        let _ = self.operations.set(service);
    }
    pub fn attach_flows(&self, service: Arc<dyn FlowService>) {
        let _ = self.flows.set(service);
    }
    pub fn attach_usage(&self, service: Arc<dyn UsageRecorder>) {
        let _ = self.usage.set(service);
    }
    pub fn attach_session_tokens(&self, service: Arc<dyn SessionTokenSigner>) {
        let _ = self.session_tokens.set(service);
    }
    pub fn attach_web_identity(&self, service: Arc<dyn WebIdentityVerifier>) {
        let _ = self.web_identity.set(service);
    }
    pub fn attach_hosts(&self, service: Arc<dyn HostService>) {
        let _ = self.hosts.set(service);
    }
    pub fn attach_billing(&self, service: Arc<dyn BillingHooks>) {
        let _ = self.billing.set(service);
    }

    /// `ctx.events`.
    pub fn events(&self) -> IamResult<&Arc<EventService>> {
        self.events.get().ok_or_else(|| not_attached("events"))
    }
    /// `ctx.decisions`.
    pub fn decisions(&self) -> IamResult<&Arc<dyn DecisionService>> {
        self.decisions
            .get()
            .ok_or_else(|| not_attached("decisions"))
    }
    /// `ctx.principals`.
    pub fn principals(&self) -> IamResult<&Arc<dyn PrincipalService>> {
        self.principals
            .get()
            .ok_or_else(|| not_attached("principals"))
    }
    /// `ctx.operations`.
    pub fn operations(&self) -> IamResult<&Arc<dyn OperationService>> {
        self.operations
            .get()
            .ok_or_else(|| not_attached("operations"))
    }
    /// `ctx.flows`.
    pub fn flows(&self) -> IamResult<&Arc<dyn FlowService>> {
        self.flows.get().ok_or_else(|| not_attached("flows"))
    }
    /// `ctx.usage`.
    pub fn usage(&self) -> IamResult<&Arc<dyn UsageRecorder>> {
        self.usage.get().ok_or_else(|| not_attached("usage"))
    }
    /// `ctx.sessionTokens`: present only when `sts.jwt` is configured.
    pub fn session_tokens(&self) -> Option<&Arc<dyn SessionTokenSigner>> {
        self.session_tokens.get()
    }
    /// `ctx.webIdentity`: present when `sts.webIdentity` is enabled.
    pub fn web_identity(&self) -> Option<&Arc<dyn WebIdentityVerifier>> {
        self.web_identity.get()
    }
    /// `ctx.hosts`.
    pub fn hosts(&self) -> IamResult<&Arc<dyn HostService>> {
        self.hosts.get().ok_or_else(|| not_attached("hosts"))
    }
    /// `ctx.billing`.
    pub fn billing(&self) -> Option<&Arc<dyn BillingHooks>> {
        self.billing.get()
    }

    // --- RecordHelpers ---------------------------------------------------------------------------------------------

    /// `tenant(tx, tenantId)`.
    pub async fn tenant(&self, tx: &Store, tenant_id: &str) -> IamResult<Tenant> {
        self.tenant_of(tx, Some(&Value::String(tenant_id.to_owned())))
            .await
    }

    /// [`ServerContext::tenant`] for an untrusted ID.
    pub async fn tenant_of(&self, tx: &Store, tenant_id: Option<&Value>) -> IamResult<Tenant> {
        let tenant_id = text(tenant_id, "tenantId", 256)?;
        match tx.get("tenants", &tenant_id).await? {
            Some(found) => decode(found),
            None => Err(IamError::with_status("NOT_FOUND", "Tenant not found", 404)),
        }
    }

    /// `ancestry(tx, target)`: the tenant and its ancestors up to the root; rejects cycles and excessive depth.
    pub async fn ancestry(&self, tx: &Store, target: &Tenant) -> IamResult<Vec<Tenant>> {
        let mut list = vec![target.clone()];
        let mut seen: IndexSet<String> = IndexSet::new();
        seen.insert(target.id.clone());
        while let Some(parent_id) = list
            .last()
            .and_then(|last| last.parent_id.clone())
            .filter(|parent| !parent.is_empty())
        {
            let parent = self.tenant(tx, &parent_id).await?;
            if seen.contains(&parent.id) || list.len() as f64 > self.config.max_depth {
                return Err(IamError::with_status(
                    "INVALID_HIERARCHY",
                    "Invalid tenant hierarchy",
                    500,
                ));
            }
            seen.insert(parent.id.clone());
            list.push(parent);
        }
        Ok(list)
    }

    /// `ancestorIds(tx, tenantId)`: tolerant of tenants that no longer exist (events recorded during a purge).
    pub async fn ancestor_ids(&self, tx: &Store, tenant_id: &str) -> IamResult<Vec<String>> {
        let mut ids: Vec<String> = Vec::new();
        let mut current = Some(tenant_id.to_owned()).filter(|id| !id.is_empty());
        while let Some(id) = current {
            if ids.len() as f64 > self.config.max_depth || ids.contains(&id) {
                break;
            }
            ids.push(id.clone());
            let realm = tx.get("tenants", &id).await?;
            current = realm
                .as_ref()
                .and_then(|realm| realm.get("parentId"))
                .and_then(Value::as_str)
                .filter(|parent| !parent.is_empty())
                .map(str::to_owned);
        }
        Ok(ids)
    }

    /// `rootPrincipal(tx, principal)`: a root-tenant human with the root capability in an MFA user session.
    pub async fn root_principal(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
    ) -> IamResult<bool> {
        let realm = self.tenant(tx, &principal.identity.tenant_id).await?;
        Ok(realm.kind == "root"
            && realm.parent_id.is_none()
            && principal.identity.root_admin
            && principal.session.kind == SessionKind::User
            && principal.session.mfa)
    }

    /// `authorityChain(tx, authorityId)`: the ceilings of an authority and its parents, or None when any link is
    /// revoked or missing.
    pub async fn authority_chain(
        &self,
        tx: &Store,
        authority_id: &str,
    ) -> IamResult<Option<Vec<PolicyDocument>>> {
        let mut policies = Vec::new();
        let mut seen: IndexSet<String> = IndexSet::new();
        let mut current = Some(authority_id.to_owned()).filter(|id| !id.is_empty());
        while let Some(id) = current {
            if seen.contains(&id) || seen.len() > 100 {
                return Ok(None);
            }
            seen.insert(id.clone());
            let Some(record) = tx.get("grantAuthorities", &id).await? else {
                return Ok(None);
            };
            let authority: GrantAuthority = decode(record)?;
            if authority.revoked {
                return Ok(None);
            }
            policies.push(authority.ceiling);
            current = authority.parent_authority_id.filter(|id| !id.is_empty());
        }
        Ok(Some(policies))
    }

    /// `scoped(tx, collection, recordId, tenantId)`: a record of the tenant, NOT_FOUND otherwise.
    pub async fn scoped(
        &self,
        tx: &Store,
        collection: &str,
        record_id: Option<&Value>,
        tenant_id: &str,
    ) -> IamResult<Record> {
        let record_id = text(record_id, "id", 256)?;
        match tx.get(collection, &record_id).await? {
            Some(record) if record.get("tenantId").and_then(Value::as_str) == Some(tenant_id) => {
                Ok(record)
            }
            _ => Err(IamError::with_status(
                "NOT_FOUND",
                "Resource not found",
                404,
            )),
        }
    }

    /// [`ServerContext::scoped`] decoded into a typed record.
    pub async fn scoped_as<T: DeserializeOwned>(
        &self,
        tx: &Store,
        collection: &str,
        record_id: &str,
        tenant_id: &str,
    ) -> IamResult<T> {
        decode(
            self.scoped(
                tx,
                collection,
                Some(&Value::String(record_id.to_owned())),
                tenant_id,
            )
            .await?,
        )
    }

    /// `activeIdentity(tx, identityId, tenantId)`: deleted identities remain readable as historical principals only.
    pub async fn active_identity(
        &self,
        tx: &Store,
        identity_id: &str,
        tenant_id: &str,
    ) -> IamResult<Identity> {
        let identity: Identity = self
            .scoped_as(tx, "identities", identity_id, tenant_id)
            .await?;
        if identity.status == IdentityStatus::Deleted {
            return Err(IamError::with_status(
                "NOT_FOUND",
                "Identity has been deleted",
                404,
            ));
        }
        Ok(identity)
    }

    /// `serviceAccount(tx, identityId, tenantId)`.
    pub async fn service_account(
        &self,
        tx: &Store,
        identity_id: &str,
        tenant_id: &str,
    ) -> IamResult<Identity> {
        let account: Identity = self
            .scoped_as(tx, "identities", identity_id, tenant_id)
            .await?;
        if account.kind != IdentityKind::Service {
            return Err(IamError::with_status(
                "NOT_FOUND",
                "Service account not found",
                404,
            ));
        }
        Ok(account)
    }

    /// `claimSlug(tx, tenantId, value)`: reserves a global sign-in alias.
    pub async fn claim_slug(
        &self,
        tx: &Store,
        tenant_id: &str,
        value: Option<&Value>,
    ) -> IamResult<String> {
        let alias = slug(value)?;
        if tx.get("tenantAliases", &alias).await?.is_some() {
            return Err(IamError::with_status(
                "SLUG_TAKEN",
                "This slug is already in use",
                409,
            ));
        }
        let mut record = Record::new();
        record.insert("id".into(), Value::String(alias.clone()));
        record.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
        record.insert("createdAt".into(), crate::js::number(date_now()));
        tx.insert("tenantAliases", &record).await?;
        Ok(alias)
    }

    /// `protectLastOwner(tx, identity)`.
    pub async fn protect_last_owner(&self, tx: &Store, identity: &Identity) -> IamResult<()> {
        if identity.status != IdentityStatus::Active {
            return Ok(());
        }
        let count = |flag: &'static str| {
            let filter = Filter::new()
                .eq("tenantId", identity.tenant_id.clone())
                .eq(flag, true)
                .eq("status", "active");
            async move {
                Ok::<usize, IamError>(tx.find("identities", &filter, &find_all()).await?.len())
            }
        };
        if identity.owner && count("owner").await? <= 1 {
            return Err(IamError::with_status(
                "LAST_OWNER",
                "Cannot remove the final active owner",
                409,
            ));
        }
        if identity.root_admin && count("rootAdmin").await? <= 1 {
            return Err(IamError::with_status(
                "LAST_ROOT_ADMIN",
                "Cannot remove the final root administrator",
                409,
            ));
        }
        Ok(())
    }

    /// `revokeAll(tx, identityId)`: every session an identity holds directly or through role assumption.
    pub async fn revoke_all(&self, tx: &Store, identity_id: &str) -> IamResult<()> {
        self.auth.revoke_identity(tx, identity_id).await?;
        let sessions = tx
            .find(
                "sessions",
                &Filter::new().eq("originalIdentityId", identity_id),
                &find_all(),
            )
            .await?;
        for session in sessions {
            tx.delete("sessions", better_iam_core::record_id(&session))
                .await?;
        }
        Ok(())
    }

    /// `grantingAuthority(tx, principal, tenantId, authorityId?)`: an explicit authority the caller owns, a
    /// root-issued one, or their active delegated authority.
    pub async fn granting_authority(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        authority_id: Option<&str>,
    ) -> IamResult<GrantAuthority> {
        // A "view as" session would spend the member's authority, not the administrator's.
        if principal.session.impersonator_id.is_some() {
            return Err(IamError::with_status(
                "IMPERSONATION_RESTRICTED",
                "Access cannot be granted while impersonating",
                403,
            ));
        }
        if let Some(authority_id) = authority_id.filter(|id| !id.is_empty()) {
            let authority: GrantAuthority = self
                .scoped_as(tx, "grantAuthorities", authority_id, tenant_id)
                .await?;
            if !authority.revoked
                && (authority.identity_id == principal.identity.id
                    || self.root_principal(tx, principal).await?)
                && self.authority_chain(tx, &authority.id).await?.is_some()
            {
                return Ok(authority);
            }
            return Err(IamError::with_status(
                "ACCESS_DENIED",
                "Cannot use another administrator\u{2019}s grant authority",
                403,
            ));
        }
        if self.root_principal(tx, principal).await? {
            let found = tx
                .find(
                    "grantAuthorities",
                    &Filter::new()
                        .eq("tenantId", tenant_id)
                        .eq("identityId", principal.identity.id.clone())
                        .eq("rootIssued", true),
                    &find_all(),
                )
                .await?;
            if let Some(existing) = found.into_iter().next() {
                return decode(existing);
            }
            let mut record = Record::new();
            record.insert("id".into(), Value::String(id()));
            record.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
            record.insert(
                "identityId".into(),
                Value::String(principal.identity.id.clone()),
            );
            record.insert("rootIssued".into(), Value::Bool(true));
            record.insert("ceiling".into(), all_value());
            record.insert("revoked".into(), Value::Bool(false));
            return decode(tx.insert("grantAuthorities", &record).await?);
        }
        let candidates = tx
            .find(
                "grantAuthorities",
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("identityId", principal.identity.id.clone())
                    .eq("revoked", false),
                &find_all(),
            )
            .await?;
        for candidate in candidates {
            let authority: GrantAuthority = decode(candidate)?;
            if self.authority_chain(tx, &authority.id).await?.is_some() {
                return Ok(authority);
            }
        }
        Err(IamError::with_status(
            "GRANT_AUTHORITY_REQUIRED",
            "An active delegated grant authority is required",
            403,
        ))
    }

    /// `canEditGrantResource(tx, principal, record)`: grant-bearing records (roles, policies) may only be edited by
    /// their issuing authority or by root.
    pub async fn can_edit_grant_resource(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        record: &Record,
    ) -> IamResult<()> {
        if self.root_principal(tx, principal).await? {
            return Ok(());
        }
        let Some(Value::String(authority_id)) = record.get("authorityId") else {
            return Err(IamError::with_status(
                "PROTECTED_RESOURCE",
                "This resource is controlled by a superior authority",
                403,
            ));
        };
        let tenant_id = record
            .get("tenantId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        self.granting_authority(tx, principal, &tenant_id, Some(authority_id))
            .await?;
        Ok(())
    }

    /// `ownerSetup(tx, realm, identity, authority)`: the protected Owner policy, role, and binding of a newly
    /// activated tenant.
    pub async fn owner_setup(
        &self,
        tx: &Store,
        realm: &Tenant,
        identity: &Identity,
        authority: &GrantAuthority,
    ) -> IamResult<()> {
        let policy_id = id();
        let mut policy = Record::new();
        policy.insert("id".into(), Value::String(policy_id.clone()));
        policy.insert("tenantId".into(), Value::String(realm.id.clone()));
        policy.insert("name".into(), Value::String("Owner".into()));
        policy.insert("uniqueKey".into(), Value::String("system:owner".into()));
        policy.insert("document".into(), all_value());
        policy.insert("version".into(), Value::from(1));
        let role_id = id();
        let mut role = Record::new();
        role.insert("id".into(), Value::String(role_id.clone()));
        role.insert("tenantId".into(), Value::String(realm.id.clone()));
        role.insert("name".into(), Value::String("Owner".into()));
        role.insert("uniqueKey".into(), Value::String("system:owner".into()));
        role.insert(
            "policyIds".into(),
            Value::Array(vec![Value::String(policy_id)]),
        );
        role.insert("protected".into(), Value::Bool(true));
        tx.insert("policies", &policy).await?;
        tx.insert("roles", &role).await?;
        let mut updated = encode(authority);
        updated.insert("identityId".into(), Value::String(identity.id.clone()));
        tx.put("grantAuthorities", &updated).await?;
        let mut binding = Record::new();
        binding.insert("id".into(), Value::String(id()));
        binding.insert("tenantId".into(), Value::String(realm.id.clone()));
        binding.insert("subjectType".into(), Value::String("identity".into()));
        binding.insert("subjectId".into(), Value::String(identity.id.clone()));
        binding.insert("roleId".into(), Value::String(role_id));
        binding.insert("authorityId".into(), Value::String(authority.id.clone()));
        tx.insert("bindings", &binding).await?;
        Ok(())
    }

    /// `enforceLimit(tx, tenant, key, count, adding = 1)`: LIMIT_EXCEEDED when adding `adding` records would exceed
    /// the tenant's plan limit for `key`.
    pub async fn enforce_limit<F, Fut>(
        &self,
        tenant: &Tenant,
        key: &str,
        count: F,
        adding: Option<f64>,
    ) -> IamResult<()>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = IamResult<f64>>,
    {
        let Some(limit) = tenant
            .limits
            .as_ref()
            .and_then(|limits: &TenantLimits| limit_value(limits, key))
        else {
            return Ok(());
        };
        if count().await? + adding.unwrap_or(1.0) > limit {
            let label = LIMIT_LABELS
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, label)| *label)
                .unwrap_or("undefined");
            return Err(IamError::with_status(
                "LIMIT_EXCEEDED",
                format!(
                    "This tenant has reached its {label} limit ({})",
                    number_to_string(limit)
                ),
                409,
            ));
        }
        Ok(())
    }

    /// `liveBinding(binding)`: started (`startsAt`) and not expired.
    pub fn live_binding(&self, binding: &Binding) -> bool {
        let now = self.now();
        binding.starts_at.is_none_or(|starts| starts <= now)
            && binding.expires_at.is_none_or(|expires| expires > now)
    }

    /// `expiredBinding(binding)`: a temporary binding past its end (future-dated bindings are not expired).
    pub fn expired_binding(&self, binding: &Binding) -> bool {
        binding
            .expires_at
            .is_some_and(|expires| expires <= self.now())
    }

    /// `liveMembership(member)`: no expiry, or one still ahead.
    pub fn live_membership(&self, member: &GroupMember) -> bool {
        member.expires_at.is_none_or(|expires| expires > self.now())
    }

    /// `bindingStart(value)`: a future start (epoch milliseconds, not in the past, within ten years).
    pub fn binding_start(&self, value: Option<&Value>) -> IamResult<f64> {
        let starts_at = integer(value, "startsAt", 0.0, core_js::MAX_SAFE_INTEGER)?;
        if starts_at < self.now() - 60_000.0 {
            return Err(invalid_input("startsAt must not be in the past"));
        }
        if starts_at > self.now() + 10.0 * 365.0 * 86_400_000.0 {
            return Err(invalid_input("startsAt must be within ten years"));
        }
        Ok(starts_at)
    }

    /// `bindingExpiry(value)`.
    pub fn binding_expiry(&self, value: Option<&Value>) -> IamResult<f64> {
        let expires_at = integer(value, "expiresAt", 0.0, core_js::MAX_SAFE_INTEGER)?;
        if expires_at <= self.now() {
            return Err(invalid_input("expiresAt must be in the future"));
        }
        if expires_at > self.now() + 10.0 * 365.0 * 86_400_000.0 {
            return Err(invalid_input("expiresAt must be within ten years"));
        }
        Ok(expires_at)
    }

    /// `identityExpired(identity)`: true once an identity's scheduled deactivation has passed.
    pub fn identity_expired(&self, identity: &Identity) -> bool {
        identity
            .expires_at
            .is_some_and(|expires| expires <= self.now())
    }

    /// `accessWindow(value)`: days, `HH:MM` bounds, an IANA time zone.
    pub fn access_window(&self, value: Option<&Value>) -> IamResult<AccessWindow> {
        access_window(value)
    }

    /// `withinWindow(binding, at = now)`: no window, or the instant falls inside it.
    pub fn within_window(&self, binding: &Binding, at: Option<f64>) -> IamResult<bool> {
        match &binding.window {
            None => Ok(true),
            Some(window) => inside_window(window, at.unwrap_or_else(|| self.now())),
        }
    }
}

/// `accessWindow(value)` (a record helper that needs no context).
pub fn access_window(value: Option<&Value>) -> IamResult<AccessWindow> {
    let input: &Map<String, Value> = object(value)?;
    let mut window = AccessWindow {
        from: text(input.get("from"), "window.from", 5)?,
        to: text(input.get("to"), "window.to", 5)?,
        time_zone: text(input.get("timeZone"), "window.timeZone", 64)?,
        days: None,
    };
    if minutes_of(&window.from)? == minutes_of(&window.to)? {
        return Err(invalid_input("Window must not be empty"));
    }
    if !timezones::is_valid_time_zone(&window.time_zone) {
        return Err(invalid_input("Unknown window.timeZone"));
    }
    if let Some(days) = input.get("days") {
        let Value::Array(items) = days else {
            return Err(invalid_input("window.days must list 1-7 weekdays"));
        };
        if items.is_empty() || items.len() > 7 {
            return Err(invalid_input("window.days must list 1-7 weekdays"));
        }
        let mut unique: Vec<f64> = Vec::new();
        for day in items {
            let day = integer(Some(day), "window.days", 0.0, 6.0)?;
            if !unique.contains(&day) {
                unique.push(day);
            }
        }
        // `.sort()` compares the decimal strings, which for 0-6 is numeric order.
        unique.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        window.days = Some(unique);
    }
    Ok(window)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn windows() {
        let window = access_window(Some(&json!({
            "from": "22:00", "to": "06:00", "timeZone": "UTC", "days": [5, 1, 5]
        })))
        .unwrap();
        assert_eq!(window.days.as_deref(), Some(&[1.0, 5.0][..]));
        // Monday 2024-01-01 23:00 UTC: inside (evening part of Monday).
        assert!(inside_window(&window, 1_704_150_000_000.0).unwrap());
        // Tuesday 2024-01-02 03:00 UTC: early part belongs to Monday.
        assert!(inside_window(&window, 1_704_164_400_000.0).unwrap());
        // Wednesday 03:00: belongs to Tuesday, not listed.
        assert!(!inside_window(&window, 1_704_250_800_000.0).unwrap());
        let message = |value: Value| access_window(Some(&value)).unwrap_err().message;
        assert_eq!(
            message(json!({ "from": "9:00", "to": "17:00", "timeZone": "UTC" })),
            "Window times must be HH:MM"
        );
        assert_eq!(
            message(json!({ "from": "09:00", "to": "09:00", "timeZone": "UTC" })),
            "Window must not be empty"
        );
        assert_eq!(
            message(json!({ "from": "09:00", "to": "17:00", "timeZone": "Mars/Base" })),
            "Unknown window.timeZone"
        );
        assert_eq!(
            message(json!({ "from": "09:00", "to": "17:00", "timeZone": "UTC", "days": [] })),
            "window.days must list 1-7 weekdays"
        );
        assert_eq!(
            message(json!({ "from": "09:00", "to": "17:00", "timeZone": "UTC", "days": [7] })),
            "Invalid window.days"
        );
        assert_eq!(
            message(json!({ "from": "24:00", "to": "17:00", "timeZone": "UTC" })),
            "Window times must be HH:MM"
        );
    }

    #[test]
    fn slugs() {
        assert_eq!(slug(Some(&json!("Acme-Corp"))).unwrap(), "acme-corp");
        assert_eq!(
            slug(Some(&json!("-acme"))).unwrap_err().message,
            "Slug must use 1-63 lowercase letters, digits, or hyphens"
        );
        assert_eq!(slug(Some(&json!(""))).unwrap_err().message, "Invalid slug");
    }
}
