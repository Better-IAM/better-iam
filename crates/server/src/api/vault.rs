//! Port of `packages/server/src/api/vault.ts`.
//!
//! The secrets vault. Secrets live in one tenant under a path-like name and are authorized as
//! `iam/vault/secrets/{name}`: `iam:vault:read` (metadata), `iam:vault:reveal` (values), `iam:vault:write` (new
//! versions and stages), `iam:vault:rotate`, `iam:vault:lease` (check-outs and dynamic leases) and `iam:vault:manage`
//! (create, settings, delete, versions' state). Policy conditions see `resource.name`, `resource.tag.{key}`,
//! `resource.kind`, `resource.createdBy`, `resource.checkoutRequired` and `resource.rotationEnabled`.
//!
//! The record helpers of vault.ts are reached through the small adapters at the top of this file (`settings`,
//! `timed`, `value_use`, the `added` decoding), so a refinement of their signatures touches one place.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Direction, Filter, FindOptions,
    IamError, IamResult, IamStoreExt, Identity, IdentityKind, IdentityStatus, OrderOptions, Record,
    Tenant, TenantStatus, find_ordered, js as core_js,
};
use futures::future::BoxFuture;
use indexmap::IndexMap;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::agents::agent_standing;
use crate::api::{Body, Reply};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, OperationDenied, OperationResult, decide_on};
use crate::decisions::impersonating_actor;
use crate::delegations::{Delegation, delegation_ancestors, delegation_live, use_confirmation};
use crate::js::{number, truthy, utf16_len};
use crate::kms::{alias_names, assert_usable, find_key, key_attributes};
use crate::options::{
    AuthorizationRequest, ResolvedResource, ResourceTarget, VaultEngine, VaultRotator,
};
use crate::options_value::options_value;
use crate::port::{Callback, decode, encode, undefined};
use crate::utils::id;
use crate::validation::{integer, text};
use crate::vault::{
    self as store_vault, PasswordGenerator, SYSTEM_STAGES, VAULT_COLLECTIONS, VAULT_OPERATOR,
    VaultLease, VaultSecret, VaultVersion,
};
use better_iam_types::api::vault;

const MINUTE: f64 = 60_000.0;
const DAY: f64 = 24.0 * 60.0 * MINUTE;

/// Every action decided on `iam/vault/secrets/{name}`.
const SECRET_ACTIONS: [&str; 6] = [
    "iam:vault:read",
    "iam:vault:reveal",
    "iam:vault:write",
    "iam:vault:rotate",
    "iam:vault:lease",
    "iam:vault:manage",
];

/// How long revocations that keep failing are retried before the lease is given up.
const REVOKE_PATIENCE_MS: f64 = 7.0 * DAY;

const SCAN_PAGE: i64 = 500;

// --- adapters to vault.ts --------------------------------------------------------------------------------------

/// A collection of `vaultCollections`.
fn col(key: &str) -> &'static str {
    let collections: &'static Value = &VAULT_COLLECTIONS;
    collections.get(key).and_then(Value::as_str).unwrap_or("")
}

/// `VaultSettings`: the validated `vault` option. The JSON settings come from `vaultSettings`; the rotators and
/// engines, which JSON cannot carry, are the options' own (validated by `vaultSettings` at construction).
struct Settings {
    raw: Value,
    max_secrets_per_tenant: f64,
    access_retention_ms: f64,
    rotators: IndexMap<String, Arc<dyn VaultRotator>>,
    engines: IndexMap<String, Arc<dyn VaultEngine>>,
}

/// `vaultSettings(ctx)`.
fn settings(ctx: &ServerContext) -> IamResult<Settings> {
    let raw = store_vault::vault_settings(&json!({ "options": &*options_value(&ctx.options) }))?;
    let vault = ctx.options.vault.as_ref();
    Ok(Settings {
        max_secrets_per_tenant: raw
            .get("maxSecretsPerTenant")
            .and_then(Value::as_f64)
            .unwrap_or(1000.0),
        access_retention_ms: raw
            .get("accessRetentionMs")
            .and_then(Value::as_f64)
            .unwrap_or(90.0 * DAY),
        rotators: vault
            .and_then(|options| options.rotators.clone())
            .unwrap_or_default(),
        engines: vault
            .and_then(|options| options.engines.clone())
            .unwrap_or_default(),
        raw,
    })
}

/// `withTimeout(ctx, what, call)`.
async fn timed(ctx: &Arc<ServerContext>, what: &str, call: Callback) -> IamResult<Value> {
    store_vault::with_timeout(ctx, what, &call).await
}

/// `ValueUse`: the principal a value is encrypted or opened for, as the KMS audit records it.
fn value_use(principal: &AuthenticatedPrincipal) -> Value {
    json!({ "identity": principal.identity, "session": principal.session })
}

/// `addVersion(...)`: `{ secret, version }`.
async fn add_version(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    secret: &VaultSecret,
    value: &str,
    source: &str,
    actor_id: &str,
    use_: Option<&Value>,
) -> IamResult<(VaultSecret, VaultVersion)> {
    let added = store_vault::add_version(ctx, tx, secret, value, source, actor_id, use_).await?;
    let secret = typed::<VaultSecret>(added.get("secret"))?;
    let version = typed::<VaultVersion>(added.get("version"))?;
    Ok((secret, version))
}

/// A typed record from a JSON value (STORAGE_CORRUPT for a malformed one).
fn typed<T: serde::de::DeserializeOwned>(value: Option<&Value>) -> IamResult<T> {
    match value {
        Some(Value::Object(map)) => decode(map.clone()),
        _ => decode(Record::new()),
    }
}

fn resource(name: &str) -> IamResult<String> {
    store_vault::secret_resource(name)
}

fn secret_name(value: Option<&Value>) -> IamResult<String> {
    store_vault::secret_name(value)
}

// --- JSON helpers ------------------------------------------------------------------------------------------------

/// Numbers as JavaScript writes them (`1`, not `1.0`), recursively.
fn js_value(value: Value) -> Value {
    match value {
        Value::Number(n) => match n.as_f64() {
            Some(f) if !n.is_i64() && !n.is_u64() => number(f),
            _ => Value::Number(n),
        },
        Value::Array(items) => Value::Array(items.into_iter().map(js_value).collect()),
        Value::Object(map) => {
            Value::Object(map.into_iter().map(|(k, v)| (k, js_value(v))).collect())
        }
        other => other,
    }
}

/// A typed record as the JSON object the store keeps, with JavaScript numbers.
fn record<T: Serialize>(value: &T) -> Record {
    match js_value(Value::Object(encode(value))) {
        Value::Object(map) => map,
        _ => Record::new(),
    }
}

fn json_of<T: Serialize>(value: &T) -> Value {
    js_value(serde_json::to_value(value).unwrap_or(Value::Null))
}

fn string(value: impl Into<String>) -> Value {
    Value::String(value.into())
}

fn meta(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

fn stages_json(stages: &IndexMap<String, f64>) -> Value {
    Value::Object(
        stages
            .iter()
            .map(|(label, version)| (label.clone(), number(*version)))
            .collect(),
    )
}

fn tags_json(tags: &IndexMap<String, String>) -> Value {
    Value::Object(
        tags.iter()
            .map(|(key, value)| (key.clone(), string(value.clone())))
            .collect(),
    )
}

fn fields_json(fields: &IndexMap<String, Value>) -> Value {
    Value::Object(fields.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
}

fn rotation_member<'a>(secret: &'a VaultSecret, key: &str) -> Option<&'a Value> {
    secret
        .rotation
        .as_ref()
        .and_then(|rotation| rotation.get(key))
}

/// `secret.rotation?.field` when it is a non-empty string.
fn rotation_field(secret: &VaultSecret) -> Option<String> {
    match rotation_member(secret, "field") {
        Some(Value::String(field)) if !field.is_empty() => Some(field.clone()),
        _ => None,
    }
}

fn is_json(format: &Value) -> bool {
    format == "json"
}

fn is_dynamic(secret: &VaultSecret) -> bool {
    secret.kind == "dynamic"
}

// --- views -------------------------------------------------------------------------------------------------------

/// A secret's metadata, as `iam:vault:read` shows it. Never carries a value.
fn view(secret: &VaultSecret, leases: &[VaultLease], now: f64) -> Value {
    let mut out = Map::new();
    out.insert("name".into(), string(secret.name.clone()));
    if let Some(description) = &secret.description {
        out.insert("description".into(), string(description.clone()));
    }
    out.insert("kind".into(), secret.kind.clone());
    out.insert("format".into(), secret.format.clone());
    out.insert("tags".into(), tags_json(&secret.tags));
    out.insert("status".into(), string(secret.status.clone()));
    if let Some(at) = secret.deletion_at {
        out.insert("deletionAt".into(), number(at));
    }
    out.insert("stages".into(), stages_json(&secret.stages));
    out.insert("latestVersion".into(), number(secret.latest_version));
    out.insert("maxVersions".into(), number(secret.max_versions));
    if let Some(rotation) = secret.rotation.as_ref().filter(|r| truthy(Some(r))) {
        let mut shown = Map::new();
        let copy = |shown: &mut Map<String, Value>, key: &str| {
            if let Some(value) = rotation.get(key) {
                shown.insert(key.into(), js_value(value.clone()));
            }
        };
        copy(&mut shown, "intervalDays");
        if truthy(rotation.get("generator")) {
            copy(&mut shown, "generator");
        }
        copy(&mut shown, "field");
        copy(&mut shown, "rotator");
        copy(&mut shown, "lastRotatedAt");
        copy(&mut shown, "nextRotationAt");
        let due = match rotation.get("nextRotationAt") {
            None => false,
            Some(Value::Null) => 0.0 <= now,
            Some(value) => value.as_f64().is_some_and(|at| at <= now),
        };
        shown.insert("due".into(), Value::Bool(due));
        if truthy(rotation.get("lastFailure")) {
            copy(&mut shown, "lastFailure");
        }
        if truthy(rotation.get("failures")) {
            copy(&mut shown, "failures");
        }
        out.insert("rotation".into(), Value::Object(shown));
    }
    if let Some(checkout) = &secret.checkout {
        out.insert("checkout".into(), json_of(checkout));
    }
    if let Some(engine) = &secret.engine {
        out.insert("engine".into(), string(engine.clone()));
    }
    if let Some(config) = &secret.engine_config {
        out.insert("engineConfig".into(), config.clone());
    }
    if let Some(lease) = &secret.lease {
        out.insert("lease".into(), json_of(lease));
    }
    if let Some(key) = &secret.kms_key_id {
        out.insert("kmsKeyId".into(), string(key.clone()));
    }
    out.insert(
        "checkedOut".into(),
        Value::Array(
            leases
                .iter()
                .filter(|lease| lease.kind == "checkout")
                .map(|lease| {
                    json!({
                        "leaseId": lease.id,
                        "holderId": lease.holder_id,
                        "expiresAt": number(lease.expires_at),
                    })
                })
                .collect(),
        ),
    );
    out.insert(
        "activeLeases".into(),
        number(
            leases
                .iter()
                .filter(|lease| lease.kind == "dynamic")
                .count() as f64,
        ),
    );
    out.insert("createdAt".into(), number(secret.created_at));
    out.insert("createdBy".into(), string(secret.created_by.clone()));
    out.insert("updatedAt".into(), number(secret.updated_at));
    out.insert("updatedBy".into(), string(secret.updated_by.clone()));
    if let Some(at) = secret.last_accessed_at {
        out.insert("lastAccessedAt".into(), number(at));
    }
    Value::Object(out)
}

fn stages_of(secret: &VaultSecret, version: f64) -> Vec<String> {
    let mut labels: Vec<String> = secret
        .stages
        .iter()
        .filter(|(_, value)| **value == version)
        .map(|(label, _)| label.clone())
        .collect();
    crate::js::sort_strings(&mut labels);
    labels
}

fn version_view(secret: &VaultSecret, version: &VaultVersion) -> Value {
    let mut out = Map::new();
    out.insert("version".into(), number(version.version));
    out.insert("state".into(), string(version.state.clone()));
    out.insert("stages".into(), json!(stages_of(secret, version.version)));
    out.insert("source".into(), string(version.source.clone()));
    out.insert("createdAt".into(), number(version.created_at));
    out.insert("createdBy".into(), string(version.created_by.clone()));
    if let Some(at) = version.disabled_at {
        out.insert("disabledAt".into(), number(at));
    }
    if let Some(at) = version.destroyed_at {
        out.insert("destroyedAt".into(), number(at));
    }
    Value::Object(out)
}

/// A revealed value: `value` always, and the parsed `fields` of a `json` secret.
#[derive(Debug, Clone)]
struct Revealed {
    name: String,
    version: f64,
    stages: Vec<String>,
    format: Value,
    value: String,
    fields: Option<IndexMap<String, Value>>,
    created_at: f64,
}

impl Revealed {
    /// What plugin hooks may see (everything but the values), in the TypeScript member order.
    fn answer(&self) -> Map<String, Value> {
        meta(vec![
            ("name", string(self.name.clone())),
            ("version", number(self.version)),
            ("stages", json!(self.stages)),
            ("format", self.format.clone()),
            ("createdAt", number(self.created_at)),
        ])
    }

    /// The values hooks may not see.
    fn values(&self) -> Map<String, Value> {
        let mut values = meta(vec![("value", string(self.value.clone()))]);
        if let Some(fields) = &self.fields {
            values.insert("fields".into(), fields_json(fields));
        }
        values
    }

    /// The whole `RevealedSecret`.
    fn to_json(&self) -> Value {
        let mut out = meta(vec![
            ("name", string(self.name.clone())),
            ("version", number(self.version)),
            ("stages", json!(self.stages)),
            ("format", self.format.clone()),
            ("value", string(self.value.clone())),
        ]);
        if let Some(fields) = &self.fields {
            out.insert("fields".into(), fields_json(fields));
        }
        out.insert("createdAt".into(), number(self.created_at));
        Value::Object(out)
    }
}

fn revealed(secret: &VaultSecret, version: &VaultVersion, value: String) -> IamResult<Revealed> {
    let fields = if is_json(&secret.format) {
        Some(store_vault::parse_fields(&value)?)
    } else {
        None
    };
    Ok(Revealed {
        name: secret.name.clone(),
        version: version.version,
        stages: stages_of(secret, version.version),
        format: secret.format.clone(),
        value,
        fields,
        created_at: version.created_at,
    })
}

/// The agent and delegation behind a delegated session, recorded on the leases it takes.
fn lease_actor(principal: &AuthenticatedPrincipal, record: &mut Record) {
    if let Some(agent_id) = &principal.session.agent_id {
        record.insert("agentId".into(), string(agent_id.clone()));
    }
    if let Some(delegation_id) = &principal.session.delegation_id {
        record.insert("delegationId".into(), string(delegation_id.clone()));
    }
}

fn lease_view(lease: &VaultLease, holder_name: Option<&str>) -> Value {
    let mut out = Map::new();
    out.insert("id".into(), string(lease.id.clone()));
    out.insert("name".into(), string(lease.name.clone()));
    out.insert("kind".into(), string(lease.kind.clone()));
    out.insert("holderId".into(), string(lease.holder_id.clone()));
    if let Some(name) = holder_name {
        out.insert("holderName".into(), string(name));
    }
    if let Some(version) = lease.version {
        out.insert("version".into(), number(version));
    }
    if let Some(reason) = &lease.reason {
        out.insert("reason".into(), string(reason.clone()));
    }
    out.insert("state".into(), string(lease.state.clone()));
    out.insert("issuedAt".into(), number(lease.issued_at));
    out.insert("expiresAt".into(), number(lease.expires_at));
    out.insert("maxExpiresAt".into(), number(lease.max_expires_at));
    if let Some(at) = lease.ended_at {
        out.insert("endedAt".into(), number(at));
    }
    if let Some(by) = &lease.ended_by {
        out.insert("endedBy".into(), string(by.clone()));
    }
    if let Some(error) = &lease.last_error {
        out.insert("lastError".into(), string(error.clone()));
    }
    Value::Object(out)
}

// --- helpers -----------------------------------------------------------------------------------------------------

fn writable(realm: &Tenant) -> IamResult<()> {
    if realm.status == TenantStatus::Deleted {
        return Err(IamError::new(
            "INVALID_TRANSITION",
            "Deleted tenants cannot be updated",
        ));
    }
    Ok(())
}

async fn existing_secret(tx: &Store, tenant_id: &str, name: &str) -> IamResult<VaultSecret> {
    store_vault::find_secret(tx, tenant_id, name)
        .await?
        .ok_or_else(|| IamError::with_status("NOT_FOUND", "Secret not found", 404))
}

fn active_secret(secret: VaultSecret) -> IamResult<VaultSecret> {
    if secret.status != "active" {
        return Err(IamError::with_status(
            "SECRET_PENDING_DELETION",
            "This secret is scheduled for deletion; restore it first",
            409,
        ));
    }
    Ok(secret)
}

fn static_secret(secret: VaultSecret) -> IamResult<VaultSecret> {
    if secret.kind != "static" {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Dynamic secrets have no stored value; request a lease with vault.lease",
        ));
    }
    Ok(secret)
}

/// Values leave the vault only for the person themselves, never through "view as".
fn refuse_impersonation(principal: &AuthenticatedPrincipal) -> OperationResult<()> {
    if principal
        .session
        .impersonator_id
        .as_deref()
        .is_some_and(|id| !id.is_empty())
    {
        return Err(OperationDenied::new(Some(
            "Secret values are not available while viewing as another member",
        )));
    }
    Ok(())
}

/// `{ ...accessEntry(principal), action, version?, leaseId? }`.
fn access(
    principal: &AuthenticatedPrincipal,
    action: &str,
    version: Option<f64>,
    lease_id: Option<&str>,
) -> Value {
    let mut entry = meta(vec![
        ("identityId", string(principal.identity.id.clone())),
        ("sessionKind", string(principal.session.kind.as_str())),
    ]);
    if let Some(agent_id) = principal
        .session
        .agent_id
        .as_deref()
        .filter(|id| !id.is_empty())
    {
        entry.insert("agentId".into(), string(agent_id));
    }
    entry.insert("action".into(), string(action));
    if let Some(version) = version {
        entry.insert("version".into(), number(version));
    }
    if let Some(lease_id) = lease_id {
        entry.insert("leaseId".into(), string(lease_id));
    }
    Value::Object(entry)
}

/// A json secret that rotates when checked in must say which field rotation replaces, or returns would not rotate.
fn checkout_fits(secret: &VaultSecret) -> IamResult<()> {
    if secret
        .checkout
        .as_ref()
        .is_some_and(|policy| policy.rotate_on_checkin)
        && is_json(&secret.format)
        && rotation_field(secret).is_none()
    {
        return Err(IamError::new(
            "INVALID_INPUT",
            "A json secret that rotates on check-in needs rotation.field, the field rotation replaces",
        ));
    }
    Ok(())
}

fn max_versions(value: Option<&Value>, fallback: f64) -> IamResult<f64> {
    match value {
        None => Ok(fallback),
        Some(value) => integer(Some(value), "maxVersions", 1.0, 100.0),
    }
}

fn default_generator() -> IamResult<PasswordGenerator> {
    typed(Some(&store_vault::DEFAULT_GENERATOR))
}

/// The next value a rotation writes: the explicit one, or the generator's (into `rotation.field` for json secrets).
fn next_value(
    vault: &Settings,
    secret: &VaultSecret,
    previous: Option<&str>,
    explicit: &Value,
) -> IamResult<(String, &'static str)> {
    if explicit.get("value").is_some() || explicit.get("fields").is_some() {
        return Ok((
            store_vault::secret_value(&vault.raw, &secret.format, explicit)?,
            "put",
        ));
    }
    let generator = match rotation_member(secret, "generator") {
        Some(value) if !value.is_null() => typed::<PasswordGenerator>(Some(value))?,
        _ => default_generator()?,
    };
    let generated = store_vault::generate_value(&generator)?;
    if secret.format == "text" {
        return Ok((generated, "rotation"));
    }
    let Some(field) = rotation_field(secret) else {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Pass the new fields, or set rotation.field so rotation can generate one",
        ));
    };
    let mut fields = match previous.filter(|value| !value.is_empty()) {
        Some(previous) => store_vault::parse_fields(previous)?,
        None => IndexMap::new(),
    };
    fields.insert(field, string(generated));
    Ok((
        store_vault::secret_value(
            &vault.raw,
            &string("json"),
            &json!({ "fields": fields_json(&fields) }),
        )?,
        "rotation",
    ))
}

/// A state the rotation machinery carries from the staging transaction to the promotion one.
#[derive(Debug, Clone)]
struct StagedRotation {
    tenant_id: String,
    secret_id: String,
    name: String,
    version: f64,
    value: String,
    previous: Option<String>,
    format: Value,
    tags: IndexMap<String, String>,
    rotator: Option<String>,
}

impl StagedRotation {
    /// The staged rotation without its values, as plugin hooks see it.
    fn answer(&self) -> Map<String, Value> {
        let mut out = meta(vec![
            ("tenantId", string(self.tenant_id.clone())),
            ("secretId", string(self.secret_id.clone())),
            ("name", string(self.name.clone())),
            ("version", number(self.version)),
            ("format", self.format.clone()),
            ("tags", tags_json(&self.tags)),
        ]);
        if let Some(rotator) = &self.rotator {
            out.insert("rotator".into(), string(rotator.clone()));
        }
        out
    }

    fn values(&self) -> Map<String, Value> {
        let mut values = meta(vec![("value", string(self.value.clone()))]);
        if let Some(previous) = &self.previous {
            values.insert("previous".into(), string(previous.clone()));
        }
        values
    }
}

/// Stages the next version as `pending` (or reuses a pending version left by a failed attempt, so a rotator sees the
/// same value on every retry) and returns what the rotator needs. Runs inside the caller's transaction.
async fn stage_rotation(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    original: &VaultSecret,
    actor_id: &str,
    explicit: &Value,
    use_: Option<&Value>,
) -> IamResult<StagedRotation> {
    let mut secret = static_secret(active_secret(original.clone())?)?;
    let current = match secret.stages.get("current") {
        Some(number) => store_vault::version_of(tx, &secret, *number).await?,
        None => None,
    };
    let previous = match &current {
        Some(current) if current.state == "enabled" => {
            Some(store_vault::open_version(ctx, tx, current, use_).await?)
        }
        _ => None,
    };
    let pending = match secret.stages.get("pending") {
        Some(number) => store_vault::version_of(tx, &secret, *number).await?,
        None => None,
    };
    let fresh = explicit.get("value").is_some() || explicit.get("fields").is_some();
    let version: VaultVersion;
    let value: String;
    // Only a version this machinery staged (and whose attempt failed) is retried: a `pending` label someone set with
    // `put` or `setStage` is never handed to the rotator, or `iam:vault:write` could choose the live credential.
    match pending {
        Some(pending)
            if !fresh
                && pending.state == "enabled"
                && secret.rotation_pending == Some(pending.version) =>
        {
            value = store_vault::open_version(ctx, tx, &pending, use_).await?;
            version = pending;
        }
        _ => {
            let vault = settings(ctx)?;
            let (next, source) = next_value(&vault, &secret, previous.as_deref(), explicit)?;
            let (added_secret, added_version) =
                add_version(ctx, tx, &secret, &next, source, actor_id, use_).await?;
            let mut staged = added_secret.clone();
            let mut stages = secret.stages.clone();
            stages.insert("pending".into(), added_version.version);
            staged.stages = stages;
            staged.rotation_pending = Some(added_version.version);
            staged.updated_at = ctx.now();
            staged.updated_by = actor_id.to_owned();
            let stored = tx.put(col("secrets"), &record(&staged)).await?;
            secret = decode(stored)?;
            version = added_version;
            value = next;
        }
    }
    Ok(StagedRotation {
        tenant_id: secret.tenant_id.clone(),
        secret_id: secret.id.clone(),
        name: secret.name.clone(),
        version: version.version,
        value,
        previous,
        format: secret.format.clone(),
        tags: secret.tags.clone(),
        rotator: rotation_member(&secret, "rotator")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

/// Records a failed rotation on the secret (the message must already be redacted) and schedules the retry: one hour,
/// doubling up to a day, for secrets that rotate on a schedule or when a check-out comes back. An on-demand rotation is
/// retried by calling it again.
async fn record_rotation_failure(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    secret: &VaultSecret,
    message: &str,
) -> IamResult<()> {
    let now = ctx.now();
    let failures = rotation_member(secret, "failures")
        .and_then(Value::as_f64)
        .unwrap_or(0.0)
        + 1.0;
    let retry_in = DAY.min(60.0 * MINUTE * 2f64.powf((failures - 1.0).min(5.0)));
    let scheduled = rotation_member(secret, "intervalDays").is_some()
        || secret
            .checkout
            .as_ref()
            .is_some_and(|policy| policy.rotate_on_checkin);
    let mut rotation = secret
        .rotation
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    rotation.insert(
        "lastFailure".into(),
        json!({ "at": number(now), "message": message }),
    );
    rotation.insert("failures".into(), number(failures));
    if scheduled {
        rotation.insert("nextRotationAt".into(), number(now + retry_in));
    }
    let mut next = secret.clone();
    next.rotation = Some(Value::Object(rotation));
    tx.put(col("secrets"), &record(&next)).await?;
    Ok(())
}

/// Who acts in the vault's audit events: a principal, or the scheduler (`deployment-operator`).
#[derive(Clone)]
enum Actor {
    Principal(Box<AuthenticatedPrincipal>),
    Operator,
}

/// The vault's audit recorder for one secret.
#[derive(Clone)]
struct Recorder {
    actor: Actor,
    tenant_id: String,
    name: String,
}

impl Recorder {
    /// `principalRecorder(ctx, principal, tenantId, name)`.
    fn principal(principal: &AuthenticatedPrincipal, tenant_id: &str, name: &str) -> Self {
        Self {
            actor: Actor::Principal(Box::new(principal.clone())),
            tenant_id: tenant_id.to_owned(),
            name: name.to_owned(),
        }
    }

    /// `operatorRecorder(ctx, tenantId, name)`.
    fn operator(tenant_id: &str, name: &str) -> Self {
        Self {
            actor: Actor::Operator,
            tenant_id: tenant_id.to_owned(),
            name: name.to_owned(),
        }
    }

    /// The same actor recording for another secret (`record(name)`).
    fn named(&self, name: &str) -> Self {
        Self {
            name: name.to_owned(),
            ..self.clone()
        }
    }

    async fn record(
        &self,
        ctx: &Arc<ServerContext>,
        tx: &Store,
        action: &str,
        outcome: AuditOutcome,
        metadata: Map<String, Value>,
    ) -> IamResult<()> {
        let resource_id = resource(&self.name)?;
        match &self.actor {
            Actor::Principal(principal) => {
                ctx.events()?
                    .audit(
                        tx,
                        principal,
                        action,
                        &self.tenant_id,
                        &resource_id,
                        outcome,
                        false,
                        Some(metadata),
                    )
                    .await
            }
            Actor::Operator => {
                let event = meta(vec![
                    ("id", string(id())),
                    ("tenantId", string(self.tenant_id.clone())),
                    ("actorId", string(VAULT_OPERATOR)),
                    ("action", string(action)),
                    ("resourceId", string(resource_id)),
                    ("timestamp", number(ctx.now())),
                    (
                        "outcome",
                        string(match outcome {
                            AuditOutcome::Allow => "allow",
                            AuditOutcome::Deny => "deny",
                        }),
                    ),
                    ("metadata", Value::Object(metadata)),
                ]);
                ctx.events()?.record_audit(tx, &event).await
            }
        }
    }
}

/// The outcome of `completeRotation`.
enum RotationOutcome {
    Ok { version: f64, result: Value },
    Failed(String),
}

/// `redactedMessage(error, values)` for an error message.
fn redacted(message: &str, values: &[Option<String>]) -> IamResult<String> {
    store_vault::redacted_message(Some(&string(message)), values)
}

/// Calls the rotator (outside any transaction), then promotes the pending version, or records the failure with a
/// growing retry delay. Returns the outcome; the caller decides whether a failure throws.
async fn complete_rotation(
    ctx: &Arc<ServerContext>,
    staged: &StagedRotation,
    actor_id: &str,
    recorder: &Recorder,
) -> IamResult<RotationOutcome> {
    let mut failure: Option<String> = None;
    if let Some(rotator_name) = &staged.rotator {
        let vault = settings(ctx)?;
        match vault.rotators.get(rotator_name).cloned() {
            None => failure = Some(format!("The rotator {rotator_name} is not configured")),
            Some(rotator) => {
                let attempt: IamResult<()> = async {
                    let mut input = meta(vec![
                        ("tenantId", string(staged.tenant_id.clone())),
                        ("name", string(staged.name.clone())),
                        ("version", number(staged.version)),
                        ("value", string(staged.value.clone())),
                    ]);
                    if is_json(&staged.format) {
                        input.insert(
                            "fields".into(),
                            fields_json(&store_vault::parse_fields(&staged.value)?),
                        );
                    }
                    if let Some(previous) = &staged.previous {
                        input.insert("previous".into(), string(previous.clone()));
                        if is_json(&staged.format) {
                            input.insert(
                                "previousFields".into(),
                                fields_json(&store_vault::parse_fields(previous)?),
                            );
                        }
                    }
                    input.insert("tags".into(), tags_json(&staged.tags));
                    let input = Value::Object(input);
                    let call: Callback = Arc::new(move |_| {
                        let (rotator, input) = (rotator.clone(), input.clone());
                        Box::pin(async move { rotator.rotate(input).await.map(|()| Value::Null) })
                    });
                    timed(ctx, &format!("The rotator {rotator_name}"), call).await?;
                    Ok(())
                }
                .await;
                if let Err(error) = attempt {
                    failure = Some(redacted(
                        &error.message,
                        &[Some(staged.value.clone()), staged.previous.clone()],
                    )?);
                }
            }
        }
    }
    let (staged, failure, recorder) = (staged, &failure, recorder);
    ctx.store
        .transaction(|tx| async move {
            let secret = match tx.get(col("secrets"), &staged.secret_id).await? {
                Some(raw) => Some(decode::<VaultSecret>(raw)?),
                None => None,
            };
            let Some(secret) = secret.filter(|secret| secret.status == "active") else {
                return Ok(RotationOutcome::Failed(
                    "The secret was deleted during rotation".into(),
                ));
            };
            if let Some(failure) = failure {
                record_rotation_failure(ctx, &tx, &secret, failure).await?;
                let mut metadata = meta(vec![
                    ("name", string(secret.name.clone())),
                    ("version", number(staged.version)),
                ]);
                if let Some(rotator) = &staged.rotator {
                    metadata.insert("rotator".into(), string(rotator.clone()));
                }
                metadata.insert("error".into(), string(failure.clone()));
                recorder
                    .record(ctx, &tx, "vault:rotate", AuditOutcome::Deny, metadata)
                    .await?;
                return Ok(RotationOutcome::Failed(failure.clone()));
            }
            if secret.stages.get("pending") != Some(&staged.version)
                && secret.stages.get("current") != Some(&staged.version)
            {
                return Ok(RotationOutcome::Failed(
                    "Another change replaced the pending version during rotation".into(),
                ));
            }
            // The version may have been disabled or destroyed while the rotator ran: never make that current.
            let version = store_vault::version_of(&tx, &secret, staged.version).await?;
            if !version.is_some_and(|version| version.state == "enabled") {
                return Ok(RotationOutcome::Failed(
                    "The pending version was disabled or destroyed during rotation".into(),
                ));
            }
            let promoted = store_vault::promote_version(
                ctx,
                &tx,
                &secret,
                staged.version,
                actor_id,
                Some(true),
            )
            .await?;
            store_vault::record_access(
                ctx,
                &tx,
                &promoted,
                &json!({
                    "identityId": actor_id,
                    "action": "rotate",
                    "version": number(staged.version),
                }),
            )
            .await?;
            let mut metadata = meta(vec![
                ("name", string(secret.name.clone())),
                ("version", number(staged.version)),
            ]);
            if let Some(rotator) = &staged.rotator {
                metadata.insert("rotator".into(), string(rotator.clone()));
            }
            recorder
                .record(ctx, &tx, "vault:rotate", AuditOutcome::Allow, metadata)
                .await?;
            let rotated_at =
                match rotation_member(&promoted, "lastRotatedAt").and_then(Value::as_f64) {
                    Some(at) => at,
                    None => ctx.now(),
                };
            let mut result = meta(vec![
                ("name", string(promoted.name.clone())),
                ("version", number(staged.version)),
                ("rotatedAt", number(rotated_at)),
            ]);
            if let Some(rotator) = &staged.rotator {
                result.insert("rotator".into(), string(rotator.clone()));
            }
            result.insert("stages".into(), stages_json(&promoted.stages));
            Ok(RotationOutcome::Ok {
                version: staged.version,
                result: Value::Object(result),
            })
        })
        .await
}

/// Rotates a `rotateOnCheckin` secret once its last check-out has ended (returned, revoked or expired). Failures,
/// including one that stops the rotation before the rotator runs, are recorded on the secret and audited, and
/// `iam.vault.rotateDue` retries them; they are never thrown, because the check-out has ended either way.
async fn rotate_returned(
    ctx: &Arc<ServerContext>,
    tenant_id: &str,
    secret_id: &str,
    actor_id: &str,
    recorder: &Recorder,
) -> IamResult<Option<f64>> {
    let staged = ctx
        .store
        .transaction(|tx| async move {
            let secret = match tx.get(col("secrets"), secret_id).await? {
                Some(raw) => decode::<VaultSecret>(raw)?,
                None => return Ok(None),
            };
            if secret.tenant_id != tenant_id
                || secret.status != "active"
                || !secret
                    .checkout
                    .as_ref()
                    .is_some_and(|policy| policy.rotate_on_checkin)
            {
                return Ok(None);
            }
            // Another holder still has the value: rotate once the last one returns it.
            if store_vault::live_leases(ctx, &tx, &secret)
                .await?
                .iter()
                .any(|lease| lease.kind == "checkout")
            {
                return Ok(None);
            }
            Ok(Some(
                stage_rotation(ctx, &tx, &secret, actor_id, &json!({}), None).await?,
            ))
        })
        .await;
    let staged = match staged {
        Ok(staged) => staged,
        Err(error) => {
            let message = error.message.clone();
            let _ = ctx
                .store
                .transaction(|tx| async move {
                    let secret = match tx.get(col("secrets"), secret_id).await? {
                        Some(raw) => decode::<VaultSecret>(raw)?,
                        None => return Ok(()),
                    };
                    if secret.status != "active" {
                        return Ok(());
                    }
                    let message = redacted(&message, &[])?;
                    record_rotation_failure(ctx, &tx, &secret, &message).await?;
                    recorder
                        .named(&secret.name)
                        .record(
                            ctx,
                            &tx,
                            "vault:rotate",
                            AuditOutcome::Deny,
                            meta(vec![
                                ("name", string(secret.name.clone())),
                                ("error", string(message)),
                            ]),
                        )
                        .await
                })
                .await;
            return Ok(None);
        }
    };
    let Some(staged) = staged else {
        return Ok(None);
    };
    let outcome = complete_rotation(ctx, &staged, actor_id, &recorder.named(&staged.name)).await?;
    Ok(match outcome {
        RotationOutcome::Ok { version, .. } => Some(version),
        RotationOutcome::Failed(_) => None,
    })
}

/// The engine's credential, validated against the secret's format and the size limit. Errors are messages (the
/// caller redacts and records them).
fn issued_value(
    vault: &Settings,
    format: &Value,
    issued: &Value,
) -> Result<(String, Option<String>), String> {
    if !matches!(issued, Value::Object(_) | Value::Array(_)) {
        return Err("The engine returned no credential".into());
    }
    let member = |key: &str| issued.as_object().and_then(|map| map.get(key));
    let input = |key: &str| {
        let mut map = Map::new();
        if let Some(value) = member(key) {
            map.insert(key.into(), value.clone());
        }
        Value::Object(map)
    };
    let value = if is_json(format) {
        if member("fields").is_some() {
            store_vault::secret_value(&vault.raw, &string("json"), &input("fields"))
        } else {
            store_vault::secret_value(&vault.raw, &string("json"), &input("value"))
        }
    } else {
        store_vault::secret_value(&vault.raw, &string("text"), &input("value"))
    }
    .map_err(|error| error.message)?;
    let handle = match member("handle") {
        None => None,
        Some(Value::String(handle)) if utf16_len(handle) <= 4096 => Some(handle.clone()),
        Some(_) => return Err("The engine returned an invalid handle".into()),
    };
    Ok((value, handle))
}

/// Ends a dynamic lease at its engine; the caller records the outcome. Fails with the redacted message.
async fn revoke_at_engine(
    ctx: &Arc<ServerContext>,
    lease: &VaultLease,
    secret: Option<&VaultSecret>,
) -> Result<(), String> {
    let engine_name = secret.and_then(|secret| secret.engine.clone());
    let vault = settings(ctx).map_err(|error| error.message)?;
    let engine = engine_name
        .as_ref()
        .filter(|name| !name.is_empty())
        .and_then(|name| vault.engines.get(name).cloned());
    let Some(engine) = engine.filter(|engine| engine.has_revoke()) else {
        return Ok(());
    };
    let handle = match &lease.handle_sealed {
        Some(sealed) if !sealed.is_empty() => {
            let context = store_vault::lease_handle_context(&lease.id).map_err(|e| e.message)?;
            Some(store_vault::open_value(ctx, sealed, &context).map_err(|e| e.message)?)
        }
        _ => None,
    };
    let mut input = meta(vec![
        ("tenantId", string(lease.tenant_id.clone())),
        ("name", string(lease.name.clone())),
        ("leaseId", string(lease.id.clone())),
        (
            "config",
            secret
                .and_then(|secret| secret.engine_config.clone())
                .unwrap_or_else(|| json!({})),
        ),
    ]);
    if let Some(handle) = &handle {
        input.insert("handle".into(), string(handle.clone()));
    }
    let input = Value::Object(input);
    let call: Callback = Arc::new(move |_| {
        let (engine, input) = (engine.clone(), input.clone());
        Box::pin(async move { engine.revoke(input).await.map(|()| Value::Null) })
    });
    let what = format!("The engine {}", engine_name.unwrap_or_default());
    match timed(ctx, &what, call).await {
        Ok(_) => Ok(()),
        Err(error) => Err(redacted(&error.message, &[handle]).unwrap_or_else(|e| e.message)),
    }
}

/// Revokes a dynamic lease at its engine and records the outcome: the lease ends in its `endState` (default `ended`),
/// or stays `revoking` with a retry scheduled (one minute, doubling up to six hours) for `iam.vault.expireLeases`. The
/// lease must already be `revoking`. Engines without `revoke` end the lease at once.
async fn revoke_and_record(
    ctx: &Arc<ServerContext>,
    lease_id: &str,
) -> IamResult<Result<(), String>> {
    let lease = match ctx.store.get(col("leases"), lease_id).await? {
        Some(raw) => decode::<VaultLease>(raw)?,
        None => return Ok(Ok(())),
    };
    if lease.state != "revoking" {
        return Ok(Ok(()));
    }
    let secret = match ctx.store.get(col("secrets"), &lease.secret_id).await? {
        Some(raw) => Some(decode::<VaultSecret>(raw)?),
        None => None,
    };
    let error = revoke_at_engine(ctx, &lease, secret.as_ref()).await.err();
    let failure = &error;
    ctx.store
        .transaction(|tx| async move {
            let current = match tx.get(col("leases"), lease_id).await? {
                Some(raw) => decode::<VaultLease>(raw)?,
                None => return Ok(()),
            };
            if current.state != "revoking" {
                return Ok(());
            }
            let now = ctx.now();
            let mut next = current.clone();
            match failure {
                None => {
                    next.retry_at = None;
                    next.end_state = None;
                    next.state = current.end_state.clone().unwrap_or_else(|| "ended".into());
                    next.ended_at = Some(current.ended_at.unwrap_or(now));
                }
                Some(error) => {
                    let attempts = current.revoke_attempts.unwrap_or(0.0) + 1.0;
                    next.revoke_attempts = Some(attempts);
                    next.revoke_started_at = Some(current.revoke_started_at.unwrap_or(now));
                    next.retry_at = Some(
                        now + (6.0 * 60.0 * MINUTE)
                            .min(MINUTE * 2f64.powf((attempts - 1.0).min(9.0))),
                    );
                    next.last_error = Some(error.clone());
                }
            }
            tx.put(col("leases"), &record(&next)).await?;
            Ok(())
        })
        .await?;
    Ok(match error {
        None => Ok(()),
        Some(error) => Err(error),
    })
}

/// `ctx.decisions.decide(tx, subject, { tenantId, action, resource: { type: 'iam', id } }, true)`.
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

/// The principal, and the "view as" administrator behind its session when there is one.
async fn subjects(
    tx: &Store,
    principal: &AuthenticatedPrincipal,
) -> IamResult<Vec<AuthenticatedPrincipal>> {
    let actor = impersonating_actor(tx, principal).await?;
    let mut subjects = vec![principal.clone()];
    if let Some(actor) = actor {
        subjects.push(actor);
    }
    Ok(subjects)
}

/// Re-decides `action` on a secret as it is now inside the transaction (after its attributes changed, or a second
/// action one call also needs), for the caller and any "view as" administrator. An allowed call uses up a delegation's
/// confirmation of that action, as the operation's own action does.
async fn require_still(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    realm: &Tenant,
    name: &str,
    action: &str,
    message: &str,
) -> OperationResult<()> {
    let resource_id = resource(name)?;
    for subject in subjects(tx, principal).await? {
        let decision = ctx
            .decisions()?
            .decide(
                tx,
                &subject,
                &iam_request(&realm.id, action, &resource_id),
                true,
            )
            .await?;
        if !decision.allowed {
            return Err(OperationDenied::new(Some(message)));
        }
    }
    use_confirmation(tx, principal, action, "iam", &resource_id, ctx.now()).await?;
    Ok(())
}

/// The vault actions the caller, and any "view as" administrator behind the session, may perform on a secret as it
/// is stored now (one set per subject), to compare before and after a change of its attributes.
async fn reach(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    realm: &Tenant,
    name: &str,
) -> IamResult<Vec<HashSet<&'static str>>> {
    let resource_id = resource(name)?;
    let mut result = Vec::new();
    for subject in subjects(tx, principal).await? {
        let mut allowed = HashSet::new();
        for action in SECRET_ACTIONS {
            let decision = ctx
                .decisions()?
                .decide(
                    tx,
                    &subject,
                    &iam_request(&realm.id, action, &resource_id),
                    true,
                )
                .await?;
            if decision.allowed {
                allowed.insert(action);
            }
        }
        result.push(allowed);
    }
    Ok(result)
}

/// Refuses a change of a secret's attributes (tags, settings, key) that opens an action on it to the caller that the
/// secret as it was did not: managing a secret must not move it into what the caller may reveal, lease or rotate.
async fn require_no_wider(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    realm: &Tenant,
    name: &str,
    before: &[HashSet<&'static str>],
) -> OperationResult<()> {
    let after = reach(ctx, tx, principal, realm, name).await?;
    for (index, allowed) in after.iter().enumerate() {
        for action in SECRET_ACTIONS {
            if allowed.contains(action)
                && !before.get(index).is_some_and(|set| set.contains(action))
            {
                return Err(OperationDenied::new(Some(&format!(
                    "The change would give you {action} on the secret, which you do not have on it now"
                ))));
            }
        }
    }
    Ok(())
}

/// Refuses with ACCESS_DENIED unless the caller (and, in "view as", the administrator behind the session) may perform
/// `action` on the KMS key: binding a secret to a key, and taking a secret's values out from under one.
async fn require_key_action(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    realm: &Tenant,
    key_id: &str,
    action: &str,
) -> OperationResult<()> {
    let key = find_key(tx, &realm.id, Some(&string(key_id))).await?;
    let key_value = serde_json::to_value(&key).unwrap_or(Value::Null);
    let aliases = alias_names(tx, &key_value).await?;
    let resource = ResolvedResource {
        tenant_id: realm.id.clone(),
        kind: "iam".into(),
        id: format!("kms/{}", key.id),
        attributes: Some(key_attributes(&key_value, &aliases, None)?),
        classification: None,
    };
    for subject in subjects(tx, principal).await? {
        let prepared = ctx
            .decisions()?
            .prepare_decision(tx, &subject, realm, action)
            .await?;
        let decision = decide_on(&prepared, &resource, None)?;
        if !decision.allowed {
            return Err(OperationDenied::new(Some(if action == "iam:kms:encrypt" {
                "This needs iam:kms:encrypt on the secret\u{2019}s customer-managed key"
            } else {
                "This needs iam:kms:decrypt on the secret\u{2019}s customer-managed key"
            })));
        }
    }
    // A delegation that holds the key action back for the person's confirmation: this call uses the approval up.
    use_confirmation(tx, principal, action, "iam", &resource.id, ctx.now()).await?;
    Ok(())
}

/// A customer-managed key the caller may bind secrets to: an enabled encryption key of the tenant (id or
/// `alias/{name}`) on which they hold `iam:kms:encrypt`, so vault rights cannot put values under a key they cannot use.
async fn usable_key(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    realm: &Tenant,
    reference: Option<&Value>,
) -> OperationResult<String> {
    let key = find_key(tx, &realm.id, reference).await?;
    assert_usable(&key, &string("encrypt"))?;
    // The KMS service helpers envelope-encrypt with AES-256-GCM keys only; refuse others when binding, not later.
    if key.key_spec != "aes-256-gcm" {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Customer-managed keys for the vault are aes-256-gcm encryption keys",
        )
        .into());
    }
    require_key_action(ctx, tx, principal, realm, &key.id, "iam:kms:encrypt").await?;
    Ok(key.id)
}

/// The key-owner's say over a customer-managed secret, as with AWS KMS: values come out only for callers who may also
/// decrypt with its key, and go in only for callers who may encrypt with it. Jobs and `iam.vault` are not asked.
async fn require_secret_key(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    realm: &Tenant,
    secret: &VaultSecret,
    actions: &[&str],
) -> OperationResult<()> {
    let Some(key_id) = &secret.kms_key_id else {
        return Ok(());
    };
    for action in actions {
        require_key_action(ctx, tx, principal, realm, key_id, action).await?;
    }
    Ok(())
}

async fn views(ctx: &Arc<ServerContext>, tx: &Store, secret: &VaultSecret) -> IamResult<Value> {
    let leases = store_vault::live_leases(ctx, tx, secret).await?;
    Ok(view(secret, &leases, ctx.now()))
}

async fn put_secret(tx: &Store, secret: &VaultSecret) -> IamResult<VaultSecret> {
    decode(tx.put(col("secrets"), &record(secret)).await?)
}

async fn put_lease(tx: &Store, lease: &VaultLease) -> IamResult<VaultLease> {
    decode(tx.put(col("leases"), &record(lease)).await?)
}

async fn get_lease(tx: &Store, lease_id: &str) -> IamResult<Option<VaultLease>> {
    match tx.get(col("leases"), lease_id).await? {
        Some(raw) => Ok(Some(decode(raw)?)),
        None => Ok(None),
    }
}

async fn get_secret(tx: &Store, secret_id: &str) -> IamResult<Option<VaultSecret>> {
    match tx.get(col("secrets"), secret_id).await? {
        Some(raw) => Ok(Some(decode(raw)?)),
        None => Ok(None),
    }
}

/// The names of identities by id, read once each (`identities` records).
async fn identity_names(
    tx: &Store,
    ids: impl IntoIterator<Item = String>,
) -> IamResult<HashMap<String, String>> {
    let mut names = HashMap::new();
    for identity_id in ids {
        if names.contains_key(&identity_id) {
            continue;
        }
        if let Some(identity) = tx.get("identities", &identity_id).await?
            && let Some(name) = identity.get("name").and_then(Value::as_str)
        {
            names.insert(identity_id, name.to_owned());
        }
    }
    Ok(names)
}

/// A call on a lease, by verb.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LeaseVerb {
    Checkin,
    Renew,
    Revoke,
}

impl LeaseVerb {
    fn as_str(self) -> &'static str {
        match self {
            LeaseVerb::Checkin => "checkin",
            LeaseVerb::Renew => "renew",
            LeaseVerb::Revoke => "revoke",
        }
    }
}

/// What a call on a lease did, for the work that follows its transaction.
#[derive(Clone)]
enum LeaseOutcome {
    Checkin {
        tenant_id: String,
        secret_id: String,
        actor: Box<AuthenticatedPrincipal>,
    },
    Renew {
        result: Value,
        lease: Box<VaultLease>,
        secret: Option<Box<VaultSecret>>,
        ttl: f64,
    },
    Revoke {
        kind: &'static str,
        lease: Box<VaultLease>,
        actor: Box<AuthenticatedPrincipal>,
    },
}

impl LeaseOutcome {
    /// The value the TypeScript `fn` returns (what plugin hooks see).
    fn to_json(&self) -> Value {
        match self {
            LeaseOutcome::Checkin {
                tenant_id,
                secret_id,
                ..
            } => json!({ "tenantId": tenant_id, "secretId": secret_id }),
            LeaseOutcome::Renew { result, .. } => result.clone(),
            LeaseOutcome::Revoke { kind, lease, .. } => {
                json!({ "kind": kind, "lease": Value::Object(record(lease.as_ref())) })
            }
        }
    }
}

// --- the API -----------------------------------------------------------------------------------------------------

/// The answer and the values of a value operation's mutation, apart.
type Split = (Map<String, Value>, Map<String, Value>);

/// The mutation of a value operation.
type ValueMutation<'m> =
    Box<dyn FnOnce(MutationContext) -> BoxFuture<'m, OperationResult<Split>> + Send + 'm>;

/// The `vault` API group (`createVaultApi(ctx)`): one method per route `vault/{method}`.
pub struct VaultApi {
    ctx: Arc<ServerContext>,
}

/// `createVaultApi(ctx)`.
pub fn create_vault_api(ctx: &Arc<ServerContext>) -> IamResult<VaultApi> {
    Ok(VaultApi { ctx: ctx.clone() })
}

impl VaultApi {
    async fn operation(
        &self,
        credential: &CredentialInput,
        tenant_id: Option<&Value>,
        action: &str,
        resource_id: &str,
        mutation: Mutation<'_>,
    ) -> IamResult<Value> {
        self.ctx
            .operations()?
            .operation(credential, tenant_id, action, resource_id, mutation, false)
            .await
    }

    /// An operation whose answer carries secret values: plugins' `afterOperation` hooks see the answer without them, as
    /// with the KMS's plaintexts. `run` returns the answer and the values apart; the caller gets both.
    async fn value_operation<'m>(
        &self,
        credential: &CredentialInput,
        tenant_id: Option<&Value>,
        action: &str,
        resource_id: &str,
        run: ValueMutation<'m>,
    ) -> IamResult<Value> {
        let slot: Arc<Mutex<Option<Map<String, Value>>>> = Arc::default();
        let values = slot.clone();
        let mutation: Mutation<'m> = Box::new(move |call| {
            Box::pin(async move {
                let (answer, split) = run(call).await?;
                *values.lock().unwrap_or_else(|e| e.into_inner()) = Some(split);
                Ok(Value::Object(answer))
            })
        });
        let answer = self
            .operation(credential, tenant_id, action, resource_id, mutation)
            .await?;
        let mut out = answer.as_object().cloned().unwrap_or_default();
        let values = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
        for (key, value) in values.unwrap_or_default() {
            out.insert(key, value);
        }
        Ok(Value::Object(out))
    }

    /// What one verb does to a lease (the TypeScript `fn` of each lease call).
    #[allow(clippy::too_many_arguments)]
    async fn lease_call(
        &self,
        verb: LeaseVerb,
        input: &Map<String, Value>,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        lease: VaultLease,
        secret: Option<VaultSecret>,
        holder: bool,
    ) -> OperationResult<LeaseOutcome> {
        let ctx = &self.ctx;
        match verb {
            LeaseVerb::Checkin => {
                if lease.kind != "checkout" {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "This is a dynamic lease; use revokeLease",
                    )
                    .into());
                }
                if lease.state != "active" || lease.expires_at <= ctx.now() {
                    return Err(IamError::new(
                        "INVALID_TRANSITION",
                        "This check-out has already ended",
                    )
                    .into());
                }
                let mut ended = lease.clone();
                ended.state = "ended".into();
                ended.ended_at = Some(ctx.now());
                ended.ended_by = Some(principal.identity.id.clone());
                put_lease(tx, &ended).await?;
                if let Some(secret) = &secret {
                    store_vault::record_access(
                        ctx,
                        tx,
                        secret,
                        &access(principal, "checkin", lease.version, Some(&lease.id)),
                    )
                    .await?;
                }
                Ok(LeaseOutcome::Checkin {
                    tenant_id: lease.tenant_id.clone(),
                    secret_id: lease.secret_id.clone(),
                    actor: Box::new(principal.clone()),
                })
            }
            LeaseVerb::Renew => {
                if !holder {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Only the holder renews a lease",
                        403,
                    )
                    .into());
                }
                let now = ctx.now();
                if lease.state != "active" || lease.expires_at <= now {
                    return Err(IamError::new(
                        "INVALID_TRANSITION",
                        "This lease has already ended",
                    )
                    .into());
                }
                let Some(secret) = secret.filter(|secret| secret.status == "active") else {
                    return Err(IamError::with_status(
                        "SECRET_PENDING_DELETION",
                        "This secret is scheduled for deletion",
                        409,
                    )
                    .into());
                };
                // Extending access is using it again: the holder must still be allowed to lease the secret.
                let realm = ctx.tenant(tx, &lease.tenant_id).await?;
                require_still(
                    ctx,
                    tx,
                    principal,
                    &realm,
                    &lease.name,
                    "iam:vault:lease",
                    "Renewing needs iam:vault:lease on the secret",
                )
                .await?;
                let length = match input.get("ttlMs") {
                    None => lease.ttl_ms.unwrap_or(lease.expires_at - lease.issued_at),
                    Some(value) => integer(Some(value), "ttlMs", MINUTE, 30.0 * DAY)?,
                };
                let expires_at = (now + length).min(lease.max_expires_at);
                if expires_at <= lease.expires_at {
                    return Err(IamError::with_status(
                        "LIMIT_EXCEEDED",
                        "This lease has reached its longest allowed length",
                        409,
                    )
                    .into());
                }
                let mut extended = lease.clone();
                extended.expires_at = expires_at;
                let next = put_lease(tx, &extended).await?;
                store_vault::record_access(
                    ctx,
                    tx,
                    &secret,
                    &access(principal, "renew", None, Some(&lease.id)),
                )
                .await?;
                let result = json!({
                    "leaseId": next.id,
                    "expiresAt": number(next.expires_at),
                    "maxExpiresAt": number(next.max_expires_at),
                });
                Ok(LeaseOutcome::Renew {
                    result,
                    lease: Box::new(next),
                    secret: Some(Box::new(secret)),
                    ttl: expires_at - now,
                })
            }
            LeaseVerb::Revoke => {
                if lease.state != "active" && lease.state != "revoking" && lease.state != "issuing"
                {
                    return Err(IamError::new(
                        "INVALID_TRANSITION",
                        "This lease has already ended",
                    )
                    .into());
                }
                let now = ctx.now();
                if let Some(secret) = &secret {
                    store_vault::record_access(
                        ctx,
                        tx,
                        secret,
                        &access(principal, "revoke", None, Some(&lease.id)),
                    )
                    .await?;
                }
                if lease.kind == "checkout" {
                    let mut ended = lease.clone();
                    ended.state = "ended".into();
                    ended.ended_at = Some(now);
                    ended.ended_by = Some(principal.identity.id.clone());
                    put_lease(tx, &ended).await?;
                    return Ok(LeaseOutcome::Revoke {
                        kind: "checkout",
                        lease: Box::new(lease),
                        actor: Box::new(principal.clone()),
                    });
                }
                // A lease still being issued is marked here; the issue sees it and revokes what the engine minted.
                let issuing = lease.state == "issuing";
                let mut marked = lease.clone();
                marked.state = if issuing { "ended" } else { "revoking" }.into();
                marked.ended_at = Some(lease.ended_at.unwrap_or(now));
                marked.ended_by = Some(
                    lease
                        .ended_by
                        .clone()
                        .unwrap_or_else(|| principal.identity.id.clone()),
                );
                if !issuing {
                    marked.end_state =
                        Some(lease.end_state.clone().unwrap_or_else(|| "ended".into()));
                }
                put_lease(tx, &marked).await?;
                Ok(LeaseOutcome::Revoke {
                    kind: if issuing { "issuing" } else { "dynamic" },
                    lease: Box::new(lease),
                    actor: Box::new(principal.clone()),
                })
            }
        }
    }

    /// A call on a lease by its holder (no further permission: returning a check-out must always be possible) or, for
    /// anyone else, an `iam:vault:manage` operation on the secret.
    async fn on_lease(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        verb: LeaseVerb,
    ) -> IamResult<LeaseOutcome> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let lease_id = text(input.get("leaseId"), "leaseId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let peek = get_lease(&ctx.store, &lease_id)
            .await?
            .filter(|lease| lease.tenant_id == tenant_id)
            .ok_or_else(|| IamError::with_status("NOT_FOUND", "Lease not found", 404))?;
        let (tenant_id, lease_id) = (&tenant_id, &lease_id);
        let load = |tx: Store| async move {
            let lease = get_lease(&tx, lease_id)
                .await?
                .filter(|lease| lease.tenant_id == *tenant_id)
                .ok_or_else(|| IamError::with_status("NOT_FOUND", "Lease not found", 404))?;
            let secret = get_secret(&tx, &lease.secret_id).await?;
            Ok::<_, IamError>((lease, secret))
        };
        if peek.holder_id == authenticated.identity.id {
            let authenticated = &authenticated;
            return ctx
                .store
                .transaction(|tx| async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    ctx.tenant(&tx, tenant_id).await?;
                    if principal
                        .session
                        .impersonator_id
                        .as_deref()
                        .is_some_and(|id| !id.is_empty())
                    {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "Leases cannot be changed while viewing as another member",
                            403,
                        ));
                    }
                    let (lease, secret) = load(tx.clone()).await?;
                    // The session that took the lease may always return it. Another session of the holder (a delegated
                    // session, an API key a session policy narrows) acts on it only while it could take the lease
                    // itself.
                    if lease.session_id.as_deref() != Some(principal.session.id.as_str()) {
                        let realm = ctx.tenant(&tx, tenant_id).await?;
                        require_still(
                            ctx,
                            &tx,
                            &principal,
                            &realm,
                            &lease.name,
                            "iam:vault:lease",
                            "This session may not lease the secret; use the session that took the lease",
                        )
                        .await
                        .map_err(IamError::from)?;
                    }
                    let (lease_id, kind, name) =
                        (lease.id.clone(), lease.kind.clone(), lease.name.clone());
                    let value = self
                        .lease_call(verb, input, &tx, &principal, lease, secret, true)
                        .await
                        .map_err(IamError::from)?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            &format!("vault:{}", verb.as_str()),
                            tenant_id,
                            &resource(&name)?,
                            AuditOutcome::Allow,
                            false,
                            Some(meta(vec![
                                ("leaseId", string(lease_id)),
                                ("kind", string(kind)),
                            ])),
                        )
                        .await?;
                    Ok(value)
                })
                .await;
        }
        let slot: Arc<Mutex<Option<LeaseOutcome>>> = Arc::default();
        let outcome = slot.clone();
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let (lease, secret) = load(tx.clone()).await?;
                let (lease_id, kind, holder_id, name) = (
                    lease.id.clone(),
                    lease.kind.clone(),
                    lease.holder_id.clone(),
                    lease.name.clone(),
                );
                let value = self
                    .lease_call(verb, input, &tx, &principal, lease, secret, false)
                    .await?;
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        &format!("vault:{}", verb.as_str()),
                        tenant_id,
                        &resource(&name)?,
                        AuditOutcome::Allow,
                        false,
                        Some(meta(vec![
                            ("leaseId", string(lease_id)),
                            ("kind", string(kind)),
                            ("holderId", string(holder_id)),
                        ])),
                    )
                    .await?;
                let json = value.to_json();
                *outcome.lock().unwrap_or_else(|e| e.into_inner()) = Some(value);
                Ok(json)
            })
        });
        self.operation(
            credential,
            Some(&string(tenant_id.clone())),
            "iam:vault:manage",
            &resource(&peek.name)?,
            mutation,
        )
        .await?;
        let outcome = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
        outcome.ok_or_else(crate::js::internal_error)
    }

    /// `vault/accessLog`: who used a secret, newest first: reveals, check-outs and returns, leases, renewals,
    /// revocations, new versions and rotations, kept `vault.accessRetentionDays` (default 90). At most `limit` (1-500,
    /// default 100), optionally for one `identityId`. Requires iam:vault:read.
    pub async fn access_log(
        &self,
        credential: &CredentialInput,
        input: Body<vault::AccessLogInput>,
    ) -> IamResult<Reply<vault::AccessLogOutput>> {
        let body = &input;
        let name = secret_name(input.get("name"))?;
        let limit = match input.get("limit") {
            None => 100.0,
            Some(value) => integer(Some(value), "limit", 1.0, 500.0)?,
        };
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx, tenant: realm, ..
                  }| {
                Box::pin(async move {
                    let secret = existing_secret(&tx, &realm.id, name_ref).await?;
                    let mut filter = Filter::new()
                        .eq("tenantId", realm.id.clone())
                        .eq("secretId", secret.id.clone());
                    if let Some(identity_id) = body.get("identityId") {
                        filter =
                            filter.eq("identityId", text(Some(identity_id), "identityId", 256)?);
                    }
                    let records = find_ordered(
                        tx.as_ref(),
                        col("access"),
                        &filter,
                        &OrderOptions {
                            direction: Direction::Desc,
                            limit: Some(limit as i64),
                            ..OrderOptions::by("at")
                        },
                        None,
                    )
                    .await?;
                    let identities: Vec<String> = records
                        .iter()
                        .map(|record| {
                            record
                                .get("identityId")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned()
                        })
                        .collect();
                    let names = identity_names(&tx, identities).await?;
                    let mut out = Vec::new();
                    for record in records {
                        let identity_id = record
                            .get("identityId")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned();
                        let mut entry = Map::new();
                        entry.insert(
                            "at".into(),
                            js_value(record.get("at").cloned().unwrap_or(Value::Null)),
                        );
                        entry.insert("identityId".into(), string(identity_id.clone()));
                        if let Some(name) = names.get(&identity_id) {
                            entry.insert("identityName".into(), string(name.clone()));
                        }
                        entry.insert(
                            "action".into(),
                            record.get("action").cloned().unwrap_or(Value::Null),
                        );
                        for key in ["version", "leaseId", "sessionKind", "agentId"] {
                            if let Some(value) = record.get(key) {
                                entry.insert(key.into(), js_value(value.clone()));
                            }
                        }
                        out.push(Value::Object(entry));
                    }
                    Ok(Value::Array(out))
                })
            },
        );
        let result = self
            .operation(
                credential,
                input.get("tenantId"),
                "iam:vault:read",
                &resource(&name)?,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `vault/checkin`: returns a check-out (its holder needs no further permission; anyone else needs
    /// iam:vault:manage). A secret with `rotateOnCheckin` rotates once its last holder returns it; `rotated` says to
    /// which version. Audited as `vault:checkin`.
    pub async fn checkin(
        &self,
        credential: &CredentialInput,
        input: Body<vault::CheckinInput>,
    ) -> IamResult<Reply<vault::CheckinOutput>> {
        let ctx = &self.ctx;
        let LeaseOutcome::Checkin {
            tenant_id,
            secret_id,
            actor,
        } = self
            .on_lease(credential, &input, LeaseVerb::Checkin)
            .await?
        else {
            return Err(crate::js::internal_error());
        };
        let rotated = rotate_returned(
            ctx,
            &tenant_id,
            &secret_id,
            &actor.identity.id,
            &Recorder::principal(&actor, &tenant_id, ""),
        )
        .await?;
        let mut out = meta(vec![
            (
                "leaseId",
                input.get("leaseId").cloned().unwrap_or(Value::Null),
            ),
            ("state", string("ended")),
        ]);
        if let Some(version) = rotated {
            out.insert("rotated".into(), number(version));
        }
        Ok(Reply::json(Value::Object(out)))
    }

    /// `vault/checkout`: checks out a static secret: its current value with a lease of `durationMs` (default and at
    /// most the policy's `maxDurationMs`). An exclusive secret has one holder at a time (SECRET_CHECKED_OUT otherwise);
    /// `reason` is required when the policy says so. Refused while viewing as another member. Requires
    /// iam:vault:lease; audited as `vault:checkout`.
    pub async fn checkout(
        &self,
        credential: &CredentialInput,
        input: Body<vault::CheckoutInput>,
    ) -> IamResult<Reply<vault::CheckoutOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let name = secret_name(input.get("name"))?;
        let name_ref = &name;
        let result = self
            .value_operation(
                credential,
                input.get("tenantId"),
                "iam:vault:lease",
                &resource(&name)?,
                Box::new(move |MutationContext { tx, tenant: realm, principal }| {
                    Box::pin(async move {
                        refuse_impersonation(&principal)?;
                        let secret = static_secret(active_secret(
                            existing_secret(&tx, &realm.id, name_ref).await?,
                        )?)?;
                        require_secret_key(ctx, &tx, &principal, &realm, &secret, &["iam:kms:decrypt"])
                            .await?;
                        // Without a policy there is nothing to check out: iam:vault:lease granted for dynamic secrets
                        // must not hand out stored values that iam:vault:reveal guards.
                        let Some(policy) = secret.checkout.clone() else {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "This secret has no check-out policy; reveal it with vault.reveal",
                            )
                            .into());
                        };
                        let reason = match body.get("reason") {
                            None => None,
                            Some(Value::String(reason)) if reason.is_empty() => None,
                            Some(value) => Some(
                                core_js::trim(&text(Some(value), "reason", 512)?).to_owned(),
                            ),
                        };
                        let reason = reason.filter(|reason| !reason.is_empty());
                        if policy.require_reason && reason.is_none() {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "A check-out of this secret needs a reason",
                            )
                            .into());
                        }
                        let duration = match body.get("durationMs") {
                            None => policy.max_duration_ms,
                            Some(value) => {
                                integer(Some(value), "durationMs", MINUTE, policy.max_duration_ms)?
                            }
                        };
                        let live = store_vault::live_leases(ctx, &tx, &secret).await?;
                        let holders: Vec<&VaultLease> =
                            live.iter().filter(|lease| lease.kind == "checkout").collect();
                        if holders
                            .iter()
                            .any(|lease| lease.holder_id == principal.identity.id)
                        {
                            return Err(IamError::with_status(
                                "SECRET_CHECKED_OUT",
                                "You already hold a check-out of this secret; check it in or renew it",
                                409,
                            )
                            .into());
                        }
                        if policy.exclusive && !holders.is_empty() {
                            return Err(IamError::with_status(
                                "SECRET_CHECKED_OUT",
                                "Someone else has this secret checked out; try again when it is checked in",
                                409,
                            )
                            .into());
                        }
                        let version = store_vault::select_version(&tx, &secret, &json!({})).await?;
                        let use_ = value_use(&principal);
                        let value =
                            store_vault::open_version(ctx, &tx, &version, Some(&use_)).await?;
                        let now = ctx.now();
                        let lease_id = id();
                        let mut lease = meta(vec![
                            ("id", string(lease_id.clone())),
                            ("tenantId", string(realm.id.clone())),
                            ("secretId", string(secret.id.clone())),
                            ("name", string(name_ref.clone())),
                            ("kind", string("checkout")),
                            ("holderId", string(principal.identity.id.clone())),
                            ("sessionId", string(principal.session.id.clone())),
                        ]);
                        lease_actor(&principal, &mut lease);
                        lease.insert("version".into(), number(version.version));
                        if let Some(reason) = &reason {
                            lease.insert("reason".into(), string(reason.clone()));
                        }
                        let expires_at = now + duration;
                        let max_expires_at = now + policy.max_duration_ms;
                        lease.insert("state".into(), string("active"));
                        lease.insert("issuedAt".into(), number(now));
                        lease.insert("expiresAt".into(), number(expires_at));
                        lease.insert("maxExpiresAt".into(), number(max_expires_at));
                        lease.insert("ttlMs".into(), number(duration));
                        tx.insert(col("leases"), &lease).await?;
                        store_vault::record_access(
                            ctx,
                            &tx,
                            &secret,
                            &access(&principal, "checkout", Some(version.version), Some(&lease_id)),
                        )
                        .await?;
                        let mut metadata = meta(vec![
                            ("name", string(name_ref.clone())),
                            ("version", number(version.version)),
                            ("leaseId", string(lease_id.clone())),
                            ("expiresAt", number(expires_at)),
                        ]);
                        if let Some(reason) = &reason {
                            metadata.insert("reason".into(), string(reason.clone()));
                        }
                        ctx.events()?
                            .audit(
                                &tx,
                                &principal,
                                "vault:checkout",
                                &realm.id,
                                &resource(name_ref)?,
                                AuditOutcome::Allow,
                                false,
                                Some(metadata),
                            )
                            .await?;
                        let shown = revealed(&secret, &version, value)?;
                        let mut answer = shown.answer();
                        answer.insert("leaseId".into(), string(lease_id));
                        answer.insert("expiresAt".into(), number(expires_at));
                        answer.insert("maxExpiresAt".into(), number(max_expires_at));
                        Ok((answer, shown.values()))
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `vault/create`: creates a secret. Static secrets may start with a value (`value`, or `fields` for `json`
    /// secrets), a generated one (`generate: true` or a generator), or none yet. Dynamic secrets name an `engine` from
    /// the `vault.engines` option and have no stored value: each `vault.lease` mints a credential. Requires
    /// iam:vault:manage on `iam/vault/secrets/{name}`; audited as `vault:create`.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<vault::CreateInput>,
    ) -> IamResult<Reply<vault::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let name = secret_name(input.get("name"))?;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      tenant: realm,
                      principal,
                  }| {
                Box::pin(async move {
                    writable(&realm)?;
                    let vault = settings(ctx)?;
                    let kind = match body.get("kind") {
                        None | Some(Value::Null) => string("static"),
                        Some(kind) => kind.clone(),
                    };
                    if kind == "dynamic" && body.get("kmsKey").is_some() {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "Dynamic secrets store no values to encrypt",
                        )
                        .into());
                    }
                    if kind != "static" && kind != "dynamic" {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "kind must be static or dynamic",
                        )
                        .into());
                    }
                    let format = store_vault::secret_format(body.get("format"))?;
                    if let Some(existing) =
                        store_vault::find_secret(&tx, &realm.id, name_ref).await?
                    {
                        return Err(IamError::with_status(
                        "CONFLICT",
                        if existing.status == "pending-deletion" {
                            "A secret with this name is scheduled for deletion; restore it or wait until it is purged"
                        } else {
                            "A secret with this name already exists"
                        },
                        409,
                    )
                    .into());
                    }
                    let count = tx
                        .find(
                            col("secrets"),
                            &Filter::new().eq("tenantId", realm.id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                        .len() as f64;
                    if count >= vault.max_secrets_per_tenant {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!(
                                "A tenant can hold at most {} secrets",
                                core_js::number_to_string(vault.max_secrets_per_tenant)
                            ),
                            409,
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let tags = store_vault::secret_tags(body.get("tags"))?;
                    let max = max_versions(body.get("maxVersions"), 10.0)?;
                    let mut fresh = meta(vec![
                        ("id", string(id())),
                        ("tenantId", string(realm.id.clone())),
                        ("uniqueKey", string(name_ref.clone())),
                        ("name", string(name_ref.clone())),
                        ("kind", kind.clone()),
                        ("format", format.clone()),
                        ("tags", tags_json(&tags)),
                        ("status", string("active")),
                        ("stages", json!({})),
                        ("latestVersion", number(0.0)),
                        ("maxVersions", number(max)),
                        ("createdAt", number(now)),
                        ("createdBy", string(principal.identity.id.clone())),
                        ("updatedAt", number(now)),
                        ("updatedBy", string(principal.identity.id.clone())),
                    ]);
                    if let Some(description) = body.get("description") {
                        fresh.insert(
                            "description".into(),
                            string(core_js::trim(&text(
                                Some(description),
                                "description",
                                1024,
                            )?)),
                        );
                    }
                    if kind == "dynamic" {
                        let engine = text(body.get("engine"), "engine", 64)?;
                        if !vault.engines.contains_key(&engine) {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                format!("Unknown engine {engine}"),
                            )
                            .into());
                        }
                        for key in ["value", "fields", "generate", "rotation", "checkout"] {
                            if body.get(key).is_some() {
                                return Err(IamError::new(
                                    "INVALID_INPUT",
                                    format!("Dynamic secrets take no {key}"),
                                )
                                .into());
                            }
                        }
                        fresh.insert("engine".into(), string(engine));
                        fresh.insert(
                            "engineConfig".into(),
                            store_vault::engine_config(body.get("engineConfig"))?,
                        );
                        fresh.insert(
                            "lease".into(),
                            json_of(&store_vault::lease_settings(body.get("lease"), None)?),
                        );
                    } else {
                        if body.get("engine").is_some()
                            || body.get("engineConfig").is_some()
                            || truthy(body.get("lease"))
                        {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "engine settings are for dynamic secrets",
                            )
                            .into());
                        }
                        let rotation = store_vault::schedule_rotation(
                            store_vault::rotation_settings(
                                &vault.raw,
                                &format,
                                body.get("rotation"),
                                None,
                            )?
                            .as_ref(),
                            now,
                            now,
                        )?;
                        if let Some(rotation) = rotation {
                            fresh.insert("rotation".into(), js_value(rotation));
                        }
                        if let Some(checkout) =
                            store_vault::checkout_policy(body.get("checkout"), None)?
                        {
                            fresh.insert("checkout".into(), json_of(&checkout));
                        }
                        if let Some(reference) = body.get("kmsKey") {
                            let key_id =
                                usable_key(ctx, &tx, &principal, &realm, Some(reference)).await?;
                            fresh.insert("kmsKeyId".into(), string(key_id));
                        }
                        checkout_fits(&decode::<VaultSecret>(fresh.clone())?)?;
                    }
                    tx.insert(col("secrets"), &fresh).await?;
                    let mut secret: VaultSecret = decode(fresh)?;
                    // Decided again with the new secret's attributes (tags, kind, engine, settings), which the first
                    // decision could not see: a name nobody uses yet has none.
                    require_still(
                        ctx,
                        &tx,
                        &principal,
                        &realm,
                        name_ref,
                        "iam:vault:manage",
                        "You may not create a secret with these attributes",
                    )
                    .await?;
                    let mut initial: Option<f64> = None;
                    let generate = truthy(body.get("generate"));
                    let given = body.get("value").is_some() || body.get("fields").is_some();
                    if kind == "static" && (given || generate) {
                        if generate && given {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "Pass a value or generate, not both",
                            )
                            .into());
                        }
                        let value = if generate {
                            let generated = store_vault::generate_value(
                                &store_vault::password_generator(body.get("generate"))?,
                            )?;
                            if is_json(&format) {
                                let Some(field) = rotation_field(&secret) else {
                                    return Err(IamError::new(
                                    "INVALID_INPUT",
                                    "json secrets generate into rotation.field; set it or pass fields",
                                )
                                .into());
                                };
                                let mut object = Map::new();
                                object.insert(field, string(generated));
                                core_js::stringify(&Value::Object(object))
                            } else {
                                generated
                            }
                        } else {
                            store_vault::secret_value(&vault.raw, &format, &body.value())?
                        };
                        let use_ = value_use(&principal);
                        let (added_secret, added_version) = add_version(
                            ctx,
                            &tx,
                            &secret,
                            &value,
                            if generate { "generated" } else { "put" },
                            &principal.identity.id,
                            Some(&use_),
                        )
                        .await?;
                        secret = store_vault::promote_version(
                            ctx,
                            &tx,
                            &added_secret,
                            added_version.version,
                            &principal.identity.id,
                            None,
                        )
                        .await?;
                        initial = Some(added_version.version);
                        store_vault::record_access(
                            ctx,
                            &tx,
                            &secret,
                            &access(&principal, "put", initial, None),
                        )
                        .await?;
                    }
                    let mut metadata = meta(vec![
                        ("name", string(name_ref.clone())),
                        ("kind", kind.clone()),
                        ("format", format.clone()),
                        ("tags", tags_json(&secret.tags)),
                    ]);
                    if let Some(version) = initial {
                        metadata.insert("version".into(), number(version));
                    }
                    if let Some(engine) = &secret.engine {
                        metadata.insert("engine".into(), string(engine.clone()));
                    }
                    if let Some(key) = &secret.kms_key_id {
                        metadata.insert("kmsKeyId".into(), string(key.clone()));
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "vault:create",
                            &realm.id,
                            &resource(name_ref)?,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(views(ctx, &tx, &secret).await?)
                })
            },
        );
        let result = self
            .operation(
                credential,
                input.get("tenantId"),
                "iam:vault:manage",
                &resource(&name)?,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `vault/delete`: schedules a secret for deletion after a recovery window of `recoveryDays` (7-30, default 30),
    /// during which it can be restored but not read; `recoveryDays: 0` deletes it at once (versions, leases and access
    /// records; live dynamic leases are revoked at their engine first). Live check-outs end. Requires
    /// iam:vault:manage; audited as `vault:delete`.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<vault::DeleteInput>,
    ) -> IamResult<Reply<vault::DeleteOutput>> {
        let ctx = &self.ctx;
        let name = secret_name(input.get("name"))?;
        let days = match input.get("recoveryDays") {
            None => 30.0,
            Some(Value::Number(n)) if n.as_f64() == Some(0.0) => 0.0,
            Some(value) => integer(Some(value), "recoveryDays", 7.0, 30.0)?,
        };
        let name_ref = &name;
        let slot: Arc<Mutex<Option<(String, f64)>>> = Arc::default();
        let scheduled = slot.clone();
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      tenant: realm,
                      principal,
                  }| {
                Box::pin(async move {
                    // Deleting at once destroys every value for good: only from a recently signed-in session.
                    if days == 0.0 {
                        ctx.auth.require_recent(&principal)?;
                    }
                    let secret = existing_secret(&tx, &realm.id, name_ref).await?;
                    if secret.status == "pending-deletion" && days != 0.0 {
                        return Err(IamError::with_status(
                            "SECRET_PENDING_DELETION",
                            "This secret is already scheduled for deletion",
                            409,
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let deletion_at = now + days * DAY;
                    let mut next = secret.clone();
                    next.status = "pending-deletion".into();
                    next.deletion_at = Some(deletion_at);
                    next.deletion_requested_by = Some(principal.identity.id.clone());
                    next.updated_at = now;
                    next.updated_by = principal.identity.id.clone();
                    let stored = put_secret(&tx, &next).await?;
                    for lease in store_vault::live_leases(ctx, &tx, &secret).await? {
                        if lease.kind == "checkout" {
                            let mut ended = lease.clone();
                            ended.state = "ended".into();
                            ended.ended_at = Some(now);
                            ended.ended_by = Some(principal.identity.id.clone());
                            put_lease(&tx, &ended).await?;
                        }
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "vault:delete",
                            &realm.id,
                            &resource(name_ref)?,
                            AuditOutcome::Allow,
                            false,
                            Some(meta(vec![
                                ("name", string(name_ref.clone())),
                                ("recoveryDays", number(days)),
                                ("deletionAt", number(deletion_at)),
                            ])),
                        )
                        .await?;
                    *scheduled.lock().unwrap_or_else(|e| e.into_inner()) =
                        Some((stored.id.clone(), deletion_at));
                    Ok(json!({
                        "secretId": stored.id,
                        "tenantId": realm.id,
                        "deletionAt": number(deletion_at),
                    }))
                })
            },
        );
        self.operation(
            credential,
            input.get("tenantId"),
            "iam:vault:manage",
            &resource(&name)?,
            mutation,
        )
        .await?;
        let (secret_id, deletion_at) = slot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(crate::js::internal_error)?;
        if days == 0.0 {
            purge_secret(ctx, &secret_id).await?;
            return Ok(Reply::json(json!({
                "name": name,
                "status": "deleted",
                "deletionAt": number(deletion_at),
            })));
        }
        Ok(Reply::json(json!({
            "name": name,
            "status": "pending-deletion",
            "deletionAt": number(deletion_at),
        })))
    }

    /// `vault/destroyVersion`: destroys a version's value for good (the record stays as history); stage labels on it
    /// are removed. The current version cannot be destroyed. Requires iam:vault:manage; audited as
    /// `vault:destroy-version`.
    pub async fn destroy_version(
        &self,
        credential: &CredentialInput,
        input: Body<vault::DestroyVersionInput>,
    ) -> IamResult<Reply<vault::DestroyVersionOutput>> {
        let ctx = &self.ctx;
        let name = secret_name(input.get("name"))?;
        let number_ = integer(
            input.get("version"),
            "version",
            1.0,
            core_js::MAX_SAFE_INTEGER,
        )?;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      tenant: realm,
                      principal,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let secret = static_secret(existing_secret(&tx, &realm.id, name_ref).await?)?;
                    let Some(version) = store_vault::version_of(&tx, &secret, number_).await?
                    else {
                        return Err(
                            IamError::with_status("NOT_FOUND", "Version not found", 404).into()
                        );
                    };
                    if secret.stages.get("current") == Some(&number_) {
                        return Err(IamError::new(
                        "INVALID_TRANSITION",
                        "The current version cannot be destroyed; promote another version first",
                    )
                    .into());
                    }
                    let mut destroyed = version.clone();
                    destroyed.sealed = None;
                    destroyed.state = "destroyed".into();
                    destroyed.destroyed_at = Some(ctx.now());
                    let next: VaultVersion =
                        decode(tx.put(col("versions"), &record(&destroyed)).await?)?;
                    let mut updated = secret.clone();
                    updated.stages = secret
                        .stages
                        .iter()
                        .filter(|(_, value)| **value != number_)
                        .map(|(label, value)| (label.clone(), *value))
                        .collect();
                    updated.updated_at = ctx.now();
                    updated.updated_by = principal.identity.id.clone();
                    let stored = put_secret(&tx, &updated).await?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "vault:destroy-version",
                            &realm.id,
                            &resource(name_ref)?,
                            AuditOutcome::Allow,
                            false,
                            Some(meta(vec![
                                ("name", string(name_ref.clone())),
                                ("version", number(number_)),
                            ])),
                        )
                        .await?;
                    Ok(version_view(&stored, &next))
                })
            },
        );
        let result = self
            .operation(
                credential,
                input.get("tenantId"),
                "iam:vault:manage",
                &resource(&name)?,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `vault/generate`: a value from a generator without storing it (a password for a form, say): `length` 8-256,
    /// `charset` (alphanumeric, ascii, hex, base64url, numeric), `exclude`, `eachClass`. Needs only a session.
    pub async fn generate(
        &self,
        credential: &CredentialInput,
        input: Body<vault::GenerateInput>,
    ) -> IamResult<Reply<vault::GenerateOutput>> {
        self.ctx.principals()?.authenticate(credential).await?;
        let value =
            store_vault::generate_value(&store_vault::password_generator(input.get("generator"))?)?;
        Ok(Reply::json(json!({ "value": value })))
    }

    /// `vault/get`: a secret's metadata and live check-outs. Requires iam:vault:read.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<vault::GetInput>,
    ) -> IamResult<Reply<vault::GetOutput>> {
        let ctx = &self.ctx;
        let name = secret_name(input.get("name"))?;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx, tenant: realm, ..
                  }| {
                Box::pin(async move {
                    let secret = existing_secret(&tx, &realm.id, name_ref).await?;
                    Ok(views(ctx, &tx, &secret).await?)
                })
            },
        );
        let result = self
            .operation(
                credential,
                input.get("tenantId"),
                "iam:vault:read",
                &resource(&name)?,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `vault/lease`: a dynamic secret's credential, minted by its engine for the caller with a lease of `ttlMs`
    /// (default and maximum from the secret's `lease` settings). The value is returned once and never stored; the lease
    /// is revoked at the engine by `revokeLease`, or by `iam.vault.expireLeases` once it expires. Engine failures fail
    /// with ENGINE_FAILED (502). Refused while viewing as another member. Requires iam:vault:lease; audited as
    /// `vault:lease`.
    pub async fn lease(
        &self,
        credential: &CredentialInput,
        input: Body<vault::LeaseInput>,
    ) -> IamResult<Reply<vault::LeaseOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let name = secret_name(input.get("name"))?;
        let name_ref = &name;
        type Issuing = (VaultLease, VaultSecret, Value, f64, AuthenticatedPrincipal);
        let slot: Arc<Mutex<Option<Issuing>>> = Arc::default();
        let issuing = slot.clone();
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      tenant: realm,
                      principal,
                  }| {
                Box::pin(async move {
                    refuse_impersonation(&principal)?;
                    let secret = active_secret(existing_secret(&tx, &realm.id, name_ref).await?)?;
                    if secret.kind != "dynamic" {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "Static secrets are revealed or checked out, not leased",
                        )
                        .into());
                    }
                    let lease = match &secret.lease {
                        Some(lease) => lease.clone(),
                        None => store_vault::lease_settings(None, None)?,
                    };
                    let ttl = match body.get("ttlMs") {
                        None => lease.default_ttl_ms,
                        Some(value) => integer(Some(value), "ttlMs", MINUTE, lease.max_ttl_ms)?,
                    };
                    let now = ctx.now();
                    let mut fresh = meta(vec![
                        ("id", string(id())),
                        ("tenantId", string(realm.id.clone())),
                        ("secretId", string(secret.id.clone())),
                        ("name", string(name_ref.clone())),
                        ("kind", string("dynamic")),
                        ("holderId", string(principal.identity.id.clone())),
                        ("sessionId", string(principal.session.id.clone())),
                    ]);
                    lease_actor(&principal, &mut fresh);
                    fresh.insert("state".into(), string("issuing"));
                    fresh.insert("issuedAt".into(), number(now));
                    fresh.insert("expiresAt".into(), number(now + ttl));
                    fresh.insert("maxExpiresAt".into(), number(now + lease.max_ttl_ms));
                    fresh.insert("ttlMs".into(), number(ttl));
                    tx.insert(col("leases"), &fresh).await?;
                    let mut holder = meta(vec![
                        ("id", string(principal.identity.id.clone())),
                        ("kind", json_of(&principal.identity.kind)),
                        ("name", string(principal.identity.name.clone())),
                    ]);
                    if let Some(email) = principal
                        .identity
                        .email
                        .as_deref()
                        .filter(|e| !e.is_empty())
                    {
                        holder.insert("email".into(), string(email));
                    }
                    let holder = Value::Object(holder);
                    let answer = json!({
                        "lease": Value::Object(fresh.clone()),
                        "secret": Value::Object(record(&secret)),
                        "holder": holder,
                        "ttl": number(ttl),
                    });
                    let lease_record: VaultLease = decode(fresh)?;
                    *issuing.lock().unwrap_or_else(|e| e.into_inner()) =
                        Some((lease_record, secret, holder, ttl, principal.clone()));
                    Ok(answer)
                })
            },
        );
        self.operation(
            credential,
            input.get("tenantId"),
            "iam:vault:lease",
            &resource(&name)?,
            mutation,
        )
        .await?;
        let (lease, secret, holder, ttl, caller) = slot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(crate::js::internal_error)?;
        let vault = settings(ctx)?;
        let engine_name = secret.engine.clone().unwrap_or_else(|| "undefined".into());
        let engine = vault.engines.get(&engine_name).cloned();
        let mut raw: Option<Value> = None;
        let mut issued: Option<(String, Option<String>)> = None;
        let mut failure: Option<String> = None;
        match &engine {
            None => failure = Some(format!("The engine {engine_name} is not configured")),
            Some(engine) => {
                let input = json!({
                    "tenantId": lease.tenant_id,
                    "name": name,
                    "leaseId": lease.id,
                    "config": secret.engine_config.clone().unwrap_or_else(|| json!({})),
                    "ttlMs": number(ttl),
                    "holder": holder,
                });
                let engine = engine.clone();
                let call: Callback = Arc::new(move |_| {
                    let (engine, input) = (engine.clone(), input.clone());
                    Box::pin(async move { engine.issue(input).await })
                });
                let attempt = match timed(ctx, &format!("The engine {engine_name}"), call).await {
                    Ok(value) => {
                        raw = Some(value.clone());
                        issued_value(&vault, &secret.format, &value)
                    }
                    Err(error) => Err(error.message),
                };
                match attempt {
                    Ok(value) => issued = Some(value),
                    Err(message) => {
                        let member = |key: &str| {
                            raw.as_ref()
                                .and_then(Value::as_object)
                                .and_then(|map| map.get(key))
                        };
                        let raw_value = member("value").and_then(Value::as_str).map(str::to_owned);
                        let raw_fields = member("fields")
                            .filter(|fields| truthy(Some(fields)))
                            .map(core_js::stringify);
                        failure = Some(redacted(&message, &[raw_value, raw_fields])?);
                    }
                }
            }
        }
        // Once `issue` was called, a credential may exist even when the call failed or timed out: such leases are
        // revoked at the engine by id (with the handle when one came back), and retried until the engine confirms.
        let handle = raw
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|map| map.get("handle"))
            .and_then(Value::as_str)
            .filter(|handle| utf16_len(handle) <= 4096)
            .map(str::to_owned);
        let recorder = Recorder::principal(&caller, &lease.tenant_id, &name);
        let has_engine = engine.is_some();
        let (lease_ref, secret_ref, failure_ref, issued_ref, handle_ref, recorder_ref, caller_ref) = (
            &lease, &secret, &failure, &issued, &handle, &recorder, &caller,
        );
        let stored = ctx
            .store
            .transaction(|tx| async move {
                let current = get_lease(&tx, &lease_ref.id).await?;
                let live = current
                    .as_ref()
                    .filter(|current| current.state == "issuing");
                let (Some(current), None, Some(issued)) = (live, failure_ref, issued_ref) else {
                    if let Some(current) = &current {
                        let mut ended = current.clone();
                        ended.state = if has_engine { "revoking" } else { "failed" }.into();
                        ended.ended_at = Some(ctx.now());
                        ended.ended_by = Some(
                            current
                                .ended_by
                                .clone()
                                .unwrap_or_else(|| VAULT_OPERATOR.to_owned()),
                        );
                        if has_engine {
                            ended.end_state = Some(
                                if failure_ref.is_some() {
                                    "failed"
                                } else {
                                    "ended"
                                }
                                .into(),
                            );
                        }
                        if let Some(handle) = handle_ref {
                            ended.handle_sealed = Some(store_vault::seal_value(
                                ctx,
                                handle,
                                &store_vault::lease_handle_context(&current.id)?,
                            )?);
                        }
                        ended.last_error =
                            Some(failure_ref.clone().unwrap_or_else(|| {
                                "The lease was ended while it was issued".into()
                            }));
                        put_lease(&tx, &ended).await?;
                    }
                    recorder_ref
                        .record(
                            ctx,
                            &tx,
                            "vault:lease",
                            AuditOutcome::Deny,
                            meta(vec![
                                ("name", string(lease_ref.name.clone())),
                                ("leaseId", string(lease_ref.id.clone())),
                                (
                                    "error",
                                    string(
                                        failure_ref
                                            .clone()
                                            .unwrap_or_else(|| "ended while issuing".into()),
                                    ),
                                ),
                            ]),
                        )
                        .await?;
                    return Ok(None);
                };
                let mut next = current.clone();
                next.state = "active".into();
                if let Some(handle) = &issued.1 {
                    next.handle_sealed = Some(store_vault::seal_value(
                        ctx,
                        handle,
                        &store_vault::lease_handle_context(&current.id)?,
                    )?);
                }
                put_lease(&tx, &next).await?;
                store_vault::record_access(
                    ctx,
                    &tx,
                    secret_ref,
                    &access(caller_ref, "lease", None, Some(&current.id)),
                )
                .await?;
                recorder_ref
                    .record(
                        ctx,
                        &tx,
                        "vault:lease",
                        AuditOutcome::Allow,
                        meta(vec![
                            ("name", string(lease_ref.name.clone())),
                            ("leaseId", string(current.id.clone())),
                            ("expiresAt", number(current.expires_at)),
                        ]),
                    )
                    .await?;
                Ok(Some(next))
            })
            .await?;
        let Some(stored) = stored else {
            // Take back whatever the engine may have minted now; a refusal is retried by iam.vault.expireLeases.
            if has_engine {
                let _ = revoke_and_record(ctx, &lease.id).await?;
            }
            return Err(IamError::with_status(
                "ENGINE_FAILED",
                failure.unwrap_or_else(|| "The lease was ended while it was issued".into()),
                502,
            ));
        };
        let value = issued.map(|issued| issued.0).unwrap_or_default();
        let mut out = meta(vec![
            ("leaseId", string(stored.id.clone())),
            ("name", string(name.clone())),
            ("format", secret.format.clone()),
            ("value", string(value.clone())),
        ]);
        if is_json(&secret.format) {
            out.insert(
                "fields".into(),
                fields_json(&store_vault::parse_fields(&value)?),
            );
        }
        out.insert("issuedAt".into(), number(stored.issued_at));
        out.insert("expiresAt".into(), number(stored.expires_at));
        out.insert("maxExpiresAt".into(), number(stored.max_expires_at));
        out.insert(
            "renewable".into(),
            Value::Bool(stored.expires_at < stored.max_expires_at),
        );
        Ok(Reply::json(Value::Object(out)))
    }

    /// `vault/list`: the secrets the caller may read (`iam:vault:read` on each), sorted by name: optionally under
    /// `prefix`, with all of `tags`, and by `status` (default `active`; `all` includes pending deletions). At most
    /// `limit` (1-500, default 100) from `offset`, with the `total` the caller may see. Needs only a session of the
    /// tenant; the listing itself is not audited.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<vault::ListInput>,
    ) -> IamResult<Reply<vault::ListOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let prefix = store_vault::secret_prefix(input.get("prefix"))?;
        let tags = match input.get("tags") {
            None => IndexMap::new(),
            Some(tags) => store_vault::secret_tags(Some(tags))?,
        };
        let status = match input.get("status") {
            None | Some(Value::Null) => "active".to_owned(),
            Some(Value::String(status))
                if ["active", "pending-deletion", "all"].contains(&status.as_str()) =>
            {
                status.clone()
            }
            Some(_) => {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "status must be active, pending-deletion or all",
                ));
            }
        };
        let limit = match input.get("limit") {
            None => 100.0,
            Some(value) => integer(Some(value), "limit", 1.0, 500.0)?,
        };
        let offset = match input.get("offset") {
            None => 0.0,
            Some(value) => integer(Some(value), "offset", 0.0, 1_000_000.0)?,
        };
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let (tenant_id, prefix, tags, status, authenticated) =
            (&tenant_id, &prefix, &tags, &status, &authenticated);
        let result = ctx
            .store
            .transaction(|tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, authenticated)
                    .await?;
                let realm = ctx.tenant(&tx, tenant_id).await?;
                let prepared = ctx
                    .decisions()?
                    .prepare_decision(&tx, &principal, &realm, "iam:vault:read")
                    .await?;
                let actor = impersonating_actor(&tx, &principal).await?;
                let own = match &actor {
                    Some(actor) => Some(
                        ctx.decisions()?
                            .prepare_decision(&tx, actor, &realm, "iam:vault:read")
                            .await?,
                    ),
                    None => None,
                };
                let allows = |evaluator: &crate::contracts::PreparedDecision,
                              secret: &VaultSecret|
                 -> IamResult<bool> {
                    let attributes: Map<String, Value> = store_vault::secret_attributes(secret)?
                        .into_iter()
                        .collect();
                    Ok(decide_on(
                        evaluator,
                        &ResolvedResource {
                            tenant_id: realm.id.clone(),
                            kind: "iam".into(),
                            id: resource(&secret.name)?,
                            attributes: Some(attributes),
                            classification: None,
                        },
                        None,
                    )?
                    .allowed)
                };
                let mut candidates = Vec::new();
                for raw in tx
                    .find(
                        col("secrets"),
                        &Filter::new().eq("tenantId", realm.id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    let secret: VaultSecret = decode(raw)?;
                    if (status == "all" || secret.status == *status)
                        && secret.name.starts_with(prefix.as_str())
                        && tags
                            .iter()
                            .all(|(key, value)| secret.tags.get(key) == Some(value))
                    {
                        candidates.push(secret);
                    }
                }
                let mut visible = Vec::new();
                for secret in candidates {
                    if allows(&prepared, &secret)?
                        && match &own {
                            None => true,
                            Some(own) => allows(own, &secret)?,
                        }
                    {
                        visible.push(secret);
                    }
                }
                visible.sort_by(|a, b| a.name.cmp(&b.name));
                let mut page = Vec::new();
                for secret in visible.iter().skip(offset as usize).take(limit as usize) {
                    page.push(views(ctx, &tx, secret).await?);
                }
                Ok(json!({ "secrets": page, "total": number(visible.len() as f64) }))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `vault/listLeases`: a secret's leases and check-outs, newest first: live ones, or all kept history with
    /// `includeEnded`. Requires iam:vault:read.
    pub async fn list_leases(
        &self,
        credential: &CredentialInput,
        input: Body<vault::ListLeasesInput>,
    ) -> IamResult<Reply<vault::ListLeasesOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let name = secret_name(input.get("name"))?;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx, tenant: realm, ..
                  }| {
                Box::pin(async move {
                    let secret = existing_secret(&tx, &realm.id, name_ref).await?;
                    let now = ctx.now();
                    let include_ended = body.get("includeEnded") == Some(&Value::Bool(true));
                    let mut leases = Vec::new();
                    for raw in tx
                        .find(
                            col("leases"),
                            &Filter::new()
                                .eq("tenantId", realm.id.clone())
                                .eq("secretId", secret.id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        let lease: VaultLease = decode(raw)?;
                        if include_ended
                            || (lease.state == "active" && lease.expires_at > now)
                            || lease.state == "revoking"
                        {
                            leases.push(lease);
                        }
                    }
                    leases.sort_by(|a, b| {
                        b.issued_at
                            .partial_cmp(&a.issued_at)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    });
                    let holders: Vec<String> =
                        leases.iter().map(|lease| lease.holder_id.clone()).collect();
                    let names = identity_names(&tx, holders).await?;
                    Ok(Value::Array(
                        leases
                            .iter()
                            .map(|lease| {
                                lease_view(lease, names.get(&lease.holder_id).map(String::as_str))
                            })
                            .collect(),
                    ))
                })
            },
        );
        let result = self
            .operation(
                credential,
                input.get("tenantId"),
                "iam:vault:read",
                &resource(&name)?,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `vault/listMine`: the caller's own live check-outs and leases in the tenant. Needs only a session of the
    /// tenant.
    pub async fn list_mine(
        &self,
        credential: &CredentialInput,
        input: Body<vault::ListMineInput>,
    ) -> IamResult<Reply<vault::ListMineOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let (tenant_id, authenticated) = (&tenant_id, &authenticated);
        let result = ctx
            .store
            .transaction(|tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, authenticated)
                    .await?;
                ctx.tenant(&tx, tenant_id).await?;
                let now = ctx.now();
                let mut leases = Vec::new();
                for raw in tx
                    .find(
                        col("leases"),
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("holderId", principal.identity.id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    let lease: VaultLease = decode(raw)?;
                    if lease.state == "active" && lease.expires_at > now {
                        leases.push(lease);
                    }
                }
                leases.sort_by(|a, b| {
                    b.issued_at
                        .partial_cmp(&a.issued_at)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                Ok(Value::Array(
                    leases
                        .iter()
                        .map(|lease| lease_view(lease, Some(&principal.identity.name)))
                        .collect(),
                ))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `vault/listVersions`: every kept version, newest first, with its state and stage labels. Requires
    /// iam:vault:read.
    pub async fn list_versions(
        &self,
        credential: &CredentialInput,
        input: Body<vault::ListVersionsInput>,
    ) -> IamResult<Reply<vault::ListVersionsOutput>> {
        let name = secret_name(input.get("name"))?;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx, tenant: realm, ..
                  }| {
                Box::pin(async move {
                    let secret = existing_secret(&tx, &realm.id, name_ref).await?;
                    Ok(Value::Array(
                        store_vault::secret_versions(&tx, &secret)
                            .await?
                            .iter()
                            .map(|version| version_view(&secret, version))
                            .collect(),
                    ))
                })
            },
        );
        let result = self
            .operation(
                credential,
                input.get("tenantId"),
                "iam:vault:read",
                &resource(&name)?,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `vault/promote`: makes an enabled version `current` (the old one becomes `previous`); rolls back as well as
    /// forward. Requires iam:vault:write; audited as `vault:promote`.
    pub async fn promote(
        &self,
        credential: &CredentialInput,
        input: Body<vault::PromoteInput>,
    ) -> IamResult<Reply<vault::PromoteOutput>> {
        let ctx = &self.ctx;
        let name = secret_name(input.get("name"))?;
        let number_ = integer(
            input.get("version"),
            "version",
            1.0,
            core_js::MAX_SAFE_INTEGER,
        )?;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      tenant: realm,
                      principal,
                  }| {
                Box::pin(async move {
                    writable(&realm)?;
                    let secret = static_secret(active_secret(
                        existing_secret(&tx, &realm.id, name_ref).await?,
                    )?)?;
                    let Some(version) = store_vault::version_of(&tx, &secret, number_).await?
                    else {
                        return Err(
                            IamError::with_status("NOT_FOUND", "Version not found", 404).into()
                        );
                    };
                    if version.state != "enabled" {
                        return Err(IamError::with_status(
                            "VERSION_DISABLED",
                            "Only enabled versions can become current",
                            409,
                        )
                        .into());
                    }
                    let stored = store_vault::promote_version(
                        ctx,
                        &tx,
                        &secret,
                        number_,
                        &principal.identity.id,
                        None,
                    )
                    .await?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "vault:promote",
                            &realm.id,
                            &resource(name_ref)?,
                            AuditOutcome::Allow,
                            false,
                            Some(meta(vec![
                                ("name", string(name_ref.clone())),
                                ("version", number(number_)),
                                (
                                    "previous",
                                    secret
                                        .stages
                                        .get("current")
                                        .map(|current| number(*current))
                                        .unwrap_or(Value::Null),
                                ),
                            ])),
                        )
                        .await?;
                    Ok(views(ctx, &tx, &stored).await?)
                })
            },
        );
        let result = self
            .operation(
                credential,
                input.get("tenantId"),
                "iam:vault:write",
                &resource(&name)?,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `vault/put`: stores a new version (`value`, `fields` for json secrets, or `generate`). It becomes `current`
    /// (the old one `previous`) unless `stage` names another label: `pending` stages it for a later `promote` or
    /// `rotate`, any custom label just points at it. Versions past `maxVersions` that no stage names are deleted.
    /// Requires iam:vault:write; audited as `vault:put`.
    pub async fn put(
        &self,
        credential: &CredentialInput,
        input: Body<vault::PutInput>,
    ) -> IamResult<Reply<vault::PutOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let name = secret_name(input.get("name"))?;
        let stage = match input.get("stage") {
            None => "current".to_owned(),
            Some(stage) => store_vault::stage_name(Some(stage))?,
        };
        if stage == "previous" {
            return Err(IamError::new(
                "INVALID_INPUT",
                "previous moves by itself when a version becomes current",
            ));
        }
        let (name_ref, stage_ref) = (&name, &stage);
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      tenant: realm,
                      principal,
                  }| {
                Box::pin(async move {
                    writable(&realm)?;
                    let mut secret = static_secret(active_secret(
                        existing_secret(&tx, &realm.id, name_ref).await?,
                    )?)?;
                    let generate = truthy(body.get("generate"));
                    // Generating into a json secret reads its current fields, which is a decryption as well.
                    let actions: &[&str] = if generate && is_json(&secret.format) {
                        &["iam:kms:encrypt", "iam:kms:decrypt"]
                    } else {
                        &["iam:kms:encrypt"]
                    };
                    require_secret_key(ctx, &tx, &principal, &realm, &secret, actions).await?;
                    let use_ = value_use(&principal);
                    let value = if generate {
                        if body.get("value").is_some() || body.get("fields").is_some() {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "Pass a value or generate, not both",
                            )
                            .into());
                        }
                        let generated = store_vault::generate_value(
                            &store_vault::password_generator(body.get("generate"))?,
                        )?;
                        if is_json(&secret.format) {
                            let Some(field) = rotation_field(&secret) else {
                                return Err(IamError::new(
                                    "INVALID_INPUT",
                                    "json secrets generate into rotation.field",
                                )
                                .into());
                            };
                            let current = match secret.stages.get("current") {
                                Some(number) => {
                                    store_vault::version_of(&tx, &secret, *number).await?
                                }
                                None => None,
                            };
                            let mut fields = match &current {
                                Some(current) if current.state == "enabled" => {
                                    store_vault::parse_fields(
                                        &store_vault::open_version(ctx, &tx, current, Some(&use_))
                                            .await?,
                                    )?
                                }
                                _ => IndexMap::new(),
                            };
                            fields.insert(field, string(generated));
                            core_js::stringify(&fields_json(&fields))
                        } else {
                            generated
                        }
                    } else {
                        store_vault::secret_value(
                            &settings(ctx)?.raw,
                            &secret.format,
                            &body.value(),
                        )?
                    };
                    let (added_secret, added_version) = add_version(
                        ctx,
                        &tx,
                        &secret,
                        &value,
                        if generate { "generated" } else { "put" },
                        &principal.identity.id,
                        Some(&use_),
                    )
                    .await?;
                    if stage_ref == "current" {
                        secret = store_vault::promote_version(
                            ctx,
                            &tx,
                            &added_secret,
                            added_version.version,
                            &principal.identity.id,
                            None,
                        )
                        .await?;
                    } else {
                        let mut stages = added_secret.stages.clone();
                        stages.insert(stage_ref.clone(), added_version.version);
                        if custom_labels(&stages) > 8 {
                            return Err(IamError::with_status(
                                "LIMIT_EXCEEDED",
                                "A secret has at most 8 custom stage labels",
                                409,
                            )
                            .into());
                        }
                        let mut next = added_secret.clone();
                        next.stages = stages;
                        next.updated_at = ctx.now();
                        next.updated_by = principal.identity.id.clone();
                        secret = put_secret(&tx, &next).await?;
                        store_vault::prune_versions(&tx, &secret).await?;
                    }
                    store_vault::record_access(
                        ctx,
                        &tx,
                        &secret,
                        &access(&principal, "put", Some(added_version.version), None),
                    )
                    .await?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "vault:put",
                            &realm.id,
                            &resource(name_ref)?,
                            AuditOutcome::Allow,
                            false,
                            Some(meta(vec![
                                ("name", string(name_ref.clone())),
                                ("version", number(added_version.version)),
                                ("stage", string(stage_ref.clone())),
                            ])),
                        )
                        .await?;
                    Ok(version_view(&secret, &added_version))
                })
            },
        );
        let result = self
            .operation(
                credential,
                input.get("tenantId"),
                "iam:vault:write",
                &resource(&name)?,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `vault/renewLease`: extends a live check-out or dynamic lease by `ttlMs` from now (default: its original
    /// length), never past its `maxExpiresAt`; a dynamic lease's engine is told through `renew` when it has one.
    /// Holder only. Audited as `vault:renew`.
    pub async fn renew_lease(
        &self,
        credential: &CredentialInput,
        input: Body<vault::RenewLeaseInput>,
    ) -> IamResult<Reply<vault::RenewLeaseOutput>> {
        let ctx = &self.ctx;
        let LeaseOutcome::Renew {
            result,
            lease,
            secret,
            ttl,
        } = self.on_lease(credential, &input, LeaseVerb::Renew).await?
        else {
            return Err(crate::js::internal_error());
        };
        let vault = settings(ctx)?;
        let engine = secret
            .as_ref()
            .and_then(|secret| secret.engine.as_ref())
            .filter(|name| !name.is_empty())
            .and_then(|name| vault.engines.get(name).cloned());
        if let Some(engine) = engine.filter(|engine| lease.kind == "dynamic" && engine.has_renew())
        {
            let secret = secret.as_deref();
            let handle = match &lease.handle_sealed {
                Some(sealed) if !sealed.is_empty() => Some(store_vault::open_value(
                    ctx,
                    sealed,
                    &store_vault::lease_handle_context(&lease.id)?,
                )?),
                _ => None,
            };
            let mut call_input = meta(vec![
                ("tenantId", string(lease.tenant_id.clone())),
                ("name", string(lease.name.clone())),
                ("leaseId", string(lease.id.clone())),
                (
                    "config",
                    secret
                        .and_then(|secret| secret.engine_config.clone())
                        .unwrap_or_else(|| json!({})),
                ),
                ("ttlMs", number(ttl)),
            ]);
            if let Some(handle) = &handle {
                call_input.insert("handle".into(), string(handle.clone()));
            }
            let call_input = Value::Object(call_input);
            let call: Callback = Arc::new(move |_| {
                let (engine, input) = (engine.clone(), call_input.clone());
                Box::pin(async move { engine.renew(input).await.map(|()| Value::Null) })
            });
            let what = format!(
                "The engine {}",
                secret
                    .and_then(|secret| secret.engine.clone())
                    .unwrap_or_default()
            );
            if let Err(error) = timed(ctx, &what, call).await {
                return Err(IamError::with_status(
                    "ENGINE_FAILED",
                    redacted(&error.message, &[handle])?,
                    502,
                ));
            }
        }
        Ok(Reply::json(result))
    }

    /// `vault/restore`: cancels a scheduled deletion. Requires iam:vault:manage; audited as `vault:restore`.
    pub async fn restore(
        &self,
        credential: &CredentialInput,
        input: Body<vault::RestoreInput>,
    ) -> IamResult<Reply<vault::RestoreOutput>> {
        let ctx = &self.ctx;
        let name = secret_name(input.get("name"))?;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      tenant: realm,
                      principal,
                  }| {
                Box::pin(async move {
                    writable(&realm)?;
                    let secret = existing_secret(&tx, &realm.id, name_ref).await?;
                    if secret.status != "pending-deletion" {
                        return Err(IamError::new(
                            "INVALID_TRANSITION",
                            "This secret is not scheduled for deletion",
                        )
                        .into());
                    }
                    let mut next = secret.clone();
                    next.deletion_at = None;
                    next.deletion_requested_by = None;
                    next.status = "active".into();
                    next.updated_at = ctx.now();
                    next.updated_by = principal.identity.id.clone();
                    let stored = put_secret(&tx, &next).await?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "vault:restore",
                            &realm.id,
                            &resource(name_ref)?,
                            AuditOutcome::Allow,
                            false,
                            Some(meta(vec![("name", string(name_ref.clone()))])),
                        )
                        .await?;
                    Ok(views(ctx, &tx, &stored).await?)
                })
            },
        );
        let result = self
            .operation(
                credential,
                input.get("tenantId"),
                "iam:vault:manage",
                &resource(&name)?,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `vault/reveal`: a secret's value: the `current` version, or `version` / `stage`. Refused while viewing as
    /// another member, for dynamic secrets (use `lease`), for disabled (VERSION_DISABLED) and destroyed
    /// (VERSION_DESTROYED) versions, and with CHECKOUT_REQUIRED when the secret is handed out only through check-outs
    /// (the holder of a live check-out may reveal the version they checked out). Requires iam:vault:reveal; audited as
    /// `vault:reveal`.
    pub async fn reveal(
        &self,
        credential: &CredentialInput,
        input: Body<vault::RevealInput>,
    ) -> IamResult<Reply<vault::RevealOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let name = secret_name(input.get("name"))?;
        let name_ref = &name;
        let result = self
            .value_operation(
                credential,
                input.get("tenantId"),
                "iam:vault:reveal",
                &resource(&name)?,
                Box::new(move |MutationContext { tx, tenant: realm, principal }| {
                    Box::pin(async move {
                        refuse_impersonation(&principal)?;
                        let secret = static_secret(active_secret(
                            existing_secret(&tx, &realm.id, name_ref).await?,
                        )?)?;
                        require_secret_key(ctx, &tx, &principal, &realm, &secret, &["iam:kms:decrypt"])
                            .await?;
                        let mut version =
                            store_vault::select_version(&tx, &secret, &body.value()).await?;
                        if secret.checkout.as_ref().is_some_and(|policy| policy.required) {
                            let live = store_vault::live_leases(ctx, &tx, &secret).await?;
                            let Some(held) = live.iter().find(|lease| {
                                lease.kind == "checkout" && lease.holder_id == principal.identity.id
                            }) else {
                                return Err(IamError::with_status(
                                    "CHECKOUT_REQUIRED",
                                    "This secret is handed out only through check-outs (vault.checkout)",
                                    409,
                                )
                                .into());
                            };
                            if body.get("version").is_none()
                                && body.get("stage").is_none()
                                && let Some(held_version) = held.version
                                && let Some(found) =
                                    store_vault::version_of(&tx, &secret, held_version).await?
                            {
                                version = found;
                            }
                            if Some(version.version) != held.version {
                                return Err(IamError::with_status(
                                    "CHECKOUT_REQUIRED",
                                    "A check-out reveals only the version it handed out",
                                    409,
                                )
                                .into());
                            }
                        }
                        let use_ = value_use(&principal);
                        let value =
                            store_vault::open_version(ctx, &tx, &version, Some(&use_)).await?;
                        store_vault::record_access(
                            ctx,
                            &tx,
                            &secret,
                            &access(&principal, "reveal", Some(version.version), None),
                        )
                        .await?;
                        ctx.events()?
                            .audit(
                                &tx,
                                &principal,
                                "vault:reveal",
                                &realm.id,
                                &resource(name_ref)?,
                                AuditOutcome::Allow,
                                false,
                                Some(meta(vec![
                                    ("name", string(name_ref.clone())),
                                    ("version", number(version.version)),
                                ])),
                            )
                            .await?;
                        let shown = revealed(&secret, &version, value)?;
                        Ok((shown.answer(), shown.values()))
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `vault/revokeLease`: ends a lease now: a check-out is checked in (without rotation), a dynamic lease is revoked
    /// at its engine. Holder, or iam:vault:manage for anyone's. A revocation the engine refuses stays `revoking` and is
    /// retried by `iam.vault.expireLeases`. Audited as `vault:revoke`.
    pub async fn revoke_lease(
        &self,
        credential: &CredentialInput,
        input: Body<vault::RevokeLeaseInput>,
    ) -> IamResult<Reply<vault::RevokeLeaseOutput>> {
        let ctx = &self.ctx;
        let LeaseOutcome::Revoke { kind, lease, actor } =
            self.on_lease(credential, &input, LeaseVerb::Revoke).await?
        else {
            return Err(crate::js::internal_error());
        };
        if kind == "checkout" {
            // Ending someone's check-out is returning it: a secret that rotates on check-in rotates now too.
            let rotated = rotate_returned(
                ctx,
                &lease.tenant_id,
                &lease.secret_id,
                &actor.identity.id,
                &Recorder::principal(&actor, &lease.tenant_id, ""),
            )
            .await?;
            let mut out = meta(vec![
                ("leaseId", string(lease.id.clone())),
                ("state", string("ended")),
            ]);
            if let Some(version) = rotated {
                out.insert("rotated".into(), number(version));
            }
            return Ok(Reply::json(Value::Object(out)));
        }
        if kind == "issuing" {
            return Ok(Reply::json(
                json!({ "leaseId": lease.id, "state": "ended" }),
            ));
        }
        Ok(Reply::json(
            match revoke_and_record(ctx, &lease.id).await? {
                Ok(()) => json!({ "leaseId": lease.id, "state": "ended" }),
                Err(error) => json!({ "leaseId": lease.id, "state": "revoking", "error": error }),
            },
        ))
    }

    /// `vault/rotate`: rotates a static secret now: stages a new version as `pending` (generated, or `value` /
    /// `fields` when given), lets the secret's rotator apply it to the system it unlocks, then makes it current. A
    /// failing rotator leaves the pending version for the next attempt, records the error, and fails with
    /// ROTATION_FAILED (502). Requires iam:vault:rotate; audited as `vault:rotate` (outcome deny on failure).
    pub async fn rotate(
        &self,
        credential: &CredentialInput,
        input: Body<vault::RotateInput>,
    ) -> IamResult<Reply<vault::RotateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let name = secret_name(input.get("name"))?;
        let name_ref = &name;
        let slot: Arc<Mutex<Option<(StagedRotation, AuthenticatedPrincipal)>>> = Arc::default();
        let staging = slot.clone();
        self.value_operation(
            credential,
            input.get("tenantId"),
            "iam:vault:rotate",
            &resource(&name)?,
            Box::new(move |MutationContext { tx, tenant: realm, principal: caller }| {
                Box::pin(async move {
                    writable(&realm)?;
                    let secret = existing_secret(&tx, &realm.id, name_ref).await?;
                    if body.get("value").is_some() || body.get("fields").is_some() {
                        // A value the caller chooses is one they know, and the rotator makes it live: never for secrets
                        // that leave only through check-outs, and otherwise only for callers who may write and reveal
                        // it anyway.
                        if secret.checkout.as_ref().is_some_and(|policy| policy.required) {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "Secrets handed out only through check-outs rotate to generated values",
                            )
                            .into());
                        }
                        require_still(
                            ctx,
                            &tx,
                            &caller,
                            &realm,
                            name_ref,
                            "iam:vault:write",
                            "Rotating to a value you choose needs iam:vault:write on the secret",
                        )
                        .await?;
                        require_still(
                            ctx,
                            &tx,
                            &caller,
                            &realm,
                            name_ref,
                            "iam:vault:reveal",
                            "Rotating to a value you choose needs iam:vault:reveal on the secret",
                        )
                        .await?;
                    }
                    require_secret_key(
                        ctx,
                        &tx,
                        &caller,
                        &realm,
                        &secret,
                        &["iam:kms:encrypt", "iam:kms:decrypt"],
                    )
                    .await?;
                    let use_ = value_use(&caller);
                    let staged = stage_rotation(
                        ctx,
                        &tx,
                        &secret,
                        &caller.identity.id,
                        &body.value(),
                        Some(&use_),
                    )
                    .await?;
                    let split = (staged.answer(), staged.values());
                    *staging.lock().unwrap_or_else(|e| e.into_inner()) = Some((staged, caller));
                    Ok(split)
                })
            }),
        )
        .await?;
        let (staged, principal) = slot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(crate::js::internal_error)?;
        let outcome = complete_rotation(
            ctx,
            &staged,
            &principal.identity.id,
            &Recorder::principal(&principal, &staged.tenant_id, &name),
        )
        .await?;
        match outcome {
            RotationOutcome::Ok { result, .. } => Ok(Reply::json(result)),
            RotationOutcome::Failed(message) => {
                Err(IamError::with_status("ROTATION_FAILED", message, 502))
            }
        }
    }

    /// `vault/setStage`: points a custom stage label (or `pending`) at a version, or removes it with `version: null`.
    /// `current` and `previous` move only through `put`, `promote` and `rotate`. At most 8 custom labels. Requires
    /// iam:vault:write; audited as `vault:stage`.
    pub async fn set_stage(
        &self,
        credential: &CredentialInput,
        input: Body<vault::SetStageInput>,
    ) -> IamResult<Reply<vault::SetStageOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let name = secret_name(input.get("name"))?;
        let stage = store_vault::stage_name(input.get("stage"))?;
        if stage == "current" || stage == "previous" {
            return Err(IamError::new(
                "INVALID_INPUT",
                "Use promote to change the current version",
            ));
        }
        let (name_ref, stage_ref) = (&name, &stage);
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      tenant: realm,
                      principal,
                  }| {
                Box::pin(async move {
                    writable(&realm)?;
                    let secret = static_secret(active_secret(
                        existing_secret(&tx, &realm.id, name_ref).await?,
                    )?)?;
                    let mut stages = secret.stages.clone();
                    let removed = body.get("version") == Some(&Value::Null);
                    if removed {
                        stages.shift_remove(stage_ref);
                    } else {
                        let number_ = integer(
                            body.get("version"),
                            "version",
                            1.0,
                            core_js::MAX_SAFE_INTEGER,
                        )?;
                        let version = store_vault::version_of(&tx, &secret, number_).await?;
                        if !version.is_some_and(|version| version.state != "destroyed") {
                            return Err(IamError::with_status(
                                "NOT_FOUND",
                                "Version not found",
                                404,
                            )
                            .into());
                        }
                        stages.insert(stage_ref.clone(), number_);
                        if custom_labels(&stages) > 8 {
                            return Err(IamError::with_status(
                                "LIMIT_EXCEEDED",
                                "A secret has at most 8 custom stage labels",
                                409,
                            )
                            .into());
                        }
                    }
                    let mut next = secret.clone();
                    next.stages = stages.clone();
                    next.updated_at = ctx.now();
                    next.updated_by = principal.identity.id.clone();
                    let stored = put_secret(&tx, &next).await?;
                    store_vault::prune_versions(&tx, &stored).await?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "vault:stage",
                            &realm.id,
                            &resource(name_ref)?,
                            AuditOutcome::Allow,
                            false,
                            Some(meta(vec![
                                ("name", string(name_ref.clone())),
                                ("stage", string(stage_ref.clone())),
                                (
                                    "version",
                                    if removed {
                                        Value::Null
                                    } else {
                                        stages
                                            .get(stage_ref)
                                            .map(|version| number(*version))
                                            .unwrap_or(Value::Null)
                                    },
                                ),
                            ])),
                        )
                        .await?;
                    Ok(views(ctx, &tx, &stored).await?)
                })
            },
        );
        let result = self
            .operation(
                credential,
                input.get("tenantId"),
                "iam:vault:write",
                &resource(&name)?,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `vault/setVersionState`: disables a version (`state: 'disabled'`: kept, but not revealed) or enables it again.
    /// The current version cannot be disabled. Requires iam:vault:manage; audited as `vault:version-state`.
    pub async fn set_version_state(
        &self,
        credential: &CredentialInput,
        input: Body<vault::SetVersionStateInput>,
    ) -> IamResult<Reply<vault::SetVersionStateOutput>> {
        let ctx = &self.ctx;
        let name = secret_name(input.get("name"))?;
        let number_ = integer(
            input.get("version"),
            "version",
            1.0,
            core_js::MAX_SAFE_INTEGER,
        )?;
        let state = match input.get("state") {
            Some(Value::String(state)) if state == "enabled" || state == "disabled" => {
                state.clone()
            }
            _ => {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "state must be enabled or disabled",
                ));
            }
        };
        let (name_ref, state_ref) = (&name, &state);
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      tenant: realm,
                      principal,
                  }| {
                Box::pin(async move {
                    writable(&realm)?;
                    let secret = static_secret(existing_secret(&tx, &realm.id, name_ref).await?)?;
                    let Some(version) = store_vault::version_of(&tx, &secret, number_).await?
                    else {
                        return Err(
                            IamError::with_status("NOT_FOUND", "Version not found", 404).into()
                        );
                    };
                    if version.state == "destroyed" {
                        return Err(IamError::with_status(
                            "VERSION_DESTROYED",
                            "This version was destroyed",
                            410,
                        )
                        .into());
                    }
                    if state_ref == "disabled" && secret.stages.get("current") == Some(&number_) {
                        return Err(IamError::new(
                            "INVALID_TRANSITION",
                            "The current version cannot be disabled; promote another version first",
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let mut changed = version.clone();
                    changed.state = state_ref.clone();
                    changed.disabled_at = if state_ref == "disabled" {
                        Some(now)
                    } else {
                        None
                    };
                    let next: VaultVersion =
                        decode(tx.put(col("versions"), &record(&changed)).await?)?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "vault:version-state",
                            &realm.id,
                            &resource(name_ref)?,
                            AuditOutcome::Allow,
                            false,
                            Some(meta(vec![
                                ("name", string(name_ref.clone())),
                                ("version", number(number_)),
                                ("state", string(state_ref.clone())),
                            ])),
                        )
                        .await?;
                    Ok(version_view(&secret, &next))
                })
            },
        );
        let result = self
            .operation(
                credential,
                input.get("tenantId"),
                "iam:vault:manage",
                &resource(&name)?,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `vault/update`: changes a secret's settings: `description` (`null` clears), `tags` (replaced as a whole),
    /// `maxVersions`, `rotation` and `checkout` (`null` removes them), a dynamic secret's `engineConfig` and `lease`,
    /// and `kmsKey` (a customer-managed key to move the values under, every kept version re-encrypted, or `null` to
    /// move them back under the deployment secret). Values change through `put` and `rotate`. Requires
    /// iam:vault:manage; audited as `vault:update`.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<vault::UpdateInput>,
    ) -> IamResult<Reply<vault::UpdateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let name = secret_name(input.get("name"))?;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      tenant: realm,
                      principal,
                  }| {
                Box::pin(async move {
                    writable(&realm)?;
                    let secret = active_secret(existing_secret(&tx, &realm.id, name_ref).await?)?;
                    let before = reach(ctx, &tx, &principal, &realm, name_ref).await?;
                    let vault = settings(ctx)?;
                    let now = ctx.now();
                    let mut next = secret.clone();
                    next.description = None;
                    next.rotation = None;
                    next.checkout = None;
                    next.updated_at = now;
                    next.updated_by = principal.identity.id.clone();
                    match body.get("description") {
                        None => next.description = secret.description.clone(),
                        Some(Value::Null) => {}
                        Some(description) => {
                            next.description = Some(
                                core_js::trim(&text(Some(description), "description", 1024)?)
                                    .to_owned(),
                            );
                        }
                    }
                    if let Some(tags) = body.get("tags") {
                        next.tags = store_vault::secret_tags(Some(tags))?;
                    }
                    if let Some(value) = body.get("maxVersions") {
                        next.max_versions = max_versions(Some(value), 10.0)?;
                    }
                    if is_dynamic(&secret) {
                        if body.get("rotation").is_some() || body.get("checkout").is_some() {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "Dynamic secrets are not rotated or checked out",
                            )
                            .into());
                        }
                        if let Some(config) = body.get("engineConfig") {
                            next.engine_config = Some(store_vault::engine_config(Some(config))?);
                        }
                        if let Some(lease) = body.get("lease") {
                            next.lease = Some(store_vault::lease_settings(Some(lease), None)?);
                        }
                    } else {
                        if body.get("engineConfig").is_some() || body.get("lease").is_some() {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "engine settings are for dynamic secrets",
                            )
                            .into());
                        }
                        let rotation = store_vault::schedule_rotation(
                            store_vault::rotation_settings(
                                &vault.raw,
                                &secret.format,
                                body.get("rotation"),
                                secret.rotation.as_ref(),
                            )?
                            .as_ref(),
                            secret.created_at,
                            now,
                        )?;
                        if let Some(rotation) = rotation {
                            next.rotation = Some(js_value(rotation));
                        }
                        if let Some(checkout) = store_vault::checkout_policy(
                            body.get("checkout"),
                            secret.checkout.as_ref(),
                        )? {
                            next.checkout = Some(checkout);
                        }
                    }
                    let mut reencrypted = 0.0;
                    if let Some(reference) = body.get("kmsKey") {
                        if is_dynamic(&secret) {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "Dynamic secrets store no values to encrypt",
                            )
                            .into());
                        }
                        let mut target = next.clone();
                        target.kms_key_id = None;
                        if !reference.is_null() {
                            target.kms_key_id = Some(
                                usable_key(ctx, &tx, &principal, &realm, Some(reference)).await?,
                            );
                        }
                        if target.kms_key_id != secret.kms_key_id {
                            // Taking values out from under a customer-managed key is a decryption with it.
                            if let Some(previous) = &secret.kms_key_id {
                                require_key_action(
                                    ctx,
                                    &tx,
                                    &principal,
                                    &realm,
                                    previous,
                                    "iam:kms:decrypt",
                                )
                                .await?;
                            }
                            let use_ = value_use(&principal);
                            let target_value = Value::Object(record(&target));
                            for version in store_vault::secret_versions(&tx, &secret).await? {
                                if version.sealed.is_none() {
                                    continue;
                                }
                                let value =
                                    store_vault::open_stored(ctx, &tx, &version, Some(&use_))
                                        .await?;
                                let encrypted = store_vault::encrypt_version(
                                    ctx,
                                    &tx,
                                    &target_value,
                                    &version,
                                    &value,
                                    &use_,
                                )
                                .await?;
                                tx.put(col("versions"), &record(&encrypted)).await?;
                                reencrypted += 1.0;
                            }
                        }
                        next = target;
                    }
                    checkout_fits(&next)?;
                    let stored = put_secret(&tx, &next).await?;
                    // New tags and settings are new attributes: the caller must still be allowed to manage the secret
                    // with them, and may not gain any other action on it by the change.
                    require_still(
                        ctx,
                        &tx,
                        &principal,
                        &realm,
                        name_ref,
                        "iam:vault:manage",
                        "The change puts the secret outside what you may manage",
                    )
                    .await?;
                    require_no_wider(ctx, &tx, &principal, &realm, name_ref, &before).await?;
                    store_vault::prune_versions(&tx, &stored).await?;
                    let mut metadata = meta(vec![
                        ("name", string(name_ref.clone())),
                        ("tags", tags_json(&stored.tags)),
                        ("maxVersions", number(stored.max_versions)),
                        (
                            "rotation",
                            rotation_member(&stored, "intervalDays")
                                .cloned()
                                .map(js_value)
                                .unwrap_or(Value::Null),
                        ),
                        (
                            "rotator",
                            rotation_member(&stored, "rotator")
                                .cloned()
                                .unwrap_or(Value::Null),
                        ),
                        ("checkout", Value::Bool(stored.checkout.is_some())),
                        (
                            "kmsKeyId",
                            stored
                                .kms_key_id
                                .clone()
                                .map(Value::String)
                                .unwrap_or(Value::Null),
                        ),
                    ]);
                    if reencrypted != 0.0 {
                        metadata.insert("reencrypted".into(), number(reencrypted));
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "vault:update",
                            &realm.id,
                            &resource(name_ref)?,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(views(ctx, &tx, &stored).await?)
                })
            },
        );
        let result = self
            .operation(
                credential,
                input.get("tenantId"),
                "iam:vault:manage",
                &resource(&name)?,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// Stage labels that are not the vault's own.
fn custom_labels(stages: &IndexMap<String, f64>) -> usize {
    stages
        .keys()
        .filter(|label| !SYSTEM_STAGES.contains(&label.as_str()))
        .count()
}

// --- maintenance -------------------------------------------------------------------------------------------------

/// What a scan keeps: an owned lease in, a verdict out.
type Keep = Box<dyn FnMut(VaultLease) -> BoxFuture<'static, IamResult<bool>> + Send>;

/// Up to `limit` records of a collection that match `filter` and `keep`, read in keyset pages (id order), so a crowd
/// of records that do not qualify can never hide the ones that do from a job.
async fn scan(
    store: &Store,
    collection: &str,
    filter: &Filter,
    mut keep: Keep,
    limit: f64,
) -> IamResult<Vec<VaultLease>> {
    let mut found = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let page = store
            .find(
                collection,
                filter,
                &FindOptions {
                    limit: Some(SCAN_PAGE),
                    offset: None,
                    after: after.clone(),
                },
            )
            .await?;
        let size = page.len() as i64;
        let last = page
            .last()
            .and_then(|record| record.get("id"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        for raw in page {
            let lease: VaultLease = decode(raw)?;
            if keep(lease.clone()).await? {
                found.push(lease);
                if found.len() as f64 >= limit {
                    return Ok(found);
                }
            }
        }
        if size < SCAN_PAGE {
            return Ok(found);
        }
        after = last;
    }
}

fn keep_if(test: impl Fn(&VaultLease) -> bool + Send + 'static) -> Keep {
    Box::new(move |lease| {
        let verdict = test(&lease);
        Box::pin(async move { Ok(verdict) })
    })
}

/// Deletes a secret with its versions, leases and access records, once every live dynamic lease has been revoked at
/// its engine: a revocation that fails keeps the secret (still pending deletion) for the next run, so no credential
/// outlives the records that could take it back. Audited as `vault:purge`.
async fn purge_secret(ctx: &Arc<ServerContext>, secret_id: &str) -> IamResult<bool> {
    let live = ctx
        .store
        .transaction(|tx| async move {
            let Some(secret) = get_secret(&tx, secret_id).await? else {
                return Ok(None);
            };
            if secret.status != "pending-deletion" {
                return Ok(None);
            }
            let mut ids = Vec::new();
            for raw in tx
                .find(
                    col("leases"),
                    &Filter::new()
                        .eq("tenantId", secret.tenant_id.clone())
                        .eq("secretId", secret.id.clone()),
                    &FindOptions::default(),
                )
                .await?
            {
                let lease: VaultLease = decode(raw)?;
                if lease.kind != "dynamic"
                    || !(lease.state == "active"
                        || lease.state == "revoking"
                        || lease.state == "issuing")
                {
                    continue;
                }
                if lease.state != "revoking" {
                    let mut marked = lease.clone();
                    marked.state = "revoking".into();
                    marked.ended_at = Some(lease.ended_at.unwrap_or_else(|| ctx.now()));
                    marked.ended_by = Some(
                        lease
                            .ended_by
                            .clone()
                            .unwrap_or_else(|| VAULT_OPERATOR.to_owned()),
                    );
                    marked.end_state = Some("ended".into());
                    put_lease(&tx, &marked).await?;
                }
                ids.push(lease.id);
            }
            Ok(Some(ids))
        })
        .await?;
    let Some(live) = live else {
        return Ok(false);
    };
    let mut revoked = true;
    for lease_id in &live {
        if revoke_and_record(ctx, lease_id).await?.is_err() {
            revoked = false;
        }
    }
    if !revoked {
        return Ok(false);
    }
    ctx.store
        .transaction(|tx| async move {
            let Some(secret) = get_secret(&tx, secret_id).await? else {
                return Ok(false);
            };
            if secret.status != "pending-deletion" {
                return Ok(false);
            }
            let scope = Filter::new()
                .eq("tenantId", secret.tenant_id.clone())
                .eq("secretId", secret.id.clone());
            let mut versions = 0.0;
            for collection in [col("versions"), col("leases"), col("access")] {
                for raw in tx.find(collection, &scope, &FindOptions::default()).await? {
                    let record_id = raw.get("id").and_then(Value::as_str).unwrap_or_default();
                    tx.delete(collection, record_id).await?;
                    if collection == col("versions") {
                        versions += 1.0;
                    }
                }
            }
            tx.delete(col("secrets"), &secret.id).await?;
            Recorder::operator(&secret.tenant_id, &secret.name)
                .record(
                    ctx,
                    &tx,
                    "vault:purge",
                    AuditOutcome::Allow,
                    meta(vec![
                        ("name", string(secret.name.clone())),
                        ("versions", number(versions)),
                    ]),
                )
                .await?;
            Ok(true)
        })
        .await
}

/// Trusted, credential-free access for the deployment's own code (`iam.vault`), and the vault's scheduler jobs.
pub struct VaultRuntime {
    ctx: Arc<ServerContext>,
}

/// `createVaultRuntime(ctx)`: validates the `vault` option now, so a bad one fails construction with INVALID_CONFIG.
pub fn create_vault_runtime(ctx: &Arc<ServerContext>) -> IamResult<VaultRuntime> {
    match settings(ctx) {
        // vault.ts is ported by its own unit: until `vaultSettings` exists the option cannot be checked here, and the
        // deployment still starts (every vault call answers NOT_IMPLEMENTED meanwhile).
        Err(error) if error.code == "NOT_IMPLEMENTED" => {}
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    Ok(VaultRuntime { ctx: ctx.clone() })
}

/// `vault://{name}` or `vault://{name}#{field}` (`/^vault:\/\/([^#]+)(?:#(.+))?$/`): the name and the field.
fn vault_reference(value: &str) -> Option<(String, Option<String>)> {
    let rest = value.strip_prefix("vault://")?;
    match rest.find('#') {
        None if !rest.is_empty() => Some((rest.to_owned(), None)),
        None => None,
        Some(0) => None,
        Some(index) => {
            let field = &rest[index + 1..];
            let line_terminator = |c: char| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}');
            if field.is_empty() || field.chars().any(line_terminator) {
                return None;
            }
            Some((rest[..index].to_owned(), Some(field.to_owned())))
        }
    }
}

/// `bounded(options.limit, fallback)`.
fn bounded(options: Option<&Value>, fallback: f64) -> IamResult<f64> {
    match crate::js::member(options, "limit") {
        None => Ok(fallback),
        Some(value) => integer(Some(value), "limit", 1.0, 100_000.0),
    }
}

impl VaultRuntime {
    /// `read(tenantId, name, options = {})`.
    async fn read(
        &self,
        tenant_id: Option<&Value>,
        name: Option<&Value>,
        options: Option<&Value>,
    ) -> IamResult<Revealed> {
        let ctx = &self.ctx;
        let empty = json!({});
        let options = options.unwrap_or(&empty);
        ctx.store
            .transaction(|tx| async move {
                let realm = ctx.tenant(&tx, &text(tenant_id, "tenantId", 256)?).await?;
                let secret = store_vault::find_secret(&tx, &realm.id, &secret_name(name)?)
                    .await?
                    .filter(|secret| secret.status == "active")
                    .ok_or_else(|| IamError::with_status("NOT_FOUND", "Secret not found", 404))?;
                let secret = static_secret(secret)?;
                let version = store_vault::select_version(&tx, &secret, options).await?;
                let value = store_vault::open_version(ctx, &tx, &version, None).await?;
                revealed(&secret, &version, value)
            })
            .await
    }

    /// A static secret's value for server code: the `current` version, or `version` / `stage`. No credential and no
    /// audit event (the access log records nothing either); check-out rules do not apply. NOT_FOUND for secrets pending
    /// deletion.
    pub async fn get(
        &self,
        tenant_id: &str,
        name: &str,
        options: Option<&Value>,
    ) -> IamResult<Value> {
        Ok(self
            .read(Some(&string(tenant_id)), Some(&string(name)), options)
            .await?
            .to_json())
    }

    /// Replaces every string of the form `vault://{name}` (the value) or `vault://{name}#{field}` (one field of a json
    /// secret) inside a JSON value, for configuration objects. Each secret is read once per call.
    pub async fn resolve(&self, tenant_id: &str, value: &Value) -> IamResult<Value> {
        self.resolve_value(Some(&string(tenant_id)), value).await
    }

    async fn resolve_value(&self, tenant_id: Option<&Value>, value: &Value) -> IamResult<Value> {
        let mut cache: HashMap<String, Result<Revealed, IamError>> = HashMap::new();
        self.walk(tenant_id, value, &mut cache).await
    }

    fn walk<'a>(
        &'a self,
        tenant_id: Option<&'a Value>,
        item: &'a Value,
        cache: &'a mut HashMap<String, Result<Revealed, IamError>>,
    ) -> BoxFuture<'a, IamResult<Value>> {
        Box::pin(async move {
            match item {
                Value::String(text) => {
                    let Some((name, field)) = vault_reference(text) else {
                        return Ok(item.clone());
                    };
                    if !cache.contains_key(&name) {
                        let read = self
                            .read(tenant_id, Some(&string(name.clone())), None)
                            .await;
                        cache.insert(name.clone(), read);
                    }
                    let secret = match cache.get(&name) {
                        Some(Ok(secret)) => secret.clone(),
                        Some(Err(error)) => return Err(error.clone()),
                        None => return Err(crate::js::internal_error()),
                    };
                    let Some(field) = field else {
                        return Ok(string(secret.value));
                    };
                    match store_vault::own_field(secret.fields.as_ref(), &field)? {
                        Some(value) => Ok(value),
                        None => Err(IamError::with_status(
                            "NOT_FOUND",
                            format!("The secret {name} has no field {field}"),
                            404,
                        )),
                    }
                }
                Value::Array(items) => {
                    let mut out = Vec::with_capacity(items.len());
                    for entry in items {
                        out.push(self.walk(tenant_id, entry, cache).await?);
                    }
                    Ok(Value::Array(out))
                }
                Value::Object(map) => {
                    let mut out = Map::new();
                    for (key, entry) in map {
                        out.insert(key.clone(), self.walk(tenant_id, entry, cache).await?);
                    }
                    Ok(Value::Object(out))
                }
                other => Ok(other.clone()),
            }
        })
    }

    /// Rotates every static secret whose scheduled rotation (or a retry of a failed one) is due (hourly job): generated
    /// values and rotators run as `deployment-operator`; secrets with neither are recorded once per due date as
    /// `vault:rotation-due`.
    pub async fn rotate_due(&self, options: Option<&Value>) -> IamResult<Value> {
        let ctx = &self.ctx;
        let limit = bounded(options, 1000.0)?;
        let now = ctx.now();
        let mut rotated = Vec::new();
        let mut failed = Vec::new();
        let mut reminded = Vec::new();
        let filter = match crate::js::member(options, "tenantId") {
            None => Filter::new(),
            Some(tenant_id) => {
                Filter::new().eq("tenantId", text(Some(tenant_id), "tenantId", 256)?)
            }
        };
        let next_at = |secret: &VaultSecret| {
            rotation_member(secret, "nextRotationAt").and_then(Value::as_f64)
        };
        let mut due = Vec::new();
        for raw in ctx
            .store
            .find(col("secrets"), &filter, &FindOptions::default())
            .await?
        {
            let secret: VaultSecret = decode(raw)?;
            if secret.status == "active"
                && secret.kind == "static"
                && next_at(&secret).is_some_and(|at| at <= now)
            {
                due.push(secret);
            }
        }
        due.sort_by(|a, b| {
            next_at(a)
                .unwrap_or(0.0)
                .partial_cmp(&next_at(b).unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        due.truncate(limit as usize);
        for candidate in &due {
            // Rotations the vault can run itself: a generator, a rotator, or a check-out return that failed to rotate.
            let automatic = truthy(rotation_member(candidate, "generator"))
                || truthy(rotation_member(candidate, "rotator"))
                || candidate
                    .checkout
                    .as_ref()
                    .is_some_and(|policy| policy.rotate_on_checkin);
            if !automatic {
                let was_reminded = ctx
                    .store
                    .transaction(|tx| async move {
                        let Some(secret) = get_secret(&tx, &candidate.id).await? else {
                            return Ok(false);
                        };
                        let Some(rotation) = secret.rotation.as_ref().and_then(Value::as_object)
                        else {
                            return Ok(false);
                        };
                        let next_rotation_at = rotation.get("nextRotationAt");
                        if !truthy(next_rotation_at) {
                            return Ok(false);
                        }
                        let next_rotation_at =
                            next_rotation_at.and_then(Value::as_f64).unwrap_or(f64::NAN);
                        if next_rotation_at > now {
                            return Ok(false);
                        }
                        let notified = match rotation.get("dueNotifiedAt") {
                            None | Some(Value::Null) => 0.0,
                            Some(value) => value.as_f64().unwrap_or(f64::NAN),
                        };
                        if notified >= next_rotation_at {
                            return Ok(false);
                        }
                        let mut changed = rotation.clone();
                        changed.insert("dueNotifiedAt".into(), number(now));
                        let mut next = secret.clone();
                        next.rotation = Some(Value::Object(changed));
                        put_secret(&tx, &next).await?;
                        Recorder::operator(&secret.tenant_id, &secret.name)
                            .record(
                                ctx,
                                &tx,
                                "vault:rotation-due",
                                AuditOutcome::Allow,
                                meta(vec![
                                    ("name", string(secret.name.clone())),
                                    ("dueAt", number(next_rotation_at)),
                                ]),
                            )
                            .await?;
                        Ok(true)
                    })
                    .await?;
                if was_reminded {
                    reminded
                        .push(json!({ "tenantId": candidate.tenant_id, "name": candidate.name }));
                }
                continue;
            }
            let attempt: IamResult<Option<(StagedRotation, RotationOutcome)>> = async {
                let staged = ctx
                    .store
                    .transaction(|tx| async move {
                        let Some(secret) = get_secret(&tx, &candidate.id).await? else {
                            return Ok(None);
                        };
                        if secret.status != "active"
                            || !next_at(&secret).is_some_and(|at| at <= now)
                        {
                            return Ok(None);
                        }
                        // A shared credential that is checked out rotates when it comes back, not under its holder.
                        if secret
                            .checkout
                            .as_ref()
                            .is_some_and(|policy| policy.rotate_on_checkin)
                            && store_vault::live_leases(ctx, &tx, &secret)
                                .await?
                                .iter()
                                .any(|lease| lease.kind == "checkout")
                        {
                            return Ok(None);
                        }
                        Ok(Some(
                            stage_rotation(ctx, &tx, &secret, VAULT_OPERATOR, &json!({}), None)
                                .await?,
                        ))
                    })
                    .await?;
                let Some(staged) = staged else {
                    return Ok(None);
                };
                let outcome = complete_rotation(
                    ctx,
                    &staged,
                    VAULT_OPERATOR,
                    &Recorder::operator(&staged.tenant_id, &staged.name),
                )
                .await?;
                Ok(Some((staged, outcome)))
            }
            .await;
            match attempt {
                Ok(None) => {}
                Ok(Some((staged, RotationOutcome::Ok { version, .. }))) => {
                    rotated.push(json!({
                        "tenantId": staged.tenant_id,
                        "name": staged.name,
                        "version": number(version),
                    }));
                }
                Ok(Some((staged, RotationOutcome::Failed(message)))) => {
                    failed.push(json!({
                        "tenantId": staged.tenant_id,
                        "name": staged.name,
                        "message": message,
                    }));
                }
                Err(error) => {
                    // Refused before the rotator ran (a json secret without rotation.field, say): recorded and retried
                    // later.
                    let message = redacted(&error.message, &[])?;
                    let message_ref = &message;
                    let _ = ctx
                        .store
                        .transaction(|tx| async move {
                            let Some(secret) = get_secret(&tx, &candidate.id).await? else {
                                return Ok(());
                            };
                            if secret.status != "active" {
                                return Ok(());
                            }
                            record_rotation_failure(ctx, &tx, &secret, message_ref).await?;
                            Recorder::operator(&secret.tenant_id, &secret.name)
                                .record(
                                    ctx,
                                    &tx,
                                    "vault:rotate",
                                    AuditOutcome::Deny,
                                    meta(vec![
                                        ("name", string(secret.name.clone())),
                                        ("error", string(message_ref.clone())),
                                    ]),
                                )
                                .await
                        })
                        .await;
                    failed.push(json!({
                        "tenantId": candidate.tenant_id,
                        "name": candidate.name,
                        "message": message,
                    }));
                }
            }
        }
        Ok(json!({ "rotated": rotated, "failed": failed, "reminded": reminded }))
    }

    /// Ends expired check-outs (rotating `rotateOnCheckin` secrets), revokes expired dynamic leases and those of people
    /// who are no longer active at their engine, retries failed revocations with backoff for seven days, and deletes
    /// lease history past `accessRetentionDays` (every few minutes).
    pub async fn expire_leases(&self, options: Option<&Value>) -> IamResult<Value> {
        let ctx = &self.ctx;
        let limit = bounded(options, 1000.0)?;
        let now = ctx.now();
        let (mut expired, mut retrying, mut abandoned, mut pruned, mut rotated) =
            (0.0, 0.0, 0.0, 0.0, 0.0);
        let leases = col("leases");
        let mut candidates: Vec<VaultLease> = Vec::new();
        for raw in find_ordered(
            ctx.store.as_ref(),
            leases,
            &Filter::new().eq("state", "active"),
            &OrderOptions {
                to: Some(now),
                limit: Some(limit as i64),
                ..OrderOptions::by("expiresAt")
            },
            None,
        )
        .await?
        {
            candidates.push(decode(raw)?);
        }
        candidates.extend(
            scan(
                &ctx.store,
                leases,
                &Filter::new().eq("state", "revoking"),
                keep_if(move |lease| lease.retry_at.unwrap_or(0.0) <= now),
                limit,
            )
            .await?,
        );
        candidates.extend(
            scan(
                &ctx.store,
                leases,
                &Filter::new().eq("state", "issuing"),
                keep_if(move |lease| lease.issued_at <= now - 10.0 * MINUTE),
                limit,
            )
            .await?,
        );
        // Live leases whose holder may no longer have them end too: a person or agent who is no longer active, an
        // agent whose sponsor left, and a lease an agent took for a person under a delegation that has ended. Every
        // active lease is looked at, however many there are; at most `limit` of them end per run.
        let verdicts: Arc<Mutex<HashMap<String, bool>>> = Arc::default();
        let departed: Keep = {
            let (ctx, verdicts) = (ctx.clone(), verdicts.clone());
            Box::new(move |lease: VaultLease| {
                let (ctx, verdicts) = (ctx.clone(), verdicts.clone());
                Box::pin(async move {
                    if lease.expires_at <= now {
                        return Ok(false);
                    }
                    let stands = may_act(&ctx, &verdicts, &lease.holder_id).await?
                        && match &lease.agent_id {
                            None => true,
                            Some(agent_id) => may_act(&ctx, &verdicts, agent_id).await?,
                        }
                        && match &lease.delegation_id {
                            None => true,
                            Some(delegation_id) => {
                                delegation_stands(&ctx, &verdicts, delegation_id, now).await?
                            }
                        };
                    Ok(!stands)
                })
            })
        };
        candidates.extend(
            scan(
                &ctx.store,
                leases,
                &Filter::new().eq("state", "active"),
                departed,
                limit,
            )
            .await?,
        );
        let mut seen: HashSet<String> = HashSet::new();
        for candidate in &candidates {
            if !seen.insert(candidate.id.clone()) {
                continue;
            }
            if candidate.state == "issuing" {
                // An issue that never finished (the process stopped): whatever the engine minted is revoked by id.
                if candidate.issued_at > now - 10.0 * MINUTE {
                    continue;
                }
                let marked = ctx
                    .store
                    .transaction(|tx| async move {
                        let Some(lease) = get_lease(&tx, &candidate.id).await? else {
                            return Ok(false);
                        };
                        if lease.state != "issuing" {
                            return Ok(false);
                        }
                        let mut next = lease.clone();
                        next.state = "revoking".into();
                        next.ended_at = Some(now);
                        next.ended_by = Some(VAULT_OPERATOR.into());
                        next.end_state = Some("failed".into());
                        next.last_error = Some("The issue never completed".into());
                        put_lease(&tx, &next).await?;
                        Ok(true)
                    })
                    .await?;
                if !marked {
                    continue;
                }
                if revoke_and_record(ctx, &candidate.id).await?.is_ok() {
                    expired += 1.0;
                } else {
                    retrying += 1.0;
                }
                continue;
            }
            if candidate.kind == "checkout" {
                let ended = ctx
                    .store
                    .transaction(|tx| async move {
                        let Some(lease) = get_lease(&tx, &candidate.id).await? else {
                            return Ok(false);
                        };
                        if lease.state != "active" {
                            return Ok(false);
                        }
                        let mut next = lease.clone();
                        next.state = "expired".into();
                        next.ended_at = Some(now);
                        next.ended_by = Some(VAULT_OPERATOR.into());
                        put_lease(&tx, &next).await?;
                        Recorder::operator(&lease.tenant_id, &lease.name)
                            .record(
                                ctx,
                                &tx,
                                "vault:checkout-expired",
                                AuditOutcome::Allow,
                                meta(vec![
                                    ("name", string(lease.name.clone())),
                                    ("leaseId", string(lease.id.clone())),
                                    ("holderId", string(lease.holder_id.clone())),
                                ]),
                            )
                            .await?;
                        Ok(true)
                    })
                    .await?;
                if !ended {
                    continue;
                }
                expired += 1.0;
                if rotate_returned(
                    ctx,
                    &candidate.tenant_id,
                    &candidate.secret_id,
                    VAULT_OPERATOR,
                    &Recorder::operator(&candidate.tenant_id, ""),
                )
                .await?
                .is_some()
                {
                    rotated += 1.0;
                }
                continue;
            }
            // Dynamic: mark the revocation (an expiry, or the end for a holder who left), then revoke at the engine.
            enum Marked {
                Revoke(Box<VaultLease>),
                Skip,
                Abandoned,
            }
            let marked = ctx
                .store
                .transaction(|tx| async move {
                    let Some(current) = get_lease(&tx, &candidate.id).await? else {
                        return Ok(Marked::Skip);
                    };
                    if current.state != "active" && current.state != "revoking" {
                        return Ok(Marked::Skip);
                    }
                    if current.state == "active" {
                        let mut next = current.clone();
                        next.state = "revoking".into();
                        next.ended_at = Some(now);
                        next.ended_by = Some(VAULT_OPERATOR.into());
                        next.end_state = Some(
                            if current.expires_at <= now {
                                "expired"
                            } else {
                                "ended"
                            }
                            .into(),
                        );
                        return Ok(Marked::Revoke(Box::new(put_lease(&tx, &next).await?)));
                    }
                    // Given up after seven days of refusals: recorded, so someone revokes it by hand.
                    if let Some(started) = current.revoke_started_at
                        && now - started > REVOKE_PATIENCE_MS
                    {
                        let mut next = current.clone();
                        next.state = "failed".into();
                        next.ended_at = Some(current.ended_at.unwrap_or(now));
                        put_lease(&tx, &next).await?;
                        Recorder::operator(&current.tenant_id, &current.name)
                            .record(
                                ctx,
                                &tx,
                                "vault:revoke-failed",
                                AuditOutcome::Deny,
                                meta(vec![
                                    ("name", string(current.name.clone())),
                                    ("leaseId", string(current.id.clone())),
                                    (
                                        "error",
                                        string(
                                            current
                                                .last_error
                                                .clone()
                                                .unwrap_or_else(|| "unknown".into()),
                                        ),
                                    ),
                                ]),
                            )
                            .await?;
                        return Ok(Marked::Abandoned);
                    }
                    Ok(Marked::Revoke(Box::new(current)))
                })
                .await?;
            let lease = match marked {
                Marked::Revoke(lease) => lease,
                Marked::Skip => continue,
                Marked::Abandoned => {
                    abandoned += 1.0;
                    continue;
                }
            };
            if revoke_and_record(ctx, &lease.id).await?.is_err() {
                retrying += 1.0;
                continue;
            }
            expired += 1.0;
            let lease_ref = &lease;
            ctx.store
                .transaction(|tx| async move {
                    Recorder::operator(&lease_ref.tenant_id, &lease_ref.name)
                        .record(
                            ctx,
                            &tx,
                            "vault:lease-expired",
                            AuditOutcome::Allow,
                            meta(vec![
                                ("name", string(lease_ref.name.clone())),
                                ("leaseId", string(lease_ref.id.clone())),
                                ("holderId", string(lease_ref.holder_id.clone())),
                            ]),
                        )
                        .await
                })
                .await?;
        }
        // Lease history past the access retention.
        let cutoff = now - settings(ctx)?.access_retention_ms;
        for state in ["ended", "expired", "failed"] {
            let old = scan(
                &ctx.store,
                leases,
                &Filter::new().eq("state", state),
                keep_if(move |lease| lease.ended_at.unwrap_or(lease.expires_at) < cutoff),
                limit,
            )
            .await?;
            for lease in old {
                let lease_id = &lease.id;
                ctx.store
                    .transaction(|tx| async move { tx.delete(leases, lease_id).await })
                    .await?;
                pruned += 1.0;
            }
        }
        Ok(json!({
            "expired": number(expired),
            "retrying": number(retrying),
            "abandoned": number(abandoned),
            "pruned": number(pruned),
            "rotated": number(rotated),
        }))
    }

    /// Deletes secrets whose recovery window has ended, once their dynamic leases are revoked (daily).
    pub async fn purge_deleted(&self, options: Option<&Value>) -> IamResult<Value> {
        let ctx = &self.ctx;
        let limit = bounded(options, 1000.0)?;
        let now = ctx.now();
        let mut purged = 0.0;
        let mut due = Vec::new();
        for raw in ctx
            .store
            .find(
                col("secrets"),
                &Filter::new().eq("status", "pending-deletion"),
                &FindOptions::default(),
            )
            .await?
        {
            let secret: VaultSecret = decode(raw)?;
            if secret.deletion_at.unwrap_or(0.0) <= now {
                due.push(secret);
            }
        }
        due.truncate(limit as usize);
        for secret in &due {
            if purge_secret(ctx, &secret.id).await? {
                purged += 1.0;
            }
        }
        Ok(json!({ "purged": number(purged) }))
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        let arg = |index: usize| args.get(index).filter(|value| !is_undefined(value));
        match method {
            "get" => Some(
                self.read(arg(0), arg(1), arg(2))
                    .await
                    .map(|secret| secret.to_json()),
            ),
            "resolve" => Some(match arg(1) {
                Some(value) => self.resolve_value(arg(0), value).await,
                None => Ok(undefined()),
            }),
            "rotateDue" => Some(self.rotate_due(arg(0)).await),
            "expireLeases" => Some(self.expire_leases(arg(0)).await),
            "purgeDeleted" => Some(self.purge_deleted(arg(0)).await),
            _ => None,
        }
    }
}

/// The tagged encoding of `undefined` in a `call`'s arguments.
fn is_undefined(value: &Value) -> bool {
    value == &undefined()
}

/// Whether an identity may still act: active, unexpired, and for an agent, in good standing (its sponsor too).
async fn may_act(
    ctx: &Arc<ServerContext>,
    verdicts: &Mutex<HashMap<String, bool>>,
    identity_id: &str,
) -> IamResult<bool> {
    let key = format!("identity:{identity_id}");
    if let Some(verdict) = verdicts.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        return Ok(*verdict);
    }
    let verdict = match ctx.store.get("identities", identity_id).await? {
        None => false,
        Some(raw) => {
            let identity: Identity = decode(raw)?;
            if identity.status != IdentityStatus::Active || ctx.identity_expired(&identity) {
                false
            } else {
                identity.kind != IdentityKind::Agent
                    || agent_standing(ctx, &ctx.store, &identity).await? == "ok"
            }
        }
    };
    verdicts
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, verdict);
    Ok(verdict)
}

/// Whether a delegation still stands: live, with every ancestor in the hand-off chain intact.
async fn delegation_stands(
    ctx: &Arc<ServerContext>,
    verdicts: &Mutex<HashMap<String, bool>>,
    delegation_id: &str,
    now: f64,
) -> IamResult<bool> {
    let key = format!("delegation:{delegation_id}");
    if let Some(verdict) = verdicts.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        return Ok(*verdict);
    }
    let verdict = match ctx.store.get("delegations", delegation_id).await? {
        None => false,
        Some(raw) => {
            let delegation: Delegation = decode(raw)?;
            delegation_live(&delegation, now)
                && delegation_ancestors(&ctx.store, &delegation, now)
                    .await?
                    .is_some()
        }
    };
    verdicts
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, verdict);
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_references() {
        assert_eq!(vault_reference("vault://smtp"), Some(("smtp".into(), None)));
        assert_eq!(
            vault_reference("vault://smtp#host"),
            Some(("smtp".into(), Some("host".into())))
        );
        assert_eq!(
            vault_reference("vault://a/b#c#d"),
            Some(("a/b".into(), Some("c#d".into())))
        );
        assert_eq!(vault_reference("vault://"), None);
        assert_eq!(vault_reference("vault://#x"), None);
        assert_eq!(vault_reference("vault://smtp#"), None);
        assert_eq!(vault_reference("vault://smtp#a\nb"), None);
        assert_eq!(
            vault_reference("vault://sm\ntp"),
            Some(("sm\ntp".into(), None))
        );
        assert_eq!(vault_reference("plain"), None);
    }

    #[test]
    fn javascript_numbers() {
        assert_eq!(
            js_value(json!({ "a": 1.0, "b": [2.5, 3.0], "c": 4 })).to_string(),
            r#"{"a":1,"b":[2.5,3],"c":4}"#
        );
    }
}
