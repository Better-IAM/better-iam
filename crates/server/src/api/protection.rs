//! Port of `packages/server/src/api/protection.ts`: the `protection` API group (data protection by tokenization) and
//! the retention job `iam.protection.sweep()`.
//!
//! Profiles and tokens are read and written as raw JSON records, so member order and members this port does not know
//! survive a round trip (a mixed fleet shares the database with TypeScript). The typed helpers of tokenization.ts and
//! kms.ts see typed views of them.

use std::sync::Arc;

use better_iam_core::js::cmp_utf16;
use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError, IamResult, IamStoreExt,
    Record,
};
use better_iam_types::api::protection;
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply};
use crate::context::{ServerContext, Store};
use crate::contracts::{OperationDenied, OperationResult};
use crate::guarded::{
    Guard, GuardAction, GuardCall, GuardOptions, GuardTarget, Target, create_guard,
};
use crate::js::{js_string, number, number_to_string, to_number, truthy, utf16_len};
use crate::kms::{
    EncryptionContext, KmsKey, KmsServiceUse, ServiceDataKey, alias_names, assert_unmanaged,
    assert_usable, create_service_key, find_key, key_attributes, kms_actions, kms_data_key_for,
    kms_open_data_key_for, retire_service_key,
};
use crate::tokenization::{
    DATA_TYPES, DEFAULT_MASK, MAX_BATCH, MAX_PROFILES_PER_TENANT, ProtectionProfile, fingerprint,
    format_preserving_space, lookup_context, mask_style, mask_value, needs_deterministic,
    new_token, normalize_value, open_value, profile_name, protection_actions, seal_value,
    summarize_profile, token_key,
};
use crate::utils::id;
use crate::validation::{integer, text, text256};

const DAY: f64 = 86_400_000.0;
/// Tokens a retention sweep reads per transaction.
const SWEEP_BATCH: usize = 500;

/// `ProtectionTarget`: a guard target that carries the profile it names.
#[derive(Debug, Clone, Default)]
struct ProtectionTarget {
    resource_id: String,
    attributes: Map<String, Value>,
    profile: Option<Record>,
}

impl GuardTarget for ProtectionTarget {
    fn resource_id(&self) -> &str {
        &self.resource_id
    }
    fn attributes(&self) -> &Map<String, Value> {
        &self.attributes
    }
}

impl ProtectionTarget {
    /// The located profile (every target `profileTarget` builds has one).
    fn profile(&self) -> Record {
        self.profile.clone().unwrap_or_default()
    }
}

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// A string member of a record ("" when absent or not a string).
fn record_text(record: &Record, key: &str) -> String {
    record
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// `record.member ?? fallback` for a JSON member.
fn member_or(record: &Record, key: &str, fallback: Value) -> Value {
    match record.get(key) {
        None | Some(Value::Null) => fallback,
        Some(value) => value.clone(),
    }
}

/// The action a frozen action table names (`protectionActions.read`, `kmsActions.decrypt`).
fn action_of(table: IamResult<Value>, name: &str) -> IamResult<String> {
    Ok(js_string(table?.get(name)))
}

fn protection_action(name: &str) -> IamResult<String> {
    action_of(protection_actions(), name)
}

fn kms_action(name: &str) -> IamResult<String> {
    action_of(kms_actions(), name)
}

/// The typed view of a stored profile the tokenization helpers read (`tokens ?? 0` as `summarizeProfile` reads it).
fn typed_profile(record: &Record) -> IamResult<ProtectionProfile> {
    let mut view = record.clone();
    if matches!(view.get("tokens"), None | Some(Value::Null)) {
        view.insert("tokens".into(), Value::from(0));
    }
    crate::port::decode(view)
}

fn summary(record: &Record) -> IamResult<Value> {
    let summary = summarize_profile(&typed_profile(record)?)?;
    Ok(serde_json::to_value(summary).unwrap_or(Value::Null))
}

fn key_value(key: &KmsKey) -> Value {
    serde_json::to_value(key).unwrap_or(Value::Null)
}

/// An encryption context from its JSON form.
fn context_of(value: Value) -> IamResult<EncryptionContext> {
    match value {
        Value::Object(map) => Ok(EncryptionContext { extra: map }),
        _ => Ok(EncryptionContext { extra: Map::new() }),
    }
}

/// `{ protection: profileId }`: the context batch data keys are bound to.
fn batch_context(profile_id: &str) -> EncryptionContext {
    let mut extra = Map::new();
    extra.insert("protection".into(), Value::String(profile_id.to_owned()));
    EncryptionContext { extra }
}

/// `{ via: 'protection', principal }`.
fn service_use(principal: &AuthenticatedPrincipal) -> KmsServiceUse {
    KmsServiceUse {
        via: "protection".into(),
        principal: Some(principal.clone()),
    }
}

/// `(current ?? 0) + delta` as JavaScript computes it.
fn plus(current: Option<&Value>, delta: f64) -> Value {
    match current {
        None | Some(Value::Null) => number(delta),
        Some(value @ (Value::String(_) | Value::Array(_) | Value::Object(_))) => Value::String(
            format!("{}{}", js_string(Some(value)), number_to_string(delta)),
        ),
        Some(value) => number(to_number(value) + delta),
    }
}

/// `Math.max(0, (current ?? 0) - delta)`.
fn minus(current: Option<&Value>, delta: f64) -> Value {
    let base = match current {
        None | Some(Value::Null) => 0.0,
        Some(value) => to_number(value),
    };
    let difference = base - delta;
    number(if difference.is_nan() {
        f64::NAN
    } else {
        difference.max(0.0)
    })
}

/// A number member as a JavaScript comparison reads it (`undefined` is NaN).
fn numeric(value: Option<&Value>) -> f64 {
    value.map_or(f64::NAN, to_number)
}

fn list(value: Option<&Value>, name: &str) -> IamResult<Vec<Value>> {
    match value {
        Some(Value::Array(items)) if !items.is_empty() && items.len() as f64 <= MAX_BATCH => {
            Ok(items.clone())
        }
        _ => Err(invalid(format!(
            "{name} must list 1 to {} entries",
            number_to_string(MAX_BATCH)
        ))),
    }
}

/// `/^[a-z][a-z0-9-]{0,63}$/`.
fn short_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn purpose_of(value: Option<&Value>) -> IamResult<String> {
    let purpose = text(value, "purpose", 64)?;
    if !short_name(&purpose) {
        return Err(invalid(
            "purpose is a short lowercase name, such as payment-processing or fraud-review",
        ));
    }
    Ok(purpose)
}

fn token_list(value: Option<&Value>) -> IamResult<Vec<String>> {
    list(value, "tokens")?
        .into_iter()
        .map(|item| match item {
            Value::String(token)
                if !token.is_empty()
                    && utf16_len(&token) <= 4096
                    && !token.chars().any(|c| (c as u32) <= 0x1f) =>
            {
                Ok(token)
            }
            _ => Err(invalid("Every token must be a string")),
        })
        .collect()
}

/// `profileAttributes(profile, extra)`: what policies see of a profile (`resource.{name}`).
fn profile_attributes(profile: &Record, extra: Map<String, Value>) -> Map<String, Value> {
    let mut attributes = Map::new();
    if let Some(name) = profile.get("name") {
        attributes.insert("profile".into(), name.clone());
    }
    for key in ["dataType", "format", "deterministic"] {
        if let Some(value) = profile.get(key) {
            attributes.insert(key.into(), value.clone());
        }
    }
    for (key, value) in extra {
        attributes.insert(key, value);
    }
    attributes
}

/// `findProfile(tx, tenantId, name)`.
async fn find_profile(
    tx: &Store,
    tenant_id: Option<&Value>,
    name: Option<&Value>,
) -> IamResult<Record> {
    let tenant = text256(tenant_id, "tenantId")?;
    let unique_key = format!("name:{}", profile_name(name)?);
    tx.find(
        "protectionProfiles",
        &Filter::new()
            .eq("tenantId", tenant)
            .eq("uniqueKey", unique_key),
        &FindOptions::default(),
    )
    .await?
    .into_iter()
    .next()
    .ok_or_else(|| IamError::with_status("NOT_FOUND", "Protection profile not found", 404))
}

/// `profileTarget(tenantId, name, extra)(tx)`.
async fn profile_target(
    tx: Store,
    tenant_id: Option<Value>,
    name: Option<Value>,
    extra: impl FnOnce(&Record) -> IamResult<Map<String, Value>>,
) -> IamResult<ProtectionTarget> {
    let profile = find_profile(&tx, tenant_id.as_ref(), name.as_ref()).await?;
    let extra = extra(&profile)?;
    Ok(ProtectionTarget {
        resource_id: format!("protection/{}", record_text(&profile, "name")),
        attributes: profile_attributes(&profile, extra),
        profile: Some(profile),
    })
}

fn no_extra(_profile: &Record) -> IamResult<Map<String, Value>> {
    Ok(Map::new())
}

/// A profile bound to a customer key (one it did not create) leaves the key's owner in charge, as the vault does:
/// every call needs the caller's own KMS permission on the key, so revoking it stops the profile's use too.
async fn require_key_use(
    call: &GuardCall<ProtectionTarget>,
    profile: &Record,
    action: &str,
) -> OperationResult<()> {
    let key = find_key(
        &call.tx,
        &record_text(profile, "tenantId"),
        profile.get("keyId"),
    )
    .await?;
    if key.managed_by.as_deref() == Some("protection")
        && profile.get("id").and_then(Value::as_str) == key.managed_id.as_deref()
    {
        return Ok(());
    }
    let key_json = key_value(&key);
    let aliases = alias_names(&call.tx, &key_json).await?;
    let target = Target {
        resource_id: format!("kms/{}", key.id),
        attributes: key_attributes(&key_json, &aliases, None)?,
    };
    if !call.allowed(action, &target).await? {
        return Err(OperationDenied::new(Some(&format!(
            "This needs {action} on the profile's customer-managed key"
        ))));
    }
    Ok(())
}

/// The profile's fingerprint key, unwrapped by its KMS key (so it stops with the key). Wipe it after use.
async fn lookup_key(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    profile: &Record,
    principal: &AuthenticatedPrincipal,
) -> IamResult<Vec<u8>> {
    kms_open_data_key_for(
        ctx,
        tx,
        &record_text(profile, "tenantId"),
        &record_text(profile, "lookupKeyWrapped"),
        &context_of(lookup_context(&record_text(profile, "id"))?)?,
        &service_use(principal),
    )
    .await
}

/// The stored records of `tokens` in a profile, keyed by token (absent tokens are missing from the map).
async fn records_of(
    tx: &Store,
    profile: &Record,
    tokens: &[String],
) -> IamResult<IndexMap<String, Record>> {
    let tenant_id = record_text(profile, "tenantId");
    let profile_id = profile.get("id");
    let mut records = IndexMap::new();
    let distinct: IndexSet<&String> = tokens.iter().collect();
    for token in distinct {
        let record = tx
            .find(
                "protectionTokens",
                &Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("uniqueKey", token_key(&record_text(profile, "id"), token)?),
                &FindOptions::default(),
            )
            .await?
            .into_iter()
            .next();
        if let Some(record) = record
            && record.get("profileId") == profile_id
            && record.get("token").and_then(Value::as_str) == Some(token.as_str())
        {
            records.insert(token.clone(), record);
        }
    }
    Ok(records)
}

/// Opens the values of stored tokens, unwrapping each distinct batch data key once.
async fn open_all(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    profile: &Record,
    records: Vec<&Record>,
    principal: &AuthenticatedPrincipal,
) -> IamResult<IndexMap<String, String>> {
    let mut keys: IndexMap<String, Vec<u8>> = IndexMap::new();
    let mut values = IndexMap::new();
    let tenant_id = record_text(profile, "tenantId");
    let context = batch_context(&record_text(profile, "id"));
    let outcome: IamResult<()> = async {
        for record in records {
            let wrapped = record_text(record, "wrapped");
            if !keys.contains_key(&wrapped) {
                let data_key = kms_open_data_key_for(
                    ctx,
                    tx,
                    &tenant_id,
                    &wrapped,
                    &context,
                    &service_use(principal),
                )
                .await?;
                keys.insert(wrapped.clone(), data_key);
            }
            let value = open_value(&keys[&wrapped], &Value::Object(record.clone()))?;
            values.insert(record_text(record, "token"), value);
        }
        Ok(())
    }
    .await;
    for key in keys.values_mut() {
        key.fill(0);
    }
    outcome?;
    Ok(values)
}

/// Whether any token remains in a profile (read by query, not by the counter).
async fn holds_tokens(tx: &Store, profile: &Record) -> IamResult<bool> {
    Ok(!tx
        .find(
            "protectionTokens",
            &Filter::new()
                .eq("tenantId", member_or(profile, "tenantId", Value::Null))
                .eq("profileId", member_or(profile, "id", Value::Null)),
            &FindOptions::limit(1),
        )
        .await?
        .is_empty())
}

/// Plugins see which profile served a call, never values or tokens (format-preserving ones keep digits).
fn hook_result(value: &Value) -> Value {
    let rest = |members: Map<String, Value>| {
        Value::Object(
            members
                .into_iter()
                .filter(|(key, _)| key != "values" && key != "tokens")
                .collect(),
        )
    };
    match value {
        Value::Object(map) => rest(map.clone()),
        Value::Array(items) => rest(
            items
                .iter()
                .enumerate()
                .map(|(index, item)| (index.to_string(), item.clone()))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Refusals are audited with the profile and purpose too.
fn describe(target: &ProtectionTarget) -> Map<String, Value> {
    let mut metadata = Map::new();
    if let Some(name) = target
        .profile
        .as_ref()
        .and_then(|profile| profile.get("name"))
    {
        metadata.insert("profile".into(), name.clone());
    }
    if let Some(Value::String(purpose)) = target.attributes.get("purpose") {
        metadata.insert("purpose".into(), Value::String(purpose.clone()));
    }
    metadata
}

/// The `protection` API group (`createProtectionApi(ctx)`): one method per route `protection/{method}`.
///
/// Data protection by tokenization. A profile says how one kind of sensitive value is tokenized, masked and
/// protected; policies name it as `iam/protection/{name}` with `resource.profile`, `resource.dataType`,
/// `resource.format` and `resource.deterministic`; detokenizing adds `resource.purpose` and masking `resource.style`.
/// Values are encrypted under the profile's KMS key (one wrapped data key per call) and never written to the audit
/// trail; tokens are not either, only counts. Sessions that view as someone else are refused.
pub struct ProtectionApi {
    ctx: Arc<ServerContext>,
    guard: Guard<ProtectionTarget>,
}

/// `createProtectionApi(ctx)`.
pub fn create_protection_api(ctx: &Arc<ServerContext>) -> IamResult<ProtectionApi> {
    let mut recorded_failures = IndexMap::new();
    recorded_failures.insert("KEY_STATE_INVALID".to_owned(), "key-unavailable".to_owned());
    let guard = create_guard(
        ctx.clone(),
        "protection",
        GuardOptions {
            fallback: None,
            describe: Some(Arc::new(describe)),
            recorded_failures,
            hook_result: Some(Arc::new(hook_result)),
        },
    );
    Ok(ProtectionApi {
        ctx: ctx.clone(),
        guard,
    })
}

impl ProtectionApi {
    /// `protection/createProfile`: creates a tokenization profile for one kind of value (`card`, `ssn`, `email`,
    /// `phone` or `generic`): its token format, whether tokens are deterministic, its display mask, its retention, and
    /// the tenant AES key that protects its values (an existing one the caller may use, or a new one managed by the
    /// profile). Requires iam:protection:manage on `iam/protection/{name}`.
    pub async fn create_profile(
        &self,
        credential: &CredentialInput,
        input: Body<protection::CreateProfileInput>,
    ) -> IamResult<Reply<protection::CreateProfileOutput>> {
        let name = profile_name(input.get("name"))?;
        let data_type = match input.get("dataType") {
            Some(Value::String(kind)) if DATA_TYPES.contains(&kind.as_str()) => kind.clone(),
            _ => {
                return Err(invalid(format!(
                    "dataType must be one of {}",
                    DATA_TYPES.join(", ")
                )));
            }
        };
        let data_type_value = Value::String(data_type.clone());
        let format = match input.get("format") {
            None | Some(Value::Null) => Value::String(
                if data_type == "generic" {
                    "random"
                } else {
                    "format-preserving"
                }
                .into(),
            ),
            Some(value) => value.clone(),
        };
        if !matches!(format.as_str(), Some("random" | "format-preserving")) {
            return Err(invalid("format must be random or format-preserving"));
        }
        let deterministic = match input.get("deterministic") {
            None => needs_deterministic(&data_type_value, &format)?,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => return Err(invalid("deterministic must be true or false")),
        };
        if !deterministic && needs_deterministic(&data_type_value, &format)? {
            return Err(invalid(format!(
                "Format-preserving {data_type} tokens keep the last four digits and have few random ones left, so these profiles must be deterministic (or use random tokens)"
            )));
        }
        let mask = match input.get("mask") {
            None => DEFAULT_MASK
                .get(data_type.as_str())
                .cloned()
                .unwrap_or(Value::Null),
            Some(value) => mask_style(&data_type_value, Some(value), None)?,
        };
        let description = match input.get("description") {
            None => None,
            Some(value) => Some(text(Some(value), "description", 512)?),
        };
        let retention_days = match input.get("retentionDays") {
            None => None,
            Some(value) => Some(integer(Some(value), "retentionDays", 1.0, 3650.0)?),
        };
        let key_ref = input.get("keyId").cloned();
        let mut attributes = Map::new();
        attributes.insert("profile".into(), Value::String(name.clone()));
        attributes.insert("dataType".into(), data_type_value.clone());
        attributes.insert("format".into(), format.clone());
        attributes.insert("deterministic".into(), Value::Bool(deterministic));
        let located = ProtectionTarget {
            resource_id: format!("protection/{name}"),
            attributes,
            profile: None,
        };
        let ctx = self.ctx.clone();
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(protection_action("manage")?),
                move |_tx, _principal| Box::pin(async move { Ok(located) }),
                move |call, _target| {
                    Box::pin(async move {
                        let (tx, tenant, principal) =
                            (call.tx.clone(), call.tenant.clone(), call.principal.clone());
                        let existing = tx
                            .find(
                                "protectionProfiles",
                                &Filter::new().eq("tenantId", tenant.id.clone()),
                                &FindOptions::default(),
                            )
                            .await?;
                        if existing.len() as f64 >= MAX_PROFILES_PER_TENANT {
                            return Err(IamError::with_status(
                                "LIMIT_EXCEEDED",
                                format!(
                                    "A tenant keeps at most {} protection profiles",
                                    number_to_string(MAX_PROFILES_PER_TENANT)
                                ),
                                409,
                            )
                            .into());
                        }
                        if existing.iter().any(|profile| {
                            profile.get("name").and_then(Value::as_str) == Some(name.as_str())
                        }) {
                            return Err(IamError::with_status(
                                "CONFLICT",
                                "A profile with that name exists",
                                409,
                            )
                            .into());
                        }
                        let profile_id = id();
                        let key = match &key_ref {
                            Some(reference) => {
                                let key = find_key(&tx, &tenant.id, Some(reference)).await?;
                                assert_usable(&key, &Value::String("encrypt".into()))?;
                                // Another profile's or module's key stays theirs.
                                assert_unmanaged(&key_value(&key))?;
                                if key.key_spec.as_str() != Some("aes-256-gcm") {
                                    return Err(invalid("Profiles need an aes-256-gcm key").into());
                                }
                                // Whoever binds a key to a profile must be able to use it for exactly this (and every
                                // caller will).
                                let key_json = key_value(&key);
                                let aliases = alias_names(&tx, &key_json).await?;
                                let target = Target {
                                    resource_id: format!("kms/{}", key.id),
                                    attributes: key_attributes(&key_json, &aliases, None)?,
                                };
                                for action in
                                    [kms_action("generate-data-key")?, kms_action("decrypt")?]
                                {
                                    if !call.allowed(&action, &target).await? {
                                        return Err(OperationDenied::new(Some(
                                            "You may not protect values with that key",
                                        )));
                                    }
                                }
                                key
                            }
                            None => {
                                create_service_key(
                                    &ctx,
                                    &tx,
                                    &json!({
                                        "tenantId": tenant.id,
                                        "keySpec": "aes-256-gcm",
                                        "keyUsage": "encrypt",
                                        "description": format!("Data protection profile: {name}"),
                                        "tags": { "protection-profile": name },
                                        "createdBy": principal.identity.id,
                                        "managedBy": "protection",
                                        "managedId": profile_id,
                                    }),
                                )
                                .await?
                            }
                        };
                        let mut lookup: ServiceDataKey = kms_data_key_for(
                            &ctx,
                            &tx,
                            &tenant.id,
                            &key.id,
                            &context_of(lookup_context(&profile_id)?)?,
                            &service_use(&principal),
                        )
                        .await?;
                        lookup.data_key.fill(0);
                        let now = number(ctx.now());
                        let mut profile = Record::new();
                        profile.insert("id".into(), Value::String(profile_id.clone()));
                        profile.insert("tenantId".into(), Value::String(tenant.id.clone()));
                        profile.insert("uniqueKey".into(), Value::String(format!("name:{name}")));
                        profile.insert("name".into(), Value::String(name.clone()));
                        profile.insert("dataType".into(), data_type_value.clone());
                        profile.insert("format".into(), format.clone());
                        profile.insert("deterministic".into(), Value::Bool(deterministic));
                        profile.insert("keyId".into(), Value::String(key.id.clone()));
                        profile.insert("mask".into(), mask.clone());
                        profile.insert(
                            "lookupKeyWrapped".into(),
                            Value::String(lookup.wrapped.clone()),
                        );
                        profile.insert("tokens".into(), Value::from(0));
                        profile.insert("createdAt".into(), now.clone());
                        profile.insert(
                            "createdBy".into(),
                            Value::String(principal.identity.id.clone()),
                        );
                        profile.insert("updatedAt".into(), now);
                        if let Some(description) = description.filter(|text| !text.is_empty()) {
                            profile.insert("description".into(), Value::String(description));
                        }
                        if let Some(days) = retention_days {
                            profile.insert("retentionDays".into(), number(days));
                        }
                        tx.insert("protectionProfiles", &profile).await?;
                        call.note("profile", Value::String(name.clone()));
                        call.note("dataType", data_type_value.clone());
                        call.note("format", format.clone());
                        call.note("deterministic", Value::Bool(deterministic));
                        call.note("keyId", Value::String(key.id.clone()));
                        Ok(summary(&profile)?)
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `protection/deleteProfile`: deletes a profile that holds no tokens (delete its tokens first). Requires
    /// iam:protection:manage and recent authentication. A key the profile created is scheduled for deletion (7 days); a
    /// customer key stays.
    pub async fn delete_profile(
        &self,
        credential: &CredentialInput,
        input: Body<protection::DeleteProfileInput>,
    ) -> IamResult<Reply<protection::DeleteProfileOutput>> {
        let ctx = self.ctx.clone();
        let (tenant_id, name) = (
            input.get("tenantId").cloned(),
            input.get("profile").cloned(),
        );
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(protection_action("manage")?),
                move |tx, _principal| Box::pin(profile_target(tx, tenant_id, name, no_extra)),
                move |call, target| {
                    Box::pin(async move {
                        let profile = target.profile();
                        ctx.auth.require_recent(&call.principal)?;
                        if holds_tokens(&call.tx, &profile).await? {
                            return Err(IamError::with_status(
                                "RESOURCE_IN_USE",
                                "The profile still holds tokens",
                                409,
                            )
                            .into());
                        }
                        call.tx
                            .delete("protectionProfiles", &record_text(&profile, "id"))
                            .await?;
                        let deletion_date = retire_service_key(
                            &ctx,
                            &call.tx,
                            &record_text(&profile, "tenantId"),
                            &record_text(&profile, "keyId"),
                            "protection",
                            &record_text(&profile, "id"),
                        )
                        .await?;
                        if let Some(date) = deletion_date {
                            call.note("keyDeletionDate", number(date));
                        }
                        Ok(json!({ "success": true }))
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `protection/deleteTokens`: deletes tokens and their values for good (right to erasure), named by `tokens` or by
    /// `values` (every token issued for each value, found by its keyed fingerprint, which needs the profile's key
    /// enabled). Up to 100 either way. Requires iam:protection:delete on the profile.
    pub async fn delete_tokens(
        &self,
        credential: &CredentialInput,
        input: Body<protection::DeleteTokensInput>,
    ) -> IamResult<Reply<protection::DeleteTokensOutput>> {
        if input.get("tokens").is_none() == input.get("values").is_none() {
            return Err(invalid("Name either tokens or values"));
        }
        let tokens = match input.get("tokens") {
            None => None,
            Some(value) => Some(token_list(Some(value))?),
        };
        let raw = match input.get("values") {
            None => None,
            Some(value) => Some(list(Some(value), "values")?),
        };
        let ctx = self.ctx.clone();
        let (tenant_id, name) = (
            input.get("tenantId").cloned(),
            input.get("profile").cloned(),
        );
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(protection_action("delete")?),
                move |tx, _principal| Box::pin(profile_target(tx, tenant_id, name, no_extra)),
                move |call, target| {
                    Box::pin(async move {
                        let current = target.profile();
                        let tx = call.tx.clone();
                        let mut doomed: Vec<Record> = Vec::new();
                        let by_token = tokens.is_some();
                        if let Some(tokens) = &tokens {
                            doomed.extend(records_of(&tx, &current, tokens).await?.into_values());
                        } else {
                            let data_type = member_or(&current, "dataType", Value::Null);
                            let mut values = IndexSet::new();
                            for item in raw.unwrap_or_default() {
                                values.insert(normalize_value(&data_type, Some(&item))?);
                            }
                            let mut key = lookup_key(&ctx, &tx, &current, &call.principal).await?;
                            let found: IamResult<()> = async {
                                for value in &values {
                                    doomed.extend(
                                        tx.find(
                                            "protectionTokens",
                                            &Filter::new()
                                                .eq(
                                                    "tenantId",
                                                    member_or(&current, "tenantId", Value::Null),
                                                )
                                                .eq(
                                                    "profileId",
                                                    member_or(&current, "id", Value::Null),
                                                )
                                                .eq("fingerprint", fingerprint(&key, value)?),
                                            &FindOptions::default(),
                                        )
                                        .await?,
                                    );
                                }
                                Ok(())
                            }
                            .await;
                            key.fill(0);
                            found?;
                        }
                        for record in &doomed {
                            tx.delete("protectionTokens", &record_text(record, "id"))
                                .await?;
                        }
                        if !doomed.is_empty() {
                            let mut next = current.clone();
                            next.insert(
                                "tokens".into(),
                                minus(current.get("tokens"), doomed.len() as f64),
                            );
                            tx.put("protectionProfiles", &next).await?;
                        }
                        call.note("deleted", Value::from(doomed.len()));
                        call.note(
                            "by",
                            Value::String(if by_token { "token" } else { "value" }.into()),
                        );
                        Ok(json!({ "deleted": doomed.len() }))
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `protection/detokenize`: turns up to 100 tokens of one profile back into their values, in order (`null` for
    /// tokens the profile does not hold). `purpose` (a short lowercase name, such as `payment-processing`) is required:
    /// policies read it as `resource.purpose` and the audit records it, refusals included. Requires
    /// iam:protection:detokenize on the profile (and iam:kms:decrypt on a customer key).
    pub async fn detokenize(
        &self,
        credential: &CredentialInput,
        input: Body<protection::DetokenizeInput>,
    ) -> IamResult<Reply<protection::DetokenizeOutput>> {
        let tokens = token_list(input.get("tokens"))?;
        let purpose = purpose_of(input.get("purpose"))?;
        let ctx = self.ctx.clone();
        let (tenant_id, name) = (
            input.get("tenantId").cloned(),
            input.get("profile").cloned(),
        );
        let extra_purpose = purpose.clone();
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(protection_action("detokenize")?),
                move |tx, _principal| {
                    Box::pin(profile_target(tx, tenant_id, name, move |_profile| {
                        let mut extra = Map::new();
                        extra.insert("purpose".into(), Value::String(extra_purpose));
                        Ok(extra)
                    }))
                },
                move |call, target| {
                    Box::pin(async move {
                        let profile = target.profile();
                        require_key_use(&call, &profile, &kms_action("decrypt")?).await?;
                        let records = records_of(&call.tx, &profile, &tokens).await?;
                        let opened = open_all(
                            &ctx,
                            &call.tx,
                            &profile,
                            records.values().collect(),
                            &call.principal,
                        )
                        .await?;
                        call.note("purpose", Value::String(purpose.clone()));
                        call.note("count", Value::from(tokens.len()));
                        call.note("found", Value::from(records.len()));
                        let values: Vec<Value> = tokens
                            .iter()
                            .map(|token| {
                                opened
                                    .get(token)
                                    .map_or(Value::Null, |value| Value::String(value.clone()))
                            })
                            .collect();
                        Ok(json!({ "values": values }))
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `protection/getProfile`: one profile, with the number of tokens it holds. Requires iam:protection:read.
    pub async fn get_profile(
        &self,
        credential: &CredentialInput,
        input: Body<protection::GetProfileInput>,
    ) -> IamResult<Reply<protection::GetProfileOutput>> {
        let (tenant_id, name) = (
            input.get("tenantId").cloned(),
            input.get("profile").cloned(),
        );
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(protection_action("read")?),
                move |tx, _principal| Box::pin(profile_target(tx, tenant_id, name, no_extra)),
                move |_call, target| Box::pin(async move { Ok(summary(&target.profile())?) }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `protection/listProfiles`: the tenant's profiles the caller may read (`iam:protection:read`, per profile).
    pub async fn list_profiles(
        &self,
        credential: &CredentialInput,
        input: Body<protection::ListProfilesInput>,
    ) -> IamResult<Reply<protection::ListProfilesOutput>> {
        let items = self
            .guard
            .visible(
                credential,
                input.get("tenantId"),
                &protection_action("read")?,
                "protection",
                move |tx, tenant| {
                    Box::pin(async move {
                        let mut profiles = tx
                            .find(
                                "protectionProfiles",
                                &Filter::new().eq("tenantId", tenant.id.clone()),
                                &FindOptions::default(),
                            )
                            .await?;
                        profiles.sort_by(|a, b| {
                            cmp_utf16(&record_text(a, "name"), &record_text(b, "name"))
                        });
                        profiles
                            .iter()
                            .map(|profile| {
                                Ok((
                                    summary(profile)?,
                                    Target {
                                        resource_id: format!(
                                            "protection/{}",
                                            js_string(profile.get("name"))
                                        ),
                                        attributes: profile_attributes(profile, Map::new()),
                                    },
                                ))
                            })
                            .collect::<IamResult<Vec<_>>>()
                    })
                },
            )
            .await?;
        Ok(Reply::json(Value::Array(items)))
    }

    /// `protection/mask`: the masked form of up to 100 tokens' values, for display (`**** **** **** 4242`,
    /// `j***@example.com`), with the profile's mask or `style` (one its data type allows). Policies see the style used
    /// as `resource.style`. A mask never shows more than half of a value, except the first six and last four digits of
    /// a long card number. Requires iam:protection:mask (and iam:kms:decrypt on a customer key).
    pub async fn mask(
        &self,
        credential: &CredentialInput,
        input: Body<protection::MaskInput>,
    ) -> IamResult<Reply<protection::MaskOutput>> {
        let tokens = token_list(input.get("tokens"))?;
        let ctx = self.ctx.clone();
        let (tenant_id, name) = (
            input.get("tenantId").cloned(),
            input.get("profile").cloned(),
        );
        let requested = input.get("style").cloned();
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(protection_action("mask")?),
                move |tx, _principal| {
                    Box::pin(profile_target(tx, tenant_id, name, move |profile| {
                        let style = match &requested {
                            None => profile.get("mask").cloned(),
                            Some(value) => Some(mask_style(
                                &member_or(profile, "dataType", Value::Null),
                                Some(value),
                                Some("style"),
                            )?),
                        };
                        let mut extra = Map::new();
                        if let Some(style) = style {
                            extra.insert("style".into(), style);
                        }
                        Ok(extra)
                    }))
                },
                move |call, target| {
                    Box::pin(async move {
                        let profile = target.profile();
                        let style = target.attributes.get("style").cloned();
                        require_key_use(&call, &profile, &kms_action("decrypt")?).await?;
                        let records = records_of(&call.tx, &profile, &tokens).await?;
                        let opened = open_all(
                            &ctx,
                            &call.tx,
                            &profile,
                            records.values().collect(),
                            &call.principal,
                        )
                        .await?;
                        if let Some(style) = &style {
                            call.note("style", style.clone());
                        }
                        call.note("count", Value::from(tokens.len()));
                        call.note("found", Value::from(records.len()));
                        let data_type = member_or(&profile, "dataType", Value::Null);
                        let style = style.unwrap_or(Value::Null);
                        let mut values = Vec::with_capacity(tokens.len());
                        for token in &tokens {
                            values.push(match opened.get(token) {
                                None => Value::Null,
                                Some(value) => {
                                    Value::String(mask_value(&data_type, &style, value)?)
                                }
                            });
                        }
                        Ok(json!({ "values": values }))
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `protection/tokenize`: replaces up to 100 values by tokens, in order. Values are validated and normalized for the
    /// profile's data type (a card number must pass the Luhn check). A deterministic profile returns the token it
    /// already issued for a value; otherwise every call issues new tokens. On a deterministic profile this permission
    /// can test guesses against known tokens, so grant it as narrowly as detokenize (`resource.deterministic`).
    /// Requires iam:protection:tokenize on the profile (and iam:kms:generate-data-key on a customer key); audited with
    /// counts only.
    pub async fn tokenize(
        &self,
        credential: &CredentialInput,
        input: Body<protection::TokenizeInput>,
    ) -> IamResult<Reply<protection::TokenizeOutput>> {
        let raw = list(input.get("values"), "values")?;
        let ctx = self.ctx.clone();
        let (tenant_id, name) = (
            input.get("tenantId").cloned(),
            input.get("profile").cloned(),
        );
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(protection_action("tokenize")?),
                move |tx, _principal| Box::pin(profile_target(tx, tenant_id, name, no_extra)),
                move |call, target| {
                    Box::pin(async move {
                        let current = target.profile();
                        let tx = call.tx.clone();
                        let principal = call.principal.clone();
                        let data_type = member_or(&current, "dataType", Value::Null);
                        let format = member_or(&current, "format", Value::Null);
                        let tenant_id = record_text(&current, "tenantId");
                        let profile_id = record_text(&current, "id");
                        let values = raw
                            .iter()
                            .map(|value| normalize_value(&data_type, Some(value)))
                            .collect::<IamResult<Vec<String>>>()?;
                        if format.as_str() == Some("format-preserving") {
                            for value in &values {
                                if !format_preserving_space(&data_type, value)? {
                                    return Err(invalid(
                                        "Format-preserving generic values need at least 12 letters or digits; use a random profile",
                                    )
                                    .into());
                                }
                            }
                        }
                        require_key_use(&call, &current, &kms_action("generate-data-key")?)
                            .await?;
                        let mut key = lookup_key(&ctx, &tx, &current, &principal).await?;
                        let mut tokens: Vec<Value> = Vec::new();
                        let mut issued: IndexMap<String, Value> = IndexMap::new();
                        let mut batch: Option<ServiceDataKey> = None;
                        let mut created = 0usize;
                        let outcome: IamResult<()> = async {
                            for value in &values {
                                let print = fingerprint(&key, value)?;
                                if truthy(current.get("deterministic")) {
                                    let known = match issued.get(&print) {
                                        Some(token) => Some(token.clone()),
                                        None => tx
                                            .find(
                                                "protectionTokens",
                                                &Filter::new()
                                                    .eq("tenantId", tenant_id.clone())
                                                    .eq("profileId", profile_id.clone())
                                                    .eq("fingerprint", print.clone()),
                                                &FindOptions::default(),
                                            )
                                            .await?
                                            .into_iter()
                                            .next()
                                            .and_then(|record| record.get("token").cloned()),
                                    };
                                    if let Some(known) = known.filter(|known| truthy(Some(known)))
                                    {
                                        tokens.push(known.clone());
                                        issued.insert(print, known);
                                        continue;
                                    }
                                }
                                if batch.is_none() {
                                    batch = Some(
                                        kms_data_key_for(
                                            &ctx,
                                            &tx,
                                            &tenant_id,
                                            &record_text(&current, "keyId"),
                                            &batch_context(&profile_id),
                                            &service_use(&principal),
                                        )
                                        .await?,
                                    );
                                }
                                let mut token: Option<String> = None;
                                let mut attempt = 0;
                                while attempt < 10 && token.is_none() {
                                    let candidate = new_token(&data_type, &format, value)?;
                                    let taken = tx
                                        .find(
                                            "protectionTokens",
                                            &Filter::new()
                                                .eq("tenantId", tenant_id.clone())
                                                .eq("uniqueKey", token_key(&profile_id, &candidate)?),
                                            &FindOptions::default(),
                                        )
                                        .await?
                                        .len();
                                    if taken == 0
                                        && !issued
                                            .values()
                                            .any(|known| known.as_str() == Some(candidate.as_str()))
                                    {
                                        token = Some(candidate);
                                    }
                                    attempt += 1;
                                }
                                let Some(token) = token else {
                                    return Err(IamError::with_status(
                                        "CONFLICT",
                                        "No free token could be found for a value",
                                        409,
                                    ));
                                };
                                let batch = batch.as_ref().expect("the batch data key");
                                let mut record = Record::new();
                                record.insert("id".into(), Value::String(id()));
                                record.insert("tenantId".into(), Value::String(tenant_id.clone()));
                                record.insert(
                                    "uniqueKey".into(),
                                    Value::String(token_key(&profile_id, &token)?),
                                );
                                record.insert("profileId".into(), Value::String(profile_id.clone()));
                                record.insert("token".into(), Value::String(token.clone()));
                                record.insert("fingerprint".into(), Value::String(print.clone()));
                                record.insert("wrapped".into(), Value::String(batch.wrapped.clone()));
                                record.insert(
                                    "sealed".into(),
                                    Value::String(seal_value(
                                        &batch.data_key,
                                        &tenant_id,
                                        &profile_id,
                                        &token,
                                        value,
                                    )?),
                                );
                                record.insert("createdAt".into(), number(ctx.now()));
                                record.insert(
                                    "createdBy".into(),
                                    Value::String(principal.identity.id.clone()),
                                );
                                tx.insert("protectionTokens", &record).await?;
                                issued.insert(print, Value::String(token.clone()));
                                tokens.push(Value::String(token));
                                created += 1;
                            }
                            Ok(())
                        }
                        .await;
                        key.fill(0);
                        if let Some(batch) = batch.as_mut() {
                            batch.data_key.fill(0);
                        }
                        outcome?;
                        if created > 0 {
                            let mut next = current.clone();
                            next.insert("tokens".into(), plus(current.get("tokens"), created as f64));
                            tx.put("protectionProfiles", &next).await?;
                        }
                        // Whether a value was known already stays in the audit trail: callers would learn who else is
                        // stored.
                        call.note("count", Value::from(values.len()));
                        call.note("created", Value::from(created));
                        Ok(json!({ "tokens": tokens }))
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `protection/updateProfile`: changes a profile's description, mask or retention (`retentionDays: null` keeps
    /// tokens until deleted). The data type, format and key never change: tokens already issued depend on them.
    /// Requires iam:protection:manage; setting or shortening retention deletes tokens, so it also needs
    /// iam:protection:delete and recent authentication.
    pub async fn update_profile(
        &self,
        credential: &CredentialInput,
        input: Body<protection::UpdateProfileInput>,
    ) -> IamResult<Reply<protection::UpdateProfileOutput>> {
        let ctx = self.ctx.clone();
        let (tenant_id, name) = (
            input.get("tenantId").cloned(),
            input.get("profile").cloned(),
        );
        let description = input.get("description").cloned();
        let mask = input.get("mask").cloned();
        let retention = input.get("retentionDays").cloned();
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(protection_action("manage")?),
                move |tx, _principal| Box::pin(profile_target(tx, tenant_id, name, no_extra)),
                move |call, target| {
                    Box::pin(async move {
                        let profile = target.profile();
                        let mut next = profile.clone();
                        next.insert("updatedAt".into(), number(ctx.now()));
                        match &description {
                            Some(Value::Null) => {
                                next.shift_remove("description");
                            }
                            Some(value) => {
                                next.insert(
                                    "description".into(),
                                    Value::String(text(Some(value), "description", 512)?),
                                );
                            }
                            None => {}
                        }
                        if let Some(value) = &mask {
                            next.insert(
                                "mask".into(),
                                mask_style(
                                    &member_or(&profile, "dataType", Value::Null),
                                    Some(value),
                                    None,
                                )?,
                            );
                        }
                        match &retention {
                            Some(Value::Null) => {
                                next.shift_remove("retentionDays");
                            }
                            Some(value) => {
                                let days = integer(Some(value), "retentionDays", 1.0, 3650.0)?;
                                let shortens = match profile.get("retentionDays") {
                                    None => true,
                                    Some(current) => days < to_number(current),
                                };
                                if shortens {
                                    if !call
                                        .allowed(&protection_action("delete")?, &target)
                                        .await?
                                    {
                                        return Err(OperationDenied::new(Some(
                                            "Setting or shortening retention deletes tokens: it needs iam:protection:delete",
                                        )));
                                    }
                                    ctx.auth.require_recent(&call.principal)?;
                                }
                                next.insert("retentionDays".into(), number(days));
                            }
                            None => {}
                        }
                        call.tx.put("protectionProfiles", &next).await?;
                        if let Some(mask) = next.get("mask") {
                            call.note("mask", mask.clone());
                        }
                        if let Some(days) = next.get("retentionDays") {
                            call.note("retentionDays", days.clone());
                        }
                        Ok(summary(&next)?)
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// One page of a retention sweep.
struct SweepPage {
    count: usize,
    last: Option<String>,
    full: bool,
}

/// `sweepTokens(ctx, input)`: deletes tokens past their profile's retention, a batch per transaction (so the write
/// lock is never held for a whole profile), and audits each profile swept as `protection:retention-sweep`.
pub async fn sweep_tokens(ctx: &Arc<ServerContext>, input: Option<&Value>) -> IamResult<Value> {
    let tenant_input = input.and_then(|input| input.get("tenantId")).cloned();
    let profiles = ctx
        .store
        .transaction(|tx| {
            let tenant_input = tenant_input.clone();
            async move {
                let filter = if truthy(tenant_input.as_ref()) {
                    Filter::new().eq("tenantId", text256(tenant_input.as_ref(), "tenantId")?)
                } else {
                    Filter::new()
                };
                tx.find("protectionProfiles", &filter, &FindOptions::default())
                    .await
            }
        })
        .await?;
    let mut deleted = 0usize;
    let mut swept = 0usize;
    for listed in &profiles {
        if listed.get("retentionDays").is_none() {
            continue;
        }
        swept += 1;
        let listed_id = record_text(listed, "id");
        let mut removed = 0usize;
        let mut after: Option<String> = None;
        loop {
            let page = ctx
                .store
                .transaction(|tx| {
                    let (listed_id, after) = (listed_id.clone(), after.clone());
                    async move {
                        let Some(profile) = tx.get("protectionProfiles", &listed_id).await? else {
                            return Ok(None);
                        };
                        let Some(retention) = profile.get("retentionDays") else {
                            return Ok(None);
                        };
                        let cutoff = ctx.now() - to_number(retention) * DAY;
                        let records = tx
                            .find(
                                "protectionTokens",
                                &Filter::new()
                                    .eq("tenantId", member_or(&profile, "tenantId", Value::Null))
                                    .eq("profileId", member_or(&profile, "id", Value::Null)),
                                &FindOptions {
                                    limit: Some(SWEEP_BATCH as i64),
                                    after,
                                    ..FindOptions::default()
                                },
                            )
                            .await?;
                        let mut count = 0usize;
                        for record in &records {
                            if numeric(record.get("createdAt")) <= cutoff {
                                tx.delete("protectionTokens", &record_text(record, "id"))
                                    .await?;
                                count += 1;
                            }
                        }
                        if count > 0 {
                            let mut next = profile.clone();
                            next.insert(
                                "tokens".into(),
                                minus(profile.get("tokens"), count as f64),
                            );
                            tx.put("protectionProfiles", &next).await?;
                        }
                        Ok(Some(SweepPage {
                            count,
                            last: records
                                .last()
                                .and_then(|record| record.get("id"))
                                .map(|id| js_string(Some(id))),
                            full: records.len() == SWEEP_BATCH,
                        }))
                    }
                })
                .await?;
            let Some(page) = page else { break };
            removed += page.count;
            match page.last {
                Some(last) if page.full => after = Some(last),
                _ => break,
            }
        }
        if removed > 0 {
            let mut metadata = Map::new();
            metadata.insert("deleted".into(), Value::from(removed));
            metadata.insert(
                "retentionDays".into(),
                member_or(listed, "retentionDays", Value::Null),
            );
            let mut event = Record::new();
            event.insert("id".into(), Value::String(id()));
            event.insert(
                "tenantId".into(),
                listed.get("tenantId").cloned().unwrap_or(Value::Null),
            );
            event.insert(
                "actorId".into(),
                Value::String("deployment-operator".into()),
            );
            event.insert(
                "action".into(),
                Value::String("protection:retention-sweep".into()),
            );
            event.insert(
                "resourceId".into(),
                Value::String(format!("protection/{}", js_string(listed.get("name")))),
            );
            event.insert("timestamp".into(), number(ctx.now()));
            event.insert("outcome".into(), Value::String("allow".into()));
            event.insert("metadata".into(), Value::Object(metadata));
            ctx.store
                .transaction(|tx| {
                    let event = event.clone();
                    async move { ctx.events()?.record_audit(&tx, &event).await }
                })
                .await?;
        }
        deleted += removed;
    }
    Ok(json!({ "deleted": deleted, "profiles": swept }))
}

/// `iam.protection`: the retention job. Applications use `api.protection`.
pub struct ProtectionRuntime {
    ctx: Arc<ServerContext>,
}

/// `createProtectionRuntime(ctx)`.
pub fn create_protection_runtime(ctx: &Arc<ServerContext>) -> IamResult<ProtectionRuntime> {
    Ok(ProtectionRuntime { ctx: ctx.clone() })
}

impl ProtectionRuntime {
    /// Deletes tokens older than their profile's `retentionDays` (run daily).
    pub async fn sweep(&self, input: Option<&Value>) -> IamResult<Value> {
        sweep_tokens(&self.ctx, input).await
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        match method {
            "sweep" => {
                let input = args.first().filter(|value| !value.is_null());
                Some(self.sweep(input).await)
            }
            _ => None,
        }
    }
}
