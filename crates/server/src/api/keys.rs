//! Port of `packages/server/src/api/keys.ts`: the `keys` API group (key management) and the scheduler job
//! `iam.kms.maintain()`.
//!
//! Key management (KMS). Keys belong to a tenant and are addressed by id or `alias/{name}`; policies name them as
//! `iam/kms/{keyId}` and may condition on `resource.keySpec`, `resource.keyUsage`, `resource.keyState`,
//! `resource.aliases`, `resource.tags.{key}`, `resource.encryptionContext.{key}` / `resource.encryptionContextKeys`
//! and, for signatures, `resource.algorithm`. Every call is authorized and audited (actions `iam:kms:*`, resource
//! `kms/{keyId}`, never the plaintext); a key grant allows named operations to one identity when no policy does,
//! within the caller's boundaries. Sessions viewing as someone else ("impersonation") are refused.
//!
//! Keys, aliases and grants are read and written as raw JSON records, so member order and members this port does
//! not know survive a round trip (a mixed fleet shares the database with TypeScript).

use std::sync::Arc;

use better_iam_auth::crypto::random_bytes;
use better_iam_auth::util::{base64_padded, base64url, node_base64_decode};
use better_iam_core::js::{cmp_utf16, number_to_string};
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, Identity, IdentityStatus, Record, TenantStatus,
};
use better_iam_types::api::keys;
use futures::future::BoxFuture;
use indexmap::{IndexMap, IndexSet};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply};
use crate::context::{ServerContext, Store};
use crate::contracts::{OperationDenied, OperationResult};
use crate::guarded::{
    Guard, GuardAction, GuardCall, GuardOptions, GuardTarget, Target, create_guard,
};
use crate::js::{internal_error, js_string, number, truthy};
use crate::kms::{
    CiphertextHeader, EncryptionContext, KMS_ACTIONS, KmsGrant, KmsKey, KmsKeyVersion,
    MAX_ALIASES_PER_KEY, MAX_GRANTS_PER_KEY, MAX_KEYS_PER_TENANT, MAX_MESSAGE_BYTES,
    MAX_PLAINTEXT_BYTES, MAX_VERSIONS, acts_in_own_right, add_key_version, algorithms_for,
    alias_names, assert_unmanaged, assert_usable, base64_bytes, base64url_chars, candidate_grants,
    decrypt_with, encrypt_with, encryption_context, find_key, find_key_record, fingerprint,
    grant_constraints, grant_operation_for, grant_operations, is_alias, key_attributes, key_json,
    key_spec, key_tags, key_usage_for, key_version, kms_action, mac_with, parse_ciphertext,
    parse_kid_typed, payload, public_jwk, request_attributes, same_bytes, sign_with,
    signing_algorithm, spec_family, summarize_grant, summarize_key, verify_with,
};
use crate::port::decode;
use crate::utils::id;
use crate::validation::{integer, object, text};

const DAY: f64 = 86_400_000.0;

/// `KeyTarget`: the audited resource (`kms`, the tenant's key collection, or `kms/{keyId}`), the attributes policies
/// see, and the located key.
#[derive(Debug, Clone, Default)]
pub struct KeyTarget {
    resource_id: String,
    attributes: Map<String, Value>,
    /// The key as stored (kept raw for read-modify-write).
    record: Option<Record>,
    key: Option<KmsKey>,
    aliases: Option<Vec<String>>,
    /// The call's encryption context, for context-constrained grants.
    context: Option<EncryptionContext>,
}

impl GuardTarget for KeyTarget {
    fn resource_id(&self) -> &str {
        &self.resource_id
    }
    fn attributes(&self) -> &Map<String, Value> {
        &self.attributes
    }
}

impl KeyTarget {
    /// The located key (`key!`).
    fn key(&self) -> IamResult<KmsKey> {
        self.key.clone().ok_or_else(internal_error)
    }
    /// The located key as stored.
    fn record(&self) -> IamResult<Record> {
        self.record.clone().ok_or_else(internal_error)
    }
    /// The key's aliases (`aliases!`).
    fn aliases(&self) -> Vec<String> {
        self.aliases.clone().unwrap_or_default()
    }
}

/// `{ context?, algorithm? }`: what a call adds to a key's attributes.
#[derive(Debug, Clone, Default)]
struct KeyExtra {
    context: Option<EncryptionContext>,
    algorithm: Option<String>,
}

impl KeyExtra {
    fn context(context: &EncryptionContext) -> Self {
        Self {
            context: Some(context.clone()),
            algorithm: None,
        }
    }
    fn algorithm(algorithm: String) -> Self {
        Self {
            context: None,
            algorithm: Some(algorithm),
        }
    }
    fn json(&self) -> Value {
        let mut extra = Map::new();
        if let Some(context) = &self.context {
            extra.insert("context".into(), Value::Object(context.extra.clone()));
        }
        if let Some(algorithm) = &self.algorithm {
            extra.insert("algorithm".into(), Value::String(algorithm.clone()));
        }
        Value::Object(extra)
    }
}

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// A typed value as the JSON TypeScript returns (integral numbers without a fraction).
fn js_value<T: Serialize>(value: &T) -> Value {
    fn normalize(value: Value) -> Value {
        match value {
            Value::Number(n) => match n.as_f64() {
                Some(float) if n.is_f64() => number(float),
                _ => Value::Number(n),
            },
            Value::Array(items) => Value::Array(items.into_iter().map(normalize).collect()),
            Value::Object(map) => {
                Value::Object(map.into_iter().map(|(k, v)| (k, normalize(v))).collect())
            }
            other => other,
        }
    }
    normalize(serde_json::to_value(value).unwrap_or(Value::Null))
}

fn summary_json(key: &KmsKey, aliases: &[String]) -> IamResult<Value> {
    Ok(js_value(&summarize_key(key, aliases)?))
}

fn optional_text(value: Option<&Value>, name: &str, max: usize) -> IamResult<Option<String>> {
    match value {
        None => Ok(None),
        Some(value) => Ok(Some(
            better_iam_core::js::trim(&text(Some(value), name, max)?).to_owned(),
        )),
    }
}

fn alias_name(value: Option<&Value>) -> IamResult<String> {
    let name = text(value, "alias", 256)?;
    if !is_alias(&name) {
        return Err(invalid(
            "alias must be alias/{name} with letters, digits, slashes, underscores or hyphens",
        ));
    }
    Ok(name)
}

fn rotation_period(value: Option<&Value>) -> IamResult<Option<f64>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => Ok(Some(integer(
            Some(value),
            "rotationPeriodDays",
            1.0,
            3650.0,
        )?)),
    }
}

fn signature_format(value: Option<&Value>) -> IamResult<Value> {
    match value {
        None => Ok(Value::String("der".into())),
        Some(Value::String(format)) if format == "der" || format == "jose" => Ok(value
            .cloned()
            .unwrap_or_else(|| Value::String("der".into()))),
        _ => Err(invalid("format must be der or jose")),
    }
}

/// `/^[A-Za-z0-9]{1,16}$/`.
fn short_algorithm(value: &str) -> bool {
    !value.is_empty() && value.len() <= 16 && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

/// The algorithm a signing call asks for, as `resource.algorithm`: the key's default when none is named, otherwise
/// the name itself (bounded). It is validated against the key only once the call is authorized, so callers without
/// access learn nothing about the key.
fn requested_algorithm(key: &KmsKey, value: Option<&Value>) -> IamResult<String> {
    let Some(value) = value else {
        return Ok(algorithms_for(key.spec(), key.usage())?
            .into_iter()
            .next()
            .unwrap_or_else(|| "none".into()));
    };
    Ok(match value {
        Value::String(name) if short_algorithm(name) => name.clone(),
        _ => "invalid".into(),
    })
}

/// What a token names, as `resource.jwt.*`, so policies can limit the tokens a caller mints.
fn jwt_attributes(claims: &Map<String, Value>, kind: &str) -> Map<String, Value> {
    let mut attributes = Map::new();
    attributes.insert("jwt".into(), Value::Bool(true));
    attributes.insert("jwt.typ".into(), Value::String(kind.into()));
    for name in ["sub", "iss"] {
        if let Some(Value::String(value)) = claims.get(name) {
            attributes.insert(format!("jwt.{name}"), Value::String(value.clone()));
        }
    }
    match claims.get("aud") {
        Some(Value::String(audience)) => {
            attributes.insert("jwt.aud".into(), Value::String(audience.clone()));
        }
        Some(Value::Array(items)) => {
            let mut audiences: Vec<String> = items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect();
            audiences.sort_by(|a, b| cmp_utf16(a, b));
            attributes.insert("jwt.audiences".into(), json!(audiences));
        }
        _ => {}
    }
    attributes
}

fn json_segment(value: &str, name: &str) -> IamResult<Map<String, Value>> {
    let refused = || invalid(format!("The token {name} is not valid JSON"));
    let decoded = String::from_utf8_lossy(&node_base64_decode(value)).into_owned();
    let parsed = better_iam_core::js::parse(&decoded).map_err(|_| refused())?;
    object(Some(&parsed)).cloned().map_err(|_| refused())
}

/// JavaScript strict equality of two JSON values (`undefined` is None).
fn strict_equal(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(Value::Number(a)), Some(Value::Number(b))) => a.as_f64() == b.as_f64(),
        (Some(Value::Object(_) | Value::Array(_)), _)
        | (_, Some(Value::Object(_) | Value::Array(_))) => false,
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// `b.createdAt - a.createdAt || (a.id < b.id ? -1 : 1)`: newest first, ties by id.
fn newest_first(a: &Record, b: &Record) -> std::cmp::Ordering {
    let created = |record: &Record| {
        record
            .get("createdAt")
            .and_then(Value::as_f64)
            .unwrap_or(f64::NAN)
    };
    match created(b).partial_cmp(&created(a)) {
        Some(std::cmp::Ordering::Equal) | None => {
            if cmp_utf16(&js_string(a.get("id")), &js_string(b.get("id")))
                == std::cmp::Ordering::Less
            {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        }
        Some(order) => order,
    }
}

/// Versions sorted `b.version - a.version` (newest first).
fn by_version_desc(a: &KmsKeyVersion, b: &KmsKeyVersion) -> std::cmp::Ordering {
    b.version
        .partial_cmp(&a.version)
        .unwrap_or(std::cmp::Ordering::Equal)
}

/// Locates a key (id or alias) with its aliases and policy attributes (`keyTarget(tenantId, reference, extra)`).
async fn key_target(
    tx: Store,
    tenant_id: Option<Value>,
    reference: Option<Value>,
    extra: KeyExtra,
) -> IamResult<KeyTarget> {
    let tenant_id = text(tenant_id.as_ref(), "tenantId", 256)?;
    let record = find_key_record(&tx, &tenant_id, reference.as_ref()).await?;
    let key: KmsKey = decode(record.clone())?;
    let key_value = Value::Object(record.clone());
    let aliases = alias_names(&tx, &key_value).await?;
    Ok(KeyTarget {
        resource_id: format!("kms/{}", key.id),
        attributes: key_attributes(&key_value, &aliases, Some(&extra.json()))?,
        record: Some(record),
        key: Some(key),
        aliases: Some(aliases),
        context: extra.context,
    })
}

/// `saveKey(tx, key, changes)`: `{ ...key, ...changes, updatedAt }`, removing the members a change leaves undefined.
async fn save_key(
    ctx: &ServerContext,
    tx: &Store,
    record: &Record,
    changes: Vec<(&str, Option<Value>)>,
) -> IamResult<(Record, KmsKey)> {
    let mut next = record.clone();
    for (name, value) in changes {
        match value {
            Some(value) => {
                next.insert(name.into(), value);
            }
            None => {
                next.shift_remove(name);
            }
        }
    }
    next.insert("updatedAt".into(), number(ctx.now()));
    tx.put("kmsKeys", &next).await?;
    let key = decode(next.clone())?;
    Ok((next, key))
}

fn state_change(key: &KmsKey, allowed_from: &[&str], verb: &str) -> IamResult<()> {
    if !allowed_from.contains(&key.state_name()) {
        return Err(IamError::with_status(
            "KEY_STATE_INVALID",
            format!(
                "A key that is {} cannot be {verb}",
                key.state_name().replacen('-', " ", 1)
            ),
            409,
        ));
    }
    Ok(())
}

async fn rotate_key(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    record: &Record,
    key: &KmsKey,
    origin: &str,
) -> IamResult<(Record, KmsKey)> {
    if key.current_version >= MAX_VERSIONS {
        return Err(IamError::with_status(
            "LIMIT_EXCEEDED",
            format!(
                "A key keeps at most {} versions",
                number_to_string(MAX_VERSIONS)
            ),
            409,
        ));
    }
    let version = key.current_version + 1.0;
    add_key_version(ctx, tx, &Value::Object(record.clone()), version, origin).await?;
    let now = ctx.now();
    let mut changes = vec![
        ("currentVersion", Some(number(version))),
        ("lastRotatedAt", Some(number(now))),
    ];
    if let Some(period) = key.rotation_period_days {
        changes.push(("nextRotationAt", Some(number(now + period * DAY))));
    }
    save_key(ctx, tx, record, changes).await
}

/// Alias names are a namespace of their own: creating, moving or removing `alias/{name}` also needs iam:kms:update
/// on `iam/kms/alias/{name}` (`resource.alias`), so whoever manages one key cannot claim a name others rely on.
async fn assert_alias_allowed(call: &GuardCall<KeyTarget>, name: &str) -> OperationResult<()> {
    let mut attributes = Map::new();
    attributes.insert("alias".into(), Value::String(name.into()));
    let target = Target {
        resource_id: format!("kms/{name}"),
        attributes,
    };
    if !call.allowed(kms_action("update"), &target).await? {
        return Err(OperationDenied::new(Some(&format!(
            "You may not manage the alias {name}"
        ))));
    }
    Ok(())
}

/// How a key looks to policies: its tags and aliases.
struct KeyView<'a> {
    tags: &'a Value,
    aliases: &'a [String],
}

/// Changing what a key looks like to policies (its tags, its aliases) must not hand the caller rights on it: every
/// KMS action they may not take on the key as it is stays refused on the key as it would be. Otherwise someone who
/// manages every key but may decrypt only one team's could retag a key into that team, or drop the alias a deny
/// names.
async fn assert_no_new_rights(
    call: &GuardCall<KeyTarget>,
    record: &Record,
    before: KeyView<'_>,
    after: KeyView<'_>,
) -> OperationResult<()> {
    let key_id = js_string(record.get("id"));
    let target = |view: &KeyView<'_>| -> IamResult<Target> {
        let mut key = record.clone();
        key.insert("tags".into(), view.tags.clone());
        Ok(Target {
            resource_id: format!("kms/{key_id}"),
            attributes: key_attributes(&Value::Object(key), view.aliases, None)?,
        })
    };
    let (before, after) = (target(&before)?, target(&after)?);
    for (operation, action) in KMS_ACTIONS {
        if operation == "create" {
            continue;
        }
        if !call.allowed(action, &before).await? && call.allowed(action, &after).await? {
            return Err(OperationDenied::new(Some(&format!(
                "That change would give you {action} on this key"
            ))));
        }
    }
    Ok(())
}

/// A grant works only while its creator could make the same call now, with the same key attributes and encryption
/// context: an expired binding, a revoked role, a lapsed activation or a deny added later takes the grant down with
/// it. The creator is evaluated as a plain session of their own (no MFA, no session tags), which fails closed for
/// policies that need more.
async fn creator_still_allowed(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    grant: &KmsGrant,
    action: &str,
    target: &KeyTarget,
) -> IamResult<bool> {
    let creator: Option<Identity> = tx.get_as("identities", &grant.created_by).await?;
    let Some(creator) = creator else {
        return Ok(false);
    };
    if creator.tenant_id != grant.tenant_id
        || creator.status != IdentityStatus::Active
        || ctx.identity_expired(&creator)
    {
        return Ok(false);
    }
    let tenant = ctx.tenant(tx, &grant.tenant_id).await?;
    // Policies alone decide for the creator (no fallback), as `guard.decide(..., false)` does.
    let plain = create_guard::<KeyTarget>(ctx.clone(), "kms", GuardOptions::default());
    let principal = ctx.decisions()?.simulated_principal(&creator, false);
    Ok(plain
        .decide(tx, &principal, &tenant, action, target, false)
        .await?
        .decision
        .allowed)
}

/// The guard's fallback: a live grant to the caller whose creator could still make the call.
async fn grant_fallback(
    ctx: Arc<ServerContext>,
    tx: Store,
    principal: AuthenticatedPrincipal,
    action: String,
    target: KeyTarget,
) -> IamResult<Option<Map<String, Value>>> {
    let (Some(operation), Some(key)) = (grant_operation_for(&action), target.key.as_ref()) else {
        return Ok(None);
    };
    let operation = Value::String(operation.into());
    for grant in candidate_grants(
        &ctx,
        &tx,
        key,
        &principal,
        &operation,
        target.context.as_ref(),
    )
    .await?
    {
        if creator_still_allowed(&ctx, &tx, &grant, &action, &target).await? {
            let mut note = Map::new();
            note.insert("grantId".into(), Value::String(grant.id.clone()));
            return Ok(Some(note));
        }
    }
    Ok(None)
}

fn describe(target: &KeyTarget) -> Map<String, Value> {
    let mut metadata = Map::new();
    if let Some(key) = &target.key {
        metadata.insert("keyId".into(), Value::String(key.id.clone()));
    }
    if let Some(context) = &target.context
        && !context.extra.is_empty()
    {
        metadata.insert(
            "encryptionContext".into(),
            Value::Object(context.extra.clone()),
        );
    }
    metadata
}

/// Plugins see which key and version served a call, never plaintexts, data keys or signed tokens.
fn hook_result(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut rest = map.clone();
            for name in ["plaintext", "plaintextBase64", "token"] {
                rest.shift_remove(name);
            }
            Value::Object(rest)
        }
        // `{ plaintext, ...rest } = array` spreads the array's indexes into an object.
        Value::Array(items) => Value::Object(
            items
                .iter()
                .enumerate()
                .map(|(index, item)| (index.to_string(), item.clone()))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// What a guarded decrypt hands back to the public call (plugins see it without the plaintext).
#[derive(Debug, Clone, Serialize)]
struct Opened {
    plaintext: Vec<u8>,
    text: bool,
    #[serde(rename = "keyId")]
    key_id: String,
    #[serde(rename = "keyVersion")]
    key_version: f64,
}

/// What a guarded encrypt returns.
#[derive(Debug, Clone, Serialize)]
struct Sealed {
    ciphertext: String,
    #[serde(rename = "keyId")]
    key_id: String,
    #[serde(rename = "keyVersion")]
    key_version: f64,
}

/// The `keys` API group (`createKeysApi(ctx)`): one method per route `keys/{method}`.
pub struct KeysApi {
    ctx: Arc<ServerContext>,
    /// The envelope of every KMS call (guarded.rs): authenticate, locate the key, decide, run, audit. A key grant
    /// stands in for a policy grant only when nothing denied the call and every boundary allowed it; a ciphertext
    /// that fails to decrypt after the call was authorized is audited as a denied call.
    guard: Guard<KeyTarget>,
}

/// `createKeysApi(ctx)`.
pub fn create_keys_api(ctx: &Arc<ServerContext>) -> IamResult<KeysApi> {
    let mut recorded_failures = IndexMap::new();
    for (code, reason) in [
        ("INVALID_CIPHERTEXT", "invalid-ciphertext"),
        ("KEY_STATE_INVALID", "key-state"),
        ("KEY_MANAGED", "key-managed"),
    ] {
        recorded_failures.insert(code.to_owned(), reason.to_owned());
    }
    let fallback_ctx = ctx.clone();
    let guard = create_guard(
        ctx.clone(),
        "kms",
        GuardOptions {
            fallback: Some(Arc::new(move |tx, principal, action, target| {
                Box::pin(grant_fallback(
                    fallback_ctx.clone(),
                    tx,
                    principal,
                    action,
                    target,
                ))
            })),
            describe: Some(Arc::new(describe)),
            recorded_failures,
            hook_result: Some(Arc::new(hook_result)),
        },
    );
    Ok(KeysApi {
        ctx: ctx.clone(),
        guard,
    })
}

type Run<R> = Box<
    dyn FnOnce(GuardCall<KeyTarget>, KeyTarget) -> BoxFuture<'static, OperationResult<R>> + Send,
>;

impl KeysApi {
    /// `keyOperation(credential, tenantId, action, keyTarget(tenantId, reference, extra), fn)`.
    async fn key_call<R>(
        &self,
        credential: &CredentialInput,
        tenant_id: Option<&Value>,
        action: &str,
        reference: Option<Value>,
        extra: KeyExtra,
        run: Run<R>,
    ) -> IamResult<R>
    where
        R: Serialize + Send + 'static,
    {
        let tenant = tenant_id.cloned();
        self.guard
            .run(
                credential,
                tenant_id,
                GuardAction::Fixed(action.to_owned()),
                move |tx, _principal| Box::pin(key_target(tx, tenant, reference, extra)),
                run,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn encrypt_call(
        &self,
        credential: &CredentialInput,
        tenant_id: Option<&Value>,
        key_ref: Option<Value>,
        plaintext: Vec<u8>,
        is_text: bool,
        context: EncryptionContext,
        note: Map<String, Value>,
    ) -> IamResult<Sealed> {
        let ctx = self.ctx.clone();
        let extra = KeyExtra::context(&context);
        self.key_call(
            credential,
            tenant_id,
            kms_action("encrypt"),
            key_ref,
            extra,
            Box::new(move |call, target| {
                Box::pin(async move {
                    let key = target.key()?;
                    assert_usable(&key, &Value::String("encrypt".into()))?;
                    assert_unmanaged(&key_json(&key))?;
                    let version =
                        key_version(&call.tx, &key_json(&key), key.current_version).await?;
                    for (name, value) in note {
                        call.note(&name, value);
                    }
                    call.note("keyVersion", number(version.version));
                    Ok(Sealed {
                        ciphertext: encrypt_with(
                            &ctx, &key, &version, &plaintext, is_text, &context,
                        )?,
                        key_id: key.id.clone(),
                        key_version: version.version,
                    })
                })
            }),
        )
        .await
    }

    async fn decrypt_call(
        &self,
        credential: &CredentialInput,
        tenant_id: Option<&Value>,
        ciphertext: Option<&Value>,
        context: EncryptionContext,
        expected_key: Option<Value>,
        note: Map<String, Value>,
    ) -> IamResult<Opened> {
        let parsed: CiphertextHeader = parse_ciphertext(ciphertext)?;
        let ctx = self.ctx.clone();
        let tenant = tenant_id.cloned();
        let locate_parsed = parsed.clone();
        let locate_context = context.clone();
        self.guard
            .run(
                credential,
                tenant_id,
                GuardAction::Fixed(kms_action("decrypt").to_owned()),
                move |tx, _principal| {
                    Box::pin(async move {
                        let target = key_target(
                            tx.clone(),
                            tenant.clone(),
                            Some(Value::String(locate_parsed.key_id.clone())),
                            KeyExtra::context(&locate_context),
                        )
                        .await?;
                        if let Some(expected_key) = expected_key {
                            let tenant_id = text(tenant.as_ref(), "tenantId", 256)?;
                            let expected = find_key(&tx, &tenant_id, Some(&expected_key)).await?;
                            if Some(&expected.id) != target.key.as_ref().map(|key| &key.id) {
                                return Err(IamError::with_status(
                                    "INVALID_CIPHERTEXT",
                                    "The ciphertext was not produced by that key",
                                    400,
                                ));
                            }
                        }
                        Ok(target)
                    })
                },
                move |call: GuardCall<KeyTarget>, target: KeyTarget| {
                    Box::pin(async move {
                        let key = target.key()?;
                        assert_usable(&key, &Value::String("encrypt".into()))?;
                        assert_unmanaged(&key_json(&key))?;
                        let version = key_version(&call.tx, &key_json(&key), parsed.version)
                            .await
                            .map_err(|_| {
                                IamError::with_status(
                                    "INVALID_CIPHERTEXT",
                                    "The ciphertext is not valid",
                                    400,
                                )
                            })?;
                        for (name, value) in note {
                            call.note(&name, value);
                        }
                        call.note("keyVersion", number(version.version));
                        Ok(Opened {
                            plaintext: decrypt_with(&ctx, &key, &version, &parsed, &context)?,
                            text: parsed.text,
                            key_id: key.id.clone(),
                            key_version: version.version,
                        })
                    })
                },
            )
            .await
    }

    /// `keys/cancelDeletion`: cancels a scheduled deletion; the key comes back disabled. Requires iam:kms:delete.
    pub async fn cancel_deletion(
        &self,
        credential: &CredentialInput,
        input: Body<keys::CancelDeletionInput>,
    ) -> IamResult<Reply<keys::CancelDeletionOutput>> {
        let ctx = self.ctx.clone();
        let result = self
            .key_call(
                credential,
                input.get("tenantId"),
                kms_action("delete"),
                input.get("keyId").cloned(),
                KeyExtra::default(),
                Box::new(move |call, target| {
                    Box::pin(async move {
                        let key = target.key()?;
                        state_change(&key, &["pending-deletion"], "restored")?;
                        call.note("cancelled", Value::Bool(true));
                        let (_, saved) = save_key(
                            &ctx,
                            &call.tx,
                            &target.record()?,
                            vec![
                                ("state", Some(Value::String("disabled".into()))),
                                ("deletionDate", None),
                            ],
                        )
                        .await?;
                        Ok(summary_json(&saved, &target.aliases())?)
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/create`: creates a key: `aes-256-gcm` (default; encrypt/decrypt and data keys), `hmac-sha256|384|512`
    /// (MACs), `ecc-p256|p384` and `ed25519` (signatures), or `rsa-2048|3072|4096` with `keyUsage` `encrypt`
    /// (RSA-OAEP) or `sign` (PS256-PS512, RS256-RS512). Policies can require request tags or specs through
    /// `resource.tags.{key}`, `resource.keySpec` and `resource.keyUsage`. Requires iam:kms:create on `iam/kms`;
    /// audited as `iam:kms:create`.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<keys::CreateInput>,
    ) -> IamResult<Reply<keys::CreateOutput>> {
        let default_spec = Value::String("aes-256-gcm".into());
        let spec = key_spec(Some(match input.get("keySpec") {
            None | Some(Value::Null) => &default_spec,
            Some(value) => value,
        }))?;
        let usage = key_usage_for(&spec, input.get("keyUsage"))?;
        let tags = key_tags(input.get("tags"))?;
        let description = optional_text(input.get("description"), "description", 512)?;
        let period = rotation_period(input.get("rotationPeriodDays"))?;
        let alias = match input.get("alias") {
            None => None,
            Some(value) => Some(alias_name(Some(value))?),
        };
        let located = KeyTarget {
            resource_id: "kms".into(),
            attributes: request_attributes(&spec, &usage, &tags)?,
            ..KeyTarget::default()
        };
        let ctx = self.ctx.clone();
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(kms_action("create").to_owned()),
                move |_tx, _principal| Box::pin(async move { Ok(located) }),
                move |call: GuardCall<KeyTarget>, _target: KeyTarget| {
                    Box::pin(async move {
                        let (tx, tenant, principal) =
                            (call.tx.clone(), call.tenant.clone(), call.principal.clone());
                        if let Some(alias) = &alias {
                            assert_alias_allowed(&call, alias).await?;
                        }
                        let existing = tx
                            .find(
                                "kmsKeys",
                                &Filter::new().eq("tenantId", tenant.id.clone()),
                                &FindOptions::default(),
                            )
                            .await?;
                        if existing.len() as f64 >= MAX_KEYS_PER_TENANT {
                            return Err(IamError::with_status(
                                "LIMIT_EXCEEDED",
                                format!(
                                    "A tenant keeps at most {} keys",
                                    number_to_string(MAX_KEYS_PER_TENANT)
                                ),
                                409,
                            )
                            .into());
                        }
                        if let Some(alias) = &alias
                            && !tx
                                .find(
                                    "kmsAliases",
                                    &Filter::new()
                                        .eq("tenantId", tenant.id.clone())
                                        .eq("uniqueKey", alias.clone()),
                                    &FindOptions::default(),
                                )
                                .await?
                                .is_empty()
                        {
                            return Err(IamError::with_status(
                                "CONFLICT",
                                "That alias is already in use",
                                409,
                            )
                            .into());
                        }
                        let now = ctx.now();
                        let key_id = id();
                        let mut key = Record::new();
                        key.insert("id".into(), Value::String(key_id.clone()));
                        key.insert("tenantId".into(), Value::String(tenant.id.clone()));
                        key.insert("keySpec".into(), spec.clone());
                        key.insert("keyUsage".into(), usage.clone());
                        key.insert("state".into(), Value::String("enabled".into()));
                        key.insert("currentVersion".into(), number(1.0));
                        key.insert("tags".into(), json!(tags));
                        key.insert("createdAt".into(), number(now));
                        key.insert(
                            "createdBy".into(),
                            Value::String(principal.identity.id.clone()),
                        );
                        key.insert("updatedAt".into(), number(now));
                        if let Some(description) = description.filter(|text| !text.is_empty()) {
                            key.insert("description".into(), Value::String(description));
                        }
                        if let Some(period) = period {
                            key.insert("rotationPeriodDays".into(), number(period));
                            key.insert("nextRotationAt".into(), number(now + period * DAY));
                        }
                        tx.insert("kmsKeys", &key).await?;
                        add_key_version(&ctx, &tx, &Value::Object(key.clone()), 1.0, "create")
                            .await?;
                        if let Some(alias) = &alias {
                            let mut record = Record::new();
                            record.insert("id".into(), Value::String(id()));
                            record.insert("tenantId".into(), Value::String(tenant.id.clone()));
                            record.insert("uniqueKey".into(), Value::String(alias.clone()));
                            record.insert("name".into(), Value::String(alias.clone()));
                            record.insert("keyId".into(), Value::String(key_id.clone()));
                            record.insert("createdAt".into(), number(now));
                            record.insert(
                                "createdBy".into(),
                                Value::String(principal.identity.id.clone()),
                            );
                            record.insert("updatedAt".into(), number(now));
                            tx.insert("kmsAliases", &record).await?;
                        }
                        call.note("keyId", Value::String(key_id.clone()));
                        call.note("keySpec", spec.clone());
                        call.note("keyUsage", usage.clone());
                        if let Some(alias) = &alias {
                            call.note("alias", Value::String(alias.clone()));
                        }
                        let typed: KmsKey = decode(key)?;
                        Ok(summary_json(
                            &typed,
                            &alias.into_iter().collect::<Vec<_>>(),
                        )?)
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/createAlias`: names a key `alias/{name}` (unique in the tenant, at most 50 per key). Requires
    /// iam:kms:update on the key and on `iam/kms/alias/{name}`.
    pub async fn create_alias(
        &self,
        credential: &CredentialInput,
        input: Body<keys::CreateAliasInput>,
    ) -> IamResult<Reply<keys::CreateAliasOutput>> {
        let name = alias_name(input.get("alias"))?;
        if let Some(Value::String(key_id)) = input.get("keyId")
            && key_id.starts_with("alias/")
        {
            return Err(invalid("keyId must be a key id, not an alias"));
        }
        let ctx = self.ctx.clone();
        let result = self
            .key_call(
                credential,
                input.get("tenantId"),
                kms_action("update"),
                input.get("keyId").cloned(),
                KeyExtra::default(),
                Box::new(move |call, target| {
                    Box::pin(async move {
                        let (tx, tenant, principal) =
                            (call.tx.clone(), call.tenant.clone(), call.principal.clone());
                        let key = target.key()?;
                        let record = target.record()?;
                        let aliases = target.aliases();
                        assert_alias_allowed(&call, &name).await?;
                        if key.state_name() == "pending-deletion" {
                            state_change(&key, &["enabled", "disabled"], "given an alias")?;
                        }
                        if !tx
                            .find(
                                "kmsAliases",
                                &Filter::new()
                                    .eq("tenantId", tenant.id.clone())
                                    .eq("uniqueKey", name.clone()),
                                &FindOptions::default(),
                            )
                            .await?
                            .is_empty()
                        {
                            return Err(IamError::with_status(
                                "CONFLICT",
                                "That alias is already in use",
                                409,
                            )
                            .into());
                        }
                        if aliases.len() as f64 >= MAX_ALIASES_PER_KEY {
                            return Err(IamError::with_status(
                                "LIMIT_EXCEEDED",
                                format!(
                                    "A key has at most {} aliases",
                                    number_to_string(MAX_ALIASES_PER_KEY)
                                ),
                                409,
                            )
                            .into());
                        }
                        let tags = record.get("tags").cloned().unwrap_or(Value::Null);
                        let mut after = aliases.clone();
                        after.push(name.clone());
                        assert_no_new_rights(
                            &call,
                            &record,
                            KeyView {
                                tags: &tags,
                                aliases: &aliases,
                            },
                            KeyView {
                                tags: &tags,
                                aliases: &after,
                            },
                        )
                        .await?;
                        let now = ctx.now();
                        let mut alias = Record::new();
                        alias.insert("id".into(), Value::String(id()));
                        alias.insert("tenantId".into(), Value::String(tenant.id.clone()));
                        alias.insert("uniqueKey".into(), Value::String(name.clone()));
                        alias.insert("name".into(), Value::String(name.clone()));
                        alias.insert("keyId".into(), Value::String(key.id.clone()));
                        alias.insert("createdAt".into(), number(now));
                        alias.insert(
                            "createdBy".into(),
                            Value::String(principal.identity.id.clone()),
                        );
                        alias.insert("updatedAt".into(), number(now));
                        let stored = tx.insert("kmsAliases", &alias).await?;
                        call.note("alias", Value::String(name.clone()));
                        Ok(json!({
                            "name": name,
                            "keyId": stored.get("keyId").cloned().unwrap_or(Value::Null),
                            "createdAt": number(now),
                            "updatedAt": number(now),
                        }))
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/createGrant`: grants an identity (a person, service account or agent) named operations on one key
    /// (`read`, `encrypt`, `decrypt`, `generate-data-key`, `sign`, `verify`, `generate-mac`, `verify-mac`), optionally
    /// until `expiresAt` and, for encryption operations, only with a given encryption context
    /// (`constraints.encryptionContextEquals` / `encryptionContextSubset`). A grant only passes on what its creator
    /// holds: every operation must be allowed to the caller by policy now, and each use checks again that the creator
    /// could still make that very call. Grants never bypass boundaries, explicit denies, or session and key scopes.
    /// Requires iam:kms:grant from a user session or API key acting in its own right; at most 50 per key.
    pub async fn create_grant(
        &self,
        credential: &CredentialInput,
        input: Body<keys::CreateGrantInput>,
    ) -> IamResult<Reply<keys::CreateGrantOutput>> {
        if let Some(kind) = input.get("granteeType")
            && kind.as_str() != Some("identity")
        {
            return Err(invalid(
                "Grants name one identity; grant a group access with a role instead",
            ));
        }
        let grantee_id = text(input.get("granteeId"), "granteeId", 256)?;
        let name = optional_text(input.get("name"), "name", 128)?;
        let operations_input = input.get("operations").cloned();
        let constraints_input = input.get("constraints").cloned();
        let expires_input = input.get("expiresAt").cloned();
        let ctx = self.ctx.clone();
        let result = self
            .key_call(
                credential,
                input.get("tenantId"),
                kms_action("grant"),
                input.get("keyId").cloned(),
                KeyExtra::default(),
                Box::new(move |call, target| {
                    Box::pin(async move {
                        let (tx, tenant, principal) =
                            (call.tx.clone(), call.tenant.clone(), call.principal.clone());
                        let key = target.key()?;
                        let aliases = target.aliases();
                        // A grant is checked against its creator's own access for as long as it lives, so it must be
                        // made by an identity of this tenant acting in its own right, not a role, token or delegated
                        // session.
                        if !acts_in_own_right(&principal)?
                            || principal.identity.tenant_id != tenant.id
                        {
                            return Err(OperationDenied::new(Some(
                                "Create grants from your own session or API key",
                            )));
                        }
                        if key.state_name() == "pending-deletion" {
                            state_change(&key, &["enabled", "disabled"], "granted")?;
                        }
                        assert_unmanaged(&key_json(&key))?;
                        let operations =
                            grant_operations(operations_input.as_ref(), &key.key_usage)?;
                        let constraints =
                            grant_constraints(constraints_input.as_ref(), &operations)?;
                        let expires_at = match &expires_input {
                            None => None,
                            Some(value) => Some(ctx.binding_expiry(Some(value))?),
                        };
                        ctx.active_identity(&tx, &grantee_id, &tenant.id).await?;
                        // Checked with the context the grant is limited to, where it names one exactly.
                        let context = constraints
                            .as_ref()
                            .and_then(|constraints| constraints.encryption_context_equals.clone());
                        let key_value = key_json(&key);
                        for operation in &operations {
                            let operation = js_string(Some(operation));
                            let action = kms_action(&operation);
                            let extra = match &context {
                                Some(context) if operation != "read" => {
                                    json!({ "context": context })
                                }
                                _ => json!({}),
                            };
                            let target = Target {
                                resource_id: format!("kms/{}", key.id),
                                attributes: key_attributes(&key_value, &aliases, Some(&extra))?,
                            };
                            if !call.allowed(action, &target).await? {
                                return Err(OperationDenied::new(Some(&format!(
                                    "You may not grant {operation}: you do not hold it"
                                ))));
                            }
                        }
                        let existing = tx
                            .find(
                                "kmsGrants",
                                &Filter::new()
                                    .eq("tenantId", tenant.id.clone())
                                    .eq("keyId", key.id.clone()),
                                &FindOptions::default(),
                            )
                            .await?;
                        if existing.len() as f64 >= MAX_GRANTS_PER_KEY {
                            return Err(IamError::with_status(
                                "LIMIT_EXCEEDED",
                                format!(
                                    "A key has at most {} grants",
                                    number_to_string(MAX_GRANTS_PER_KEY)
                                ),
                                409,
                            )
                            .into());
                        }
                        let grant_id = id();
                        let mut grant = Record::new();
                        grant.insert("id".into(), Value::String(grant_id.clone()));
                        grant.insert("tenantId".into(), Value::String(tenant.id.clone()));
                        grant.insert("keyId".into(), Value::String(key.id.clone()));
                        grant.insert("granteeType".into(), Value::String("identity".into()));
                        grant.insert("granteeId".into(), Value::String(grantee_id.clone()));
                        grant.insert("operations".into(), Value::Array(operations.clone()));
                        grant.insert("createdAt".into(), number(ctx.now()));
                        grant.insert(
                            "createdBy".into(),
                            Value::String(principal.identity.id.clone()),
                        );
                        if let Some(name) = name.filter(|name| !name.is_empty()) {
                            grant.insert("name".into(), Value::String(name));
                        }
                        if let Some(constraints) = &constraints {
                            grant.insert("constraints".into(), js_value(constraints));
                        }
                        if let Some(expires_at) = expires_at {
                            grant.insert("expiresAt".into(), number(expires_at));
                        }
                        tx.insert("kmsGrants", &grant).await?;
                        call.note("grantId", Value::String(grant_id));
                        call.note("granteeType", Value::String("identity".into()));
                        call.note("granteeId", Value::String(grantee_id.clone()));
                        call.note("operations", Value::Array(operations.clone()));
                        if let Some(constraints) = &constraints {
                            call.note("constraints", js_value(constraints));
                        }
                        if let Some(expires_at) = expires_at {
                            call.note("expiresAt", number(expires_at));
                        }
                        let typed: KmsGrant = decode(grant)?;
                        Ok(js_value(&summarize_grant(&typed, ctx.now())?))
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/decrypt`: decrypts a ciphertext from `encrypt`, `generateDataKey` or `reEncrypt` with the same
    /// `encryptionContext`. Text comes back as `plaintext`, bytes as `plaintextBase64`. The key is read from the
    /// ciphertext; `keyId` (id or alias) additionally insists on it. A wrong context or a tampered ciphertext fails
    /// with `INVALID_CIPHERTEXT` and is audited as a denied decrypt. Requires iam:kms:decrypt.
    pub async fn decrypt(
        &self,
        credential: &CredentialInput,
        input: Body<keys::DecryptInput>,
    ) -> IamResult<Reply<keys::DecryptOutput>> {
        let context = encryption_context(input.get("encryptionContext"), None)?;
        let mut opened = self
            .decrypt_call(
                credential,
                input.get("tenantId"),
                input.get("ciphertext"),
                context,
                input.get("keyId").cloned(),
                Map::new(),
            )
            .await?;
        let mut result = Map::new();
        if opened.text {
            result.insert(
                "plaintext".into(),
                Value::String(String::from_utf8_lossy(&opened.plaintext).into_owned()),
            );
        } else {
            result.insert(
                "plaintextBase64".into(),
                Value::String(base64_padded(&opened.plaintext)),
            );
        }
        result.insert("keyId".into(), Value::String(opened.key_id.clone()));
        result.insert("keyVersion".into(), number(opened.key_version));
        opened.plaintext.fill(0);
        Ok(Reply::json(Value::Object(result)))
    }

    /// `keys/deleteAlias`: removes an alias; the key stays. Requires iam:kms:update on the key it names and on
    /// `iam/kms/alias/{name}`.
    pub async fn delete_alias(
        &self,
        credential: &CredentialInput,
        input: Body<keys::DeleteAliasInput>,
    ) -> IamResult<Reply<keys::DeleteAliasOutput>> {
        let name = alias_name(input.get("alias"))?;
        let reference = Value::String(name.clone());
        let result = self
            .key_call(
                credential,
                input.get("tenantId"),
                kms_action("update"),
                Some(reference),
                KeyExtra::default(),
                Box::new(move |call, target| {
                    Box::pin(async move {
                        let (tx, tenant) = (call.tx.clone(), call.tenant.clone());
                        let record = target.record()?;
                        let aliases = target.aliases();
                        assert_alias_allowed(&call, &name).await?;
                        let tags = record.get("tags").cloned().unwrap_or(Value::Null);
                        let after: Vec<String> = aliases
                            .iter()
                            .filter(|item| **item != name)
                            .cloned()
                            .collect();
                        assert_no_new_rights(
                            &call,
                            &record,
                            KeyView {
                                tags: &tags,
                                aliases: &aliases,
                            },
                            KeyView {
                                tags: &tags,
                                aliases: &after,
                            },
                        )
                        .await?;
                        let alias = tx
                            .find(
                                "kmsAliases",
                                &Filter::new()
                                    .eq("tenantId", tenant.id.clone())
                                    .eq("uniqueKey", name.clone()),
                                &FindOptions::default(),
                            )
                            .await?
                            .into_iter()
                            .next()
                            .ok_or_else(internal_error)?;
                        tx.delete("kmsAliases", &js_string(alias.get("id"))).await?;
                        call.note("alias", Value::String(name.clone()));
                        Ok(json!({ "success": true }))
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `enable` / `disable`: moves an enabled or disabled key to `state`.
    async fn set_state(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        state: &'static str,
    ) -> IamResult<Value> {
        let ctx = self.ctx.clone();
        self.key_call(
            credential,
            input.get("tenantId"),
            kms_action("update"),
            input.get("keyId").cloned(),
            KeyExtra::default(),
            Box::new(move |call, target| {
                Box::pin(async move {
                    let key = target.key()?;
                    state_change(&key, &["enabled", "disabled"], state)?;
                    call.note("state", Value::String(state.into()));
                    let (_, saved) = save_key(
                        &ctx,
                        &call.tx,
                        &target.record()?,
                        vec![("state", Some(Value::String(state.into())))],
                    )
                    .await?;
                    Ok(summary_json(&saved, &target.aliases())?)
                })
            }),
        )
        .await
    }

    /// `keys/disable`: disables a key: every cryptographic call with it is refused (`KEY_STATE_INVALID`) until it is
    /// enabled again, which makes everything encrypted under it unreadable meanwhile. Requires iam:kms:update.
    pub async fn disable(
        &self,
        credential: &CredentialInput,
        input: Body<keys::DisableInput>,
    ) -> IamResult<Reply<keys::DisableOutput>> {
        Ok(Reply::json(
            self.set_state(credential, input.raw(), "disabled").await?,
        ))
    }

    /// `keys/enable`: enables a disabled key. Requires iam:kms:update.
    pub async fn enable(
        &self,
        credential: &CredentialInput,
        input: Body<keys::EnableInput>,
    ) -> IamResult<Reply<keys::EnableOutput>> {
        Ok(Reply::json(
            self.set_state(credential, input.raw(), "enabled").await?,
        ))
    }

    /// `keys/encrypt`: encrypts up to 4 KiB (`plaintext` as UTF-8 text, or `plaintextBase64`) under an encryption
    /// key's current version, bound to the optional `encryptionContext`. Returns a self-describing `ciphertext` (key
    /// and version inside). For larger data encrypt locally with `generateDataKey`. Requires iam:kms:encrypt.
    pub async fn encrypt(
        &self,
        credential: &CredentialInput,
        input: Body<keys::EncryptInput>,
    ) -> IamResult<Reply<keys::EncryptOutput>> {
        let data = payload(input.raw(), "plaintext", MAX_PLAINTEXT_BYTES)?;
        let context = encryption_context(input.get("encryptionContext"), None)?;
        let sealed = self
            .encrypt_call(
                credential,
                input.get("tenantId"),
                input.get("keyId").cloned(),
                data.bytes,
                data.text,
                context,
                Map::new(),
            )
            .await?;
        Ok(Reply::json(js_value(&sealed)))
    }

    /// `keys/generateDataKey`: a fresh data key (`bytes`: 16, 24, 32 (default) or 64) for encrypting large data
    /// locally: the plaintext (`plaintextBase64`, omitted with `includePlaintext: false`) to use and discard, and its
    /// `ciphertext` under the KMS key to store beside the data. Decrypt the stored ciphertext to use it again.
    /// Requires iam:kms:generate-data-key (and iam:kms:decrypt later).
    pub async fn generate_data_key(
        &self,
        credential: &CredentialInput,
        input: Body<keys::GenerateDataKeyInput>,
    ) -> IamResult<Reply<keys::GenerateDataKeyOutput>> {
        let bytes = match input.get("bytes") {
            None | Some(Value::Null) => 32.0,
            Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
            Some(_) => f64::NAN,
        };
        if ![16.0, 24.0, 32.0, 64.0].contains(&bytes) {
            return Err(invalid("bytes must be 16, 24, 32 or 64"));
        }
        let context = encryption_context(input.get("encryptionContext"), None)?;
        let include_plaintext = input.get("includePlaintext") != Some(&Value::Bool(false));
        let ctx = self.ctx.clone();
        let extra = KeyExtra::context(&context);
        let result = self
            .key_call(
                credential,
                input.get("tenantId"),
                kms_action("generate-data-key"),
                input.get("keyId").cloned(),
                extra,
                Box::new(move |call, target| {
                    Box::pin(async move {
                        let key = target.key()?;
                        assert_usable(&key, &Value::String("encrypt".into()))?;
                        assert_unmanaged(&key_json(&key))?;
                        let version =
                            key_version(&call.tx, &key_json(&key), key.current_version).await?;
                        let mut material = random_bytes(bytes as usize);
                        call.note("keyVersion", number(version.version));
                        call.note("bytes", number(bytes));
                        let sealed = encrypt_with(&ctx, &key, &version, &material, false, &context);
                        let result = sealed.map(|ciphertext| {
                            let mut result = Map::new();
                            result.insert("ciphertext".into(), Value::String(ciphertext));
                            if include_plaintext {
                                result.insert(
                                    "plaintextBase64".into(),
                                    Value::String(base64_padded(&material)),
                                );
                            }
                            result.insert("keyId".into(), Value::String(key.id.clone()));
                            result.insert("keyVersion".into(), number(version.version));
                            result.insert("bytes".into(), number(bytes));
                            Value::Object(result)
                        });
                        material.fill(0);
                        Ok(result?)
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/generateMac`: an HMAC (`mac`, base64url) of a message with a MAC key's current version. Requires
    /// iam:kms:generate-mac.
    pub async fn generate_mac(
        &self,
        credential: &CredentialInput,
        input: Body<keys::GenerateMacInput>,
    ) -> IamResult<Reply<keys::GenerateMacOutput>> {
        let message = payload(input.raw(), "message", MAX_MESSAGE_BYTES)?.bytes;
        let ctx = self.ctx.clone();
        let result = self
            .key_call(
                credential,
                input.get("tenantId"),
                kms_action("generate-mac"),
                input.get("keyId").cloned(),
                KeyExtra::default(),
                Box::new(move |call, target| {
                    Box::pin(async move {
                        let key = target.key()?;
                        assert_usable(&key, &Value::String("mac".into()))?;
                        assert_unmanaged(&key_json(&key))?;
                        let version =
                            key_version(&call.tx, &key_json(&key), key.current_version).await?;
                        call.note("keyVersion", number(version.version));
                        Ok(json!({
                            "mac": base64url(mac_with(&ctx, &key_json(&key), &version, &message)?),
                            "algorithm": algorithms_for(key.spec(), key.usage())?.into_iter().next(),
                            "keyId": key.id,
                            "keyVersion": number(version.version),
                        }))
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/get`: one key by id or alias. Requires iam:kms:read (or a grant allowing `read`).
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<keys::GetInput>,
    ) -> IamResult<Reply<keys::GetOutput>> {
        let result = self
            .key_call(
                credential,
                input.get("tenantId"),
                kms_action("read"),
                input.get("keyId").cloned(),
                KeyExtra::default(),
                Box::new(move |_call, target| {
                    Box::pin(async move { Ok(summary_json(&target.key()?, &target.aliases())?) })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/jwks`: every version's public key of an asymmetric key as a JWK Set, for JWT verifiers. Requires
    /// iam:kms:read.
    pub async fn jwks(
        &self,
        credential: &CredentialInput,
        input: Body<keys::JwksInput>,
    ) -> IamResult<Reply<keys::JwksOutput>> {
        let result = self
            .key_call(
                credential,
                input.get("tenantId"),
                kms_action("read"),
                input.get("keyId").cloned(),
                KeyExtra::default(),
                Box::new(move |call, target| {
                    Box::pin(async move {
                        let key = target.key()?;
                        if spec_family(key.spec()) == "aes" || key.usage() == "mac" {
                            return Err(invalid("Symmetric keys have no public key").into());
                        }
                        let mut versions: Vec<KmsKeyVersion> = Vec::new();
                        for record in call
                            .tx
                            .find(
                                "kmsKeyVersions",
                                &Filter::new()
                                    .eq("tenantId", key.tenant_id.clone())
                                    .eq("keyId", key.id.clone()),
                                &FindOptions::default(),
                            )
                            .await?
                        {
                            versions.push(decode(record)?);
                        }
                        versions.sort_by(by_version_desc);
                        let keys = versions
                            .iter()
                            .map(|version| public_jwk(&key, version))
                            .collect::<IamResult<Vec<_>>>()?;
                        Ok(json!({ "keys": keys }))
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/list`: the tenant's keys the caller may read (`iam:kms:read`, evaluated per key so tag-scoped readers
    /// see theirs), newest first, optionally only one `state` or `keyUsage`. Never material.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<keys::ListInput>,
    ) -> IamResult<Reply<keys::ListOutput>> {
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let limit = integer(
            Some(
                input
                    .get("limit")
                    .filter(|v| !v.is_null())
                    .unwrap_or(&json!(100)),
            ),
            "limit",
            1.0,
            1000.0,
        )?;
        let offset = integer(
            Some(
                input
                    .get("offset")
                    .filter(|v| !v.is_null())
                    .unwrap_or(&json!(0)),
            ),
            "offset",
            0.0,
            1_000_000.0,
        )?;
        let state = input.get("state").cloned();
        if let Some(state) = &state
            && !matches!(
                state.as_str(),
                Some("enabled" | "disabled" | "pending-deletion")
            )
        {
            return Err(invalid("Invalid state"));
        }
        let usage = input.get("keyUsage").cloned();
        if let Some(usage) = &usage
            && !matches!(usage.as_str(), Some("encrypt" | "sign" | "mac"))
        {
            return Err(invalid("Invalid keyUsage"));
        }
        let keys = self
            .guard
            .visible(
                credential,
                Some(&Value::String(tenant_id)),
                kms_action("read"),
                "kms",
                move |tx, tenant| {
                    Box::pin(async move {
                        let mut aliases: IndexMap<String, Vec<String>> = IndexMap::new();
                        for alias in tx
                            .find(
                                "kmsAliases",
                                &Filter::new().eq("tenantId", tenant.id.clone()),
                                &FindOptions::default(),
                            )
                            .await?
                        {
                            aliases
                                .entry(js_string(alias.get("keyId")))
                                .or_default()
                                .push(js_string(alias.get("name")));
                        }
                        let mut records: Vec<Record> = tx
                            .find(
                                "kmsKeys",
                                &Filter::new().eq("tenantId", tenant.id.clone()),
                                &FindOptions::default(),
                            )
                            .await?
                            .into_iter()
                            .filter(|key| {
                                state
                                    .as_ref()
                                    .is_none_or(|state| key.get("state") == Some(state))
                                    && usage
                                        .as_ref()
                                        .is_none_or(|usage| key.get("keyUsage") == Some(usage))
                            })
                            .collect();
                        records.sort_by(newest_first);
                        let mut items = Vec::new();
                        for record in records {
                            let key: KmsKey = decode(record.clone())?;
                            let names = aliases.get(&key.id).cloned().unwrap_or_default();
                            items.push((
                                summary_json(&key, &names)?,
                                Target {
                                    resource_id: format!("kms/{}", key.id),
                                    attributes: key_attributes(
                                        &Value::Object(record),
                                        &names,
                                        None,
                                    )?,
                                },
                            ));
                        }
                        Ok(items)
                    })
                },
            )
            .await?;
        let total = keys.len();
        let page: Vec<Value> = keys
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok(Reply::json(json!({ "keys": page, "total": total })))
    }

    /// `keys/listAliases`: every alias of the tenant, or of one key. Requires iam:kms:read on `iam/kms` (or on that
    /// key).
    pub async fn list_aliases(
        &self,
        credential: &CredentialInput,
        input: Body<keys::ListAliasesInput>,
    ) -> IamResult<Reply<keys::ListAliasesOutput>> {
        fn view(mut aliases: Vec<Record>) -> Value {
            aliases.sort_by(|a, b| {
                if cmp_utf16(&js_string(a.get("name")), &js_string(b.get("name")))
                    == std::cmp::Ordering::Less
                {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                }
            });
            Value::Array(
                aliases
                    .into_iter()
                    .map(|alias| {
                        let member = |name: &str| alias.get(name).cloned().unwrap_or(Value::Null);
                        json!({
                            "name": member("name"),
                            "keyId": member("keyId"),
                            "createdAt": member("createdAt"),
                            "updatedAt": member("updatedAt"),
                        })
                    })
                    .collect(),
            )
        }
        let result = if input.get("keyId").is_some() {
            self.key_call(
                credential,
                input.get("tenantId"),
                kms_action("read"),
                input.get("keyId").cloned(),
                KeyExtra::default(),
                Box::new(move |call, target| {
                    Box::pin(async move {
                        let key = target.key()?;
                        let aliases = call
                            .tx
                            .find(
                                "kmsAliases",
                                &Filter::new()
                                    .eq("tenantId", key.tenant_id.clone())
                                    .eq("keyId", key.id.clone()),
                                &FindOptions::default(),
                            )
                            .await?;
                        Ok(view(aliases))
                    })
                }),
            )
            .await?
        } else {
            self.guard
                .run(
                    credential,
                    input.get("tenantId"),
                    GuardAction::Fixed(kms_action("read").to_owned()),
                    move |_tx, _principal| {
                        Box::pin(async move {
                            Ok(KeyTarget {
                                resource_id: "kms".into(),
                                ..KeyTarget::default()
                            })
                        })
                    },
                    move |call: GuardCall<KeyTarget>, _target: KeyTarget| {
                        Box::pin(async move {
                            let aliases = call
                                .tx
                                .find(
                                    "kmsAliases",
                                    &Filter::new().eq("tenantId", call.tenant.id.clone()),
                                    &FindOptions::default(),
                                )
                                .await?;
                            Ok(view(aliases))
                        })
                    },
                )
                .await?
        };
        Ok(Reply::json(result))
    }

    /// `keys/listGrants`: the key's grants, newest first, with `active` (not lapsed). Requires iam:kms:read; a caller
    /// reading through a `read` grant of its own sees only its own grants.
    pub async fn list_grants(
        &self,
        credential: &CredentialInput,
        input: Body<keys::ListGrantsInput>,
    ) -> IamResult<Reply<keys::ListGrantsOutput>> {
        let ctx = self.ctx.clone();
        let result = self
            .key_call(
                credential,
                input.get("tenantId"),
                kms_action("read"),
                input.get("keyId").cloned(),
                KeyExtra::default(),
                Box::new(move |call, target| {
                    Box::pin(async move {
                        let key = target.key()?;
                        let through_grant = call
                            .metadata
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .contains_key("grantId");
                        let mut grants: Vec<Record> = call
                            .tx
                            .find(
                                "kmsGrants",
                                &Filter::new()
                                    .eq("tenantId", key.tenant_id.clone())
                                    .eq("keyId", key.id.clone()),
                                &FindOptions::default(),
                            )
                            .await?
                            .into_iter()
                            .filter(|grant| {
                                !through_grant
                                    || grant.get("granteeId").and_then(Value::as_str)
                                        == Some(call.principal.identity.id.as_str())
                            })
                            .collect();
                        grants.sort_by(newest_first);
                        let mut summaries = Vec::new();
                        for grant in grants {
                            let grant: KmsGrant = decode(grant)?;
                            summaries.push(js_value(&summarize_grant(&grant, ctx.now())?));
                        }
                        Ok(Value::Array(summaries))
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/listVersions`: the key's versions, newest first, with the public key fingerprint of asymmetric ones.
    /// Requires iam:kms:read.
    pub async fn list_versions(
        &self,
        credential: &CredentialInput,
        input: Body<keys::ListVersionsInput>,
    ) -> IamResult<Reply<keys::ListVersionsOutput>> {
        let result = self
            .key_call(
                credential,
                input.get("tenantId"),
                kms_action("read"),
                input.get("keyId").cloned(),
                KeyExtra::default(),
                Box::new(move |call, target| {
                    Box::pin(async move {
                        let key = target.key()?;
                        let mut versions: Vec<KmsKeyVersion> = Vec::new();
                        for record in call
                            .tx
                            .find(
                                "kmsKeyVersions",
                                &Filter::new()
                                    .eq("tenantId", key.tenant_id.clone())
                                    .eq("keyId", key.id.clone()),
                                &FindOptions::default(),
                            )
                            .await?
                        {
                            versions.push(decode(record)?);
                        }
                        versions.sort_by(by_version_desc);
                        let mut out = Vec::new();
                        for version in versions {
                            let mut view = Map::new();
                            view.insert("version".into(), number(version.version));
                            view.insert(
                                "current".into(),
                                Value::Bool(version.version == key.current_version),
                            );
                            view.insert("origin".into(), Value::String(version.origin.clone()));
                            view.insert("createdAt".into(), number(version.created_at));
                            if let Some(pem) = version
                                .public_key_pem
                                .as_deref()
                                .filter(|pem| !pem.is_empty())
                            {
                                view.insert(
                                    "publicKeyFingerprint".into(),
                                    Value::String(fingerprint(pem)?),
                                );
                            }
                            out.push(Value::Object(view));
                        }
                        Ok(Value::Array(out))
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/publicKey`: the public key of an asymmetric key version (default: current) as SPKI PEM and JWK (`kid` =
    /// `{keyId}.{version}`), for verifying signatures or encrypting offline. Requires iam:kms:read.
    pub async fn public_key(
        &self,
        credential: &CredentialInput,
        input: Body<keys::PublicKeyInput>,
    ) -> IamResult<Reply<keys::PublicKeyOutput>> {
        let requested = input.get("keyVersion").cloned();
        let result = self
            .key_call(
                credential,
                input.get("tenantId"),
                kms_action("read"),
                input.get("keyId").cloned(),
                KeyExtra::default(),
                Box::new(move |call, target| {
                    Box::pin(async move {
                        let key = target.key()?;
                        if spec_family(key.spec()) == "aes" || key.usage() == "mac" {
                            return Err(invalid("Symmetric keys have no public key").into());
                        }
                        let number_wanted = match &requested {
                            None => key.current_version,
                            Some(value) => integer(Some(value), "keyVersion", 1.0, MAX_VERSIONS)?,
                        };
                        let version = key_version(&call.tx, &key_json(&key), number_wanted).await?;
                        Ok(json!({
                            "keyId": key.id,
                            "keyVersion": number(version.version),
                            "keySpec": key.key_spec,
                            "keyUsage": key.key_usage,
                            "algorithms": algorithms_for(key.spec(), key.usage())?,
                            "publicKeyPem": version.public_key_pem,
                            "jwk": public_jwk(&key, &version)?,
                        }))
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/reEncrypt`: decrypts and encrypts again under `destinationKeyId` (and context) without the plaintext
    /// leaving the server: for moving data to a new key or context. Needs iam:kms:decrypt on the source key and
    /// iam:kms:encrypt on the destination; audited as both.
    pub async fn re_encrypt(
        &self,
        credential: &CredentialInput,
        input: Body<keys::ReEncryptInput>,
    ) -> IamResult<Reply<keys::ReEncryptOutput>> {
        let source = encryption_context(
            input.get("sourceEncryptionContext"),
            Some("sourceEncryptionContext"),
        )?;
        let destination = encryption_context(
            input.get("destinationEncryptionContext"),
            Some("destinationEncryptionContext"),
        )?;
        // One id links the decrypt and encrypt events of the same re-encryption.
        let mut note = Map::new();
        note.insert("reEncryptId".into(), Value::String(id()));
        let mut opened = self
            .decrypt_call(
                credential,
                input.get("tenantId"),
                input.get("ciphertext"),
                source,
                None,
                note.clone(),
            )
            .await?;
        let sealed = self
            .encrypt_call(
                credential,
                input.get("tenantId"),
                input.get("destinationKeyId").cloned(),
                opened.plaintext.clone(),
                opened.text,
                destination,
                note,
            )
            .await;
        opened.plaintext.fill(0);
        let sealed = sealed?;
        Ok(Reply::json(json!({
            "ciphertext": sealed.ciphertext,
            "keyId": sealed.key_id,
            "keyVersion": number(sealed.key_version),
            "sourceKeyId": opened.key_id,
            "sourceKeyVersion": number(opened.key_version),
        })))
    }

    /// `keys/retireGrant`: gives up a grant made to the caller's own identity: no permission needed, so a workload
    /// can drop access it no longer uses. Audited as `kms:grant-retire`.
    pub async fn retire_grant(
        &self,
        credential: &CredentialInput,
        input: Body<keys::RetireGrantInput>,
    ) -> IamResult<Reply<keys::RetireGrantOutput>> {
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let grant_id = text(input.get("grantId"), "grantId", 256)?;
        let ctx = &self.ctx;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let authenticated = &authenticated;
        let (tenant_id, grant_id) = (&tenant_id, &grant_id);
        let result = ctx
            .store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, authenticated)
                    .await?;
                let tenant = ctx.tenant(&tx, tenant_id).await?;
                if tenant.status != TenantStatus::Active {
                    return Err(IamError::with_status(
                        "TENANT_INACTIVE",
                        "The tenant is not active",
                        403,
                    ));
                }
                let grant: KmsGrant = ctx.scoped_as(&tx, "kmsGrants", grant_id, tenant_id).await?;
                if !acts_in_own_right(&principal)?
                    || principal.session.tenant_id != *tenant_id
                    || grant.grantee_id != principal.identity.id
                {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Only the grantee can retire this grant",
                        403,
                    ));
                }
                tx.delete("kmsGrants", &grant.id).await?;
                let mut metadata = Map::new();
                metadata.insert("grantId".into(), Value::String(grant.id.clone()));
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "kms:grant-retire",
                        tenant_id,
                        &format!("kms/{}", grant.key_id),
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(json!({ "success": true }))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/revokeGrant`: revokes a grant. Requires iam:kms:grant on its key.
    pub async fn revoke_grant(
        &self,
        credential: &CredentialInput,
        input: Body<keys::RevokeGrantInput>,
    ) -> IamResult<Reply<keys::RevokeGrantOutput>> {
        let ctx = self.ctx.clone();
        let tenant = input.get("tenantId").cloned();
        let grant_input = input.get("grantId").cloned();
        let delete_id = js_string(input.get("grantId"));
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(kms_action("grant").to_owned()),
                move |tx, _principal| {
                    Box::pin(async move {
                        let grant_id = text(grant_input.as_ref(), "grantId", 256)?;
                        let tenant_id = text(tenant.as_ref(), "tenantId", 256)?;
                        let grant = ctx
                            .scoped(&tx, "kmsGrants", Some(&Value::String(grant_id)), &tenant_id)
                            .await?;
                        key_target(tx, tenant, grant.get("keyId").cloned(), KeyExtra::default())
                            .await
                    })
                },
                move |call: GuardCall<KeyTarget>, _target: KeyTarget| {
                    Box::pin(async move {
                        call.tx.delete("kmsGrants", &delete_id).await?;
                        call.note("grantId", Value::String(delete_id.clone()));
                        call.note("revoked", Value::Bool(true));
                        Ok(json!({ "success": true }))
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/rotate`: rotates on demand: new material becomes the current version for encrypting, signing and MACs;
    /// older versions keep decrypting and verifying. Requires iam:kms:update; enabled keys only.
    pub async fn rotate(
        &self,
        credential: &CredentialInput,
        input: Body<keys::RotateInput>,
    ) -> IamResult<Reply<keys::RotateOutput>> {
        let ctx = self.ctx.clone();
        let result = self
            .key_call(
                credential,
                input.get("tenantId"),
                kms_action("update"),
                input.get("keyId").cloned(),
                KeyExtra::default(),
                Box::new(move |call, target| {
                    Box::pin(async move {
                        let key = target.key()?;
                        state_change(&key, &["enabled"], "rotated")?;
                        // Each version is new key material (RSA generation is slow): ten on-demand rotations a day
                        // per key.
                        let since = ctx.now() - DAY;
                        let recent = call
                            .tx
                            .find(
                                "kmsKeyVersions",
                                &Filter::new()
                                    .eq("tenantId", key.tenant_id.clone())
                                    .eq("keyId", key.id.clone())
                                    .eq("origin", "rotate"),
                                &FindOptions::default(),
                            )
                            .await?
                            .into_iter()
                            .filter(|version| {
                                version
                                    .get("createdAt")
                                    .and_then(Value::as_f64)
                                    .is_some_and(|created| created > since)
                            })
                            .count();
                        if recent >= 10 {
                            return Err(IamError::with_status(
                                "RATE_LIMITED",
                                "A key rotates on demand at most ten times a day",
                                429,
                            )
                            .into());
                        }
                        let (_, rotated) =
                            rotate_key(&ctx, &call.tx, &target.record()?, &key, "rotate").await?;
                        call.note("rotated", Value::Bool(true));
                        call.note("keyVersion", number(rotated.current_version));
                        Ok(summary_json(&rotated, &target.aliases())?)
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/scheduleDeletion`: schedules destruction after a waiting period (7-30 days, default 30). Meanwhile the
    /// key is unusable and the deletion can be cancelled; afterwards `iam.kms.maintain()` destroys its material,
    /// aliases and grants, and nothing encrypted under it can be decrypted again. Requires iam:kms:delete and recent
    /// authentication.
    pub async fn schedule_deletion(
        &self,
        credential: &CredentialInput,
        input: Body<keys::ScheduleDeletionInput>,
    ) -> IamResult<Reply<keys::ScheduleDeletionOutput>> {
        let waiting_days = integer(
            Some(
                input
                    .get("waitingDays")
                    .filter(|value| !value.is_null())
                    .unwrap_or(&json!(30)),
            ),
            "waitingDays",
            7.0,
            30.0,
        )?;
        let ctx = self.ctx.clone();
        let result = self
            .key_call(
                credential,
                input.get("tenantId"),
                kms_action("delete"),
                input.get("keyId").cloned(),
                KeyExtra::default(),
                Box::new(move |call, target| {
                    Box::pin(async move {
                        let key = target.key()?;
                        ctx.auth.require_recent(&call.principal)?;
                        state_change(&key, &["enabled", "disabled"], "scheduled for deletion")?;
                        let deletion_date = ctx.now() + waiting_days * DAY;
                        call.note("deletionDate", number(deletion_date));
                        let (_, saved) = save_key(
                            &ctx,
                            &call.tx,
                            &target.record()?,
                            vec![
                                ("state", Some(Value::String("pending-deletion".into()))),
                                ("deletionDate", Some(number(deletion_date))),
                            ],
                        )
                        .await?;
                        Ok(summary_json(&saved, &target.aliases())?)
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// The located target of `sign` and `verify`: the key with `resource.algorithm`.
    fn signing_locate(
        tenant: Option<Value>,
        reference: Option<Value>,
        algorithm: Option<Value>,
    ) -> impl FnOnce(Store, AuthenticatedPrincipal) -> BoxFuture<'static, IamResult<KeyTarget>> + Send
    {
        move |tx, _principal| {
            Box::pin(async move {
                let tenant_id = text(tenant.as_ref(), "tenantId", 256)?;
                let key = find_key(&tx, &tenant_id, reference.as_ref()).await?;
                let requested = requested_algorithm(&key, algorithm.as_ref())?;
                key_target(
                    tx,
                    tenant,
                    Some(Value::String(key.id.clone())),
                    KeyExtra::algorithm(requested),
                )
                .await
            })
        }
    }

    /// `keys/sign`: signs a message (`message` UTF-8 or `messageBase64`, up to 64 KiB) with a signing key's current
    /// version. `algorithm` defaults to the key's first (ES256, ES384, EdDSA, or PS256 for RSA); ECDSA signatures are
    /// DER unless `format: 'jose'` (raw r||s, as in JWS). Returns `signature` (base64url) and the `keyVersion` to
    /// verify with. Requires iam:kms:sign (`resource.algorithm` names the algorithm).
    pub async fn sign(
        &self,
        credential: &CredentialInput,
        input: Body<keys::SignInput>,
    ) -> IamResult<Reply<keys::SignOutput>> {
        let message = payload(input.raw(), "message", MAX_MESSAGE_BYTES)?.bytes;
        let format = signature_format(input.get("format"))?;
        let ctx = self.ctx.clone();
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(kms_action("sign").to_owned()),
                Self::signing_locate(
                    input.get("tenantId").cloned(),
                    input.get("keyId").cloned(),
                    input.get("algorithm").cloned(),
                ),
                move |call: GuardCall<KeyTarget>, target: KeyTarget| {
                    Box::pin(async move {
                        let key = target.key()?;
                        assert_usable(&key, &Value::String("sign".into()))?;
                        // A certificate authority's key signs only through the pki API: a raw signature over a
                        // certificate body would be a certificate nobody decided on.
                        assert_unmanaged(&key_json(&key))?;
                        let algorithm =
                            signing_algorithm(&key_json(&key), target.attributes.get("algorithm"))?;
                        let version =
                            key_version(&call.tx, &key_json(&key), key.current_version).await?;
                        call.note("keyVersion", number(version.version));
                        call.note("algorithm", Value::String(algorithm.clone()));
                        let signature =
                            sign_with(&ctx, &version, &algorithm, &message, Some(&format))?;
                        Ok(json!({
                            "signature": base64url(signature),
                            "algorithm": algorithm,
                            "format": format,
                            "keyId": key.id,
                            "keyVersion": number(version.version),
                        }))
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/signJwt`: signs a JWT with a signing key (ES256, ES384, EdDSA, PS256-PS512, RS256-RS512) or a MAC key
    /// (HS256-HS512): header `{ alg, kid, typ }` with `kid` = `{keyId}.{version}` (matching `jwks`), the given
    /// `claims`, `iat` when absent, and `exp` from `expiresInSeconds` (1 s to 1 year). Requires iam:kms:sign or
    /// iam:kms:generate-mac, with `resource.algorithm`, `resource.jwt` (true), `resource.jwt.typ` and the `sub`, `iss`
    /// and `aud` claims as `resource.jwt.sub`, `resource.jwt.iss` and `resource.jwt.aud` (or `resource.jwt.audiences`),
    /// so policies can limit which tokens a caller may mint, or allow tokens but not raw signatures.
    pub async fn sign_jwt(
        &self,
        credential: &CredentialInput,
        input: Body<keys::SignJwtInput>,
    ) -> IamResult<Reply<keys::SignJwtOutput>> {
        let mut claims = object(input.get("claims"))?.clone();
        let expires_in = match input.get("expiresInSeconds") {
            None => None,
            Some(value) => Some(integer(
                Some(value),
                "expiresInSeconds",
                1.0,
                366.0 * 86400.0,
            )?),
        };
        let kind = match input.get("type") {
            None => "JWT".to_owned(),
            Some(value) => text(Some(value), "type", 64)?,
        };
        let ctx = self.ctx.clone();
        let tenant = input.get("tenantId").cloned();
        let reference = input.get("keyId").cloned();
        let algorithm_input = input.get("algorithm").cloned();
        let locate_claims = claims.clone();
        let locate_kind = kind.clone();
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Of(Arc::new(|target: &KeyTarget| {
                    if target.key.as_ref().map(KmsKey::usage) == Some("mac") {
                        kms_action("generate-mac").to_owned()
                    } else {
                        kms_action("sign").to_owned()
                    }
                })),
                move |tx, _principal| {
                    Box::pin(async move {
                        let tenant_id = text(tenant.as_ref(), "tenantId", 256)?;
                        let key = find_key(&tx, &tenant_id, reference.as_ref()).await?;
                        if key.usage() == "encrypt" {
                            return Err(invalid("Encryption keys cannot sign tokens"));
                        }
                        let requested = requested_algorithm(&key, algorithm_input.as_ref())?;
                        let mut target = key_target(
                            tx,
                            tenant,
                            Some(Value::String(key.id.clone())),
                            KeyExtra::algorithm(requested),
                        )
                        .await?;
                        for (name, value) in jwt_attributes(&locate_claims, &locate_kind) {
                            target.attributes.insert(name, value);
                        }
                        Ok(target)
                    })
                },
                move |call: GuardCall<KeyTarget>, target: KeyTarget| {
                    Box::pin(async move {
                        let key = target.key()?;
                        assert_usable(&key, &key.key_usage)?;
                        assert_unmanaged(&key_json(&key))?;
                        let algorithm =
                            signing_algorithm(&key_json(&key), target.attributes.get("algorithm"))?;
                        let version =
                            key_version(&call.tx, &key_json(&key), key.current_version).await?;
                        let now = (ctx.now() / 1000.0).floor();
                        if !claims.contains_key("iat") {
                            claims.insert("iat".into(), number(now));
                        }
                        if let Some(expires_in) = expires_in {
                            claims.insert("exp".into(), number(now + expires_in));
                        }
                        let encoded_claims =
                            base64url(better_iam_core::js::stringify(&Value::Object(claims)));
                        if encoded_claims.len() > 65536 {
                            return Err(invalid("claims are larger than 48 KiB").into());
                        }
                        let header = json!({
                            "alg": algorithm,
                            "kid": format!("{}.{}", key.id, number_to_string(version.version)),
                            "typ": kind,
                        });
                        let signing_input = format!(
                            "{}.{encoded_claims}",
                            base64url(better_iam_core::js::stringify(&header))
                        );
                        let signature = if key.usage() == "mac" {
                            mac_with(&ctx, &key_json(&key), &version, signing_input.as_bytes())?
                        } else {
                            sign_with(
                                &ctx,
                                &version,
                                &algorithm,
                                signing_input.as_bytes(),
                                Some(&Value::String("jose".into())),
                            )?
                        };
                        call.note("keyVersion", number(version.version));
                        call.note("algorithm", Value::String(algorithm.clone()));
                        call.note("jwt", Value::Bool(true));
                        Ok(json!({
                            "token": format!("{signing_input}.{}", base64url(signature)),
                            "algorithm": algorithm,
                            "keyId": key.id,
                            "keyVersion": number(version.version),
                        }))
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/update`: changes the description, replaces the tags, or sets (`null` clears) the automatic rotation
    /// period. New tags must leave the caller able to manage the key: iam:kms:update is evaluated again with them, so
    /// a tag-scoped administrator cannot move a key out of their reach or into another team's. Requires
    /// iam:kms:update.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<keys::UpdateInput>,
    ) -> IamResult<Reply<keys::UpdateOutput>> {
        // Some(None) = `null` (clear), None = absent.
        let description: Option<Option<String>> = match input.get("description") {
            Some(Value::Null) => Some(None),
            other => optional_text(other, "description", 512)?.map(Some),
        };
        let tags = match input.get("tags") {
            None => None,
            Some(value) => Some(key_tags(Some(value))?),
        };
        let period: Option<Option<f64>> = match input.get("rotationPeriodDays") {
            Some(Value::Null) => Some(None),
            other => rotation_period(other)?.map(Some),
        };
        let ctx = self.ctx.clone();
        let result = self
            .key_call(
                credential,
                input.get("tenantId"),
                kms_action("update"),
                input.get("keyId").cloned(),
                KeyExtra::default(),
                Box::new(move |call, target| {
                    Box::pin(async move {
                        let key = target.key()?;
                        let record = target.record()?;
                        let aliases = target.aliases();
                        if key.state_name() == "pending-deletion" {
                            state_change(&key, &["enabled", "disabled"], "updated")?;
                        }
                        let mut changes: Vec<(&str, Option<Value>)> = Vec::new();
                        match description {
                            Some(None) => changes.push(("description", None)),
                            Some(Some(description)) => {
                                changes.push(("description", Some(Value::String(description))))
                            }
                            None => {}
                        }
                        if let Some(tags) = tags {
                            let tags_value = json!(tags);
                            let mut moved = record.clone();
                            moved.insert("tags".into(), tags_value.clone());
                            let moved_target = Target {
                                resource_id: format!("kms/{}", key.id),
                                attributes: key_attributes(&Value::Object(moved), &aliases, None)?,
                            };
                            if !call.allowed(kms_action("update"), &moved_target).await? {
                                return Err(OperationDenied::new(Some(
                                    "Those tags would take the key out of your reach",
                                )));
                            }
                            let current = record.get("tags").cloned().unwrap_or(Value::Null);
                            assert_no_new_rights(
                                &call,
                                &record,
                                KeyView {
                                    tags: &current,
                                    aliases: &aliases,
                                },
                                KeyView {
                                    tags: &tags_value,
                                    aliases: &aliases,
                                },
                            )
                            .await?;
                            changes.push(("tags", Some(tags_value)));
                            let mut names: Vec<String> = tags.keys().cloned().collect();
                            names.sort_by(|a, b| cmp_utf16(a, b));
                            call.note("tags", json!(names));
                        }
                        match period {
                            Some(None) => {
                                changes.push(("rotationPeriodDays", None));
                                changes.push(("nextRotationAt", None));
                            }
                            Some(Some(period)) => {
                                changes.push(("rotationPeriodDays", Some(number(period))));
                                changes.push((
                                    "nextRotationAt",
                                    Some(number(ctx.now() + period * DAY)),
                                ));
                                call.note("rotationPeriodDays", number(period));
                            }
                            None => {}
                        }
                        let (_, saved) = save_key(&ctx, &call.tx, &record, changes).await?;
                        Ok(summary_json(&saved, &aliases)?)
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/updateAlias`: points an alias at another key of the same usage and kind, so applications that name the
    /// alias switch keys without a deploy. Requires iam:kms:update on both keys and on `iam/kms/alias/{name}`.
    pub async fn update_alias(
        &self,
        credential: &CredentialInput,
        input: Body<keys::UpdateAliasInput>,
    ) -> IamResult<Reply<keys::UpdateAliasOutput>> {
        let name = alias_name(input.get("alias"))?;
        if let Some(Value::String(key_id)) = input.get("keyId")
            && key_id.starts_with("alias/")
        {
            return Err(invalid("keyId must be a key id, not an alias"));
        }
        let ctx = self.ctx.clone();
        let result = self
            .key_call(
                credential,
                input.get("tenantId"),
                kms_action("update"),
                input.get("keyId").cloned(),
                KeyExtra::default(),
                Box::new(move |call, target| {
                    Box::pin(async move {
                        let (tx, tenant) = (call.tx.clone(), call.tenant.clone());
                        let key = target.key()?;
                        let record = target.record()?;
                        let aliases = target.aliases();
                        assert_alias_allowed(&call, &name).await?;
                        let Some(mut alias) = tx
                            .find(
                                "kmsAliases",
                                &Filter::new()
                                    .eq("tenantId", tenant.id.clone())
                                    .eq("uniqueKey", name.clone()),
                                &FindOptions::default(),
                            )
                            .await?
                            .into_iter()
                            .next()
                        else {
                            return Err(
                                IamError::with_status("NOT_FOUND", "Alias not found", 404).into()
                            );
                        };
                        if key.state_name() == "pending-deletion" {
                            state_change(&key, &["enabled", "disabled"], "given an alias")?;
                        }
                        let alias_key = js_string(alias.get("keyId"));
                        if alias_key != key.id && aliases.len() as f64 >= MAX_ALIASES_PER_KEY {
                            return Err(IamError::with_status(
                                "LIMIT_EXCEEDED",
                                format!(
                                    "A key has at most {} aliases",
                                    number_to_string(MAX_ALIASES_PER_KEY)
                                ),
                                409,
                            )
                            .into());
                        }
                        let previous_record = find_key_record(
                            &tx,
                            &tenant.id,
                            Some(&Value::String(alias_key.clone())),
                        )
                        .await?;
                        let previous: KmsKey = decode(previous_record.clone())?;
                        if previous.key_usage != key.key_usage
                            || spec_family(previous.spec()) != spec_family(key.spec())
                        {
                            return Err(invalid(
                                "An alias can only move to a key of the same kind and usage",
                            )
                            .into());
                        }
                        let previous_value = Value::Object(previous_record.clone());
                        let previous_aliases = alias_names(&tx, &previous_value).await?;
                        let previous_target = Target {
                            resource_id: format!("kms/{}", previous.id),
                            attributes: key_attributes(&previous_value, &previous_aliases, None)?,
                        };
                        if !call.allowed(kms_action("update"), &previous_target).await? {
                            return Err(OperationDenied::new(Some(
                                "You may not manage the key the alias names now",
                            )));
                        }
                        if previous.id != key.id {
                            // The new key gains the name and the old one loses it: neither may open anything for the
                            // caller.
                            let tags = record.get("tags").cloned().unwrap_or(Value::Null);
                            let mut gained = aliases.clone();
                            gained.push(name.clone());
                            assert_no_new_rights(
                                &call,
                                &record,
                                KeyView {
                                    tags: &tags,
                                    aliases: &aliases,
                                },
                                KeyView {
                                    tags: &tags,
                                    aliases: &gained,
                                },
                            )
                            .await?;
                            let previous_tags =
                                previous_record.get("tags").cloned().unwrap_or(Value::Null);
                            let lost: Vec<String> = previous_aliases
                                .iter()
                                .filter(|item| **item != name)
                                .cloned()
                                .collect();
                            assert_no_new_rights(
                                &call,
                                &previous_record,
                                KeyView {
                                    tags: &previous_tags,
                                    aliases: &previous_aliases,
                                },
                                KeyView {
                                    tags: &previous_tags,
                                    aliases: &lost,
                                },
                            )
                            .await?;
                        }
                        let now = ctx.now();
                        alias.insert("keyId".into(), Value::String(key.id.clone()));
                        alias.insert("updatedAt".into(), number(now));
                        tx.put("kmsAliases", &alias).await?;
                        call.note("alias", Value::String(name.clone()));
                        call.note("previousKeyId", Value::String(previous.id.clone()));
                        Ok(json!({
                            "name": name,
                            "keyId": key.id,
                            "createdAt": alias.get("createdAt").cloned().unwrap_or(Value::Null),
                            "updatedAt": number(now),
                        }))
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/verify`: checks a signature from `sign` against the message, with `keyVersion` (default: current) and
    /// `algorithm` (default: the key's first). Returns `{ valid }`; a mismatch is not an error. Requires
    /// iam:kms:verify.
    pub async fn verify(
        &self,
        credential: &CredentialInput,
        input: Body<keys::VerifyInput>,
    ) -> IamResult<Reply<keys::VerifyOutput>> {
        let message = payload(input.raw(), "message", MAX_MESSAGE_BYTES)?.bytes;
        let signature = base64_bytes(input.get("signature"), "signature", 1024.0)?;
        let format = signature_format(input.get("format"))?;
        let requested = input.get("keyVersion").cloned();
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Fixed(kms_action("verify").to_owned()),
                Self::signing_locate(
                    input.get("tenantId").cloned(),
                    input.get("keyId").cloned(),
                    input.get("algorithm").cloned(),
                ),
                move |call: GuardCall<KeyTarget>, target: KeyTarget| {
                    Box::pin(async move {
                        let key = target.key()?;
                        assert_usable(&key, &Value::String("sign".into()))?;
                        let algorithm =
                            signing_algorithm(&key_json(&key), target.attributes.get("algorithm"))?;
                        let wanted = match &requested {
                            None => key.current_version,
                            Some(value) => integer(Some(value), "keyVersion", 1.0, MAX_VERSIONS)?,
                        };
                        let version = key_version(&call.tx, &key_json(&key), wanted).await?;
                        let valid =
                            verify_with(&version, &algorithm, &message, &signature, Some(&format))?;
                        call.note("keyVersion", number(version.version));
                        call.note("algorithm", Value::String(algorithm.clone()));
                        call.note("valid", Value::Bool(valid));
                        Ok(json!({
                            "valid": valid,
                            "algorithm": algorithm,
                            "keyId": key.id,
                            "keyVersion": number(version.version),
                        }))
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/verifyJwt`: verifies a JWT signed by `signJwt` (or any JWS made with the key): the `kid` names the key
    /// version, `alg` must be one the key supports, and `exp` / `nbf` are checked with `clockToleranceSeconds`
    /// (default 60), plus `audience` and `issuer` when given. Returns `{ valid: true, claims, header }` or
    /// `{ valid: false, reason }`. Requires iam:kms:verify or iam:kms:verify-mac.
    pub async fn verify_jwt(
        &self,
        credential: &CredentialInput,
        input: Body<keys::VerifyJwtInput>,
    ) -> IamResult<Reply<keys::VerifyJwtOutput>> {
        let token = text(input.get("token"), "token", 131072)?;
        let parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        if parts.len() != 3 || parts.iter().any(|part| !base64url_chars(part)) {
            return Err(invalid("token must be a compact JWS"));
        }
        let header = json_segment(&parts[0], "header")?;
        let claims = json_segment(&parts[1], "claims")?;
        let kid = parse_kid_typed(header.get("kid"));
        if kid.is_none() && input.get("keyId").is_none() {
            return Err(invalid("The token has no KMS kid; pass keyId"));
        }
        let tolerance = integer(
            Some(
                input
                    .get("clockToleranceSeconds")
                    .filter(|value| !value.is_null())
                    .unwrap_or(&json!(60)),
            ),
            "clockToleranceSeconds",
            0.0,
            600.0,
        )?;
        let ctx = self.ctx.clone();
        let tenant = input.get("tenantId").cloned();
        let key_input = input.get("keyId").cloned();
        let audience = input.get("audience").cloned();
        let issuer = input.get("issuer").cloned();
        let locate_kid = kid.clone();
        let header_alg = header.get("alg").cloned();
        let result = self
            .guard
            .run(
                credential,
                input.get("tenantId"),
                GuardAction::Of(Arc::new(|target: &KeyTarget| {
                    if target.key.as_ref().map(KmsKey::usage) == Some("mac") {
                        kms_action("verify-mac").to_owned()
                    } else {
                        kms_action("verify").to_owned()
                    }
                })),
                move |tx, _principal| {
                    Box::pin(async move {
                        let tenant_id = text(tenant.as_ref(), "tenantId", 256)?;
                        let reference = match key_input {
                            Some(Value::Null) | None => match &locate_kid {
                                Some(kid) => Value::String(kid.key_id.clone()),
                                // `kid!.keyId` on a token without a kid and a null keyId: a TypeError.
                                None => return Err(internal_error()),
                            },
                            Some(value) => value,
                        };
                        let key = find_key(&tx, &tenant_id, Some(&reference)).await?;
                        if let Some(kid) = &locate_kid
                            && kid.key_id != key.id
                        {
                            return Err(invalid("The token was not signed with that key"));
                        }
                        if key.usage() == "encrypt" {
                            return Err(invalid("Encryption keys do not sign tokens"));
                        }
                        // The token's own claim, bounded before it reaches policies as `resource.algorithm`.
                        let algorithm = match &header_alg {
                            Some(Value::String(alg)) if short_algorithm(alg) => alg.clone(),
                            _ => "none".to_owned(),
                        };
                        key_target(
                            tx,
                            Some(Value::String(tenant_id)),
                            Some(Value::String(key.id.clone())),
                            KeyExtra::algorithm(algorithm),
                        )
                        .await
                    })
                },
                move |call: GuardCall<KeyTarget>, target: KeyTarget| {
                    Box::pin(async move {
                        let key = target.key()?;
                        assert_usable(&key, &key.key_usage)?;
                        let algorithm = js_string(target.attributes.get("algorithm"));
                        let wanted = kid.as_ref().map_or(key.current_version, |kid| kid.version);
                        let version = key_version(&call.tx, &key_json(&key), wanted).await?;
                        let invalid_because = |reason: &str| {
                            json!({
                                "valid": false,
                                "reason": reason,
                                "keyId": key.id,
                                "keyVersion": number(version.version),
                            })
                        };
                        let outcome = || -> IamResult<Value> {
                            if !algorithms_for(key.spec(), key.usage())?.contains(&algorithm) {
                                return Ok(invalid_because("algorithm"));
                            }
                            // Critical extensions are not understood here, so a token that needs them is refused
                            // (RFC 7515 4.1.11).
                            if header.contains_key("crit") {
                                return Ok(invalid_because("header"));
                            }
                            let time_claim = |value: Option<&Value>| match value {
                                None => true,
                                Some(Value::Number(n)) => n.as_f64().is_some_and(f64::is_finite),
                                Some(_) => false,
                            };
                            if !time_claim(claims.get("exp")) || !time_claim(claims.get("nbf")) {
                                return Ok(invalid_because("claims"));
                            }
                            let signing_input = format!("{}.{}", parts[0], parts[1]);
                            let signature = node_base64_decode(&parts[2]);
                            // One spelling per signature, so string-keyed replay caches cannot be sidestepped.
                            if base64url(&signature) != parts[2] {
                                return Ok(invalid_because("signature"));
                            }
                            let valid = if key.usage() == "mac" {
                                same_bytes(
                                    &mac_with(
                                        &ctx,
                                        &key_json(&key),
                                        &version,
                                        signing_input.as_bytes(),
                                    )?,
                                    &signature,
                                )?
                            } else {
                                verify_with(
                                    &version,
                                    &algorithm,
                                    signing_input.as_bytes(),
                                    &signature,
                                    Some(&Value::String("jose".into())),
                                )?
                            };
                            if !valid {
                                return Ok(invalid_because("signature"));
                            }
                            let now = (ctx.now() / 1000.0).floor();
                            if let Some(exp) = claims.get("exp").and_then(Value::as_f64)
                                && exp + tolerance <= now
                            {
                                return Ok(invalid_because("expired"));
                            }
                            if let Some(nbf) = claims.get("nbf").and_then(Value::as_f64)
                                && nbf - tolerance > now
                            {
                                return Ok(invalid_because("not-yet-valid"));
                            }
                            if let Some(audience) = &audience {
                                let audiences: Vec<Option<&Value>> = match claims.get("aud") {
                                    Some(Value::Array(items)) => items.iter().map(Some).collect(),
                                    other => vec![other],
                                };
                                if !audiences
                                    .iter()
                                    .any(|item| strict_equal(*item, Some(audience)))
                                {
                                    return Ok(invalid_because("audience"));
                                }
                            }
                            if let Some(issuer) = &issuer
                                && !strict_equal(claims.get("iss"), Some(issuer))
                            {
                                return Ok(invalid_because("issuer"));
                            }
                            Ok(json!({
                                "valid": true,
                                "algorithm": algorithm,
                                "header": header,
                                "claims": claims,
                                "keyId": key.id,
                                "keyVersion": number(version.version),
                            }))
                        };
                        let result = outcome()?;
                        call.note("keyVersion", number(version.version));
                        call.note("algorithm", Value::String(algorithm.clone()));
                        call.note("jwt", Value::Bool(true));
                        let valid = result.get("valid").cloned().unwrap_or(Value::Bool(false));
                        call.note("valid", valid.clone());
                        if valid != Value::Bool(true) {
                            call.note(
                                "reason",
                                result.get("reason").cloned().unwrap_or(Value::Null),
                            );
                        }
                        Ok(result)
                    })
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `keys/verifyMac`: checks a MAC in constant time with `keyVersion` (default: current). Returns `{ valid }`.
    /// Requires iam:kms:verify-mac.
    pub async fn verify_mac(
        &self,
        credential: &CredentialInput,
        input: Body<keys::VerifyMacInput>,
    ) -> IamResult<Reply<keys::VerifyMacOutput>> {
        let message = payload(input.raw(), "message", MAX_MESSAGE_BYTES)?.bytes;
        let mac = base64_bytes(input.get("mac"), "mac", 128.0)?;
        let requested = input.get("keyVersion").cloned();
        let ctx = self.ctx.clone();
        let result = self
            .key_call(
                credential,
                input.get("tenantId"),
                kms_action("verify-mac"),
                input.get("keyId").cloned(),
                KeyExtra::default(),
                Box::new(move |call, target| {
                    Box::pin(async move {
                        let key = target.key()?;
                        assert_usable(&key, &Value::String("mac".into()))?;
                        assert_unmanaged(&key_json(&key))?;
                        let wanted = match &requested {
                            None => key.current_version,
                            Some(value) => integer(Some(value), "keyVersion", 1.0, MAX_VERSIONS)?,
                        };
                        let version = key_version(&call.tx, &key_json(&key), wanted).await?;
                        let valid = same_bytes(
                            &mac_with(&ctx, &key_json(&key), &version, &message)?,
                            &mac,
                        )?;
                        call.note("keyVersion", number(version.version));
                        call.note("valid", Value::Bool(valid));
                        Ok(json!({
                            "valid": valid,
                            "keyId": key.id,
                            "keyVersion": number(version.version),
                        }))
                    })
                }),
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// `{ id, tenantId, actorId: 'deployment-operator', action, resourceId: 'kms/{keyId}', timestamp, outcome, metadata }`.
fn system_event(
    ctx: &ServerContext,
    tenant_id: &str,
    action: &str,
    key_id: &str,
    metadata: Map<String, Value>,
) -> Record {
    let mut event = Record::new();
    event.insert("id".into(), Value::String(id()));
    event.insert("tenantId".into(), Value::String(tenant_id.into()));
    event.insert(
        "actorId".into(),
        Value::String("deployment-operator".into()),
    );
    event.insert("action".into(), Value::String(action.into()));
    event.insert("resourceId".into(), Value::String(format!("kms/{key_id}")));
    event.insert("timestamp".into(), number(ctx.now()));
    event.insert("outcome".into(), Value::String("allow".into()));
    event.insert("metadata".into(), Value::Object(metadata));
    event
}

/// The KMS scheduler job: rotates keys whose automatic rotation is due, destroys keys whose deletion waiting period
/// has passed (material, aliases and grants; audited as `kms:key-destroy`), and removes lapsed grants and grants
/// whose grantee is gone. Run it hourly.
pub async fn maintain_keys(ctx: &Arc<ServerContext>, input: Option<&Value>) -> IamResult<Value> {
    let mut rotated: Vec<Value> = Vec::new();
    let mut destroyed: Vec<Value> = Vec::new();
    let mut grants_removed: usize = 0;
    let tenant_filter = match input.and_then(|input| input.get("tenantId")) {
        Some(tenant) if truthy(Some(tenant)) => Some(text(Some(tenant), "tenantId", 256)?),
        _ => None,
    };
    let filter = || match &tenant_filter {
        Some(tenant) => Filter::new().eq("tenantId", tenant.clone()),
        None => Filter::new(),
    };
    let candidates = {
        let filter = filter();
        ctx.store
            .transaction(move |tx| async move {
                tx.find("kmsKeys", &filter, &FindOptions::default()).await
            })
            .await?
    };
    for candidate in candidates {
        let now = ctx.now();
        let candidate_id = js_string(candidate.get("id"));
        let state = candidate.get("state").and_then(Value::as_str);
        let deletion_date = candidate
            .get("deletionDate")
            .and_then(Value::as_f64)
            .unwrap_or(f64::INFINITY);
        if state == Some("pending-deletion") && deletion_date <= now {
            let candidate_id = candidate_id.clone();
            let gone = ctx
                .store
                .transaction(move |tx| async move {
                    let Some(key) = tx.get("kmsKeys", &candidate_id).await? else {
                        return Ok(None);
                    };
                    let deletion = key
                        .get("deletionDate")
                        .and_then(Value::as_f64)
                        .unwrap_or(f64::INFINITY);
                    if key.get("state").and_then(Value::as_str) != Some("pending-deletion")
                        || deletion > now
                    {
                        return Ok(None);
                    }
                    let tenant_id = js_string(key.get("tenantId"));
                    let key_id = js_string(key.get("id"));
                    for collection in ["kmsKeyVersions", "kmsAliases", "kmsGrants"] {
                        for record in tx
                            .find(
                                collection,
                                &Filter::new()
                                    .eq("tenantId", tenant_id.clone())
                                    .eq("keyId", key_id.clone()),
                                &FindOptions::default(),
                            )
                            .await?
                        {
                            tx.delete(collection, &js_string(record.get("id"))).await?;
                        }
                    }
                    tx.delete("kmsKeys", &key_id).await?;
                    let mut metadata = Map::new();
                    metadata.insert(
                        "keySpec".into(),
                        key.get("keySpec").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert(
                        "versions".into(),
                        key.get("currentVersion").cloned().unwrap_or(Value::Null),
                    );
                    ctx.events()?
                        .record_audit(
                            &tx,
                            &system_event(ctx, &tenant_id, "kms:key-destroy", &key_id, metadata),
                        )
                        .await?;
                    Ok(Some(json!({ "tenantId": tenant_id, "keyId": key_id })))
                })
                .await?;
            destroyed.extend(gone);
            continue;
        }
        let next_rotation = candidate.get("nextRotationAt").and_then(Value::as_f64);
        if state == Some("enabled") && next_rotation.is_some_and(|next| next <= now) {
            let done = ctx
                .store
                .transaction(move |tx| async move {
                    let Some(mut key) = tx.get("kmsKeys", &candidate_id).await? else {
                        return Ok(None);
                    };
                    let next = key.get("nextRotationAt").and_then(Value::as_f64);
                    let period = key.get("rotationPeriodDays").and_then(Value::as_f64);
                    let current = key
                        .get("currentVersion")
                        .and_then(Value::as_f64)
                        .unwrap_or(f64::NAN);
                    let (Some(next), Some(period)) = (next, period) else {
                        return Ok(None);
                    };
                    if key.get("state").and_then(Value::as_str) != Some("enabled")
                        || next > now
                        || current >= MAX_VERSIONS
                        || current.is_nan()
                    {
                        return Ok(None);
                    }
                    let version = current + 1.0;
                    add_key_version(ctx, &tx, &Value::Object(key.clone()), version, "automatic")
                        .await?;
                    key.insert("currentVersion".into(), number(version));
                    key.insert("lastRotatedAt".into(), number(now));
                    key.insert("nextRotationAt".into(), number(now + period * DAY));
                    key.insert("updatedAt".into(), number(now));
                    tx.put("kmsKeys", &key).await?;
                    let tenant_id = js_string(key.get("tenantId"));
                    let key_id = js_string(key.get("id"));
                    let mut metadata = Map::new();
                    metadata.insert("keyVersion".into(), number(version));
                    metadata.insert("automatic".into(), Value::Bool(true));
                    ctx.events()?
                        .record_audit(
                            &tx,
                            &system_event(ctx, &tenant_id, "kms:key-rotate", &key_id, metadata),
                        )
                        .await?;
                    Ok(Some(json!({
                        "tenantId": tenant_id,
                        "keyId": key_id,
                        "keyVersion": number(version),
                    })))
                })
                .await?;
            rotated.extend(done);
        }
    }
    // Lapsed grants, and grants whose grantee or creator is gone, one tenant per transaction.
    let tenants: IndexSet<String> = {
        let filter = filter();
        ctx.store
            .transaction(move |tx| async move {
                Ok(tx
                    .find("kmsGrants", &filter, &FindOptions::default())
                    .await?
                    .iter()
                    .map(|grant| js_string(grant.get("tenantId")))
                    .collect::<IndexSet<String>>())
            })
            .await?
    };
    for tenant_id in tenants {
        let removed = ctx
            .store
            .transaction(move |tx| async move {
                let now = ctx.now();
                let mut removed = 0usize;
                let deleted = |identity_id: String| {
                    let tx = tx.clone();
                    let tenant_id = tenant_id.clone();
                    async move {
                        let identity: Option<Identity> =
                            tx.get_as("identities", &identity_id).await?;
                        Ok::<bool, IamError>(match identity {
                            None => true,
                            Some(identity) => {
                                identity.tenant_id != tenant_id
                                    || identity.status == IdentityStatus::Deleted
                            }
                        })
                    }
                };
                for grant in tx
                    .find(
                        "kmsGrants",
                        &Filter::new().eq("tenantId", tenant_id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    let lapsed = grant
                        .get("expiresAt")
                        .and_then(Value::as_f64)
                        .is_some_and(|expires| expires <= now);
                    let gone = lapsed
                        || deleted(js_string(grant.get("granteeId"))).await?
                        || deleted(js_string(grant.get("createdBy"))).await?;
                    if !gone {
                        continue;
                    }
                    tx.delete("kmsGrants", &js_string(grant.get("id"))).await?;
                    removed += 1;
                }
                Ok(removed)
            })
            .await?;
        grants_removed += removed;
    }
    Ok(json!({
        "rotated": rotated,
        "destroyed": destroyed,
        "grantsRemoved": grants_removed,
    }))
}

/// `iam.kms`: the scheduler job and nothing else; applications use `api.keys`.
pub struct KmsRuntime {
    ctx: Arc<ServerContext>,
}

/// `createKmsRuntime(ctx)`.
pub fn create_kms_runtime(ctx: &Arc<ServerContext>) -> IamResult<KmsRuntime> {
    Ok(KmsRuntime { ctx: ctx.clone() })
}

impl KmsRuntime {
    /// Automatic rotation, destruction after the deletion waiting period, and grant cleanup (run hourly).
    pub async fn maintain(&self, input: Option<&Value>) -> IamResult<Value> {
        maintain_keys(&self.ctx, input).await
    }
    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        match method {
            "maintain" => Some(
                self.maintain(args.first().filter(|value| !value.is_null()))
                    .await,
            ),
            _ => None,
        }
    }
}
