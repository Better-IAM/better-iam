//! Provider persistence (adapter.ts): encrypted artifacts with hashed token identifiers, bound to the tenant of
//! their client and account, with every user grant re-validated against its IAM session on each use.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, IamStore, IamStoreExt, Record, js, tenant_tree_active,
};
use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::errors::{OidcError, ProviderError, ProviderResult};
use crate::jose;

/// `hash(text)`: SHA-256, hex.
pub fn hash(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Sentinel tenant for artifacts that exist before any client or account is known (for example interactions).
pub const PROTOCOL_TENANT: &str = "__protocol__";

/// AES-256-GCM sealing for provider artifacts (`cipher(key)`); the key is separate from signing and cookie keys.
#[derive(Clone)]
pub struct Cipher {
    key: [u8; 32],
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cipher")
    }
}

/// The error `crypt.open` throws for a value that does not decrypt.
pub fn decrypt_failed() -> IamError {
    IamError::with_status(
        "INTERNAL_ERROR",
        "Unsupported state or unable to authenticate data",
        500,
    )
}

impl Cipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// `seal(value)`: `base64(iv || ciphertext || tag)` over `JSON.stringify(value)`.
    pub fn seal(&self, value: &Value) -> String {
        self.seal_text(&js::stringify(value))
    }

    /// Seals a string as UTF-8.
    pub fn seal_text(&self, text: &str) -> String {
        let iv: [u8; 12] = rand::random();
        let cipher = Aes256Gcm::new((&self.key).into());
        let sealed = cipher
            .encrypt(Nonce::from_slice(&iv), text.as_bytes())
            .unwrap_or_default();
        let mut out = iv.to_vec();
        out.extend_from_slice(&sealed);
        jose::b64(&out)
    }

    /// Opens a sealed string.
    pub fn open_text(&self, value: &str) -> IamResult<String> {
        let buffer = jose::b64_decode_lenient(value);
        if buffer.len() < 28 {
            return Err(decrypt_failed());
        }
        let cipher = Aes256Gcm::new((&self.key).into());
        let plain = cipher
            .decrypt(Nonce::from_slice(&buffer[..12]), &buffer[12..])
            .map_err(|_| decrypt_failed())?;
        String::from_utf8(plain).map_err(|_| decrypt_failed())
    }

    /// `open<T>(value)`: decrypts and parses JSON.
    pub fn open(&self, value: &str) -> IamResult<Value> {
        let text = self.open_text(value)?;
        js::parse(&text).map_err(|_| decrypt_failed())
    }

    /// Opens a sealed JSON object.
    pub fn open_object(&self, value: &str) -> IamResult<Map<String, Value>> {
        match self.open(value)? {
            Value::Object(map) => Ok(map),
            _ => Err(decrypt_failed()),
        }
    }
}

/// `cipher(key)`.
pub fn cipher(key: [u8; 32]) -> Cipher {
    Cipher::new(key)
}

/// `encryptionKey(encoded)`: a base64-encoded 32-byte key.
pub fn encryption_key(encoded: &str) -> IamResult<[u8; 32]> {
    let key = jose::b64_decode_lenient(encoded);
    key.try_into().map_err(|_| {
        IamError::new(
            "configuration",
            "OAuth encryptionKey must encode exactly 32 bytes.",
        )
    })
}

/// `validateSession(sessionId)` of the host.
pub type ValidateSession = Arc<dyn Fn(String) -> BoxFuture<'static, IamResult<()>> + Send + Sync>;

/// Stores a client created by dynamic registration (`registerClient(clientId, payload)`).
pub type RegisterClient =
    Arc<dyn Fn(String, Map<String, Value>) -> BoxFuture<'static, ProviderResult<()>> + Send + Sync>;

type PendingRevocation = Shared<BoxFuture<'static, Result<(), ProviderError>>>;

struct AdapterShared {
    store: Arc<dyn IamStore>,
    crypt: Cipher,
    validate_session: Option<ValidateSession>,
    register_client: Option<RegisterClient>,
    pending_revocations: Mutex<HashMap<String, PendingRevocation>>,
}

/// `createProviderAdapter(store, encodedKey, validateSession?, registerClient?)`: the adapter constructor. Call
/// [`ProviderAdapterFactory::model`] for the adapter of one model (`new Adapter('RefreshToken')`).
#[derive(Clone)]
pub struct ProviderAdapterFactory {
    shared: Arc<AdapterShared>,
}

impl std::fmt::Debug for ProviderAdapterFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProviderAdapterFactory")
    }
}

/// `createProviderAdapter(...)`.
pub fn create_provider_adapter(
    store: Arc<dyn IamStore>,
    encoded_key: &str,
    validate_session: Option<ValidateSession>,
    register_client: Option<RegisterClient>,
) -> IamResult<ProviderAdapterFactory> {
    let crypt = cipher(encryption_key(encoded_key)?);
    Ok(ProviderAdapterFactory {
        shared: Arc::new(AdapterShared {
            store,
            crypt,
            validate_session,
            register_client,
            pending_revocations: Mutex::new(HashMap::new()),
        }),
    })
}

impl ProviderAdapterFactory {
    /// The adapter of one model (`new PersistentAdapter(model)`).
    pub fn model(&self, model: &str) -> ProviderAdapter {
        ProviderAdapter {
            model: model.to_owned(),
            shared: self.shared.clone(),
        }
    }

    pub(crate) fn store(&self) -> &Arc<dyn IamStore> {
        &self.shared.store
    }
}

/// A persistent adapter for one model.
#[derive(Clone)]
pub struct ProviderAdapter {
    model: String,
    shared: Arc<AdapterShared>,
}

impl std::fmt::Debug for ProviderAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProviderAdapter({})", self.model)
    }
}

fn str_member<'a>(record: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

fn number_member(record: &Map<String, Value>, key: &str) -> Option<f64> {
    record.get(key).and_then(Value::as_f64)
}

/// A truthy JavaScript value.
pub(crate) fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(number)) => number
            .as_f64()
            .is_some_and(|value| value != 0.0 && !value.is_nan()),
        Some(Value::String(text)) => !text.is_empty(),
        Some(_) => true,
    }
}

/// `client(id)`: a live client row: not revoked, its tenant tree active, and its service account (if any) active in
/// the same tenant.
pub(crate) async fn live_client(store: &dyn IamStore, id: &str) -> IamResult<Option<Record>> {
    let Some(row) = store.get("oauthClients", &hash(id)).await? else {
        return Ok(None);
    };
    if truthy(row.get("revoked"))
        || !tenant_tree_active(store, str_member(&row, "tenantId").unwrap_or_default()).await?
    {
        return Ok(None);
    }
    if let Some(service_id) = str_member(&row, "serviceAccountId").filter(|id| !id.is_empty()) {
        let service = store.get("identities", service_id).await?;
        let usable = service.is_some_and(|service| {
            str_member(&service, "kind") == Some("service")
                && str_member(&service, "status") == Some("active")
                && str_member(&service, "tenantId") == str_member(&row, "tenantId")
        });
        if !usable {
            return Ok(None);
        }
    }
    Ok(Some(row))
}

impl AdapterShared {
    /// `validGrantSession(grantId, accountId?)`.
    async fn valid_grant_session(
        &self,
        grant_id: &str,
        account_id: Option<&str>,
    ) -> ProviderResult<()> {
        let store = self.store.as_ref();
        if store
            .get("oauthRevokedGrants", &hash(grant_id))
            .await?
            .is_some()
        {
            return Err(OidcError::invalid_grant("Grant is revoked.").into());
        }
        let binding = store.get("oauthGrantSessions", &hash(grant_id)).await?;
        let Some(binding) = binding.filter(|binding| {
            account_id
                .filter(|account| !account.is_empty())
                .is_none_or(|account| str_member(binding, "identityId") == Some(account))
        }) else {
            return Err(OidcError::invalid_grant("Grant has no valid IAM session binding.").into());
        };
        let session_id = str_member(&binding, "sessionId").unwrap_or_default();
        let identity_id = str_member(&binding, "identityId").unwrap_or_default();
        let tenant_id = str_member(&binding, "tenantId").unwrap_or_default();
        let session = store.get("sessions", session_id).await?;
        let identity = store.get("identities", identity_id).await?;
        let mfa = store.get("authMfa", identity_id).await?;
        let now = js::now_ms();
        let mut usable = false;
        if let (Some(session), Some(identity)) = (&session, &identity) {
            let mfa_enabled = mfa.as_ref().is_some_and(|mfa| truthy(mfa.get("enabled")));
            usable = str_member(session, "kind") == Some("user")
                && str_member(session, "identityId") == Some(identity_id)
                && str_member(session, "tenantId") == Some(tenant_id)
                && str_member(identity, "tenantId") == Some(tenant_id)
                && str_member(identity, "status") == Some("active")
                && number_member(session, "expiresAt").is_some_and(|expires| expires > now)
                && (self.validate_session.is_some()
                    || number_member(session, "lastSeenAt")
                        .is_some_and(|seen| now - seen < 86_400_000.0))
                && !((truthy(identity.get("rootAdmin")) || mfa_enabled)
                    && !truthy(session.get("mfa")));
            if usable {
                usable = tenant_tree_active(store, tenant_id).await?;
            }
        }
        if !usable {
            return Err(OidcError::invalid_grant("IAM session is unavailable.").into());
        }
        if let Some(validate) = &self.validate_session {
            let id = session
                .as_ref()
                .and_then(|session| str_member(session, "id"))
                .unwrap_or_default()
                .to_owned();
            validate(id).await?;
        }
        Ok(())
    }

    /// `scope(payload)`: the tenant an artifact belongs to, derived from its client and account, which must agree.
    async fn scope(&self, payload: &Map<String, Value>) -> ProviderResult<String> {
        let store = self.store.as_ref();
        let mut tenant_id: Option<String> = None;
        let client_id = match payload.get("clientId") {
            Some(value) if !value.is_null() => Some(value.as_str().unwrap_or_default().to_owned()),
            _ => payload
                .get("params")
                .and_then(|params| params.get("client_id"))
                .and_then(Value::as_str)
                .map(str::to_owned),
        };
        if let Some(client_id) = client_id.filter(|id| !id.is_empty()) {
            let Some(row) = live_client(store, &client_id).await? else {
                return Err(OidcError::invalid_client(Some("Client is unavailable.")).into());
            };
            tenant_id = str_member(&row, "tenantId").map(str::to_owned);
        }
        let account_id = str_member(payload, "accountId").filter(|id| !id.is_empty());
        if let Some(account_id) = account_id {
            let identity = store.get("identities", account_id).await?;
            let active = match &identity {
                Some(identity) => {
                    str_member(identity, "status") == Some("active")
                        && tenant_tree_active(
                            store,
                            str_member(identity, "tenantId").unwrap_or_default(),
                        )
                        .await?
                }
                None => false,
            };
            let Some(identity) = identity.filter(|_| active) else {
                return Err(OidcError::invalid_grant("Account is unavailable.").into());
            };
            let identity_tenant = str_member(&identity, "tenantId")
                .unwrap_or_default()
                .to_owned();
            if tenant_id
                .as_ref()
                .is_some_and(|tenant| *tenant != identity_tenant)
            {
                return Err(OidcError::invalid_grant(
                    "Account and client belong to different tenants.",
                )
                .into());
            }
            tenant_id = Some(identity_tenant);
        }
        if let Some(grant_id) = str_member(payload, "grantId").filter(|id| !id.is_empty()) {
            if store
                .get("oauthRevokedGrants", &hash(grant_id))
                .await?
                .is_some()
            {
                return Err(OidcError::invalid_grant("Grant is revoked.").into());
            }
            self.valid_grant_session(grant_id, account_id).await?;
        }
        Ok(tenant_id.unwrap_or_else(|| PROTOCOL_TENANT.to_owned()))
    }
}

impl ProviderAdapter {
    pub fn model_name(&self) -> &str {
        &self.model
    }

    fn record_id(&self, id: &str) -> String {
        hash(&format!("{}:{id}", self.model))
    }

    /// `upsert(id, payload, expiresIn = 86400)`.
    pub async fn upsert(
        &self,
        id: &str,
        payload: &Map<String, Value>,
        expires_in: Option<f64>,
    ) -> ProviderResult<()> {
        if self.model == "Client" {
            let Some(register) = &self.shared.register_client else {
                return Err(IamError::with_status(
                    "PROTECTED_OPERATION",
                    "Use authenticated registerClient().",
                    403,
                )
                .into());
            };
            return register(id.to_owned(), payload.clone()).await;
        }
        let expires_in = expires_in.unwrap_or(86400.0);
        let shared = self.shared.clone();
        let model = self.model.clone();
        let record_id = self.record_id(id);
        let payload = payload.clone();
        shared
            .store
            .clone()
            .transaction(move |tx| async move {
                let tenant_id = shared
                    .scope(&payload)
                    .await
                    .map_err(provider_to_iam_carrier)?;
                let previous = tx.get("oauthArtifacts", &record_id).await?;
                if let Some(previous) = &previous {
                    let bound = str_member(previous, "boundTenantId").unwrap_or_default();
                    if bound != PROTOCOL_TENANT && bound != tenant_id {
                        return Err(provider_to_iam_carrier(
                            OidcError::invalid_grant("Immutable tenant binding changed.").into(),
                        ));
                    }
                }
                let mut record = Map::new();
                record.insert("id".into(), json!(record_id));
                record.insert(
                    "tenantId".into(),
                    previous
                        .as_ref()
                        .and_then(|previous| previous.get("tenantId").cloned())
                        .unwrap_or_else(|| json!(tenant_id)),
                );
                record.insert("boundTenantId".into(), json!(tenant_id));
                record.insert("model".into(), json!(model));
                record.insert(
                    "encrypted".into(),
                    json!(shared.crypt.seal(&Value::Object(payload.clone()))),
                );
                record.insert(
                    "expiresAt".into(),
                    js::number(js::now_ms() + expires_in * 1000.0).unwrap_or(Value::Null),
                );
                if let Some(client_id) = payload.get("clientId").filter(|value| !value.is_null()) {
                    record.insert("clientId".into(), client_id.clone());
                }
                if let Some(account_id) = payload.get("accountId").filter(|value| !value.is_null())
                {
                    record.insert("accountId".into(), account_id.clone());
                }
                if let Some(uid) = str_member(&payload, "uid").filter(|uid| !uid.is_empty()) {
                    record.insert("uidHash".into(), json!(hash(uid)));
                }
                if let Some(code) = str_member(&payload, "userCode").filter(|code| !code.is_empty())
                {
                    record.insert("userCodeHash".into(), json!(hash(code)));
                }
                if let Some(grant) =
                    str_member(&payload, "grantId").filter(|grant| !grant.is_empty())
                {
                    record.insert("grantIdHash".into(), json!(hash(grant)));
                }
                if previous.is_some() {
                    tx.put("oauthArtifacts", &record).await?;
                } else {
                    tx.insert("oauthArtifacts", &record).await?;
                }
                Ok(())
            })
            .await
            .map_err(iam_carrier_to_provider)
    }

    async fn unpack(&self, row: Option<Record>) -> ProviderResult<Option<Map<String, Value>>> {
        let Some(row) = row else {
            return Ok(None);
        };
        if number_member(&row, "expiresAt").is_none_or(|expires| expires <= js::now_ms()) {
            return Ok(None);
        }
        let payload = self
            .shared
            .crypt
            .open_object(str_member(&row, "encrypted").unwrap_or_default())?;
        match self.shared.scope(&payload).await {
            Ok(tenant) if Some(tenant.as_str()) == str_member(&row, "boundTenantId") => {}
            _ => return Ok(None),
        }
        if self.model == "Grant"
            && let Some(jti) = str_member(&payload, "jti").filter(|jti| !jti.is_empty())
            && self
                .shared
                .valid_grant_session(jti, str_member(&payload, "accountId"))
                .await
                .is_err()
        {
            return Ok(None);
        }
        if self.model == "Session" && truthy(payload.get("accountId")) {
            let grants: Vec<String> = payload
                .get("authorizations")
                .and_then(Value::as_object)
                .map(|authorizations| {
                    authorizations
                        .values()
                        .filter_map(|value| value.get("grantId").and_then(Value::as_str))
                        .filter(|grant| !grant.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            if grants.is_empty() {
                return Ok(None);
            }
            let mut any = false;
            for grant in &grants {
                if self
                    .shared
                    .valid_grant_session(grant, str_member(&payload, "accountId"))
                    .await
                    .is_ok()
                {
                    any = true;
                }
            }
            if !any {
                return Ok(None);
            }
        }
        if let Some(grant_hash) = str_member(&row, "grantIdHash").filter(|hash| !hash.is_empty())
            && self
                .shared
                .store
                .get("oauthRevokedGrants", grant_hash)
                .await?
                .is_some()
        {
            return Ok(None);
        }
        Ok(Some(payload))
    }

    /// `find(id)`.
    pub async fn find(&self, id: &str) -> ProviderResult<Option<Map<String, Value>>> {
        if self.model == "Client" {
            let row = live_client(self.shared.store.as_ref(), id).await?;
            return match row {
                Some(row) => {
                    Ok(Some(self.shared.crypt.open_object(
                        str_member(&row, "encrypted").unwrap_or_default(),
                    )?))
                }
                None => Ok(None),
            };
        }
        let row = self
            .shared
            .store
            .get("oauthArtifacts", &self.record_id(id))
            .await?;
        self.unpack(row).await
    }

    async fn find_by(
        &self,
        field: &str,
        value: &str,
    ) -> ProviderResult<Option<Map<String, Value>>> {
        let rows = self
            .shared
            .store
            .find(
                "oauthArtifacts",
                &Filter::new()
                    .eq("model", self.model.clone())
                    .eq(field, hash(value)),
                &FindOptions::default(),
            )
            .await?;
        self.unpack(rows.into_iter().next()).await
    }

    /// `findByUid(uid)`.
    pub async fn find_by_uid(&self, uid: &str) -> ProviderResult<Option<Map<String, Value>>> {
        self.find_by("uidHash", uid).await
    }

    /// `findByUserCode(userCode)`.
    pub async fn find_by_user_code(
        &self,
        user_code: &str,
    ) -> ProviderResult<Option<Map<String, Value>>> {
        self.find_by("userCodeHash", user_code).await
    }

    /// `destroy(id)`.
    pub async fn destroy(&self, id: &str) -> ProviderResult<()> {
        let record_id = self.record_id(id);
        self.shared
            .store
            .transaction(move |tx| async move { tx.delete("oauthArtifacts", &record_id).await })
            .await?;
        Ok(())
    }

    /// `consume(id)`: single use; a second consumption revokes the whole grant family, including tokens issued by a
    /// racing request.
    pub async fn consume(&self, id: &str) -> ProviderResult<()> {
        let record_id = self.record_id(id);
        let crypt = self.shared.crypt.clone();
        let outcome: (bool, Option<String>) = self
            .shared
            .store
            .transaction(move |tx| async move {
                let row = tx.get("oauthArtifacts", &record_id).await?;
                let Some(mut row) = row.filter(|row| {
                    number_member(row, "expiresAt").is_some_and(|expires| expires > js::now_ms())
                }) else {
                    return Ok((true, None));
                };
                let mut payload =
                    crypt.open_object(str_member(&row, "encrypted").unwrap_or_default())?;
                if truthy(payload.get("consumed")) {
                    return Ok((true, str_member(&payload, "grantId").map(str::to_owned)));
                }
                payload.insert(
                    "consumed".into(),
                    json!((js::now_ms() / 1000.0).floor() as i64),
                );
                row.insert(
                    "encrypted".into(),
                    json!(crypt.seal(&Value::Object(payload))),
                );
                tx.put("oauthArtifacts", &row).await?;
                Ok((false, None))
            })
            .await?;
        // Commit family revocation before throwing. Rejected requests cannot roll it back.
        if outcome.0 {
            if let Some(grant_id) = outcome.1.filter(|grant| !grant.is_empty()) {
                self.revoke_by_grant_id(&grant_id).await?;
            }
            return Err(OidcError::invalid_grant(
                "Credential is unavailable or has already been consumed.",
            )
            .into());
        }
        Ok(())
    }

    /// `revokeByGrantId(grantId)`.
    pub async fn revoke_by_grant_id(&self, grant_id: &str) -> ProviderResult<()> {
        let grant_id_hash = hash(grant_id);
        let (operation, owner) = {
            let mut pending = self
                .shared
                .pending_revocations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match pending.get(&grant_id_hash) {
                Some(existing) => (existing.clone(), false),
                None => {
                    let store = self.shared.store.clone();
                    let hash_value = grant_id_hash.clone();
                    let grant_record = hash(&format!("Grant:{grant_id}"));
                    let operation: BoxFuture<'static, Result<(), ProviderError>> = async move {
                        store
                            .transaction(move |tx| async move {
                                if tx.get("oauthRevokedGrants", &hash_value).await?.is_none() {
                                    let mut record = Map::new();
                                    record.insert("id".into(), json!(hash_value));
                                    record.insert("tenantId".into(), json!(PROTOCOL_TENANT));
                                    record.insert(
                                        "revokedAt".into(),
                                        js::number(js::now_ms()).unwrap_or(Value::Null),
                                    );
                                    tx.insert("oauthRevokedGrants", &record).await?;
                                }
                                for row in tx
                                    .find(
                                        "oauthArtifacts",
                                        &Filter::new().eq("grantIdHash", hash_value.clone()),
                                        &FindOptions::default(),
                                    )
                                    .await?
                                {
                                    tx.delete(
                                        "oauthArtifacts",
                                        str_member(&row, "id").unwrap_or_default(),
                                    )
                                    .await?;
                                }
                                tx.delete("oauthArtifacts", &grant_record).await?;
                                Ok(())
                            })
                            .await
                            .map_err(ProviderError::from)
                    }
                    .boxed();
                    let shared = operation.shared();
                    pending.insert(grant_id_hash.clone(), shared.clone());
                    (shared, true)
                }
            }
        };
        let result = operation.await;
        if owner {
            self.shared
                .pending_revocations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&grant_id_hash);
        }
        result
    }
}

static CARRIER_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static CARRIED_ERRORS: Mutex<Vec<(String, ProviderError)>> = Mutex::new(Vec::new());

/// Carries a protocol error through a store transaction (whose callback returns [`IamError`]): the error is parked
/// and an [`IamError`] with a unique marker code takes its place until [`iam_carrier_to_provider`] restores it.
pub(crate) fn provider_to_iam_carrier(error: ProviderError) -> IamError {
    match error {
        ProviderError::Iam(error) => error,
        ProviderError::Oidc(error) => {
            let marker = format!(
                "OAUTH_PROTOCOL_ERROR#{}",
                CARRIER_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            );
            let message = error.error.clone();
            let status = error.status;
            CARRIED_ERRORS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((marker.clone(), ProviderError::Oidc(error)));
            IamError::with_status(marker, message, status)
        }
    }
}

/// Restores an error parked by [`provider_to_iam_carrier`].
pub(crate) fn iam_carrier_to_provider(error: IamError) -> ProviderError {
    if error.code.starts_with("OAUTH_PROTOCOL_ERROR#") {
        let mut carried = CARRIED_ERRORS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(index) = carried.iter().position(|(marker, _)| *marker == error.code) {
            return carried.remove(index).1;
        }
    }
    ProviderError::Iam(error)
}
