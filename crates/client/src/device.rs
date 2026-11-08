//! Registered-device proofs (`@better-iam/client/device`).
//!
//! A device keeps an ECDSA P-256 key pair it creates on first use, enrols the public half once with
//! `devices.enroll`, and then signs a short-lived proof bound to the session it presents. Proofs are compact JWS
//! (`ES256`, `typ: device-proof+jwt`, `kid` = the key's RFC 7638 thumbprint) over `{ iat, sid, tid? }`, reused for
//! up to four minutes per session id and tenant id. The server reads them from `x-better-iam-device`; a missing or
//! invalid proof only means "no device". The server keeps each key for one account only, so a process used with
//! several accounts needs a prover (and key) per account: pass each its own `scope`, such as the identity id.
//!
//! ```ignore
//! let device = create_device_prover(DeviceProverOptions::default())?;
//! let prover = device.clone();
//! let session_id = Arc::new(Mutex::new(None::<String>));
//! let current = session_id.clone();
//! let client = create_iam_client(ClientOptions::new(origin).headers_fn(move || {
//!     let (prover, id) = (prover.clone(), current.lock().unwrap().clone());
//!     async move { Ok(prover.headers(id.as_deref(), None).await) }
//! }))?;
//! *session_id.lock().unwrap() = Some(client.auth().get_session().await?.session.id);
//! let public_key = device.public_jwk().await?;
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock, Weak};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use indexmap::IndexMap;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{BoxError, Error, HeaderList, IamClientError};

/// The request header that carries a device proof.
pub const DEVICE_PROOF_HEADER: &str = "x-better-iam-device";

const DEFAULT_DATABASE: &str = "better-iam-registered-device";
const OBJECT_STORE_NAME: &str = "keys";
const RECORD_KEY: &str = "current";
/// Serializes first-time key creation across provers, so two opened together settle on one key.
const CREATION_LOCK: &str = "better-iam:registered-device-key";
const PROOF_TYPE: &str = "device-proof+jwt";
/// The server accepts `iat` within 300 seconds of its clock; reuse leaves a minute of that window.
const PROOF_REUSE_MS: f64 = 240_000.0;
const MAX_CACHED_PROOFS: usize = 16;

fn base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Printable ASCII without spaces (`/^[!-~]{1,max}$/`).
fn printable(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| (b'!'..=b'~').contains(&byte))
}

/// A device key pair: an ECDSA P-256 signing key and its public key.
///
/// Pairs the prover generates are non-extractable: nothing in this crate hands out their private key, which
/// stays inside the pair (WebCrypto's `extractable: false`). A pair built from a signing key you hold is
/// extractable, and [`indexed_db_key_store`] refuses to keep it.
#[derive(Clone)]
pub struct DeviceKeyPair {
    signing: Arc<SigningKey>,
    public: VerifyingKey,
    extractable: bool,
}

impl DeviceKeyPair {
    /// A fresh, non-extractable pair.
    pub fn generate() -> Self {
        let signing = SigningKey::random(&mut rand::rngs::OsRng);
        let public = *signing.verifying_key();
        Self {
            signing: Arc::new(signing),
            public,
            extractable: false,
        }
    }

    /// A pair from a signing key the caller holds (extractable).
    pub fn from_signing_key(signing: SigningKey) -> Self {
        let public = *signing.verifying_key();
        Self {
            signing: Arc::new(signing),
            public,
            extractable: true,
        }
    }

    pub fn public_key(&self) -> &VerifyingKey {
        &self.public
    }

    /// Whether the private key is available outside the pair.
    pub fn extractable(&self) -> bool {
        self.extractable
    }

    /// Whether both pairs hold the same key.
    pub fn same_key(&self, other: &DeviceKeyPair) -> bool {
        self.public == other.public
    }

    /// The ES256 signature of `data`: r and s as two 32-byte big-endian integers (the JOSE form).
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing.sign(data);
        signature.to_bytes().to_vec()
    }
}

impl fmt::Debug for DeviceKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceKeyPair")
            .field("public", &self.public)
            .field("extractable", &self.extractable)
            .finish_non_exhaustive()
    }
}

/// Where a device keeps its signing key between runs (`DeviceKeyStore`).
#[async_trait::async_trait]
pub trait DeviceKeyStore: Send + Sync {
    async fn load(&self) -> Result<Option<DeviceKeyPair>, BoxError>;
    async fn save(&self, pair: &DeviceKeyPair) -> Result<(), BoxError>;
    async fn clear(&self) -> Result<(), BoxError>;
}

/// Keeps the key pair in memory only: for tests, scripts, and servers that re-enrol after a restart.
#[derive(Default)]
pub struct MemoryKeyStore {
    current: Mutex<Option<DeviceKeyPair>>,
}

impl MemoryKeyStore {
    fn current(&self) -> MutexGuard<'_, Option<DeviceKeyPair>> {
        self.current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[async_trait::async_trait]
impl DeviceKeyStore for MemoryKeyStore {
    async fn load(&self) -> Result<Option<DeviceKeyPair>, BoxError> {
        Ok(self.current().clone())
    }

    async fn save(&self, pair: &DeviceKeyPair) -> Result<(), BoxError> {
        *self.current() = Some(pair.clone());
        Ok(())
    }

    async fn clear(&self) -> Result<(), BoxError> {
        *self.current() = None;
        Ok(())
    }
}

/// `memoryKeyStore()`.
pub fn memory_key_store() -> Arc<dyn DeviceKeyStore> {
    Arc::new(MemoryKeyStore::default())
}

/// The host's persistent key database, the counterpart of a browser's `indexedDB`: databases by name, each with
/// object stores holding key pairs by key, kept as they are (never exported). A Rust host that has one (a desktop
/// app's secure storage, a test double) installs it with [`set_key_database`]; [`indexed_db_key_store`] and the
/// default store of [`create_device_prover`] use it.
#[async_trait::async_trait]
pub trait KeyDatabase: Send + Sync {
    /// The pair under `key` in object store `store` of database `database` (created empty on first use).
    async fn get(
        &self,
        database: &str,
        store: &str,
        key: &str,
    ) -> Result<Option<DeviceKeyPair>, BoxError>;
    async fn put(
        &self,
        database: &str,
        store: &str,
        key: &str,
        pair: DeviceKeyPair,
    ) -> Result<(), BoxError>;
    async fn delete(&self, database: &str, store: &str, key: &str) -> Result<(), BoxError>;
}

fn key_database_slot() -> &'static RwLock<Option<Arc<dyn KeyDatabase>>> {
    static SLOT: OnceLock<RwLock<Option<Arc<dyn KeyDatabase>>>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(None))
}

/// Installs (or, with `None`, removes) the process's key database; returns the previous one.
pub fn set_key_database(database: Option<Arc<dyn KeyDatabase>>) -> Option<Arc<dyn KeyDatabase>> {
    let mut slot = key_database_slot()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    std::mem::replace(&mut *slot, database)
}

fn key_database() -> Option<Arc<dyn KeyDatabase>> {
    key_database_slot()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn unsupported(message: &str) -> BoxError {
    Arc::new(IamClientError::new("UNSUPPORTED_ENVIRONMENT", message, 0))
}

/// Keeps the key pair in the host's key database (see [`KeyDatabase`]), database `name`, one record. Saving an
/// extractable private key is refused. Every call fails with `UNSUPPORTED_ENVIRONMENT` where no key database is
/// installed.
pub struct IndexedDbKeyStore {
    name: String,
}

/// `indexedDbKeyStore(name)`: the name defaults to `better-iam-registered-device`.
pub fn indexed_db_key_store(name: Option<&str>) -> Result<IndexedDbKeyStore, Error> {
    let name = name.unwrap_or(DEFAULT_DATABASE);
    let length = name.encode_utf16().count();
    if length == 0 || length > 128 {
        return Err(IamClientError::new(
            "INVALID_CONFIG",
            "indexedDbKeyStore needs a database name of 1 to 128 characters",
            0,
        )
        .into());
    }
    Ok(IndexedDbKeyStore {
        name: name.to_owned(),
    })
}

impl IndexedDbKeyStore {
    fn open(&self) -> Result<Arc<dyn KeyDatabase>, BoxError> {
        key_database().ok_or_else(|| {
            unsupported(
                "IndexedDB is not available here; use memoryKeyStore() or your own DeviceKeyStore outside browsers",
            )
        })
    }
}

#[async_trait::async_trait]
impl DeviceKeyStore for IndexedDbKeyStore {
    async fn load(&self) -> Result<Option<DeviceKeyPair>, BoxError> {
        self.open()?
            .get(&self.name, OBJECT_STORE_NAME, RECORD_KEY)
            .await
    }

    async fn save(&self, pair: &DeviceKeyPair) -> Result<(), BoxError> {
        if pair.extractable {
            return Err(Arc::new(IamClientError::new(
                "INVALID_INPUT",
                "indexedDbKeyStore keeps only non-extractable private keys",
                0,
            )));
        }
        self.open()?
            .put(&self.name, OBJECT_STORE_NAME, RECORD_KEY, pair.clone())
            .await
    }

    async fn clear(&self) -> Result<(), BoxError> {
        self.open()?
            .delete(&self.name, OBJECT_STORE_NAME, RECORD_KEY)
            .await
    }
}

/// The public half of a device key, as `devices.enroll` takes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePublicJwk {
    /// `EC`.
    pub kty: String,
    /// `P-256`.
    pub crv: String,
    pub x: String,
    pub y: String,
}

/// The hook of [`DeviceProverOptions::on_error`].
pub type ErrorHook = Arc<dyn Fn(&Error) + Send + Sync>;

/// The clock of a prover, in milliseconds.
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

/// `DeviceProverOptions`.
#[derive(Clone, Default)]
pub struct DeviceProverOptions {
    /// Where the key pair lives. Defaults to [`indexed_db_key_store`] when a [`KeyDatabase`] is installed and to
    /// [`memory_key_store`] otherwise, where the key lasts only as long as the process.
    pub store: Option<Arc<dyn DeviceKeyStore>>,
    /// Keeps a separate key pair per scope in the default store, such as the signed-in identity's id. 1 to 64
    /// printable characters without spaces; ignored when `store` is given.
    pub scope: Option<String>,
    /// The signature algorithm. Only `ES256` (ECDSA P-256 with SHA-256) is supported.
    pub algorithm: Option<String>,
    /// The clock, in milliseconds, used for a proof's `iat`. Defaults to the system clock. The server accepts proofs
    /// issued up to five minutes either side of its own clock; on devices whose clocks drift further, pass one
    /// corrected with the server time that `auth.getSession()` returns as `limits.now`.
    pub now: Option<Clock>,
    /// Called when [`DeviceProver::headers`] could not produce a proof. `headers()` then sends no proof, which the
    /// server treats as "no device".
    pub on_error: Option<ErrorHook>,
}

struct ActiveKey {
    pair: DeviceKeyPair,
    jwk: DevicePublicJwk,
    kid: String,
    /// The encoded protected header, the same for every proof of this key.
    header: String,
}

type KeyFuture = Shared<BoxFuture<'static, Result<Arc<ActiveKey>, Error>>>;
type ProofFuture = Shared<BoxFuture<'static, Result<String, Error>>>;

struct CachedProof {
    id: u64,
    issued_at: f64,
    token: ProofFuture,
}

#[derive(Default)]
struct ProverState {
    active: Option<(u64, KeyFuture)>,
    proofs: IndexMap<String, CachedProof>,
    next_id: u64,
}

struct ProverInner {
    store: Arc<dyn DeviceKeyStore>,
    lock_name: String,
    clock: Clock,
    on_error: Option<ErrorHook>,
    state: Mutex<ProverState>,
    /// Key creation and reset run one at a time, so a reset never races a key that is still being saved.
    lane: tokio::sync::Mutex<()>,
}

/// Proves which registered device a request comes from (`DeviceProver`). Clones share the key and the cache.
#[derive(Clone)]
pub struct DeviceProver {
    inner: Arc<ProverInner>,
}

/// A store failure as the prover reports it: the client error a store raised, or the store's own error.
fn from_store(error: BoxError) -> Error {
    match error.downcast_ref::<IamClientError>() {
        Some(client) => client.clone().into(),
        None => Error::Other(error),
    }
}

/// The process-wide named locks (the Web Locks API of browsers): one creation at a time per name.
fn named_lock(name: &str) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let mut locks = LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(name).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(name.to_owned(), Arc::downgrade(&lock));
    lock
}

fn invalid_config(message: &str) -> Error {
    IamClientError::new("INVALID_CONFIG", message, 0).into()
}

/// `Date.now()`.
fn system_now() -> f64 {
    better_iam_core::js::now_ms()
}

/// `createDeviceProver(options)`.
pub fn create_device_prover(options: DeviceProverOptions) -> Result<DeviceProver, Error> {
    if options
        .algorithm
        .as_deref()
        .is_some_and(|algorithm| algorithm != "ES256")
    {
        return Err(invalid_config(
            "Device proofs support only the ES256 algorithm",
        ));
    }
    let scope = options.scope.as_deref();
    if scope.is_some_and(|scope| !printable(scope, 64)) {
        return Err(invalid_config(
            "scope must be 1 to 64 printable characters without spaces",
        ));
    }
    let store = match options.store {
        Some(store) => store,
        None if key_database().is_some() => {
            let name = match scope {
                Some(scope) => format!("{DEFAULT_DATABASE}:{scope}"),
                None => DEFAULT_DATABASE.to_owned(),
            };
            Arc::new(indexed_db_key_store(Some(&name))?)
        }
        None => memory_key_store(),
    };
    let lock_name = match scope {
        Some(scope) => format!("{CREATION_LOCK}:{scope}"),
        None => CREATION_LOCK.to_owned(),
    };
    Ok(DeviceProver {
        inner: Arc::new(ProverInner {
            store,
            lock_name,
            clock: options.now.unwrap_or_else(|| Arc::new(system_now)),
            on_error: options.on_error,
            state: Mutex::new(ProverState::default()),
            lane: tokio::sync::Mutex::new(()),
        }),
    })
}

async fn load_or_create(store: &dyn DeviceKeyStore) -> Result<DeviceKeyPair, Error> {
    if let Some(stored) = store.load().await.map_err(from_store)? {
        return Ok(stored);
    }
    let pair = DeviceKeyPair::generate();
    store.save(&pair).await.map_err(from_store)?;
    Ok(pair)
}

fn describe(pair: DeviceKeyPair) -> ActiveKey {
    let point = pair.public.to_encoded_point(false);
    let coordinate =
        |bytes: Option<&p256::FieldBytes>| bytes.map(|bytes| base64url(bytes)).unwrap_or_default();
    let jwk = DevicePublicJwk {
        kty: "EC".to_owned(),
        crv: "P-256".to_owned(),
        x: coordinate(point.x()),
        y: coordinate(point.y()),
    };
    // RFC 7638: the required members only, in lexicographic order, without whitespace.
    let canonical = better_iam_core::js::stringify(&serde_json::json!({
        "crv": jwk.crv, "kty": jwk.kty, "x": jwk.x, "y": jwk.y,
    }));
    let kid = base64url(&Sha256::digest(canonical.as_bytes()));
    let header = base64url(
        better_iam_core::js::stringify(&serde_json::json!({
            "alg": "ES256", "typ": PROOF_TYPE, "kid": kid,
        }))
        .as_bytes(),
    );
    ActiveKey {
        pair,
        jwk,
        kid,
        header,
    }
}

fn check_id(value: &str, name: &str) -> Result<(), Error> {
    if printable(value, 256) {
        return Ok(());
    }
    Err(IamClientError::new(
        "INVALID_INPUT",
        format!("{name} must be 1 to 256 printable characters without spaces"),
        0,
    )
    .into())
}

impl ProverInner {
    fn state(&self) -> MutexGuard<'_, ProverState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn current_key(self: &Arc<Self>) -> KeyFuture {
        let mut state = self.state();
        if let Some((_, active)) = &state.active {
            return active.clone();
        }
        state.next_id += 1;
        let id = state.next_id;
        let inner = self.clone();
        let pending = async move {
            let result = async {
                let _lane = inner.lane.lock().await;
                let lock = named_lock(&inner.lock_name);
                let pair = {
                    let _held = lock.lock().await;
                    load_or_create(inner.store.as_ref()).await?
                };
                Ok(Arc::new(describe(pair)))
            }
            .await;
            // A failure is not remembered: the next call tries again.
            if result.is_err() {
                let mut state = inner.state();
                if state
                    .active
                    .as_ref()
                    .is_some_and(|(active, _)| *active == id)
                {
                    state.active = None;
                }
            }
            result
        }
        .boxed()
        .shared();
        state.active = Some((id, pending.clone()));
        pending
    }

    async fn sign(
        self: Arc<Self>,
        session_id: String,
        tenant_id: Option<String>,
        issued_at: f64,
    ) -> Result<String, Error> {
        let key = self.current_key().await?;
        let mut claims = Map::new();
        claims.insert(
            "iat".into(),
            better_iam_core::js::number((issued_at / 1000.0).floor()).unwrap_or(Value::Null),
        );
        claims.insert("sid".into(), Value::String(session_id));
        if let Some(tenant_id) = tenant_id {
            claims.insert("tid".into(), Value::String(tenant_id));
        }
        let payload = better_iam_core::js::stringify(&Value::Object(claims));
        let signing_input = format!("{}.{}", key.header, base64url(payload.as_bytes()));
        let signature = key.pair.sign(signing_input.as_bytes());
        if signature.len() != 64 {
            return Err(IamClientError::new(
                "UNSUPPORTED_ENVIRONMENT",
                "WebCrypto returned an ECDSA signature that is not in the raw r||s form",
                0,
            )
            .into());
        }
        Ok(format!("{signing_input}.{}", base64url(&signature)))
    }
}

impl DeviceProver {
    /// The public JWK for `devices.enroll` (EC P-256).
    pub async fn public_jwk(&self) -> Result<DevicePublicJwk, Error> {
        Ok(self.inner.current_key().await?.jwk.clone())
    }

    /// The RFC 7638 thumbprint (the key id).
    pub async fn key_id(&self) -> Result<String, Error> {
        Ok(self.inner.current_key().await?.kid.clone())
    }

    /// A fresh compact JWS for the given session id (cached about four minutes per session id and tenant id).
    pub async fn proof(&self, session_id: &str, tenant_id: Option<&str>) -> Result<String, Error> {
        check_id(session_id, "sessionId")?;
        if let Some(tenant_id) = tenant_id {
            check_id(tenant_id, "tenantId")?;
        }
        let now = (self.inner.clock)();
        if !now.is_finite() {
            return Err(invalid_config("now() must return milliseconds"));
        }
        let fresh =
            |entry: &CachedProof| entry.issued_at <= now && now - entry.issued_at < PROOF_REUSE_MS;
        // Ids never contain spaces, so the pair maps to one cache key without ambiguity.
        let cache_key = match tenant_id {
            Some(tenant_id) => format!("{session_id} {tenant_id}"),
            None => session_id.to_owned(),
        };
        let token = {
            let mut state = self.inner.state();
            match state.proofs.get(&cache_key).filter(|entry| fresh(entry)) {
                Some(cached) => cached.token.clone(),
                None => {
                    state.proofs.retain(|_, entry| fresh(entry));
                    while state.proofs.len() >= MAX_CACHED_PROOFS {
                        state.proofs.shift_remove_index(0);
                    }
                    state.next_id += 1;
                    let id = state.next_id;
                    let inner = self.inner.clone();
                    let signing = self.inner.clone().sign(
                        session_id.to_owned(),
                        tenant_id.map(str::to_owned),
                        now,
                    );
                    let key = cache_key.clone();
                    let token = async move {
                        let result = signing.await;
                        if result.is_err() {
                            let mut state = inner.state();
                            if state.proofs.get(&key).is_some_and(|entry| entry.id == id) {
                                state.proofs.shift_remove(&key);
                            }
                        }
                        result
                    }
                    .boxed()
                    .shared();
                    state.proofs.insert(
                        cache_key,
                        CachedProof {
                            id,
                            issued_at: now,
                            token: token.clone(),
                        },
                    );
                    token
                }
            }
        };
        token.await
    }

    /// Headers for [`ClientOptions::headers_fn`](crate::ClientOptions::headers_fn): `x-better-iam-device` with a
    /// proof once a session id is known. No headers while the session id is unknown, and when no proof can be made
    /// (reported to `on_error`), so a device problem never fails the request itself.
    pub async fn headers(&self, session_id: Option<&str>, tenant_id: Option<&str>) -> HeaderList {
        let Some(session_id) = session_id.filter(|id| !id.is_empty()) else {
            return Vec::new();
        };
        match self.proof(session_id, tenant_id).await {
            Ok(proof) => vec![(DEVICE_PROOF_HEADER.to_owned(), proof)],
            Err(error) => {
                if let Some(hook) = &self.inner.on_error {
                    // A hook that fails never fails the request that asked for headers.
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook(&error)));
                }
                Vec::new()
            }
        }
    }

    /// Forgets the key pair (in memory and in the store) and every cached proof; the next proof uses a new key.
    pub async fn reset(&self) -> Result<(), Error> {
        {
            let mut state = self.inner.state();
            state.active = None;
            state.proofs.clear();
        }
        let _lane = self.inner.lane.lock().await;
        self.inner.store.clear().await.map_err(from_store)
    }
}
