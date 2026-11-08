//! OpenID Shared Signals Framework transmitter (ssf.ts): turns IAM audit events into signed Security Event Tokens
//! (RFC 8417) with CAEP and RISC event types and pushes them to each tenant's receivers (RFC 8935) with retries.

use std::collections::HashMap;
use std::sync::Arc;

use better_iam_auth::safe_fetch::{
    FetchBody, FetchError, FetchRequest, FetchResponse, GuardedFetch, GuardedFetchOptions,
    RedirectMode, SafeFetchAddressOptions, check_fetch_url, create_guarded_fetch,
};
use better_iam_core::{
    CredentialInput, Filter, FindOptions, IamError, IamResult, IamStore, IamStoreExt, Record,
    ResourceRef, append_audit_event, js, tenant_tree_active,
};
use bytes::Bytes;
use futures::future::BoxFuture;
use serde_json::{Map, Value, json};

use crate::adapter::{Cipher, truthy};
use crate::jose;
use crate::resource_server::{HttpRequest, HttpResponse, request_url_string, response};

const CAEP: &str = "https://schemas.openid.net/secevent/caep/event-type";
const RISC: &str = "https://schemas.openid.net/secevent/risc/event-type";
const SSF: &str = "https://schemas.openid.net/secevent/ssf/event-type";
const PUSH: &str = "urn:ietf:rfc:8935";

/// Security event types the transmitter emits (`sharedSignalEvents`).
pub mod shared_signal_events {
    pub const SESSION_REVOKED: &str =
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    pub const CREDENTIAL_CHANGE: &str =
        "https://schemas.openid.net/secevent/caep/event-type/credential-change";
    pub const IDENTIFIER_CHANGED: &str =
        "https://schemas.openid.net/secevent/risc/event-type/identifier-changed";
    pub const ACCOUNT_DISABLED: &str =
        "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
    pub const ACCOUNT_PURGED: &str =
        "https://schemas.openid.net/secevent/risc/event-type/account-purged";
}

/// Every supported event type, in declaration order.
pub fn supported_events() -> Vec<String> {
    vec![
        format!("{CAEP}/session-revoked"),
        format!("{CAEP}/credential-change"),
        format!("{RISC}/identifier-changed"),
        format!("{RISC}/account-disabled"),
        format!("{RISC}/account-purged"),
    ]
}

/// Which IAM audit events become which security event, and the event-specific claims.
fn mapping(action: &str) -> Option<(String, Vec<(&'static str, &'static str)>)> {
    use shared_signal_events::*;
    let revoked = (SESSION_REVOKED.to_owned(), vec![]);
    let password = (
        CREDENTIAL_CHANGE.to_owned(),
        vec![("credential_type", "password"), ("change_type", "update")],
    );
    Some(match action {
        "auth:session:revoke"
        | "auth:session:revoke-others"
        | "identity:revoke-sessions"
        | "tenant:revoke-sessions" => revoked,
        "auth:password:change" | "auth:password:reset" => password,
        "auth:mfa:enable" => (
            CREDENTIAL_CHANGE.to_owned(),
            vec![("credential_type", "app"), ("change_type", "create")],
        ),
        "auth:mfa:disable" => (
            CREDENTIAL_CHANGE.to_owned(),
            vec![("credential_type", "app"), ("change_type", "delete")],
        ),
        "auth:passkey:create" => (
            CREDENTIAL_CHANGE.to_owned(),
            vec![
                ("credential_type", "fido2-platform"),
                ("change_type", "create"),
            ],
        ),
        "auth:passkey:delete" => (
            CREDENTIAL_CHANGE.to_owned(),
            vec![
                ("credential_type", "fido2-platform"),
                ("change_type", "delete"),
            ],
        ),
        "auth:email:change" | "identity:email-change" => (IDENTIFIER_CHANGED.to_owned(), vec![]),
        "identity:offboard" | "identity:expire" => (ACCOUNT_DISABLED.to_owned(), vec![]),
        "identity:delete" => (ACCOUNT_PURGED.to_owned(), vec![]),
        // Identity threat detection and response: ended sessions and containment.
        "threat:revoke-sessions" => revoked,
        "threat:contain" => (ACCOUNT_DISABLED.to_owned(), vec![]),
        _ => return None,
    })
}

/// The audit actions the transmitter subscribes to (`Object.keys(mapping)`).
pub const MAPPED_ACTIONS: [&str; 17] = [
    "auth:session:revoke",
    "auth:session:revoke-others",
    "identity:revoke-sessions",
    "tenant:revoke-sessions",
    "auth:password:change",
    "auth:password:reset",
    "auth:mfa:enable",
    "auth:mfa:disable",
    "auth:passkey:create",
    "auth:passkey:delete",
    "auth:email:change",
    "identity:email-change",
    "identity:offboard",
    "identity:expire",
    "identity:delete",
    "threat:revoke-sessions",
    "threat:contain",
];

/// The audit actions with a mapping.
pub fn mapped_actions() -> Vec<&'static str> {
    MAPPED_ACTIONS.to_vec()
}

/// `authorize(credential, action, resource)` of the host (`iam:ssf:streams:*` on `ssf/{streamId}`).
pub type AuthorizeFn = Arc<
    dyn Fn(CredentialInput, String, ResourceRef) -> BoxFuture<'static, IamResult<()>> + Send + Sync,
>;
/// `authenticate(credential)` of the host: the identity ID of the caller.
pub type AuthenticateIdFn =
    Arc<dyn Fn(CredentialInput) -> BoxFuture<'static, IamResult<String>> + Send + Sync>;
/// A replacement transport (`config.fetch`).
pub type FetchFn = Arc<
    dyn Fn(FetchRequest) -> BoxFuture<'static, Result<FetchResponse, FetchError>> + Send + Sync,
>;

/// `SharedSignalsConfig`.
#[derive(Clone)]
pub struct SharedSignalsConfig {
    pub store: Arc<dyn IamStore>,
    pub authorize: AuthorizeFn,
    pub authenticate: AuthenticateIdFn,
    /// The transmitter's issuer (usually the OAuth issuer).
    pub issuer: String,
    /// Private signing keys (`{ keys: [...] }`); the first key with `alg` and `d` signs.
    pub jwks: Value,
    pub jwks_uri: Option<String>,
    /// Base64-encoded 32-byte key encrypting receivers' authorization headers at rest.
    pub encryption_key: String,
    pub allow_insecure_localhost: bool,
    pub allow_private_networks: bool,
    pub timeout_ms: Option<u64>,
    pub fetch: Option<FetchFn>,
}

/// `StreamInput` (partial for updates: every member optional; `authorization: Some(None)` removes the header).
#[derive(Debug, Clone, Default)]
pub struct StreamInput {
    pub name: Option<Value>,
    pub endpoint_url: Option<Value>,
    pub audience: Option<Value>,
    pub authorization: Option<Option<Value>>,
    pub events: Option<Value>,
    pub subject_format: Option<Value>,
    pub enabled: Option<Value>,
}

impl StreamInput {
    /// Reads the members of a JSON input (`authorization: null` is kept as a removal).
    pub fn from_value(input: &Value) -> Self {
        let member = |name: &str| input.get(name).filter(|value| !value.is_null()).cloned();
        Self {
            name: member("name"),
            endpoint_url: member("endpointUrl"),
            audience: member("audience"),
            authorization: input
                .get("authorization")
                .map(|value| (!value.is_null()).then(|| value.clone())),
            events: member("events"),
            subject_format: member("subjectFormat"),
            enabled: member("enabled"),
        }
    }
}

const LOOPBACK: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];
const MAX_ATTEMPTS: f64 = 8.0;

/// Backoff after each failed attempt: 30 s, 2 min, 8 min, ~30 min, then 2 h.
fn backoff(attempts: f64) -> f64 {
    (30_000.0 * 4f64.powf(attempts - 1.0)).min(2.0 * 3_600_000.0)
}

fn str_member<'a>(record: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

fn num(record: &Map<String, Value>, key: &str) -> f64 {
    record.get(key).and_then(Value::as_f64).unwrap_or(0.0)
}

fn number(value: f64) -> Value {
    js::number(value).unwrap_or(Value::Null)
}

fn invalid_input(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

fn hostname_of(url: &url::Url) -> String {
    match url.host() {
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        Some(host) => host.to_string(),
        None => String::new(),
    }
}

struct Signer {
    jwk: Map<String, Value>,
    key: Result<jose::Key, jose::JoseError>,
}

/// `createSharedSignalsTransmitter(config)`.
pub struct SharedSignalsTransmitter {
    config: SharedSignalsConfig,
    crypt: Cipher,
    signer: Signer,
    issuer: String,
    jwks_uri: String,
    address_rules: SafeFetchAddressOptions,
    guarded: GuardedFetch,
    timeout_ms: u64,
    discovery_path: String,
}

impl std::fmt::Debug for SharedSignalsTransmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedSignalsTransmitter")
    }
}

/// `createSharedSignalsTransmitter(config)`.
pub fn create_shared_signals_transmitter(
    config: SharedSignalsConfig,
) -> IamResult<Arc<SharedSignalsTransmitter>> {
    let key: [u8; 32] = jose::b64_decode_lenient(&config.encryption_key)
        .try_into()
        .map_err(|_| {
            IamError::new(
                "configuration",
                "SSF encryptionKey must encode exactly 32 bytes.",
            )
        })?;
    let signer_jwk = config
        .jwks
        .get("keys")
        .and_then(Value::as_array)
        .and_then(|keys| {
            keys.iter()
                .filter_map(Value::as_object)
                .find(|candidate| truthy(candidate.get("alg")) && truthy(candidate.get("d")))
                .cloned()
        })
        .ok_or_else(|| {
            IamError::new(
                "configuration",
                "SSF needs a private signing key with an `alg` in jwks.",
            )
        })?;
    let issuer = config
        .issuer
        .strip_suffix('/')
        .unwrap_or(&config.issuer)
        .to_owned();
    let jwks_uri = config
        .jwks_uri
        .clone()
        .unwrap_or_else(|| format!("{issuer}/jwks"));
    let signer_key = jose::import_jwk(&signer_jwk);
    let address_rules = SafeFetchAddressOptions {
        any_port: true,
        allow_insecure_localhost: config.allow_insecure_localhost,
        allow_private_networks: config.allow_private_networks,
    };
    let guarded = create_guarded_fetch(GuardedFetchOptions {
        allow_private_networks: config.allow_private_networks,
        allow_insecure_localhost: config.allow_insecure_localhost,
        any_port: true,
        max_bytes: Some(64 * 1024),
    });
    let issuer_path = url::Url::parse(&issuer)
        .map(|url| url.path().to_owned())
        .map_err(|_| IamError::new("configuration", "Invalid URL"))?;
    let discovery_path = format!(
        "/.well-known/ssf-configuration{}",
        issuer_path.strip_suffix('/').unwrap_or(&issuer_path)
    );
    Ok(Arc::new(SharedSignalsTransmitter {
        timeout_ms: config.timeout_ms.unwrap_or(10_000),
        crypt: Cipher::new(key),
        signer: Signer {
            jwk: signer_jwk,
            key: signer_key,
        },
        issuer,
        jwks_uri,
        address_rules,
        guarded,
        discovery_path,
        config,
    }))
}

/// The handler an event bus calls for each matching audit event.
pub type EventHandler = Arc<dyn Fn(Record) -> BoxFuture<'static, IamResult<()>> + Send + Sync>;

impl SharedSignalsTransmitter {
    fn endpoint(&self, value: Option<&Value>) -> IamResult<String> {
        let refused = || invalid_input("The receiver endpoint must be an absolute HTTPS URL.");
        let text = match value {
            Some(Value::String(text)) => text.clone(),
            Some(other) => js::stringify(other),
            None => "undefined".to_owned(),
        };
        let parsed = url::Url::parse(&text).map_err(|_| refused())?;
        let local = self.config.allow_insecure_localhost
            && parsed.scheme() == "http"
            && LOOPBACK.contains(&hostname_of(&parsed).as_str());
        if (parsed.scheme() != "https" && !local)
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(refused());
        }
        // IP literals are judged now; hostnames are judged by the transport each time it connects.
        check_fetch_url(parsed.as_str(), &self.address_rules).map_err(|_| {
            invalid_input(
                "The receiver endpoint must point at a public address (see allowPrivateNetworks).",
            )
        })?;
        Ok(parsed.to_string())
    }

    fn settings(
        &self,
        input: &StreamInput,
        current: Option<&Record>,
    ) -> IamResult<Map<String, Value>> {
        let current_member = |name: &str| current.and_then(|record| record.get(name)).cloned();
        let name = input.name.clone().or_else(|| current_member("name"));
        let endpoint_url = self.endpoint(
            input
                .endpoint_url
                .clone()
                .or_else(|| current_member("endpointUrl"))
                .as_ref(),
        )?;
        let audience = input
            .audience
            .clone()
            .or_else(|| current_member("audience"))
            .unwrap_or_else(|| json!(endpoint_url));
        let events = input
            .events
            .clone()
            .or_else(|| current_member("events"))
            .unwrap_or_else(|| json!(supported_events()));
        let subject_format = input
            .subject_format
            .clone()
            .or_else(|| current_member("subjectFormat"))
            .unwrap_or_else(|| json!("iss_sub"));
        let enabled = input
            .enabled
            .clone()
            .or_else(|| current_member("enabled"))
            .unwrap_or(json!(true));
        let name = match name {
            Some(Value::String(name))
                if !js::trim(&name).is_empty() && js::utf16_len(&name) <= 200 =>
            {
                name
            }
            _ => {
                return Err(invalid_input(
                    "A stream name of at most 200 characters is required.",
                ));
            }
        };
        let audience = match audience {
            Value::String(audience) if !audience.is_empty() && js::utf16_len(&audience) <= 2048 => {
                audience
            }
            _ => return Err(invalid_input("The audience must be a non-empty string.")),
        };
        let supported = supported_events();
        let events = match events {
            Value::Array(events)
                if !events.is_empty()
                    && events.iter().all(|event| {
                        event
                            .as_str()
                            .is_some_and(|event| supported.iter().any(|s| s == event))
                    }) =>
            {
                events
            }
            _ => {
                return Err(invalid_input(format!(
                    "Supported event types: {}.",
                    supported.join(", ")
                )));
            }
        };
        if subject_format != json!("iss_sub") && subject_format != json!("email") {
            return Err(invalid_input("subjectFormat must be iss_sub or email."));
        }
        if !enabled.is_boolean() {
            return Err(invalid_input("enabled must be a boolean."));
        }
        if let Some(authorization) = &input.authorization {
            let ok = authorization
                .as_ref()
                .and_then(Value::as_str)
                .is_some_and(|value| js::utf16_len(value) <= 4096 && !value.contains(['\r', '\n']));
            if !ok {
                return Err(invalid_input("The authorization header value is invalid."));
            }
        }
        let mut unique: Vec<Value> = Vec::new();
        for event in events {
            if !unique.contains(&event) {
                unique.push(event);
            }
        }
        let mut out = Map::new();
        out.insert("name".into(), json!(js::trim(&name)));
        out.insert("endpointUrl".into(), json!(endpoint_url));
        out.insert("audience".into(), json!(audience));
        out.insert("events".into(), Value::Array(unique));
        out.insert("subjectFormat".into(), subject_format);
        out.insert("enabled".into(), enabled);
        Ok(out)
    }

    async fn authorized(
        &self,
        credential: &CredentialInput,
        action: &str,
        tenant_id: &str,
        id: &str,
    ) -> IamResult<String> {
        (self.config.authorize)(
            credential.clone(),
            action.to_owned(),
            ResourceRef {
                tenant_id: tenant_id.to_owned(),
                kind: "ssf".into(),
                id: id.to_owned(),
            },
        )
        .await?;
        (self.config.authenticate)(credential.clone()).await
    }

    async fn owned(store: &dyn IamStore, tenant_id: &str, stream_id: &str) -> IamResult<Record> {
        let stream = if stream_id.is_empty() {
            None
        } else {
            store.get("ssfStreams", stream_id).await?
        };
        stream
            .filter(|stream| str_member(stream, "tenantId") == Some(tenant_id))
            .ok_or_else(|| IamError::with_status("NOT_FOUND", "Stream not found.", 404))
    }

    async fn audit(
        tx: &dyn IamStore,
        tenant_id: &str,
        actor_id: &str,
        action: &str,
        id: &str,
    ) -> IamResult<()> {
        let mut event = Map::new();
        event.insert("id".into(), json!(uuid::Uuid::new_v4().to_string()));
        event.insert("tenantId".into(), json!(tenant_id));
        event.insert("actorId".into(), json!(actor_id));
        event.insert("action".into(), json!(action));
        event.insert("resourceId".into(), json!(id));
        event.insert("timestamp".into(), number(js::now_ms()));
        event.insert("outcome".into(), json!("allow"));
        append_audit_event(tx, &event).await?;
        Ok(())
    }

    async fn summary(&self, stream: &Record, store: &dyn IamStore) -> IamResult<Value> {
        let pending = store
            .find(
                "ssfDeliveries",
                &Filter::new()
                    .eq("streamId", str_member(stream, "id").unwrap_or_default())
                    .eq("status", "pending"),
                &FindOptions::default(),
            )
            .await?
            .len();
        let mut out = Map::new();
        for key in [
            "id",
            "tenantId",
            "name",
            "endpointUrl",
            "audience",
            "events",
            "subjectFormat",
            "enabled",
        ] {
            out.insert(key.into(), stream.get(key).cloned().unwrap_or(Value::Null));
        }
        out.insert(
            "hasAuthorization".into(),
            json!(truthy(stream.get("sealedAuthorization"))),
        );
        out.insert(
            "createdAt".into(),
            stream.get("createdAt").cloned().unwrap_or(Value::Null),
        );
        out.insert(
            "updatedAt".into(),
            stream.get("updatedAt").cloned().unwrap_or(Value::Null),
        );
        out.insert("pending".into(), json!(pending));
        if truthy(stream.get("lastDeliveredAt")) {
            out.insert("lastDeliveredAt".into(), stream["lastDeliveredAt"].clone());
        }
        if truthy(stream.get("lastError")) {
            out.insert("lastError".into(), stream["lastError"].clone());
        }
        Ok(Value::Object(out))
    }

    /// A signed Security Event Token for one receiver.
    fn security_event(
        &self,
        stream: &Record,
        event_type: &str,
        subject: Value,
        claims: Value,
        txn: Option<&str>,
    ) -> IamResult<(String, String)> {
        let jti = uuid::Uuid::new_v4().to_string();
        let alg = str_member(&self.signer.jwk, "alg")
            .unwrap_or_default()
            .to_owned();
        let key = self
            .signer
            .key
            .as_ref()
            .map_err(|error| IamError::with_status("INTERNAL_ERROR", error.to_string(), 500))?;
        let mut payload = Map::new();
        payload.insert("sub_id".into(), subject);
        let mut events = Map::new();
        events.insert(event_type.to_owned(), claims);
        payload.insert("events".into(), Value::Object(events));
        // Every tenant's events share this issuer and key: receivers serving one organization check `tenant_id`.
        payload.insert(
            "tenant_id".into(),
            stream.get("tenantId").cloned().unwrap_or(Value::Null),
        );
        if let Some(txn) = txn.filter(|txn| !txn.is_empty()) {
            payload.insert("txn".into(), json!(txn));
        }
        payload.insert("iss".into(), json!(self.issuer));
        payload.insert(
            "aud".into(),
            stream.get("audience").cloned().unwrap_or(Value::Null),
        );
        payload.insert("iat".into(), json!((js::now_ms() / 1000.0).floor() as i64));
        payload.insert("jti".into(), json!(jti));
        let mut header = Map::new();
        header.insert("typ".into(), json!("secevent+jwt"));
        if let Some(kid) = self.signer.jwk.get("kid").filter(|kid| truthy(Some(kid))) {
            header.insert("kid".into(), kid.clone());
        }
        let set = jose::sign_jwt(key, &alg, header, &Value::Object(payload))
            .map_err(|error| IamError::with_status("INTERNAL_ERROR", error.to_string(), 500))?;
        Ok((jti, set))
    }

    async fn enqueue(
        &self,
        stream: &Record,
        event_type: &str,
        jti: &str,
        set: &str,
    ) -> IamResult<()> {
        let now = js::now_ms();
        let mut record = Map::new();
        record.insert("id".into(), json!(uuid::Uuid::new_v4().to_string()));
        record.insert(
            "tenantId".into(),
            stream.get("tenantId").cloned().unwrap_or(Value::Null),
        );
        record.insert(
            "streamId".into(),
            stream.get("id").cloned().unwrap_or(Value::Null),
        );
        record.insert("eventType".into(), json!(event_type));
        record.insert("jti".into(), json!(jti));
        record.insert("set".into(), json!(set));
        record.insert("status".into(), json!("pending"));
        record.insert("attempts".into(), json!(0));
        record.insert("createdAt".into(), number(now));
        record.insert("nextAttemptAt".into(), number(now));
        self.config
            .store
            .transaction(move |tx| async move {
                tx.insert("ssfDeliveries", &record).await?;
                Ok(())
            })
            .await
    }

    /// The subject of an event in the stream's format; email falls back to `iss_sub` when the address is gone.
    async fn subject_of(&self, stream: &Record, event: &Record) -> IamResult<Value> {
        if str_member(event, "action") == Some("tenant:revoke-sessions") {
            return Ok(json!({
                "format": "complex",
                "tenant": { "format": "opaque", "id": event.get("tenantId").cloned().unwrap_or(Value::Null) },
            }));
        }
        let resource_id = event.get("resourceId").cloned().unwrap_or(Value::Null);
        if str_member(stream, "subjectFormat") == Some("email") {
            let identity = match resource_id.as_str() {
                Some(id) => self.config.store.get("identities", id).await?,
                None => None,
            };
            // Only a verified address of the stream's own tenant names someone.
            if let Some(identity) = identity
                && truthy(identity.get("email"))
                && identity.get("emailVerified") == Some(&Value::Bool(true))
                && identity.get("tenantId") == stream.get("tenantId")
            {
                return Ok(json!({ "format": "email", "email": identity["email"].clone() }));
            }
        }
        Ok(json!({ "format": "iss_sub", "iss": self.issuer, "sub": resource_id }))
    }

    /// `publish(event)`: queues SETs for one audit event. Returns the number of streams addressed.
    pub async fn publish(&self, event: &Record) -> IamResult<usize> {
        let Some((event_type, extra)) = mapping(str_member(event, "action").unwrap_or_default())
        else {
            return Ok(0);
        };
        if str_member(event, "outcome") != Some("allow") {
            return Ok(0);
        }
        let streams: Vec<Record> = self
            .config
            .store
            .find(
                "ssfStreams",
                &Filter::new().eq(
                    "tenantId",
                    event.get("tenantId").cloned().unwrap_or(Value::Null),
                ),
                &FindOptions::default(),
            )
            .await?
            .into_iter()
            // Paused streams keep receiving events; their deliveries wait until the stream is enabled again.
            .filter(|stream| {
                stream
                    .get("events")
                    .and_then(Value::as_array)
                    .is_some_and(|events| {
                        events
                            .iter()
                            .any(|value| value.as_str() == Some(event_type.as_str()))
                    })
            })
            .collect();
        let event_timestamp = (num(event, "timestamp") / 1000.0).floor();
        for stream in &streams {
            let mut claims = Map::new();
            claims.insert("event_timestamp".into(), number(event_timestamp));
            claims.insert(
                "initiating_entity".into(),
                json!(if event.get("actorId") == event.get("resourceId") {
                    "user"
                } else {
                    "admin"
                }),
            );
            for (key, value) in &extra {
                claims.insert((*key).to_owned(), json!(value));
            }
            let subject = self.subject_of(stream, event).await?;
            let (jti, set) = self.security_event(
                stream,
                &event_type,
                subject,
                Value::Object(claims),
                str_member(event, "id"),
            )?;
            self.enqueue(stream, &event_type, &jti, &set).await?;
        }
        Ok(streams.len())
    }

    async fn send(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        match &self.config.fetch {
            Some(fetch) => fetch(request).await,
            None => self.guarded.fetch(request).await,
        }
    }

    async fn deliver(&self, record: &Record, stream: Option<&Record>) -> IamResult<bool> {
        let error: Option<String> = match stream {
            None => Some("The stream was deleted.".into()),
            Some(stream) if !truthy(stream.get("enabled")) => return Ok(false),
            Some(stream) => {
                if !tenant_tree_active(
                    self.config.store.as_ref(),
                    str_member(stream, "tenantId").unwrap_or_default(),
                )
                .await?
                {
                    Some("The tenant is unavailable.".into())
                } else {
                    let mut request = FetchRequest::new(
                        str_member(stream, "endpointUrl").unwrap_or_default(),
                        "POST",
                        Some(FetchBody::Text(
                            str_member(record, "set").unwrap_or_default().to_owned(),
                        )),
                    )
                    .redirect(RedirectMode::Error)
                    .header("content-type", "application/secevent+jwt")
                    .header("accept", "application/json");
                    if let Some(sealed) = str_member(stream, "sealedAuthorization")
                        .filter(|sealed| !sealed.is_empty())
                    {
                        request = request.header("authorization", self.crypt.open_text(sealed)?);
                    }
                    let timeout = std::time::Duration::from_millis(self.timeout_ms);
                    let outcome = tokio::time::timeout(timeout, async {
                        let mut response = self.send(request).await?;
                        if response.status != 202
                            && response.status != 200
                            && response.status != 204
                        {
                            let text: String = response
                                .body
                                .text()
                                .await
                                .unwrap_or_default()
                                .chars()
                                .take(300)
                                .collect();
                            let detail = match js::parse(&text) {
                                Ok(body) => {
                                    let part = |name: &str| match body.get(name) {
                                        None | Some(Value::Null) => String::new(),
                                        Some(Value::String(value)) => value.clone(),
                                        Some(other) => js::stringify(other),
                                    };
                                    format!(": {} {}", part("err"), part("description"))
                                        .trim_end()
                                        .to_owned()
                                }
                                Err(_) => String::new(),
                            };
                            Ok::<Option<String>, FetchError>(Some(format!(
                                "HTTP {}{detail}",
                                response.status
                            )))
                        } else {
                            response.body.cancel();
                            Ok(None)
                        }
                    })
                    .await;
                    match outcome {
                        Ok(Ok(result)) => result,
                        Ok(Err(_)) => Some("The receiver is unreachable.".into()),
                        Err(_) => Some("The receiver did not answer in time.".into()),
                    }
                }
            }
        };
        let now = js::now_ms();
        let attempts = num(record, "attempts") + 1.0;
        let mut updated = record.clone();
        let failed = error.is_some() && (attempts >= MAX_ATTEMPTS || stream.is_none());
        updated.insert("attempts".into(), number(attempts));
        updated.insert(
            "status".into(),
            json!(match (&error, failed) {
                (Some(_), true) => "failed",
                (Some(_), false) => "pending",
                (None, _) => "delivered",
            }),
        );
        if error.is_some() {
            updated.insert("nextAttemptAt".into(), number(now + backoff(attempts)));
        }
        match &error {
            Some(message) => {
                updated.insert("lastError".into(), json!(message));
            }
            None => {
                updated.insert("deliveredAt".into(), number(now));
            }
        }
        if failed {
            updated.insert("failedAt".into(), number(now));
        }
        let stream_id = stream
            .and_then(|stream| str_member(stream, "id"))
            .map(str::to_owned);
        let error_for_stream = error.clone();
        self.config
            .store
            .transaction(move |tx| async move {
                tx.put("ssfDeliveries", &updated).await?;
                if let Some(stream_id) = stream_id
                    && let Some(mut current) = tx.get("ssfStreams", &stream_id).await?
                {
                    match &error_for_stream {
                        Some(message) => {
                            current.insert("lastError".into(), json!(message));
                        }
                        None => {
                            current.insert("lastDeliveredAt".into(), number(now));
                            current.shift_remove("lastError");
                        }
                    }
                    tx.put("ssfStreams", &current).await?;
                }
                Ok(())
            })
            .await?;
        Ok(error.is_none())
    }

    /// `dispatch({ limit })`: sends every due delivery (at most `limit`, default 200) and prunes delivered records
    /// older than a week.
    pub async fn dispatch(&self, limit: Option<usize>) -> IamResult<Value> {
        let now = js::now_ms();
        let mut due: Vec<Record> = self
            .config
            .store
            .find(
                "ssfDeliveries",
                &Filter::new().eq("status", "pending"),
                &FindOptions::default(),
            )
            .await?
            .into_iter()
            .filter(|record| num(record, "nextAttemptAt") <= now)
            .collect();
        due.sort_by(|a, b| num(a, "createdAt").total_cmp(&num(b, "createdAt")));
        due.truncate(limit.unwrap_or(200));
        let mut streams: HashMap<String, Option<Record>> = HashMap::new();
        let mut delivered = 0;
        let mut failed = 0;
        for record in &due {
            let stream_id = str_member(record, "streamId")
                .unwrap_or_default()
                .to_owned();
            if !streams.contains_key(&stream_id) {
                let stream = self.config.store.get("ssfStreams", &stream_id).await?;
                streams.insert(stream_id.clone(), stream);
            }
            let stream = streams.get(&stream_id).cloned().flatten();
            if stream
                .as_ref()
                .is_some_and(|stream| !truthy(stream.get("enabled")))
            {
                continue;
            }
            if self.deliver(record, stream.as_ref()).await? {
                delivered += 1;
            } else {
                failed += 1;
            }
        }
        let week_ago = now - 7.0 * 86_400_000.0;
        self.config
            .store
            .transaction(move |tx| async move {
                for old in tx
                    .find(
                        "ssfDeliveries",
                        &Filter::new().eq("status", "delivered"),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    if num(&old, "deliveredAt") < week_ago {
                        tx.delete("ssfDeliveries", str_member(&old, "id").unwrap_or_default())
                            .await?;
                    }
                }
                Ok(())
            })
            .await?;
        Ok(json!({ "delivered": delivered, "failed": failed }))
    }

    /// SSF transmitter metadata.
    pub fn metadata(&self) -> Value {
        json!({
            "spec_version": "1_0",
            "issuer": self.issuer,
            "jwks_uri": self.jwks_uri,
            "delivery_methods_supported": [PUSH],
            "critical_subject_members": [],
            "default_subjects": "ALL",
        })
    }

    /// Serves the transmitter metadata at `/.well-known/ssf-configuration{issuer path}`; None otherwise.
    pub fn handler(&self, request: &HttpRequest) -> Option<HttpResponse> {
        let url = request_url_string(request, None);
        let path = url::Url::parse(&url)
            .map(|url| url.path().to_owned())
            .unwrap_or_default();
        if path != self.discovery_path {
            return None;
        }
        let method = request.method().as_str();
        if method != "GET" && method != "HEAD" {
            return Some(response(
                405,
                &[("allow", "GET, HEAD".to_owned())],
                Bytes::new(),
            ));
        }
        Some(response(
            200,
            &[
                ("content-type", "application/json".to_owned()),
                ("cache-control", "public, max-age=3600".to_owned()),
                ("access-control-allow-origin", "*".to_owned()),
            ],
            js::stringify(&self.metadata()),
        ))
    }

    /// `createStream(credential, input)` (`iam:ssf:streams:create`).
    pub async fn create_stream(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let id = format!("ssf-{}", hex(&rand::random::<[u8; 8]>()));
        let tenant_id = text_member(input, "tenantId");
        let actor = self
            .authorized(credential, "iam:ssf:streams:create", &tenant_id, &id)
            .await?;
        let stream_input = StreamInput::from_value(input);
        let values = self.settings(&stream_input, None)?;
        let sealed = match &stream_input.authorization {
            Some(Some(Value::String(value))) if !value.is_empty() => {
                Some(self.crypt.seal_text(value))
            }
            _ => None,
        };
        let store = self.config.store.clone();
        let record = store
            .transaction(move |tx| async move {
                if !tenant_tree_active(tx.as_ref(), &tenant_id).await? {
                    return Err(IamError::with_status(
                        "TENANT_INACTIVE",
                        "Tenant unavailable.",
                        403,
                    ));
                }
                let now = js::now_ms();
                let mut record = Map::new();
                record.insert("id".into(), json!(id));
                record.insert("tenantId".into(), json!(tenant_id));
                for (key, value) in values {
                    record.insert(key, value);
                }
                if let Some(sealed) = sealed {
                    record.insert("sealedAuthorization".into(), json!(sealed));
                }
                record.insert("createdAt".into(), number(now));
                record.insert("updatedAt".into(), number(now));
                tx.insert("ssfStreams", &record).await?;
                Self::audit(tx.as_ref(), &tenant_id, &actor, "iam:ssf:CreateStream", &id).await?;
                Ok(record)
            })
            .await?;
        self.summary(&record, self.config.store.as_ref()).await
    }

    /// `listStreams(credential, { tenantId })`.
    pub async fn list_streams(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Vec<Value>> {
        let tenant_id = text_member(input, "tenantId");
        self.authorized(credential, "iam:ssf:streams:read", &tenant_id, "*")
            .await?;
        let mut streams = self
            .config
            .store
            .find(
                "ssfStreams",
                &Filter::new().eq("tenantId", tenant_id),
                &FindOptions::default(),
            )
            .await?;
        streams.sort_by(|a, b| {
            num(a, "createdAt")
                .total_cmp(&num(b, "createdAt"))
                .then_with(|| {
                    js::cmp_utf16(
                        str_member(a, "id").unwrap_or_default(),
                        str_member(b, "id").unwrap_or_default(),
                    )
                })
        });
        let mut out = Vec::new();
        for stream in &streams {
            out.push(self.summary(stream, self.config.store.as_ref()).await?);
        }
        Ok(out)
    }

    /// `getStream(credential, { tenantId, streamId })`.
    pub async fn get_stream(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let tenant_id = text_member(input, "tenantId");
        let stream_id = text_member(input, "streamId");
        self.authorized(credential, "iam:ssf:streams:read", &tenant_id, &stream_id)
            .await?;
        let stream = Self::owned(self.config.store.as_ref(), &tenant_id, &stream_id).await?;
        self.summary(&stream, self.config.store.as_ref()).await
    }

    /// `updateStream(credential, input)`: `authorization: null` removes the header. Pausing holds deliveries.
    pub async fn update_stream(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let tenant_id = text_member(input, "tenantId");
        let stream_id = text_member(input, "streamId");
        let actor = self
            .authorized(credential, "iam:ssf:streams:update", &tenant_id, &stream_id)
            .await?;
        let stream_input = StreamInput::from_value(input);
        let store = self.config.store.clone();
        let this = self;
        let record = store
            .transaction(|tx| async move {
                let current = Self::owned(tx.as_ref(), &tenant_id, &stream_id).await?;
                let settings_input = StreamInput {
                    authorization: match &stream_input.authorization {
                        Some(Some(value)) => Some(Some(value.clone())),
                        _ => None,
                    },
                    ..stream_input.clone()
                };
                let values = this.settings(&settings_input, Some(&current))?;
                // The stored authorization is write-only: pointing the stream somewhere else must not send it along.
                if values.get("endpointUrl") != current.get("endpointUrl")
                    && truthy(current.get("sealedAuthorization"))
                    && stream_input.authorization.is_none()
                {
                    return Err(invalid_input(
                        "Changing the receiver endpoint needs the authorization header again (or null to remove it).",
                    ));
                }
                let mut record = current.clone();
                for (key, value) in values {
                    record.insert(key, value);
                }
                record.insert("updatedAt".into(), number(js::now_ms()));
                match &stream_input.authorization {
                    Some(None) => {
                        record.shift_remove("sealedAuthorization");
                    }
                    Some(Some(value)) => {
                        let text = match value {
                            Value::String(text) => text.clone(),
                            other => js::stringify(other),
                        };
                        record.insert("sealedAuthorization".into(), json!(this.crypt.seal_text(&text)));
                    }
                    None => {}
                }
                tx.put("ssfStreams", &record).await?;
                Self::audit(
                    tx.as_ref(),
                    &tenant_id,
                    &actor,
                    "iam:ssf:UpdateStream",
                    str_member(&current, "id").unwrap_or_default(),
                )
                .await?;
                this.summary(&record, tx.as_ref()).await
            })
            .await?;
        Ok(record)
    }

    /// `deleteStream(credential, { tenantId, streamId })`: removes a stream and its undelivered events.
    pub async fn delete_stream(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<()> {
        let tenant_id = text_member(input, "tenantId");
        let stream_id = text_member(input, "streamId");
        let actor = self
            .authorized(credential, "iam:ssf:streams:delete", &tenant_id, &stream_id)
            .await?;
        self.config
            .store
            .transaction(move |tx| async move {
                let current = Self::owned(tx.as_ref(), &tenant_id, &stream_id).await?;
                let id = str_member(&current, "id").unwrap_or_default().to_owned();
                for record in tx
                    .find(
                        "ssfDeliveries",
                        &Filter::new().eq("streamId", id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    tx.delete(
                        "ssfDeliveries",
                        str_member(&record, "id").unwrap_or_default(),
                    )
                    .await?;
                }
                tx.delete("ssfStreams", &id).await?;
                Self::audit(tx.as_ref(), &tenant_id, &actor, "iam:ssf:DeleteStream", &id).await
            })
            .await
    }

    /// `verifyStream(credential, { tenantId, streamId, state? })`: sends an SSF verification event straight away.
    pub async fn verify_stream(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let tenant_id = text_member(input, "tenantId");
        let stream_id = text_member(input, "streamId");
        self.authorized(credential, "iam:ssf:streams:update", &tenant_id, &stream_id)
            .await?;
        let stream = Self::owned(self.config.store.as_ref(), &tenant_id, &stream_id).await?;
        let state = match input.get("state") {
            Some(Value::Null) | None => jose::b64url(&rand::random::<[u8; 12]>()),
            Some(Value::String(state)) => state.clone(),
            Some(other) => js::stringify(other),
        };
        let event_type = format!("{SSF}/verification");
        let (jti, set) = self.security_event(
            &stream,
            &event_type,
            json!({ "format": "opaque", "id": stream.get("id").cloned().unwrap_or(Value::Null) }),
            json!({ "state": state }),
            None,
        )?;
        self.enqueue(&stream, &event_type, &jti, &set).await?;
        let record = self
            .config
            .store
            .find(
                "ssfDeliveries",
                &Filter::new().eq("jti", jti.clone()),
                &FindOptions::default(),
            )
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| IamError::with_status("INTERNAL_ERROR", "Delivery not found", 500))?;
        let delivered = self.deliver(&record, Some(&stream)).await?;
        let after = self
            .config
            .store
            .get(
                "ssfDeliveries",
                str_member(&record, "id").unwrap_or_default(),
            )
            .await?;
        let mut out = Map::new();
        out.insert("delivered".into(), json!(delivered));
        out.insert("jti".into(), json!(jti));
        if let Some(after) = after
            && truthy(after.get("lastError"))
            && !delivered
        {
            out.insert("error".into(), after["lastError"].clone());
        }
        Ok(Value::Object(out))
    }

    /// `listDeliveries(credential, { tenantId, streamId, status?, limit? })`: newest first.
    pub async fn list_deliveries(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Vec<Value>> {
        let tenant_id = text_member(input, "tenantId");
        let stream_id = text_member(input, "streamId");
        self.authorized(credential, "iam:ssf:streams:read", &tenant_id, &stream_id)
            .await?;
        Self::owned(self.config.store.as_ref(), &tenant_id, &stream_id).await?;
        let status = input
            .get("status")
            .filter(|value| truthy(Some(value)))
            .cloned();
        let limit = input
            .get("limit")
            .filter(|value| !value.is_null())
            .map(js::to_number)
            .unwrap_or(50.0)
            .min(500.0);
        let mut records: Vec<Record> = self
            .config
            .store
            .find(
                "ssfDeliveries",
                &Filter::new().eq("streamId", stream_id),
                &FindOptions::default(),
            )
            .await?
            .into_iter()
            .filter(|record| {
                status
                    .as_ref()
                    .is_none_or(|status| record.get("status") == Some(status))
            })
            .collect();
        records.sort_by(|a, b| num(b, "createdAt").total_cmp(&num(a, "createdAt")));
        // `slice(0, end)`: a negative end counts from the back, NaN is zero.
        let count = if limit.is_nan() {
            0
        } else if limit < 0.0 {
            records.len().saturating_sub((-limit).floor() as usize)
        } else {
            limit.floor() as usize
        };
        Ok(records
            .into_iter()
            .take(count)
            .map(|record| {
                let mut out = Map::new();
                for key in [
                    "id",
                    "streamId",
                    "eventType",
                    "jti",
                    "status",
                    "attempts",
                    "createdAt",
                ] {
                    out.insert(key.into(), record.get(key).cloned().unwrap_or(Value::Null));
                }
                if str_member(&record, "status") == Some("pending") {
                    out.insert(
                        "nextAttemptAt".into(),
                        record.get("nextAttemptAt").cloned().unwrap_or(Value::Null),
                    );
                }
                for key in ["deliveredAt", "failedAt", "lastError"] {
                    if truthy(record.get(key)) {
                        out.insert(key.into(), record[key].clone());
                    }
                }
                Value::Object(out)
            })
            .collect())
    }

    /// `subscribe(events, { onError })`: publishes matching IAM events as they are dispatched, then delivers them.
    /// `subscribe_fn` registers the handler with the event bus (`iam.events.subscribe(patterns, handler)`) and returns
    /// its subscription.
    pub fn subscribe<S>(
        self: &Arc<Self>,
        subscribe_fn: impl FnOnce(&[&str], EventHandler) -> IamResult<S>,
        on_error: Option<Arc<dyn Fn(IamError) + Send + Sync>>,
    ) -> IamResult<S> {
        let this = self.clone();
        let handler: EventHandler = Arc::new(move |event: Record| {
            let this = this.clone();
            let on_error = on_error.clone();
            Box::pin(async move {
                let result = async {
                    if this.publish(&event).await? > 0 {
                        this.dispatch(None).await?;
                    }
                    Ok::<(), IamError>(())
                }
                .await;
                if let Err(error) = result
                    && let Some(on_error) = &on_error
                {
                    on_error(error);
                }
                Ok(())
            })
        });
        let actions = mapped_actions();
        subscribe_fn(&actions, handler)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn text_member(input: &Value, key: &str) -> String {
    match input.get(key) {
        Some(Value::String(text)) => text.clone(),
        _ => String::new(),
    }
}
