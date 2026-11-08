//! Port of `packages/scim/src/outbound.ts`: outbound SCIM 2.0 provisioning: keeps downstream applications' user
//! directories in step with a tenant's members. Each target receives the active members in scope (all members, or
//! members of chosen groups) as SCIM users keyed by `externalId`; people who leave scope, are disabled, or are
//! deleted are deactivated (or deleted) downstream.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use better_iam_auth::safe_fetch::{
    FetchBody, FetchRequest, GuardedFetch, GuardedFetchOptions, RedirectMode,
    SafeFetchAddressOptions, check_fetch_url, create_guarded_fetch,
};
use better_iam_core::{
    CredentialInput, Filter, FindOptions, IamError, IamResult, IamStoreExt, Record, ResourceRef,
    append_audit_event, js as core_js, tenant_tree_active,
};
use futures::future::{BoxFuture, FutureExt, Shared};
use serde_json::{Map, Value, json};

use crate::js::{
    date_now, encode_uri_component, js_string, nullish, number, random_bytes, random_uuid, truthy,
    utf16_prefix,
};
use crate::provisioning::{find, put_member};
use crate::resources::{HttpResponse, http_response};
use crate::service::{HttpRequest, request_url};
use crate::types::{AuthenticateFn, AuthorizeFn, RecordAuditFn, Store};
use crate::validation::hash;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const ENTERPRISE_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LOOPBACK: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];
/// SCIM user attributes the provisioner can fill from declared identity attributes (`ProvisioningAttribute`).
const PROVISIONING_ATTRIBUTES: [&str; 4] = ["title", "department", "division", "employeeNumber"];

/// One downstream request (`fetch(url, init)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// A downstream answer: its status and its body text, or why the body could not be read in full (too large, cut
/// off, or past the deadline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportResponse {
    pub status: u16,
    pub body: Result<String, String>,
}

/// Why a downstream request did not produce a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The deadline passed (`AbortSignal.timeout`).
    Timeout,
    /// Anything else: refused by the address rules, a redirect, a network failure.
    Failed(String),
}

/// `ProvisioningConfig.fetch`: the transport for downstream calls. Redirects must fail; the request must give up at
/// `deadline`. A replacement must enforce its own address rules.
#[async_trait::async_trait]
pub trait ScimTransport: Send + Sync {
    async fn send(
        &self,
        request: TransportRequest,
        deadline: tokio::time::Instant,
    ) -> Result<TransportResponse, TransportError>;
}

/// The default transport: a guarded fetch that refuses private and reserved addresses at connect time (a hostname
/// cannot be re-pointed at the internal network after validation), never follows redirects, and bounds responses to
/// 1 MB.
pub struct GuardedTransport {
    fetch: GuardedFetch,
}

impl GuardedTransport {
    pub fn new(options: GuardedFetchOptions) -> Self {
        Self {
            fetch: create_guarded_fetch(options),
        }
    }
}

#[async_trait::async_trait]
impl ScimTransport for GuardedTransport {
    async fn send(
        &self,
        request: TransportRequest,
        deadline: tokio::time::Instant,
    ) -> Result<TransportResponse, TransportError> {
        let mut fetch = FetchRequest::new(
            request.url,
            request.method,
            request.body.map(FetchBody::Text),
        )
        .redirect(RedirectMode::Error);
        for (name, value) in request.headers {
            fetch = fetch.header(name, value);
        }
        let mut response = match tokio::time::timeout_at(deadline, self.fetch.fetch(fetch)).await {
            Err(_) => return Err(TransportError::Timeout),
            Ok(Err(error)) => return Err(TransportError::Failed(error.to_string())),
            Ok(Ok(response)) => response,
        };
        let body = match tokio::time::timeout_at(deadline, response.body.text()).await {
            Err(_) => Err("The body was cut off.".to_owned()),
            Ok(Err(error)) => Err(error.to_string()),
            Ok(Ok(text)) => Ok(text),
        };
        Ok(TransportResponse {
            status: response.status,
            body,
        })
    }
}

/// `ProvisioningConfig`.
#[derive(Clone)]
pub struct ProvisioningConfig {
    pub store: Store,
    /// `iam:scim:targets:*` on `scim/outbound/{targetId}`; `iam.protocolHost` supplies it.
    pub authorize: AuthorizeFn,
    pub authenticate: AuthenticateFn,
    /// Base64-encoded 32-byte key that encrypts downstream bearer tokens at rest.
    pub encryption_key: String,
    /// Keys being rotated out (base64, 32 bytes each): tokens sealed with them still open, and `rotate_keys()`
    /// re-seals them with `encryption_key`.
    pub previous_encryption_keys: Option<Vec<String>>,
    /// Allows `http://` targets on loopback addresses, for local development and tests only.
    pub allow_insecure_localhost: bool,
    /// Lets targets resolve to private and reserved addresses. Off by default: tenant administrators choose target
    /// URLs, so without this they could make the server call into its own network.
    pub allow_private_networks: bool,
    /// Per-request timeout for downstream calls (default 10 seconds).
    pub timeout_ms: Option<f64>,
    /// Replaces the default transport, which enforces the address rules above; a replacement must enforce its own.
    pub fetch: Option<Arc<dyn ScimTransport>>,
    /// Records an audit event and fans it out (webhooks, subscribers); `iam.protocolHost` supplies it.
    pub record_audit: Option<RecordAuditFn>,
    /// Where `handler` serves the JSON management API (`{basePath}/targets/{list,get,create,update,delete,sync,
    /// preview}`), default `/scim/provisioning`.
    pub base_path: Option<String>,
}

impl ProvisioningConfig {
    /// A configuration with the required members and every option at its default.
    pub fn new(
        store: Store,
        authorize: AuthorizeFn,
        authenticate: AuthenticateFn,
        encryption_key: impl Into<String>,
    ) -> Self {
        Self {
            store,
            authorize,
            authenticate,
            encryption_key: encryption_key.into(),
            previous_encryption_keys: None,
            allow_insecure_localhost: false,
            allow_private_networks: false,
            timeout_ms: None,
            fetch: None,
            record_audit: None,
            base_path: None,
        }
    }
}

/// An IAM event as `subscribe` hands it to the provisioner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisioningEvent {
    pub tenant_id: String,
    pub action: String,
}

/// A handler for IAM events.
pub type EventHandler = Arc<dyn Fn(ProvisioningEvent) + Send + Sync>;
/// The function that ends a subscription.
pub type Unsubscribe = Box<dyn FnOnce() + Send>;

/// What `subscribe` subscribes to (`iam.events`): handlers for audit events whose action matches any pattern.
pub trait EventSource {
    fn subscribe(&self, patterns: Vec<String>, handler: EventHandler) -> Unsubscribe;
}

/// The options of `subscribe`.
#[derive(Clone, Default)]
pub struct SubscribeOptions {
    /// Default 2 seconds.
    pub debounce_ms: Option<u64>,
    pub on_error: Option<Arc<dyn Fn(IamError) + Send + Sync>>,
}

/// A failure of one downstream step: a downstream refusal (`DownstreamError`) or anything else.
#[derive(Debug, Clone)]
enum SyncError {
    Downstream {
        message: String,
        status: Option<u16>,
    },
    /// Not a downstream refusal (a storage failure, an unexpected exception): reported without its details.
    Other,
}

impl From<IamError> for SyncError {
    fn from(_: IamError) -> Self {
        SyncError::Other
    }
}

fn downstream(message: impl Into<String>) -> SyncError {
    SyncError::Downstream {
        message: message.into(),
        status: None,
    }
}

struct CallResult {
    status: u16,
    json: Option<Value>,
}

impl CallResult {
    fn member(&self, key: &str) -> Option<&Value> {
        self.json
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|map| map.get(key))
    }
}

/// `ProvisioningRun`.
#[derive(Debug, Clone, Default)]
struct Run {
    started_at: f64,
    finished_at: f64,
    created: u64,
    updated: u64,
    deactivated: u64,
    deleted: u64,
    unchanged: u64,
    failed: u64,
    groups_created: u64,
    groups_updated: u64,
    groups_deleted: u64,
    groups_unchanged: u64,
    errors: Vec<Value>,
}

impl Run {
    fn to_json(&self) -> Value {
        json!({
            "startedAt": number(self.started_at),
            "finishedAt": number(self.finished_at),
            "created": self.created,
            "updated": self.updated,
            "deactivated": self.deactivated,
            "deleted": self.deleted,
            "unchanged": self.unchanged,
            "failed": self.failed,
            "groups": {
                "created": self.groups_created,
                "updated": self.groups_updated,
                "deleted": self.groups_deleted,
                "unchanged": self.groups_unchanged,
            },
            "errors": self.errors,
        })
    }

    fn fail(&mut self, id: &str, error: &SyncError, subject: &str) {
        self.failed += 1;
        if self.errors.len() < 20 {
            let mut entry = Map::new();
            entry.insert(subject.to_owned(), json!(id));
            if let SyncError::Downstream {
                status: Some(status),
                ..
            } = error
                && *status != 0
            {
                entry.insert("status".into(), json!(status));
            }
            entry.insert(
                "message".into(),
                json!(match error {
                    SyncError::Downstream { message, .. } => message.clone(),
                    SyncError::Other => "Provisioning failed unexpectedly.".to_owned(),
                }),
            );
            self.errors.push(Value::Object(entry));
        }
    }
}

/// Temporary and access-package memberships stop counting at `expiresAt`, before the purge worker removes them.
fn live_membership(membership: &Record) -> bool {
    match membership.get("expiresAt") {
        Some(Value::Number(value)) => core_js::number_value(value) > date_now(),
        _ => true,
    }
}

/// A filter value (RFC 7644 compValue, a JSON string): escaped, never stripped, so it matches only itself.
fn quoted(value: &str) -> String {
    core_js::quote(value)
}

/// Node's lenient base64 decoding (`Buffer.from(value, 'base64')`): both alphabets, whitespace and other characters
/// skipped, decoding stops at the first `=`.
fn decode_base64(value: &str) -> Vec<u8> {
    let mut sextets = Vec::with_capacity(value.len());
    for c in value.chars() {
        let sextet = match c {
            'A'..='Z' => c as u8 - b'A',
            'a'..='z' => c as u8 - b'a' + 26,
            '0'..='9' => c as u8 - b'0' + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            '=' => break,
            _ => continue,
        };
        sextets.push(sextet);
    }
    let mut out = Vec::with_capacity(sextets.len() * 3 / 4);
    for chunk in sextets.chunks(4) {
        let mut buffer = 0u32;
        for (index, sextet) in chunk.iter().enumerate() {
            buffer |= u32::from(*sextet) << (18 - 6 * index);
        }
        let bytes = buffer.to_be_bytes();
        match chunk.len() {
            4 => out.extend_from_slice(&bytes[1..4]),
            3 => out.extend_from_slice(&bytes[1..3]),
            2 => out.push(bytes[1]),
            _ => {}
        }
    }
    out
}

fn base64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/`.
fn attribute_source(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && value.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `value.length` truthiness (`!value.length` is false): a nonempty array or string.
fn has_length(value: &Value) -> bool {
    match value {
        Value::Array(items) => !items.is_empty(),
        Value::String(text) => !text.is_empty(),
        _ => false,
    }
}

/// A string member, or "" for anything else (resource references of authorization calls).
fn string_member(input: &Value, key: &str) -> String {
    input
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// The validated settings of a target (`settings(input, current)`).
struct Settings {
    name: String,
    base_url: String,
    group_ids: Vec<Value>,
    deprovision: String,
    attribute_mapping: Map<String, Value>,
    push_groups: bool,
    enabled: bool,
}

impl Settings {
    fn write(&self, record: &mut Record) {
        record.insert("name".into(), json!(self.name));
        record.insert("baseUrl".into(), json!(self.base_url));
        record.insert("groupIds".into(), Value::Array(self.group_ids.clone()));
        record.insert("deprovision".into(), json!(self.deprovision));
        record.insert(
            "attributeMapping".into(),
            Value::Object(self.attribute_mapping.clone()),
        );
        record.insert("pushGroups".into(), json!(self.push_groups));
        record.insert("enabled".into(), json!(self.enabled));
    }
}

type RunFuture = Shared<BoxFuture<'static, IamResult<Value>>>;

struct Inner {
    config: ProvisioningConfig,
    key: [u8; 32],
    previous_keys: Vec<[u8; 32]>,
    address_rules: SafeFetchAddressOptions,
    request: Arc<dyn ScimTransport>,
    timeout_ms: f64,
    running: Mutex<HashMap<String, RunFuture>>,
    base_path: String,
}

/// Outbound SCIM provisioning (`createScimProvisioner(config)`). Cheap to clone.
#[derive(Clone)]
pub struct ScimProvisioner {
    inner: Arc<Inner>,
}

/// `createScimProvisioner(config)`.
pub fn create_scim_provisioner(config: ProvisioningConfig) -> IamResult<ScimProvisioner> {
    ScimProvisioner::new(config)
}

fn key_of(value: &str) -> Option<[u8; 32]> {
    decode_base64(value).try_into().ok()
}

impl Inner {
    fn seal(&self, value: &str) -> String {
        let iv = random_bytes(12);
        let cipher = Aes256Gcm::new((&self.key).into());
        let sealed = cipher
            .encrypt(Nonce::from_slice(&iv), value.as_bytes())
            .expect("AES-GCM encryption does not fail");
        let mut out = iv;
        out.extend_from_slice(&sealed);
        base64_encode(&out)
    }

    /// Opens a sealed token with the current key or a previous one; `index` 0 is the current key.
    fn open_with(&self, value: &str) -> Option<(String, usize)> {
        let buffer = decode_base64(value);
        if buffer.len() < 28 {
            return None;
        }
        let iv = &buffer[..12];
        let payload = &buffer[12..];
        for (index, candidate) in std::iter::once(&self.key)
            .chain(self.previous_keys.iter())
            .enumerate()
        {
            let cipher = Aes256Gcm::new(candidate.into());
            if let Ok(plain) = cipher.decrypt(Nonce::from_slice(iv), payload) {
                return Some((String::from_utf8_lossy(&plain).into_owned(), index));
            }
        }
        None
    }

    fn open(&self, value: Option<&Value>) -> IamResult<String> {
        value
            .and_then(Value::as_str)
            .and_then(|value| self.open_with(value))
            .map(|(value, _)| value)
            .ok_or_else(|| {
                IamError::new(
                    "INVALID_SEALED_VALUE",
                    "The stored downstream token cannot be opened.",
                )
            })
    }

    fn base_url(&self, value: Option<&Value>) -> IamResult<String> {
        let invalid = || {
            IamError::new(
                "INVALID_INPUT",
                "The SCIM base URL must be an absolute HTTPS URL.",
            )
        };
        let mut parsed = url::Url::parse(&js_string(value)).map_err(|_| invalid())?;
        let hostname = match parsed.host() {
            Some(url::Host::Ipv6(address)) => format!("[{address}]"),
            Some(host) => host.to_string(),
            None => String::new(),
        };
        let local = self.config.allow_insecure_localhost
            && parsed.scheme() == "http"
            && LOOPBACK.contains(&hostname.as_str());
        if (parsed.scheme() != "https" && !local)
            || !parsed.username().is_empty()
            || parsed
                .password()
                .is_some_and(|password| !password.is_empty())
            || parsed
                .fragment()
                .is_some_and(|fragment| !fragment.is_empty())
            || parsed.query().is_some_and(|query| !query.is_empty())
        {
            return Err(invalid());
        }
        // IP literals are judged now; hostnames are judged by the transport each time it connects.
        parsed.set_fragment(None);
        if check_fetch_url(parsed.as_str(), &self.address_rules).is_err() {
            return Err(IamError::new(
                "INVALID_INPUT",
                "The SCIM base URL must point at a public address (see allowPrivateNetworks).",
            ));
        }
        let path = parsed.path();
        let path = path.strip_suffix('/').unwrap_or(path);
        Ok(format!("{}{path}", parsed.origin().ascii_serialization()))
    }

    fn settings(&self, input: &Value, current: Option<&Record>) -> IamResult<Settings> {
        let from = |key: &str| -> Option<Value> {
            nullish(input.get(key))
                .cloned()
                .or_else(|| current.and_then(|current| current.get(key).cloned()))
        };
        let defaulted = |key: &str| -> Option<Value> {
            nullish(input.get(key))
                .cloned()
                .or_else(|| current.and_then(|current| nullish(current.get(key)).cloned()))
        };
        let name = from("name");
        let group_ids = defaulted("groupIds").unwrap_or_else(|| json!([]));
        let deprovision = defaulted("deprovision").unwrap_or_else(|| json!("deactivate"));
        let mapping = defaulted("attributeMapping").unwrap_or_else(|| json!({}));
        let enabled = defaulted("enabled").unwrap_or(json!(true));
        let push_groups = defaulted("pushGroups").unwrap_or(json!(false));
        let invalid = |message: &str| IamError::new("INVALID_INPUT", message);
        let push = match push_groups {
            Value::Bool(flag) if !(flag && !has_length(&group_ids)) => flag,
            _ => return Err(invalid("pushGroups needs the groups to push in groupIds.")),
        };
        let name = match &name {
            Some(Value::String(text))
                if !core_js::trim(text).is_empty() && core_js::utf16_len(text) <= 200 =>
            {
                core_js::trim(text).to_owned()
            }
            _ => {
                return Err(invalid(
                    "A target name of at most 200 characters is required.",
                ));
            }
        };
        let group_ids = match &group_ids {
            Value::Array(items)
                if items.len() <= 50
                    && items
                        .iter()
                        .all(|item| matches!(item, Value::String(text) if !text.is_empty())) =>
            {
                let mut unique: Vec<Value> = Vec::new();
                for item in items {
                    if !unique.contains(item) {
                        unique.push(item.clone());
                    }
                }
                unique
            }
            _ => return Err(invalid("groupIds must list at most 50 group IDs.")),
        };
        let deprovision = match &deprovision {
            Value::String(text) if text == "deactivate" || text == "delete" => text.clone(),
            _ => return Err(invalid("deprovision must be deactivate or delete.")),
        };
        let mapping_error = || {
            invalid(
                "attributeMapping maps title, department, division, or employeeNumber to identity attributes.",
            )
        };
        let attribute_mapping = match &mapping {
            Value::Object(map) => {
                if map.iter().any(|(attribute, source)| {
                    !PROVISIONING_ATTRIBUTES.contains(&attribute.as_str())
                        || !matches!(source, Value::String(text) if attribute_source(text))
                }) {
                    return Err(mapping_error());
                }
                map.clone()
            }
            // `Object.entries([])` is empty; any element is an index key, which no attribute is.
            Value::Array(items) if items.is_empty() => Map::new(),
            _ => return Err(mapping_error()),
        };
        let enabled = match enabled {
            Value::Bool(flag) => flag,
            _ => return Err(invalid("enabled must be a boolean.")),
        };
        let base_url = self.base_url(
            nullish(input.get("baseUrl"))
                .or_else(|| current.and_then(|current| current.get("baseUrl"))),
        )?;
        Ok(Settings {
            name,
            base_url,
            group_ids,
            deprovision,
            attribute_mapping,
            push_groups: push,
            enabled,
        })
    }

    fn token(value: Option<&Value>) -> IamResult<String> {
        match value {
            Some(Value::String(text))
                if (8..=4096).contains(&core_js::utf16_len(text))
                    && !core_js::has_js_whitespace(text) =>
            {
                Ok(text.clone())
            }
            _ => Err(IamError::new(
                "INVALID_INPUT",
                "A downstream bearer token is required.",
            )),
        }
    }

    async fn summary(&self, target: &Record, store: &Store) -> IamResult<Value> {
        let links = find(
            store.as_ref(),
            "provisioningLinks",
            Filter::new().eq("targetId", target.get("id").cloned().unwrap_or(Value::Null)),
        )
        .await?;
        let mut map = Map::new();
        put_member(&mut map, "id", target.get("id"));
        put_member(&mut map, "tenantId", target.get("tenantId"));
        put_member(&mut map, "name", target.get("name"));
        put_member(&mut map, "baseUrl", target.get("baseUrl"));
        put_member(&mut map, "groupIds", target.get("groupIds"));
        put_member(&mut map, "deprovision", target.get("deprovision"));
        put_member(&mut map, "attributeMapping", target.get("attributeMapping"));
        map.insert(
            "pushGroups".into(),
            json!(target.get("pushGroups") == Some(&Value::Bool(true))),
        );
        put_member(&mut map, "enabled", target.get("enabled"));
        put_member(&mut map, "createdAt", target.get("createdAt"));
        put_member(&mut map, "updatedAt", target.get("updatedAt"));
        put_member(&mut map, "tokenUpdatedAt", target.get("tokenUpdatedAt"));
        map.insert(
            "provisioned".into(),
            json!(
                links
                    .iter()
                    .filter(|link| truthy(link.get("active")))
                    .count()
            ),
        );
        if let Some(last_run) = target.get("lastRun").filter(|value| truthy(Some(value))) {
            map.insert("lastRun".into(), last_run.clone());
        }
        Ok(Value::Object(map))
    }

    async fn authorize(
        &self,
        credential: &CredentialInput,
        action: &str,
        tenant_id: &str,
        kind: &str,
        id: &str,
    ) -> IamResult<()> {
        (self.config.authorize)(
            credential.clone(),
            action.to_owned(),
            ResourceRef {
                tenant_id: tenant_id.to_owned(),
                kind: kind.to_owned(),
                id: id.to_owned(),
            },
        )
        .await
    }

    async fn authorized(
        &self,
        credential: &CredentialInput,
        action: &str,
        tenant_id: &str,
        target_id: &str,
    ) -> IamResult<String> {
        self.authorize(
            credential,
            action,
            tenant_id,
            "scim",
            &format!("outbound/{target_id}"),
        )
        .await?;
        // Configuring, syncing and previewing a target send (or show) every member in scope: name, email, mapped
        // attributes and groups. That is reading the directory, so it needs that permission too, not only the
        // target's.
        if action != "iam:scim:targets:read" && action != "iam:scim:targets:delete" {
            self.authorize(
                credential,
                "iam:identities:read",
                tenant_id,
                "iam",
                tenant_id,
            )
            .await?;
        }
        (self.config.authenticate)(credential.clone()).await
    }

    async fn owned(&self, store: &Store, input: &Value) -> IamResult<Record> {
        let target = match input.get("targetId") {
            Some(Value::String(id)) if !id.is_empty() => {
                store.get("provisioningTargets", id).await?
            }
            _ => None,
        };
        match target {
            Some(target) if target.get("tenantId") == input.get("tenantId") => Ok(target),
            _ => Err(IamError::with_status(
                "NOT_FOUND",
                "Provisioning target not found.",
                404,
            )),
        }
    }

    async fn audit(
        &self,
        tx: &Store,
        tenant_id: Option<&Value>,
        actor_id: &str,
        action: &str,
        resource_id: &str,
    ) -> IamResult<()> {
        let mut event = Map::new();
        event.insert("id".into(), json!(random_uuid()));
        put_member(&mut event, "tenantId", tenant_id);
        event.insert("actorId".into(), json!(actor_id));
        event.insert("action".into(), json!(action));
        event.insert("resourceId".into(), json!(resource_id));
        event.insert("timestamp".into(), number(date_now()));
        event.insert("outcome".into(), json!("allow"));
        // Through the host when it fans events out to webhooks and subscribers; `subscribe` ignores these itself.
        match &self.config.record_audit {
            Some(record_audit) => record_audit(tx.clone(), event).await,
            None => append_audit_event(tx.as_ref(), &event).await.map(|_| ()),
        }
    }

    /// One downstream SCIM call with the target's bearer token.
    async fn call(
        &self,
        target: &Record,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<CallResult, SyncError> {
        let unreachable = || downstream("The SCIM service is unreachable.");
        let token = self
            .open(target.get("sealedToken"))
            .map_err(|_| unreachable())?;
        let mut headers = vec![
            ("authorization".to_owned(), format!("Bearer {token}")),
            ("accept".to_owned(), "application/scim+json".to_owned()),
        ];
        if body.is_some() {
            headers.push((
                "content-type".to_owned(),
                "application/scim+json".to_owned(),
            ));
        }
        let request = TransportRequest {
            url: format!("{}{path}", js_string(target.get("baseUrl"))),
            method: method.to_owned(),
            headers,
            body: body.map(core_js::stringify),
        };
        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_millis(self.timeout_ms.max(0.0) as u64);
        let response =
            match tokio::time::timeout_at(deadline, self.request.send(request, deadline)).await {
                Err(_) | Ok(Err(TransportError::Timeout)) => {
                    return Err(downstream("The SCIM service did not answer in time."));
                }
                Ok(Err(TransportError::Failed(_))) => return Err(unreachable()),
                Ok(Ok(response)) => response,
            };
        let text = response
            .body
            .map_err(|_| downstream("The SCIM response is too large or was cut off."))?;
        if core_js::utf16_len(&text) > 1_000_000 {
            return Err(downstream("The SCIM response is too large."));
        }
        let json = if text.is_empty() {
            None
        } else {
            core_js::parse(&text).ok()
        };
        Ok(CallResult {
            status: response.status,
            json,
        })
    }

    fn failure(result: &CallResult, what: &str) -> SyncError {
        let detail = match result.member("detail") {
            Some(Value::String(detail)) => format!(": {}", utf16_prefix(detail, 200)),
            _ => String::new(),
        };
        SyncError::Downstream {
            message: format!("{what} failed with HTTP {}{detail}", result.status),
            status: Some(result.status),
        }
    }

    /// The SCIM representation of an in-scope member.
    fn user(target: &Record, identity: &Record) -> Value {
        let mut enterprise = Map::new();
        let mut title: Option<String> = None;
        if let Some(Value::Object(mapping)) = target.get("attributeMapping") {
            for (attribute, source) in core_js::entries(mapping) {
                let value = identity
                    .get("attributes")
                    .and_then(Value::as_object)
                    .and_then(|attributes| attributes.get(&js_string(Some(source))));
                let Some(value) = value.filter(|value| !value.is_null()) else {
                    continue;
                };
                if attribute == "title" {
                    title = Some(js_string(Some(value)));
                } else {
                    enterprise.insert(attribute.clone(), json!(js_string(Some(value))));
                }
            }
        }
        let mut map = Map::new();
        map.insert(
            "schemas".into(),
            if enterprise.is_empty() {
                json!([USER_SCHEMA])
            } else {
                json!([USER_SCHEMA, ENTERPRISE_SCHEMA])
            },
        );
        put_member(&mut map, "externalId", identity.get("id"));
        put_member(&mut map, "userName", identity.get("email"));
        put_member(&mut map, "displayName", identity.get("name"));
        let mut name = Map::new();
        put_member(&mut name, "formatted", identity.get("name"));
        map.insert("name".into(), Value::Object(name));
        let mut email = Map::new();
        put_member(&mut email, "value", identity.get("email"));
        email.insert("type".into(), json!("work"));
        email.insert("primary".into(), json!(true));
        map.insert("emails".into(), json!([Value::Object(email)]));
        if let Some(title) = title {
            map.insert("title".into(), json!(title));
        }
        map.insert("active".into(), json!(true));
        if !enterprise.is_empty() {
            map.insert(ENTERPRISE_SCHEMA.into(), Value::Object(enterprise));
        }
        Value::Object(map)
    }

    /// The single downstream resource matching one of the filters, if any.
    async fn lookup(
        &self,
        target: &Record,
        resource: &str,
        filters: &[String],
    ) -> Result<Option<String>, SyncError> {
        let lower = resource.to_lowercase();
        for filter in filters {
            let query = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("filter", filter)
                .append_pair("count", "2")
                .finish();
            let found = self
                .call(target, "GET", &format!("/{resource}?{query}"), None)
                .await?;
            if found.status != 200 {
                return Err(Self::failure(&found, &format!("Looking up {lower}")));
            }
            let resources = match found.member("Resources") {
                Some(Value::Array(items)) => items.clone(),
                _ => Vec::new(),
            };
            if resources.len() > 1 {
                return Err(downstream(format!("Several downstream {lower} match.")));
            }
            if let Some(first) = resources.first() {
                if first.is_null() {
                    // `resources[0].id` of null is a TypeError.
                    return Err(SyncError::Other);
                }
                if let Some(Value::String(id)) = first.get("id") {
                    return Ok(Some(id.clone()));
                }
            }
        }
        Ok(None)
    }

    /// An existing downstream user for the same person, so a first sync adopts instead of duplicating: the one this
    /// target created for them (`externalId`), or, only when their address is verified, the account whose `userName`
    /// is that address. Someone who merely typed another person's address never takes over their downstream account,
    /// and an account another person's link already holds is never adopted twice.
    async fn adopt(&self, target: &Record, identity: &Record) -> Result<Option<String>, SyncError> {
        let mut filters = vec![format!(
            "externalId eq {}",
            quoted(&js_string(identity.get("id")))
        )];
        if identity.get("emailVerified") == Some(&Value::Bool(true))
            && truthy(identity.get("email"))
        {
            filters.push(format!(
                "userName eq {}",
                quoted(&js_string(identity.get("email")))
            ));
        }
        let Some(remote_id) = self.lookup(target, "Users", &filters).await? else {
            return Ok(None);
        };
        let holders = find(
            self.config.store.as_ref(),
            "provisioningLinks",
            Filter::new()
                .eq("targetId", target.get("id").cloned().unwrap_or(Value::Null))
                .eq("remoteId", remote_id.clone()),
        )
        .await?;
        if holders
            .iter()
            .any(|link| link.get("identityId") != identity.get("id"))
        {
            return Err(downstream(
                "The matching downstream account is linked to someone else.",
            ));
        }
        Ok(Some(remote_id))
    }

    async fn upsert(&self, collection: &'static str, record: Record) -> IamResult<()> {
        self.config
            .store
            .transaction(move |tx| async move {
                let id = js_string(record.get("id"));
                if tx.get(collection, &id).await?.is_some() {
                    tx.put(collection, &record).await?;
                } else {
                    tx.insert(collection, &record).await?;
                }
                Ok(())
            })
            .await
    }

    async fn remove(&self, collection: &'static str, id: String) -> IamResult<()> {
        self.config
            .store
            .transaction(move |tx| async move { tx.delete(collection, &id).await })
            .await
    }

    /// With `pushGroups`, each scoped group exists downstream (adopted by `externalId` or `displayName`) with the
    /// provisioned users as members; groups that leave scope or disappear are deleted downstream.
    async fn push_groups(&self, target: &Record, live: bool, run: &mut Run) -> IamResult<()> {
        let store = &self.config.store;
        let target_id = target.get("id").cloned().unwrap_or(Value::Null);
        let tenant_id = target.get("tenantId").cloned().unwrap_or(Value::Null);
        let mut links: Vec<(String, Record)> = Vec::new();
        for link in find(
            store.as_ref(),
            "provisioningGroupLinks",
            Filter::new().eq("targetId", target_id.clone()),
        )
        .await?
        {
            let group_id = js_string(link.get("groupId"));
            match links.iter_mut().find(|(id, _)| *id == group_id) {
                Some(entry) => entry.1 = link,
                None => links.push((group_id, link)),
            }
        }
        if !truthy(target.get("pushGroups")) && links.is_empty() {
            return Ok(());
        }
        let mut remote_users: HashMap<String, Value> = HashMap::new();
        for link in find(
            store.as_ref(),
            "provisioningLinks",
            Filter::new().eq("targetId", target_id.clone()),
        )
        .await?
        {
            if truthy(link.get("active")) {
                remote_users.insert(
                    js_string(link.get("identityId")),
                    link.get("remoteId").cloned().unwrap_or(Value::Null),
                );
            }
        }
        let mut wanted: HashSet<String> = HashSet::new();
        let group_ids: Vec<Value> = if live && truthy(target.get("pushGroups")) {
            target
                .get("groupIds")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        for group_id_value in group_ids {
            let group_id = js_string(Some(&group_id_value));
            let group = store.get("groups", &group_id).await?;
            let Some(group) = group else {
                continue;
            };
            let Some(Value::String(group_name)) = group.get("name").cloned() else {
                continue;
            };
            if group.get("tenantId") != Some(&tenant_id) {
                continue;
            }
            wanted.insert(group_id.clone());
            let mut remote_ids: Vec<String> = Vec::new();
            for membership in find(
                store.as_ref(),
                "groupMembers",
                Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("groupId", group_id_value.clone()),
            )
            .await?
            {
                if !live_membership(&membership) {
                    continue;
                }
                if let Some(remote) = remote_users.get(&js_string(membership.get("identityId")))
                    && truthy(Some(remote))
                {
                    remote_ids.push(js_string(Some(remote)));
                }
            }
            remote_ids.sort_by(|a, b| core_js::cmp_utf16(a, b));
            let members: Vec<Value> = remote_ids
                .iter()
                .map(|value| json!({ "value": value }))
                .collect();
            let payload = json!({
                "schemas": [GROUP_SCHEMA],
                "externalId": group_id_value,
                "displayName": group_name,
                "members": members,
            });
            let fingerprint = hash(&core_js::stringify(&payload));
            let link = links
                .iter()
                .find(|(id, _)| *id == group_id)
                .map(|(_, link)| link.clone());
            let result: Result<(), SyncError> = async {
                if link.as_ref().and_then(|link| link.get("fingerprint"))
                    == Some(&json!(fingerprint))
                {
                    run.groups_unchanged += 1;
                    return Ok(());
                }
                let mut remote_id =
                    match link.as_ref().and_then(|link| nullish(link.get("remoteId"))) {
                        Some(remote) => Some(js_string(Some(remote))),
                        None => {
                            self.lookup(
                                target,
                                "Groups",
                                &[
                                    format!("externalId eq {}", quoted(&group_id)),
                                    format!("displayName eq {}", quoted(&group_name)),
                                ],
                            )
                            .await?
                        }
                    };
                let mut created = false;
                if let Some(remote) = remote_id.clone().filter(|remote| !remote.is_empty()) {
                    let mut body = payload.clone();
                    body.as_object_mut()
                        .expect("the payload is an object")
                        .insert("id".into(), json!(remote));
                    let replaced = self
                        .call(
                            target,
                            "PUT",
                            &format!("/Groups/{}", encode_uri_component(&remote)),
                            Some(&body),
                        )
                        .await?;
                    if replaced.status == 404 {
                        remote_id = None;
                    } else if !(200..300).contains(&replaced.status) {
                        return Err(Self::failure(&replaced, "Updating the group"));
                    }
                }
                let remote_id = match remote_id.filter(|remote| !remote.is_empty()) {
                    Some(remote) => remote,
                    None => {
                        let posted = self.call(target, "POST", "/Groups", Some(&payload)).await?;
                        if posted.status != 201 && posted.status != 200 {
                            return Err(Self::failure(&posted, "Creating the group"));
                        }
                        let Some(Value::String(id)) = posted.member("id") else {
                            return Err(downstream("The SCIM service returned no group ID."));
                        };
                        created = true;
                        id.clone()
                    }
                };
                let mut record = Map::new();
                record.insert(
                    "id".into(),
                    json!(hash(&format!(
                        "{}:group:{group_id}",
                        js_string(Some(&target_id))
                    ))),
                );
                record.insert("tenantId".into(), tenant_id.clone());
                record.insert("targetId".into(), target_id.clone());
                record.insert("groupId".into(), json!(group_id));
                record.insert("remoteId".into(), json!(remote_id));
                record.insert("fingerprint".into(), json!(fingerprint));
                record.insert("syncedAt".into(), number(date_now()));
                self.upsert("provisioningGroupLinks", record).await?;
                if created {
                    run.groups_created += 1;
                } else {
                    run.groups_updated += 1;
                }
                Ok(())
            }
            .await;
            if let Err(error) = result {
                run.fail(&group_id, &error, "groupId");
            }
        }
        for (group_id, link) in links {
            if wanted.contains(&group_id) {
                continue;
            }
            let result: Result<(), SyncError> = async {
                let removed = self
                    .call(
                        target,
                        "DELETE",
                        &format!(
                            "/Groups/{}",
                            encode_uri_component(&js_string(link.get("remoteId")))
                        ),
                        None,
                    )
                    .await?;
                if ![204, 200, 404].contains(&removed.status) {
                    return Err(Self::failure(&removed, "Deleting the group"));
                }
                self.remove("provisioningGroupLinks", js_string(link.get("id")))
                    .await?;
                run.groups_deleted += 1;
                Ok(())
            }
            .await;
            if let Err(error) = result {
                run.fail(&group_id, &error, "groupId");
            }
        }
        Ok(())
    }

    /// Who should exist downstream now, and what the target has provisioned so far.
    async fn scope_of(
        &self,
        target: &Record,
    ) -> IamResult<(bool, Vec<(String, Record)>, Vec<(String, Record)>)> {
        let store = &self.config.store;
        let tenant_id = target.get("tenantId").cloned().unwrap_or(Value::Null);
        let active = tenant_tree_active(store.as_ref(), &js_string(Some(&tenant_id))).await?;
        let group_ids: Vec<Value> = target
            .get("groupIds")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut members: HashSet<String> = HashSet::new();
        for group_id in &group_ids {
            for membership in find(
                store.as_ref(),
                "groupMembers",
                Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("groupId", group_id.clone()),
            )
            .await?
            {
                if live_membership(&membership) {
                    members.insert(js_string(membership.get("identityId")));
                }
            }
        }
        let mut in_scope: Vec<(String, Record)> = Vec::new();
        if active && truthy(target.get("enabled")) {
            for identity in find(
                store.as_ref(),
                "identities",
                Filter::new().eq("tenantId", tenant_id.clone()),
            )
            .await?
            {
                let unexpired = match identity.get("expiresAt") {
                    Some(Value::Number(value)) => core_js::number_value(value) > date_now(),
                    _ => true,
                };
                let id = js_string(identity.get("id"));
                if identity.get("kind").and_then(Value::as_str) == Some("user")
                    && identity.get("status").and_then(Value::as_str) == Some("active")
                    && truthy(identity.get("email"))
                    && unexpired
                    && (group_ids.is_empty() || members.contains(&id))
                {
                    match in_scope.iter_mut().find(|(key, _)| *key == id) {
                        Some(entry) => entry.1 = identity,
                        None => in_scope.push((id, identity)),
                    }
                }
            }
        }
        let mut links: Vec<(String, Record)> = Vec::new();
        for link in find(
            store.as_ref(),
            "provisioningLinks",
            Filter::new().eq("targetId", target.get("id").cloned().unwrap_or(Value::Null)),
        )
        .await?
        {
            let identity_id = js_string(link.get("identityId"));
            match links.iter_mut().find(|(key, _)| *key == identity_id) {
                Some(entry) => entry.1 = link,
                None => links.push((identity_id, link)),
            }
        }
        Ok((active, in_scope, links))
    }

    /// The plan of the next sync: never writes downstream or to the store.
    async fn preview(&self, target: &Record) -> IamResult<Value> {
        let (_, in_scope, links) = self.scope_of(target).await?;
        let actions = [
            "create",
            "adopt",
            "update",
            "reactivate",
            "deactivate",
            "delete",
            "unchanged",
        ];
        let mut counts: Vec<(&str, u64)> = actions.iter().map(|action| (*action, 0)).collect();
        let mut changes: Vec<Value> = Vec::new();
        let mut errors: Vec<Value> = Vec::new();
        let mut plan = |identity_id: &str,
                        email: Option<&Value>,
                        action: &str,
                        counts: &mut Vec<(&str, u64)>| {
            if let Some(entry) = counts.iter_mut().find(|(name, _)| *name == action) {
                entry.1 += 1;
            }
            if changes.len() < 200 {
                let mut change = Map::new();
                change.insert("identityId".into(), json!(identity_id));
                put_member(&mut change, "email", email);
                change.insert("action".into(), json!(action));
                changes.push(Value::Object(change));
            }
        };
        let bump = |counts: &mut Vec<(&str, u64)>, action: &str| {
            if let Some(entry) = counts.iter_mut().find(|(name, _)| *name == action) {
                entry.1 += 1;
            }
        };
        let link_of = |id: &str| {
            links
                .iter()
                .find(|(key, _)| key == id)
                .map(|(_, link)| link)
        };
        for (identity_id, identity) in &in_scope {
            let email = identity.get("email");
            if let Some(link) = link_of(identity_id) {
                if !truthy(link.get("active")) {
                    plan(identity_id, email, "reactivate", &mut counts);
                } else if link.get("fingerprint")
                    != Some(&json!(hash(&core_js::stringify(&Self::user(
                        target, identity
                    )))))
                {
                    plan(identity_id, email, "update", &mut counts);
                } else {
                    bump(&mut counts, "unchanged");
                }
                continue;
            }
            match self.adopt(target, identity).await {
                Ok(existing) => plan(
                    identity_id,
                    email,
                    if existing.is_some() {
                        "adopt"
                    } else {
                        "create"
                    },
                    &mut counts,
                ),
                Err(error) => {
                    if errors.len() < 20 {
                        let mut entry = Map::new();
                        entry.insert("identityId".into(), json!(identity_id));
                        if let SyncError::Downstream {
                            status: Some(status),
                            ..
                        } = &error
                            && *status != 0
                        {
                            entry.insert("status".into(), json!(status));
                        }
                        entry.insert(
                            "message".into(),
                            json!(match &error {
                                SyncError::Downstream { message, .. } => message.clone(),
                                SyncError::Other => "Lookup failed.".to_owned(),
                            }),
                        );
                        errors.push(Value::Object(entry));
                    }
                }
            }
        }
        let deletes = target.get("deprovision").and_then(Value::as_str) == Some("delete");
        for (identity_id, link) in &links {
            if in_scope.iter().any(|(key, _)| key == identity_id) {
                continue;
            }
            if deletes {
                plan(identity_id, None, "delete", &mut counts);
            } else if truthy(link.get("active")) {
                plan(identity_id, None, "deactivate", &mut counts);
            }
        }
        let mut counts_json = Map::new();
        for (action, count) in counts {
            counts_json.insert(action.to_owned(), json!(count));
        }
        Ok(json!({ "counts": Value::Object(counts_json), "changes": changes, "errors": errors }))
    }

    async fn reconcile(&self, target: &Record) -> IamResult<Value> {
        let mut run = Run {
            started_at: date_now(),
            ..Run::default()
        };
        let (active, in_scope, links) = self.scope_of(target).await?;
        let target_id = target.get("id").cloned().unwrap_or(Value::Null);
        let tenant_id = target.get("tenantId").cloned().unwrap_or(Value::Null);
        for (identity_id, identity) in &in_scope {
            let payload = Self::user(target, identity);
            let fingerprint = hash(&core_js::stringify(&payload));
            let link = links
                .iter()
                .find(|(key, _)| key == identity_id)
                .map(|(_, link)| link);
            let result: Result<(), SyncError> = async {
                if let Some(link) = link
                    && truthy(link.get("active"))
                    && link.get("fingerprint") == Some(&json!(fingerprint))
                {
                    run.unchanged += 1;
                    return Ok(());
                }
                let mut remote_id = match link.and_then(|link| nullish(link.get("remoteId"))) {
                    Some(remote) => Some(js_string(Some(remote))),
                    None => self.adopt(target, identity).await?,
                };
                let mut created = false;
                if let Some(remote) = remote_id.clone().filter(|remote| !remote.is_empty()) {
                    let mut body = payload.clone();
                    body.as_object_mut()
                        .expect("the payload is an object")
                        .insert("id".into(), json!(remote));
                    let replaced = self
                        .call(
                            target,
                            "PUT",
                            &format!("/Users/{}", encode_uri_component(&remote)),
                            Some(&body),
                        )
                        .await?;
                    if replaced.status == 404 {
                        remote_id = None;
                    } else if !(200..300).contains(&replaced.status) {
                        return Err(Self::failure(&replaced, "Updating the user"));
                    }
                }
                let remote_id = match remote_id.filter(|remote| !remote.is_empty()) {
                    Some(remote) => remote,
                    None => {
                        let posted = self.call(target, "POST", "/Users", Some(&payload)).await?;
                        if posted.status != 201 && posted.status != 200 {
                            return Err(Self::failure(&posted, "Creating the user"));
                        }
                        let Some(Value::String(id)) = posted.member("id") else {
                            return Err(downstream("The SCIM service returned no user ID."));
                        };
                        created = true;
                        id.clone()
                    }
                };
                let mut record = Map::new();
                record.insert(
                    "id".into(),
                    json!(hash(&format!(
                        "{}:{identity_id}",
                        js_string(Some(&target_id))
                    ))),
                );
                record.insert("tenantId".into(), tenant_id.clone());
                record.insert("targetId".into(), target_id.clone());
                record.insert("identityId".into(), json!(identity_id));
                record.insert("remoteId".into(), json!(remote_id));
                record.insert("fingerprint".into(), json!(fingerprint));
                record.insert("active".into(), json!(true));
                record.insert("syncedAt".into(), number(date_now()));
                self.upsert("provisioningLinks", record).await?;
                if created {
                    run.created += 1;
                } else {
                    run.updated += 1;
                }
                Ok(())
            }
            .await;
            if let Err(error) = result {
                run.fail(identity_id, &error, "identityId");
            }
        }
        let deletes = target.get("deprovision").and_then(Value::as_str) == Some("delete");
        for (identity_id, link) in &links {
            if in_scope.iter().any(|(key, _)| key == identity_id) {
                continue;
            }
            let result: Result<(), SyncError> = async {
                let path = format!(
                    "/Users/{}",
                    encode_uri_component(&js_string(link.get("remoteId")))
                );
                if deletes {
                    let removed = self.call(target, "DELETE", &path, None).await?;
                    if ![204, 200, 404].contains(&removed.status) {
                        return Err(Self::failure(&removed, "Deleting the user"));
                    }
                    self.remove("provisioningLinks", js_string(link.get("id")))
                        .await?;
                    run.deleted += 1;
                    return Ok(());
                }
                if !truthy(link.get("active")) {
                    return Ok(());
                }
                let body = json!({
                    "schemas": [PATCH_SCHEMA],
                    "Operations": [{ "op": "replace", "value": { "active": false } }],
                });
                let patched = self.call(target, "PATCH", &path, Some(&body)).await?;
                if patched.status == 404 {
                    self.remove("provisioningLinks", js_string(link.get("id")))
                        .await?;
                    return Ok(());
                }
                if !(200..300).contains(&patched.status) {
                    return Err(Self::failure(&patched, "Deactivating the user"));
                }
                let mut saved = link.clone();
                saved.insert("active".into(), json!(false));
                saved.insert("fingerprint".into(), json!(""));
                saved.insert("syncedAt".into(), number(date_now()));
                self.upsert("provisioningLinks", saved).await?;
                run.deactivated += 1;
                Ok(())
            }
            .await;
            if let Err(error) = result {
                run.fail(identity_id, &error, "identityId");
            }
        }
        self.push_groups(target, active && truthy(target.get("enabled")), &mut run)
            .await?;
        run.finished_at = date_now();
        let last_run = run.to_json();
        let id = js_string(Some(&target_id));
        let stored = last_run.clone();
        self.config
            .store
            .transaction(move |tx| async move {
                if let Some(mut current) = tx.get("provisioningTargets", &id).await? {
                    current.insert("lastRun".into(), stored);
                    tx.put("provisioningTargets", &current).await?;
                }
                Ok(())
            })
            .await?;
        Ok(last_run)
    }
}

impl ScimProvisioner {
    /// `createScimProvisioner(config)`.
    pub fn new(config: ProvisioningConfig) -> IamResult<Self> {
        let key = key_of(&config.encryption_key).ok_or_else(|| {
            IamError::new(
                "configuration",
                "Provisioning encryptionKey must encode exactly 32 bytes.",
            )
        })?;
        let previous_keys = config
            .previous_encryption_keys
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|value| key_of(value))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                IamError::new(
                    "configuration",
                    "Each previous provisioning encryption key must encode exactly 32 bytes.",
                )
            })?;
        // Tenant administrators choose target URLs, so the default transport refuses private and reserved addresses
        // at connect time (a hostname cannot be re-pointed at the internal network after validation) and bounds
        // responses.
        let address_rules = SafeFetchAddressOptions {
            any_port: true,
            allow_insecure_localhost: config.allow_insecure_localhost,
            allow_private_networks: config.allow_private_networks,
        };
        let request: Arc<dyn ScimTransport> = match &config.fetch {
            Some(fetch) => fetch.clone(),
            None => Arc::new(GuardedTransport::new(GuardedFetchOptions {
                allow_private_networks: address_rules.allow_private_networks,
                allow_insecure_localhost: address_rules.allow_insecure_localhost,
                any_port: true,
                max_bytes: Some(1_000_000),
            })),
        };
        let base_path = config
            .base_path
            .clone()
            .unwrap_or_else(|| "/scim/provisioning".to_owned());
        let base_path = base_path.strip_suffix('/').unwrap_or(&base_path).to_owned();
        Ok(Self {
            inner: Arc::new(Inner {
                timeout_ms: config.timeout_ms.unwrap_or(10_000.0),
                config,
                key,
                previous_keys,
                address_rules,
                request,
                running: Mutex::new(HashMap::new()),
                base_path,
            }),
        })
    }

    /// `basePath`.
    pub fn base_path(&self) -> &str {
        &self.inner.base_path
    }

    /// Runs one reconciliation per target at a time; concurrent requests share the running one.
    async fn run_once(&self, target: Record) -> IamResult<Value> {
        let id = js_string(target.get("id"));
        let future = {
            let mut running = self
                .inner
                .running
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match running.get(&id) {
                Some(pending) => pending.clone(),
                None => {
                    let inner = self.inner.clone();
                    let key = id.clone();
                    let future: BoxFuture<'static, IamResult<Value>> = Box::pin(async move {
                        let result = inner.reconcile(&target).await;
                        inner
                            .running
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .remove(&key);
                        result
                    });
                    let shared = future.shared();
                    running.insert(id.clone(), shared.clone());
                    shared
                }
            }
        };
        future.await
    }

    /// `syncAll({ tenantId? })`: deployment operation for schedulers and event hooks: reconciles every target
    /// (optionally one tenant's). Runs with no credential; do not expose it over HTTP. Answers `{ [targetId]: run }`.
    pub async fn sync_all(&self, tenant_id: Option<&str>) -> IamResult<Value> {
        let filter = match tenant_id.filter(|id| !id.is_empty()) {
            Some(id) => Filter::new().eq("tenantId", id.to_owned()),
            None => Filter::new(),
        };
        let targets = find(
            self.inner.config.store.as_ref(),
            "provisioningTargets",
            filter,
        )
        .await?;
        let mut runs = Map::new();
        for target in targets {
            let id = js_string(target.get("id"));
            let run = self.run_once(target).await?;
            runs.insert(id, run);
        }
        Ok(Value::Object(runs))
    }

    /// `createTarget(credential, input)`: adds a downstream application (`iam:scim:targets:create`). The token is
    /// encrypted and never returned.
    pub async fn create_target(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let inner = &self.inner;
        let id = format!("scim-target-{}", hex::encode(random_bytes(8)));
        let tenant_id = string_member(input, "tenantId");
        let principal = inner
            .authorized(credential, "iam:scim:targets:create", &tenant_id, &id)
            .await?;
        let values = inner.settings(input, None)?;
        let sealed_token = inner.seal(&Inner::token(input.get("token"))?);
        let this = self.inner.clone();
        let raw_tenant = input.get("tenantId").cloned();
        inner
            .config
            .store
            .transaction(move |tx| async move {
                if !tenant_tree_active(tx.as_ref(), &tenant_id).await? {
                    return Err(IamError::with_status(
                        "TENANT_INACTIVE",
                        "Tenant unavailable.",
                        403,
                    ));
                }
                let now = date_now();
                let mut record = Map::new();
                record.insert("id".into(), json!(id));
                put_member(&mut record, "tenantId", raw_tenant.as_ref());
                values.write(&mut record);
                record.insert("sealedToken".into(), json!(sealed_token));
                record.insert("createdAt".into(), number(now));
                record.insert("updatedAt".into(), number(now));
                record.insert("tokenUpdatedAt".into(), number(now));
                tx.insert("provisioningTargets", &record).await?;
                this.audit(
                    &tx,
                    raw_tenant.as_ref(),
                    &principal,
                    "iam:scim:CreateTarget",
                    &id,
                )
                .await?;
                this.summary(&record, &tx).await
            })
            .await
    }

    /// `listTargets(credential, { tenantId })`.
    pub async fn list_targets(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let inner = &self.inner;
        inner
            .authorized(
                credential,
                "iam:scim:targets:read",
                &string_member(input, "tenantId"),
                "*",
            )
            .await?;
        let mut filter = Filter::new();
        filter.set("tenantId", input.get("tenantId").cloned());
        let mut targets = find(inner.config.store.as_ref(), "provisioningTargets", filter).await?;
        let created = |record: &Record| {
            record
                .get("createdAt")
                .and_then(Value::as_f64)
                .unwrap_or(f64::NAN)
        };
        targets.sort_by(|a, b| {
            let difference = created(a) - created(b);
            if difference != 0.0 && !difference.is_nan() {
                return difference
                    .partial_cmp(&0.0)
                    .unwrap_or(std::cmp::Ordering::Equal);
            }
            if core_js::cmp_utf16(&js_string(a.get("id")), &js_string(b.get("id")))
                == std::cmp::Ordering::Less
            {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });
        let mut summaries = Vec::new();
        for target in &targets {
            summaries.push(inner.summary(target, &inner.config.store).await?);
        }
        Ok(Value::Array(summaries))
    }

    /// `getTarget(credential, { tenantId, targetId })`.
    pub async fn get_target(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let inner = &self.inner;
        inner
            .authorized(
                credential,
                "iam:scim:targets:read",
                &string_member(input, "tenantId"),
                &js_string(input.get("targetId")),
            )
            .await?;
        let target = inner.owned(&inner.config.store, input).await?;
        inner.summary(&target, &inner.config.store).await
    }

    /// `updateTarget(credential, input)`: changes a target; a new `token` replaces the stored one. Scope changes apply
    /// at the next sync.
    pub async fn update_target(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let inner = &self.inner;
        let principal = inner
            .authorized(
                credential,
                "iam:scim:targets:update",
                &string_member(input, "tenantId"),
                &js_string(input.get("targetId")),
            )
            .await?;
        let this = self.inner.clone();
        inner
            .config
            .store
            .transaction(move |tx| async move {
                let current = this.owned(&tx, input).await?;
                let now = date_now();
                let values = this.settings(input, Some(&current))?;
                // The stored token is write-only: pointing the target somewhere else must not send it along, so a new
                // base URL needs the token again (whoever sets it proves they hold a credential for the new service).
                if current.get("baseUrl") != Some(&json!(values.base_url))
                    && input.get("token").is_none()
                {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "Changing the SCIM base URL needs the downstream token again.",
                    ));
                }
                let mut record = current.clone();
                values.write(&mut record);
                if input.get("token").is_some() {
                    let sealed = this.seal(&Inner::token(input.get("token"))?);
                    record.insert("sealedToken".into(), json!(sealed));
                    record.insert("tokenUpdatedAt".into(), number(now));
                }
                record.insert("updatedAt".into(), number(now));
                tx.put("provisioningTargets", &record).await?;
                let id = js_string(current.get("id"));
                this.audit(
                    &tx,
                    input.get("tenantId"),
                    &principal,
                    "iam:scim:UpdateTarget",
                    &id,
                )
                .await?;
                this.summary(&record, &tx).await
            })
            .await
    }

    /// `deleteTarget(credential, { tenantId, targetId })`: removes a target and its links. Downstream accounts are left
    /// as they are.
    pub async fn delete_target(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<()> {
        let inner = &self.inner;
        let principal = inner
            .authorized(
                credential,
                "iam:scim:targets:delete",
                &string_member(input, "tenantId"),
                &js_string(input.get("targetId")),
            )
            .await?;
        let this = self.inner.clone();
        inner
            .config
            .store
            .transaction(move |tx| async move {
                let current = this.owned(&tx, input).await?;
                let target_id = current.get("id").cloned().unwrap_or(Value::Null);
                for link in find(
                    tx.as_ref(),
                    "provisioningLinks",
                    Filter::new().eq("targetId", target_id.clone()),
                )
                .await?
                {
                    tx.delete("provisioningLinks", &js_string(link.get("id")))
                        .await?;
                }
                for link in find(
                    tx.as_ref(),
                    "provisioningGroupLinks",
                    Filter::new().eq("targetId", target_id.clone()),
                )
                .await?
                {
                    tx.delete("provisioningGroupLinks", &js_string(link.get("id")))
                        .await?;
                }
                let id = js_string(Some(&target_id));
                tx.delete("provisioningTargets", &id).await?;
                this.audit(
                    &tx,
                    input.get("tenantId"),
                    &principal,
                    "iam:scim:DeleteTarget",
                    &id,
                )
                .await
            })
            .await
    }

    /// `previewTarget(credential, { tenantId, targetId })`: what a sync would change right now
    /// (`iam:scim:targets:read`); only read-only lookups reach the application.
    pub async fn preview_target(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let inner = &self.inner;
        let tenant_id = string_member(input, "tenantId");
        inner
            .authorized(
                credential,
                "iam:scim:targets:read",
                &tenant_id,
                &js_string(input.get("targetId")),
            )
            .await?;
        // The preview lists members' addresses and looks them up downstream: reading the directory.
        inner
            .authorize(
                credential,
                "iam:identities:read",
                &tenant_id,
                "iam",
                &tenant_id,
            )
            .await?;
        let target = inner.owned(&inner.config.store, input).await?;
        inner.preview(&target).await
    }

    /// `syncTarget(credential, { tenantId, targetId })`: reconciles one target now (`iam:scim:targets:sync`) and
    /// returns the run.
    pub async fn sync_target(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let inner = &self.inner;
        let principal = inner
            .authorized(
                credential,
                "iam:scim:targets:sync",
                &string_member(input, "tenantId"),
                &js_string(input.get("targetId")),
            )
            .await?;
        let target = inner.owned(&inner.config.store, input).await?;
        let target_id = js_string(target.get("id"));
        let run = self.run_once(target).await?;
        let this = self.inner.clone();
        let tenant = input.get("tenantId").cloned();
        inner
            .config
            .store
            .transaction(move |tx| async move {
                this.audit(
                    &tx,
                    tenant.as_ref(),
                    &principal,
                    "iam:scim:SyncTarget",
                    &target_id,
                )
                .await
            })
            .await?;
        Ok(run)
    }

    /// `subscribe(events, options)`: keeps targets current from IAM events: membership, identity, and tenant changes
    /// schedule a sync of the tenant's targets after `debounce_ms` (default 2 seconds). Returns the unsubscribe
    /// function.
    pub fn subscribe(&self, events: &dyn EventSource, options: SubscribeOptions) -> Unsubscribe {
        let timers: Arc<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let runtime = tokio::runtime::Handle::try_current().ok();
        let this = self.clone();
        let handler_timers = timers.clone();
        let debounce = std::time::Duration::from_millis(options.debounce_ms.unwrap_or(2000));
        let handler: EventHandler = Arc::new(move |event: ProvisioningEvent| {
            // The provisioner's own management and sync events never schedule another run.
            if own_event(&event.action) {
                return;
            }
            let Some(runtime) = tokio::runtime::Handle::try_current()
                .ok()
                .or_else(|| runtime.clone())
            else {
                return;
            };
            let mut guard = handler_timers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(previous) = guard.remove(&event.tenant_id) {
                previous.abort();
            }
            let tenant = event.tenant_id.clone();
            let timers = handler_timers.clone();
            let provisioner = this.clone();
            let on_error = options.on_error.clone();
            let spawner = runtime.clone();
            let task = runtime.spawn(async move {
                tokio::time::sleep(debounce).await;
                timers
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&tenant);
                spawner.spawn(async move {
                    if let Err(error) = provisioner.sync_all(Some(&tenant)).await
                        && let Some(on_error) = on_error
                    {
                        on_error(error);
                    }
                });
            });
            guard.insert(event.tenant_id, task);
        });
        let patterns = [
            "iam:identities:*",
            "iam:groups:*",
            "iam:packages:*",
            "package:*",
            "group:*",
            "iam:tenants:*",
            "iam:scim:*",
            "identity:*",
            "tenant:*",
            "invitation:*",
        ]
        .iter()
        .map(|pattern| (*pattern).to_owned())
        .collect();
        let unsubscribe = events.subscribe(patterns, handler);
        Box::new(move || {
            unsubscribe();
            let mut guard = timers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (_, timer) in guard.drain() {
                timer.abort();
            }
        })
    }

    /// `handler(request)`: the JSON management API for browsers and scripts: `POST {basePath}/targets/…` with the
    /// caller's IAM cookie or bearer token. Like the IAM API it requires `X-Better-IAM: 1` and a JSON body, so
    /// cross-site forms cannot call it, and it answers `{ data }` or `{ error: { code, message } }`. None for requests
    /// outside the base path.
    pub async fn handler(&self, request: &HttpRequest) -> Option<HttpResponse> {
        let url = request_url(request)?;
        let base_path = &self.inner.base_path;
        if !url.path().starts_with(&format!("{base_path}/")) {
            return None;
        }
        let name = url.path()[base_path.len() + 1..].to_owned();
        let reply = |body: Value, status: u16| {
            http_response(
                status,
                Some(core_js::stringify(&body)),
                &[
                    ("content-type", "application/json".to_owned()),
                    ("cache-control", "no-store".to_owned()),
                ],
            )
        };
        const ROUTES: [&str; 7] = [
            "targets/list",
            "targets/get",
            "targets/create",
            "targets/update",
            "targets/delete",
            "targets/sync",
            "targets/preview",
        ];
        if !ROUTES.contains(&name.as_str()) {
            return Some(reply(
                json!({ "error": { "code": "NOT_FOUND", "message": "Unknown route." } }),
                404,
            ));
        }
        let header = |key: &str| {
            let values: Vec<String> = request
                .headers()
                .get_all(key)
                .iter()
                .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
                .collect();
            (!values.is_empty()).then(|| values.join(", "))
        };
        let result: IamResult<Value> = async {
            if request.method() != http::Method::POST {
                return Err(IamError::with_status(
                    "METHOD_NOT_ALLOWED",
                    "Use POST.",
                    405,
                ));
            }
            if header("x-better-iam").as_deref() != Some("1")
                || !header("content-type")
                    .is_some_and(|value| value.starts_with("application/json"))
            {
                return Err(IamError::with_status(
                    "CSRF_REJECTED",
                    "JSON requests require X-Better-IAM: 1.",
                    403,
                ));
            }
            if request.body().len() > 64 * 1024 {
                return Err(IamError::with_status(
                    "INVALID_INPUT",
                    "Request too large.",
                    413,
                ));
            }
            let text = String::from_utf8_lossy(request.body());
            let body = if text.is_empty() {
                json!({})
            } else {
                core_js::parse(&text).map_err(|_| {
                    IamError::with_status("INVALID_INPUT", "The body must be JSON.", 400)
                })?
            };
            if !body.is_object() {
                return Err(IamError::with_status(
                    "INVALID_INPUT",
                    "The body must be a JSON object.",
                    400,
                ));
            }
            let credential = CredentialInput {
                headers: Some(
                    request
                        .headers()
                        .iter()
                        .map(|(key, value)| {
                            (
                                key.as_str().to_owned(),
                                String::from_utf8_lossy(value.as_bytes()).into_owned(),
                            )
                        })
                        .collect(),
                ),
                token: None,
            };
            match name.as_str() {
                "targets/list" => self.list_targets(&credential, &body).await,
                "targets/get" => self.get_target(&credential, &body).await,
                "targets/create" => self.create_target(&credential, &body).await,
                "targets/update" => self.update_target(&credential, &body).await,
                "targets/delete" => self
                    .delete_target(&credential, &body)
                    .await
                    .map(|()| Value::Null),
                "targets/sync" => self.sync_target(&credential, &body).await,
                _ => self.preview_target(&credential, &body).await,
            }
        }
        .await;
        Some(match result {
            Ok(data) => reply(json!({ "data": data }), 200),
            Err(error) if crate::js::is_unexpected(&error) => reply(
                json!({
                    "error": { "code": "INTERNAL_ERROR", "message": "Provisioning request failed." }
                }),
                500,
            ),
            Err(error) => reply(
                json!({ "error": { "code": error.code, "message": error.message } }),
                error.status,
            ),
        })
    }

    /// `rotateKeys()`: deployment operation (not served over HTTP): re-seals every stored downstream token opened by a
    /// previous key with `encryption_key`, so the previous keys can be removed. Idempotent. Answers `{ resealed,
    /// current, unreadable }`.
    pub async fn rotate_keys(&self) -> IamResult<Value> {
        let mut resealed = 0u64;
        let mut current = 0u64;
        let mut unreadable = 0u64;
        let mut after: Option<String> = None;
        loop {
            let inner = self.inner.clone();
            let cursor = after.clone();
            let (page, counts) = self
                .inner
                .config
                .store
                .transaction(move |tx| async move {
                    let mut counts = (0u64, 0u64, 0u64);
                    let targets = tx
                        .find(
                            "provisioningTargets",
                            &Filter::new(),
                            &FindOptions {
                                limit: Some(200),
                                offset: None,
                                after: cursor,
                            },
                        )
                        .await?;
                    for target in &targets {
                        let opened = target
                            .get("sealedToken")
                            .and_then(Value::as_str)
                            .and_then(|value| inner.open_with(value));
                        match opened {
                            None => counts.2 += 1,
                            Some((_, 0)) => counts.1 += 1,
                            Some((value, _)) => {
                                let mut record = target.clone();
                                record.insert("sealedToken".into(), json!(inner.seal(&value)));
                                tx.put("provisioningTargets", &record).await?;
                                counts.0 += 1;
                            }
                        }
                    }
                    Ok((targets, counts))
                })
                .await?;
            resealed += counts.0;
            current += counts.1;
            unreadable += counts.2;
            if page.len() < 200 {
                return Ok(
                    json!({ "resealed": resealed, "current": current, "unreadable": unreadable }),
                );
            }
            after = page.last().map(|target| js_string(target.get("id")));
        }
    }
}

/// `/^iam:scim:\w+Target$/`.
fn own_event(action: &str) -> bool {
    action
        .strip_prefix("iam:scim:")
        .and_then(|rest| rest.strip_suffix("Target"))
        .is_some_and(|middle| {
            !middle.is_empty()
                && middle
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}
