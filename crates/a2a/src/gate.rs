//! Authorization for Agent2Agent (A2A) servers speaking JSON-RPC over HTTP (gate.ts).
//!
//! [`create_a2a_gate`] sits in front of an A2A endpoint (a request → response handler). It serves the agent card at
//! `/.well-known/agent-card.json` without authentication, authenticates every other request (a Better IAM
//! credential: a person's session, an agent's key, or a delegated session in which an agent acts for a person; or an
//! OAuth access token), decides `message/send` and `message/stream` by the skill a message names (its
//! `metadata.skillId`) or the agent-wide message rule, and makes tasks private to the caller who started them:
//! `tasks/get`, `tasks/cancel`, `tasks/resubscribe` and push notification settings for a task another caller started
//! answer "task not found". `agent/getAuthenticatedExtendedCard` lists only the skills the caller may use.

use std::future::Future;
use std::sync::{Arc, LazyLock, Mutex};

use async_trait::async_trait;
use better_iam_core::{CredentialInput, js, match_pattern};
use bytes::Bytes;
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::cards::{AgentCard, CardSource, plain};
use crate::error::A2aError;
use crate::transport::{
    self, Body, BodyError, Utf8Stream, decode_utf8, header, json_response, read_all, read_bounded,
};

/// A resource the policy engine decides on (`A2aResourceRef`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2aResourceRef {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

impl A2aResourceRef {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        A2aResourceRef {
            kind: kind.into(),
            id: id.into(),
        }
    }
}

/// The resource of a message chosen from its params.
pub type ResourceFn =
    Arc<dyn Fn(&Map<String, Value>) -> Result<A2aResourceRef, A2aError> + Send + Sync>;

/// The resource a rule's messages act on.
#[derive(Clone)]
pub enum RuleResource {
    Fixed(A2aResourceRef),
    /// Chosen per message from its params; a failure denies the message.
    Of(ResourceFn),
}

impl From<A2aResourceRef> for RuleResource {
    fn from(resource: A2aResourceRef) -> Self {
        RuleResource::Fixed(resource)
    }
}

/// How one skill (or the agent's messages as a whole) is authorized (`A2aRule`).
#[derive(Clone, Default)]
pub struct A2aRule {
    /// The Better IAM action a message needs (Better IAM credentials).
    pub action: Option<String>,
    /// The resource the message acts on; default `{ type: 'a2a-skill', id: skillId }` (`a2a-agent`/`agent` for
    /// `message`).
    pub resource: Option<RuleResource>,
    /// Scopes an OAuth access token needs (OAuth callers).
    pub scopes: Option<Vec<String>>,
    /// Any authenticated caller may send such messages.
    pub public: bool,
}

impl A2aRule {
    /// A rule any authenticated caller passes (`{ public: true }`).
    pub fn public() -> Self {
        A2aRule {
            public: true,
            ..A2aRule::default()
        }
    }

    /// A rule needing `action` on `resource` (`{ action, resource }`).
    pub fn action(action: impl Into<String>, resource: Option<A2aResourceRef>) -> Self {
        A2aRule {
            action: Some(action.into()),
            resource: resource.map(RuleResource::Fixed),
            ..A2aRule::default()
        }
    }
}

/// The identity of an authenticated principal, as the gate reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A2aIdentity {
    pub id: String,
    pub tenant_id: String,
    pub kind: String,
}

/// The session of an authenticated principal, as the gate reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A2aSession {
    pub id: String,
    pub tenant_id: String,
    pub kind: String,
    pub agent_id: Option<String>,
    pub delegation_id: Option<String>,
}

/// `iam.authenticate(credential)`'s result, as the gate reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A2aPrincipal {
    pub identity: A2aIdentity,
    pub session: A2aSession,
}

/// One authorization answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A2aAuthorization {
    pub allowed: bool,
    pub reason: String,
}

/// One check of a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A2aCheck {
    pub action: String,
    pub resource: A2aResourceRef,
}

/// A delegation, as the gate reads it (`delegations.get`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct A2aDelegation {
    /// The actions the person confirms one request at a time.
    pub confirm: Option<Vec<String>>,
}

/// A filed confirmation request (`delegations.requestConfirmation`).
#[derive(Debug, Clone, PartialEq)]
pub struct A2aConfirmationRequest {
    pub id: String,
    pub status: String,
    pub expires_at: f64,
}

/// The delegation calls the gate makes to ask a person to confirm an agent's request (`iam.api.delegations`).
#[async_trait]
pub trait A2aDelegations: Send + Sync {
    /// `delegations.get(credential, { tenantId, delegationId })`.
    async fn get(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        delegation_id: &str,
    ) -> Result<A2aDelegation, A2aError>;

    /// `delegations.requestConfirmation(credential, { tenantId, action, resource, reason })`.
    async fn request_confirmation(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        action: &str,
        resource: &A2aResourceRef,
        reason: &str,
    ) -> Result<A2aConfirmationRequest, A2aError>;
}

/// The part of a Better IAM instance (`better_iam()`) or client the gate needs (`A2aIam`).
#[async_trait]
pub trait A2aIam: Send + Sync {
    /// `iam.authenticate(credential)`.
    async fn authenticate(&self, credential: &CredentialInput) -> Result<A2aPrincipal, A2aError>;

    /// `iam.authorize({ ...credential, tenantId, action, resource })`.
    async fn authorize(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        action: &str,
        resource: &A2aResourceRef,
    ) -> Result<A2aAuthorization, A2aError>;

    /// `iam.authorizeMany({ ...credential, tenantId, checks })`: one result per check, in order.
    async fn authorize_many(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        checks: &[A2aCheck],
    ) -> Result<Vec<A2aAuthorization>, A2aError>;

    /// `iam.api.delegations`: present on a `better_iam()` instance; lets the gate ask a person to confirm an agent's
    /// request.
    fn delegations(&self) -> Option<&dyn A2aDelegations> {
        None
    }
}

/// The request an OAuth verifier checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A2aOAuthRequest {
    pub authorization: Option<String>,
    pub dpop: Option<String>,
    pub method: String,
    pub url: String,
}

/// What a verified access token says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A2aOAuthToken {
    pub subject: Option<String>,
    pub client_id: String,
    pub tenant_id: Option<String>,
    pub scopes: Vec<String>,
}

/// The access-token verifier of `better-iam-oauth` (`createAccessTokenVerifier` or a resource guard's `verifier`)
/// (`A2aOAuthVerifier`).
#[async_trait]
pub trait A2aOAuthVerifier: Send + Sync {
    /// `verifyRequest(request, requirement)`.
    async fn verify_request(
        &self,
        request: &A2aOAuthRequest,
        scopes: Option<&[String]>,
    ) -> Result<A2aOAuthToken, A2aError>;
}

/// A caller with a Better IAM credential.
#[derive(Debug, Clone, PartialEq)]
pub struct A2aIamCaller {
    pub credential: CredentialInput,
    pub tenant_id: String,
    pub identity_id: String,
    pub identity_kind: String,
    pub session_kind: String,
    /// The agent behind the credential: its own key, or the agent of a delegated session.
    pub agent_id: Option<String>,
    pub delegation_id: Option<String>,
}

/// A caller with an OAuth access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A2aOAuthCaller {
    pub subject: Option<String>,
    pub client_id: String,
    pub tenant_id: Option<String>,
    pub scopes: Vec<String>,
}

/// Who is calling the A2A server (`A2aCaller`).
#[derive(Debug, Clone, PartialEq)]
pub enum A2aCaller {
    Iam(A2aIamCaller),
    OAuth(A2aOAuthCaller),
}

impl A2aCaller {
    /// `kind`: `iam` or `oauth`.
    pub fn kind(&self) -> &'static str {
        match self {
            A2aCaller::Iam(_) => "iam",
            A2aCaller::OAuth(_) => "oauth",
        }
    }
}

/// Who started each task and each conversation (A2A context), by key `task:{id}` or `context:{id}`
/// (`A2aTaskOwners`). The default keeps owners in this process's memory.
#[async_trait]
pub trait A2aTaskOwners: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<String>, A2aError>;
    async fn set(&self, key: &str, owner: &str) -> Result<(), A2aError>;
}

/// Options of [`memory_task_owners`].
#[derive(Clone, Default)]
pub struct MemoryTaskOwnersOptions {
    /// At most this many entries (default 100000).
    pub max_tasks: Option<usize>,
    /// How long each entry is kept, in milliseconds (default seven days).
    pub ttl_ms: Option<f64>,
    pub now: Option<crate::cards::Clock>,
}

/// In-memory owners ([`memory_task_owners`]).
pub struct MemoryTaskOwners {
    max_tasks: usize,
    ttl_ms: f64,
    now: Option<crate::cards::Clock>,
    owners: Mutex<IndexMap<String, (String, f64)>>,
}

impl MemoryTaskOwners {
    fn now(&self) -> f64 {
        match &self.now {
            Some(now) => now(),
            None => js::now_ms(),
        }
    }
}

/// In-memory owners: at most `max_tasks` entries (default 100000), each kept `ttl_ms` (default seven days)
/// (`memoryTaskOwners`).
pub fn memory_task_owners(options: MemoryTaskOwnersOptions) -> MemoryTaskOwners {
    MemoryTaskOwners {
        max_tasks: options.max_tasks.unwrap_or(100_000),
        ttl_ms: options.ttl_ms.unwrap_or(7.0 * 24.0 * 3600.0 * 1000.0),
        now: options.now,
        owners: Mutex::new(IndexMap::new()),
    }
}

#[async_trait]
impl A2aTaskOwners for MemoryTaskOwners {
    async fn get(&self, key: &str) -> Result<Option<String>, A2aError> {
        let mut owners = self
            .owners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((owner, until)) = owners.get(key) else {
            return Ok(None);
        };
        if *until <= self.now() {
            owners.shift_remove(key);
            return Ok(None);
        }
        Ok(Some(owner.clone()))
    }

    async fn set(&self, key: &str, owner: &str) -> Result<(), A2aError> {
        let until = self.now() + self.ttl_ms;
        let mut owners = self
            .owners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        owners.shift_remove(key);
        owners.insert(key.to_owned(), (owner.to_owned(), until));
        while owners.len() > self.max_tasks {
            owners.shift_remove_index(0);
        }
        Ok(())
    }
}

/// Messages naming a skill without a rule: refused (`Deny`, the default) or decided by `message`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnlistedSkills {
    #[default]
    Deny,
    Message,
}

/// Requests the gate does not decide itself: refused (`Deny`, the default) or passed on (`Allow`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Passthrough {
    #[default]
    Deny,
    Allow,
}

/// Chooses the tenant per caller from its identity id and its session's tenant; None refuses the caller.
pub type TenantFn = Arc<dyn Fn(&str, &str) -> Option<String> + Send + Sync>;

/// The tenant decisions are made in: the organization that runs this agent.
#[derive(Clone)]
pub enum A2aTenant {
    Fixed(String),
    /// Chosen per caller (`{ identityId, sessionTenantId }`); None refuses the caller.
    Choose(TenantFn),
}

impl From<String> for A2aTenant {
    fn from(tenant_id: String) -> Self {
        A2aTenant::Fixed(tenant_id)
    }
}

impl From<&str> for A2aTenant {
    fn from(tenant_id: &str) -> Self {
        A2aTenant::Fixed(tenant_id.to_owned())
    }
}

/// How a request names its skill.
pub type SkillOfFn = Arc<dyn Fn(&Map<String, Value>) -> Option<String> + Send + Sync>;
/// Called with unexpected errors.
pub type OnErrorFn = Arc<dyn Fn(&A2aError) + Send + Sync>;
/// The reason shown to the person asked to confirm an agent's request.
pub type ConfirmationReasonFn =
    Arc<dyn Fn(Option<&str>, &Map<String, Value>) -> String + Send + Sync>;

/// `A2aGateOptions`.
#[derive(Clone)]
pub struct A2aGateOptions {
    pub iam: Arc<dyn A2aIam>,
    /// The rule for every message that names no skill (and for all messages when skills are not used).
    pub message: A2aRule,
    /// Rules by skill id, for messages that name a skill (`metadata.skillId`).
    pub skills: Option<IndexMap<String, A2aRule>>,
    /// Messages naming a skill without a rule: refused (the default) or decided by `message`.
    pub unlisted_skills: UnlistedSkills,
    /// How a request names its skill (default: `params.message.metadata.skillId`, then `params.metadata.skillId`).
    pub skill_of: Option<SkillOfFn>,
    /// The card served at `/.well-known/agent-card.json` (for example from `create_card_attestor`).
    pub card: Option<CardSource>,
    /// The card answered to `agent/getAuthenticatedExtendedCard`, with only the skills the caller may use.
    pub extended_card: Option<CardSource>,
    /// Who started each task and conversation; supply a shared store when several instances serve the agent.
    /// Unknown tasks and conversations belong to no one, so a restart with the in-memory default ends access to
    /// earlier ones.
    pub tasks: Option<Arc<dyn A2aTaskOwners>>,
    /// Callers allowed this action on the `message` rule's resource may read and cancel every task (operators).
    pub task_admin_action: Option<String>,
    /// JSON-RPC methods A2A does not define: refused (the default) or passed on.
    pub other_methods: Passthrough,
    /// HTTP methods other than POST (besides the agent card): refused with 405 (the default) or passed on to the
    /// server unchecked apart from authentication (for servers that serve more than JSON-RPC at this address).
    pub other_http_methods: Passthrough,
    /// The tenant decisions are made in: the organization that runs this agent (required). Deciding in each
    /// caller's own tenant would let any organization grant itself access.
    pub tenant_id: A2aTenant,
    /// Accepts OAuth access tokens too, decided by each rule's `scopes`. A token naming a tenant other than a fixed
    /// `tenant_id` is refused.
    pub oauth: Option<Arc<dyn A2aOAuthVerifier>>,
    /// Called with unexpected errors before the gate answers JSON-RPC `-32603` (HTTP 500).
    pub on_error: Option<OnErrorFn>,
    /// When an agent acting for a person (a delegated session) sends a message whose action the person confirms one
    /// request at a time (the delegation's `confirm`), ask the person (`delegations.requestConfirmation`) and answer
    /// with [`A2A_CONFIRMATION_REQUESTED`]. On by default when `iam.delegations()` exists; `Some(false)` turns it off.
    pub confirmations: Option<bool>,
    pub confirmation_reason: Option<ConfirmationReasonFn>,
    /// Largest accepted JSON-RPC body in bytes (default 4 MiB).
    pub max_body_bytes: Option<usize>,
}

impl A2aGateOptions {
    /// Options with the required members; the others take their defaults.
    pub fn new(iam: Arc<dyn A2aIam>, tenant_id: impl Into<A2aTenant>, message: A2aRule) -> Self {
        A2aGateOptions {
            iam,
            message,
            skills: None,
            unlisted_skills: UnlistedSkills::Deny,
            skill_of: None,
            card: None,
            extended_card: None,
            tasks: None,
            task_admin_action: None,
            other_methods: Passthrough::Deny,
            other_http_methods: Passthrough::Deny,
            tenant_id: tenant_id.into(),
            oauth: None,
            on_error: None,
            confirmations: None,
            confirmation_reason: None,
            max_body_bytes: None,
        }
    }
}

/// JSON-RPC error code (HTTP 403) of a message the caller may not send: `error.data.reason` says why
/// (`ACCESS_DENIED`, `UNKNOWN_SKILL`, `NO_RULE_FOR_CALLER`, `INSUFFICIENT_SCOPE`). Tasks of other callers answer
/// A2A's own `-32001`.
pub const A2A_ACCESS_DENIED: i64 = -32050;
/// JSON-RPC error code (HTTP 403) telling an agent that acts for a person that the person must confirm this request
/// first: a confirmation request was filed (`error.data.confirmationId`, `error.data.expiresAt`); retry once
/// approved.
pub const A2A_CONFIRMATION_REQUESTED: i64 = -32051;

/// A filed confirmation.
#[derive(Debug, Clone, PartialEq)]
pub struct A2aConfirmation {
    pub id: String,
    pub expires_at: f64,
}

/// `A2aDecision`.
#[derive(Debug, Clone, PartialEq)]
pub struct A2aDecision {
    pub allowed: bool,
    /// `ALLOWED`, `PUBLIC`, `ACCESS_DENIED`, `UNKNOWN_SKILL`, `AMBIGUOUS_SKILL`, `NO_RULE_FOR_CALLER`,
    /// `INSUFFICIENT_SCOPE`, or `CONFIRMATION_REQUESTED`.
    pub reason: String,
    pub confirmation: Option<A2aConfirmation>,
}

impl A2aDecision {
    fn of(allowed: bool, reason: &str) -> Self {
        A2aDecision {
            allowed,
            reason: reason.to_owned(),
            confirmation: None,
        }
    }
}

const TASK_METHODS: [&str; 7] = [
    "tasks/get",
    "tasks/cancel",
    "tasks/resubscribe",
    "tasks/pushNotificationConfig/set",
    "tasks/pushNotificationConfig/get",
    "tasks/pushNotificationConfig/list",
    "tasks/pushNotificationConfig/delete",
];
const MESSAGE_METHODS: [&str; 2] = ["message/send", "message/stream"];
const EXTENDED_CARD_METHOD: &str = "agent/getAuthenticatedExtendedCard";

/// A rule and, for a skill's own rule, the skill its default resource is named after.
struct Found {
    rule: A2aRule,
    named: Option<String>,
}

/// `presented(request)`: the credential a request carries, as `(scheme, token)`.
fn presented(headers: &http::HeaderMap) -> Option<(String, String)> {
    let authorization = header(headers, "authorization").unwrap_or_default();
    if let Some(found) = bearer_or_dpop(&authorization) {
        return Some(found);
    }
    match header(headers, "x-api-key") {
        Some(key) if !key.is_empty() => Some(("Bearer".to_owned(), key)),
        _ => None,
    }
}

/// `/^(Bearer|DPoP)\s+(\S+)$/i`.
fn bearer_or_dpop(value: &str) -> Option<(String, String)> {
    let scheme_length = ["bearer", "dpop"].into_iter().find_map(|scheme| {
        value
            .get(..scheme.len())
            .filter(|prefix| prefix.eq_ignore_ascii_case(scheme))
            .map(|_| scheme.len())
    })?;
    let (scheme, rest) = value.split_at(scheme_length);
    let token = rest.trim_start_matches(js::is_js_whitespace);
    if token.len() == rest.len() || token.is_empty() || token.chars().any(js::is_js_whitespace) {
        return None;
    }
    Some((scheme.to_owned(), token.to_owned()))
}

/// The skill ids a request names: in the message's metadata and in the request's (`namedSkills`).
fn named_skills(params: &Map<String, Value>) -> Vec<Value> {
    let message = plain(params.get("message"));
    let mut names = Vec::new();
    if let Some(metadata) = message.and_then(|message| plain(message.get("metadata")))
        && let Some(skill) = metadata.get("skillId")
    {
        names.push(skill.clone());
    }
    if let Some(metadata) = plain(params.get("metadata"))
        && let Some(skill) = metadata.get("skillId")
    {
        names.push(skill.clone());
    }
    names
}

fn default_skill_of(params: &Map<String, Value>) -> Option<String> {
    match named_skills(params).first() {
        Some(Value::String(skill)) => Some(skill.clone()),
        _ => None,
    }
}

/// The A2A message metadata key that carries a Better IAM hand-off (`delegations.handoff`) from the calling agent to
/// the agent it calls, so the called agent can act for the same person with `delegations.assume`
/// (`handoffMetadataKey`).
pub const HANDOFF_METADATA_KEY: &str = "better-iam/handoff";

/// The members object spread syntax copies from a value (`{ ...value }`).
fn spread(value: Option<&Value>) -> Map<String, Value> {
    match value {
        Some(Value::Object(map)) => map.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(index, item)| (index.to_string(), item.clone()))
            .collect(),
        Some(Value::String(text)) => text
            .encode_utf16()
            .enumerate()
            .map(|(index, unit)| {
                (
                    index.to_string(),
                    Value::String(String::from_utf16_lossy(&[unit])),
                )
            })
            .collect(),
        _ => Map::new(),
    }
}

/// Adds a hand-off to an A2A message's metadata (the calling side) (`withHandoff`).
pub fn with_handoff(message: &Map<String, Value>, delegation_id: &str) -> Map<String, Value> {
    let mut out = message.clone();
    let existing = match message.get("metadata") {
        None | Some(Value::Null) => None,
        other => other,
    };
    let mut metadata = spread(existing);
    metadata.insert(
        HANDOFF_METADATA_KEY.to_owned(),
        Value::String(delegation_id.to_owned()),
    );
    out.insert("metadata".to_owned(), Value::Object(metadata));
    out
}

/// The hand-off an A2A request carries (the called side): the delegation id in the message's metadata, else in the
/// request's. Open a session for it with the called agent's own key (`delegations.assume`), which refuses hand-offs
/// that are not this agent's (`handoffOf`).
pub fn handoff_of(params: &Map<String, Value>) -> Option<String> {
    let message = plain(params.get("message"));
    let from_message = message
        .and_then(|message| plain(message.get("metadata")))
        .and_then(|metadata| metadata.get(HANDOFF_METADATA_KEY))
        .filter(|value| !value.is_null());
    let value = from_message.or_else(|| {
        plain(params.get("metadata"))
            .and_then(|metadata| metadata.get(HANDOFF_METADATA_KEY))
            .filter(|value| !value.is_null())
    });
    match value {
        Some(Value::String(id)) if !id.is_empty() => Some(id.clone()),
        _ => None,
    }
}

/// The owner key of a caller: the same person through the same agent (or none), or the same OAuth client and
/// subject (`taskOwnerOf`).
pub fn task_owner_of(caller: &A2aCaller) -> String {
    match caller {
        A2aCaller::Iam(caller) => format!(
            "iam:{}:{}:{}",
            caller.tenant_id,
            caller.identity_id,
            caller.agent_id.as_deref().unwrap_or("")
        ),
        A2aCaller::OAuth(caller) => format!(
            "oauth:{}:{}",
            caller.client_id,
            caller.subject.as_deref().unwrap_or("")
        ),
    }
}

/// A skill's `id` as a lookup key: `String(id)`, or None when the skill has no id.
fn skill_key(id: Option<&Value>) -> Option<String> {
    match id {
        None => None,
        Some(Value::String(id)) => Some(id.clone()),
        Some(other) => Some(better_iam_auth::util::js_string(other)),
    }
}

/// The request URL (`request.url`): its absolute target, or its path on `http://{Host}`.
fn request_url(parts: &http::request::Parts) -> String {
    if parts.uri.scheme().is_some() {
        return parts.uri.to_string();
    }
    let host = header(&parts.headers, "host").unwrap_or_else(|| "localhost".to_owned());
    let target = parts.uri.path_and_query().map_or("/", |path| path.as_str());
    format!("http://{host}{target}")
}

/// The request's method as `Request#method` reports it (standard methods upper-cased).
fn method_of(method: &http::Method) -> String {
    let text = method.as_str();
    for standard in ["DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT"] {
        if text.eq_ignore_ascii_case(standard) {
            return standard.to_owned();
        }
    }
    text.to_owned()
}

/// The request's headers as a credential carries them.
fn credential_headers(headers: &http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// Decisions shared by the gate and by handlers written with an A2A SDK ([`create_a2a_authorizer`]).
#[derive(Clone)]
pub struct A2aAuthorizer {
    options: Arc<A2aGateOptions>,
}

/// `createA2aAuthorizer(options)`.
pub fn create_a2a_authorizer(options: A2aGateOptions) -> A2aAuthorizer {
    A2aAuthorizer {
        options: Arc::new(options),
    }
}

impl A2aAuthorizer {
    /// The rule for a skill (or for messages naming none), and the skill its default resource is named after.
    fn rule_for(&self, skill: Option<&str>) -> Option<Found> {
        if let (Some(skill), Some(skills)) = (skill, &self.options.skills)
            && let Some(rule) = skills.get(skill)
        {
            return Some(Found {
                rule: rule.clone(),
                named: Some(skill.to_owned()),
            });
        }
        if skill.is_none() || self.options.unlisted_skills == UnlistedSkills::Message {
            return Some(Found {
                rule: self.options.message.clone(),
                named: None,
            });
        }
        None
    }

    fn resource_of(found: &Found, params: &Map<String, Value>) -> Result<A2aResourceRef, A2aError> {
        match &found.rule.resource {
            Some(RuleResource::Of(resource)) => resource(params),
            Some(RuleResource::Fixed(resource)) => Ok(resource.clone()),
            None => Ok(match &found.named {
                Some(named) => A2aResourceRef::new("a2a-skill", named.clone()),
                None => A2aResourceRef::new("a2a-agent", "agent"),
            }),
        }
    }

    async fn request_confirmation(
        &self,
        caller: &A2aCaller,
        skill: Option<&str>,
        action: &str,
        resource: &A2aResourceRef,
        params: &Map<String, Value>,
    ) -> Option<A2aConfirmation> {
        let delegations = self.options.iam.delegations()?;
        let A2aCaller::Iam(caller) = caller else {
            return None;
        };
        if self.options.confirmations == Some(false) || caller.session_kind != "delegated" {
            return None;
        }
        let delegation_id = caller
            .delegation_id
            .as_deref()
            .filter(|id| !id.is_empty())?;
        let delegation = delegations
            .get(&caller.credential, &caller.tenant_id, delegation_id)
            .await
            .ok()?;
        let confirmed = delegation.confirm.as_ref().is_some_and(|confirm| {
            confirm
                .iter()
                .any(|pattern| match_pattern(pattern, action, None))
        });
        if !confirmed {
            return None;
        }
        let reason = match &self.options.confirmation_reason {
            Some(reason) => reason(skill, params),
            None => match skill.filter(|skill| !skill.is_empty()) {
                Some(skill) => format!(
                    "Your agent wants to use the skill {skill} of another agent ({action})."
                ),
                None => format!("Your agent wants to send a message to another agent ({action})."),
            },
        };
        let request = delegations
            .request_confirmation(
                &caller.credential,
                &caller.tenant_id,
                action,
                resource,
                &reason,
            )
            .await
            .ok()?;
        Some(A2aConfirmation {
            id: request.id,
            expires_at: request.expires_at,
        })
    }

    async fn decide(
        &self,
        caller: &A2aCaller,
        found: Option<Found>,
        skill: Option<&str>,
        params: &Map<String, Value>,
        confirm: bool,
    ) -> Result<A2aDecision, A2aError> {
        let Some(found) = found else {
            return Ok(A2aDecision::of(false, "UNKNOWN_SKILL"));
        };
        let rule = &found.rule;
        if rule.public {
            return Ok(A2aDecision::of(true, "PUBLIC"));
        }
        let iam_caller = match caller {
            A2aCaller::OAuth(oauth) => {
                let Some(scopes) = rule.scopes.as_ref().filter(|scopes| !scopes.is_empty()) else {
                    return Ok(A2aDecision::of(false, "NO_RULE_FOR_CALLER"));
                };
                return Ok(if scopes.iter().all(|scope| oauth.scopes.contains(scope)) {
                    A2aDecision::of(true, "ALLOWED")
                } else {
                    A2aDecision::of(false, "INSUFFICIENT_SCOPE")
                });
            }
            A2aCaller::Iam(iam) => iam,
        };
        let Some(action) = rule.action.as_deref().filter(|action| !action.is_empty()) else {
            return Ok(A2aDecision::of(false, "NO_RULE_FOR_CALLER"));
        };
        let Ok(resource) = Self::resource_of(&found, params) else {
            return Ok(A2aDecision::of(false, "ACCESS_DENIED"));
        };
        let decision = self
            .options
            .iam
            .authorize(
                &iam_caller.credential,
                &iam_caller.tenant_id,
                action,
                &resource,
            )
            .await?;
        if decision.allowed {
            return Ok(A2aDecision::of(true, "ALLOWED"));
        }
        let confirmation = if confirm {
            self.request_confirmation(caller, skill, action, &resource, params)
                .await
        } else {
            None
        };
        Ok(match confirmation {
            Some(confirmation) => A2aDecision {
                allowed: false,
                reason: "CONFIRMATION_REQUESTED".to_owned(),
                confirmation: Some(confirmation),
            },
            None => A2aDecision::of(false, "ACCESS_DENIED"),
        })
    }

    /// A Better IAM credential first, then (with `oauth`) an OAuth access token; None when neither is valid.
    pub async fn authenticate(&self, request: &http::request::Parts) -> Option<A2aCaller> {
        let (scheme, token) = presented(&request.headers)?;
        let options = &self.options;
        if scheme.eq_ignore_ascii_case("bearer") {
            let credential = CredentialInput {
                headers: Some(credential_headers(&request.headers)),
                token: Some(token),
            };
            match options.iam.authenticate(&credential).await {
                Ok(principal) => {
                    let tenant_id = match &options.tenant_id {
                        A2aTenant::Fixed(tenant_id) => Some(tenant_id.clone()),
                        A2aTenant::Choose(choose) => {
                            choose(&principal.identity.id, &principal.session.tenant_id)
                        }
                    };
                    let tenant_id = tenant_id.filter(|tenant_id| !tenant_id.is_empty())?;
                    let agent_id = if principal.session.kind == "delegated" {
                        principal.session.agent_id.clone()
                    } else if principal.identity.kind == "agent" {
                        Some(principal.identity.id.clone())
                    } else {
                        None
                    };
                    return Some(A2aCaller::Iam(A2aIamCaller {
                        credential,
                        tenant_id,
                        identity_id: principal.identity.id,
                        identity_kind: principal.identity.kind,
                        session_kind: principal.session.kind,
                        agent_id: agent_id.filter(|id| !id.is_empty()),
                        delegation_id: principal.session.delegation_id.filter(|id| !id.is_empty()),
                    }));
                }
                Err(_) => {
                    options.oauth.as_ref()?;
                }
            }
        }
        let oauth = options.oauth.as_ref()?;
        let token = oauth
            .verify_request(
                &A2aOAuthRequest {
                    authorization: header(&request.headers, "authorization"),
                    dpop: header(&request.headers, "dpop"),
                    method: method_of(&request.method),
                    url: request_url(request),
                },
                None,
            )
            .await
            .ok()?;
        // A token issued for another organization is not a token for this agent.
        if let (A2aTenant::Fixed(fixed), Some(tenant_id)) = (&options.tenant_id, &token.tenant_id)
            && tenant_id != fixed
        {
            return None;
        }
        Some(A2aCaller::OAuth(A2aOAuthCaller {
            subject: token.subject.filter(|subject| !subject.is_empty()),
            client_id: token.client_id,
            tenant_id: token.tenant_id.filter(|tenant_id| !tenant_id.is_empty()),
            scopes: token.scopes,
        }))
    }

    /// The skill a `message/send` or `message/stream` request names, if any.
    pub fn skill_of(&self, params: &Map<String, Value>) -> Option<String> {
        match &self.options.skill_of {
            Some(skill_of) => skill_of(params),
            None => default_skill_of(params),
        }
    }

    /// Whether the caller may send a message with these params (asking for a confirmation when that applies). A
    /// request naming two different skills (in the message's and the request's metadata) is refused as
    /// `AMBIGUOUS_SKILL`, so the gate and the server cannot disagree on which skill runs.
    pub async fn can_send(
        &self,
        caller: &A2aCaller,
        params: &Map<String, Value>,
    ) -> Result<A2aDecision, A2aError> {
        // A skill id that is not a string (an array, a number) would pass as "no skill" (the message rule) while the
        // server may still coerce it to a skill name: refuse it like two different skills.
        if self.options.skill_of.is_none() {
            let names = named_skills(params);
            let distinct = match names.as_slice() {
                [first, second] => !js::strict_equal(first, second),
                _ => false,
            };
            if distinct || names.iter().any(|name| !name.is_string()) {
                return Ok(A2aDecision::of(false, "AMBIGUOUS_SKILL"));
            }
        }
        let skill = self.skill_of(params);
        let found = self.rule_for(skill.as_deref());
        self.decide(caller, found, skill.as_deref(), params, true)
            .await
    }

    /// Whether the caller may read and cancel every task (`taskAdminAction`).
    pub async fn is_task_admin(&self, caller: &A2aCaller) -> Result<bool, A2aError> {
        let Some(action) = self
            .options
            .task_admin_action
            .as_deref()
            .filter(|action| !action.is_empty())
        else {
            return Ok(false);
        };
        if !matches!(caller, A2aCaller::Iam(_)) {
            return Ok(false);
        }
        let rule = A2aRule {
            action: Some(action.to_owned()),
            public: false,
            ..self.options.message.clone()
        };
        let decision = self
            .decide(
                caller,
                Some(Found { rule, named: None }),
                None,
                &Map::new(),
                false,
            )
            .await?;
        Ok(decision.allowed)
    }

    /// The skills the caller may use, in order (checked 50 at a time). A skill is an object with an `id`; an entry
    /// that is `null` fails as reading its `id` throws.
    pub async fn visible_skills(
        &self,
        caller: &A2aCaller,
        skills: &[Value],
    ) -> Result<Vec<Value>, A2aError> {
        let mut visible: Vec<Option<Value>> = Vec::new();
        let mut checks: Vec<(Option<Value>, A2aCheck)> = Vec::new();
        let id_of = |skill: &Value| -> Result<Option<Value>, A2aError> {
            match skill {
                Value::Null => Err(A2aError::type_error(
                    "Cannot read properties of null (reading 'id')",
                )),
                Value::Object(map) => Ok(map.get("id").cloned()),
                _ => Ok(None),
            }
        };
        for skill in skills {
            let id = id_of(skill)?;
            let key = skill_key(id.as_ref());
            let Some(found) = self.rule_for(key.as_deref()) else {
                continue;
            };
            let rule = &found.rule;
            if rule.public {
                visible.push(id);
            } else if let A2aCaller::OAuth(oauth) = caller {
                if rule.scopes.as_ref().is_some_and(|scopes| {
                    !scopes.is_empty() && scopes.iter().all(|scope| oauth.scopes.contains(scope))
                }) {
                    visible.push(id);
                }
            } else if let Some(action) = rule.action.as_deref().filter(|action| !action.is_empty())
            {
                if matches!(rule.resource, Some(RuleResource::Of(_))) {
                    visible.push(id);
                } else {
                    let resource = Self::resource_of(&found, &Map::new())?;
                    checks.push((
                        id,
                        A2aCheck {
                            action: action.to_owned(),
                            resource,
                        },
                    ));
                }
            }
        }
        if let A2aCaller::Iam(iam) = caller {
            for batch in checks.chunks(50) {
                let requests: Vec<A2aCheck> =
                    batch.iter().map(|(_, check)| check.clone()).collect();
                let results = self
                    .options
                    .iam
                    .authorize_many(&iam.credential, &iam.tenant_id, &requests)
                    .await?;
                for (position, (id, _)) in batch.iter().enumerate() {
                    if results.get(position).is_some_and(|result| result.allowed) {
                        visible.push(id.clone());
                    }
                }
            }
        }
        let has = |id: Option<&Value>| {
            visible.iter().any(|seen| match (seen, id) {
                (None, None) => true,
                (Some(seen), Some(id)) => same_value_zero(seen, id),
                _ => false,
            })
        };
        let mut out = Vec::new();
        for skill in skills {
            if has(id_of(skill)?.as_ref()) {
                out.push(skill.clone());
            }
        }
        Ok(out)
    }
}

/// `SameValueZero` for set membership: primitives by value, objects and arrays never equal to another parse.
fn same_value_zero(left: &Value, right: &Value) -> bool {
    js::strict_equal(left, right)
}

/// A JSON-RPC error response (`rpcError`).
fn rpc_error(
    id: &Value,
    code: i64,
    message: &str,
    data: Option<Value>,
    status: u16,
) -> http::Response<Body> {
    let mut error = Map::new();
    error.insert("code".into(), Value::from(code));
    error.insert("message".into(), Value::String(message.to_owned()));
    if let Some(data) = data {
        error.insert("data".into(), data);
    }
    json_response(
        &json!({ "jsonrpc": "2.0", "id": id, "error": Value::Object(error) }),
        status,
        &[],
    )
}

/// The owner keys a JSON-RPC result names: its task (a task's `id`, or the `taskId` of a message or task event) and
/// its conversation (`contextId`) (`ownedKeysOf`).
fn owned_keys_of(result: Option<&Value>) -> Vec<String> {
    let Some(result) = plain(result) else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    let task_id = if result.get("kind").and_then(Value::as_str) == Some("task") {
        result.get("id")
    } else {
        result.get("taskId")
    };
    if let Some(Value::String(task_id)) = task_id
        && !task_id.is_empty()
    {
        keys.push(format!("task:{task_id}"));
    }
    if let Some(Value::String(context_id)) = result.get("contextId")
        && !context_id.is_empty()
    {
        keys.push(format!("context:{context_id}"));
    }
    keys
}

static EVENT_BOUNDARY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\r?\n\r?\n").expect("valid pattern"));
static LINE_BREAK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\r?\n").expect("valid pattern"));

/// The gate ([`create_a2a_gate`]): [`A2aGate::handle`] answers the request itself (the agent card, challenges,
/// refusals) or passes it to `next` (the A2A server's handler) with the authenticated caller, recording who started
/// each task on the way back.
#[derive(Clone)]
pub struct A2aGate {
    authorizer: A2aAuthorizer,
    owners: Arc<dyn A2aTaskOwners>,
    max_body_bytes: usize,
}

/// `createA2aGate(options)`.
pub fn create_a2a_gate(options: A2aGateOptions) -> A2aGate {
    let owners = options
        .tasks
        .clone()
        .unwrap_or_else(|| Arc::new(memory_task_owners(MemoryTaskOwnersOptions::default())));
    let max_body_bytes = options.max_body_bytes.unwrap_or(4 * 1024 * 1024);
    A2aGate {
        authorizer: create_a2a_authorizer(options),
        owners,
        max_body_bytes,
    }
}

fn challenge(error: Option<&str>) -> http::Response<Body> {
    let www_authenticate = match error {
        Some(error) => format!("Bearer error=\"{error}\""),
        None => "Bearer".to_owned(),
    };
    json_response(
        &json!({
            "error": error.unwrap_or("unauthorized"),
            "error_description": "Present a Better IAM credential or an OAuth access token",
        }),
        401,
        &[
            ("cache-control", "no-store"),
            ("www-authenticate", &www_authenticate),
        ],
    )
}

/// Records the owner of every task and conversation a result names; failures of the store are ignored, as the
/// TypeScript gate's `try { ... } catch {}` does.
async fn remember(owners: &Arc<dyn A2aTaskOwners>, result: Option<&Value>, owner: &str) {
    let _ = async {
        for key in owned_keys_of(result) {
            if owners.get(&key).await?.is_none() {
                owners.set(&key, owner).await?;
            }
        }
        Ok::<(), A2aError>(())
    }
    .await;
}

/// The `result` of a parsed JSON-RPC message (`message.result`), or None when reading it would throw.
fn result_of(message: &Value) -> Option<Option<&Value>> {
    match message {
        Value::Null => None,
        Value::Object(map) => Some(map.get("result")),
        _ => Some(None),
    }
}

/// One event of an event stream: its `data:` lines, joined (`inspect`).
async fn inspect(owners: &Arc<dyn A2aTaskOwners>, event: &str, owner: &str) {
    let data: Vec<&str> = LINE_BREAK
        .split(event)
        .filter(|line| line.starts_with("data:"))
        .map(|line| {
            let rest = &line[5..];
            rest.strip_prefix(' ').unwrap_or(rest)
        })
        .collect();
    let data = data.join("\n");
    if data.is_empty() {
        return;
    }
    if let Ok(message) = js::parse(&data)
        && let Some(result) = result_of(&message)
    {
        remember(owners, result, owner).await;
    }
}

/// What the gate does with a JSON-RPC request it checked.
enum Step {
    /// Answers it itself.
    Answer(http::Response<Body>),
    /// Passes it to the server and handles the response so.
    Forward(After),
    /// Not a method the gate decides (`otherMethods`).
    Unhandled,
}

/// What happens to the server's response.
enum After {
    /// Recording the tasks and conversations it names.
    Observe,
    /// Nothing.
    Pass,
    /// Filtering the skills of an extended card.
    FilterSkills,
}

struct EventStreamState {
    body: Body,
    decoder: Utf8Stream,
    buffer: String,
    owners: Arc<dyn A2aTaskOwners>,
    owner: String,
    done: bool,
}

impl A2aGate {
    /// The decisions this gate makes.
    pub fn authorizer(&self) -> &A2aAuthorizer {
        &self.authorizer
    }

    fn options(&self) -> &A2aGateOptions {
        &self.authorizer.options
    }

    /// Records the owner of every task and conversation a response names, in a JSON body or an event stream, without
    /// changing it (`observe`).
    async fn observe(
        &self,
        response: http::Response<Body>,
        owner: String,
    ) -> Result<http::Response<Body>, A2aError> {
        let content_type = header(response.headers(), "content-type").unwrap_or_default();
        if content_type.contains("application/json") {
            let (parts, body) = response.into_parts();
            let text = decode_utf8(&read_all(body).await?);
            if let Ok(message) = js::parse(&text)
                && let Some(result) = result_of(&message)
            {
                remember(&self.owners, result, &owner).await;
            }
            // Passed on as the text the gate read (`new Response(text, ...)`).
            let mut rebuilt = http::Response::new(transport::full(Bytes::from(text)));
            *rebuilt.status_mut() = parts.status;
            *rebuilt.headers_mut() = parts.headers;
            return Ok(rebuilt);
        }
        if !content_type.contains("text/event-stream") {
            return Ok(response);
        }
        let (parts, body) = response.into_parts();
        let state = EventStreamState {
            body,
            decoder: Utf8Stream::default(),
            buffer: String::new(),
            owners: self.owners.clone(),
            owner,
            done: false,
        };
        let stream = futures::stream::unfold(state, |mut state| async move {
            if state.done {
                return None;
            }
            match state.body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        let text = state.decoder.decode(data);
                        state.buffer.push_str(&text);
                        while let Some(boundary) = EVENT_BOUNDARY.find(&state.buffer) {
                            let event = state.buffer[..boundary.start()].to_owned();
                            state.buffer.drain(..boundary.end());
                            // Recorded before the event reaches the caller, so a follow-up request can already use
                            // the task.
                            inspect(&state.owners, &event, &state.owner).await;
                        }
                    }
                    Some((Ok::<Frame<Bytes>, BodyError>(frame), state))
                }
                Some(Err(error)) => {
                    state.done = true;
                    Some((Err(error), state))
                }
                None => {
                    let rest = state.decoder.finish();
                    state.buffer.push_str(&rest);
                    if !js::trim(&state.buffer).is_empty() {
                        let event = std::mem::take(&mut state.buffer);
                        inspect(&state.owners, &event, &state.owner).await;
                    }
                    None
                }
            }
        });
        let mut rebuilt = http::Response::new(StreamBody::new(stream).boxed_unsync());
        *rebuilt.status_mut() = parts.status;
        *rebuilt.headers_mut() = parts.headers;
        Ok(rebuilt)
    }

    /// Whether the caller started the task (or is a task administrator); unknown tasks belong to no one.
    async fn owns_task(
        &self,
        caller: &A2aCaller,
        task_id: Option<&Value>,
    ) -> Result<bool, A2aError> {
        let Some(Value::String(task_id)) = task_id else {
            return Ok(false);
        };
        if task_id.is_empty() {
            return Ok(false);
        }
        if self.owners.get(&format!("task:{task_id}")).await? == Some(task_owner_of(caller)) {
            return Ok(true);
        }
        self.authorizer.is_task_admin(caller).await
    }

    /// Whether the caller may add to a conversation: one they started, or as a task administrator. Conversations
    /// are started by the server (its answers name them), so an unknown one belongs to no one.
    async fn may_join(
        &self,
        caller: &A2aCaller,
        context_id: Option<&Value>,
    ) -> Result<bool, A2aError> {
        let Some(Value::String(context_id)) = context_id else {
            return Ok(false);
        };
        if context_id.is_empty() {
            return Ok(false);
        }
        if self.owners.get(&format!("context:{context_id}")).await? == Some(task_owner_of(caller)) {
            return Ok(true);
        }
        self.authorizer.is_task_admin(caller).await
    }

    fn failed(&self, id: &Value, error: &A2aError) -> http::Response<Body> {
        if let Some(on_error) = &self.options().on_error {
            on_error(error);
        }
        rpc_error(id, -32603, "Internal error", None, 500)
    }

    /// The answer to an error inside the guarded part of the gate (its `catch`): a challenge for an unauthenticated
    /// credential, otherwise `-32603` (HTTP 500).
    fn caught(&self, id: &Value, error: &A2aError) -> http::Response<Body> {
        if let Some(iam) = error.iam()
            && (iam.status == 401 || iam.code == "UNAUTHENTICATED")
        {
            return challenge(Some("invalid_token"));
        }
        self.failed(id, error)
    }

    /// The checks of a JSON-RPC request before it reaches the server: an answer, or what to do with the server's
    /// response.
    async fn guard(
        &self,
        caller: &A2aCaller,
        method: &str,
        params: &Map<String, Value>,
        id: &Value,
    ) -> Result<Step, A2aError> {
        if MESSAGE_METHODS.contains(&method) {
            let sent = plain(params.get("message")).cloned().unwrap_or_default();
            // Continuing a task or a conversation, or pointing at earlier tasks: only whoever started them may.
            if let Some(task_id) = sent.get("taskId")
                && !self.owns_task(caller, Some(task_id)).await?
            {
                return Ok(Step::Answer(rpc_error(
                    id,
                    -32001,
                    "Task not found",
                    None,
                    200,
                )));
            }
            if let Some(context_id) = sent.get("contextId")
                && !self.may_join(caller, Some(context_id)).await?
            {
                return Ok(Step::Answer(rpc_error(
                    id,
                    -32602,
                    "Invalid params: unknown context",
                    None,
                    200,
                )));
            }
            if let Some(references) = sent.get("referenceTaskIds") {
                let Some(references) = references.as_array().filter(|items| items.len() <= 100)
                else {
                    return Ok(Step::Answer(rpc_error(
                        id,
                        -32602,
                        "Invalid params: referenceTaskIds",
                        None,
                        200,
                    )));
                };
                for reference in references {
                    if !self.owns_task(caller, Some(reference)).await? {
                        return Ok(Step::Answer(rpc_error(
                            id,
                            -32001,
                            "Task not found",
                            None,
                            200,
                        )));
                    }
                }
            }
            let decision = self.authorizer.can_send(caller, params).await?;
            if !decision.allowed {
                return Ok(Step::Answer(match &decision.confirmation {
                    Some(confirmation) => rpc_error(
                        id,
                        A2A_CONFIRMATION_REQUESTED,
                        "The person you act for must confirm this request first. Retry after they approve it.",
                        Some(json!({
                            "reason": decision.reason,
                            "confirmationId": confirmation.id,
                            "expiresAt": js::number(confirmation.expires_at).unwrap_or(Value::Null),
                        })),
                        403,
                    ),
                    None => rpc_error(
                        id,
                        A2A_ACCESS_DENIED,
                        match decision.reason.as_str() {
                            "UNKNOWN_SKILL" => "Unknown skill",
                            "AMBIGUOUS_SKILL" => "The request names two different skills",
                            _ => "Access denied",
                        },
                        Some(json!({ "reason": decision.reason })),
                        403,
                    ),
                }));
            }
            return Ok(Step::Forward(After::Observe));
        }
        if TASK_METHODS.contains(&method) {
            let task_id = if method == "tasks/pushNotificationConfig/set" {
                params.get("taskId")
            } else {
                params.get("id")
            };
            if !self.owns_task(caller, task_id).await? {
                return Ok(Step::Answer(rpc_error(
                    id,
                    -32001,
                    "Task not found",
                    None,
                    200,
                )));
            }
            return Ok(Step::Forward(After::Pass));
        }
        if method == EXTENDED_CARD_METHOD {
            let Some(extended) = &self.options().extended_card else {
                return Ok(Step::Forward(After::FilterSkills));
            };
            let card = extended.card().await?;
            let skills = skills_of(&card)?;
            let visible = self.authorizer.visible_skills(caller, &skills).await?;
            let mut result = card;
            result.insert("skills".into(), Value::Array(visible));
            return Ok(Step::Answer(json_response(
                &json!({ "jsonrpc": "2.0", "id": id, "result": Value::Object(result) }),
                200,
                &[],
            )));
        }
        Ok(Step::Unhandled)
    }

    /// The server's answer to `agent/getAuthenticatedExtendedCard` with only the skills the caller may use.
    async fn filter_skills(
        &self,
        caller: &A2aCaller,
        response: http::Response<Body>,
    ) -> Result<http::Response<Body>, A2aError> {
        let content_type = header(response.headers(), "content-type").unwrap_or_default();
        if !content_type.contains("application/json") {
            return Ok(response);
        }
        let status = response.status().as_u16();
        let bytes = read_all(response.into_body()).await?;
        let mut body = js::parse(&decode_utf8(&bytes))
            .map_err(|error| A2aError::message(error.to_string()))?;
        let found = match &body {
            Value::Null => {
                return Err(A2aError::type_error(
                    "Cannot read properties of null (reading 'result')",
                ));
            }
            Value::Object(map) => match map.get("result") {
                Some(Value::Object(result)) => match result.get("skills") {
                    Some(Value::Array(skills)) => Some((result.clone(), skills.clone())),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        };
        if let Some((mut result, skills)) = found {
            let visible = self.authorizer.visible_skills(caller, &skills).await?;
            result.insert("skills".into(), Value::Array(visible));
            if let Value::Object(map) = &mut body {
                map.insert("result".into(), Value::Object(result));
            }
        }
        Ok(json_response(&body, status, &[]))
    }

    /// `gate(request, next)`: answers the request itself or passes it on to `next` with the caller. Errors of `next`
    /// on the paths the gate does not guard (other HTTP methods and other JSON-RPC methods passed on) and of reading
    /// the request body are returned as they are.
    pub async fn handle<N, F>(
        &self,
        request: http::Request<Body>,
        next: N,
    ) -> Result<http::Response<Body>, A2aError>
    where
        N: FnOnce(http::Request<Body>, A2aCaller) -> F,
        F: Future<Output = Result<http::Response<Body>, A2aError>>,
    {
        let options = self.options();
        let (parts, body) = request.into_parts();
        let method = method_of(&parts.method);
        let path = parts.uri.path().to_owned();
        if let Some(card) = &options.card
            && (path == "/.well-known/agent-card.json" || path == "/.well-known/agent.json")
        {
            if method == "OPTIONS" {
                return Ok(http::Response::builder()
                    .status(204)
                    .header("access-control-allow-origin", "*")
                    .header("access-control-allow-methods", "GET, OPTIONS")
                    .body(transport::empty())
                    .expect("valid response"));
            }
            if method != "GET" && method != "HEAD" {
                return Ok(json_response(
                    &json!({ "error": "method not allowed" }),
                    405,
                    &[("allow", "GET, OPTIONS")],
                ));
            }
            return Ok(match card.card().await {
                Ok(card) => json_response(
                    &Value::Object(card),
                    200,
                    &[
                        ("access-control-allow-origin", "*"),
                        ("cache-control", "public, max-age=300"),
                    ],
                ),
                Err(error) => {
                    if let Some(on_error) = &options.on_error {
                        on_error(&error);
                    }
                    json_response(
                        &json!({ "error": "agent card unavailable" }),
                        503,
                        &[("retry-after", "30")],
                    )
                }
            });
        }
        if presented(&parts.headers).is_none() {
            return Ok(challenge(None));
        }
        let Some(caller) = self.authorizer.authenticate(&parts).await else {
            return Ok(challenge(Some("invalid_token")));
        };
        if method != "POST" {
            return match options.other_http_methods {
                Passthrough::Allow => next(http::Request::from_parts(parts, body), caller).await,
                Passthrough::Deny => Ok(json_response(
                    &json!({ "error": "method not allowed" }),
                    405,
                    &[("allow", "POST")],
                )),
            };
        }
        let Some(text) = bounded_body(&parts.headers, body, self.max_body_bytes).await? else {
            return Ok(json_response(
                &json!({ "error": "request too large" }),
                413,
                &[],
            ));
        };
        let Ok(parsed) = js::parse(&text) else {
            return Ok(rpc_error(&Value::Null, -32700, "Parse error", None, 200));
        };
        let message_method = match &parsed {
            Value::Object(map) => map.get("method").and_then(Value::as_str).map(str::to_owned),
            _ => None,
        };
        let Some(message_method) = message_method else {
            return Ok(rpc_error(
                &Value::Null,
                -32600,
                "Invalid Request: A2A takes one JSON-RPC request per call",
                None,
                200,
            ));
        };
        let message = parsed.as_object().expect("checked above");
        let id = match message.get("id") {
            None => Value::Null,
            Some(id) => id.clone(),
        };
        let params = plain(message.get("params")).cloned().unwrap_or_default();
        let owner = task_owner_of(&caller);
        // The server receives the request exactly as the gate read it (no duplicate keys a different parser could
        // pick).
        let mut forward_parts = parts;
        forward_parts.headers.remove(http::header::CONTENT_LENGTH);
        if !forward_parts
            .headers
            .contains_key(http::header::CONTENT_TYPE)
        {
            forward_parts.headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/plain;charset=UTF-8"),
            );
        }
        forward_parts.method = http::Method::POST;
        let forward =
            http::Request::from_parts(forward_parts, transport::full(js::stringify(&parsed)));
        let step = match self.guard(&caller, &message_method, &params, &id).await {
            Ok(step) => step,
            Err(error) => return Ok(self.caught(&id, &error)),
        };
        match step {
            Step::Answer(response) => Ok(response),
            Step::Unhandled => match options.other_methods {
                Passthrough::Allow => next(forward, caller).await,
                Passthrough::Deny => Ok(rpc_error(&id, -32601, "Method not found", None, 200)),
            },
            Step::Forward(after) => {
                let outcome = async {
                    let response = next(forward, caller.clone()).await?;
                    match after {
                        After::Observe => self.observe(response, owner).await,
                        After::Pass => Ok(response),
                        After::FilterSkills => self.filter_skills(&caller, response).await,
                    }
                }
                .await;
                Ok(outcome.unwrap_or_else(|error| self.caught(&id, &error)))
            }
        }
    }
}

/// The skills of a card (`card?.skills ?? []`); a value that is not an array cannot be iterated.
fn skills_of(card: &AgentCard) -> Result<Vec<Value>, A2aError> {
    match card.get("skills") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(skills)) => Ok(skills.clone()),
        Some(_) => Err(A2aError::type_error("card.skills is not iterable")),
    }
}

/// `boundedBody(request, maxBytes)`: the request body as text, or None when it is larger than `max_bytes` (read no
/// further than that).
async fn bounded_body(
    headers: &http::HeaderMap,
    body: Body,
    max_bytes: usize,
) -> Result<Option<String>, A2aError> {
    let declared =
        header(headers, "content-length").map_or(0.0, |value| js::string_to_number(&value));
    if declared > max_bytes as f64 {
        return Ok(None);
    }
    Ok(read_bounded(body, max_bytes)
        .await?
        .map(|bytes| decode_utf8(&bytes)))
}
