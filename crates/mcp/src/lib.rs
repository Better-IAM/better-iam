//! Tool-level authorization for Model Context Protocol servers: the Rust port of `@better-iam/mcp`.
//!
//! [`McpGate`] sits in front of any Streamable HTTP MCP endpoint (a request → response handler): it authenticates the
//! caller, answers unauthenticated requests with a `WWW-Authenticate` challenge that points at the endpoint's
//! protected resource metadata (RFC 9728, served by the gate), refuses `tools/call` requests the caller may not make,
//! and removes the tools the caller may not use from `tools/list` answers, in JSON and in event streams.
//!
//! Callers present either a Better IAM credential (a person's session, a service account or AI agent key, or a
//! delegated agent session acting for a person), decided by the Better IAM policy engine as `action` on `resource`,
//! or an OAuth access token from the Better IAM authorization server (verified by an [`McpOAuthVerifier`]), decided
//! by its scopes. [`McpAuthorizer`] exposes the same decisions for tool handlers written with an MCP SDK.

mod better_iam;
mod stream;

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use better_iam_core::{CredentialInput, IamError, IamResult};
use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::request::Parts;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body::Body;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use url::Url;

pub use stream::Utf8Decoder;

/// Errors a body can fail with.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The body of the requests the gate forwards and of the responses it answers.
pub type GateBody = UnsyncBoxBody<Bytes, BoxError>;

/// A resource the policy engine decides on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpResourceRef {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

impl McpResourceRef {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
        }
    }
}

/// A resource derived from a call's arguments (the JSON-RPC `params.arguments`); an `Err` refuses the call.
pub type DeriveResource = Arc<dyn Fn(&Value) -> Result<McpResourceRef, String> + Send + Sync>;

/// The resource a tool call acts on.
#[derive(Clone)]
pub enum McpResource {
    /// A fixed reference.
    Fixed(McpResourceRef),
    /// One derived from the call's arguments.
    Derived(DeriveResource),
}

impl McpResource {
    /// A resource derived from the call's arguments.
    pub fn derived(
        derive: impl Fn(&Value) -> Result<McpResourceRef, String> + Send + Sync + 'static,
    ) -> Self {
        McpResource::Derived(Arc::new(derive))
    }
}

/// How one tool is authorized.
#[derive(Clone, Default)]
pub struct McpToolRule {
    /// The Better IAM action a call needs (Better IAM credentials).
    pub action: Option<String>,
    /// The resource the call acts on. Defaults to `{ type: toolResourceType, id: toolName }`. Tools with derived
    /// resources are listed for everyone the rule could allow (their `list_as` resource, when given, decides the
    /// listing).
    pub resource: Option<McpResource>,
    /// The resource that decides whether a tool with a derived `resource` appears in `tools/list`.
    pub list_as: Option<McpResourceRef>,
    /// Scopes an OAuth access token needs for the tool (OAuth callers).
    pub scopes: Option<Vec<String>>,
    /// Any authenticated caller may use the tool.
    pub public: bool,
}

/// The identity of an authenticated principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpIdentity {
    pub id: String,
    pub tenant_id: String,
    pub kind: String,
    pub name: Option<String>,
}

/// The session of an authenticated principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpSession {
    pub id: String,
    pub tenant_id: String,
    pub kind: String,
    pub agent_id: Option<String>,
    pub delegation_id: Option<String>,
}

/// What `authenticate` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpPrincipal {
    pub identity: McpIdentity,
    pub session: McpSession,
}

/// One check of `authorizeMany`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpCheck {
    pub action: String,
    pub resource: McpResourceRef,
}

/// One decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpCheckResult {
    pub allowed: bool,
    pub reason: String,
}

/// The part of a Better IAM instance (`betterIam()`) or client the gate needs (`McpIam`). A [`better_iam_server::BetterIam`]
/// (or anything that borrows one) implements it.
#[async_trait]
pub trait McpIam: Send + Sync {
    async fn authenticate(&self, credential: &CredentialInput) -> IamResult<McpPrincipal>;

    async fn authorize(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        action: &str,
        resource: &McpResourceRef,
    ) -> IamResult<McpCheckResult>;

    async fn authorize_many(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        checks: &[McpCheck],
    ) -> IamResult<Vec<McpCheckResult>>;

    /// Present on a `betterIam()` instance: lets the gate ask a person to confirm an agent's action.
    fn delegations(&self) -> Option<Arc<dyn McpDelegationsApi>> {
        None
    }
}

/// A delegation as the gate reads it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct McpDelegation {
    /// Action patterns the person confirms one call at a time.
    pub confirm: Option<Vec<String>>,
}

/// The input of `delegations.requestConfirmation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpConfirmationInput {
    pub tenant_id: String,
    pub action: String,
    pub resource: McpResourceRef,
    pub reason: String,
}

/// A confirmation request.
#[derive(Debug, Clone, PartialEq)]
pub struct McpConfirmationRequest {
    pub id: String,
    pub status: String,
    pub expires_at: f64,
}

/// The part of the `delegations` API the gate uses for per-action confirmations.
#[async_trait]
pub trait McpDelegationsApi: Send + Sync {
    async fn get(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        delegation_id: &str,
    ) -> IamResult<McpDelegation>;

    async fn request_confirmation(
        &self,
        credential: &CredentialInput,
        input: &McpConfirmationInput,
    ) -> IamResult<McpConfirmationRequest>;
}

/// The request an OAuth verifier checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpOAuthRequest {
    pub authorization: Option<String>,
    pub dpop: Option<String>,
    pub method: String,
    pub url: String,
}

/// Scopes a token must carry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct McpScopeRequirement {
    pub scopes: Option<Vec<String>>,
}

/// A verified access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpOAuthToken {
    pub subject: Option<String>,
    pub client_id: String,
    pub tenant_id: Option<String>,
    pub scopes: Vec<String>,
}

/// The access-token verifier of the Better IAM OAuth package (`createAccessTokenVerifier` or a resource guard's
/// `verifier`).
#[async_trait]
pub trait McpOAuthVerifier: Send + Sync {
    async fn verify_request(
        &self,
        request: &McpOAuthRequest,
        requirement: Option<&McpScopeRequirement>,
    ) -> IamResult<McpOAuthToken>;
}

/// A caller presenting a Better IAM credential.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpIamCaller {
    #[serde(skip)]
    pub credential: CredentialInput,
    /// The tenant decisions are made in.
    pub tenant_id: String,
    pub identity_id: String,
    pub identity_kind: String,
    pub session_kind: String,
    /// The agent behind the credential: its own key, or the agent of a delegated session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_id: Option<String>,
}

/// A caller presenting an OAuth access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpOAuthCaller {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub scopes: Vec<String>,
}

/// Who is calling the MCP server (`kind: 'iam' | 'oauth'`).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind")]
pub enum McpCaller {
    #[serde(rename = "iam")]
    Iam(McpIamCaller),
    #[serde(rename = "oauth")]
    OAuth(McpOAuthCaller),
}

/// The caller facts a tenant chooser receives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpTenantCaller {
    pub identity_id: String,
    pub session_tenant_id: String,
}

/// Chooses the tenant per caller; `None` refuses the caller.
pub type ChooseTenant = Arc<dyn Fn(&McpTenantCaller) -> Option<String> + Send + Sync>;

/// The tenant decisions are made in: the organization that runs this MCP server.
#[derive(Clone)]
pub enum McpTenant {
    Fixed(String),
    /// Chooses it per caller; `None` refuses the caller.
    Choose(ChooseTenant),
}

/// What tools without a rule are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum McpUnlisted {
    /// Refused and hidden.
    #[default]
    Deny,
    /// Open to any authenticated caller.
    Allow,
}

/// The reason shown to the person in a confirmation request.
pub type ConfirmationReason = Arc<dyn Fn(&str, &Value) -> String + Send + Sync>;

/// Options of [`McpAuthorizer`].
#[derive(Clone)]
pub struct McpAuthorizerOptions {
    /// The Better IAM instance or client that authenticates credentials and decides.
    pub iam: Arc<dyn McpIam>,
    /// Rules by tool name.
    pub tools: HashMap<String, McpToolRule>,
    /// Tools without a rule: refused and hidden (the default) or open to any authenticated caller.
    pub unlisted: McpUnlisted,
    /// The resource type of the default per-tool resource (default `mcp-tool`).
    pub tool_resource_type: Option<String>,
    /// The tenant decisions are made in (required). Deciding in each caller's own tenant would let any organization
    /// grant itself access.
    pub tenant_id: McpTenant,
    /// Accepts OAuth access tokens too, decided by each tool's `scopes`. A token naming a tenant other than a fixed
    /// `tenant_id` is refused.
    pub oauth: Option<Arc<dyn McpOAuthVerifier>>,
    /// When an agent acting for a person calls a tool whose action the person confirms one call at a time, ask the
    /// person on the agent's behalf and tell the agent to retry after the approval. On by default when the instance
    /// has the delegations API; `Some(false)` turns it off.
    pub confirmations: Option<bool>,
    /// The reason shown to the person (default: which tool the agent wants to run).
    pub confirmation_reason: Option<ConfirmationReason>,
}

impl McpAuthorizerOptions {
    /// Options with the defaults for everything but the instance, the tenant, and the rules.
    pub fn new(
        iam: Arc<dyn McpIam>,
        tenant_id: McpTenant,
        tools: HashMap<String, McpToolRule>,
    ) -> Self {
        Self {
            iam,
            tools,
            unlisted: McpUnlisted::Deny,
            tool_resource_type: None,
            tenant_id,
            oauth: None,
            confirmations: None,
            confirmation_reason: None,
        }
    }
}

/// A confirmation the person was asked for.
#[derive(Debug, Clone, PartialEq)]
pub struct McpConfirmation {
    pub id: String,
    pub expires_at: f64,
}

/// A decision on a tool call.
#[derive(Debug, Clone, PartialEq)]
pub struct McpDecision {
    pub allowed: bool,
    /// `ALLOWED`, `PUBLIC`, `ACCESS_DENIED`, `UNKNOWN_TOOL`, `NO_RULE_FOR_CALLER`, `INSUFFICIENT_SCOPE`, or
    /// `CONFIRMATION_REQUESTED` (the person was asked to confirm; retry after they approve).
    pub reason: String,
    /// For `CONFIRMATION_REQUESTED`: the request the person decides on.
    pub confirmation: Option<McpConfirmation>,
}

impl McpDecision {
    fn new(allowed: bool, reason: &str) -> Self {
        Self {
            allowed,
            reason: reason.to_owned(),
            confirmation: None,
        }
    }
}

/// The request facts the authorizer reads.
#[derive(Debug, Clone)]
pub struct McpRequestHead {
    pub method: String,
    pub url: String,
    pub headers: HeaderMap,
}

/// A tool as `tools/list` lists it: anything with a name.
pub trait McpNamed {
    fn tool_name(&self) -> Option<&str>;
}

impl McpNamed for Value {
    fn tool_name(&self) -> Option<&str> {
        self.get("name").and_then(Value::as_str)
    }
}

impl McpNamed for String {
    fn tool_name(&self) -> Option<&str> {
        Some(self)
    }
}

impl McpNamed for &str {
    fn tool_name(&self) -> Option<&str> {
        Some(self)
    }
}

/// `headers.get(name)` of a fetch `Headers`: every value joined with `, `.
fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let values: Vec<String> = headers
        .get_all(name)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

fn credential_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for name in headers.keys() {
        if let Some(value) = header_value(headers, name.as_str()) {
            pairs.push((name.as_str().to_owned(), value));
        }
    }
    pairs
}

static PRESENTED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(Bearer|DPoP)\s+(\S+)$").expect("static regex"));

/// The credential in a request: `Authorization: Bearer …` (or `DPoP …`), else `x-api-key`.
fn presented(headers: &HeaderMap) -> Option<(String, String)> {
    let authorization = header_value(headers, "authorization").unwrap_or_default();
    if let Some(found) = PRESENTED.captures(&authorization) {
        return Some((found[1].to_owned(), found[2].to_owned()));
    }
    header_value(headers, "x-api-key")
        .filter(|key| !key.is_empty())
        .map(|key| ("Bearer".to_owned(), key))
}

/// Decisions shared by the gate and by tool handlers written with an MCP SDK (`createMcpAuthorizer`).
pub struct McpAuthorizer {
    options: McpAuthorizerOptions,
}

impl McpAuthorizer {
    /// `createMcpAuthorizer(options)`.
    pub fn new(options: McpAuthorizerOptions) -> Self {
        Self { options }
    }

    fn resource_type(&self) -> &str {
        self.options
            .tool_resource_type
            .as_deref()
            .unwrap_or("mcp-tool")
    }

    fn rule(&self, name: &str) -> Option<McpToolRule> {
        match self.options.tools.get(name) {
            Some(rule) => Some(rule.clone()),
            None if self.options.unlisted == McpUnlisted::Allow => Some(McpToolRule {
                public: true,
                ..McpToolRule::default()
            }),
            None => None,
        }
    }

    fn resource_of(
        &self,
        name: &str,
        found: &McpToolRule,
        args: &Value,
    ) -> Result<McpResourceRef, String> {
        match &found.resource {
            Some(McpResource::Derived(derive)) => derive(args),
            Some(McpResource::Fixed(resource)) => Ok(resource.clone()),
            None => Ok(McpResourceRef::new(self.resource_type(), name)),
        }
    }

    /// For a delegated caller refused an action its delegation holds back for confirmation: files the confirmation
    /// request with the person and returns it. `None` when that does not apply or the request cannot be made (the
    /// call is then simply refused).
    async fn request_confirmation(
        &self,
        caller: &McpCaller,
        tool: &str,
        action: &str,
        resource: &McpResourceRef,
        args: &Value,
    ) -> Option<McpConfirmation> {
        let delegations = self.options.iam.delegations();
        let McpCaller::Iam(caller) = caller else {
            return None;
        };
        let delegations = delegations?;
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
        let held_back = delegation.confirm.as_ref().is_some_and(|patterns| {
            patterns
                .iter()
                .any(|pattern| better_iam_core::match_pattern(pattern, action, None))
        });
        if !held_back {
            return None;
        }
        let reason = match &self.options.confirmation_reason {
            Some(reason) => reason(tool, args),
            None => format!(
                "Your agent wants to run the tool {tool} ({action} on {}/{}).",
                resource.kind, resource.id
            ),
        };
        let request = delegations
            .request_confirmation(
                &caller.credential,
                &McpConfirmationInput {
                    tenant_id: caller.tenant_id.clone(),
                    action: action.to_owned(),
                    resource: resource.clone(),
                    reason,
                },
            )
            .await
            .ok()?;
        Some(McpConfirmation {
            id: request.id,
            expires_at: request.expires_at,
        })
    }

    /// Authenticates a request's credential: a Better IAM credential first, then (with `oauth`) an OAuth access
    /// token. `None` when the request carries none or it is not valid.
    pub async fn authenticate(&self, request: &McpRequestHead) -> Option<McpCaller> {
        let (scheme, token) = presented(&request.headers)?;
        if scheme.eq_ignore_ascii_case("bearer") {
            let credential = CredentialInput {
                headers: Some(credential_headers(&request.headers)),
                token: Some(token.clone()),
            };
            match self.options.iam.authenticate(&credential).await {
                Ok(principal) => {
                    let tenant_id = match &self.options.tenant_id {
                        McpTenant::Fixed(tenant) => Some(tenant.clone()),
                        McpTenant::Choose(choose) => choose(&McpTenantCaller {
                            identity_id: principal.identity.id.clone(),
                            session_tenant_id: principal.session.tenant_id.clone(),
                        }),
                    };
                    let tenant_id = tenant_id.filter(|tenant| !tenant.is_empty())?;
                    let agent_id = if principal.session.kind == "delegated" {
                        principal.session.agent_id.clone()
                    } else if principal.identity.kind == "agent" {
                        Some(principal.identity.id.clone())
                    } else {
                        None
                    };
                    return Some(McpCaller::Iam(McpIamCaller {
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
                    self.options.oauth.as_ref()?;
                }
            }
        }
        let oauth = self.options.oauth.as_ref()?;
        let token = oauth
            .verify_request(
                &McpOAuthRequest {
                    authorization: header_value(&request.headers, "authorization"),
                    dpop: header_value(&request.headers, "dpop"),
                    method: request.method.clone(),
                    url: request.url.clone(),
                },
                None,
            )
            .await
            .ok()?;
        // A token issued for another organization is not a token for this server.
        if let McpTenant::Fixed(tenant) = &self.options.tenant_id
            && token
                .tenant_id
                .as_ref()
                .is_some_and(|issued| issued != tenant)
        {
            return None;
        }
        Some(McpCaller::OAuth(McpOAuthCaller {
            client_id: token.client_id,
            scopes: token.scopes,
            subject: token.subject.filter(|subject| !subject.is_empty()),
            tenant_id: token.tenant_id.filter(|tenant| !tenant.is_empty()),
        }))
    }

    /// Whether the caller may call `name` with `args` (Better IAM denials are audited by the server).
    pub async fn can_call(
        &self,
        caller: &McpCaller,
        name: &str,
        args: &Value,
    ) -> IamResult<McpDecision> {
        let Some(found) = self.rule(name) else {
            return Ok(McpDecision::new(false, "UNKNOWN_TOOL"));
        };
        if found.public {
            return Ok(McpDecision::new(true, "PUBLIC"));
        }
        let iam_caller = match caller {
            McpCaller::OAuth(oauth) => {
                let scopes = found.scopes.as_deref().unwrap_or_default();
                if scopes.is_empty() {
                    return Ok(McpDecision::new(false, "NO_RULE_FOR_CALLER"));
                }
                let missing = scopes.iter().any(|scope| !oauth.scopes.contains(scope));
                return Ok(if missing {
                    McpDecision::new(false, "INSUFFICIENT_SCOPE")
                } else {
                    McpDecision::new(true, "ALLOWED")
                });
            }
            McpCaller::Iam(iam_caller) => iam_caller,
        };
        let Some(action) = found.action.as_deref().filter(|action| !action.is_empty()) else {
            return Ok(McpDecision::new(false, "NO_RULE_FOR_CALLER"));
        };
        let Ok(resource) = self.resource_of(name, &found, args) else {
            return Ok(McpDecision::new(false, "ACCESS_DENIED"));
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
            return Ok(McpDecision::new(true, "ALLOWED"));
        }
        Ok(
            match self
                .request_confirmation(caller, name, action, &resource, args)
                .await
            {
                Some(confirmation) => McpDecision {
                    allowed: false,
                    reason: "CONFIRMATION_REQUESTED".into(),
                    confirmation: Some(confirmation),
                },
                None => McpDecision::new(false, "ACCESS_DENIED"),
            },
        )
    }

    /// The tools the caller may see, in their original order (checked 50 at a time).
    pub async fn visible_tools<T: McpNamed>(
        &self,
        caller: &McpCaller,
        tools: Vec<T>,
    ) -> IamResult<Vec<T>> {
        let mut visible: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut checks: Vec<(String, McpCheck)> = Vec::new();
        for tool in &tools {
            let Some(name) = tool.tool_name() else {
                continue;
            };
            let Some(found) = self.rule(name) else {
                continue;
            };
            if found.public {
                visible.insert(name.to_owned());
                continue;
            }
            match caller {
                McpCaller::OAuth(oauth) => {
                    let scopes = found.scopes.as_deref().unwrap_or_default();
                    if !scopes.is_empty() && scopes.iter().all(|scope| oauth.scopes.contains(scope))
                    {
                        visible.insert(name.to_owned());
                    }
                }
                McpCaller::Iam(_) => {
                    let Some(action) = found.action.clone().filter(|action| !action.is_empty())
                    else {
                        continue;
                    };
                    let resource = match (&found.resource, &found.list_as) {
                        (Some(McpResource::Derived(_)), None) => {
                            visible.insert(name.to_owned());
                            continue;
                        }
                        (Some(McpResource::Derived(_)), Some(list_as)) => list_as.clone(),
                        (Some(McpResource::Fixed(resource)), _) => resource.clone(),
                        (None, _) => McpResourceRef::new(self.resource_type(), name),
                    };
                    checks.push((name.to_owned(), McpCheck { action, resource }));
                }
            }
        }
        if let McpCaller::Iam(caller) = caller {
            for batch in checks.chunks(50) {
                let request: Vec<McpCheck> = batch.iter().map(|(_, check)| check.clone()).collect();
                let results = self
                    .options
                    .iam
                    .authorize_many(&caller.credential, &caller.tenant_id, &request)
                    .await?;
                for (position, (name, _)) in batch.iter().enumerate() {
                    if results.get(position).is_some_and(|result| result.allowed) {
                        visible.insert(name.clone());
                    }
                }
            }
        }
        Ok(tools
            .into_iter()
            .filter(|tool| tool.tool_name().is_some_and(|name| visible.contains(name)))
            .collect())
    }
}

/// RFC 9728 protected resource metadata the gate serves and names in its challenges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpResourceMetadata {
    /// The MCP endpoint's resource identifier (its canonical URL), the audience of OAuth tokens for it.
    pub resource: String,
    /// Issuer URLs of the authorization servers that issue tokens for it (the Better IAM OAuth issuer).
    pub authorization_servers: Vec<String>,
    pub scopes: Option<Vec<String>>,
    pub resource_name: Option<String>,
    pub documentation: Option<String>,
}

/// Options of [`McpGate`].
#[derive(Clone)]
pub struct McpGateOptions {
    pub authorizer: McpAuthorizerOptions,
    /// Serve protected resource metadata and point 401 challenges at it (for OAuth-capable MCP clients).
    pub metadata: Option<McpResourceMetadata>,
    /// Largest accepted JSON-RPC body in bytes (default 4 MiB).
    pub max_body_bytes: Option<usize>,
}

fn invalid_url() -> IamError {
    IamError::new("INVALID_CONFIG", "Invalid URL")
}

/// Where RFC 9728 metadata lives for a resource: `/.well-known/oauth-protected-resource` + the resource path.
pub fn protected_resource_metadata_url(resource: &str) -> IamResult<String> {
    let url = Url::parse(resource).map_err(|_| invalid_url())?;
    let path = if url.path() == "/" {
        ""
    } else {
        url.path().strip_suffix('/').unwrap_or(url.path())
    };
    Ok(format!(
        "{}/.well-known/oauth-protected-resource{path}",
        url.origin().ascii_serialization()
    ))
}

fn boxed<B>(body: B) -> GateBody
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    body.map_err(Into::into).boxed_unsync()
}

fn full(bytes: impl Into<Bytes>) -> GateBody {
    boxed(Full::new(bytes.into()).map_err(|never| match never {}))
}

/// A JSON answer (`json(body, status, headers)`).
fn json_response(body: &Value, status: u16) -> Response<GateBody> {
    let mut response = Response::new(full(better_iam_core::js::stringify(body)));
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// `message.id` of a parsed message: `None` when absent (`undefined`).
fn member(value: &Value, name: &str) -> Option<Value> {
    value
        .as_object()
        .and_then(|object| object.get(name))
        .cloned()
}

/// `jsonRpc(value)`: an object with a string `method`.
fn json_rpc(value: &Value) -> Option<&Map<String, Value>> {
    let message = value.as_object()?;
    message.get("method")?.as_str()?;
    Some(message)
}

/// `Number(text)` for a header value: trimmed decimal, empty is 0, anything else NaN.
fn js_number(text: &str) -> f64 {
    let text = better_iam_core::js::trim(text);
    if text.is_empty() {
        return 0.0;
    }
    if text.contains(|c: char| c.is_ascii_alphabetic() && c != 'e' && c != 'E') {
        return f64::NAN;
    }
    text.parse().unwrap_or(f64::NAN)
}

/// The gate (`createMcpGate`): [`McpGate::handle`] answers the request itself (metadata, challenges, refused calls)
/// or passes it to `next` (the MCP server's handler) with the authenticated caller, filtering `tools/list` answers
/// on the way back.
pub struct McpGate {
    authorizer: Arc<McpAuthorizer>,
    max_body_bytes: usize,
    metadata_url: Option<String>,
    metadata_path: Option<String>,
    metadata_document: Option<String>,
    /// The canonical origin of the endpoint, for requests whose target is a path.
    resource_origin: Option<String>,
}

impl McpGate {
    /// `createMcpGate(options)`; INVALID_CONFIG when `metadata.resource` is not a URL.
    pub fn new(options: McpGateOptions) -> IamResult<Self> {
        let authorizer = Arc::new(McpAuthorizer::new(options.authorizer));
        let max_body_bytes = options.max_body_bytes.unwrap_or(4 * 1024 * 1024);
        let (metadata_url, metadata_path, metadata_document, resource_origin) = match &options
            .metadata
        {
            Some(metadata) => {
                let url = protected_resource_metadata_url(&metadata.resource)?;
                let path = Url::parse(&url)
                    .map_err(|_| invalid_url())?
                    .path()
                    .to_owned();
                let mut document = Map::new();
                document.insert("resource".into(), json!(metadata.resource));
                document.insert(
                    "authorization_servers".into(),
                    json!(metadata.authorization_servers),
                );
                if let Some(scopes) = metadata.scopes.as_ref().filter(|scopes| !scopes.is_empty()) {
                    document.insert("scopes_supported".into(), json!(scopes));
                }
                document.insert("bearer_methods_supported".into(), json!(["header"]));
                if let Some(name) = metadata
                    .resource_name
                    .as_ref()
                    .filter(|name| !name.is_empty())
                {
                    document.insert("resource_name".into(), json!(name));
                }
                if let Some(documentation) = metadata
                    .documentation
                    .as_ref()
                    .filter(|documentation| !documentation.is_empty())
                {
                    document.insert("resource_documentation".into(), json!(documentation));
                }
                let origin = Url::parse(&metadata.resource)
                    .map(|url| url.origin().ascii_serialization())
                    .ok();
                (
                    Some(url),
                    Some(path),
                    Some(better_iam_core::js::stringify_object(&document)),
                    origin,
                )
            }
            None => (None, None, None, None),
        };
        Ok(Self {
            authorizer,
            max_body_bytes,
            metadata_url,
            metadata_path,
            metadata_document,
            resource_origin,
        })
    }

    /// The decisions the gate makes.
    pub fn authorizer(&self) -> &Arc<McpAuthorizer> {
        &self.authorizer
    }

    /// The request's URL: its absolute target, or its path on the endpoint's canonical origin (the metadata
    /// `resource`), else on `http://{Host}`.
    fn request_url(&self, parts: &Parts) -> Url {
        let uri = &parts.uri;
        if uri.scheme().is_some()
            && uri.authority().is_some()
            && let Ok(url) = Url::parse(&uri.to_string())
        {
            return url;
        }
        let base = self.resource_origin.clone().unwrap_or_else(|| {
            let host = header_value(&parts.headers, "host").unwrap_or_else(|| "localhost".into());
            format!("http://{host}")
        });
        let target = uri.path_and_query().map_or("/", |target| target.as_str());
        Url::parse(&base)
            .and_then(|base| base.join(target))
            .or_else(|_| Url::parse("http://localhost/"))
            .expect("static URL")
    }

    fn challenge(&self, error: Option<&str>) -> Response<GateBody> {
        let body = json!({
            "error": error.unwrap_or("unauthorized"),
            "error_description": "Present a Better IAM credential or an OAuth access token",
        });
        let mut params = Vec::new();
        if let Some(error) = error {
            params.push(format!("error=\"{error}\""));
        }
        if let Some(url) = &self.metadata_url {
            params.push(format!("resource_metadata=\"{url}\""));
        }
        let params = params.join(", ");
        let challenge = if params.is_empty() {
            "Bearer".to_owned()
        } else {
            format!("Bearer {params}")
        };
        let mut response = json_response(&body, 401);
        let headers = response.headers_mut();
        headers.insert("cache-control", HeaderValue::from_static("no-store"));
        if let Ok(value) = HeaderValue::from_str(&challenge) {
            headers.insert("www-authenticate", value);
        }
        response
    }

    /// Answers the request or passes it to `next` with the authenticated caller. Fails when the instance fails in
    /// a way that is not a refusal of the caller (the TypeScript gate rejects), or when the request body breaks.
    pub async fn handle<B, F, Fut, RB>(
        &self,
        request: Request<B>,
        next: F,
    ) -> IamResult<Response<GateBody>>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
        F: FnOnce(Request<GateBody>, McpCaller) -> Fut,
        Fut: Future<Output = Response<RB>>,
        RB: Body<Data = Bytes> + Send + 'static,
        RB::Error: Into<BoxError>,
    {
        let (parts, body) = request.into_parts();
        let url = self.request_url(&parts);
        if let (Some(document), Some(path)) = (&self.metadata_document, &self.metadata_path)
            && url.path() == path
        {
            if parts.method == Method::OPTIONS {
                let mut response =
                    Response::new(boxed(Empty::new().map_err(|never| match never {})));
                *response.status_mut() = StatusCode::NO_CONTENT;
                let headers = response.headers_mut();
                headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
                headers.insert(
                    "access-control-allow-methods",
                    HeaderValue::from_static("GET, OPTIONS"),
                );
                return Ok(response);
            }
            let mut response = Response::new(full(document.clone()));
            let headers = response.headers_mut();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
            headers.insert(
                "cache-control",
                HeaderValue::from_static("public, max-age=3600"),
            );
            return Ok(response);
        }
        if presented(&parts.headers).is_none() {
            return Ok(self.challenge(None));
        }
        let head = McpRequestHead {
            method: parts.method.as_str().to_owned(),
            url: url.as_str().to_owned(),
            headers: parts.headers.clone(),
        };
        let Some(caller) = self.authorizer.authenticate(&head).await else {
            return Ok(self.challenge(Some("invalid_token")));
        };
        // Streamable HTTP also uses GET (the server's event stream) and DELETE (ending a session): authenticated only.
        if parts.method != Method::POST {
            return Ok(boxed_response(
                next(Request::from_parts(parts, boxed(body)), caller).await,
            ));
        }
        let Some(text) = bounded_body(&parts.headers, body, self.max_body_bytes).await? else {
            return Ok(json_response(&json!({ "error": "request too large" }), 413));
        };
        let Ok(parsed) = better_iam_core::js::parse(&text) else {
            return Ok(json_response(
                &json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error" } }),
                400,
            ));
        };
        // The server receives the request exactly as the gate read it (no duplicate keys a different parser could
        // pick).
        let mut forward_parts = parts;
        forward_parts.headers.remove(CONTENT_LENGTH);
        forward_parts.method = Method::POST;
        let forward =
            Request::from_parts(forward_parts, full(better_iam_core::js::stringify(&parsed)));
        if let Value::Array(items) = &parsed {
            // Batches (dropped from MCP in 2025-06-18) may not carry tool traffic past the gate.
            let tooling = items.iter().any(|item| {
                matches!(
                    json_rpc(item)
                        .and_then(|message| message.get("method"))
                        .and_then(Value::as_str),
                    Some("tools/call" | "tools/list")
                )
            });
            return Ok(if tooling {
                json_response(
                    &json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": { "code": -32600, "message": "Batched tool requests are not supported" },
                    }),
                    400,
                )
            } else {
                boxed_response(next(forward, caller).await)
            });
        }
        let message = json_rpc(&parsed);
        let method = message
            .and_then(|message| message.get("method"))
            .and_then(Value::as_str);
        let id = member(&parsed, "id").unwrap_or(Value::Null);
        if method == Some("tools/call") {
            let params = message.and_then(|message| message.get("params"));
            // A name that is not a string (an array, a number) would be judged as no tool at all (and allowed with
            // `unlisted: allow`) while the server may coerce it to a real tool's name: refuse it.
            let Some(name) = params
                .and_then(Value::as_object)
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str)
                .map(str::to_owned)
            else {
                return Ok(json_response(
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32602, "message": "The tool name must be a string" },
                    }),
                    400,
                ));
            };
            let args = match params
                .and_then(Value::as_object)
                .and_then(|params| params.get("arguments"))
            {
                Some(arguments @ (Value::Object(_) | Value::Array(_))) => arguments.clone(),
                _ => Value::Object(Map::new()),
            };
            let decision = match self.authorizer.can_call(&caller, &name, &args).await {
                Ok(decision) => decision,
                Err(error) if error.status == 401 || error.code == "UNAUTHENTICATED" => {
                    return Ok(self.challenge(Some("invalid_token")));
                }
                Err(error) => return Err(error),
            };
            if !decision.allowed {
                let text = if decision.reason == "UNKNOWN_TOOL" {
                    format!("Unknown tool: {name}")
                } else if let Some(confirmation) = &decision.confirmation {
                    format!(
                        "The person you act for must confirm this call first. A confirmation request was sent to them (it expires at {}). Call {name} again once they approve it.",
                        better_iam_core::js::iso_string(confirmation.expires_at)
                            .unwrap_or_else(|| "Invalid Date".into())
                    )
                } else {
                    format!("Access denied: you may not call {name}")
                };
                let mut result = Map::new();
                result.insert("content".into(), json!([{ "type": "text", "text": text }]));
                result.insert("isError".into(), Value::Bool(true));
                if let Some(confirmation) = &decision.confirmation {
                    result.insert(
                        "_meta".into(),
                        json!({
                            "better-iam/confirmationId": confirmation.id,
                            "better-iam/confirmationExpiresAt": better_iam_core::js::number(confirmation.expires_at),
                        }),
                    );
                }
                return Ok(json_response(
                    &json!({ "jsonrpc": "2.0", "id": id, "result": result }),
                    200,
                ));
            }
            return Ok(boxed_response(next(forward, caller).await));
        }
        if method == Some("tools/list") {
            let response = next(forward, caller.clone()).await;
            let request_id = member(&parsed, "id");
            return stream::filter_list(self.authorizer.clone(), response, request_id, caller)
                .await;
        }
        Ok(boxed_response(next(forward, caller).await))
    }
}

fn boxed_response<RB>(response: Response<RB>) -> Response<GateBody>
where
    RB: Body<Data = Bytes> + Send + 'static,
    RB::Error: Into<BoxError>,
{
    response.map(boxed)
}

/// The request body as text, or `None` when it is larger than `max_bytes` (read no further than that).
async fn bounded_body<B>(
    headers: &HeaderMap,
    body: B,
    max_bytes: usize,
) -> IamResult<Option<String>>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    let declared = js_number(&header_value(headers, "content-length").unwrap_or_default());
    if declared > max_bytes as f64 {
        return Ok(None);
    }
    let mut body = std::pin::pin!(body);
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            let error: BoxError = error.into();
            IamError::with_status("INTERNAL_ERROR", error.to_string(), 500)
        })?;
        if let Ok(data) = frame.into_data() {
            if bytes.len() + data.len() > max_bytes {
                return Ok(None);
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(Some(Utf8Decoder::default().decode(&bytes, true)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_urls() {
        assert_eq!(
            protected_resource_metadata_url("https://mcp.acme.test/mcp").unwrap(),
            "https://mcp.acme.test/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            protected_resource_metadata_url("https://mcp.acme.test/").unwrap(),
            "https://mcp.acme.test/.well-known/oauth-protected-resource"
        );
        assert_eq!(
            protected_resource_metadata_url("https://mcp.acme.test/a/b/").unwrap(),
            "https://mcp.acme.test/.well-known/oauth-protected-resource/a/b"
        );
        assert!(protected_resource_metadata_url("not a url").is_err());
    }

    #[test]
    fn presented_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("bearer abc"));
        assert_eq!(presented(&headers), Some(("bearer".into(), "abc".into())));
        headers.insert("authorization", HeaderValue::from_static("DPoP tok"));
        assert_eq!(presented(&headers), Some(("DPoP".into(), "tok".into())));
        headers.insert("authorization", HeaderValue::from_static("Basic x"));
        assert_eq!(presented(&headers), None);
        headers.insert("x-api-key", HeaderValue::from_static("key"));
        assert_eq!(presented(&headers), Some(("Bearer".into(), "key".into())));
    }

    #[test]
    fn callers_serialize_as_typescript_shapes() {
        let caller = McpCaller::OAuth(McpOAuthCaller {
            subject: Some("user-1".into()),
            client_id: "claude-desktop".into(),
            tenant_id: None,
            scopes: vec!["docs.search".into()],
        });
        assert_eq!(
            serde_json::to_value(&caller).unwrap(),
            json!({ "kind": "oauth", "subject": "user-1", "clientId": "claude-desktop", "scopes": ["docs.search"] })
        );
    }
}
