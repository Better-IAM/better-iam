//! Port of `packages/server/src/inference-gateway.ts`.
//!
//! The inference gateway: an HTTP handler that lets any Better IAM credential (a person's session, a service account
//! or agent key, a delegated agent session) call AI models without ever holding a provider key. See
//! [`InferenceGatewayOptions`].
//!
//! The TypeScript handler takes a `Request` and answers a `Response` whose body streams; here the handler takes the
//! buffered [`HttpRequest`] the server's routes use and answers an `http::Response<GatewayBody>`, whose body is a
//! [`hyper::body::Body`] that streams server-sent events as they arrive from the provider (and meters them when the
//! stream ends or the client drops it, as the TypeScript stream's `pull` and `cancel` do).

use std::collections::HashSet;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::Duration;

use better_iam_core::{CredentialInput, IamError, IamResult};
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::stream::{self, BoxStream, Stream, StreamExt};
use hyper::body::{Body, Frame, SizeHint};
use regex::Regex;
use serde_json::{Map, Value};

use crate::api::inference::GatewayPermit;
use crate::inference::{InferenceTokenUsage, InvocationCheck, PublicModel};
use crate::js::{self, number, utf16_len};
use crate::options::HttpRequest;
use crate::safe_fetch::{
    FetchBody, FetchError, FetchRequest, FetchResponse, GuardedFetchOptions, RedirectMode,
    create_guarded_fetch,
};
use crate::utils::date_now;

/// What `GatewayRuntime.authorize` answers: the permit for a checked call, or the refused check.
#[derive(Debug, Clone)]
pub enum GatewayAuthorization {
    Permit(Box<GatewayPermit>),
    /// `{ denied: check }`: the check that refused the call (`allowed: false`).
    Denied(Box<InvocationCheck>),
}

/// What the gateway needs from `iam.inference` (`GatewayRuntime`).
#[async_trait::async_trait]
pub trait GatewayRuntime: Send + Sync {
    /// Authenticates `credential` and checks `input` (`{ model, tenantId?, estimatedTokens?, tools? }`).
    async fn authorize(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<GatewayAuthorization>;
    /// Meters a call made under a permit (`usage` is an `InvocationRecord` without `tenantId`).
    async fn record(&self, permit: &GatewayPermit, usage: &Value) -> IamResult<Value>;
    /// The enabled models a credential may invoke.
    async fn models(&self, credential: &CredentialInput) -> IamResult<Vec<PublicModel>>;
    /// Whether an OpenAI Responses API response id was created through the gateway by the same caller (the same
    /// person, through the same agent if any) at the permit's provider. A runtime without it (the default answers
    /// false) makes the gateway refuse `previous_response_id`.
    async fn owns_response(&self, permit: &GatewayPermit, response_id: &str) -> IamResult<bool> {
        let _ = (permit, response_id);
        Ok(false)
    }
}

/// A provider's answer as the gateway reads it: status, headers (names in lower case) and the streamed body.
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// None for a response without a body (`response.body === null`).
    pub body: Option<BoxStream<'static, Result<Bytes, FetchError>>>,
}

impl UpstreamResponse {
    /// A response with a whole body.
    pub fn new(status: u16, headers: Vec<(String, String)>, body: impl Into<Bytes>) -> Self {
        let body: Bytes = body.into();
        Self {
            status,
            headers,
            body: Some(stream::once(async move { Ok(body) }).boxed()),
        }
    }

    /// A response whose body arrives in chunks.
    pub fn streaming(
        status: u16,
        headers: Vec<(String, String)>,
        chunks: impl Stream<Item = Result<Bytes, FetchError>> + Send + 'static,
    ) -> Self {
        Self {
            status,
            headers,
            body: Some(chunks.boxed()),
        }
    }

    /// `response.ok`.
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// `response.headers.get(name)`: repeated values joined with ", ".
    pub fn header(&self, name: &str) -> Option<String> {
        let values: Vec<&str> = self
            .headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect();
        (!values.is_empty()).then(|| values.join(", "))
    }

    /// `response.text()`.
    async fn text(&mut self) -> Result<String, FetchError> {
        let mut bytes = Vec::new();
        if let Some(body) = self.body.as_mut() {
            while let Some(chunk) = body.next().await {
                bytes.extend_from_slice(&chunk?);
            }
        }
        Ok(decode_utf8(&bytes))
    }
}

const NULL_BODY_STATUSES: [u16; 4] = [101, 204, 205, 304];

impl From<FetchResponse> for UpstreamResponse {
    fn from(response: FetchResponse) -> Self {
        let FetchResponse {
            status,
            headers,
            body,
            ..
        } = response;
        let body = (!NULL_BODY_STATUSES.contains(&status)).then(|| {
            stream::unfold(Some(body), |state| async move {
                let mut body = state?;
                match body.chunk().await {
                    Ok(Some(chunk)) => Some((Ok(chunk), Some(body))),
                    Ok(None) => None,
                    // A failed read ends the stream after the error.
                    Err(error) => Some((Err(error), None)),
                }
            })
            .boxed()
        });
        Self {
            status,
            headers,
            body,
        }
    }
}

/// A transport for upstream calls (the gateway's `fetch`).
pub type GatewayFetch = Arc<
    dyn Fn(FetchRequest) -> BoxFuture<'static, Result<UpstreamResponse, FetchError>> + Send + Sync,
>;

/// What the gateway reports to `onError`: a failed metering (an [`IamError`]) or an unreachable provider.
#[derive(Debug, Clone)]
pub enum GatewayError {
    Iam(IamError),
    Fetch(FetchError),
}

/// `onError`.
pub type GatewayErrorFn = Arc<dyn Fn(GatewayError) + Send + Sync>;

/// The inference gateway: an HTTP handler (`Request` → `Response`) that lets any Better IAM credential (a person's
/// session, a service account or agent key, a delegated agent session) call AI models without ever holding a provider
/// key. It authenticates the caller, checks `inference:invoke` on `model/{name}` and the covering budgets, forwards
/// the request to the provider with the sealed key, streams the answer back unchanged, and meters the tokens the
/// provider reports. Requests pass through in the provider's own wire format: Anthropic Messages (`POST
/// /v1/messages`, and `POST /v1/messages/count_tokens`, checked but not metered) for models on an `anthropic`
/// provider; OpenAI Chat Completions (`POST /v1/chat/completions`), Responses (`POST /v1/responses`) and Embeddings
/// (`POST /v1/embeddings`) for `openai` and `openai-compatible` providers. `GET /v1/models` lists the models the
/// caller may use. Responses API conversations live at the provider under the organization's key, so the gateway
/// keeps them apart: `previous_response_id` must name a response the same caller created through the gateway, and
/// the `conversation` parameter and `background` mode are refused (their state and usage are out of the gateway's
/// sight).
#[derive(Clone, Default)]
pub struct InferenceGatewayOptions {
    /// Path prefix the gateway is mounted under, such as `/ai` (default: none, so routes start at `/v1`).
    pub base_path: Option<String>,
    /// Transport for upstream calls; inject one for proxies or tests. By default platform providers use an unguarded
    /// transport and base URLs an organization chose use the SSRF guard (`inference.allowPrivateNetworks`); an
    /// injected transport replaces both and must enforce its own address rules.
    pub fetch: Option<GatewayFetch>,
    /// Deadline for the upstream response headers, in milliseconds (default 10 minutes).
    pub timeout_ms: Option<f64>,
    /// `anthropic-version` sent upstream when the client sends none (default `2023-06-01`).
    pub anthropic_version: Option<String>,
    /// Largest accepted request body in bytes (default 20 MiB).
    pub max_body_bytes: Option<f64>,
    /// Called when metering after a response fails (the response itself is unaffected).
    pub on_error: Option<GatewayErrorFn>,
}

/// Error shape, and which providers serve an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Anthropic,
    Openai,
}

/// How a provider reports token usage: Anthropic Messages, OpenAI Chat Completions / Embeddings, OpenAI Responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageFormat {
    Anthropic,
    Openai,
    Responses,
}

impl From<Format> for UsageFormat {
    fn from(format: Format) -> Self {
        match format {
            Format::Anthropic => Self::Anthropic,
            Format::Openai => Self::Openai,
        }
    }
}

/// One passthrough route.
struct Endpoint {
    path: &'static str,
    format: Format,
    /// Where usage is reported; None for calls that are checked but cost nothing (not metered).
    usage: Option<UsageFormat>,
    /// Request fields that limit output tokens (capped at the model's `maxOutputTokens`).
    output_fields: &'static [&'static str],
    /// The field set to the model's cap when the request has none (by provider kind); None to leave it unset.
    default_output_field: Option<fn(&str) -> &'static str>,
}

static ENDPOINTS: [Endpoint; 5] = [
    Endpoint {
        path: "/v1/messages",
        format: Format::Anthropic,
        usage: Some(UsageFormat::Anthropic),
        output_fields: &["max_tokens"],
        default_output_field: Some(|_| "max_tokens"),
    },
    Endpoint {
        path: "/v1/messages/count_tokens",
        format: Format::Anthropic,
        usage: None,
        output_fields: &[],
        default_output_field: None,
    },
    Endpoint {
        path: "/v1/chat/completions",
        format: Format::Openai,
        usage: Some(UsageFormat::Openai),
        output_fields: &["max_tokens", "max_completion_tokens"],
        // OpenAI's own API prefers max_completion_tokens; compatible servers commonly know only max_tokens.
        default_output_field: Some(|kind| {
            if kind == "openai" {
                "max_completion_tokens"
            } else {
                "max_tokens"
            }
        }),
    },
    Endpoint {
        path: "/v1/responses",
        format: Format::Openai,
        usage: Some(UsageFormat::Responses),
        output_fields: &["max_output_tokens"],
        default_output_field: Some(|_| "max_output_tokens"),
    },
    Endpoint {
        path: "/v1/embeddings",
        format: Format::Openai,
        usage: Some(UsageFormat::Openai),
        output_fields: &[],
        default_output_field: None,
    },
];

/// Provider-side ids of Responses API objects: letters, digits, `_` and `-`.
static RESPONSE_ID_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,200}$").expect("pattern"));

/// How many tools and MCP servers a request may list: all of them are read, so more are refused.
const TOOL_LIMIT: usize = 256;
const MCP_SERVER_LIMIT: usize = 64;

/// A member of a JavaScript value (`value.key`): only objects have named members here.
fn get<'a>(value: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    match value {
        Some(Value::Object(map)) => map.get(key),
        _ => None,
    }
}

fn is_plain_object(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Object(_)))
}

/// `TextDecoder().decode(bytes)`: UTF-8 with replacement characters, a leading byte order mark removed.
fn decode_utf8(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned()
}

/// `slice(0, count)` of a string, in UTF-16 code units.
fn slice_utf16(value: &str, count: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for c in value.chars() {
        let width = c.len_utf16();
        if used + width > count {
            break;
        }
        used += width;
        out.push(c);
    }
    out
}

/// `value.replace(/[^…]/g, '_')` without the `u` flag: every UTF-16 code unit outside `allowed` becomes `_`.
fn replace_disallowed(value: &str, allowed: impl Fn(char) -> bool) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if allowed(c) {
            out.push(c);
        } else {
            for _ in 0..c.len_utf16() {
                out.push('_');
            }
        }
    }
    out
}

/// The host of a remote MCP server URL (lowercase, without a trailing dot), or `invalid` for anything but a plain
/// http(s) URL in canonical form: user info, backslashes, encoded hosts or default ports would let the host checked
/// here differ from the one a provider connects to.
fn mcp_host(value: Option<&Value>) -> String {
    let Some(Value::String(value)) = value else {
        return "invalid".to_owned();
    };
    let Ok(url) = url::Url::parse(value) else {
        return "invalid".to_owned();
    };
    let canonical = url.as_str().to_lowercase();
    let given = value.to_lowercase();
    let hostname = url.host_str().unwrap_or("");
    if (url.scheme() != "https" && url.scheme() != "http")
        || !url.username().is_empty()
        || url.password().is_some_and(|password| !password.is_empty())
        || hostname.is_empty()
        || (canonical != given && canonical != format!("{given}/"))
    {
        return "invalid".to_owned();
    }
    let lower = hostname.to_lowercase();
    let trimmed = lower.strip_suffix('.').unwrap_or(&lower);
    let replaced = replace_disallowed(trimmed, |c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | ':' | '-')
    });
    slice_utf16(&replaced, 200)
}

/// The first reference in a request to an object stored at the provider under the organization's key, which the
/// gateway cannot tie to the caller: `item_reference` inputs, `file_id`s and `file_ids` wherever they appear (message
/// parts, function outputs, image masks, code-interpreter containers), `vector_store_ids` (file search), `file`
/// sources (Anthropic, including inside tool results), and existing code-execution containers. The whole request is
/// searched (the path is kept for callers), so a reference cannot hide in a shape the gateway does not know; one too
/// large or deep to search counts as a reference. None when there is none.
pub fn stored_reference(_path: &str, body: &Map<String, Value>) -> Option<&'static str> {
    fn search(value: &Value, depth: usize, budget: &mut i64) -> Option<&'static str> {
        *budget -= 1;
        if *budget < 0 || depth > 64 {
            return Some("too-complex");
        }
        match value {
            Value::Array(items) => {
                for item in items {
                    if let Some(found) = search(item, depth + 1, budget) {
                        return Some(found);
                    }
                }
                None
            }
            Value::Object(map) => {
                if map.get("type") == Some(&Value::String("item_reference".into())) {
                    return Some("item_reference");
                }
                if matches!(map.get("file_id"), Some(Value::String(_))) {
                    return Some("file_id");
                }
                if matches!(map.get("file_ids"), Some(Value::Array(ids)) if !ids.is_empty()) {
                    return Some("file_id");
                }
                if matches!(map.get("vector_store_ids"), Some(Value::Array(ids)) if !ids.is_empty())
                {
                    return Some("vector_store");
                }
                if is_plain_object(map.get("source"))
                    && get(map.get("source"), "type") == Some(&Value::String("file".into()))
                {
                    return Some("file_id");
                }
                let container = map.get("container");
                if matches!(container, Some(Value::String(_)))
                    || (is_plain_object(container)
                        && matches!(get(container, "id"), Some(Value::String(_))))
                {
                    return Some("container");
                }
                for (key, item) in js::entries(map) {
                    // Free text and numbers never hold a reference; only structure is searched.
                    if key == "text" && item.is_string() {
                        continue;
                    }
                    if let Some(found) = search(item, depth + 1, budget) {
                        return Some(found);
                    }
                }
                None
            }
            _ => None,
        }
    }
    let mut budget: i64 = 50_000;
    search(&Value::Object(body.clone()), 0, &mut budget)
}

/// A tool kind as a policy names it: lowercase, without a version date (`web_search_20250305`) or `_preview`.
fn tool_kind(kind: &str) -> String {
    static DATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"_[0-9]{8}$").expect("pattern"));
    static PREVIEW: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"_preview(_[0-9]{4}_[0-9]{2}_[0-9]{2})?$").expect("pattern"));
    let lower = kind.to_lowercase();
    let undated = DATE.replace(&lower, "");
    let stable = PREVIEW.replace(&undated, "");
    let replaced = replace_disallowed(&stable, |c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-')
    });
    let kind = slice_utf16(&replaced, 64);
    if kind.is_empty() {
        "unknown".to_owned()
    } else {
        kind
    }
}

/// The tools a request asks the provider to run (or that the provider defines for the model to drive): Anthropic
/// server and Anthropic-defined tools (`tools[].type` other than `custom`) and remote MCP servers (`mcp_servers`);
/// OpenAI Responses built-in tools (`tools[].type` other than `function` and `custom`, MCP servers as `mcp:{host}` or
/// `mcp:{connector_id}`), and a stored prompt (`prompt`, which may bring tools of its own); Chat Completions web
/// search (`web_search_options`). Functions the caller runs itself are not listed. At most 65 entries are returned
/// (more are refused), from the first 256 tools and 64 MCP servers (the gateway refuses requests with more).
pub fn provider_tools_of(path: &str, body: &Map<String, Value>) -> Vec<String> {
    let mut tools: indexmap::IndexSet<String> = indexmap::IndexSet::new();
    let list: &[Value] = match body.get("tools") {
        Some(Value::Array(items)) => items,
        _ => &[],
    };
    for item in list.iter().take(TOOL_LIMIT) {
        let Value::Object(tool) = item else {
            continue;
        };
        let Some(Value::String(kind)) = tool.get("type") else {
            continue;
        };
        if kind.is_empty() || kind == "function" || kind == "custom" {
            continue;
        }
        if kind == "mcp" {
            match tool.get("connector_id") {
                Some(Value::String(connector)) if !tool.contains_key("server_url") => {
                    tools.insert(format!("mcp:{}", tool_kind(connector)));
                }
                _ => {
                    tools.insert(format!("mcp:{}", mcp_host(tool.get("server_url"))));
                }
            }
        } else {
            tools.insert(tool_kind(kind));
        }
    }
    if path == "/v1/messages"
        && let Some(Value::Array(servers)) = body.get("mcp_servers")
    {
        for server in servers.iter().take(MCP_SERVER_LIMIT) {
            tools.insert(format!("mcp:{}", mcp_host(get(Some(server), "url"))));
        }
    }
    if path == "/v1/responses" && !js::nullish(body.get("prompt")) {
        tools.insert("prompt".to_owned());
    }
    if path == "/v1/chat/completions" && !js::nullish(body.get("web_search_options")) {
        tools.insert("web_search".to_owned());
    }
    tools.into_iter().take(65).collect()
}

fn error_type(format: Format, status: u16) -> &'static str {
    match (format, status) {
        (Format::Anthropic, 400) => "invalid_request_error",
        (Format::Anthropic, 401) => "authentication_error",
        (Format::Anthropic, 403) => "permission_error",
        (Format::Anthropic, 404) => "not_found_error",
        (Format::Anthropic, 413) => "request_too_large",
        (Format::Anthropic, 429) => "rate_limit_error",
        (Format::Anthropic, 500 | 502) => "api_error",
        (Format::Anthropic, _) => "api_error",
        (Format::Openai, 400 | 401 | 404 | 413) => "invalid_request_error",
        (Format::Openai, 403) => "insufficient_quota",
        (Format::Openai, 429) => "rate_limit_exceeded",
        (Format::Openai, 500 | 502) => "server_error",
        (Format::Openai, _) => "server_error",
    }
}

/// The gateway's answer: a JSON or streamed body.
pub type GatewayResponse = http::Response<GatewayBody>;

fn response(status: u16, headers: Vec<(String, String)>, body: GatewayBody) -> GatewayResponse {
    let mut builder = http::Response::builder().status(status);
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::header::HeaderValue::from_str(&value),
        ) {
            builder = builder.header(name, value);
        }
    }
    builder
        .body(body)
        .unwrap_or_else(|_| http::Response::new(GatewayBody::empty()))
}

fn error_response(
    format: Format,
    status: u16,
    code: &str,
    message: &str,
    extra_headers: Vec<(String, String)>,
) -> GatewayResponse {
    let kind = error_type(format, status);
    let mut error = Map::new();
    let body = match format {
        Format::Anthropic => {
            error.insert("type".into(), Value::String(kind.into()));
            error.insert("message".into(), Value::String(message.into()));
            error.insert("code".into(), Value::String(code.into()));
            let mut body = Map::new();
            body.insert("type".into(), Value::String("error".into()));
            body.insert("error".into(), Value::Object(error));
            body
        }
        Format::Openai => {
            error.insert("message".into(), Value::String(message.into()));
            error.insert("type".into(), Value::String(kind.into()));
            error.insert("code".into(), Value::String(code.into()));
            let mut body = Map::new();
            body.insert("error".into(), Value::Object(error));
            body
        }
    };
    let mut headers = vec![("content-type".to_owned(), "application/json".to_owned())];
    headers.extend(extra_headers);
    response(
        status,
        headers,
        GatewayBody::full(js::stringify(&Value::Object(body))),
    )
}

/// `request.headers.get(name)`: repeated values joined with ", ".
fn request_header(request: &HttpRequest, name: &str) -> Option<String> {
    let values: Vec<String> = request
        .headers()
        .get_all(name)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

/// The presented credential: `Authorization: Bearer …`, else `x-api-key` (the Anthropic SDK's header).
fn credential_of(request: &HttpRequest) -> Option<String> {
    static BEARER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)^Bearer\s+(\S+)$").expect("pattern"));
    let authorization = request_header(request, "authorization").unwrap_or_default();
    if let Some(token) = BEARER
        .captures(&authorization)
        .and_then(|captures| captures.get(1))
    {
        return Some(token.as_str().to_owned());
    }
    request_header(request, "x-api-key")
}

/// A token count as providers report it: a non-negative safe integer, else 0.
fn count(item: Option<&Value>) -> f64 {
    match item.and_then(js::as_number) {
        Some(value) if js::is_safe_integer(value) && value >= 0.0 => value,
        _ => 0.0,
    }
}

/// Token counts from a provider's usage object (Anthropic, OpenAI Chat Completions / Embeddings, or OpenAI
/// Responses); None when there is none. Cached input tokens are counted apart from other input.
pub fn usage_from(format: UsageFormat, usage: Option<&Value>) -> Option<InferenceTokenUsage> {
    let usage = match usage {
        Some(value @ (Value::Object(_) | Value::Array(_))) => Some(value),
        _ => None,
    }?;
    let member = |key: &str| get(Some(usage), key);
    Some(match format {
        UsageFormat::Responses => {
            let cached = count(get(member("input_tokens_details"), "cached_tokens"));
            let mut result = InferenceTokenUsage::new(
                (count(member("input_tokens")) - cached).max(0.0),
                count(member("output_tokens")),
            );
            if cached != 0.0 {
                result.cache_read_tokens = Some(cached);
            }
            result
        }
        UsageFormat::Anthropic => {
            let mut result = InferenceTokenUsage::new(
                count(member("input_tokens")),
                count(member("output_tokens")),
            );
            let read = count(member("cache_read_input_tokens"));
            if read != 0.0 {
                result.cache_read_tokens = Some(read);
            }
            let write = count(member("cache_creation_input_tokens"));
            if write != 0.0 {
                result.cache_write_tokens = Some(write);
            }
            result
        }
        UsageFormat::Openai => {
            let cached = count(get(member("prompt_tokens_details"), "cached_tokens"));
            let mut result = InferenceTokenUsage::new(
                (count(member("prompt_tokens")) - cached).max(0.0),
                count(member("completion_tokens")),
            );
            if cached != 0.0 {
                result.cache_read_tokens = Some(cached);
            }
            result
        }
    })
}

/// A stream event the TypeScript tracker cannot read (`data: null`): reading it throws, which errors the stream.
struct UnreadableEvent;

/// Follows a server-sent event stream and keeps the latest token counts: Anthropic reports input (and cache) tokens
/// in `message_start` and cumulative output tokens in `message_delta`; OpenAI Chat Completions reports everything in
/// the final chunk when `stream_options.include_usage` is set (the gateway sets it); the Responses API reports it on
/// `response.completed` (or `response.incomplete` / `response.failed`) and names the response from
/// `response.created`. The final counts arrive last, so it also counts the characters of generated deltas: a stream
/// the client closes early is metered from them (`metered`), never as free.
struct StreamUsage {
    format: UsageFormat,
    buffer: String,
    /// Bytes of an incomplete UTF-8 sequence at the end of the last chunk (`TextDecoder` with `stream: true`).
    pending: Vec<u8>,
    /// Whether text was decoded yet (a leading byte order mark is dropped).
    started: bool,
    usage: Option<InferenceTokenUsage>,
    response_id: Option<String>,
    /// Whether the provider's final counts arrived.
    complete: bool,
    /// Characters of generated text, tool arguments and reasoning seen in deltas (UTF-16 code units).
    output_chars: usize,
}

impl StreamUsage {
    fn new(format: UsageFormat) -> Self {
        Self {
            format,
            buffer: String::new(),
            pending: Vec::new(),
            started: false,
            usage: None,
            response_id: None,
            complete: false,
            output_chars: 0,
        }
    }

    /// The usage to meter: the provider's counts once complete. Otherwise the input the provider reported so far (or
    /// `input_estimate` when it reported none) and at least a token per four generated characters, so closing a stream
    /// before its final event does not avoid metering.
    fn metered(&self, input_estimate: f64) -> InferenceTokenUsage {
        if self.complete
            && let Some(usage) = &self.usage
        {
            return usage.clone();
        }
        let estimated = (self.output_chars as f64 / 4.0).ceil();
        match &self.usage {
            Some(seen) => {
                let mut usage = seen.clone();
                usage.output_tokens = seen.output_tokens.max(estimated);
                usage
            }
            None => InferenceTokenUsage::new(input_estimate, estimated.max(0.0)),
        }
    }

    fn count(&mut self, value: Option<&Value>) {
        if let Some(Value::String(text)) = value {
            self.output_chars += utf16_len(text);
        }
    }

    /// Decodes a chunk as `TextDecoder.decode(chunk, { stream: true })` does.
    fn decode(&mut self, chunk: &[u8]) -> String {
        let mut pending = std::mem::take(&mut self.pending);
        pending.extend_from_slice(chunk);
        let mut out = String::new();
        let mut rest: &[u8] = &pending;
        loop {
            match std::str::from_utf8(rest) {
                Ok(text) => {
                    out.push_str(text);
                    rest = &[];
                    break;
                }
                Err(error) => {
                    let valid = error.valid_up_to();
                    out.push_str(std::str::from_utf8(&rest[..valid]).unwrap_or_default());
                    match error.error_len() {
                        Some(length) => {
                            out.push('\u{fffd}');
                            rest = &rest[valid + length..];
                        }
                        None => {
                            rest = &rest[valid..];
                            break;
                        }
                    }
                }
            }
        }
        self.pending = rest.to_vec();
        // The decoder drops a byte order mark at the start of the stream.
        if !self.started && !out.is_empty() {
            self.started = true;
            if let Some(stripped) = out.strip_prefix('\u{feff}') {
                return stripped.to_owned();
            }
        }
        out
    }

    fn push(&mut self, chunk: &[u8]) -> Result<(), UnreadableEvent> {
        let text = self.decode(chunk);
        self.buffer.push_str(&text);
        while let Some(newline) = self.buffer.find('\n') {
            let line = self.buffer[..newline].to_owned();
            self.buffer.drain(..=newline);
            let line = line.strip_suffix('\r').unwrap_or(&line);
            if let Some(payload) = line.strip_prefix("data:") {
                self.data(js::trim(payload))?;
            }
        }
        // A line longer than 1 MiB is not an event we need; drop it rather than buffer without bound.
        if self.buffer.len() > 1 << 20 && utf16_len(&self.buffer) > 1 << 20 {
            self.buffer.clear();
        }
        Ok(())
    }

    fn data(&mut self, payload: &str) -> Result<(), UnreadableEvent> {
        if payload.is_empty() || payload == "[DONE]" {
            return Ok(());
        }
        let Ok(event) = better_iam_core::js::parse(payload) else {
            return Ok(());
        };
        if event.is_null() {
            return Err(UnreadableEvent);
        }
        let event = Some(&event);
        let kind = match get(event, "type") {
            Some(Value::String(kind)) => Some(kind.as_str()),
            _ => None,
        };
        match self.format {
            UsageFormat::Openai => {
                if let Some(Value::Array(choices)) = get(event, "choices") {
                    for choice in choices {
                        let delta = get(Some(choice), "delta");
                        if !js::truthy(delta) {
                            continue;
                        }
                        self.count(get(delta, "content"));
                        self.count(get(delta, "reasoning_content"));
                        if let Some(Value::Array(calls)) = get(delta, "tool_calls") {
                            for call in calls {
                                self.count(get(get(Some(call), "function"), "arguments"));
                            }
                        }
                    }
                }
                if let Some(usage) = usage_from(UsageFormat::Openai, get(event, "usage")) {
                    self.usage = Some(usage);
                    self.complete = true;
                }
            }
            UsageFormat::Responses => {
                if kind.is_some_and(|kind| kind.ends_with(".delta")) {
                    self.count(get(event, "delta"));
                }
                let response = get(event, "response");
                if !js::truthy(response) || !kind.is_some_and(|kind| kind.starts_with("response."))
                {
                    return Ok(());
                }
                if let Some(Value::String(id)) = get(response, "id")
                    && self.response_id.is_none()
                {
                    self.response_id = Some(id.clone());
                }
                let usage = usage_from(UsageFormat::Responses, get(response, "usage"));
                let found = usage.is_some();
                if let Some(usage) = usage {
                    self.usage = Some(usage);
                }
                if found
                    && matches!(
                        kind,
                        Some("response.completed" | "response.incomplete" | "response.failed")
                    )
                {
                    self.complete = true;
                }
            }
            UsageFormat::Anthropic => match kind {
                Some("content_block_delta") => {
                    let delta = get(event, "delta");
                    self.count(get(delta, "text"));
                    self.count(get(delta, "partial_json"));
                    self.count(get(delta, "thinking"));
                }
                Some("message_start") => {
                    let message = get(event, "message");
                    if let Some(usage) = usage_from(UsageFormat::Anthropic, get(message, "usage")) {
                        self.usage = Some(usage);
                    }
                }
                Some("message_delta") => {
                    // Output tokens are cumulative; newer responses repeat the input and cache counts here too.
                    let delta = get(event, "usage");
                    let next = usage_from(UsageFormat::Anthropic, delta);
                    let Some(next) = next.filter(|_| js::truthy(delta)) else {
                        return Ok(());
                    };
                    let mut usage = self
                        .usage
                        .clone()
                        .unwrap_or_else(|| InferenceTokenUsage::new(0.0, 0.0));
                    usage.output_tokens = next.output_tokens;
                    if matches!(get(delta, "input_tokens"), Some(Value::Number(_))) {
                        usage.input_tokens = next.input_tokens;
                    }
                    if let Some(read) = next.cache_read_tokens {
                        usage.cache_read_tokens = Some(read);
                    }
                    if let Some(write) = next.cache_write_tokens {
                        usage.cache_write_tokens = Some(write);
                    }
                    self.usage = Some(usage);
                    // message_delta carries the final output count; message_stop follows.
                    self.complete = true;
                }
                _ => {}
            },
        }
        Ok(())
    }
}

fn upstream_url(base_url: &str, path: &str) -> String {
    // Base URLs are stored without the API version; accept one that already ends in /v1.
    if base_url.ends_with("/v1") {
        format!("{base_url}{}", &path[3..])
    } else {
        format!("{base_url}{path}")
    }
}

/// Upstream answers after which the gateway tries a model's fallbacks: rate limits, overload and server errors.
const RETRYABLE_STATUSES: [u16; 6] = [429, 500, 502, 503, 504, 529];

/// The request body as text, or None when it is larger than `max_bytes`.
fn bounded_body(request: &HttpRequest, max_bytes: f64) -> Option<String> {
    let declared = request_header(request, "content-length")
        .map(|value| js::to_number(&Value::String(value)))
        .unwrap_or(0.0);
    if declared > max_bytes {
        return None;
    }
    if request.body().len() as f64 > max_bytes {
        return None;
    }
    Some(decode_utf8(request.body()))
}

/// The response body of the gateway: a whole JSON body, or a provider's event stream forwarded as it arrives.
pub struct GatewayBody {
    kind: BodyKind,
}

enum BodyKind {
    Full(Option<Bytes>),
    Stream(BoxStream<'static, Result<Bytes, FetchError>>),
}

impl GatewayBody {
    fn full(body: impl Into<Bytes>) -> Self {
        Self {
            kind: BodyKind::Full(Some(body.into())),
        }
    }

    fn empty() -> Self {
        Self {
            kind: BodyKind::Full(None),
        }
    }

    fn stream(chunks: BoxStream<'static, Result<Bytes, FetchError>>) -> Self {
        Self {
            kind: BodyKind::Stream(chunks),
        }
    }

    /// The next chunk; None at the end.
    pub async fn chunk(&mut self) -> Option<Result<Bytes, FetchError>> {
        match &mut self.kind {
            BodyKind::Full(body) => body.take().map(Ok),
            BodyKind::Stream(chunks) => chunks.next().await,
        }
    }

    /// The whole body (reading a stream to its end, which meters it).
    pub async fn bytes(mut self) -> Result<Bytes, FetchError> {
        let mut out = Vec::new();
        while let Some(chunk) = self.chunk().await {
            out.extend_from_slice(&chunk?);
        }
        Ok(Bytes::from(out))
    }

    /// The whole body as text.
    pub async fn text(self) -> Result<String, FetchError> {
        Ok(String::from_utf8_lossy(&self.bytes().await?).into_owned())
    }
}

impl Body for GatewayBody {
    type Data = Bytes;
    type Error = FetchError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, FetchError>>> {
        match &mut self.kind {
            BodyKind::Full(body) => Poll::Ready(body.take().map(|bytes| Ok(Frame::data(bytes)))),
            BodyKind::Stream(chunks) => chunks
                .poll_next_unpin(cx)
                .map(|item| item.map(|chunk| chunk.map(Frame::data))),
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self.kind, BodyKind::Full(None))
    }

    fn size_hint(&self) -> SizeHint {
        match &self.kind {
            BodyKind::Full(Some(bytes)) => SizeHint::with_exact(bytes.len() as u64),
            BodyKind::Full(None) => SizeHint::with_exact(0),
            BodyKind::Stream(_) => SizeHint::default(),
        }
    }
}

/// Meters calls made under one permit (`meterFor(current, started)`).
struct Meter {
    runtime: Arc<dyn GatewayRuntime>,
    usage_format: Option<UsageFormat>,
    permit: GatewayPermit,
    started: f64,
    request_id: String,
    on_error: GatewayErrorFn,
}

impl Meter {
    async fn meter(
        &self,
        usage: Option<&InferenceTokenUsage>,
        status: &str,
        response_id: Option<&str>,
    ) {
        // Calls that cost nothing (token counting) are checked but not metered.
        if self.usage_format.is_none() {
            return;
        }
        let mut record = Map::new();
        record.insert(
            "model".into(),
            Value::String(permit_model_name(&self.permit)),
        );
        record.insert(
            "inputTokens".into(),
            number(usage.map_or(0.0, |usage| usage.input_tokens)),
        );
        record.insert(
            "outputTokens".into(),
            number(usage.map_or(0.0, |usage| usage.output_tokens)),
        );
        if let Some(tokens) = usage
            .and_then(|usage| usage.cache_read_tokens)
            .filter(|tokens| *tokens != 0.0)
        {
            record.insert("cacheReadTokens".into(), number(tokens));
        }
        if let Some(tokens) = usage
            .and_then(|usage| usage.cache_write_tokens)
            .filter(|tokens| *tokens != 0.0)
        {
            record.insert("cacheWriteTokens".into(), number(tokens));
        }
        record.insert("status".into(), Value::String(status.to_owned()));
        record.insert("requestId".into(), Value::String(self.request_id.clone()));
        record.insert("latencyMs".into(), number(date_now() - self.started));
        if let Some(response_id) = response_id.filter(|id| RESPONSE_ID_PATTERN.is_match(id)) {
            record.insert("responseId".into(), Value::String(response_id.to_owned()));
        }
        if let Err(error) = self
            .runtime
            .record(&self.permit, &Value::Object(record))
            .await
        {
            (self.on_error)(GatewayError::Iam(error));
        }
    }
}

/// `permit.check.model.name`.
fn permit_model_name(permit: &GatewayPermit) -> String {
    permit.check["model"]["name"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// `permit.check.model.maxOutputTokens`.
fn permit_output_cap(permit: &GatewayPermit) -> Option<f64> {
    js::as_number(&permit.check["model"]["maxOutputTokens"])
}

/// `permit.check.model.fallbacks`.
fn permit_fallbacks(permit: &GatewayPermit) -> Vec<String> {
    match &permit.check["model"]["fallbacks"] {
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// The stream forwarded to the client: the provider's chunks, untouched, tracked for usage. Metered once, at the end
/// of the stream, on a read error, or when the client drops it first.
struct Forwarded {
    upstream: BoxStream<'static, Result<Bytes, FetchError>>,
    tracker: StreamUsage,
    meter: Option<Arc<Meter>>,
    status: &'static str,
    input_estimate: f64,
    done: bool,
}

impl Forwarded {
    /// `finish()`: meters once (without the provider's final counts, estimated).
    fn take_meter(&mut self) -> Option<(Arc<Meter>, InferenceTokenUsage, Option<String>)> {
        let meter = self.meter.take()?;
        Some((
            meter,
            self.tracker.metered(self.input_estimate),
            self.tracker.response_id.clone(),
        ))
    }

    async fn finish(&mut self) {
        if let Some((meter, usage, response_id)) = self.take_meter() {
            meter
                .meter(Some(&usage), self.status, response_id.as_deref())
                .await;
        }
    }
}

impl Drop for Forwarded {
    fn drop(&mut self) {
        // The client went away before the end of the stream (`cancel`): metered from what was seen.
        if let Some((meter, usage, response_id)) = self.take_meter() {
            let status = self.status;
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    meter
                        .meter(Some(&usage), status, response_id.as_deref())
                        .await;
                });
            }
        }
    }
}

fn forward(state: Forwarded) -> BoxStream<'static, Result<Bytes, FetchError>> {
    stream::unfold(state, |mut state| async move {
        if state.done {
            return None;
        }
        match state.upstream.next().await {
            None => {
                state.finish().await;
                None
            }
            Some(Ok(chunk)) => {
                if state.tracker.push(&chunk).is_err() {
                    state.finish().await;
                    state.done = true;
                    return Some((
                        Err(FetchError {
                            message: "Cannot read properties of null".to_owned(),
                            cause: None,
                        }),
                        state,
                    ));
                }
                Some((Ok(chunk), state))
            }
            Some(Err(error)) => {
                state.finish().await;
                state.done = true;
                Some((Err(error), state))
            }
        }
    })
    .boxed()
}

/// An upstream attempt: the permit it was made under, when it started, and the answer or the transport error.
struct Sent {
    current: GatewayPermit,
    started: f64,
    outcome: Result<UpstreamResponse, FetchError>,
}

/// The gateway handler (`createInferenceGateway(runtime, options)`).
#[derive(Clone)]
pub struct InferenceGateway {
    runtime: Arc<dyn GatewayRuntime>,
    base: String,
    transport: Option<GatewayFetch>,
    timeout_ms: f64,
    anthropic_version: Option<String>,
    max_body_bytes: f64,
    on_error: GatewayErrorFn,
}

/// Builds the gateway handler over the inference runtime (see [`InferenceGatewayOptions`]).
pub fn create_inference_gateway(
    runtime: Arc<dyn GatewayRuntime>,
    options: Option<&InferenceGatewayOptions>,
) -> InferenceGateway {
    let options = options.cloned().unwrap_or_default();
    InferenceGateway {
        runtime,
        base: options
            .base_path
            .as_deref()
            .unwrap_or("")
            .trim_end_matches('/')
            .to_owned(),
        transport: options.fetch,
        timeout_ms: options.timeout_ms.unwrap_or(600_000.0),
        anthropic_version: options.anthropic_version,
        max_body_bytes: options.max_body_bytes.unwrap_or(20.0 * 1024.0 * 1024.0),
        on_error: options.on_error.unwrap_or_else(|| Arc::new(|_| {})),
    }
}

impl InferenceGateway {
    fn denial(&self, format: Format, denied: &InvocationCheck) -> GatewayResponse {
        match denied.reason.as_deref() {
            Some("BUDGET_EXCEEDED") => {
                let resets_at = denied
                    .budget
                    .as_ref()
                    .map(|budget| budget.resets_at)
                    .filter(|at| *at != 0.0 && !at.is_nan());
                let retry = resets_at.map(|at| (((at - date_now()) / 1000.0).ceil()).max(1.0));
                let name = denied
                    .budget
                    .as_ref()
                    .map_or("inference", |budget| budget.name.as_str());
                let until = resets_at
                    .and_then(better_iam_core::js::iso_string)
                    .unwrap_or_else(|| "its next window".to_owned());
                let headers = match retry {
                    Some(retry) if retry != 0.0 => {
                        vec![("retry-after".to_owned(), js::number_to_string(retry))]
                    }
                    _ => Vec::new(),
                };
                error_response(
                    format,
                    429,
                    "BUDGET_EXCEEDED",
                    &format!("Budget \"{name}\" is exhausted until {until}"),
                    headers,
                )
            }
            Some("MODEL_DISABLED") => error_response(
                format,
                403,
                "MODEL_DISABLED",
                "This model is disabled",
                Vec::new(),
            ),
            Some("TOOL_NOT_ALLOWED") => error_response(
                format,
                403,
                "TOOL_NOT_ALLOWED",
                js::trim(&format!(
                    "You may not use the provider tool {} with this model",
                    denied.tool.as_deref().unwrap_or("")
                )),
                Vec::new(),
            ),
            _ => error_response(
                format,
                403,
                "ACCESS_DENIED",
                "You may not use this model",
                Vec::new(),
            ),
        }
    }

    fn failure(&self, format: Format, error: IamError) -> GatewayResponse {
        // An exception that is not an IamError (INTERNAL_ERROR 500 in the Rust server) is reported and hidden.
        if error.code == "INTERNAL_ERROR" && error.status == 500 {
            (self.on_error)(GatewayError::Iam(error));
            return error_response(
                format,
                500,
                "INTERNAL",
                "The gateway failed to handle the request",
                Vec::new(),
            );
        }
        let status = if matches!(error.status, 401 | 403 | 404) {
            error.status
        } else {
            400
        };
        error_response(format, status, &error.code, &error.message, Vec::new())
    }

    async fn list_models(
        &self,
        request: &HttpRequest,
        credential: &CredentialInput,
    ) -> GatewayResponse {
        let anthropic = request.headers().contains_key("anthropic-version");
        let format = if anthropic {
            Format::Anthropic
        } else {
            Format::Openai
        };
        let models = match self.runtime.models(credential).await {
            Ok(models) => models,
            Err(error) => return self.failure(format, error),
        };
        let created = (date_now() / 1000.0).floor();
        let mut body = Map::new();
        if anthropic {
            let created_at = better_iam_core::js::iso_string(created * 1000.0).unwrap_or_default();
            let data = models
                .iter()
                .map(|model| {
                    let mut item = Map::new();
                    item.insert("type".into(), Value::String("model".into()));
                    item.insert("id".into(), Value::String(model.name.clone()));
                    item.insert(
                        "display_name".into(),
                        Value::String(
                            model
                                .display_name
                                .clone()
                                .unwrap_or_else(|| model.name.clone()),
                        ),
                    );
                    item.insert("created_at".into(), Value::String(created_at.clone()));
                    Value::Object(item)
                })
                .collect();
            body.insert("data".into(), Value::Array(data));
            body.insert("has_more".into(), Value::Bool(false));
            body.insert(
                "first_id".into(),
                models
                    .first()
                    .map_or(Value::Null, |model| Value::String(model.name.clone())),
            );
            body.insert(
                "last_id".into(),
                models
                    .last()
                    .map_or(Value::Null, |model| Value::String(model.name.clone())),
            );
        } else {
            body.insert("object".into(), Value::String("list".into()));
            let data = models
                .iter()
                .map(|model| {
                    let mut item = Map::new();
                    item.insert("id".into(), Value::String(model.name.clone()));
                    item.insert("object".into(), Value::String("model".into()));
                    item.insert("created".into(), number(created));
                    item.insert(
                        "owned_by".into(),
                        Value::String(model.provider.name.clone()),
                    );
                    Value::Object(item)
                })
                .collect();
            body.insert("data".into(), Value::Array(data));
        }
        response(
            200,
            vec![("content-type".to_owned(), "application/json".to_owned())],
            GatewayBody::full(js::stringify(&Value::Object(body))),
        )
    }

    /// Sends the request to a permit's provider: the answer, or the error when the provider could not be reached.
    async fn send(
        &self,
        request: &HttpRequest,
        endpoint: &Endpoint,
        body: &Map<String, Value>,
        stream: bool,
        current: GatewayPermit,
    ) -> Sent {
        let kind = current.provider.kind.clone();
        let mut upstream_body = body.clone();
        upstream_body.insert(
            "model".into(),
            Value::String(current.upstream_model.clone()),
        );
        // The model's `maxOutputTokens` caps every call: larger limits are lowered, and a call without one gets it.
        if let Some(cap) = permit_output_cap(&current)
            && !endpoint.output_fields.is_empty()
        {
            let mut limited = false;
            for field in endpoint.output_fields {
                let Some(value) = upstream_body.get(*field).and_then(js::as_number) else {
                    continue;
                };
                limited = true;
                if value > cap {
                    upstream_body.insert((*field).to_owned(), number(cap));
                }
            }
            if !limited && let Some(field) = endpoint.default_output_field.map(|of| of(&kind)) {
                upstream_body.insert(field.to_owned(), number(cap));
            }
        }
        let mut headers: Vec<(String, String)> = vec![
            ("content-type".to_owned(), "application/json".to_owned()),
            (
                "accept".to_owned(),
                if stream {
                    "text/event-stream"
                } else {
                    "application/json"
                }
                .to_owned(),
            ),
        ];
        if endpoint.format == Format::Anthropic {
            headers.push(("x-api-key".to_owned(), current.provider.api_key.clone()));
            let version = request_header(request, "anthropic-version")
                .or_else(|| self.anthropic_version.clone())
                .unwrap_or_else(|| "2023-06-01".to_owned());
            headers.push(("anthropic-version".to_owned(), version));
            if let Some(beta) =
                request_header(request, "anthropic-beta").filter(|beta| !beta.is_empty())
            {
                headers.push(("anthropic-beta".to_owned(), beta));
            }
        } else {
            headers.push((
                "authorization".to_owned(),
                format!("Bearer {}", current.provider.api_key),
            ));
            if stream && endpoint.usage == Some(UsageFormat::Openai) {
                let mut options = match body.get("stream_options") {
                    Some(Value::Object(map)) => map.clone(),
                    Some(Value::Array(items)) => items
                        .iter()
                        .enumerate()
                        .map(|(index, item)| (index.to_string(), item.clone()))
                        .collect(),
                    _ => Map::new(),
                };
                options.insert("include_usage".into(), Value::Bool(true));
                upstream_body.insert("stream_options".into(), Value::Object(options));
            }
        }
        let started = date_now();
        let mut fetch_request = FetchRequest::new(
            upstream_url(&current.provider.base_url, endpoint.path),
            "POST",
            Some(FetchBody::Text(js::stringify(&Value::Object(
                upstream_body,
            )))),
        )
        .redirect(RedirectMode::Error);
        for (name, value) in headers {
            fetch_request = fetch_request.header(name, value);
        }
        let attempt = self.fetch_upstream(&current, fetch_request);
        let outcome = match tokio::time::timeout(
            Duration::from_millis(self.timeout_ms.max(0.0) as u64),
            attempt,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => Err(FetchError {
                message: "This operation was aborted".to_owned(),
                cause: None,
            }),
        };
        Sent {
            current,
            started,
            outcome,
        }
    }

    /// The transport for a permit: the injected one, the SSRF guard for a base URL an organization chose (the answer
    /// is streamed back to the caller), or the platform's own transport.
    async fn fetch_upstream(
        &self,
        current: &GatewayPermit,
        request: FetchRequest,
    ) -> Result<UpstreamResponse, FetchError> {
        if let Some(transport) = &self.transport {
            return transport(request).await;
        }
        let options = match &current.provider.guard {
            Some(guard) => GuardedFetchOptions {
                allow_private_networks: guard["allowPrivateNetworks"] == Value::Bool(true),
                allow_insecure_localhost: guard["allowInsecureLocalhost"] == Value::Bool(true),
                any_port: guard["anyPort"] == Value::Bool(true),
                max_bytes: None,
            },
            // Platform providers: any address and port the provider's validated base URL names (`globalThis.fetch`).
            None => GuardedFetchOptions {
                allow_private_networks: true,
                allow_insecure_localhost: true,
                any_port: true,
                max_bytes: None,
            },
        };
        create_guarded_fetch(options)
            .fetch(request)
            .await
            .map(UpstreamResponse::from)
    }

    fn meter_for(&self, endpoint: &Endpoint, request_id: &str, sent: &Sent) -> Arc<Meter> {
        Arc::new(Meter {
            runtime: self.runtime.clone(),
            usage_format: endpoint.usage,
            permit: sent.current.clone(),
            started: sent.started,
            request_id: request_id.to_owned(),
            on_error: self.on_error.clone(),
        })
    }

    async fn invoke(
        &self,
        request: &HttpRequest,
        endpoint: &Endpoint,
        credential: &CredentialInput,
    ) -> GatewayResponse {
        let format = endpoint.format;
        let request_id = uuid::Uuid::new_v4().to_string();
        let Some(raw) = bounded_body(request, self.max_body_bytes) else {
            return error_response(
                format,
                413,
                "TOO_LARGE",
                "The request body is too large",
                Vec::new(),
            );
        };
        let body = match better_iam_core::js::parse(&raw) {
            Ok(Value::Object(map)) => map,
            _ => {
                return error_response(
                    format,
                    400,
                    "INVALID_INPUT",
                    "The request body must be a JSON object",
                    Vec::new(),
                );
            }
        };
        let Some(Value::String(model)) = body.get("model") else {
            return error_response(
                format,
                400,
                "INVALID_INPUT",
                "model is required",
                Vec::new(),
            );
        };
        let model = model.clone();
        let mut previous_response_id: Option<String> = None;
        if endpoint.usage == Some(UsageFormat::Responses) {
            // Conversation objects and background responses keep state and usage at the provider, out of the
            // gateway's sight; a previous response must be the caller's own (checked once the caller is known).
            if !js::nullish(body.get("conversation")) {
                return error_response(
                    format,
                    400,
                    "UNSUPPORTED_PARAMETER",
                    "The gateway does not support conversation; continue with previous_response_id",
                    Vec::new(),
                );
            }
            if body.get("background") == Some(&Value::Bool(true)) {
                return error_response(
                    format,
                    400,
                    "UNSUPPORTED_PARAMETER",
                    "The gateway does not support background responses",
                    Vec::new(),
                );
            }
            if !js::nullish(body.get("previous_response_id")) {
                match body.get("previous_response_id") {
                    Some(Value::String(id)) if RESPONSE_ID_PATTERN.is_match(id) => {
                        previous_response_id = Some(id.clone());
                    }
                    _ => {
                        return error_response(
                            format,
                            400,
                            "INVALID_INPUT",
                            "previous_response_id is invalid",
                            Vec::new(),
                        );
                    }
                }
            }
        }
        let max_output = endpoint
            .output_fields
            .iter()
            .filter_map(|field| body.get(*field).and_then(js::as_number))
            .find(|value| js::is_safe_integer(*value) && *value > 0.0);
        // A rough upper bound: four bytes per input token plus the requested output.
        let input_estimate = (utf16_len(&raw) as f64 / 4.0).ceil();
        let estimated_tokens = input_estimate + max_output.unwrap_or(0.0);
        // Every tool is read, so a request listing more than the gateway reads is refused rather than half checked.
        if matches!(body.get("tools"), Some(Value::Array(tools)) if tools.len() > TOOL_LIMIT)
            || matches!(body.get("mcp_servers"), Some(Value::Array(servers)) if servers.len() > MCP_SERVER_LIMIT)
        {
            return error_response(
                format,
                400,
                "INVALID_INPUT",
                &format!(
                    "A request may list at most {TOOL_LIMIT} tools and {MCP_SERVER_LIMIT} MCP servers"
                ),
                Vec::new(),
            );
        }
        // Objects stored at the provider under the organization's key cannot be tied to the caller.
        let reference = endpoint
            .usage
            .and_then(|_| stored_reference(endpoint.path, &body));
        if let Some(reference) = reference {
            return error_response(
                format,
                400,
                "UNSUPPORTED_PARAMETER",
                &format!(
                    "The gateway does not pass on references to stored provider objects ({reference})"
                ),
                Vec::new(),
            );
        }
        // Tools the provider would run, checked by each model's `providerTools` (token counting runs none).
        let tools = if endpoint.usage.is_some() {
            provider_tools_of(endpoint.path, &body)
        } else {
            Vec::new()
        };
        let checked = |name: &str| {
            let mut input = Map::new();
            input.insert("model".into(), Value::String(name.to_owned()));
            input.insert("estimatedTokens".into(), number(estimated_tokens));
            if !tools.is_empty() {
                input.insert(
                    "tools".into(),
                    Value::Array(tools.iter().cloned().map(Value::String).collect()),
                );
            }
            Value::Object(input)
        };
        let permit = match self.runtime.authorize(credential, &checked(&model)).await {
            Ok(GatewayAuthorization::Permit(permit)) => *permit,
            Ok(GatewayAuthorization::Denied(denied)) => return self.denial(format, &denied),
            Err(error) => return self.failure(format, error),
        };
        let kind = permit.provider.kind.clone();
        if (format == Format::Anthropic) != (kind == "anthropic") {
            let usage = if kind == "anthropic" {
                "POST /v1/messages"
            } else {
                "POST /v1/chat/completions, /v1/responses or /v1/embeddings"
            };
            return error_response(
                format,
                400,
                "WRONG_FORMAT",
                &format!(
                    "Model {} is served by an {kind} provider; use {usage}",
                    permit_model_name(&permit)
                ),
                Vec::new(),
            );
        }
        if let Some(previous) = &previous_response_id {
            let owned = match self.runtime.owns_response(&permit, previous).await {
                Ok(owned) => owned,
                Err(error) => return self.failure(format, error),
            };
            if !owned {
                return error_response(
                    format,
                    404,
                    "RESPONSE_NOT_FOUND",
                    "previous_response_id names no response of yours",
                    Vec::new(),
                );
            }
        }
        let stream = body.get("stream") == Some(&Value::Bool(true));

        // A model's fallbacks, in order, when its provider is unreachable, rate limited or failing: each only if the
        // caller may use it (access, budgets) and it speaks the same wire format.
        let permit_name = permit_model_name(&permit);
        let permit_provider = permit.provider.id.clone();
        let mut fallbacks: std::collections::VecDeque<String> =
            permit_fallbacks(&permit).into_iter().collect();
        let mut tried: HashSet<String> = HashSet::from([permit_name.clone()]);
        let mut sent = self.send(request, endpoint, &body, stream, permit).await;
        let mut fell_back = false;
        loop {
            let retry = match &sent.outcome {
                Err(_) => true,
                Ok(upstream) => RETRYABLE_STATUSES.contains(&upstream.status),
            };
            if !retry || fallbacks.is_empty() {
                break;
            }
            let mut next: Option<GatewayPermit> = None;
            while next.is_none() {
                let Some(name) = fallbacks.pop_front() else {
                    break;
                };
                if !tried.insert(name.clone()) {
                    continue;
                }
                let Ok(GatewayAuthorization::Permit(outcome)) =
                    self.runtime.authorize(credential, &checked(&name)).await
                else {
                    continue;
                };
                if (format == Format::Anthropic) != (outcome.provider.kind == "anthropic") {
                    continue;
                }
                // A continued response exists only at the provider whose ownership was checked.
                if previous_response_id.is_some() && outcome.provider.id != permit_provider {
                    continue;
                }
                next = Some(*outcome);
            }
            let Some(next) = next else {
                break;
            };
            // The failed attempt is metered (no tokens) against the model that failed, then the next one is tried.
            self.meter_for(endpoint, &request_id, &sent)
                .meter(None, "error", None)
                .await;
            drop(sent);
            sent = self.send(request, endpoint, &body, stream, next).await;
            fell_back = true;
        }
        let meter = self.meter_for(endpoint, &request_id, &sent);
        let chosen_name = permit_model_name(&sent.current);
        let mut upstream = match sent.outcome {
            Ok(upstream) => upstream,
            Err(error) => {
                meter.meter(None, "error", None).await;
                (self.on_error)(GatewayError::Fetch(error));
                return error_response(
                    format,
                    502,
                    "UPSTREAM_UNAVAILABLE",
                    "The model provider could not be reached",
                    Vec::new(),
                );
            }
        };
        let content_type = upstream.header("content-type");
        let mut headers = vec![
            (
                "content-type".to_owned(),
                content_type
                    .clone()
                    .unwrap_or_else(|| "application/json".to_owned()),
            ),
            ("x-better-iam-request-id".to_owned(), request_id.clone()),
            ("x-better-iam-model".to_owned(), chosen_name.clone()),
        ];
        if fell_back {
            headers.push(("x-better-iam-fallback-from".to_owned(), permit_name.clone()));
        }
        if let Some(upstream_request_id) = upstream
            .header("request-id")
            .or_else(|| upstream.header("x-request-id"))
            .filter(|id| !id.is_empty())
        {
            headers.push(("x-upstream-request-id".to_owned(), upstream_request_id));
        }
        let status = if upstream.ok() { "ok" } else { "error" };
        let event_stream = content_type
            .as_deref()
            .unwrap_or("")
            .contains("text/event-stream");
        if !event_stream || upstream.body.is_none() {
            let text = match upstream.text().await {
                Ok(text) => text,
                Err(error) => {
                    // `upstream.text()` rejected: an exception the gateway reports as its own failure.
                    (self.on_error)(GatewayError::Fetch(error));
                    return error_response(
                        format,
                        500,
                        "INTERNAL",
                        "The gateway failed to handle the request",
                        Vec::new(),
                    );
                }
            };
            let mut usage = None;
            let mut response_id = None;
            let mut payload = text.clone();
            if let Ok(parsed) = better_iam_core::js::parse(&text)
                && !parsed.is_null()
            {
                if let Some(format) = endpoint.usage {
                    usage = usage_from(format, get(Some(&parsed), "usage"));
                }
                if endpoint.usage == Some(UsageFormat::Responses)
                    && let Some(Value::String(id)) = get(Some(&parsed), "id")
                {
                    response_id = Some(id.clone());
                }
                if let Value::Object(mut map) = parsed
                    && map.get("model").is_some_and(Value::is_string)
                {
                    map.insert("model".into(), Value::String(chosen_name.clone()));
                    payload = js::stringify(&Value::Object(map));
                }
            }
            meter
                .meter(usage.as_ref(), status, response_id.as_deref())
                .await;
            return response(upstream.status, headers, GatewayBody::full(payload));
        }
        headers.push(("cache-control".to_owned(), "no-cache".to_owned()));
        let tracker = StreamUsage::new(endpoint.usage.unwrap_or(format.into()));
        let forwarded = forward(Forwarded {
            upstream: upstream.body.take().expect("event stream body"),
            tracker,
            meter: Some(meter),
            status,
            input_estimate,
            done: false,
        });
        response(upstream.status, headers, GatewayBody::stream(forwarded))
    }

    /// Answers one request.
    pub async fn handle(&self, request: &HttpRequest) -> GatewayResponse {
        let pathname = request.uri().path();
        let base = self.base.as_str();
        if !base.is_empty() && !pathname.starts_with(&format!("{base}/")) {
            return error_response(Format::Openai, 404, "NOT_FOUND", "Not found", Vec::new());
        }
        let path = &pathname[base.len()..];
        let endpoint = ENDPOINTS.iter().find(|endpoint| endpoint.path == path);
        let format = match endpoint {
            Some(endpoint) => endpoint.format,
            None if request.headers().contains_key("anthropic-version") => Format::Anthropic,
            None => Format::Openai,
        };
        let Some(token) = credential_of(request).filter(|token| !token.is_empty()) else {
            return error_response(
                format,
                401,
                "UNAUTHENTICATED",
                "Send a Better IAM credential as a bearer token or x-api-key",
                Vec::new(),
            );
        };
        let credential = CredentialInput {
            headers: Some(
                request
                    .headers()
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str().to_owned(),
                            String::from_utf8_lossy(value.as_bytes()).into_owned(),
                        )
                    })
                    .collect(),
            ),
            token: Some(token),
        };
        if request.method() == http::Method::GET && path == "/v1/models" {
            return self.list_models(request, &credential).await;
        }
        if request.method() == http::Method::POST
            && let Some(endpoint) = endpoint
        {
            return self.invoke(request, endpoint, &credential).await;
        }
        error_response(format, 404, "NOT_FOUND", "Not found", Vec::new())
    }
}
