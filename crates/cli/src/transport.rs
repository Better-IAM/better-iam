//! Calls the IAM HTTP API surface by route (`transport.ts`): in process against a configured instance, or over HTTP(S)
//! against a running server. Both expose exactly the routes the HTTP handler serves, with the same credential rules,
//! so a command behaves the same locally and remotely.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use better_iam_auth::MfaCredential;
use better_iam_auth::safe_fetch::{
    FetchBody, FetchRequest, GuardedFetchOptions, RedirectMode, create_guarded_fetch,
};
use better_iam_auth::service::mfa::ConfirmMfaInput;
use better_iam_core::{CredentialInput, IamError, IamErrorDetails, js};
use better_iam_server::api::dispatch::{ROUTE_PATHS, dispatch as dispatch_route};
use better_iam_server::contracts::PluginCall;
use better_iam_server::http::{
    AUTH_METHODS, AUTHENTICATED_AUTH_METHODS, AuthArgs, PUBLIC_API_METHODS, PUBLIC_AUTH_METHODS,
    ROUTE_GROUPS,
};
use better_iam_server::index::BetterIam;
use better_iam_server::metrics::locale_compare;
use better_iam_server::operations::parse_checks;
use better_iam_server::options::{
    AccessibleResourcesRequest, AuthorizationRequest, BatchAuthorizationRequest, ResourceTarget,
};
use better_iam_server::validation::{object, text};
use futures::future::BoxFuture;
use regex::Regex;
use serde_json::{Map, Value, json};
use url::Url;

use crate::errors::{CliError, CliResult, usage_error};
use crate::output::stringify;

static SEGMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9_-]*$").expect("regex"));
const TOP_LEVEL: [&str; 3] = ["authorize", "authorizeMany", "listAccessible"];

/// One HTTP request of a remote call: always `POST` with a JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCall {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// The answer to an [`HttpCall`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpReply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpReply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The Fetch implementation remote calls use (`CliIO.fetch`); a failure is a network error (`TypeError: fetch failed`).
pub type FetchFn = Arc<dyn Fn(HttpCall) -> BoxFuture<'static, CliResult<HttpReply>> + Send + Sync>;

/// `local` or `remote`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Local,
    Remote,
}

enum Inner {
    Local {
        iam: Arc<BetterIam>,
        credential: CredentialInput,
    },
    Remote(RemoteClient),
}

/// Calls API routes by path (`ApiTransport`).
pub struct ApiTransport {
    pub mode: TransportMode,
    /// The configuration file or endpoint URL the calls go to, for messages.
    pub target: String,
    inner: Inner,
}

impl ApiTransport {
    /// `call(path, input)`: the route's JSON result.
    pub async fn call(&self, path: &str, input: Option<Map<String, Value>>) -> CliResult<Value> {
        let body = input.unwrap_or_default();
        match &self.inner {
            Inner::Local { iam, credential } => {
                let result = Box::pin(dispatch(iam, credential, path, &body)).await?;
                Ok(as_json(result))
            }
            Inner::Remote(client) => client.request(path, &Value::Object(body)).await,
        }
    }
}

/// Splits `roles.create`, `roles/create`, or `plugins/reports/summary` into a route path; refuses anything else
/// (`routePath`).
pub fn route_path(route: &str) -> CliResult<String> {
    let path = if route.contains('/') {
        route.to_owned()
    } else {
        route.replacen('.', "/", 1)
    };
    let parts: Vec<&str> = path.split('/').collect();
    if !parts.iter().all(|part| SEGMENT.is_match(part))
        || (parts.len() > 2 && parts[0] != "plugins")
    {
        return Err(usage_error(
            format!("{route} is not an API route like roles.create or auth.getSession"),
            None,
        ));
    }
    if parts.len() == 1 && !TOP_LEVEL.contains(&path.as_str()) {
        return Err(usage_error(
            format!(
                "{route} names no method; use group.method (for example roles.list), or api --list {route}"
            ),
            None,
        ));
    }
    Ok(path)
}

/// Whether a route needs no credential over HTTP (sign-in ceremonies, invitation acceptance, discovery)
/// (`isPublicRoute`).
pub fn is_public_route(path: &str) -> bool {
    let mut parts = path.split('/');
    let group = parts.next().unwrap_or("");
    let method = parts.next().unwrap_or("");
    if group == "auth" {
        PUBLIC_AUTH_METHODS.contains(&method)
    } else {
        PUBLIC_API_METHODS.contains(&path)
    }
}

fn not_found() -> IamError {
    IamError::with_status("NOT_FOUND", "Endpoint not found", 404)
}

/// Results as the HTTP API returns them: JSON values only (`asJson`), with JavaScript numbers.
fn as_json(value: Value) -> Value {
    match value {
        Value::Number(number) => js::number(js::number_value(&number)).unwrap_or(Value::Null),
        Value::Array(items) => Value::Array(items.into_iter().map(as_json).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, item)| (key, as_json(item)))
                .collect(),
        ),
        other => other,
    }
}

fn to_json<T: serde::Serialize>(value: T) -> CliResult<Value> {
    serde_json::to_value(value).map_err(|_| better_iam_server::js::internal_error().into())
}

/// In-process dispatch mirroring the HTTP router: only the routes it serves, public routes without the credential,
/// everything else with it. There is no request-size limit here, unlike HTTP's 64 KiB, so large configuration files
/// apply locally in one call.
async fn dispatch(
    iam: &BetterIam,
    credential: &CredentialInput,
    path: &str,
    body: &Map<String, Value>,
) -> CliResult<Value> {
    // The same named fields the HTTP router passes, so body keys such as `headers` never reach authentication.
    if path == "authorize" {
        let resource = object(body.get("resource"))?;
        let request = AuthorizationRequest {
            credential: credential.clone(),
            tenant_id: text(body.get("tenantId"), "tenantId", 256)?,
            action: text(body.get("action"), "action", 256)?,
            resource: ResourceTarget {
                kind: text(resource.get("type"), "resource type", 256)?,
                id: text(resource.get("id"), "resource id", 256)?,
            },
        };
        return to_json(iam.authorize(&request).await?);
    }
    if path == "authorizeMany" {
        let tenant_id = text(body.get("tenantId"), "tenantId", 256)?;
        let checks = parse_checks(body.get("checks"))?;
        let results = iam
            .authorize_many(&BatchAuthorizationRequest {
                credential: credential.clone(),
                tenant_id,
                checks,
            })
            .await?;
        let results: Vec<Value> = results
            .into_iter()
            .map(|result| {
                json!({
                    "action": result.check.action,
                    "resource": { "type": result.check.resource.kind, "id": result.check.resource.id },
                    "allowed": result.allowed,
                    "reason": result.reason,
                })
            })
            .collect();
        return Ok(json!({ "results": results }));
    }
    if path == "listAccessible" {
        let tenant_id = text(body.get("tenantId"), "tenantId", 256)?;
        let action = text(body.get("action"), "action", 256)?;
        let kind = text(body.get("type"), "resource type", 64)?;
        let number = |key: &str| -> CliResult<Option<f64>> {
            match body.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(value) => match value.as_f64() {
                    Some(number) => Ok(Some(number)),
                    None => {
                        Err(better_iam_server::js::invalid_input(format!("Invalid {key}")).into())
                    }
                },
            }
        };
        let limit = number("limit")?;
        let offset = number("offset")?;
        let listed = iam
            .list_accessible(&AccessibleResourcesRequest {
                credential: credential.clone(),
                tenant_id,
                action,
                kind,
                limit,
                offset,
            })
            .await?;
        return Ok(json!({ "resources": listed.resources, "total": js::number(listed.total) }));
    }
    let parts: Vec<&str> = path.split('/').collect();
    let group = parts.first().copied().unwrap_or("");
    let method = parts.get(1).copied().unwrap_or("");
    if group == "plugins" {
        let tenant_id = match body.get("tenantId") {
            Some(Value::String(tenant)) => tenant.clone(),
            _ => String::new(),
        };
        return Ok(iam
            .call_plugin(
                credential,
                PluginCall {
                    plugin_id: Some(Value::String(method.to_owned())),
                    path: Some(Value::String(
                        parts
                            .get(2..)
                            .map(|rest| rest.join("/"))
                            .unwrap_or_default(),
                    )),
                    tenant_id: Some(Value::String(tenant_id)),
                    input: Some(Value::Object(body.clone())),
                },
            )
            .await?);
    }
    if group.is_empty() || method.is_empty() || parts.len() > 2 {
        return Err(not_found().into());
    }
    if group == "auth" {
        if !iam.auth_api.has(method) {
            return Err(not_found().into());
        }
        if method == "beginMfa" {
            let mfa = match body.get("challenge") {
                Some(Value::String(challenge)) => MfaCredential::Challenge {
                    tenant_id: text(body.get("tenantId"), "tenantId", 256)?,
                    challenge: challenge.clone(),
                },
                _ => MfaCredential::Credential(credential.clone()),
            };
            return Ok(iam.auth_api.call(method, AuthArgs::BeginMfa(mfa)).await?);
        }
        if method == "confirmMfa" {
            let empty = Map::new();
            let nested = match body.get("credential") {
                Some(Value::Object(nested)) => nested,
                _ => &empty,
            };
            let mfa = match nested.get("challenge") {
                Some(Value::String(challenge)) => MfaCredential::Challenge {
                    tenant_id: text(nested.get("tenantId"), "tenantId", 256)?,
                    challenge: challenge.clone(),
                },
                _ => MfaCredential::Credential(credential.clone()),
            };
            let input = ConfirmMfaInput {
                credential: mfa,
                code: text(body.get("code"), "code", 256)?,
                remember_device: body.get("rememberDevice") == Some(&Value::Bool(true)),
            };
            return Ok(iam
                .auth_api
                .call(method, AuthArgs::ConfirmMfa(input))
                .await?);
        }
        if PUBLIC_AUTH_METHODS.contains(&method) {
            return Ok(iam
                .auth_api
                .call(method, AuthArgs::Public(Value::Object(body.clone())))
                .await?);
        }
        if AUTHENTICATED_AUTH_METHODS.contains(&method) {
            return Ok(iam
                .auth_api
                .call(
                    method,
                    AuthArgs::Authenticated(credential.clone(), Value::Object(body.clone())),
                )
                .await?);
        }
        return Err(not_found().into());
    }
    if !ROUTE_GROUPS.contains(&group) {
        return Err(not_found().into());
    }
    // Public routes take the body only: their own token (or none) is the credential.
    let credential = if PUBLIC_API_METHODS.contains(&path) {
        CredentialInput::default()
    } else {
        credential.clone()
    };
    match dispatch_route(&iam.api, path, body.clone(), &credential).await {
        Some(result) => Ok(result?),
        None => Err(not_found().into()),
    }
}

/// Calls API routes in process on a configured instance, as `token` (or with no credential), exposing exactly the
/// routes and credential rules of the HTTP handler; what token commands use without `--url` (`localTransport`).
pub fn local_transport(iam: Arc<BetterIam>, target: &str, token: Option<&str>) -> ApiTransport {
    let credential = CredentialInput {
        token: token.map(str::to_owned),
        ..CredentialInput::default()
    };
    ApiTransport {
        mode: TransportMode::Local,
        target: target.to_owned(),
        inner: Inner::Local { iam, credential },
    }
}

/// A parsed `--url` (`parseEndpoint`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub origin: String,
    pub base_path: String,
    pub url: String,
}

/// `https://iam.example.com` (default base path `/api/iam`) or the full endpoint `https://host/custom/iam`
/// (`parseEndpoint`).
pub fn parse_endpoint(url: &str) -> CliResult<Endpoint> {
    let parsed = Url::parse(url)
        .map_err(|_| usage_error(format!("--url {url} is not an absolute http(s) URL"), None))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some_and(|query| !query.is_empty())
        || parsed
            .fragment()
            .is_some_and(|fragment| !fragment.is_empty())
    {
        return Err(usage_error(
            "--url must be an http(s) URL without credentials, query, or fragment",
            None,
        ));
    }
    let origin = parsed.origin().ascii_serialization();
    let hostname = match parsed.host() {
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        Some(host) => host.to_string(),
        None => String::new(),
    };
    // Passwords and bearer tokens never travel in clear text; the server itself requires HTTPS outside localhost too.
    if parsed.scheme() == "http"
        && !["localhost", "127.0.0.1", "[::1]"].contains(&hostname.as_str())
        && !hostname.ends_with(".localhost")
    {
        return Err(usage_error(
            format!("--url {origin} must use https (plain http is allowed for localhost only)"),
            None,
        ));
    }
    let path = parsed.path().trim_end_matches('/');
    let base_path = if path.is_empty() {
        "/api/iam".to_owned()
    } else {
        path.to_owned()
    };
    Ok(Endpoint {
        url: format!("{origin}{base_path}"),
        origin,
        base_path,
    })
}

/// Two endpoint URLs name the same IAM API (origin and base path), however they were written (`sameEndpoint`).
pub fn same_endpoint(a: &str, b: &str) -> bool {
    match (parse_endpoint(a), parse_endpoint(b)) {
        (Ok(a), Ok(b)) => a.url == b.url,
        _ => false,
    }
}

static BASE_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/[A-Za-z0-9_/-]+$").expect("regex"));
static OPAQUE_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{16,512}$").expect("regex"));
static JWT_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9_-]{2,1024}\.[A-Za-z0-9_-]{2,3072}\.[A-Za-z0-9_-]{2,1024}$")
        .expect("regex")
});
const RESERVED: [&str; 7] = [
    "then",
    "catch",
    "finally",
    "toJSON",
    "constructor",
    "prototype",
    "__proto__",
];

fn route_segment(value: &str) -> bool {
    SEGMENT.is_match(value) && !RESERVED.contains(&value)
}

/// The bearer shapes the server can accept: an opaque token or an IAM-signed session JWT (`bearerToken`).
fn bearer_token(value: &str) -> bool {
    OPAQUE_TOKEN.is_match(value) || (value.len() <= 4096 && JWT_TOKEN.is_match(value))
}

/// The typed client's request path (`createIamClient` with `requestId: true` and `retryRateLimited: true`).
struct RemoteClient {
    origin: String,
    base_path: String,
    token: Option<String>,
    fetch: FetchFn,
}

/// `new IamClientError(code, message, status, retryAfterMs?, requestId?)`.
fn client_error(code: &str, message: &str, status: u16, retry_after_ms: Option<f64>) -> CliError {
    let mut error = IamError::with_status(code, message, status);
    if retry_after_ms.is_some() {
        error.details = Some(Box::new(IamErrorDetails {
            retry_after_ms,
            ..IamErrorDetails::default()
        }));
    }
    error.into()
}

impl RemoteClient {
    async fn request(&self, path: &str, input: &Value) -> CliResult<Value> {
        match self.attempt(path, input).await {
            Err(error)
                if error.code() == "RATE_LIMITED"
                    && error
                        .error
                        .details
                        .as_ref()
                        .and_then(|details| details.retry_after_ms)
                        .is_some_and(|wait| wait <= 5_000.0) =>
            {
                let wait = error
                    .error
                    .details
                    .as_ref()
                    .and_then(|details| details.retry_after_ms)
                    .unwrap_or(0.0);
                tokio::time::sleep(Duration::from_millis(wait.max(0.0) as u64)).await;
                self.attempt(path, input).await
            }
            other => other,
        }
    }

    async fn attempt(&self, path: &str, input: &Value) -> CliResult<Value> {
        if path.is_empty() || !path.split('/').all(route_segment) {
            return Err(client_error(
                "INVALID_PATH",
                "IAM routes must use plain relative path segments",
                0,
                None,
            ));
        }
        let mut headers: Vec<(String, String)> = vec![
            ("content-type".into(), "application/json".into()),
            ("x-better-iam".into(), "1".into()),
            ("x-request-id".into(), uuid::Uuid::new_v4().to_string()),
        ];
        if let Some(token) = &self.token {
            if !bearer_token(token) {
                return Err(client_error(
                    "INVALID_TOKEN",
                    "Invalid bearer token format",
                    0,
                    None,
                ));
            }
            headers.push(("authorization".into(), format!("Bearer {token}")));
        }
        let url = format!("{}{}/{path}", self.origin, self.base_path);
        let reply = (self.fetch)(HttpCall {
            url,
            headers,
            body: stringify(input, None),
        })
        .await?;
        let invalid = |message: &str| client_error("INVALID_RESPONSE", message, reply.status, None);
        let text = String::from_utf8_lossy(&reply.body);
        let envelope =
            js::parse(&text).map_err(|_| invalid("The IAM server returned an invalid response"))?;
        let Value::Object(envelope) = envelope else {
            return Err(invalid("The IAM server returned an invalid response"));
        };
        if let Some(error) = envelope.get("error") {
            if let (Some(Value::String(code)), Some(Value::String(message))) =
                (error.get("code"), error.get("message"))
            {
                let from_body = error.get("retryAfterMs").and_then(js::as_number);
                let header = reply
                    .header("retry-after")
                    .map(js::string_to_number)
                    .unwrap_or(f64::NAN);
                let retry_after_ms =
                    from_body.or((header.is_finite() && header > 0.0).then_some(header * 1000.0));
                let mut failure = client_error(code, message, reply.status, retry_after_ms);
                let region = error
                    .get("region")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let location = error
                    .get("location")
                    .and_then(Value::as_str)
                    .filter(|location| {
                        location.starts_with("http://") || location.starts_with("https://")
                    })
                    .map(str::to_owned);
                if region.is_some() || location.is_some() {
                    let details = failure.error.details.get_or_insert_with(Box::default);
                    details.region = region;
                    details.location = location;
                }
                return Err(failure);
            }
            return Err(invalid("The IAM server returned an invalid error response"));
        }
        if !(200..300).contains(&reply.status) {
            return Err(client_error(
                "HTTP_ERROR",
                "The IAM server rejected the request",
                reply.status,
                None,
            ));
        }
        match envelope.get("data") {
            Some(data) => Ok(data.clone()),
            None => Err(invalid("The IAM server returned an invalid response")),
        }
    }
}

/// `fetch` over HTTP(S): redirects fail (`redirect: 'error'`), private and loopback addresses are allowed (the
/// endpoint is the operator's own choice), and any failure is a network error.
pub fn default_fetch() -> FetchFn {
    Arc::new(|call: HttpCall| {
        Box::pin(async move {
            let fetcher = create_guarded_fetch(GuardedFetchOptions {
                allow_private_networks: true,
                allow_insecure_localhost: true,
                any_port: true,
                max_bytes: None,
            });
            let mut request = FetchRequest::new(
                call.url,
                "POST",
                Some(FetchBody::Bytes(call.body.into_bytes())),
            )
            .redirect(RedirectMode::Error);
            for (name, value) in call.headers {
                request = request.header(name, value);
            }
            let failed = |detail: String| CliError::unknown("fetch failed", detail);
            let mut response = fetcher
                .fetch(request)
                .await
                .map_err(|error| failed(error.to_string()))?;
            let body = response
                .body
                .bytes()
                .await
                .map_err(|error| failed(error.to_string()))?;
            Ok(HttpReply {
                status: response.status,
                headers: response.headers.clone(),
                body,
            })
        })
    })
}

/// `fetch` for a plain-http `*.localhost` endpoint: refused unless every address the name resolves to is loopback.
fn loopback_only(hostname: String, inner: FetchFn) -> FetchFn {
    Arc::new(move |call: HttpCall| {
        let hostname = hostname.clone();
        let inner = inner.clone();
        Box::pin(async move {
            let addresses: Vec<std::net::SocketAddr> =
                tokio::net::lookup_host((hostname.as_str(), 80))
                    .await
                    .map(Iterator::collect)
                    .unwrap_or_default();
            if addresses.is_empty() || !addresses.iter().all(|address| address.ip().is_loopback()) {
                return Err(usage_error(
                    format!("{hostname} does not resolve to this machine, so it needs https"),
                    Some("Use http://localhost or https://."),
                ));
            }
            inner(call).await
        })
    })
}

/// Calls API routes on a running IAM server over HTTP(S) with a bearer token, through the client's request path
/// (request IDs, one retry after a short rate limit); what token commands use with `--url` or a profile saved against
/// a server (`remoteTransport`).
pub fn remote_transport(
    url: &str,
    token: Option<&str>,
    fetcher: Option<FetchFn>,
) -> CliResult<ApiTransport> {
    let endpoint = parse_endpoint(url)?;
    if !BASE_PATH.is_match(&endpoint.base_path) || endpoint.base_path.ends_with('/') {
        return Err(client_error(
            "INVALID_CONFIG",
            "basePath must be an absolute path without a trailing slash",
            0,
            None,
        ));
    }
    let host = Url::parse(&endpoint.origin).ok();
    let hostname = host
        .as_ref()
        .and_then(|host| host.host_str().map(str::to_owned))
        .unwrap_or_default();
    // Plain http is allowed for `*.localhost` names only because they mean this machine, but the system resolver may
    // answer anything: check that the name really is loopback before a password or token goes out in clear text.
    let fetch = match fetcher {
        Some(fetcher) => fetcher,
        None if host.as_ref().is_some_and(|host| host.scheme() == "http")
            && hostname.ends_with(".localhost") =>
        {
            loopback_only(hostname, default_fetch())
        }
        None => default_fetch(),
    };
    Ok(ApiTransport {
        mode: TransportMode::Remote,
        target: endpoint.url.clone(),
        inner: Inner::Remote(RemoteClient {
            origin: endpoint.origin,
            base_path: endpoint.base_path,
            token: token.map(str::to_owned),
            fetch,
        }),
    })
}

/// One route of [`list_routes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub route: String,
    /// `public` or `token`.
    pub access: &'static str,
}

/// Every route the HTTP API serves, with whether it needs a credential (`listRoutes`). The route table is the same
/// for every deployment of this version.
pub fn list_routes() -> Vec<RouteEntry> {
    let mut routes: Vec<RouteEntry> = TOP_LEVEL
        .iter()
        .map(|route| RouteEntry {
            route: (*route).to_owned(),
            access: "token",
        })
        .collect();
    for method in AUTH_METHODS {
        if PUBLIC_AUTH_METHODS.contains(method) || AUTHENTICATED_AUTH_METHODS.contains(method) {
            routes.push(RouteEntry {
                route: format!("auth/{method}"),
                access: if PUBLIC_AUTH_METHODS.contains(method) {
                    "public"
                } else {
                    "token"
                },
            });
        }
    }
    for path in ROUTE_PATHS {
        let group = path.split('/').next().unwrap_or("");
        if ROUTE_GROUPS.contains(&group) {
            routes.push(RouteEntry {
                route: (*path).to_owned(),
                access: if PUBLIC_API_METHODS.contains(path) {
                    "public"
                } else {
                    "token"
                },
            });
        }
    }
    routes.sort_by(|a, b| locale_compare(&a.route, &b.route));
    routes
}
