//! `createRequestHelpers`: the per-request helpers every framework adapter exposes, and the in-process client
//! whose transport is the IAM handler in this process.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use better_iam_core::CredentialInput;
use better_iam_server::api::filters::PlanResourcesRequest;
use better_iam_server::options::{
    AccessibleResourcesRequest, AuthorizationCheck, AuthorizationRequest,
    BatchAuthorizationRequest, HttpResponse,
};
use bytes::Bytes;
use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use http::{HeaderMap, HeaderValue, Method};
use indexmap::IndexMap;
use serde::Serialize;
use serde_json::{Map, Value, json};
use tokio::sync::oneshot;
use url::Url;

use crate::iam::{IamLike, IamSource, tenant_resource};
use crate::{
    IamRequestError, MiddlewareError, ResourceRef, SESSION_COOKIES, StepUpRequirement,
    check_step_up, credential_of, error_code, header_value, host_of, is_authentication_error,
    origin_of, parse_cookie_header, set_cookie_summary, tenant_of,
};

/// What a framework adapter provides for one request.
#[derive(Clone)]
pub struct RequestBinding {
    /// The incoming request's URL (the in-process client's origin when the instance has no `endpoint`).
    pub url: Url,
    /// The incoming request's headers.
    pub headers: HeaderMap,
    /// Appends one `Set-Cookie` header to the outgoing response.
    pub set_cookie: Arc<dyn Fn(&str) + Send + Sync>,
}

/// Options of [`create_request_helpers`].
#[derive(Clone, Default)]
pub struct RequestHelperOptions {
    /// Where the IAM HTTP API is served; defaults to the instance's `endpoint.basePath`, else `/api/iam`.
    pub base_path: Option<String>,
    /// The clock for step-up recency and cookie expiry (default `Date.now()`).
    pub now: Option<Arc<dyn Fn() -> f64 + Send + Sync>>,
}

/// One answered check.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuthorizeResult {
    pub action: String,
    pub resource: ResourceRef,
    pub allowed: bool,
    pub reason: String,
}

/// A check for [`IamRequest::authorize`]; the resource defaults to the tenant.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizeInput {
    pub action: String,
    pub resource: Option<ResourceRef>,
}

/// The input of [`IamRequest::list_accessible`].
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ListAccessibleInput {
    pub action: String,
    /// The resource type (`type`).
    pub kind: String,
    pub tenant_id: Option<String>,
    pub limit: Option<f64>,
    pub offset: Option<f64>,
}

/// The input of [`IamRequest::plan`].
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PlanInput {
    pub action: String,
    /// The resource type (`type`).
    pub kind: String,
    pub tenant_id: Option<String>,
}

/// The input of [`IamRequest::assertion`] (`AssertionInput`).
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionInput {
    pub tenant_id: String,
    pub audience: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Map<String, Value>>,
}

type SharedSession = Shared<BoxFuture<'static, Result<Option<Value>, MiddlewareError>>>;
type SharedAnswer = Shared<BoxFuture<'static, Result<bool, MiddlewareError>>>;

struct Queued {
    tenant_id: String,
    check: AuthorizationCheck,
    done: oneshot::Sender<Result<bool, MiddlewareError>>,
}

#[derive(Default)]
struct State {
    /// Cookies set (or deleted) during this request override the incoming header for later calls.
    overrides: IndexMap<String, Option<String>>,
    session: Option<SharedSession>,
    queue: Vec<Queued>,
    answers: HashMap<String, SharedAnswer>,
}

struct Inner<T> {
    source: IamSource<T>,
    binding: RequestBinding,
    options: RequestHelperOptions,
    state: Mutex<State>,
}

/// The per-request helpers every framework adapter exposes (`req.iam`). Sessions and decisions are memoized for the
/// request, and cookies the in-process client receives count for later calls. Cloning shares the same request state.
pub struct IamRequest<T> {
    inner: Arc<Inner<T>>,
}

impl<T> Clone for IamRequest<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// Builds the per-request helpers over a framework's request and response. Framework adapters call this once per
/// request.
pub fn create_request_helpers<T: IamLike>(
    source: IamSource<T>,
    binding: RequestBinding,
    options: RequestHelperOptions,
) -> IamRequest<T> {
    IamRequest {
        inner: Arc::new(Inner {
            source,
            binding,
            options,
            state: Mutex::new(State::default()),
        }),
    }
}

fn unauthenticated() -> MiddlewareError {
    IamRequestError::new("UNAUTHENTICATED", "A session is required", 401, None).into()
}

fn gone() -> MiddlewareError {
    MiddlewareError::Other("The request has ended".into())
}

impl<T: IamLike> IamRequest<T> {
    fn state(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn weak(&self) -> Weak<Inner<T>> {
        Arc::downgrade(&self.inner)
    }

    fn from_weak(weak: &Weak<Inner<T>>) -> Option<Self> {
        weak.upgrade().map(|inner| Self { inner })
    }

    fn clock(&self) -> f64 {
        match &self.inner.options.now {
            Some(now) => now(),
            None => better_iam_core::js::now_ms(),
        }
    }

    async fn resolve(&self) -> Result<Arc<T>, MiddlewareError> {
        self.inner.source.resolve().await
    }

    /// The incoming request's URL.
    pub fn url(&self) -> &Url {
        &self.inner.binding.url
    }

    fn forget(&self) {
        let mut state = self.state();
        state.session = None;
        state.answers.clear();
    }

    /// The request headers with the cookies set during the request applied.
    pub fn headers(&self) -> HeaderMap {
        let binding = &self.inner.binding;
        let mut merged = binding.headers.clone();
        let overrides = self.state().overrides.clone();
        if overrides.is_empty() {
            return merged;
        }
        let mut jar = parse_cookie_header(header_value(&binding.headers, "cookie").as_deref());
        for (name, value) in overrides {
            match value {
                None => {
                    jar.shift_remove(&name);
                }
                Some(value) => {
                    jar.insert(name, value);
                }
            }
        }
        let cookie = jar
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        merged.remove("cookie");
        if !cookie.is_empty()
            && let Ok(value) = HeaderValue::from_bytes(cookie.as_bytes())
        {
            merged.insert("cookie", value);
        }
        merged
    }

    /// The credential for direct `iam.api.*` calls: this request's headers with cookies set during the request.
    pub fn credential(&self) -> CredentialInput {
        credential_of(&self.headers())
    }

    fn set_cookie(&self, header: &str) {
        (self.inner.binding.set_cookie)(header);
        if let Some(summary) = set_cookie_summary(header, self.clock()) {
            self.state().overrides.insert(
                summary.name,
                if summary.deleted {
                    None
                } else {
                    Some(summary.value)
                },
            );
        }
    }

    /// The current session, or `None` when the request carries no usable credential.
    pub async fn get_session(&self) -> Result<Option<Value>, MiddlewareError> {
        let pending = {
            let mut state = self.state();
            match &state.session {
                Some(pending) => pending.clone(),
                None => {
                    let weak = self.weak();
                    let pending = async move {
                        let this = Self::from_weak(&weak).ok_or_else(gone)?;
                        let iam = this.resolve().await?;
                        match iam.get_session(&this.credential()).await {
                            Ok(session) => Ok(Some(session)),
                            Err(error) if is_authentication_error(&error) => Ok(None),
                            Err(error) => Err(error),
                        }
                    }
                    .boxed()
                    .shared();
                    state.session = Some(pending.clone());
                    pending
                }
            }
        };
        pending.await
    }

    async fn tenant_for(&self, explicit: Option<&str>) -> Result<Option<String>, MiddlewareError> {
        match explicit {
            Some(tenant) => Ok(Some(tenant.to_owned())),
            None => Ok(self.get_session().await?.as_ref().and_then(tenant_of)),
        }
    }

    /// The current session; fails with `IamRequestError` 401 when signed out, 403 with a `reason` when it must step
    /// up.
    pub async fn require_session(
        &self,
        step_up: Option<&StepUpRequirement>,
    ) -> Result<Value, MiddlewareError> {
        let Some(current) = self.get_session().await? else {
            return Err(unauthenticated());
        };
        if let Some(requirement) = step_up
            && let Some(failure) = check_step_up(&current, requirement, self.clock())?
        {
            return Err(IamRequestError::new(
                failure.code,
                failure.message,
                failure.status,
                Some(failure.reason),
            )
            .into());
        }
        Ok(current)
    }

    /// Enforces one action (default resource: the tenant); fails with the server's refusal (401/403/429).
    pub async fn require(
        &self,
        action: &str,
        resource: Option<ResourceRef>,
        tenant_id: Option<&str>,
    ) -> Result<(), MiddlewareError> {
        let tenant_id = self.tenant_for(tenant_id).await?;
        let Some(tenant_id) = tenant_id.filter(|tenant| !tenant.is_empty()) else {
            return Err(unauthenticated());
        };
        let iam = self.resolve().await?;
        iam.require(&AuthorizationRequest {
            credential: self.credential(),
            resource: resource.unwrap_or_else(|| tenant_resource(&tenant_id)),
            tenant_id,
            action: action.to_owned(),
        })
        .await
    }

    /// One advisory decision; checks made in the same tick share one `authorizeMany` call. False when signed out.
    pub async fn can(
        &self,
        action: &str,
        resource: Option<ResourceRef>,
        tenant_id: Option<&str>,
    ) -> Result<bool, MiddlewareError> {
        let tenant_id = self.tenant_for(tenant_id).await?;
        let Some(tenant_id) = tenant_id.filter(|tenant| !tenant.is_empty()) else {
            return Ok(false);
        };
        let check = AuthorizationCheck {
            action: action.to_owned(),
            resource: resource.unwrap_or_else(|| tenant_resource(&tenant_id)),
        };
        let key =
            serde_json::to_string(&[&tenant_id, action, &check.resource.kind, &check.resource.id])
                .unwrap_or_default();
        let answer = {
            let mut state = self.state();
            match state.answers.get(&key) {
                Some(answer) => answer.clone(),
                None => {
                    let (done, receiver) = oneshot::channel();
                    if state.queue.is_empty() {
                        let weak = self.weak();
                        tokio::spawn(async move {
                            tokio::task::yield_now().await;
                            if let Some(this) = Self::from_weak(&weak) {
                                this.flush().await;
                            }
                        });
                    }
                    state.queue.push(Queued {
                        tenant_id,
                        check,
                        done,
                    });
                    let answer = async move { receiver.await.unwrap_or_else(|_| Err(gone())) }
                        .boxed()
                        .shared();
                    state.answers.insert(key, answer.clone());
                    answer
                }
            }
        };
        answer.await
    }

    async fn flush(&self) {
        let batch = std::mem::take(&mut self.state().queue);
        let mut by_tenant: IndexMap<String, Vec<Queued>> = IndexMap::new();
        for item in batch {
            by_tenant
                .entry(item.tenant_id.clone())
                .or_default()
                .push(item);
        }
        let iam = match self.resolve().await {
            Ok(iam) => iam,
            Err(error) => {
                for item in by_tenant.into_values().flatten() {
                    let _ = item.done.send(Err(error.clone()));
                }
                return;
            }
        };
        let caller = self.credential();
        for (tenant_id, items) in by_tenant {
            let mut items = items.into_iter().peekable();
            while items.peek().is_some() {
                let slice: Vec<Queued> = items.by_ref().take(50).collect();
                let request = BatchAuthorizationRequest {
                    credential: caller.clone(),
                    tenant_id: tenant_id.clone(),
                    checks: slice.iter().map(|item| item.check.clone()).collect(),
                };
                match iam.authorize_many(&request).await {
                    Ok(results) => {
                        for (index, item) in slice.into_iter().enumerate() {
                            let allowed = results.get(index).is_some_and(|result| result.allowed);
                            let _ = item.done.send(Ok(allowed));
                        }
                    }
                    Err(error) => {
                        let refused = error_code(&error).is_some();
                        for item in slice {
                            let _ = item.done.send(if refused {
                                Ok(false)
                            } else {
                                Err(error.clone())
                            });
                        }
                    }
                }
            }
        }
    }

    /// Advisory decisions for several checks; every check is denied (`UNAUTHENTICATED`) when signed out.
    pub async fn authorize(
        &self,
        checks: Vec<AuthorizeInput>,
        tenant_id: Option<&str>,
    ) -> Result<Vec<AuthorizeResult>, MiddlewareError> {
        let tenant_id = self.tenant_for(tenant_id).await?;
        let resolved: Vec<AuthorizationCheck> = checks
            .into_iter()
            .map(|check| AuthorizationCheck {
                action: check.action,
                resource: check
                    .resource
                    .unwrap_or_else(|| tenant_resource(tenant_id.as_deref().unwrap_or_default())),
            })
            .collect();
        let Some(tenant_id) = tenant_id.filter(|tenant| !tenant.is_empty()) else {
            return Ok(resolved
                .into_iter()
                .map(|check| AuthorizeResult {
                    action: check.action,
                    resource: check.resource,
                    allowed: false,
                    reason: "UNAUTHENTICATED".into(),
                })
                .collect());
        };
        let iam = self.resolve().await?;
        let mut results = Vec::with_capacity(resolved.len());
        for slice in resolved.chunks(50) {
            let request = BatchAuthorizationRequest {
                credential: self.credential(),
                tenant_id: tenant_id.clone(),
                checks: slice.to_vec(),
            };
            match iam.authorize_many(&request).await {
                Ok(answer) => {
                    for (index, check) in slice.iter().enumerate() {
                        let result = answer.get(index);
                        results.push(AuthorizeResult {
                            action: check.action.clone(),
                            resource: check.resource.clone(),
                            allowed: result.is_some_and(|result| result.allowed),
                            reason: result
                                .map(|result| result.reason.clone())
                                .unwrap_or_else(|| "DENIED".into()),
                        });
                    }
                }
                Err(error) => {
                    let Some(code) = error_code(&error).map(str::to_owned) else {
                        return Err(error);
                    };
                    for check in slice {
                        results.push(AuthorizeResult {
                            action: check.action.clone(),
                            resource: check.resource.clone(),
                            allowed: false,
                            reason: code.clone(),
                        });
                    }
                }
            }
        }
        Ok(results)
    }

    /// The registered resources of a managed type the caller may act on (`{ resources, total }`).
    pub async fn list_accessible(
        &self,
        input: ListAccessibleInput,
    ) -> Result<Value, MiddlewareError> {
        let iam = self.resolve().await?;
        if !iam.lists_accessible() {
            return Err(MiddlewareError::Other(
                "This IAM server does not list accessible resources".into(),
            ));
        }
        let tenant_id = self.tenant_for(input.tenant_id.as_deref()).await?;
        let Some(tenant_id) = tenant_id.filter(|tenant| !tenant.is_empty()) else {
            return Ok(json!({ "resources": [], "total": 0 }));
        };
        iam.list_accessible(&AccessibleResourcesRequest {
            credential: self.credential(),
            tenant_id,
            action: input.action,
            kind: input.kind,
            limit: input.limit,
            offset: input.offset,
        })
        .await
    }

    /// Which resources of a type the caller may perform an action on, as a filter for your own query (compile it
    /// with the filter compilers of `better_iam_core`). Plans `never` when signed out.
    pub async fn plan(&self, input: PlanInput) -> Result<Value, MiddlewareError> {
        let iam = self.resolve().await?;
        if !iam.plans_resources() {
            return Err(MiddlewareError::Other(
                "This IAM server does not plan resources".into(),
            ));
        }
        let tenant_id = self.tenant_for(input.tenant_id.as_deref()).await?;
        let Some(tenant_id) = tenant_id.filter(|tenant| !tenant.is_empty()) else {
            return Ok(json!({
                "tenantId": "",
                "action": input.action,
                "type": input.kind,
                "kind": "never",
                "filter": { "kind": "false" },
            }));
        };
        iam.plan_resources(&PlanResourcesRequest {
            credential: self.credential(),
            tenant_id,
            action: input.action,
            kind: input.kind,
        })
        .await
    }

    /// A short-lived signed assertion about the caller for a downstream service.
    pub async fn assertion(&self, input: &AssertionInput) -> Result<Value, MiddlewareError> {
        let iam = self.resolve().await?;
        if !iam.issues_assertions() {
            return Err(MiddlewareError::Other(
                "This IAM server does not issue assertions".into(),
            ));
        }
        let input = serde_json::to_value(input).unwrap_or(Value::Null);
        iam.issue_assertion(&self.credential(), &input).await
    }

    /// A client whose transport is the IAM handler in this process; `Set-Cookie` answers go on this response.
    pub fn client(&self) -> InProcessClient<T> {
        InProcessClient {
            helpers: self.clone(),
        }
    }

    /// Ends the session on the server and clears its cookie; never fails for an already-dead session.
    pub async fn sign_out(&self) -> Result<(), MiddlewareError> {
        let present = parse_cookie_header(header_value(&self.headers(), "cookie").as_deref());
        if let Err(error) = self.client().call("auth", "signOut", json!({})).await
            && error_code(&error).is_none()
        {
            return Err(error);
        }
        let iam = self.resolve().await?;
        let secure = iam
            .endpoint()
            .and_then(|endpoint| endpoint.secure)
            .unwrap_or_else(|| self.inner.binding.url.scheme() == "https");
        for name in SESSION_COOKIES {
            let cleared = self.state().overrides.get(name) == Some(&None);
            if present.contains_key(name) && !cleared {
                self.set_cookie(&format!(
                    "{name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{}",
                    if secure || name.starts_with("__Host-") {
                        "; Secure"
                    } else {
                        ""
                    }
                ));
            }
        }
        self.forget();
        Ok(())
    }
}

/// Request headers forwarded when the in-process client calls the IAM handler.
const FORWARDED_HEADERS: [&str; 9] = [
    "authorization",
    "user-agent",
    "accept-language",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "x-request-id",
    // A registered device's signed proof (verified by the server against the enrolled key and the session).
    "x-better-iam-device",
];

const RESERVED: [&str; 7] = [
    "then",
    "catch",
    "finally",
    "toJSON",
    "constructor",
    "prototype",
    "__proto__",
];

/// `routeSegment`: `/^[A-Za-z][A-Za-z0-9_-]*$/`, not a reserved name.
fn route_segment(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && !RESERVED.contains(&value)
}

fn client_error(code: &str, message: &str, status: u16) -> MiddlewareError {
    IamRequestError::new(code, message, status, None).into()
}

/// The in-process client of a request (`iam.client`): the typed client of `@better-iam/client` with the IAM
/// handler of this process as its transport. Requests carry this request's credential headers and cookies, and the
/// `Set-Cookie` answers go on this request's response and count for its later calls.
pub struct InProcessClient<T> {
    helpers: IamRequest<T>,
}

impl<T> Clone for InProcessClient<T> {
    fn clone(&self) -> Self {
        Self {
            helpers: self.helpers.clone(),
        }
    }
}

impl<T: IamLike> InProcessClient<T> {
    /// `client.{group}.{method}(input)`.
    pub async fn call(
        &self,
        group: &str,
        method: &str,
        input: Value,
    ) -> Result<Value, MiddlewareError> {
        self.request(&format!("{group}/{method}"), input).await
    }

    /// `client.$request(path, input)`: `POST {basePath}/{path}` with a JSON body; resolves with the envelope's
    /// `data` and fails with the envelope's `error` (code, message, status, `retryAfterMs`, `region`, `location`).
    pub async fn request(&self, path: &str, input: Value) -> Result<Value, MiddlewareError> {
        if path.is_empty() || !path.split('/').all(route_segment) {
            return Err(client_error(
                "INVALID_PATH",
                "IAM routes must use plain relative path segments",
                0,
            ));
        }
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("x-better-iam", HeaderValue::from_static("1"));
        let input = if input.is_null() {
            Value::Object(Map::new())
        } else {
            input
        };
        let body = better_iam_core::js::stringify(&input);
        let response = self
            .fetch(
                &format!("/{path}"),
                Method::POST,
                headers,
                Some(Bytes::from(body)),
            )
            .await?;
        let status = response.status().as_u16();
        let invalid = |message: &str| client_error("INVALID_RESPONSE", message, status);
        let text = String::from_utf8_lossy(response.body());
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        let Ok(Value::Object(envelope)) = better_iam_core::js::parse(text) else {
            return Err(invalid("The IAM server returned an invalid response"));
        };
        if let Some(error) = envelope.get("error") {
            let code = error.get("code").and_then(Value::as_str);
            let message = error.get("message").and_then(Value::as_str);
            let (Some(code), Some(message)) = (code, message) else {
                return Err(invalid("The IAM server returned an invalid error response"));
            };
            let from_body = error.get("retryAfterMs").and_then(Value::as_f64);
            let header = header_value(response.headers(), "retry-after")
                .map(|value| js_number(&value))
                .unwrap_or(0.0);
            let retry_after_ms = from_body
                .or_else(|| (header.is_finite() && header > 0.0).then_some(header * 1000.0));
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
            let mut failure = IamRequestError::new(code, message, status, None);
            if retry_after_ms.is_some() || region.is_some() || location.is_some() {
                failure.details = Some(Box::new(better_iam_core::IamErrorDetails {
                    retry_after_ms,
                    region,
                    location,
                    ..Default::default()
                }));
            }
            return Err(failure.into());
        }
        if !(200..300).contains(&status) {
            return Err(client_error(
                "HTTP_ERROR",
                "The IAM server rejected the request",
                status,
            ));
        }
        match envelope.get("data") {
            Some(data) => Ok(data.clone()),
            None => Err(invalid("The IAM server returned an invalid response")),
        }
    }

    /// The transport: sends `{mount}{path}` to the IAM handler with this request's forwarded headers and cookies,
    /// applies the `Set-Cookie` answers to this request, and returns the response. `path` is relative to the IAM
    /// base path (`/auth/signIn`, with an optional query).
    pub async fn fetch(
        &self,
        path: &str,
        method: Method,
        mut headers: HeaderMap,
        body: Option<Bytes>,
    ) -> Result<HttpResponse, MiddlewareError> {
        let helpers = &self.helpers;
        let iam = helpers.resolve().await?;
        let endpoint = iam.endpoint();
        let origin = endpoint
            .as_ref()
            .map(|endpoint| endpoint.origin.clone())
            .unwrap_or_else(|| origin_of(helpers.url()));
        let mount = helpers
            .inner
            .options
            .base_path
            .clone()
            .or_else(|| endpoint.as_ref().map(|endpoint| endpoint.base_path.clone()))
            .unwrap_or_else(|| "/api/iam".into());
        let incoming = helpers.headers();
        for name in FORWARDED_HEADERS.iter().chain(["cookie"].iter()) {
            if let Some(value) = header_value(&incoming, name)
                && !headers.contains_key(*name)
                && let Ok(value) = HeaderValue::from_bytes(value.as_bytes())
            {
                headers.insert(*name, value);
            }
        }
        let invalid_url = || MiddlewareError::Other("Invalid URL".into());
        headers.insert(
            "origin",
            HeaderValue::from_bytes(origin.as_bytes()).map_err(|_| invalid_url())?,
        );
        // With organization addresses (`hosts`), the call keeps the host the visitor is on, so the server pins it to
        // that organization (and fills in its tenant ID) exactly as it would a browser call from the page.
        let address = if iam.has_hosts() {
            let scheme = Url::parse(&origin).map_err(|_| invalid_url())?;
            format!("{}://{}", scheme.scheme(), host_of(helpers.url()))
        } else {
            origin
        };
        let url = Url::parse(&address)
            .and_then(|base| base.join(&format!("{mount}{path}")))
            .map_err(|_| invalid_url())?;
        let mut request = http::Request::builder()
            .method(method)
            .uri(url.as_str())
            .body(body.unwrap_or_default())
            .map_err(|_| invalid_url())?;
        *request.headers_mut() = headers;
        let response = iam.handler(request).await;
        let issued: Vec<String> = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .collect();
        for header in &issued {
            helpers.set_cookie(header);
        }
        if !issued.is_empty() {
            helpers.forget();
        }
        Ok(response)
    }
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

#[cfg(test)]
mod tests {
    use super::{js_number, route_segment};

    #[test]
    fn route_segments_and_numbers() {
        assert!(route_segment("signIn"));
        assert!(route_segment("get-session_2"));
        assert!(!route_segment("2fa"));
        assert!(!route_segment("constructor"));
        assert!(!route_segment(""));
        assert_eq!(js_number(" 2 "), 2.0);
        assert_eq!(js_number(""), 0.0);
        assert!(js_number("soon").is_nan());
    }
}
