//! The typed client of the Better IAM HTTP API (the Rust port of `@better-iam/client`).
//!
//! Every route of the API is a method, with the request and result types generated from the TypeScript server
//! (`better-iam-types`): `client.tenants().create(input).await`, `client.auth().get_session().await`,
//! `client.authorize(input).await`. Calls follow the TypeScript client exactly: `POST {basePath}/{group}/{method}`
//! with a JSON body, the CSRF headers the server requires (`content-type: application/json`, `x-better-iam: 1`),
//! a bearer token read at each request and refused locally when it cannot be one the server issues, structured
//! [`IamClientError`]s that keep the server's code without echoing response bodies, `onUnauthenticated` for
//! sessions that ended, an optional single retry of rate-limited calls, and `X-Request-Id` tagging.
//!
//! ```ignore
//! use better_iam_client::{create_iam_client, ClientOptions};
//! use better_iam_types::api::auth;
//!
//! let client = create_iam_client(ClientOptions::new("https://app.example.com").token(token))?;
//! let session = client.auth().get_session().await?;
//! let result = client
//!     .auth()
//!     .sign_in(auth::SignInInput { tenant_id, email, password, ..Default::default() })
//!     .signal(controller.signal())
//!     .await?;
//! ```
//!
//! - [`session`]: a framework-neutral session store (`createSessionStore`).
//! - [`device`]: registered-device proofs (`createDeviceProver`).
//! - The TypeScript `@better-iam/client/passkeys` entry re-exports the browser WebAuthn helpers of
//!   `@simplewebauthn/browser`; WebAuthn ceremonies run in the browser (`navigator.credentials`), so it has no
//!   Rust counterpart.
#![forbid(unsafe_code)]

pub mod abort;
pub mod api;
pub mod device;
pub mod fetch;
pub mod session;

use std::borrow::Cow;
use std::fmt;
use std::future::{Future, IntoFuture};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

pub use abort::{AbortController, AbortError, AbortReason, AbortSignal};
pub use better_iam_types::routes::{Operation, Route};
pub use fetch::{BoxError, Fetch, FetchError, FetchRequest, FetchResponse, FnFetch};

#[cfg(feature = "default-transport")]
pub use fetch::HyperFetch;

/// HTTP errors preserve the server's stable code without exposing raw response bodies (`IamClientError`). Errors
/// raised before anything is sent (configuration, path, token) have status 0.
#[derive(Debug, Clone, PartialEq)]
pub struct IamClientError {
    pub code: String,
    pub message: String,
    pub status: u16,
    /// For `RATE_LIMITED` responses: how long to wait before retrying, from the server's `Retry-After`.
    pub retry_after_ms: Option<f64>,
    /// The `X-Request-Id` the request carried (see [`ClientOptions::request_id`]), for support tickets and log
    /// lookups.
    pub request_id: Option<String>,
    /// For `WRONG_REGION`: the region whose deployment serves the organization.
    pub region: Option<String>,
    /// For `WRONG_REGION`: the organization's sign-in URL in that region, so a sign-in page can send the person there.
    pub location: Option<String>,
}

/// `ClientError`, the alias the TypeScript client exports.
pub type ClientError = IamClientError;

impl IamClientError {
    /// The error's name, `IamClientError`.
    pub const NAME: &'static str = "IamClientError";

    pub fn new(code: impl Into<String>, message: impl Into<String>, status: u16) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            status,
            retry_after_ms: None,
            request_id: None,
            region: None,
            location: None,
        }
    }

    /// `IamClientError`.
    pub fn name(&self) -> &'static str {
        Self::NAME
    }
}

impl fmt::Display for IamClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for IamClientError {}

/// Everything a call can fail with. TypeScript rejects with an `IamClientError`, the signal's reason, or whatever
/// `fetch` or a configured callback threw; Rust names each case.
#[derive(Debug, Clone)]
pub enum Error {
    /// The server refused the call, its answer was invalid, or the client refused to send it (`IamClientError`).
    Client(Box<IamClientError>),
    /// The call's signal was aborted: the signal's reason ([`AbortError`] when it was aborted without one).
    Aborted(AbortReason),
    /// The transport failed (`fetch` rejected: network failure, refused redirect, ...).
    Fetch(BoxError),
    /// A configured callback failed (the `token` or `headers` provider), or a header was invalid.
    Other(BoxError),
}

impl Error {
    /// The [`IamClientError`], when the call failed with one.
    pub fn client(&self) -> Option<&IamClientError> {
        match self {
            Error::Client(error) => Some(error),
            _ => None,
        }
    }

    /// The error code of an [`IamClientError`].
    pub fn code(&self) -> Option<&str> {
        self.client().map(|error| error.code.as_str())
    }

    /// The HTTP status of an [`IamClientError`].
    pub fn status(&self) -> Option<u16> {
        self.client().map(|error| error.status)
    }

    /// The abort reason, when the call was aborted.
    pub fn abort_reason(&self) -> Option<&AbortReason> {
        match self {
            Error::Aborted(reason) => Some(reason),
            _ => None,
        }
    }

    fn other(message: impl Into<String>) -> Self {
        Error::Other(Arc::new(FetchError(message.into())))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Client(error) => fmt::Display::fmt(error, f),
            Error::Aborted(reason) => fmt::Display::fmt(reason, f),
            Error::Fetch(error) | Error::Other(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Client(error) => Some(error),
            Error::Aborted(reason) => Some(reason.as_ref()),
            Error::Fetch(error) | Error::Other(error) => Some(error.as_ref()),
        }
    }
}

impl From<IamClientError> for Error {
    fn from(error: IamClientError) -> Self {
        Error::Client(Box::new(error))
    }
}

/// The result of a call.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A header list: `HeadersInit` as name and value pairs.
pub type HeaderList = Vec<(String, String)>;

type TokenFn = dyn Fn() -> BoxFuture<'static, Result<Option<String>, BoxError>> + Send + Sync;
type HeadersFn = dyn Fn() -> BoxFuture<'static, Result<HeaderList, BoxError>> + Send + Sync;

/// Where the bearer token comes from (`ClientOptions.token`). The token is read at each request and never stored by
/// the client.
#[derive(Clone)]
pub enum TokenSource {
    /// A fixed token.
    Static(String),
    /// Read at each request; `None` sends no `Authorization` header.
    Dynamic(Arc<TokenFn>),
}

/// Headers added to every request (`ClientOptions.headers`).
#[derive(Clone)]
pub enum HeaderSource {
    Static(HeaderList),
    /// Read at each request, for example [`device::DeviceProver::headers`].
    Dynamic(Arc<HeadersFn>),
}

/// `ClientOptions.retryRateLimited`: retry a `RATE_LIMITED` response once after the server's `retryAfterMs`, when
/// that wait is at most `max_wait_ms` (five seconds by default); longer waits surface the error unchanged. Aborting
/// the call's signal during the wait rejects at once with the signal's reason, without a second request.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct RetryRateLimited {
    pub max_wait_ms: Option<f64>,
}

/// `ClientOptions.requestId`: send an `X-Request-Id` header on every request (the server echoes it and records it
/// on its `http` spans) and expose it as [`IamClientError::request_id`].
#[derive(Clone)]
pub enum RequestId {
    /// Generate one per request (a UUID).
    Generate,
    /// Supply your own; it must be 1 to 128 characters of `A-Z a-z 0-9 . _ : -`.
    Custom(Arc<dyn Fn() -> String + Send + Sync>),
}

/// The hook of [`ClientOptions::on_unauthenticated`].
pub type UnauthenticatedHook = Arc<dyn Fn(&IamClientError) + Send + Sync>;

/// `ClientOptions`.
#[derive(Clone, Default)]
pub struct ClientOptions {
    /// The application's origin. Required: a Rust process has no current page.
    pub base_url: Option<String>,
    /// The API base path, `/api/iam` by default.
    pub base_path: Option<String>,
    /// The bearer token. Opaque tokens and IAM-signed session JWTs (from `roles.assume` or `sts.getSessionToken`
    /// with `format: 'jwt'`) are both accepted; any other shape fails with `INVALID_TOKEN` before a request is made.
    pub token: Option<TokenSource>,
    pub headers: Option<HeaderSource>,
    /// The transport; [`HyperFetch`] by default (feature `default-transport`).
    pub fetch: Option<Arc<dyn Fetch>>,
    /// Called once per request that the server refused because the presented session can no longer be used, after
    /// the error is raised, so an application can send the person to its login page in one place. Exactly these
    /// codes trigger it: `UNAUTHENTICATED` (the session lapsed, was revoked, or the token is gone) and
    /// `SESSION_NETWORK_MISMATCH` (a session bound to its network presented from another one). Credential failures
    /// such as a wrong password (`INVALID_CREDENTIALS`) never trigger it, and neither do codes the server also raises
    /// for sign-in or step-up (`MFA_REQUIRED`, `EMAIL_UNVERIFIED`, `IP_BLOCKED`, ...). A hook that panics never
    /// changes what the caller sees.
    pub on_unauthenticated: Option<UnauthenticatedHook>,
    /// Off by default.
    pub retry_rate_limited: Option<RetryRateLimited>,
    pub request_id: Option<RequestId>,
}

impl ClientOptions {
    /// Options for the API at `base_url` (the application's origin).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: Some(base_url.into()),
            ..Self::default()
        }
    }

    pub fn base_path(mut self, base_path: impl Into<String>) -> Self {
        self.base_path = Some(base_path.into());
        self
    }

    /// A fixed bearer token.
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(TokenSource::Static(token.into()));
        self
    }

    /// A bearer token read at each request.
    pub fn token_fn<F, Fut>(mut self, read: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<String>, BoxError>> + Send + 'static,
    {
        self.token = Some(TokenSource::Dynamic(Arc::new(move || Box::pin(read()))));
        self
    }

    /// Fixed headers for every request.
    pub fn headers<I, K, V>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.headers = Some(HeaderSource::Static(
            headers
                .into_iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
        ));
        self
    }

    /// Headers read at each request.
    pub fn headers_fn<F, Fut>(mut self, read: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<HeaderList, BoxError>> + Send + 'static,
    {
        self.headers = Some(HeaderSource::Dynamic(Arc::new(move || Box::pin(read()))));
        self
    }

    pub fn fetch(mut self, fetch: impl Fetch + 'static) -> Self {
        self.fetch = Some(Arc::new(fetch));
        self
    }

    /// A transport from an async closure.
    pub fn fetch_fn<F, Fut>(self, fetch: F) -> Self
    where
        F: Fn(FetchRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<FetchResponse, BoxError>> + Send + 'static,
    {
        self.fetch(FnFetch(fetch))
    }

    pub fn on_unauthenticated(
        mut self,
        hook: impl Fn(&IamClientError) + Send + Sync + 'static,
    ) -> Self {
        self.on_unauthenticated = Some(Arc::new(hook));
        self
    }

    pub fn retry_rate_limited(mut self, retry: RetryRateLimited) -> Self {
        self.retry_rate_limited = Some(retry);
        self
    }

    pub fn request_id(mut self, request_id: RequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }
}

/// `ClientCallOptions`: per-call cancellation and headers.
#[derive(Clone, Default, Debug)]
pub struct CallOptions {
    pub signal: Option<AbortSignal>,
    pub headers: HeaderList,
}

impl CallOptions {
    pub fn signal(mut self, signal: AbortSignal) -> Self {
        self.signal = Some(signal);
        self
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// `auth` methods whose only server parameter is the credential: their body is always `{}`.
const NO_INPUT_AUTH_METHODS: [&str; 11] = [
    "signOut",
    "getSession",
    "listSessions",
    "revokeOtherSessions",
    "beginPasskeyRegistration",
    "listPasskeys",
    "regenerateRecoveryCodes",
    "disableMfa",
    "listTrustedDevices",
    "revokeTrustedDevices",
    "mfaStatus",
];

/// Methods outside `auth` whose only server parameter is the credential.
const NO_INPUT_METHODS: [&str; 3] = [
    "sts/getCallerIdentity",
    "links/list",
    "clearances/templates",
];

/// Refusals that end the presented session wherever it is used next, so `onUnauthenticated` fires for them.
const SESSION_ENDING_CODES: [&str; 2] = ["UNAUTHENTICATED", "SESSION_NETWORK_MISMATCH"];

/// Names the TypeScript client never routes (they would make the client thenable or reach the prototype).
const RESERVED: [&str; 7] = [
    "then",
    "catch",
    "finally",
    "toJSON",
    "constructor",
    "prototype",
    "__proto__",
];

/// Whether the route takes no input: its body is always `{}`, whatever the caller passes.
pub fn takes_no_input(route: &Route) -> bool {
    (route.group == "auth" && NO_INPUT_AUTH_METHODS.contains(&route.method))
        || NO_INPUT_METHODS.contains(&route.path)
}

fn ascii_word(value: &str, max: usize, allowed: impl Fn(u8) -> bool) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(allowed)
}

/// `routeSegment`: `/^[A-Za-z][A-Za-z0-9_-]*$/` and not a reserved name.
fn route_segment(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        && !RESERVED.contains(&value)
}

fn token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// `bearerToken`: an opaque token (16 to 512 of `A-Z a-z 0-9 _ -`) or an IAM-signed session JWT (three base64url
/// segments of 2-1024, 2-3072 and 2-1024 characters, at most 4096 in all). Anything else never leaves the client.
pub fn bearer_token(value: &str) -> bool {
    let length = value.len();
    if (16..=512).contains(&length) && value.bytes().all(token_char) {
        return true;
    }
    if length > 4096 {
        return false;
    }
    let segments: Vec<&str> = value.split('.').collect();
    let [header, payload, signature] = segments.as_slice() else {
        return false;
    };
    [(header, 1024), (payload, 3072), (signature, 1024)]
        .iter()
        .all(|(segment, max)| segment.len() >= 2 && ascii_word(segment, *max, token_char))
}

/// The request ids the server accepts: `/^[A-Za-z0-9._:-]{1,128}$/`.
fn plain_request_id(value: &str) -> bool {
    ascii_word(value, 128, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
    })
}

/// `/^\/[A-Za-z0-9_/-]+$/` without a trailing slash.
fn valid_base_path(value: &str) -> bool {
    value.len() >= 2
        && value.starts_with('/')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'/' | b'-'))
        && !value.ends_with('/')
}

fn config_error(message: &str) -> Error {
    IamClientError::new("INVALID_CONFIG", message, 0).into()
}

/// HTTP whitespace, which `Headers` strips from both ends of a value.
fn http_trim(value: &str) -> &str {
    value.trim_matches([' ', '\t', '\r', '\n'])
}

/// `new Headers(init)`: lowercase names, values of repeated names joined with `, `; invalid names or values fail.
fn header_list(init: &[(String, String)]) -> Result<Vec<(HeaderName, String)>> {
    let mut out: Vec<(HeaderName, String)> = Vec::new();
    for (name, value) in init {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| Error::other(format!("Invalid header name: {name}")))?;
        let value = http_trim(value);
        if value.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n')) {
            return Err(Error::other(format!("Invalid header value for {name}")));
        }
        match out.iter_mut().find(|(existing, _)| *existing == name) {
            Some((_, combined)) => {
                combined.push_str(", ");
                combined.push_str(value);
            }
            None => out.push((name, value.to_owned())),
        }
    }
    Ok(out)
}

fn set_header(headers: &mut HeaderMap, name: HeaderName, value: &str) -> Result<()> {
    let value = HeaderValue::from_str(value)
        .map_err(|_| Error::other(format!("Invalid header value for {name}")))?;
    headers.insert(name, value);
    Ok(())
}

/// A successful answer: the envelope's `data`, with what an error about it needs.
struct Answer {
    data: Value,
    status: u16,
    request_id: Option<String>,
}

struct Inner {
    base: url::Url,
    base_path: String,
    fetch: Arc<dyn Fetch>,
    token: Option<TokenSource>,
    headers: Option<HeaderSource>,
    on_unauthenticated: Option<UnauthenticatedHook>,
    retry_wait: f64,
    request_id: Option<RequestId>,
}

/// The client (`createIamClient`). Cloning is cheap and shares the configuration.
#[derive(Clone)]
pub struct IamClient {
    inner: Arc<Inner>,
}

impl fmt::Debug for IamClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Symbol.toStringTag` of the TypeScript client.
        f.write_str("BetterIamClient")
    }
}

/// `createIamClient(options)`.
///
/// ```ignore
/// let client = create_iam_client(ClientOptions::new("https://app.example.com"))?;
/// let found = client.tenants().lookup(tenants::LookupInput { slug: Some("acme".into()), ..Default::default() }).await?;
/// client.auth().sign_in(auth::SignInInput { tenant_id: found.tenant_id, email, password, ..Default::default() }).await?;
/// let checks = client.authorize_many(operations::AuthorizeManyInput { tenant_id, checks }).await?;
/// ```
pub fn create_iam_client(options: ClientOptions) -> Result<IamClient> {
    let Some(origin) = options.base_url.as_deref() else {
        return Err(config_error("baseURL is required outside a browser"));
    };
    let base = url::Url::parse(origin)
        .map_err(|_| config_error("baseURL must be an absolute HTTP(S) URL"))?;
    if !matches!(base.scheme(), "http" | "https")
        || !base.username().is_empty()
        || base.password().is_some_and(|password| !password.is_empty())
        || base.query().is_some_and(|query| !query.is_empty())
        || base.fragment().is_some_and(|fragment| !fragment.is_empty())
    {
        return Err(config_error(
            "baseURL must be an HTTP(S) URL without credentials, query, or fragment",
        ));
    }
    let base_path = options
        .base_path
        .clone()
        .unwrap_or_else(|| better_iam_types::routes::BASE_PATH.to_owned());
    if !valid_base_path(&base_path) {
        return Err(config_error(
            "basePath must be an absolute path without a trailing slash",
        ));
    }
    let fetch = match options.fetch.clone() {
        Some(fetch) => fetch,
        None => default_fetch()?,
    };
    let retry_wait = match options.retry_rate_limited {
        Some(retry) => retry.max_wait_ms.unwrap_or(5_000.0),
        None => 0.0,
    };
    // Requests resolve against the origin alone (`new URL(path, base.origin)`).
    let origin = url::Url::parse(&base.origin().ascii_serialization())
        .map_err(|_| config_error("baseURL must be an absolute HTTP(S) URL"))?;
    Ok(IamClient {
        inner: Arc::new(Inner {
            base: origin,
            base_path,
            fetch,
            token: options.token,
            headers: options.headers,
            on_unauthenticated: options.on_unauthenticated,
            retry_wait,
            request_id: options.request_id,
        }),
    })
}

#[cfg(feature = "default-transport")]
fn default_fetch() -> Result<Arc<dyn Fetch>> {
    HyperFetch::new()
        .map(|fetch| Arc::new(fetch) as Arc<dyn Fetch>)
        .map_err(|_| config_error("A Fetch implementation is required"))
}

#[cfg(not(feature = "default-transport"))]
fn default_fetch() -> Result<Arc<dyn Fetch>> {
    Err(config_error("A Fetch implementation is required"))
}

/// The retry wait honours the call's signal: an aborted call settles at once with the signal's reason instead of
/// holding its caller for the whole server-requested wait and sending a doomed request.
async fn sleep(ms: f64, signal: Option<&AbortSignal>) -> Result<()> {
    let duration = Duration::from_secs_f64(if ms.is_finite() && ms > 0.0 {
        ms / 1000.0
    } else {
        0.0
    });
    let Some(signal) = signal else {
        tokio::time::sleep(duration).await;
        return Ok(());
    };
    if let Some(reason) = signal.aborted().then(|| signal.reason()).flatten() {
        return Err(Error::Aborted(reason));
    }
    tokio::select! {
        biased;
        reason = signal.cancelled() => Err(Error::Aborted(reason)),
        () = tokio::time::sleep(duration) => Ok(()),
    }
}

impl IamClient {
    /// `$request`: the escape hatch for plugin endpoints. `path` is relative to the configured base path
    /// (`plugins/reporting/summary`) and must be plain segments; anything else fails with `INVALID_PATH`.
    pub fn request<Output: DeserializeOwned>(
        &self,
        path: impl Into<String>,
        input: &impl Serialize,
    ) -> Call<Output> {
        Call::new(
            self.clone(),
            Cow::Owned(path.into()),
            better_iam_types::to_value(input).map_err(Arc::new),
        )
    }

    /// Calls a route by its typed operation (`client.call(roles::Create, input)`), the generic form of the
    /// per-group methods. Routes that take no input send `{}` whatever `input` holds.
    pub fn call<O: Operation>(&self, _operation: O, input: O::Input) -> Call<O::Output> {
        let route = O::ROUTE;
        let body = if takes_no_input(&route) {
            Ok(Value::Object(Map::new()))
        } else {
            better_iam_types::to_value(&input).map_err(Arc::new)
        };
        Call::new(self.clone(), Cow::Borrowed(route.path), body)
    }

    fn fail(
        &self,
        code: &str,
        message: &str,
        status: u16,
        retry_after_ms: Option<f64>,
        request_id: &Option<String>,
    ) -> IamClientError {
        let mut error = IamClientError::new(code, message, status);
        error.retry_after_ms = retry_after_ms;
        error.request_id = request_id.clone();
        if SESSION_ENDING_CODES.contains(&code)
            && let Some(hook) = &self.inner.on_unauthenticated
        {
            // A hook that fails never changes what the caller sees.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook(&error)));
        }
        error
    }

    async fn send(
        &self,
        path: &str,
        input: &Result<Value, Arc<serde_json::Error>>,
        options: &CallOptions,
    ) -> Result<Answer> {
        match self.attempt(path, input, options).await {
            Err(Error::Client(error))
                if error.code == "RATE_LIMITED"
                    && self.inner.retry_wait > 0.0
                    && error
                        .retry_after_ms
                        .is_some_and(|wait| wait <= self.inner.retry_wait) =>
            {
                sleep(error.retry_after_ms.unwrap_or(0.0), options.signal.as_ref()).await?;
                self.attempt(path, input, options).await
            }
            other => other,
        }
    }

    fn next_request_id(&self) -> Option<String> {
        match &self.inner.request_id {
            Some(RequestId::Custom(supply)) => Some(supply()),
            Some(RequestId::Generate) => Some(uuid::Uuid::new_v4().to_string()),
            None => None,
        }
    }

    async fn attempt(
        &self,
        path: &str,
        input: &Result<Value, Arc<serde_json::Error>>,
        options: &CallOptions,
    ) -> Result<Answer> {
        if path.is_empty() || !path.split('/').all(route_segment) {
            return Err(IamClientError::new(
                "INVALID_PATH",
                "IAM routes must use plain relative path segments",
                0,
            )
            .into());
        }
        let configured = match &self.inner.headers {
            Some(HeaderSource::Static(list)) => list.clone(),
            Some(HeaderSource::Dynamic(read)) => read().await.map_err(Error::Other)?,
            None => Vec::new(),
        };
        let mut headers = HeaderMap::new();
        for (name, value) in header_list(&configured)? {
            set_header(&mut headers, name, &value)?;
        }
        for (name, value) in header_list(&options.headers)? {
            set_header(&mut headers, name, &value)?;
        }
        // These headers are invariant: the server's CSRF boundary requires both.
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            HeaderName::from_static("x-better-iam"),
            HeaderValue::from_static("1"),
        );
        let request_id = self.next_request_id();
        if let Some(id) = &request_id {
            if !plain_request_id(id) {
                return Err(config_error("requestId must be a short plain token"));
            }
            set_header(&mut headers, HeaderName::from_static("x-request-id"), id)?;
        }
        let token = match &self.inner.token {
            Some(TokenSource::Static(token)) => Some(token.clone()),
            Some(TokenSource::Dynamic(read)) => read().await.map_err(Error::Other)?,
            None => None,
        };
        if let Some(token) = token {
            if !bearer_token(&token) {
                return Err(
                    IamClientError::new("INVALID_TOKEN", "Invalid bearer token format", 0).into(),
                );
            }
            set_header(
                &mut headers,
                http::header::AUTHORIZATION,
                &format!("Bearer {token}"),
            )?;
        }
        let body = match input {
            Ok(Value::Null) => "{}".to_owned(),
            Ok(value) => better_iam_core::js::stringify(value),
            Err(_) => {
                return Err(IamClientError::new(
                    "INVALID_INPUT",
                    "Request input must be serializable JSON",
                    0,
                )
                .into());
            }
        };
        let url = self
            .inner
            .base
            .join(&format!("{}/{path}", self.inner.base_path))
            .map_err(|_| {
                IamClientError::new(
                    "INVALID_PATH",
                    "IAM routes must use plain relative path segments",
                    0,
                )
            })?;
        let request = FetchRequest {
            url: url.into(),
            method: Method::POST,
            headers,
            body,
            credentials: "include",
            redirect: "error",
            cache: "no-store",
            signal: options.signal.clone(),
        };
        let pending = self.inner.fetch.fetch(request);
        let response = match &options.signal {
            Some(signal) => {
                if let Some(reason) = signal.aborted().then(|| signal.reason()).flatten() {
                    return Err(Error::Aborted(reason));
                }
                tokio::select! {
                    biased;
                    reason = signal.cancelled() => return Err(Error::Aborted(reason)),
                    response = pending => response,
                }
            }
            None => pending.await,
        }
        .map_err(Error::Fetch)?;
        let status = response.status;
        let invalid =
            |message: &str| self.fail("INVALID_RESPONSE", message, status, None, &request_id);
        let body = response
            .body
            .strip_prefix(b"\xEF\xBB\xBF")
            .unwrap_or(&response.body);
        let envelope: Value = serde_json::from_str(&String::from_utf8_lossy(body))
            .map_err(|_| invalid("The IAM server returned an invalid response"))?;
        let Value::Object(mut envelope) = envelope else {
            return Err(invalid("The IAM server returned an invalid response").into());
        };
        if let Some(error) = envelope.get("error") {
            let code = error.get("code").and_then(Value::as_str);
            let message = error.get("message").and_then(Value::as_str);
            let (Some(code), Some(message)) = (code.filter(|_| error.is_object()), message) else {
                return Err(invalid("The IAM server returned an invalid error response").into());
            };
            let from_body = error.get("retryAfterMs").and_then(Value::as_f64);
            let header = retry_after_header(&response.headers);
            let retry_after_ms = from_body
                .or_else(|| (header.is_finite() && header > 0.0).then_some(header * 1000.0));
            let mut failure = self.fail(code, message, status, retry_after_ms, &request_id);
            if let Some(region) = error.get("region").and_then(Value::as_str) {
                failure.region = Some(region.to_owned());
            }
            if let Some(location) =
                error
                    .get("location")
                    .and_then(Value::as_str)
                    .filter(|location| {
                        location.starts_with("http://") || location.starts_with("https://")
                    })
            {
                failure.location = Some(location.to_owned());
            }
            return Err(failure.into());
        }
        if !response.ok() {
            return Err(self
                .fail(
                    "HTTP_ERROR",
                    "The IAM server rejected the request",
                    status,
                    None,
                    &request_id,
                )
                .into());
        }
        let Some(data) = envelope.remove("data") else {
            return Err(invalid("The IAM server returned an invalid response").into());
        };
        Ok(Answer {
            data,
            status,
            request_id,
        })
    }
}

/// `Number(response.headers.get('retry-after'))`: every value joined with `, `, absent as `null` (0).
fn retry_after_header(headers: &HeaderMap) -> f64 {
    let values: Vec<String> = headers
        .get_all(http::header::RETRY_AFTER)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect();
    if values.is_empty() {
        return 0.0;
    }
    better_iam_core::js::string_to_number(&values.join(", "))
}

/// One pending call: await it, or set its signal and headers first.
///
/// ```ignore
/// let controller = AbortController::new();
/// let session = client.auth().get_session().signal(controller.signal()).header("x-trace-id", "t1").await?;
/// ```
#[must_use = "a call does nothing until it is awaited"]
pub struct Call<Output> {
    client: IamClient,
    path: Cow<'static, str>,
    input: Result<Value, Arc<serde_json::Error>>,
    options: CallOptions,
    output: PhantomData<fn() -> Output>,
}

impl<Output> Call<Output> {
    fn new(
        client: IamClient,
        path: Cow<'static, str>,
        input: Result<Value, Arc<serde_json::Error>>,
    ) -> Self {
        Self {
            client,
            path,
            input,
            options: CallOptions::default(),
            output: PhantomData,
        }
    }

    /// The path below the base path (`roles/create`).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Cancels the call when `signal` is aborted.
    pub fn signal(mut self, signal: AbortSignal) -> Self {
        self.options.signal = Some(signal);
        self
    }

    /// Adds a header for this call; it replaces a configured header of the same name.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.headers.push((name.into(), value.into()));
        self
    }

    /// Replaces the call options.
    pub fn options(mut self, options: CallOptions) -> Self {
        self.options = options;
        self
    }
}

impl<Output: DeserializeOwned> Call<Output> {
    /// Sends the call (what awaiting it does).
    pub async fn send(self) -> Result<Output> {
        let answer = self
            .client
            .send(&self.path, &self.input, &self.options)
            .await?;
        serde_json::from_value(answer.data).map_err(|_| {
            self.client
                .fail(
                    "INVALID_RESPONSE",
                    "The IAM server returned an invalid response",
                    answer.status,
                    None,
                    &answer.request_id,
                )
                .into()
        })
    }
}

impl<Output: DeserializeOwned + Send + 'static> IntoFuture for Call<Output> {
    type Output = Result<Output>;
    type IntoFuture = BoxFuture<'static, Result<Output>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.send())
    }
}

/// The challenge of a sign-in that still needs its MFA step (`{ tenantId, challenge }`), the credential of
/// `auth.beginMfa` and `auth.confirmMfa` during that step.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaChallenge {
    pub tenant_id: String,
    pub challenge: String,
}

/// The input of `auth.confirmMfa`: the sign-in challenge when confirming during sign-in, none when an enrolled
/// session confirms its own enrolment.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmMfaInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<MfaChallenge>,
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remember_device: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_segments_follow_the_typescript_pattern() {
        assert!(route_segment("roles"));
        assert!(route_segment("get-Thing_2"));
        assert!(!route_segment("2fa"));
        assert!(!route_segment(""));
        assert!(!route_segment(".."));
        assert!(!route_segment("then"));
        assert!(!route_segment("__proto__"));
        assert!(!route_segment("https:"));
    }

    #[test]
    fn base_paths_are_absolute_without_a_trailing_slash() {
        assert!(valid_base_path("/api/iam"));
        assert!(valid_base_path("/custom/iam"));
        assert!(!valid_base_path("/"));
        assert!(!valid_base_path("/api/"));
        assert!(!valid_base_path("api"));
        assert!(!valid_base_path("/api.iam"));
    }

    #[test]
    fn request_ids_are_plain_tokens() {
        assert!(plain_request_id("req-one"));
        assert!(plain_request_id("a.b_c:d-e"));
        assert!(!plain_request_id("not valid!"));
        assert!(!plain_request_id(""));
        assert!(!plain_request_id(&"a".repeat(129)));
    }
}
