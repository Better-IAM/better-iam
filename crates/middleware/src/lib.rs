//! Framework middleware for Better IAM: the Rust port of `@better-iam/middleware`.
//!
//! - [`IamRequest`] holds the per-request helpers every adapter exposes (`getSession`, `requireSession`,
//!   `require`, `can`, `authorize`, `listAccessible`, `plan`, `assertion`, an in-process client, `signOut`), with
//!   sessions and decisions memoized for the request and cookies the in-process client receives counting for later
//!   calls ([`create_request_helpers`]).
//! - [`layer::IamTower`] is the framework integration (the Express adapter's counterpart, written as a tower layer):
//!   it serves the IAM API under its `serve` prefixes through the server's node transport, attaches [`IamRequest`] to
//!   every other request, and builds route guards (session, step-up, authorization, CSRF origin check) that answer
//!   refusals with the IAM JSON error envelope or, for page navigations, a redirect to the login / step-up page.
//! - The `axum` feature makes [`IamRequest`] an extractor and [`MiddlewareError`] a response; the `actix-web` feature
//!   provides the same integration as actix-web middleware.
//!
//! The helpers in this file are the framework-neutral pieces (`index.ts`): step-up checks, cookies, redirects, the
//! refusal answer, and the CSRF origin check.

mod dates;
mod helpers;
mod iam;
pub mod layer;

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "actix-web")]
pub mod actix;

use std::sync::Arc;

use better_iam_core::IamError;
use futures::future::BoxFuture;
use http::HeaderMap;
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use url::Url;

pub use better_iam_core::CredentialInput;
pub use better_iam_server::options::ResourceTarget as ResourceRef;
pub use helpers::IamRequest;
pub use helpers::{
    AssertionInput, AuthorizeInput, AuthorizeResult, InProcessClient, ListAccessibleInput,
    PlanInput, RequestBinding, RequestHelperOptions, create_request_helpers,
};
pub use iam::{EndpointRef, IamLike, IamSource, NodeRead};

/// The error type of the helpers and adapters: an IAM refusal (anything carrying an IAM `code` and an HTTP `status`:
/// the server's `IamError`, the in-process client's errors, [`IamRequestError`]) or any other failure (a plain
/// JavaScript `Error` / `TypeError` in the TypeScript package).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum MiddlewareError {
    #[error("{0}")]
    Refusal(IamRequestError),
    #[error("{0}")]
    Other(String),
}

impl From<IamError> for MiddlewareError {
    fn from(error: IamError) -> Self {
        MiddlewareError::Refusal(IamRequestError::from(error))
    }
}

impl From<IamRequestError> for MiddlewareError {
    fn from(error: IamRequestError) -> Self {
        MiddlewareError::Refusal(error)
    }
}

/// Why a session must step up (`StepUpFailure['reason']`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StepUpReason {
    Mfa,
    Recent,
    Impersonation,
}

impl StepUpReason {
    pub fn as_str(self) -> &'static str {
        match self {
            StepUpReason::Mfa => "mfa",
            StepUpReason::Recent => "recent",
            StepUpReason::Impersonation => "impersonation",
        }
    }
}

/// A refusal raised by the request helpers and guards, with the IAM `code` and HTTP `status`. `reason` is set for
/// step-up failures (`mfa`, `recent`, `impersonation`). Framework adapters turn it into the IAM JSON error envelope
/// or, for page navigations, a redirect to the login / step-up page. Refusals that came from the server or the
/// in-process client keep their extra members (`retryAfterMs`, `region`, `location`) in `details`.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{message}")]
pub struct IamRequestError {
    pub code: String,
    pub message: String,
    pub status: u16,
    pub reason: Option<StepUpReason>,
    pub details: Option<Box<better_iam_core::IamErrorDetails>>,
}

impl IamRequestError {
    /// `new IamRequestError(code, message, status, reason?)`.
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        status: u16,
        reason: Option<StepUpReason>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            status,
            reason,
            details: None,
        }
    }
}

impl From<IamError> for IamRequestError {
    fn from(error: IamError) -> Self {
        Self {
            code: error.code,
            message: error.message,
            status: error.status,
            reason: None,
            details: error.details,
        }
    }
}

impl From<IamRequestError> for IamError {
    fn from(error: IamRequestError) -> Self {
        IamError {
            code: error.code,
            message: error.message,
            status: error.status,
            details: error.details,
        }
    }
}

/// `mfa` of a step-up requirement: `true` needs a session that completed MFA; `'fresh'` also refuses remembered
/// devices, impersonation, assumed roles, and API keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StepUpMfa {
    #[default]
    Off,
    On,
    Fresh,
}

impl StepUpMfa {
    fn truthy(self) -> bool {
        !matches!(self, StepUpMfa::Off)
    }
}

impl<'de> Deserialize<'de> for StepUpMfa {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::Bool(true) => Ok(StepUpMfa::On),
            Value::Bool(false) => Ok(StepUpMfa::Off),
            Value::String(value) if value == "fresh" => Ok(StepUpMfa::Fresh),
            _ => Err(serde::de::Error::custom(
                "stepUp.mfa must be true, false, or 'fresh'",
            )),
        }
    }
}

/// Extra assurance a session must show. `mfa` (see [`StepUpMfa`]); `max_age_ms` needs a recent sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StepUpRequirement {
    #[serde(default)]
    pub mfa: Option<StepUpMfa>,
    #[serde(default)]
    pub max_age_ms: Option<f64>,
}

/// A failed step-up check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepUpFailure {
    /// `MFA_REQUIRED`, `RECENT_AUTH_REQUIRED` or `IMPERSONATION_RESTRICTED`.
    pub code: &'static str,
    pub reason: StepUpReason,
    pub message: &'static str,
    /// Always 403.
    pub status: u16,
}

const AUTHENTICATION_CODES: [&str; 5] = [
    "UNAUTHENTICATED",
    "MFA_REQUIRED",
    "EMAIL_UNVERIFIED",
    "TENANT_INACTIVE",
    "TENANT_UNAVAILABLE",
];

/// The IAM code an error carries, if any.
pub fn error_code(error: &MiddlewareError) -> Option<&str> {
    match error {
        MiddlewareError::Refusal(refusal) => Some(&refusal.code),
        MiddlewareError::Other(_) => None,
    }
}

/// The HTTP status an error carries, if any.
pub fn error_status(error: &MiddlewareError) -> Option<u16> {
    match error {
        MiddlewareError::Refusal(refusal) => Some(refusal.status),
        MiddlewareError::Other(_) => None,
    }
}

/// True for the errors `getSession` raises when there is no usable session.
pub fn is_authentication_error(error: &MiddlewareError) -> bool {
    error_code(error).is_some_and(|code| AUTHENTICATION_CODES.contains(&code))
}

/// True for any error carrying an IAM code and an HTTP status (server `IamError`, client errors, `IamRequestError`).
pub fn is_iam_refusal(error: &MiddlewareError) -> bool {
    matches!(error, MiddlewareError::Refusal(_))
}

const INVALID_BASE: &str = "http://better-iam.invalid";

/// `url.search`: `?query`, or empty when the query is absent or empty.
pub(crate) fn search_of(url: &Url) -> String {
    match url.query() {
        Some(query) if !query.is_empty() => format!("?{query}"),
        _ => String::new(),
    }
}

/// `url.hash`: `#fragment`, or empty when the fragment is absent or empty.
pub(crate) fn hash_of(url: &Url) -> String {
    match url.fragment() {
        Some(fragment) if !fragment.is_empty() => format!("#{fragment}"),
        _ => String::new(),
    }
}

/// `url.origin`.
pub(crate) fn origin_of(url: &Url) -> String {
    url.origin().ascii_serialization()
}

/// `url.host`: the host with its port when it is not the scheme's default.
pub(crate) fn host_of(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

/// A same-site relative path safe to redirect to, or `fallback`. Refuses schemes, `//host`, and backslash tricks.
pub fn safe_redirect_path(value: Option<&str>, fallback: &str) -> String {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return fallback.to_owned();
    };
    if !value.starts_with('/')
        || value.starts_with("//")
        || value.chars().any(|c| c == '\\' || c <= '\u{1f}')
    {
        return fallback.to_owned();
    }
    let base = Url::parse(INVALID_BASE).expect("static base URL");
    let Ok(url) = base.join(value) else {
        return fallback.to_owned();
    };
    if origin_of(&url) != INVALID_BASE {
        return fallback.to_owned();
    }
    let path = format!("{}{}{}", url.path(), search_of(&url), hash_of(&url));
    if path.starts_with("//") {
        fallback.to_owned()
    } else {
        path
    }
}

/// Appends query parameters, skipping `None` values.
pub fn with_query(target: &str, params: &[(&str, Option<&str>)]) -> String {
    let entries: Vec<(&str, &str)> = params
        .iter()
        .filter_map(|(name, value)| value.map(|value| (*name, value)))
        .collect();
    if entries.is_empty() {
        return target.to_owned();
    }
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(entries)
        .finish();
    format!(
        "{target}{}{query}",
        if target.contains('?') { '&' } else { '?' }
    )
}

/// True when `pathname` is `prefix` or below it on a segment boundary.
pub fn under_path(pathname: &str, prefix: &str) -> bool {
    let base = if prefix.ends_with('/') && prefix != "/" {
        &prefix[..prefix.len() - 1]
    } else {
        prefix
    };
    base == "/" || pathname == base || pathname.starts_with(&format!("{base}/"))
}

/// The tenant a session acts in (`session.session.tenantId`).
pub fn tenant_of(session: &Value) -> Option<String> {
    session
        .get("session")
        .and_then(|inner| inner.get("tenantId"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// JavaScript truthiness of a JSON value.
pub(crate) fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(number)) => {
            let value = number.as_f64().unwrap_or(0.0);
            value != 0.0 && !value.is_nan()
        }
        Some(Value::String(value)) => !value.is_empty(),
        Some(_) => true,
    }
}

/// Checks a session against a step-up requirement; `None` when it qualifies. Accepts the `getSession` result or its
/// inner session record. Impersonated sessions always fail a recency requirement, as the server's own check does.
/// A `max_age_ms` that is not a positive, finite number fails with a `TypeError`-like [`MiddlewareError::Other`].
pub fn check_step_up(
    session: &Value,
    requirement: &StepUpRequirement,
    now: f64,
) -> Result<Option<StepUpFailure>, MiddlewareError> {
    let mfa = requirement.mfa;
    let max_age_ms = requirement.max_age_ms;
    if let Some(max_age) = max_age_ms
        && (!max_age.is_finite() || max_age <= 0.0)
    {
        return Err(MiddlewareError::Other(
            "stepUp.maxAgeMs must be a positive, finite number of milliseconds".into(),
        ));
    }
    let empty = serde_json::Map::new();
    let outer = session.as_object().unwrap_or(&empty);
    let record = match outer.get("session") {
        Some(Value::Object(inner)) => inner,
        _ => outer,
    };
    let failure = |code, reason, message| StepUpFailure {
        code,
        reason,
        message,
        status: 403,
    };
    let impersonated = truthy(record.get("impersonatorId"))
        || record.get("method").and_then(Value::as_str) == Some("impersonation");
    if impersonated && (max_age_ms.is_some() || mfa == Some(StepUpMfa::Fresh)) {
        return Ok(Some(failure(
            "IMPERSONATION_RESTRICTED",
            StepUpReason::Impersonation,
            "This operation is unavailable while impersonating a member",
        )));
    }
    if mfa.is_some_and(StepUpMfa::truthy) && record.get("mfa") != Some(&Value::Bool(true)) {
        return Ok(Some(failure(
            "MFA_REQUIRED",
            StepUpReason::Mfa,
            "Multi-factor authentication is required",
        )));
    }
    if mfa == Some(StepUpMfa::Fresh) {
        if truthy(record.get("trustedDeviceId")) {
            return Ok(Some(failure(
                "MFA_REQUIRED",
                StepUpReason::Mfa,
                "Verify your second factor again to continue",
            )));
        }
        if record.get("kind").and_then(Value::as_str) != Some("user")
            || truthy(record.get("sourceSessionId"))
        {
            return Ok(Some(failure(
                "MFA_REQUIRED",
                StepUpReason::Mfa,
                "This credential cannot show a fresh second factor; use a signed-in session",
            )));
        }
    }
    if let Some(max_age) = max_age_ms {
        let at = record.get("authenticatedAt").and_then(Value::as_f64);
        let recent = match at {
            Some(at) => at <= now && now - at <= max_age,
            None => false,
        };
        if !recent {
            return Ok(Some(failure(
                "RECENT_AUTH_REQUIRED",
                StepUpReason::Recent,
                "Reauthenticate to perform this operation",
            )));
        }
    }
    Ok(None)
}

/// Splits a `Cookie` header into name/value pairs (values left encoded); the first of a repeated name wins.
pub fn parse_cookie_header(header: Option<&str>) -> IndexMap<String, String> {
    let mut cookies = IndexMap::new();
    for part in header.unwrap_or_default().split(';') {
        let Some(separator) = part.find('=') else {
            continue;
        };
        if separator == 0 {
            continue;
        }
        let name = better_iam_core::js::trim(&part[..separator]);
        if !name.is_empty() && !cookies.contains_key(name) {
            cookies.insert(
                name.to_owned(),
                better_iam_core::js::trim(&part[separator + 1..]).to_owned(),
            );
        }
    }
    cookies
}

/// What a `Set-Cookie` header sets: its name, raw value, and whether it deletes the cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetCookieSummary {
    pub name: String,
    pub value: String,
    pub deleted: bool,
}

/// The name, raw value, and whether a `Set-Cookie` header deletes the cookie (`Max-Age=0` or a past `Expires`).
pub fn set_cookie_summary(header: &str, now: f64) -> Option<SetCookieSummary> {
    let mut parts = header.split(';');
    let pair = parts.next().unwrap_or_default();
    let separator = pair.find('=')?;
    if pair.is_empty() || separator == 0 {
        return None;
    }
    let mut deleted = false;
    for attribute in parts {
        let mut pieces = attribute.split('=');
        let key = pieces.next().unwrap_or_default();
        let rest: Vec<&str> = pieces.collect();
        let joined = rest.join("=");
        let setting = better_iam_core::js::trim(&joined);
        let name = better_iam_core::js::to_lower(better_iam_core::js::trim(key));
        if name == "max-age" && is_integer_text(setting) {
            let value: f64 = setting.parse().unwrap_or(f64::NAN);
            if value <= 0.0 {
                deleted = true;
            }
        }
        if name == "expires"
            && let Some(at) = dates::parse_date(setting)
            && at <= now
        {
            deleted = true;
        }
    }
    Some(SetCookieSummary {
        name: better_iam_core::js::trim(&pair[..separator]).to_owned(),
        value: better_iam_core::js::trim(&pair[separator + 1..]).to_owned(),
        deleted,
    })
}

/// `/^-?\d+$/`.
fn is_integer_text(value: &str) -> bool {
    let digits = value.strip_prefix('-').unwrap_or(value);
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

/// `headers.get(name)`: every value of a header joined with `, `, as the Fetch `Headers` class answers.
pub fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter().peekable();
    values.peek()?;
    Some(
        values
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .collect::<Vec<_>>()
            .join(", "),
    )
}

/// The credential a set of request headers carries, with each header's values joined as `Headers` holds them.
pub fn credential_of(headers: &HeaderMap) -> CredentialInput {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for name in headers.keys() {
        if let Some(value) = header_value(headers, name.as_str()) {
            pairs.push((name.as_str().to_owned(), value));
        }
    }
    CredentialInput {
        headers: Some(pairs),
        token: None,
    }
}

/// The IAM API's JSON error envelope, used by every adapter for refusals.
pub fn error_body(code: &str, message: &str) -> String {
    better_iam_core::js::stringify(&serde_json::json!({
        "error": { "code": code, "message": message }
    }))
}

/// The request facts a refusal answer depends on.
#[derive(Debug, Clone)]
pub struct RefusalRequest<'a> {
    pub url: &'a Url,
    pub headers: &'a HeaderMap,
    pub method: &'a str,
}

/// How a guard answers a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalResponse {
    /// A page navigation sent to the login or step-up page (303).
    Redirect(String),
    /// The JSON error envelope.
    Json { status: u16, body: String },
}

/// Where page navigations go when signed out (`loginPath`) or when the session must step up (`stepUpPath`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefusalPages {
    pub login_path: Option<String>,
    pub step_up_path: Option<String>,
}

/// How a guard should answer a refusal: a redirect for page navigations when a page is configured, else JSON.
pub fn refusal_response(
    error: &IamRequestError,
    request: &RefusalRequest<'_>,
    pages: &RefusalPages,
) -> RefusalResponse {
    let navigation = (request.method == "GET" || request.method == "HEAD")
        && header_value(request.headers, "accept")
            .unwrap_or_default()
            .contains("text/html");
    if navigation {
        let next = safe_redirect_path(
            Some(&format!("{}{}", request.url.path(), search_of(request.url))),
            "/",
        );
        if error.status == 401
            && let Some(login) = pages.login_path.as_deref().filter(|path| !path.is_empty())
        {
            return RefusalResponse::Redirect(with_query(login, &[("next", Some(&next))]));
        }
        if let Some(reason) = error.reason
            && let Some(step_up) = pages
                .step_up_path
                .as_deref()
                .filter(|path| !path.is_empty())
        {
            return RefusalResponse::Redirect(with_query(
                step_up,
                &[("next", Some(&next)), ("reason", Some(reason.as_str()))],
            ));
        }
    }
    RefusalResponse::Json {
        status: error.status,
        body: error_body(&error.code, &error.message),
    }
}

const SAFE_METHODS: [&str; 3] = ["GET", "HEAD", "OPTIONS"];
pub(crate) const SESSION_COOKIES: [&str; 2] = ["better-iam.session", "__Host-better-iam.session"];

/// The request facts the CSRF boundary reads.
#[derive(Debug, Clone)]
pub struct OriginRequest<'a> {
    pub method: &'a str,
    pub url: &'a Url,
    pub headers: &'a HeaderMap,
}

/// The CSRF boundary for application routes: a state-changing request authenticated by the session cookie (no
/// `Authorization` header) must come from this application's origin, the IAM origin, or a trusted origin. Session
/// cookies are `SameSite=Lax`, which still sends them from sibling subdomains, so the Origin check matters.
/// Returns the refusal, or `None` when the request may proceed.
pub fn check_request_origin<I, S>(
    request: &OriginRequest<'_>,
    trusted_origins: I,
) -> Option<IamRequestError>
where
    I: IntoIterator<Item = Option<S>>,
    S: AsRef<str>,
{
    let headers = request.headers;
    if SAFE_METHODS.contains(&request.method.to_ascii_uppercase().as_str())
        || headers.contains_key("authorization")
    {
        return None;
    }
    let cookies = parse_cookie_header(header_value(headers, "cookie").as_deref());
    if !SESSION_COOKIES
        .iter()
        .any(|name| cookies.contains_key(*name))
    {
        return None;
    }
    if header_value(headers, "sec-fetch-site").as_deref() == Some("same-origin") {
        return None;
    }
    let Some(origin) = header_value(headers, "origin") else {
        return Some(IamRequestError::new(
            "CSRF_REJECTED",
            "Cookie requests require Origin",
            403,
            None,
        ));
    };
    // `null` is what sandboxed frames, redirects and no-referrer posts send, and also the `.origin` of non-http
    // trusted entries such as `capacitor://localhost`, so it must never match anything.
    if origin == "null" {
        return Some(untrusted());
    }
    let first = |name: &str| {
        header_value(headers, name).map(|value| {
            better_iam_core::js::trim(value.split(',').next().unwrap_or_default()).to_owned()
        })
    };
    let forwarded_host = first("x-forwarded-host").filter(|host| !host.is_empty());
    let forwarded_proto = first("x-forwarded-proto");
    let own = [
        origin_of(request.url),
        match forwarded_host {
            Some(host) => format!(
                "{}://{host}",
                forwarded_proto.unwrap_or_else(|| request.url.scheme().to_owned())
            ),
            None => String::new(),
        },
    ];
    let allowed = own
        .iter()
        .map(|entry| Some(entry.as_str().to_owned()))
        .chain(
            trusted_origins
                .into_iter()
                .map(|entry| entry.map(|entry| entry.as_ref().to_owned())),
        )
        .any(|entry| match entry {
            Some(entry) if !entry.is_empty() => Url::parse(&entry)
                .map(|url| origin_of(&url) == origin)
                .unwrap_or(false),
            _ => false,
        });
    if allowed { None } else { Some(untrusted()) }
}

fn untrusted() -> IamRequestError {
    IamRequestError::new("UNTRUSTED_ORIGIN", "Origin is not trusted", 403, None)
}

/// A guard callback that derives the resource from the request and the session.
pub type ResourceFn<R> = Arc<
    dyn Fn(&R, &Value) -> BoxFuture<'static, Result<ResourceRef, MiddlewareError>> + Send + Sync,
>;
/// A guard callback that derives the tenant from the request and the session.
pub type TenantFn<R> =
    Arc<dyn Fn(&R, &Value) -> BoxFuture<'static, Result<String, MiddlewareError>> + Send + Sync>;

/// The authorization a guard checks.
pub struct AuthorizeRule<R> {
    pub action: String,
    /// Defaults to the tenant itself (`iam/{tenantId}`).
    pub resource: Option<ResourceFn<R>>,
    /// Defaults to the session's tenant.
    pub tenant_id: Option<TenantFn<R>>,
}

impl<R> Clone for AuthorizeRule<R> {
    fn clone(&self) -> Self {
        Self {
            action: self.action.clone(),
            resource: self.resource.clone(),
            tenant_id: self.tenant_id.clone(),
        }
    }
}

impl<R> AuthorizeRule<R> {
    /// A rule for `action` on the tenant itself.
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            resource: None,
            tenant_id: None,
        }
    }

    /// The resource, derived synchronously from the request and the session.
    pub fn resource(
        mut self,
        resource: impl Fn(&R, &Value) -> ResourceRef + Send + Sync + 'static,
    ) -> Self {
        self.resource = Some(Arc::new(move |request, session| {
            let value = resource(request, session);
            Box::pin(async move { Ok(value) })
        }));
        self
    }

    /// The resource, derived by an asynchronous callback.
    pub fn resource_async(mut self, resource: ResourceFn<R>) -> Self {
        self.resource = Some(resource);
        self
    }

    /// The tenant, derived synchronously from the request and the session.
    pub fn tenant_id(
        mut self,
        tenant: impl Fn(&R, &Value) -> String + Send + Sync + 'static,
    ) -> Self {
        self.tenant_id = Some(Arc::new(move |request, session| {
            let value = tenant(request, session);
            Box::pin(async move { Ok(value) })
        }));
        self
    }

    /// The tenant, derived by an asynchronous callback.
    pub fn tenant_id_async(mut self, tenant: TenantFn<R>) -> Self {
        self.tenant_id = Some(tenant);
        self
    }
}

/// What a guard checks: a session, then optional step-up, then an optional authorization.
pub struct GuardSpec<R> {
    pub step_up: Option<StepUpRequirement>,
    pub authorize: Option<AuthorizeRule<R>>,
}

impl<R> Default for GuardSpec<R> {
    fn default() -> Self {
        Self {
            step_up: None,
            authorize: None,
        }
    }
}

impl<R> Clone for GuardSpec<R> {
    fn clone(&self) -> Self {
        Self {
            step_up: self.step_up,
            authorize: self.authorize.clone(),
        }
    }
}

/// Options every framework adapter shares for its guards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardOptions {
    /// Origins besides the request's own and the IAM origin that may send cookie-authenticated unsafe requests.
    pub trusted_origins: Vec<String>,
    /// Check `Origin` on cookie-authenticated POST/PUT/PATCH/DELETE requests in guards (default true).
    pub csrf: bool,
}

impl Default for GuardOptions {
    fn default() -> Self {
        Self {
            trusted_origins: Vec::new(),
            csrf: true,
        }
    }
}

/// The origin check a guard runs first.
pub struct GuardOrigin<'a> {
    pub method: &'a str,
    pub url: &'a Url,
    pub headers: &'a HeaderMap,
    pub trusted_origins: Vec<Option<String>>,
}

/// Runs a guard; resolves with the session or fails with the refusal (`IamRequestError` or the server's error).
/// With `origin`, a cookie-authenticated unsafe request from an untrusted origin is refused first.
pub async fn enforce_guard<T: IamLike, R>(
    helpers: &IamRequest<T>,
    request: &R,
    spec: &GuardSpec<R>,
    origin: Option<GuardOrigin<'_>>,
) -> Result<Value, MiddlewareError> {
    if let Some(origin) = origin {
        let check = OriginRequest {
            method: origin.method,
            url: origin.url,
            headers: origin.headers,
        };
        if let Some(refusal) = check_request_origin(&check, origin.trusted_origins) {
            return Err(refusal.into());
        }
    }
    let session = helpers.require_session(spec.step_up.as_ref()).await?;
    if let Some(rule) = &spec.authorize {
        let tenant_id = match &rule.tenant_id {
            Some(tenant) => Some(tenant(request, &session).await?),
            None => tenant_of(&session),
        };
        let Some(tenant_id) = tenant_id.filter(|tenant| !tenant.is_empty()) else {
            return Err(IamRequestError::new(
                "INVALID_INPUT",
                "No tenant to authorize in",
                400,
                None,
            )
            .into());
        };
        let resource = match &rule.resource {
            Some(resource) => resource(request, &session).await?,
            None => ResourceRef {
                kind: "iam".into(),
                id: tenant_id.clone(),
            },
        };
        helpers
            .require(&rule.action, Some(resource), Some(&tenant_id))
            .await?;
    }
    Ok(session)
}

/// A refusal a route handler returned, left on its response by the framework adapters (`errorHandler`) so the
/// middleware can answer page navigations with a redirect instead of the JSON envelope.
#[derive(Debug, Clone)]
pub struct RefusalMarker(pub IamRequestError);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_cookies_recognises_deletions_and_keeps_redirects_on_this_site() {
        let cookies = parse_cookie_header(Some("a=1; b=x%20y; a=2; junk"));
        assert_eq!(
            cookies.into_iter().collect::<Vec<_>>(),
            vec![("a".into(), "1".into()), ("b".into(), "x%20y".into())]
        );
        let now = better_iam_core::js::now_ms();
        assert_eq!(
            set_cookie_summary("s=abc; Path=/; HttpOnly", now),
            Some(SetCookieSummary {
                name: "s".into(),
                value: "abc".into(),
                deleted: false
            })
        );
        assert!(set_cookie_summary("s=; Max-Age=0", now).unwrap().deleted);
        assert!(
            set_cookie_summary("s=; Expires=Thu, 01 Jan 1970 00:00:00 GMT", now)
                .unwrap()
                .deleted
        );
        assert_eq!(safe_redirect_path(Some("//evil.test"), "/"), "/");
        assert_eq!(safe_redirect_path(Some("/ok?x=1"), "/"), "/ok?x=1");
        let fresh = StepUpRequirement {
            mfa: Some(StepUpMfa::Fresh),
            max_age_ms: None,
        };
        assert_eq!(
            check_step_up(
                &json!({ "session": { "mfa": true, "kind": "user" } }),
                &fresh,
                now
            )
            .unwrap(),
            None
        );
        assert_eq!(
            check_step_up(
                &json!({ "session": { "mfa": true, "trustedDeviceId": "d" } }),
                &fresh,
                now
            )
            .unwrap()
            .map(|failure| failure.code),
            Some("MFA_REQUIRED")
        );
        // POST navigations never redirect: a form post gets the JSON refusal.
        let error = IamRequestError::new("UNAUTHENTICATED", "A session is required", 401, None);
        let url = Url::parse("http://x/app").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("accept", "text/html".parse().unwrap());
        let pages = RefusalPages {
            login_path: Some("/login".into()),
            step_up_path: None,
        };
        let post = RefusalRequest {
            url: &url,
            headers: &headers,
            method: "POST",
        };
        assert!(matches!(
            refusal_response(&error, &post, &pages),
            RefusalResponse::Json { status: 401, .. }
        ));
        let get = RefusalRequest {
            method: "GET",
            ..post
        };
        assert_eq!(
            refusal_response(&error, &get, &pages),
            RefusalResponse::Redirect("/login?next=%2Fapp".into())
        );
    }

    #[test]
    fn step_up_validates_max_age_and_checks_recency_and_impersonation() {
        let now = 1_000_000.0;
        let bad = StepUpRequirement {
            mfa: None,
            max_age_ms: Some(0.0),
        };
        assert_eq!(
            check_step_up(&json!({}), &bad, now),
            Err(MiddlewareError::Other(
                "stepUp.maxAgeMs must be a positive, finite number of milliseconds".into()
            ))
        );
        let recent = StepUpRequirement {
            mfa: None,
            max_age_ms: Some(1000.0),
        };
        assert_eq!(
            check_step_up(&json!({ "authenticatedAt": now - 500.0 }), &recent, now).unwrap(),
            None
        );
        assert_eq!(
            check_step_up(&json!({ "authenticatedAt": now - 5000.0 }), &recent, now)
                .unwrap()
                .map(|failure| failure.reason),
            Some(StepUpReason::Recent)
        );
        assert_eq!(
            check_step_up(&json!({ "authenticatedAt": now + 1.0 }), &recent, now)
                .unwrap()
                .map(|failure| failure.code),
            Some("RECENT_AUTH_REQUIRED")
        );
        assert_eq!(
            check_step_up(
                &json!({ "session": { "method": "impersonation", "authenticatedAt": now } }),
                &recent,
                now
            )
            .unwrap()
            .map(|failure| failure.code),
            Some("IMPERSONATION_RESTRICTED")
        );
        let mfa: StepUpRequirement = serde_json::from_value(json!({ "mfa": "fresh" })).unwrap();
        assert_eq!(mfa.mfa, Some(StepUpMfa::Fresh));
        assert!(serde_json::from_value::<StepUpRequirement>(json!({ "mfa": "always" })).is_err());
    }

    #[test]
    fn refuses_null_and_untrusted_origins_on_cookie_mutations() {
        let trusted = ["capacitor://localhost", "https://admin.example.test"];
        let url = Url::parse("http://localhost:3000/api/transfer").unwrap();
        let check = |origin: &str| {
            let mut headers = HeaderMap::new();
            headers.insert("cookie", "better-iam.session=abc".parse().unwrap());
            headers.insert("origin", origin.parse().unwrap());
            check_request_origin(
                &OriginRequest {
                    method: "POST",
                    url: &url,
                    headers: &headers,
                },
                trusted.iter().map(Some),
            )
            .map(|error| error.code)
        };
        assert_eq!(check("null").as_deref(), Some("UNTRUSTED_ORIGIN"));
        assert_eq!(check("https://admin.example.test"), None);
        assert_eq!(check("http://localhost:3000"), None);
        assert_eq!(
            check("http://evil.test").as_deref(),
            Some("UNTRUSTED_ORIGIN")
        );
        // Forwarded hosts count as this application's own origin.
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "better-iam.session=abc".parse().unwrap());
        headers.insert("origin", "https://app.example.test".parse().unwrap());
        headers.insert(
            "x-forwarded-host",
            "app.example.test, proxy".parse().unwrap(),
        );
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        let forwarded = OriginRequest {
            method: "DELETE",
            url: &url,
            headers: &headers,
        };
        assert_eq!(
            check_request_origin(&forwarded, Vec::<Option<String>>::new()),
            None
        );
        // No session cookie, a bearer header, or a safe method: no check.
        let mut headers = HeaderMap::new();
        headers.insert("origin", "http://evil.test".parse().unwrap());
        let plain = OriginRequest {
            method: "POST",
            url: &url,
            headers: &headers,
        };
        assert_eq!(
            check_request_origin(&plain, Vec::<Option<String>>::new()),
            None
        );
    }

    #[test]
    fn helpers_for_paths_and_queries() {
        assert!(under_path("/api/iam/auth/signIn", "/api/iam"));
        assert!(under_path("/api/iam", "/api/iam/"));
        assert!(!under_path("/api/iamx", "/api/iam"));
        assert!(under_path("/anything", "/"));
        assert_eq!(with_query("/login", &[("next", None)]), "/login");
        assert_eq!(
            with_query(
                "/verify?x=1",
                &[("next", Some("/a b")), ("reason", Some("mfa"))]
            ),
            "/verify?x=1&next=%2Fa+b&reason=mfa"
        );
        assert_eq!(safe_redirect_path(Some("/a\\b"), "/home"), "/home");
        assert_eq!(safe_redirect_path(Some("/a/../b?#"), "/"), "/b");
        assert_eq!(safe_redirect_path(None, "/x"), "/x");
        assert_eq!(
            tenant_of(&json!({ "session": { "tenantId": "t1" } })).as_deref(),
            Some("t1")
        );
        assert_eq!(tenant_of(&Value::Null), None);
    }
}
