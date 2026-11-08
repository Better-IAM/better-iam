//! The framework integration as a tower layer: the counterpart of the Express adapter (`express.ts`), usable with
//! axum, hyper, and any other tower-based server.
//!
//! [`IamTower::layer`] serves the IAM API under its `serve` prefixes (through the server's node transport, so node
//! protocol mounts such as the OAuth provider work) and gives every other request an [`IamRequest`] in its
//! extensions; [`IamTower::require_session`] and [`IamTower::authorize`] are route guards. A refusal a route handler
//! returns (with [`RefusalMarker`] on its response, which the axum and actix-web integrations add) becomes a
//! login / step-up redirect for page navigations, as the Express `errorHandler` does.
//!
//! ```ignore
//! let iam_tower = IamTower::new(iam, IamLayerOptions { login_path: Some("/login".into()), ..Default::default() });
//! let app = Router::new()
//!     .route("/projects/{id}", get(handler).route_layer(iam_tower.authorize(
//!         AuthorizeRule::new("projects:read").resource(|parts, _| ResourceRef { kind: "project".into(), id: path_param(parts, "id").unwrap_or_default() }),
//!         None,
//!     )))
//!     .layer(iam_tower.layer());
//! ```

use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::future::BoxFuture;
use http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, LOCATION, SET_COOKIE};
use http::request::Parts;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, Either, Full, LengthLimitError, Limited};
use tower_layer::Layer;
use tower_service::Service;
use url::Url;

use crate::helpers::{RequestBinding, RequestHelperOptions, create_request_helpers};
use crate::iam::{IamLike, IamSource, NodeRead};
use crate::{
    AuthorizeRule, GuardOrigin, GuardSpec, IamRequest, MiddlewareError, RefusalMarker,
    RefusalPages, RefusalRequest, RefusalResponse, StepUpRequirement, enforce_guard,
    refusal_response, under_path,
};

/// Errors a request body can fail with.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The response body of the layer and guards: an answer of the IAM server or of a guard, or the inner service's.
pub type IamBody<B> = Either<Full<Bytes>, B>;

/// The largest request body the fallback path (an instance without a node transport) buffers for the IAM handler.
const MAX_BODY: usize = 2_097_152;

/// Options of [`IamTower`] (`IamExpressOptions`).
#[derive(Clone)]
pub struct IamLayerOptions {
    /// Where the IAM HTTP API is served; defaults to the instance's `endpoint.basePath`, else `/api/iam`.
    pub base_path: Option<String>,
    /// The clock for step-up recency and cookie expiry.
    pub now: Option<Arc<dyn Fn() -> f64 + Send + Sync>>,
    /// Origins besides the request's own and the IAM origin that may send cookie-authenticated unsafe requests.
    pub trusted_origins: Vec<String>,
    /// Check `Origin` on cookie-authenticated POST/PUT/PATCH/DELETE requests in guards (default true).
    pub csrf: bool,
    /// Path prefixes the IAM server answers (default: its `basePath`). Add protocol mounts outside it, e.g. `/oauth`
    /// or `/.well-known`, so their requests reach the node transport too.
    pub serve: Option<Vec<String>>,
    /// Where page navigations (GET with `Accept: text/html`) go when signed out; `?next=` carries the path.
    pub login_path: Option<String>,
    /// Where page navigations go when the session must step up (`?next=`, `?reason=`).
    pub step_up_path: Option<String>,
}

impl Default for IamLayerOptions {
    fn default() -> Self {
        Self {
            base_path: None,
            now: None,
            trusted_origins: Vec::new(),
            csrf: true,
            serve: None,
            login_path: None,
            step_up_path: None,
        }
    }
}

impl IamLayerOptions {
    pub(crate) fn helper_options(&self) -> RequestHelperOptions {
        RequestHelperOptions {
            base_path: self.base_path.clone(),
            now: self.now.clone(),
        }
    }

    pub(crate) fn pages(&self) -> RefusalPages {
        RefusalPages {
            login_path: self.login_path.clone(),
            step_up_path: self.step_up_path.clone(),
        }
    }
}

/// The `Set-Cookie` headers the helpers of a request issued, appended to its response.
#[derive(Clone, Default)]
pub struct CookieJar(Arc<Mutex<Vec<String>>>);

impl CookieJar {
    pub(crate) fn push(&self, header: &str) {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(header.to_owned());
    }

    /// The headers issued so far.
    pub fn take(&self) -> Vec<String> {
        std::mem::take(
            &mut *self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    /// Appends the issued headers to a response's headers.
    pub fn apply(&self, headers: &mut HeaderMap) {
        for header in self.take() {
            if let Ok(value) = HeaderValue::from_bytes(header.as_bytes()) {
                headers.append(SET_COOKIE, value);
            }
        }
    }
}

pub(crate) struct Shared<T> {
    pub(crate) source: IamSource<T>,
    pub(crate) options: IamLayerOptions,
}

/// The framework integration (`createIamExpress`): a layer that serves the IAM API and attaches the request
/// helpers, and route guards.
pub struct IamTower<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Clone for IamTower<T> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

/// The incoming request's URL (`requestUrl`): its absolute target, or its path on `http://{Host}`.
pub fn request_url(parts: &Parts) -> Url {
    let uri = &parts.uri;
    if uri.scheme().is_some()
        && uri.authority().is_some()
        && let Ok(url) = Url::parse(&uri.to_string())
    {
        return url;
    }
    let host = parts
        .headers
        .get(http::header::HOST)
        .and_then(|host| host.to_str().ok())
        .map(str::to_owned)
        .or_else(|| uri.authority().map(|authority| authority.to_string()))
        .unwrap_or_else(|| "localhost".into());
    let scheme = uri.scheme_str().unwrap_or("http");
    let target = uri.path_and_query().map_or("/", |target| target.as_str());
    Url::parse(&format!("{scheme}://{host}"))
        .and_then(|base| base.join(target))
        .or_else(|_| Url::parse("http://localhost/"))
        .expect("static URL")
}

fn full<B>(response: Response<Bytes>) -> Response<IamBody<B>> {
    response.map(|body| Either::Left(Full::new(body)))
}

fn plain<B>(status: StatusCode, text: &'static str) -> Response<IamBody<B>> {
    let mut response = Response::new(Either::Left(Full::new(Bytes::from_static(text.as_bytes()))));
    *response.status_mut() = status;
    response
}

/// The answer to a failure that is not an IAM refusal (Express hands it to its default error handler).
pub(crate) fn internal_error<B>(error: &MiddlewareError) -> Response<IamBody<B>> {
    eprintln!("better-iam middleware: {error}");
    plain(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
}

/// The answer to a refusal: a 303 to the login / step-up page for page navigations, else the JSON envelope.
pub(crate) fn refusal<B>(
    error: &MiddlewareError,
    request: &RefusalRequest<'_>,
    pages: &RefusalPages,
) -> Response<IamBody<B>> {
    let MiddlewareError::Refusal(error) = error else {
        return internal_error(error);
    };
    match refusal_response(error, request, pages) {
        RefusalResponse::Redirect(location) => {
            let mut response = Response::new(Either::Left(Full::new(Bytes::new())));
            *response.status_mut() = StatusCode::SEE_OTHER;
            if let Ok(location) = HeaderValue::from_str(&location) {
                response.headers_mut().insert(LOCATION, location);
            }
            response
        }
        RefusalResponse::Json { status, body } => {
            let mut response = Response::new(Either::Left(Full::new(Bytes::from(body))));
            *response.status_mut() =
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let headers = response.headers_mut();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
    }
}

/// Why a request body could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadFailure {
    /// Larger than the limit (413).
    TooLarge,
    /// The stream broke (400).
    Broken,
}

/// Reads a whole body up to `limit` bytes.
pub(crate) async fn read_body<B>(body: B, limit: usize) -> Result<Bytes, ReadFailure>
where
    B: Body<Data = Bytes> + Send,
    B::Error: Into<BoxError>,
{
    match Limited::new(body, limit).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => {
            Err(ReadFailure::TooLarge)
        }
        Err(_) => Err(ReadFailure::Broken),
    }
}

fn plain_bytes(status: StatusCode, text: &'static str) -> Response<Bytes> {
    let mut response = Response::new(Bytes::from_static(text.as_bytes()));
    *response.status_mut() = status;
    response
}

fn read_failure(failure: ReadFailure) -> Response<Bytes> {
    match failure {
        ReadFailure::TooLarge => plain_bytes(StatusCode::PAYLOAD_TOO_LARGE, "Request too large"),
        ReadFailure::Broken => plain_bytes(StatusCode::BAD_REQUEST, "Bad request"),
    }
}

impl<T: IamLike> IamTower<T> {
    /// `createIamExpress(source, options)`.
    pub fn new(source: impl Into<IamSource<T>>, options: IamLayerOptions) -> Self {
        Self {
            shared: Arc::new(Shared {
                source: source.into(),
                options,
            }),
        }
    }

    /// `resolve()`: the instance.
    pub async fn resolve(&self) -> Result<Arc<T>, MiddlewareError> {
        self.shared.source.resolve().await
    }

    /// The options.
    pub fn options(&self) -> &IamLayerOptions {
        &self.shared.options
    }

    /// The per-request helpers of a request, created (with its cookie jar) on first use.
    pub fn helpers(&self, parts: &mut Parts) -> IamRequest<T> {
        helpers_for(&self.shared, parts).0
    }

    /// Serves the IAM API under `serve` prefixes and attaches [`IamRequest`] to everything else.
    pub fn layer(&self) -> IamLayer<T> {
        IamLayer {
            shared: self.shared.clone(),
        }
    }

    /// A guard that requires a session (and `step_up`, when given).
    pub fn require_session(&self, step_up: Option<StepUpRequirement>) -> GuardLayer<T> {
        self.guard(GuardSpec {
            step_up,
            authorize: None,
        })
    }

    /// A guard that requires a session allowed to perform `rule.action` (default resource: the tenant); the rule's
    /// `resource` and `tenant_id` callbacks receive the request head (route parameters: `axum::path_param`).
    pub fn authorize(
        &self,
        rule: AuthorizeRule<Parts>,
        step_up: Option<StepUpRequirement>,
    ) -> GuardLayer<T> {
        self.guard(GuardSpec {
            step_up,
            authorize: Some(rule),
        })
    }

    /// A guard for any [`GuardSpec`].
    pub fn guard(&self, spec: GuardSpec<Parts>) -> GuardLayer<T> {
        GuardLayer {
            shared: self.shared.clone(),
            spec: Arc::new(spec),
        }
    }
}

/// The helpers of a request: those an outer layer attached, or new ones with a jar the caller must apply.
pub(crate) fn helpers_for<T: IamLike>(
    shared: &Shared<T>,
    parts: &mut Parts,
) -> (IamRequest<T>, Option<CookieJar>) {
    if let Some(existing) = parts.extensions.get::<IamRequest<T>>() {
        return (existing.clone(), None);
    }
    let jar = CookieJar::default();
    let sink = jar.clone();
    let created = create_request_helpers(
        shared.source.clone(),
        RequestBinding {
            url: request_url(parts),
            headers: parts.headers.clone(),
            set_cookie: Arc::new(move |header| sink.push(header)),
        },
        shared.options.helper_options(),
    );
    parts.extensions.insert(created.clone());
    parts.extensions.insert(jar.clone());
    (created, Some(jar))
}

/// The layer of [`IamTower::layer`].
pub struct IamLayer<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Clone for IamLayer<T> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<S, T> Layer<S> for IamLayer<T> {
    type Service = IamService<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        IamService {
            inner,
            shared: self.shared.clone(),
        }
    }
}

/// The service of [`IamLayer`].
pub struct IamService<S, T> {
    inner: S,
    shared: Arc<Shared<T>>,
}

impl<S: Clone, T> Clone for IamService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            shared: self.shared.clone(),
        }
    }
}

/// Serves a request to the IAM server: through the node transport when the instance has one, else through the
/// fetch-style handler with the body buffered up to 2 MiB. `read` reads the request body up to a limit.
pub(crate) async fn serve_with<T, F, Fut>(
    iam: &T,
    url: &Url,
    method: Method,
    target: String,
    mut headers: HeaderMap,
    read: F,
) -> Response<Bytes>
where
    T: IamLike,
    F: FnOnce(usize) -> Fut,
    Fut: std::future::Future<Output = Result<Bytes, ReadFailure>>,
{
    if iam.has_node_handler() {
        let bytes = match iam.node_read(&method, &target, &headers) {
            NodeRead::Skip => Bytes::new(),
            NodeRead::Limit(limit) => match read(limit).await {
                Ok(bytes) => bytes,
                Err(failure) => return read_failure(failure),
            },
        };
        return iam.node_handler(method, &target, headers, bytes).await;
    }
    let bytes = match read(MAX_BODY).await {
        Ok(bytes) => bytes,
        Err(failure) => return read_failure(failure),
    };
    headers.insert(CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    let mut request = Request::new(bytes);
    *request.method_mut() = method;
    *request.uri_mut() = match url.as_str().parse() {
        Ok(uri) => uri,
        Err(_) => return plain_bytes(StatusCode::BAD_REQUEST, "Bad request"),
    };
    *request.headers_mut() = headers;
    iam.handler(request).await
}

/// [`serve_with`] for an http-body request.
async fn serve_iam<T, B, R>(iam: &T, url: &Url, parts: Parts, body: B) -> Response<IamBody<R>>
where
    T: IamLike,
    B: Body<Data = Bytes> + Send,
    B::Error: Into<BoxError>,
{
    let target = parts
        .uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |target| target.as_str().to_owned());
    full(
        serve_with(iam, url, parts.method, target, parts.headers, |limit| {
            read_body(body, limit)
        })
        .await,
    )
}

/// The prefixes the IAM server answers.
pub(crate) fn serve_prefixes<T: IamLike>(options: &IamLayerOptions, iam: &T) -> Vec<String> {
    options.serve.clone().unwrap_or_else(|| {
        vec![
            options
                .base_path
                .clone()
                .or_else(|| iam.endpoint().map(|endpoint| endpoint.base_path))
                .unwrap_or_else(|| "/api/iam".into()),
        ]
    })
}

impl<S, T, ReqBody, ResBody> Service<Request<ReqBody>> for IamService<S, T>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    T: IamLike,
    ReqBody: Body<Data = Bytes> + Send + 'static,
    ReqBody::Error: Into<BoxError>,
    ResBody: Send + 'static,
{
    type Response = Response<IamBody<ResBody>>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let shared = self.shared.clone();
        Box::pin(async move {
            let iam = match shared.source.resolve().await {
                Ok(iam) => iam,
                Err(error) => return Ok(internal_error(&error)),
            };
            let (mut parts, body) = request.into_parts();
            let url = request_url(&parts);
            let prefixes = serve_prefixes(&shared.options, iam.as_ref());
            if prefixes.iter().any(|prefix| under_path(url.path(), prefix)) {
                return Ok(serve_iam(iam.as_ref(), &url, parts, body).await);
            }
            let (_, jar) = helpers_for(&shared, &mut parts);
            let method = parts.method.clone();
            let headers = parts.headers.clone();
            let response = inner.call(Request::from_parts(parts, body)).await?;
            let mut response = match response.extensions().get::<RefusalMarker>().cloned() {
                Some(RefusalMarker(error)) => {
                    let request = RefusalRequest {
                        url: &url,
                        headers: &headers,
                        method: method.as_str(),
                    };
                    match refusal_response(&error, &request, &shared.options.pages()) {
                        RefusalResponse::Redirect(_) => {
                            refusal(&error.into(), &request, &shared.options.pages())
                        }
                        RefusalResponse::Json { .. } => response.map(Either::Right),
                    }
                }
                None => response.map(Either::Right),
            };
            if let Some(jar) = jar {
                jar.apply(response.headers_mut());
            }
            Ok(response)
        })
    }
}

/// A route guard of [`IamTower::require_session`] / [`IamTower::authorize`].
pub struct GuardLayer<T> {
    shared: Arc<Shared<T>>,
    spec: Arc<GuardSpec<Parts>>,
}

impl<T> Clone for GuardLayer<T> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            spec: self.spec.clone(),
        }
    }
}

impl<S, T> Layer<S> for GuardLayer<T> {
    type Service = GuardService<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        GuardService {
            inner,
            shared: self.shared.clone(),
            spec: self.spec.clone(),
        }
    }
}

/// The service of [`GuardLayer`].
pub struct GuardService<S, T> {
    inner: S,
    shared: Arc<Shared<T>>,
    spec: Arc<GuardSpec<Parts>>,
}

impl<S: Clone, T> Clone for GuardService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            shared: self.shared.clone(),
            spec: self.spec.clone(),
        }
    }
}

impl<S, T, ReqBody, ResBody> Service<Request<ReqBody>> for GuardService<S, T>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    T: IamLike,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = Response<IamBody<ResBody>>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let shared = self.shared.clone();
        let spec = self.spec.clone();
        Box::pin(async move {
            let (mut parts, body) = request.into_parts();
            let (helpers, jar) = helpers_for(&shared, &mut parts);
            let url = request_url(&parts);
            let checked = guard_check(&shared, &helpers, &parts, &spec, &url).await;
            let mut response = match checked {
                Ok(()) => inner
                    .call(Request::from_parts(parts, body))
                    .await?
                    .map(Either::Right),
                Err(error) => {
                    let request = RefusalRequest {
                        url: &url,
                        headers: &parts.headers,
                        method: parts.method.as_str(),
                    };
                    refusal(&error, &request, &shared.options.pages())
                }
            };
            if let Some(jar) = jar {
                jar.apply(response.headers_mut());
            }
            Ok(response)
        })
    }
}

/// Resolves the instance and runs the guard with the CSRF origin check unless `csrf` is off.
async fn guard_check<T: IamLike>(
    shared: &Shared<T>,
    helpers: &IamRequest<T>,
    parts: &Parts,
    spec: &GuardSpec<Parts>,
    url: &Url,
) -> Result<(), MiddlewareError> {
    let iam = shared.source.resolve().await?;
    let origin = shared.options.csrf.then(|| GuardOrigin {
        method: parts.method.as_str(),
        url,
        headers: &parts.headers,
        trusted_origins: std::iter::once(iam.endpoint().map(|endpoint| endpoint.origin))
            .chain(shared.options.trusted_origins.iter().cloned().map(Some))
            .collect(),
    });
    enforce_guard(helpers, parts, spec, origin)
        .await
        .map(|_| ())
}
