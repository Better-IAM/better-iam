//! actix-web integration, the counterpart of the Express adapter: [`IamActix::middleware`] serves the IAM API under
//! its `serve` prefixes (through the server's node transport) and gives every other request an [`IamRequest`]
//! (an extractor); [`IamActix::require_session`] and [`IamActix::authorize`] are route guards (`.wrap(...)` on a
//! resource or scope); a [`MiddlewareError`] a handler returns becomes the IAM JSON error envelope, or a login /
//! step-up redirect for page navigations.
//!
//! ```ignore
//! let iam_actix = IamActix::new(iam, IamLayerOptions { login_path: Some("/login".into()), ..Default::default() });
//! App::new()
//!     .wrap(iam_actix.middleware())
//!     .service(web::resource("/me").wrap(iam_actix.require_session(None)).route(web::get().to(me)))
//! ```

use std::future::{Ready, ready};
use std::rc::Rc;
use std::sync::Arc;

use actix_service::{Service, Transform};
use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{Payload, ServiceRequest, ServiceResponse};
use actix_web::http::StatusCode as ActixStatus;
use actix_web::http::header::{
    HeaderMap as ActixHeaderMap, HeaderName as ActixHeaderName, HeaderValue as ActixHeaderValue,
};
use actix_web::{FromRequest, HttpMessage, HttpRequest, HttpResponse, ResponseError};
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use futures::future::LocalBoxFuture;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use url::Url;

use crate::helpers::{RequestBinding, create_request_helpers};
use crate::iam::{IamLike, IamSource};
use crate::layer::{CookieJar, IamLayerOptions, ReadFailure, Shared, serve_prefixes, serve_with};
use crate::{
    AuthorizeRule, GuardOrigin, GuardSpec, IamRequest, IamRequestError, MiddlewareError,
    RefusalPages, RefusalRequest, RefusalResponse, StepUpRequirement, enforce_guard, error_body,
    refusal_response, under_path,
};

/// The framework integration for actix-web.
pub struct IamActix<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Clone for IamActix<T> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

fn to_headers(headers: &ActixHeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers.iter() {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            out.append(name, value);
        }
    }
    out
}

fn to_method(request: &HttpRequest) -> Method {
    Method::from_bytes(request.method().as_str().as_bytes()).unwrap_or(Method::GET)
}

/// The incoming request's URL: `http(s)://{Host}{path}` (https when the server is bound with TLS).
pub fn request_url(request: &HttpRequest) -> Url {
    let scheme = if request.app_config().secure() {
        "https"
    } else {
        "http"
    };
    let host = request
        .headers()
        .get("host")
        .and_then(|host| host.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| request.app_config().host().to_owned());
    let target = request
        .uri()
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |target| target.as_str().to_owned());
    Url::parse(&format!("{scheme}://{host}"))
        .and_then(|base| base.join(&target))
        .or_else(|_| Url::parse("http://localhost/"))
        .expect("static URL")
}

fn to_actix(response: http::Response<Bytes>) -> HttpResponse {
    let (parts, body) = response.into_parts();
    let mut answer = HttpResponse::with_body(
        ActixStatus::from_u16(parts.status.as_u16()).unwrap_or(ActixStatus::INTERNAL_SERVER_ERROR),
        body,
    );
    let headers = answer.headers_mut();
    for (name, value) in parts.headers.iter() {
        if let (Ok(name), Ok(value)) = (
            ActixHeaderName::from_bytes(name.as_str().as_bytes()),
            ActixHeaderValue::from_bytes(value.as_bytes()),
        ) {
            headers.append(name, value);
        }
    }
    answer.map_into_boxed_body()
}

fn apply_cookies(jar: &CookieJar, headers: &mut ActixHeaderMap) {
    for header in jar.take() {
        if let Ok(value) = ActixHeaderValue::from_bytes(header.as_bytes()) {
            headers.append(actix_web::http::header::SET_COOKIE, value);
        }
    }
}

async fn read_payload(mut payload: Payload, limit: usize) -> Result<Bytes, ReadFailure> {
    let mut body = BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|_| ReadFailure::Broken)?;
        if body.len() + chunk.len() > limit {
            return Err(ReadFailure::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

/// The answer to a refusal (or a plain 500 for any other failure).
fn refusal(error: &MiddlewareError, request: &HttpRequest, pages: &RefusalPages) -> HttpResponse {
    let MiddlewareError::Refusal(error) = error else {
        eprintln!("better-iam middleware: {error}");
        return HttpResponse::InternalServerError().body("Internal Server Error");
    };
    let url = request_url(request);
    let headers = to_headers(request.headers());
    let facts = RefusalRequest {
        url: &url,
        headers: &headers,
        method: request.method().as_str(),
    };
    match refusal_response(error, &facts, pages) {
        RefusalResponse::Redirect(location) => HttpResponse::SeeOther()
            .insert_header(("location", location))
            .finish(),
        RefusalResponse::Json { status, body } => HttpResponse::build(
            ActixStatus::from_u16(status).unwrap_or(ActixStatus::INTERNAL_SERVER_ERROR),
        )
        .insert_header(("content-type", "application/json"))
        .insert_header(("cache-control", "no-store"))
        .body(body),
    }
}

/// The helpers of a request: those the middleware attached, or new ones with a jar the caller must apply.
fn helpers_for<T: IamLike>(
    shared: &Shared<T>,
    request: &HttpRequest,
) -> (IamRequest<T>, Option<CookieJar>) {
    if let Some(existing) = request.extensions().get::<IamRequest<T>>() {
        return (existing.clone(), None);
    }
    let jar = CookieJar::default();
    let sink = jar.clone();
    let created = create_request_helpers(
        shared.source.clone(),
        RequestBinding {
            url: request_url(request),
            headers: to_headers(request.headers()),
            set_cookie: Arc::new(move |header| sink.push(header)),
        },
        shared.options.helper_options(),
    );
    request.extensions_mut().insert(created.clone());
    (created, Some(jar))
}

impl<T: IamLike> IamActix<T> {
    /// The integration over an instance (or a lazy source).
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

    /// The per-request helpers of a request, created on first use (install the middleware so their cookies reach
    /// the response).
    pub fn helpers(&self, request: &HttpRequest) -> IamRequest<T> {
        helpers_for(&self.shared, request).0
    }

    /// Serves the IAM API under `serve` prefixes and attaches [`IamRequest`] to everything else.
    pub fn middleware(&self) -> IamMiddleware<T> {
        IamMiddleware {
            shared: self.shared.clone(),
        }
    }

    /// A guard that requires a session (and `step_up`, when given).
    pub fn require_session(&self, step_up: Option<StepUpRequirement>) -> IamGuard<T> {
        self.guard(GuardSpec {
            step_up,
            authorize: None,
        })
    }

    /// A guard that requires a session allowed to perform `rule.action` (default resource: the tenant); the
    /// callbacks receive the request (route parameters: `request.match_info()`).
    pub fn authorize(
        &self,
        rule: AuthorizeRule<HttpRequest>,
        step_up: Option<StepUpRequirement>,
    ) -> IamGuard<T> {
        self.guard(GuardSpec {
            step_up,
            authorize: Some(rule),
        })
    }

    /// A guard for any [`GuardSpec`].
    pub fn guard(&self, spec: GuardSpec<HttpRequest>) -> IamGuard<T> {
        IamGuard {
            shared: self.shared.clone(),
            spec: Rc::new(spec),
        }
    }
}

/// The middleware of [`IamActix::middleware`].
pub struct IamMiddleware<T> {
    shared: Arc<Shared<T>>,
}

impl<S, B, T> Transform<S, ServiceRequest> for IamMiddleware<T>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: MessageBody + 'static,
    T: IamLike,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Transform = IamMiddlewareService<S, T>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(IamMiddlewareService {
            service: Rc::new(service),
            shared: self.shared.clone(),
        }))
    }
}

/// The service of [`IamMiddleware`].
pub struct IamMiddlewareService<S, T> {
    service: Rc<S>,
    shared: Arc<Shared<T>>,
}

impl<S, B, T> Service<ServiceRequest> for IamMiddlewareService<S, T>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: MessageBody + 'static,
    T: IamLike,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_service::forward_ready!(service);

    fn call(&self, mut request: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let shared = self.shared.clone();
        Box::pin(async move {
            let iam = match shared.source.resolve().await {
                Ok(iam) => iam,
                Err(error) => {
                    let answer = refusal(&error, request.request(), &shared.options.pages());
                    return Ok(request.into_response(answer).map_into_right_body());
                }
            };
            let url = request_url(request.request());
            let prefixes = serve_prefixes(&shared.options, iam.as_ref());
            if prefixes.iter().any(|prefix| under_path(url.path(), prefix)) {
                let payload = request.take_payload();
                let target = request
                    .uri()
                    .path_and_query()
                    .map_or_else(|| "/".to_owned(), |target| target.as_str().to_owned());
                let answer = serve_with(
                    iam.as_ref(),
                    &url,
                    to_method(request.request()),
                    target,
                    to_headers(request.headers()),
                    |limit| read_payload(payload, limit),
                )
                .await;
                return Ok(request
                    .into_response(to_actix(answer))
                    .map_into_right_body());
            }
            let (_, jar) = helpers_for(&shared, request.request());
            let mut response = service.call(request).await?;
            let refused = response
                .response()
                .error()
                .and_then(|error| error.as_error::<MiddlewareError>())
                .cloned();
            if let Some(MiddlewareError::Refusal(error)) = refused {
                let facts_url = request_url(response.request());
                let headers = to_headers(response.request().headers());
                let facts = RefusalRequest {
                    url: &facts_url,
                    headers: &headers,
                    method: response.request().method().as_str(),
                };
                if let RefusalResponse::Redirect(_) =
                    refusal_response(&error, &facts, &shared.options.pages())
                {
                    let answer = refusal(
                        &MiddlewareError::Refusal(error),
                        response.request(),
                        &shared.options.pages(),
                    );
                    let mut redirected = response.into_response(answer).map_into_right_body();
                    if let Some(jar) = &jar {
                        apply_cookies(jar, redirected.headers_mut());
                    }
                    return Ok(redirected);
                }
            }
            if let Some(jar) = &jar {
                apply_cookies(jar, response.headers_mut());
            }
            Ok(response.map_into_left_body())
        })
    }
}

/// A route guard of [`IamActix::require_session`] / [`IamActix::authorize`].
pub struct IamGuard<T> {
    shared: Arc<Shared<T>>,
    spec: Rc<GuardSpec<HttpRequest>>,
}

impl<S, B, T> Transform<S, ServiceRequest> for IamGuard<T>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: MessageBody + 'static,
    T: IamLike,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Transform = IamGuardService<S, T>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(IamGuardService {
            service: Rc::new(service),
            shared: self.shared.clone(),
            spec: self.spec.clone(),
        }))
    }
}

/// The service of [`IamGuard`].
pub struct IamGuardService<S, T> {
    service: Rc<S>,
    shared: Arc<Shared<T>>,
    spec: Rc<GuardSpec<HttpRequest>>,
}

impl<S, B, T> Service<ServiceRequest> for IamGuardService<S, T>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: MessageBody + 'static,
    T: IamLike,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_service::forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let shared = self.shared.clone();
        let spec = self.spec.clone();
        Box::pin(async move {
            let http_request = request.request().clone();
            let (helpers, jar) = helpers_for(&shared, &http_request);
            let checked = guard_check(&shared, &helpers, &http_request, &spec).await;
            let mut response = match checked {
                Ok(()) => service.call(request).await?.map_into_left_body(),
                Err(error) => {
                    let answer = refusal(&error, &http_request, &shared.options.pages());
                    request.into_response(answer).map_into_right_body()
                }
            };
            if let Some(jar) = &jar {
                apply_cookies(jar, response.headers_mut());
            }
            Ok(response)
        })
    }
}

async fn guard_check<T: IamLike>(
    shared: &Shared<T>,
    helpers: &IamRequest<T>,
    request: &HttpRequest,
    spec: &GuardSpec<HttpRequest>,
) -> Result<(), MiddlewareError> {
    let iam = shared.source.resolve().await?;
    let url = request_url(request);
    let headers = to_headers(request.headers());
    let origin = shared.options.csrf.then(|| GuardOrigin {
        method: request.method().as_str(),
        url: &url,
        headers: &headers,
        trusted_origins: std::iter::once(iam.endpoint().map(|endpoint| endpoint.origin))
            .chain(shared.options.trusted_origins.iter().cloned().map(Some))
            .collect(),
    });
    enforce_guard(helpers, request, spec, origin)
        .await
        .map(|_| ())
}

impl<T: IamLike> FromRequest for IamRequest<T> {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(request: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(
            request
                .extensions()
                .get::<IamRequest<T>>()
                .cloned()
                .ok_or_else(|| {
                    actix_web::error::ErrorInternalServerError(
                        "The Better IAM middleware is not installed on this route",
                    )
                }),
        )
    }
}

impl ResponseError for MiddlewareError {
    fn status_code(&self) -> ActixStatus {
        match self {
            MiddlewareError::Refusal(refusal) => {
                ActixStatus::from_u16(refusal.status).unwrap_or(ActixStatus::INTERNAL_SERVER_ERROR)
            }
            MiddlewareError::Other(_) => ActixStatus::INTERNAL_SERVER_ERROR,
        }
    }

    /// IAM refusals become the JSON envelope (the middleware turns them into redirects for page navigations);
    /// anything else is logged and answered with a plain 500.
    fn error_response(&self) -> HttpResponse {
        match self {
            MiddlewareError::Refusal(refusal) => HttpResponse::build(self.status_code())
                .insert_header(("content-type", "application/json"))
                .insert_header(("cache-control", "no-store"))
                .body(error_body(&refusal.code, &refusal.message)),
            MiddlewareError::Other(message) => {
                eprintln!("better-iam middleware: {message}");
                HttpResponse::InternalServerError().body("Internal Server Error")
            }
        }
    }
}

impl ResponseError for IamRequestError {
    fn status_code(&self) -> ActixStatus {
        ActixStatus::from_u16(self.status).unwrap_or(ActixStatus::INTERNAL_SERVER_ERROR)
    }

    fn error_response(&self) -> HttpResponse {
        MiddlewareError::Refusal(self.clone()).error_response()
    }
}
