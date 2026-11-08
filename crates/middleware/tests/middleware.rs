//! The port of tests/middleware.test.ts and tests/middleware-plan.test.ts: the same scenario against the tower layer
//! (with axum) and actix-web — API mount, guards, page redirects, in-process sign-in, errors, sign-out — plus
//! route parameters in guard callbacks, node-only protocol mounts, request batching, and `plan()`.

#[path = "../../server/tests/organization_fixture/mod.rs"]
mod organization_fixture;

use std::borrow::Borrow;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use axum::Router;
use axum::routing::{get, post};
use better_iam_core::{CredentialInput, IamResult};
use better_iam_middleware::axum::path_param;
use better_iam_middleware::layer::{IamLayerOptions, IamTower};
use better_iam_middleware::{
    AuthorizeRule, EndpointRef, IamLike, IamRequest, IamSource, MiddlewareError, PlanInput,
    RequestBinding, RequestHelperOptions, ResourceRef, StepUpMfa, StepUpRequirement,
    create_request_helpers,
};
use better_iam_server::BetterIam;
use better_iam_server::http::ProtocolService;
use better_iam_server::options::{
    AuthorizationRequest, BatchAuthorizationRequest, HttpRequest, HttpResponse,
};
use bytes::Bytes;
use http::{HeaderMap, Method, Request};
use http_body_util::BodyExt;
use organization_fixture::{Org, organization, run};
use serde_json::{Value, json};
use tower::ServiceExt;

impl Borrow<BetterIam> for Org {
    fn borrow(&self) -> &BetterIam {
        &self.iam
    }
}

const ORIGIN: &str = "http://localhost:3000";

/// A response as the scenario reads it.
#[derive(Debug)]
struct Answer {
    status: u16,
    headers: HeaderMap,
    body: Bytes,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .map(|value| value.to_str().unwrap().to_owned())
    }

    fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect()
    }

    /// `better-iam.session=…` of the session cookie the response sets.
    fn cookie(&self) -> Option<String> {
        self.set_cookies()
            .into_iter()
            .find(|header| header.starts_with("better-iam.session="))
            .map(|header| header.split(';').next().unwrap().to_owned())
    }
}

/// One request: method, path, headers, body.
struct Call {
    method: Method,
    path: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

fn call(method: Method, path: &str, headers: &[(&str, &str)], body: Option<String>) -> Call {
    Call {
        method,
        path: path.to_owned(),
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        body,
    }
}

fn get_(path: &str, headers: &[(&str, &str)]) -> Call {
    call(Method::GET, path, headers, None)
}

fn post_(path: &str, headers: &[(&str, &str)], body: Option<String>) -> Call {
    call(Method::POST, path, headers, body)
}

type Fetch = Box<dyn Fn(Call) -> futures::future::LocalBoxFuture<'static, Answer>>;

fn axum_fetch(app: Router) -> Fetch {
    Box::new(move |call: Call| {
        let app = app.clone();
        Box::pin(async move {
            let mut request = Request::builder()
                .method(call.method)
                .uri(&call.path)
                .header("host", "127.0.0.1");
            for (name, value) in &call.headers {
                request = request.header(name, value);
            }
            let request = request
                .body(axum::body::Body::from(call.body.unwrap_or_default()))
                .unwrap();
            let response = app.oneshot(request).await.unwrap();
            let (parts, body) = response.into_parts();
            Answer {
                status: parts.status.as_u16(),
                headers: parts.headers,
                body: body.collect().await.unwrap().to_bytes(),
            }
        })
    })
}

const JSON: [(&str, &str); 3] = [
    ("content-type", "application/json"),
    ("x-better-iam", "1"),
    ("origin", ORIGIN),
];

/// The same scenario against any adapter: API mount, guards, page redirects, in-process sign-in, errors, sign-out.
async fn scenario(org: &Org, fetch: &Fetch) {
    // The IAM API is answered by the adapter.
    let sign_in = fetch(post_(
        "/api/iam/auth/signIn",
        &JSON,
        Some(
            json!({
                "tenantId": org.tenant_id,
                "email": "owner@acme.test",
                "password": "a strong tenant owner password",
            })
            .to_string(),
        ),
    ))
    .await;
    assert_eq!(sign_in.status, 200, "{:?}", sign_in.json());
    let owner = sign_in.cookie().expect("session cookie");
    let health = fetch(get_("/api/iam/health", &[])).await;
    assert_eq!(health.json()["status"], "ok");

    // Guards: JSON envelope for API calls, redirects for page navigations.
    let anonymous = fetch(get_("/me", &[])).await;
    assert_eq!(anonymous.status, 401);
    assert_eq!(
        anonymous.json(),
        json!({ "error": { "code": "UNAUTHENTICATED", "message": "A session is required" } })
    );
    assert_eq!(
        anonymous.header("cache-control").as_deref(),
        Some("no-store")
    );
    let page = fetch(get_("/me?tab=1", &[("accept", "text/html")])).await;
    assert_eq!(page.status, 303);
    assert_eq!(
        page.header("location").as_deref(),
        Some("/login?next=%2Fme%3Ftab%3D1")
    );
    assert_eq!(
        fetch(get_("/me", &[("cookie", &owner)])).await.json(),
        json!({ "email": "owner@acme.test", "canUpdate": true })
    );

    // CSRF: cookie-authenticated unsafe requests to guarded routes must come from a trusted origin.
    let cross_site = fetch(post_(
        "/danger",
        &[("cookie", &owner), ("origin", "http://evil.test")],
        None,
    ))
    .await;
    assert_eq!(cross_site.status, 403);
    assert_eq!(cross_site.json()["error"]["code"], "UNTRUSTED_ORIGIN");
    let no_origin = fetch(post_("/danger", &[("cookie", &owner)], None)).await;
    assert_eq!(no_origin.json()["error"]["code"], "CSRF_REJECTED");
    // The IAM origin is trusted.
    assert_eq!(
        fetch(post_(
            "/danger",
            &[("cookie", &owner), ("origin", ORIGIN)],
            None
        ))
        .await
        .status,
        200
    );
    assert_eq!(
        fetch(post_(
            "/danger",
            &[("cookie", &owner), ("sec-fetch-site", "same-origin")],
            None
        ))
        .await
        .status,
        200
    );
    // Bearer credentials are not ambient, so no Origin check.
    let token = owner.trim_start_matches("better-iam.session=");
    let bearer = format!("Bearer {token}");
    assert_eq!(
        fetch(post_(
            "/danger",
            &[("authorization", &bearer), ("origin", "http://evil.test")],
            None
        ))
        .await
        .status,
        200
    );

    // Step-up: a password-only session is refused (API) or sent to the step-up page (navigation).
    let secure = fetch(get_("/secure", &[("cookie", &owner)])).await;
    assert_eq!(secure.status, 403);
    assert_eq!(secure.json()["error"]["code"], "MFA_REQUIRED");
    let secure_nav = fetch(get_(
        "/secure",
        &[("cookie", &owner), ("accept", "text/html")],
    ))
    .await;
    assert_eq!(
        secure_nav.header("location").as_deref(),
        Some("/verify?next=%2Fsecure&reason=mfa")
    );

    // Authorization guard: the owner may update identities, a plain member may not.
    assert_eq!(
        fetch(get_("/admin", &[("cookie", &owner)])).await.status,
        200
    );
    org.member("bob").await;
    let bob_login = fetch(post_(
        "/login",
        &[("content-type", "application/json")],
        Some(json!({ "email": "bob@acme.test", "password": "a strong bob password" }).to_string()),
    ))
    .await;
    assert_eq!(bob_login.json(), json!({ "signedInAs": "bob@acme.test" }));
    let bob = bob_login.cookie().expect("bob's session cookie");
    assert!(
        bob_login
            .set_cookies()
            .join("\n")
            .to_lowercase()
            .contains("httponly")
    );
    let denied = fetch(get_("/admin", &[("cookie", &bob)])).await;
    assert_eq!(denied.status, 403);
    assert_eq!(denied.json()["error"]["code"], "ACCESS_DENIED");
    assert_eq!(
        fetch(get_("/me", &[("cookie", &bob)])).await.json(),
        json!({ "email": "bob@acme.test", "canUpdate": false })
    );

    // A refusal returned by a route reaches the adapter's error handling.
    let thrown = fetch(get_("/thrower", &[("cookie", &bob)])).await;
    assert_eq!(thrown.status, 403);
    assert_eq!(thrown.json()["error"]["code"], "ACCESS_DENIED");
    // ... and a page navigation that is refused that way is not redirected for a 403 without a step-up reason.
    let thrown_nav = fetch(get_(
        "/thrower",
        &[("cookie", &bob), ("accept", "text/html")],
    ))
    .await;
    assert_eq!(thrown_nav.status, 403);

    // Sign-out ends the session server-side and clears the cookie.
    let logout = fetch(post_("/logout", &[("cookie", &bob)], None)).await;
    assert_eq!(logout.json(), json!({ "signedOut": true }));
    let cleared = logout.set_cookies().join("\n");
    assert!(
        cleared.contains("better-iam.session=;") && cleared.to_lowercase().contains("max-age=0"),
        "{cleared}"
    );
    assert_eq!(fetch(get_("/me", &[("cookie", &bob)])).await.status, 401);
}

type Helpers = IamRequest<Org>;

async fn me(iam: &Helpers) -> Result<Value, MiddlewareError> {
    let session = iam.get_session().await?;
    Ok(json!({
        "email": session.as_ref().map(|session| session["identity"]["email"].clone()),
        "canUpdate": iam.can("iam:identities:update", None, None).await?,
    }))
}

async fn login(iam: &Helpers, tenant_id: &str, body: Value) -> Result<Value, MiddlewareError> {
    iam.client()
        .call(
            "auth",
            "signIn",
            json!({ "tenantId": tenant_id, "email": body["email"], "password": body["password"] }),
        )
        .await?;
    // The session the in-process client just issued counts for the rest of this request.
    let session = iam.get_session().await?;
    Ok(json!({ "signedInAs": session.map(|session| session["identity"]["email"].clone()) }))
}

async fn logout(iam: &Helpers) -> Result<Value, MiddlewareError> {
    iam.sign_out().await?;
    Ok(json!({ "signedOut": iam.get_session().await?.is_none() }))
}

async fn thrower(iam: &Helpers) -> Result<Value, MiddlewareError> {
    iam.require("iam:identities:delete", None, None).await?;
    Ok(json!({ "unreachable": true }))
}

fn pages() -> IamLayerOptions {
    IamLayerOptions {
        login_path: Some("/login".into()),
        step_up_path: Some("/verify".into()),
        ..IamLayerOptions::default()
    }
}

fn mfa() -> Option<StepUpRequirement> {
    Some(StepUpRequirement {
        mfa: Some(StepUpMfa::On),
        max_age_ms: None,
    })
}

fn axum_app(org: Arc<Org>, options: IamLayerOptions) -> Router {
    let iam = IamTower::new(org.clone(), options);
    let tenant_id = org.tenant_id.clone();
    let ok = || async { axum::Json(json!({ "ok": true })) };
    Router::new()
        .route(
            "/me",
            get(|iam: Helpers| async move { me(&iam).await.map(axum::Json) })
                .route_layer(iam.require_session(None)),
        )
        .route("/secure", get(ok).route_layer(iam.require_session(mfa())))
        .route("/danger", post(ok).route_layer(iam.require_session(None)))
        .route(
            "/admin",
            get(ok).route_layer(iam.authorize(AuthorizeRule::new("iam:identities:update"), None)),
        )
        .route(
            "/login",
            post(
                move |iam: Helpers, axum::Json(body): axum::Json<Value>| async move {
                    login(&iam, &tenant_id, body).await.map(axum::Json)
                },
            ),
        )
        .route(
            "/logout",
            post(|iam: Helpers| async move { logout(&iam).await.map(axum::Json) }),
        )
        .route(
            "/thrower",
            get(|iam: Helpers| async move { thrower(&iam).await.map(axum::Json) }),
        )
        .layer(iam.layer())
}

#[test]
fn tower_layer_with_axum_serves_the_api_guards_routes_and_handles_refusals() {
    run(|| async {
        let org = Arc::new(organization(|_| {}).await);
        let fetch = axum_fetch(axum_app(org.clone(), pages()));
        scenario(&org, &fetch).await;
    });
}

mod actix {
    use super::*;
    use actix_web::test as atest;
    use actix_web::{App, HttpRequest, HttpResponse, web};
    use better_iam_middleware::actix::IamActix;
    use std::rc::Rc;

    pub fn fetch_for<S, B>(app: Rc<S>) -> Fetch
    where
        S: actix_web::dev::Service<
                actix_http::Request,
                Response = actix_web::dev::ServiceResponse<B>,
                Error = actix_web::Error,
            > + 'static,
        B: actix_web::body::MessageBody + 'static,
    {
        Box::new(move |call: Call| {
            let app = app.clone();
            Box::pin(async move {
                let mut request = atest::TestRequest::default()
                    .method(
                        actix_web::http::Method::from_bytes(call.method.as_str().as_bytes())
                            .unwrap(),
                    )
                    .uri(&call.path)
                    .insert_header(("host", "127.0.0.1"));
                for (name, value) in &call.headers {
                    request = request.append_header((name.as_str(), value.as_str()));
                }
                if let Some(body) = call.body {
                    request = request.set_payload(body);
                }
                let response = atest::call_service(app.as_ref(), request.to_request()).await;
                let status = response.status().as_u16();
                let mut headers = HeaderMap::new();
                for (name, value) in response.headers().iter() {
                    headers.append(
                        http::HeaderName::from_bytes(name.as_str().as_bytes()).unwrap(),
                        http::HeaderValue::from_bytes(value.as_bytes()).unwrap(),
                    );
                }
                let body = atest::read_body(response).await;
                Answer {
                    status,
                    headers,
                    body,
                }
            })
        })
    }

    fn reply(result: Result<Value, MiddlewareError>) -> Result<HttpResponse, MiddlewareError> {
        result.map(|value| HttpResponse::Ok().json(value))
    }

    #[test]
    fn actix_middleware_serves_the_api_guards_routes_and_handles_refusals() {
        run(|| async {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let org = Arc::new(organization(|_| {}).await);
                    let iam = IamActix::new(org.clone(), pages());
                    let tenant_id = org.tenant_id.clone();
                    let ok = || async { HttpResponse::Ok().json(json!({ "ok": true })) };
                    let app = atest::init_service(
                        App::new()
                            .wrap(iam.middleware())
                            .service(web::resource("/me").wrap(iam.require_session(None)).route(
                                web::get().to(|iam: Helpers| async move { reply(me(&iam).await) }),
                            ))
                            .service(
                                web::resource("/secure")
                                    .wrap(iam.require_session(mfa()))
                                    .route(web::get().to(ok)),
                            )
                            .service(
                                web::resource("/danger")
                                    .wrap(iam.require_session(None))
                                    .route(web::post().to(ok)),
                            )
                            .service(
                                web::resource("/admin")
                                    .wrap(iam.authorize(
                                        AuthorizeRule::new("iam:identities:update"),
                                        None,
                                    ))
                                    .route(web::get().to(ok)),
                            )
                            .route(
                                "/login",
                                web::post().to(move |iam: Helpers, body: web::Json<Value>| {
                                    let tenant_id = tenant_id.clone();
                                    async move {
                                        reply(login(&iam, &tenant_id, body.into_inner()).await)
                                    }
                                }),
                            )
                            .route(
                                "/logout",
                                web::post()
                                    .to(|iam: Helpers| async move { reply(logout(&iam).await) }),
                            )
                            .route(
                                "/thrower",
                                web::get()
                                    .to(|iam: Helpers| async move { reply(thrower(&iam).await) }),
                            ),
                    )
                    .await;
                    let fetch = fetch_for(Rc::new(app));
                    scenario(&org, &fetch).await;
                })
                .await;
        });
    }

    #[test]
    fn actix_guards_read_route_parameters() {
        run(|| async {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let org = Arc::new(organization(|_| {}).await);
                    let iam = IamActix::new(org.clone(), IamLayerOptions::default());
                    let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
                    let record = seen.clone();
                    let rule = AuthorizeRule::<HttpRequest>::new("iam:identities:update")
                        .tenant_id(move |request, _| {
                            let tenant = request
                                .match_info()
                                .get("tenantId")
                                .unwrap_or_default()
                                .to_owned();
                            record.lock().unwrap().push(format!("actix:{tenant}"));
                            tenant
                        })
                        .resource(|request, _| ResourceRef {
                            kind: "iam".into(),
                            id: request
                                .match_info()
                                .get("tenantId")
                                .unwrap_or_default()
                                .to_owned(),
                        });
                    let app = atest::init_service(
                        App::new().wrap(iam.middleware()).service(
                            web::resource("/tenants/{tenantId}/admin")
                                .wrap(iam.authorize(rule, None))
                                .route(web::get().to(|| async { HttpResponse::Ok().finish() })),
                        ),
                    )
                    .await;
                    let fetch = fetch_for(Rc::new(app));
                    let owner = owner_cookie(&org, &fetch).await;
                    let path = format!("/tenants/{}/admin", org.tenant_id);
                    assert_eq!(fetch(get_(&path, &[("cookie", &owner)])).await.status, 200);
                    assert_eq!(
                        *seen.lock().unwrap(),
                        vec![format!("actix:{}", org.tenant_id)]
                    );
                })
                .await;
        });
    }
}

async fn owner_cookie(org: &Org, fetch: &Fetch) -> String {
    let sign_in = fetch(post_(
        "/api/iam/auth/signIn",
        &JSON,
        Some(
            json!({
                "tenantId": org.tenant_id,
                "email": "owner@acme.test",
                "password": "a strong tenant owner password",
            })
            .to_string(),
        ),
    ))
    .await;
    sign_in.cookie().expect("owner session cookie")
}

#[test]
fn authorize_callbacks_read_route_parameters() {
    run(|| async {
        let org = Arc::new(organization(|_| {}).await);
        let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let record = seen.clone();
        let iam = IamTower::new(org.clone(), IamLayerOptions::default());
        let rule = AuthorizeRule::new("iam:identities:update")
            .tenant_id(move |parts, _| {
                let tenant = path_param(parts, "tenantId").unwrap_or_default();
                record.lock().unwrap().push(format!("axum:{tenant}"));
                tenant
            })
            .resource(|parts, _| ResourceRef {
                kind: "iam".into(),
                id: path_param(parts, "tenantId").unwrap_or_default(),
            });
        let app = Router::new()
            .route(
                "/tenants/{tenantId}/admin",
                get(|| async { axum::Json(json!({ "ok": true })) })
                    .route_layer(iam.authorize(rule, None)),
            )
            .layer(iam.layer());
        let fetch = axum_fetch(app);
        let owner = owner_cookie(&org, &fetch).await;
        let path = format!("/tenants/{}/admin", org.tenant_id);
        assert_eq!(fetch(get_(&path, &[("cookie", &owner)])).await.status, 200);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![format!("axum:{}", org.tenant_id)]
        );
        // A rule naming another tenant is decided there: the owner holds nothing in the root tenant.
        let foreign = format!("/tenants/{}/admin", org.root_tenant);
        assert_eq!(
            fetch(get_(&foreign, &[("cookie", &owner)])).await.status,
            403
        );
    });
}

/// A protocol served only through the node transport's mounts: echoes the request-target it received.
struct EchoProtocol;

#[async_trait]
impl ProtocolService for EchoProtocol {
    fn base_path(&self) -> &str {
        "/node-proto"
    }

    async fn handler(&self, request: &HttpRequest) -> IamResult<Option<HttpResponse>> {
        if !request.uri().path().starts_with("/node-proto") {
            return Ok(None);
        }
        let served = request
            .uri()
            .path_and_query()
            .map(|target| target.as_str().to_owned())
            .unwrap_or_default();
        let mut response =
            http::Response::new(Bytes::from(json!({ "served": served }).to_string()));
        response.headers_mut().insert(
            "content-type",
            http::HeaderValue::from_static("application/json"),
        );
        Ok(Some(response))
    }
}

#[test]
fn protocol_mounts_listed_in_serve_are_reached() {
    run(|| async {
        let org = Arc::new(organization(|_| {}).await);
        org.iam.use_protocol(Arc::new(EchoProtocol));
        let iam = IamTower::new(
            org.clone(),
            IamLayerOptions {
                serve: Some(vec!["/api/iam".into(), "/node-proto".into()]),
                ..IamLayerOptions::default()
            },
        );
        let app = Router::new()
            .route(
                "/node-proto/x",
                get(|| async { axum::Json(json!({ "served": "by the app" })) }),
            )
            .layer(iam.layer());
        let fetch = axum_fetch(app);
        assert_eq!(
            fetch(get_("/node-proto/metadata?x=1", &[])).await.json(),
            json!({ "served": "/node-proto/metadata?x=1" })
        );
        assert_eq!(
            fetch(get_("/node-proto/x", &[])).await.json(),
            json!({ "served": "/node-proto/x" })
        );
        let posted = fetch(post_(
            "/node-proto/metadata",
            &[("content-type", "application/json")],
            Some("{\"a\":1}".into()),
        ))
        .await;
        assert_eq!(posted.json(), json!({ "served": "/node-proto/metadata" }));
        // Bodies beyond the node transport's limit are refused before they reach the server.
        let large = fetch(post_(
            "/api/iam/auth/signIn",
            &JSON,
            Some("x".repeat(70_000)),
        ))
        .await;
        assert_eq!(large.status, 413);
    });
}

/// An instance that counts its `authorizeMany` calls.
struct Counting {
    org: Arc<Org>,
    calls: AtomicUsize,
}

#[async_trait]
impl IamLike for Counting {
    async fn get_session(&self, credential: &CredentialInput) -> Result<Value, MiddlewareError> {
        self.org.as_ref().get_session(credential).await
    }

    async fn sign_out(&self, credential: &CredentialInput) -> Result<Value, MiddlewareError> {
        self.org.as_ref().sign_out(credential).await
    }

    async fn handler(&self, request: HttpRequest) -> HttpResponse {
        IamLike::handler(self.org.as_ref(), request).await
    }

    async fn require(&self, request: &AuthorizationRequest) -> Result<(), MiddlewareError> {
        IamLike::require(self.org.as_ref(), request).await
    }

    async fn authorize_many(
        &self,
        request: &BatchAuthorizationRequest,
    ) -> Result<Vec<better_iam_middleware::AuthorizeResult>, MiddlewareError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        IamLike::authorize_many(self.org.as_ref(), request).await
    }

    fn endpoint(&self) -> Option<EndpointRef> {
        IamLike::endpoint(self.org.as_ref())
    }
}

#[test]
fn batches_advisory_checks_per_request() {
    run(|| async {
        let org = Arc::new(organization(|_| {}).await);
        let counting = Arc::new(Counting {
            org: org.clone(),
            calls: AtomicUsize::new(0),
        });
        let iam = IamTower::new(counting.clone(), IamLayerOptions::default());
        let app = Router::new()
            .route(
                "/checks",
                get(|iam: IamRequest<Counting>| async move {
                    let (a, b, c) = tokio::join!(
                        iam.can("iam:identities:read", None, None),
                        iam.can("iam:identities:update", None, None),
                        iam.can("iam:identities:read", None, None),
                    );
                    axum::Json(json!([a.unwrap(), b.unwrap(), c.unwrap()]))
                }),
            )
            .layer(iam.layer());
        let token = org.owner_credential.token.clone().unwrap();
        let cookie = format!("better-iam.session={token}");
        let response = axum_fetch(app)(get_("/checks", &[("cookie", &cookie)])).await;
        assert_eq!(response.json(), json!([true, true, true]));
        assert_eq!(counting.calls.load(Ordering::SeqCst), 1);
    });
}

fn helpers_with(org: &Arc<Org>, headers: HeaderMap) -> IamRequest<Org> {
    create_request_helpers(
        IamSource::from(org.clone()),
        RequestBinding {
            url: url::Url::parse("http://localhost:3000/documents").unwrap(),
            headers,
            set_cookie: Arc::new(|_| {}),
        },
        RequestHelperOptions::default(),
    )
}

#[test]
fn plan_plans_for_the_request_credential_and_never_when_signed_out() {
    run(|| async {
        let org = Arc::new(organization(|_| {}).await);
        let mut headers = HeaderMap::new();
        let token = org.owner_credential.token.clone().unwrap();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        let owner = helpers_with(&org, headers);
        let plan = owner
            .plan(PlanInput {
                action: "documents:read".into(),
                kind: "document".into(),
                tenant_id: None,
            })
            .await
            .unwrap();
        assert_eq!(plan["tenantId"], json!(org.tenant_id));
        assert_eq!(plan["kind"], "always");
        let anonymous = helpers_with(&org, HeaderMap::new());
        let plan = anonymous
            .plan(PlanInput {
                action: "documents:read".into(),
                kind: "document".into(),
                tenant_id: None,
            })
            .await
            .unwrap();
        assert_eq!(plan["kind"], "never");
        assert_eq!(plan["filter"], json!({ "kind": "false" }));
    });
}

#[test]
fn helpers_answer_signed_out_requests_without_calling_the_server() {
    run(|| async {
        let org = Arc::new(organization(|_| {}).await);
        let anonymous = helpers_with(&org, HeaderMap::new());
        assert_eq!(anonymous.get_session().await.unwrap(), None);
        assert!(
            !anonymous
                .can("iam:identities:read", None, None)
                .await
                .unwrap()
        );
        let results = anonymous
            .authorize(
                vec![better_iam_middleware::AuthorizeInput {
                    action: "iam:identities:read".into(),
                    resource: None,
                }],
                None,
            )
            .await
            .unwrap();
        assert_eq!(results[0].reason, "UNAUTHENTICATED");
        assert!(!results[0].allowed);
        let listed = anonymous
            .list_accessible(better_iam_middleware::ListAccessibleInput {
                action: "documents:read".into(),
                kind: "document".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(listed, json!({ "resources": [], "total": 0 }));
        let refused = anonymous.require_session(None).await.unwrap_err();
        assert_eq!(better_iam_middleware::error_status(&refused), Some(401));
        // The owner's helpers decide and issue assertions with the request credential.
        let mut headers = HeaderMap::new();
        let token = org.owner_credential.token.clone().unwrap();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        let owner = helpers_with(&org, headers);
        let results = owner
            .authorize(
                vec![better_iam_middleware::AuthorizeInput {
                    action: "iam:identities:read".into(),
                    resource: None,
                }],
                None,
            )
            .await
            .unwrap();
        assert!(results[0].allowed, "{results:?}");
        assert_eq!(results[0].resource.id, org.tenant_id);
        let assertion = owner
            .assertion(&better_iam_middleware::AssertionInput {
                tenant_id: org.tenant_id.clone(),
                audience: "billing-service".into(),
                ttl_seconds: None,
                claims: None,
            })
            .await;
        assert!(
            assertion.is_ok()
                || better_iam_middleware::error_code(assertion.as_ref().unwrap_err()).is_some(),
            "{assertion:?}"
        );
        // A path that is not a plain route is refused by the in-process client before it is sent.
        let invalid = owner
            .client()
            .request("../auth/signIn", json!({}))
            .await
            .unwrap_err();
        assert_eq!(
            better_iam_middleware::error_code(&invalid),
            Some("INVALID_PATH")
        );
    });
}
