//! Middleware-guarded requests on a thread with a 1 MiB stack (the Windows main thread's size, half of the 2 MiB
//! tokio and actix-web give their workers): an axum app and an actix-web app with default settings serve the IAM
//! API, sign in through the in-process client, and pass a route guard in a debug build without enlarging any stack.

#[path = "../../server/tests/organization_fixture/mod.rs"]
mod organization_fixture;

use std::future::Future;
use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use better_iam_middleware::layer::{IamLayerOptions, IamTower};
use better_iam_middleware::{AuthorizeRule, IamRequest, MiddlewareError};
use better_iam_server::BetterIam;
use http::Request;
use http_body_util::BodyExt;
use organization_fixture::{ORIGIN, organization};
use serde_json::{Value, json};
use tower::ServiceExt;

const STACK: usize = 1024 * 1024;

/// Runs `body` polled by `block_on` on a thread with a 1 MiB stack (as `#[tokio::main]` polls `main` on the main
/// thread), with a current-thread runtime and a `LocalSet` so actix-web's `!Send` services can run on it too.
fn on_small_stack<F, Fut>(body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(tokio::task::LocalSet::new().run_until(body()));
        })
        .expect("thread")
        .join()
        .expect("the body ran within a 1 MiB stack");
}

type Helpers = IamRequest<BetterIam>;

async fn me(iam: &Helpers) -> Result<Value, MiddlewareError> {
    let session = iam.get_session().await?;
    Ok(json!({
        "email": session.as_ref().map(|session| session["identity"]["email"].clone()),
        "canUpdate": iam.can("iam:identities:update", None, None).await?,
    }))
}

async fn login(iam: &Helpers, tenant_id: &str) -> Result<Value, MiddlewareError> {
    iam.client()
        .call(
            "auth",
            "signIn",
            json!({
                "tenantId": tenant_id,
                "email": "owner@acme.test",
                "password": "a strong tenant owner password",
            }),
        )
        .await?;
    let session = iam.get_session().await?;
    Ok(json!({ "signedInAs": session.map(|session| session["identity"]["email"].clone()) }))
}

/// The session cookie (`better-iam.session=…`) among `Set-Cookie` values.
fn session_cookie<'a>(values: impl Iterator<Item = &'a str>) -> String {
    values
        .filter(|value| value.starts_with("better-iam.session="))
        .map(|value| value.split(';').next().unwrap().to_owned())
        .next()
        .expect("a session cookie")
}

/// The JSON body of the owner's sign-in.
fn sign_in_body(tenant_id: &str) -> String {
    json!({
        "tenantId": tenant_id,
        "email": "owner@acme.test",
        "password": "a strong tenant owner password",
    })
    .to_string()
}

/// An org whose `BetterIam` is moved out of the fixture into an `Arc`, as an application holds it.
async fn instance() -> (Arc<BetterIam>, String) {
    let org = organization(|_| {}).await;
    (Arc::new(org.iam), org.tenant_id)
}

#[test]
fn axum_serves_guarded_requests_within_a_one_mebibyte_stack() {
    on_small_stack(|| async {
        let (iam, tenant_id) = instance().await;
        let sign_in = sign_in_body(&tenant_id);
        let tower = IamTower::new(iam, IamLayerOptions::default());
        let app =
            Router::new()
                .route(
                    "/me",
                    get(|iam: Helpers| async move { me(&iam).await.map(axum::Json) })
                        .route_layer(tower.require_session(None)),
                )
                .route(
                    "/admin",
                    get(|| async { axum::Json(json!({ "ok": true })) }).route_layer(
                        tower.authorize(AuthorizeRule::new("iam:identities:update"), None),
                    ),
                )
                .route(
                    "/login",
                    post(move |iam: Helpers| async move {
                        login(&iam, &tenant_id).await.map(axum::Json)
                    }),
                )
                .layer(tower.layer());
        let send = |request: Request<axum::body::Body>| {
            let app = app.clone();
            async move {
                let response = app.oneshot(request).await.unwrap();
                let (parts, body) = response.into_parts();
                (parts, body.collect().await.unwrap().to_bytes())
            }
        };

        let health = send(
            Request::get("/api/iam/health")
                .header("host", "127.0.0.1")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(health.0.status, 200);
        // A first API request through the layer (the node transport into the server).
        let (parts, body) = send(
            Request::post("/api/iam/auth/signIn")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header("x-better-iam", "1")
                .header("origin", ORIGIN)
                .body(axum::body::Body::from(sign_in.clone()))
                .unwrap(),
        )
        .await;
        assert_eq!(parts.status, 200, "{body:?}");
        let (parts, body) = send(
            Request::post("/login")
                .header("host", "127.0.0.1")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(parts.status, 200, "{body:?}");
        let cookie = session_cookie(
            parts
                .headers
                .get_all("set-cookie")
                .iter()
                .map(|value| value.to_str().unwrap()),
        );
        let (parts, body) = send(
            Request::get("/me")
                .header("host", "127.0.0.1")
                .header("cookie", &cookie)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(parts.status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({ "email": "owner@acme.test", "canUpdate": true })
        );
        let (parts, _) = send(
            Request::get("/admin")
                .header("host", "127.0.0.1")
                .header("cookie", &cookie)
                .header("origin", ORIGIN)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(parts.status, 200);
    });
}

#[test]
fn actix_web_serves_guarded_requests_within_a_one_mebibyte_stack() {
    use actix_web::test as atest;
    use actix_web::{App, HttpResponse, web};
    use better_iam_middleware::actix::IamActix;

    fn reply(result: Result<Value, MiddlewareError>) -> Result<HttpResponse, MiddlewareError> {
        result.map(|value| HttpResponse::Ok().json(value))
    }

    on_small_stack(|| async {
        let (iam, tenant_id) = instance().await;
        let sign_in = sign_in_body(&tenant_id);
        let actix = IamActix::new(iam, IamLayerOptions::default());
        let app = atest::init_service(
            App::new()
                .wrap(actix.middleware())
                .service(
                    web::resource("/me")
                        .wrap(actix.require_session(None))
                        .route(web::get().to(|iam: Helpers| async move { reply(me(&iam).await) })),
                )
                .service(
                    web::resource("/admin")
                        .wrap(actix.authorize(AuthorizeRule::new("iam:identities:update"), None))
                        .route(web::get().to(|| async { HttpResponse::Ok().json(json!({})) })),
                )
                .service(
                    web::resource("/login").route(web::post().to(move |iam: Helpers| {
                        let tenant_id = tenant_id.clone();
                        async move { reply(login(&iam, &tenant_id).await) }
                    })),
                ),
        )
        .await;

        let health = atest::call_service(
            &app,
            atest::TestRequest::get()
                .uri("/api/iam/health")
                .insert_header(("host", "127.0.0.1"))
                .to_request(),
        )
        .await;
        assert_eq!(health.status(), 200);
        // A first API request through the middleware (the node transport into the server).
        let api = atest::call_service(
            &app,
            atest::TestRequest::post()
                .uri("/api/iam/auth/signIn")
                .insert_header(("host", "127.0.0.1"))
                .insert_header(("content-type", "application/json"))
                .insert_header(("x-better-iam", "1"))
                .insert_header(("origin", ORIGIN))
                .set_payload(sign_in.clone())
                .to_request(),
        )
        .await;
        assert_eq!(api.status(), 200);
        let signed_in = atest::call_service(
            &app,
            atest::TestRequest::post()
                .uri("/login")
                .insert_header(("host", "127.0.0.1"))
                .to_request(),
        )
        .await;
        assert_eq!(signed_in.status(), 200);
        let cookie = session_cookie(
            signed_in
                .headers()
                .get_all("set-cookie")
                .map(|value| value.to_str().unwrap()),
        );
        let me = atest::call_service(
            &app,
            atest::TestRequest::get()
                .uri("/me")
                .insert_header(("host", "127.0.0.1"))
                .insert_header(("cookie", cookie.as_str()))
                .to_request(),
        )
        .await;
        assert_eq!(me.status(), 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&atest::read_body(me).await).unwrap(),
            json!({ "email": "owner@acme.test", "canUpdate": true })
        );
        let admin = atest::call_service(
            &app,
            atest::TestRequest::get()
                .uri("/admin")
                .insert_header(("host", "127.0.0.1"))
                .insert_header(("cookie", cookie.as_str()))
                .to_request(),
        )
        .await;
        assert_eq!(admin.status(), 200);
    });
}
