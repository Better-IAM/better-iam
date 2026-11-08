//! Representative calls run on a thread with a 1 MiB stack (the Windows main thread's size, half of what tokio and
//! actix-web give their workers), so an ordinary `#[tokio::main]` application can call the API and serve requests
//! in a debug build without enlarging any stack: an API call through `iam.api` and requests through the handler.

#[path = "organization_fixture/mod.rs"]
mod organization_fixture;

use std::future::Future;

use bytes::Bytes;
use http::Method;
use organization_fixture::{ORIGIN, body, ok, organization};
use serde_json::{Value, json};

const STACK: usize = 1024 * 1024;

/// Runs `body` the way `#[tokio::main]` runs `main`: polled by `block_on` on the calling thread, here one with a
/// 1 MiB stack, with a runtime whose worker threads get 1 MiB too.
fn on_small_stack<F, Fut>(body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK)
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(body());
        })
        .expect("thread")
        .join()
        .expect("the body ran within a 1 MiB stack");
}

fn size_of<T>(_: &T) -> usize {
    std::mem::size_of::<T>()
}

#[test]
fn api_calls_run_within_a_one_mebibyte_stack() {
    on_small_stack(|| async {
        let org = organization(|_| {}).await;
        let iam = &org.iam;
        let create = iam.api.identities.create(
            &org.owner_credential,
            body(json!({
                "tenantId": org.tenant_id,
                "email": "carol@acme.test",
                "name": "Carol",
            })),
        );
        eprintln!("identities.create future: {} bytes", size_of(&create));
        let created = ok(create.await);
        assert_eq!(created["email"], "carol@acme.test");

        let tenant = iam.api.tenants.create(
            &org.root_credential,
            body(json!({
                "parentId": org.root_tenant,
                "type": "organization",
                "name": "Globex",
                "ownerEmail": "owner@globex.test",
                "activate": true,
            })),
        );
        eprintln!("tenants.create future: {} bytes", size_of(&tenant));
        let tenant = ok(tenant.await);
        assert_eq!(tenant["tenant"]["name"], "Globex");

        let listed = ok(iam
            .api
            .identities
            .list(
                &org.owner_credential,
                body(json!({ "tenantId": org.tenant_id })),
            )
            .await);
        assert!(listed.to_string().contains("carol@acme.test"), "{listed}");
    });
}

#[test]
fn http_requests_run_within_a_one_mebibyte_stack() {
    on_small_stack(|| async {
        let org = organization(|_| {}).await;
        let post = |path: &str, headers: &[(&str, &str)], value: Value| {
            let mut request = http::Request::builder()
                .method(Method::POST)
                .uri(format!("{ORIGIN}/api/iam/{path}"))
                .header("content-type", "application/json")
                .header("x-better-iam", "1")
                .header("origin", ORIGIN);
            for (name, value) in headers {
                request = request.header(*name, *value);
            }
            request.body(Bytes::from(value.to_string())).unwrap()
        };
        let sign_in = org.iam.http.handler(post(
            "auth/signIn",
            &[],
            json!({
                "tenantId": org.tenant_id,
                "email": "owner@acme.test",
                "password": "a strong tenant owner password",
            }),
        ));
        eprintln!("http.handler future: {} bytes", size_of(&sign_in));
        let sign_in = sign_in.await;
        assert_eq!(sign_in.status(), 200);
        let session: Value = serde_json::from_slice(sign_in.body()).unwrap();
        let token = session["data"]["token"]
            .as_str()
            .or_else(|| session["token"].as_str())
            .map(str::to_owned);
        let cookie = sign_in
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .find(|value| value.starts_with("better-iam.session="))
            .map(|value| value.split(';').next().unwrap().to_owned());
        let authorization = token.map(|token| format!("Bearer {token}"));
        let headers: Vec<(&str, &str)> = match (&authorization, &cookie) {
            (Some(authorization), _) => vec![("authorization", authorization.as_str())],
            (None, Some(cookie)) => vec![("cookie", cookie.as_str())],
            (None, None) => panic!("sign-in issued no session: {session}"),
        };
        let created = org
            .iam
            .handler(post(
                "identities/create",
                &headers,
                json!({ "tenantId": org.tenant_id, "email": "dave@acme.test", "name": "Dave" }),
            ))
            .await;
        let answer: Value = serde_json::from_slice(created.body()).unwrap();
        assert_eq!(created.status(), 200, "{answer}");
        assert_eq!(answer["data"]["email"], "dave@acme.test");
    });
}
