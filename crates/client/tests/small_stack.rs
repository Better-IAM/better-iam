//! The typed client calling a server in process, on a thread with a 1 MiB stack (the Windows main thread's size):
//! an ordinary `#[tokio::main]` application signs in and calls the API in a debug build without enlarging any stack.

#[path = "../../server/tests/organization_fixture/mod.rs"]
mod organization_fixture;
mod support;

use std::future::Future;

use better_iam_client::{ClientOptions, create_iam_client};
use better_iam_types::api::auth::SignInInput;
use organization_fixture::{ORIGIN, organization};
use serde_json::{Value, json};
use support::server_fetch;

const STACK: usize = 1024 * 1024;

/// Runs `body` the way `#[tokio::main]` runs `main`: polled by `block_on` on a thread with a 1 MiB stack.
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

#[test]
fn client_calls_run_within_a_one_mebibyte_stack() {
    on_small_stack(|| async {
        let org = organization(|_| {}).await;
        let anonymous =
            create_iam_client(ClientOptions::new(ORIGIN).fetch(server_fetch(org.iam.http.clone())))
                .unwrap();
        let signed_in = anonymous
            .auth()
            .sign_in(SignInInput {
                tenant_id: org.tenant_id.clone(),
                email: "owner@acme.test".into(),
                password: "a strong tenant owner password".into(),
                ..Default::default()
            })
            .await
            .expect("sign-in");
        let token = serde_json::to_value(&signed_in).unwrap()["token"]
            .as_str()
            .expect("a session token")
            .to_owned();
        let client = create_iam_client(
            ClientOptions::new(ORIGIN)
                .token(token)
                .fetch(server_fetch(org.iam.http.clone())),
        )
        .unwrap();
        let created = client
            .request::<Value>(
                "identities/create",
                &json!({ "tenantId": org.tenant_id, "email": "erin@acme.test", "name": "Erin" }),
            )
            .await
            .expect("identities/create");
        assert_eq!(created["email"], "erin@acme.test");
    });
}
