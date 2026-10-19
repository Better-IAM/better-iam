//! Regressions found by the fidelity review of the Rust foundation against the TypeScript sources: empty `Origin`
//! headers and device cookies (http.ts truthiness checks), the optional `afterAudit` plugin hook (events.ts
//! `fanOut`), and error details carried on the error (`retryAfterMs`).

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_core::{
    AfterAuditHook, Filter, FindOptions, IamError, IamErrorDetails, IamPlugin, IamResult, IamStore,
    Record,
};
use better_iam_server::options::BetterIamOptions;
use better_iam_server::{BetterIam, better_iam};
use bytes::Bytes;
use http::Method;
use serde_json::{Value, json};

const ORIGIN: &str = "https://iam.example.com";
const SECRET: &str = "review-test-secret-with-at-least-32-chars";

fn run<F, Fut>(body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(body());
        })
        .expect("thread")
        .join()
        .expect("test body");
}

async fn server(configure: impl FnOnce(&mut BetterIamOptions)) -> BetterIam {
    let store: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    let mut options = BetterIamOptions::new(store, SECRET, ORIGIN);
    configure(&mut options);
    let iam = better_iam(options).expect("valid options");
    iam.initialize().await.expect("initialize");
    iam.bootstrap(&json!({ "email": "root@example.test", "name": "Root", "password": "a strong root test password" }))
        .await
        .expect("bootstrap");
    iam
}

async fn post(iam: &BetterIam, path: &str, headers: &[(&str, &str)]) -> http::Response<Bytes> {
    let mut builder = http::Request::builder()
        .method(Method::POST)
        .uri(format!("{ORIGIN}/api/iam/{path}"))
        .header("content-type", "application/json")
        .header("x-better-iam", "1");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    iam.handler(builder.body(Bytes::from("{}")).unwrap()).await
}

fn json_of(response: &http::Response<Bytes>) -> Value {
    serde_json::from_slice(response.body()).unwrap_or(Value::Null)
}

#[test]
fn an_empty_origin_header_counts_as_no_origin() {
    run(|| async {
        let iam = server(|_| {}).await;
        // `if (origin)`: an empty Origin is not judged against the trusted origins.
        let anonymous = post(&iam, "auth/getSession", &[("origin", "")]).await;
        assert_eq!(anonymous.status(), 401, "{}", json_of(&anonymous));
        assert_eq!(
            json_of(&anonymous)["error"]["code"],
            json!("UNAUTHENTICATED")
        );
        assert!(
            anonymous
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
        // `headers.has('cookie') && !origin`: an empty Origin does not satisfy the cookie rule either.
        let cookie = post(
            &iam,
            "auth/getSession",
            &[("origin", ""), ("cookie", "better-iam.session=x")],
        )
        .await;
        assert_eq!(cookie.status(), 403);
        assert_eq!(
            json_of(&cookie)["error"]["message"],
            json!("Cookie requests require Origin")
        );
    });
}

#[test]
fn errors_carry_their_retry_hint_on_the_error() {
    let refused = IamError::with_status("RATE_LIMITED", "Too many attempts; try again later", 429)
        .with_details(IamErrorDetails {
            retry_after_ms: Some(1500.0),
            ..IamErrorDetails::default()
        });
    let response = better_iam_server::http::error_response(&refused);
    assert_eq!(response.status(), 429);
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        json_of(&response),
        json!({ "error": { "code": "RATE_LIMITED", "message": "Too many attempts; try again later", "retryAfterMs": 1500 } })
    );
    // The same code and message without details (another module's refusal) has no hint: nothing is looked up by
    // message any more.
    let plain = IamError::with_status("RATE_LIMITED", "Too many attempts; try again later", 429);
    let response = better_iam_server::http::error_response(&plain);
    assert!(response.headers().get("retry-after").is_none());
    assert!(json_of(&response)["error"].get("retryAfterMs").is_none());
    assert_eq!(plain, refused, "details are not part of equality");
}

struct Plain;

#[async_trait::async_trait]
impl IamPlugin for Plain {
    fn id(&self) -> &str {
        "plain"
    }
}

struct Hooked(Arc<AtomicUsize>);

struct Counter(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl AfterAuditHook for Counter {
    async fn after_audit(&self, _event: &Record) -> IamResult<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[async_trait::async_trait]
impl IamPlugin for Hooked {
    fn id(&self) -> &str {
        "hooked"
    }
    fn after_audit(&self) -> Option<Arc<dyn AfterAuditHook>> {
        Some(Arc::new(Counter(self.0.clone())))
    }
}

async fn audit_hook_rows(iam: &BetterIam) -> usize {
    iam.store
        .find("auditHooks", &Filter::new(), &FindOptions::default())
        .await
        .unwrap()
        .len()
}

#[test]
fn only_plugins_with_an_after_audit_hook_queue_audit_hooks() {
    run(|| async {
        // `plugins.some((plugin) => plugin.afterAudit)`: a plugin without the hook queues nothing.
        let plain = server(|options| options.plugins = Some(vec![Arc::new(Plain)])).await;
        assert_eq!(audit_hook_rows(&plain).await, 0);
        let calls = Arc::new(AtomicUsize::new(0));
        let hooked = {
            let calls = calls.clone();
            server(move |options| options.plugins = Some(vec![Arc::new(Hooked(calls))])).await
        };
        let queued = audit_hook_rows(&hooked).await;
        assert!(queued > 0);
        hooked.dispatch_audit_hooks().await.expect("dispatch");
        assert_eq!(calls.load(Ordering::SeqCst), queued);
    });
}

#[test]
fn an_empty_device_cookie_is_not_injected_into_sign_in() {
    run(|| async {
        let store: Arc<dyn IamStore> =
            sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
        let iam = better_iam(BetterIamOptions::new(store, SECRET, ORIGIN)).expect("options");
        iam.initialize().await.expect("initialize");
        let root = iam
            .bootstrap(&json!({ "email": "root@example.test", "name": "Root", "password": "a strong root test password" }))
            .await
            .expect("bootstrap");
        let body = json!({
            "tenantId": root["tenant"]["id"],
            "email": "root@example.test",
            "password": "a strong root test password",
        });
        let request = |cookie: &str| {
            http::Request::builder()
                .method(Method::POST)
                .uri(format!("{ORIGIN}/api/iam/auth/signIn"))
                .header("content-type", "application/json")
                .header("x-better-iam", "1")
                .header("origin", ORIGIN)
                .header("cookie", cookie)
                .body(Bytes::from(body.to_string()))
                .unwrap()
        };
        // `if (remembered)`: an empty remembered-device cookie is ignored, so the body never gets `deviceToken: ""`
        // (which `text(input.deviceToken, "deviceToken", 512)` refuses).
        let response = iam.handler(request("__Host-better-iam.device=")).await;
        assert_eq!(response.status(), 200, "{}", json_of(&response));
        // A non-empty one is injected (decoded) and validated like a body member.
        let long = format!("__Host-better-iam.device={}", "a".repeat(513));
        let response = iam.handler(request(&long)).await;
        assert_eq!(
            json_of(&response)["error"]["message"],
            json!("deviceToken must be a nonempty string of at most 512 characters")
        );
    });
}
