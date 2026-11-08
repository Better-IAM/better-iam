//! Client hooks: `onUnauthenticated`, the rate-limit retry and its cancellation, request ids
//! (tests/client-hooks.test.ts), and rate-limit refusals through the typed client (tests/retry-after.test.ts).

mod support;

#[path = "../../server/tests/organization_fixture/mod.rs"]
mod organization_fixture;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::RateLimitOptions;
use better_iam_client::{
    AbortController, AbortError, ClientOptions, Error, IamClientError, RequestId, RetryRateLimited,
    create_iam_client,
};
use better_iam_core::{IamStore, SessionClientInfo};
use better_iam_server::options::{BetterIamOptions, HttpOptions, ServerAuthOptions};
use serde_json::{Value, json};
use support::{Mock, data, failure, header, run, run_paused, server_fetch};

const ORIGIN: &str = "https://app.example.com";

fn client_error(error: Error) -> IamClientError {
    error.client().cloned().expect("an IamClientError")
}

fn sign_in_input() -> Value {
    json!({ "tenantId": "t", "email": "a@example.com", "password": "wrong" })
}

#[test]
fn reports_lapsed_sessions_once_per_request_through_on_unauthenticated_never_credential_failures() {
    run(|| async {
        let fetcher = Mock::new();
        fetcher
            .once(failure("UNAUTHENTICATED", 401, json!({}), &[]))
            .once(failure("INVALID_CREDENTIALS", 401, json!({}), &[]))
            .once(data(json!({ "identity": { "id": "usr_1" } })));
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let client = create_iam_client(
            ClientOptions::new(ORIGIN)
                .fetch(fetcher.fetch())
                .on_unauthenticated(move |error| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    panic!("hook failure for {}", error.code);
                }),
        )
        .unwrap();
        let error = client_error(
            client
                .request::<Value>("auth/getSession", &json!({}))
                .await
                .unwrap_err(),
        );
        assert_eq!(
            (error.code.as_str(), error.status),
            ("UNAUTHENTICATED", 401)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // A wrong password is the caller's problem, not a lapsed session.
        let error = client_error(
            client
                .request::<Value>("auth/signIn", &sign_in_input())
                .await
                .unwrap_err(),
        );
        assert_eq!(error.code, "INVALID_CREDENTIALS");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let session: Value = client.request("auth/getSession", &json!({})).await.unwrap();
        assert_eq!(session, json!({ "identity": { "id": "usr_1" } }));
    });
}

#[test]
fn treats_a_session_refused_from_another_network_as_ended_but_not_sign_in_or_step_up_refusals() {
    run(|| async {
        let fetcher = Mock::new();
        fetcher
            .once(failure("SESSION_NETWORK_MISMATCH", 401, json!({}), &[]))
            .once(failure("MFA_REQUIRED", 403, json!({}), &[]))
            .once(failure("EMAIL_UNVERIFIED", 403, json!({}), &[]))
            .once(failure("IP_BLOCKED", 403, json!({}), &[]))
            .once(failure("INVALID_CREDENTIALS", 401, json!({}), &[]));
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let record = seen.clone();
        let client = create_iam_client(
            ClientOptions::new(ORIGIN)
                .fetch(fetcher.fetch())
                .on_unauthenticated(move |error| record.lock().unwrap().push(error.code.clone())),
        )
        .unwrap();
        let error = client_error(client.auth().get_session().await.unwrap_err());
        assert_eq!(
            (error.code.as_str(), error.status),
            ("SESSION_NETWORK_MISMATCH", 401)
        );
        assert_eq!(
            *seen.lock().unwrap(),
            vec!["SESSION_NETWORK_MISMATCH".to_owned()]
        );
        // These are also raised by sign-in and step-up flows, where a trip to the login page would not help.
        for code in ["MFA_REQUIRED", "EMAIL_UNVERIFIED", "IP_BLOCKED"] {
            assert_eq!(
                client_error(client.auth().get_session().await.unwrap_err()).code,
                code
            );
        }
        let error = client_error(
            client
                .request::<Value>("auth/signIn", &sign_in_input())
                .await
                .unwrap_err(),
        );
        assert_eq!(error.code, "INVALID_CREDENTIALS");
        assert_eq!(seen.lock().unwrap().len(), 1);
    });
}

#[test]
fn reports_a_network_bound_session_presented_from_elsewhere_against_a_real_server() {
    organization_fixture::run(|| async {
        let f = organization_fixture::organization(|options| {
            options.http = Some(HttpOptions {
                client_info: Some(Arc::new(|head| {
                    let ip = head.headers.get("x-test-ip")?.to_str().ok()?.to_owned();
                    Some(SessionClientInfo {
                        ip: Some(ip),
                        ..SessionClientInfo::default()
                    })
                })),
                ..HttpOptions::default()
            });
        })
        .await;
        let alice = f.member("alice").await;
        let session = f
            .iam
            .auth
            .with_client(
                Some(SessionClientInfo {
                    ip: Some("203.0.113.7".into()),
                    ..SessionClientInfo::default()
                }),
                f.sign_in(&alice),
            )
            .await;
        f.iam
            .api
            .tenants
            .set_auth_policy(
                &f.owner_credential,
                organization_fixture::body(json!({
                    "tenantId": f.tenant_id,
                    "authPolicy": { "bindSessionsToIp": true },
                })),
            )
            .await
            .expect("set the auth policy");
        let calls: Arc<Mutex<Vec<String>>> = Arc::default();
        let token = session.token.clone().unwrap();
        let from = |ip: &str| {
            let record = calls.clone();
            create_iam_client(
                ClientOptions::new("http://localhost:3000")
                    .token(token.clone())
                    .headers([("x-test-ip", ip)])
                    .fetch(server_fetch(f.iam.http.clone()))
                    .on_unauthenticated(move |error| {
                        record.lock().unwrap().push(error.code.clone())
                    }),
            )
            .unwrap()
        };
        let current = from("203.0.113.7")
            .auth()
            .get_session()
            .await
            .expect("the session");
        assert_eq!(current.identity.id, alice);
        let error = client_error(from("198.51.100.9").auth().get_session().await.unwrap_err());
        assert_eq!(
            (error.code.as_str(), error.status),
            ("SESSION_NETWORK_MISMATCH", 401)
        );
        assert_eq!(
            *calls.lock().unwrap(),
            vec!["SESSION_NETWORK_MISMATCH".to_owned()]
        );
    });
}

#[test]
fn retries_a_rate_limited_call_once_after_the_server_wait_when_that_wait_is_short_enough() {
    run_paused(|| async {
        let fetcher = Mock::new();
        fetcher
            .once(failure(
                "RATE_LIMITED",
                429,
                json!({ "retryAfterMs": 1_500 }),
                &[],
            ))
            .once(data(json!({ "identity": { "id": "usr_1" } })))
            .once(failure(
                "RATE_LIMITED",
                429,
                json!({ "retryAfterMs": 60_000 }),
                &[],
            ))
            .once(failure(
                "RATE_LIMITED",
                429,
                json!({ "retryAfterMs": 1_000 }),
                &[],
            ))
            .once(failure(
                "RATE_LIMITED",
                429,
                json!({ "retryAfterMs": 1_000 }),
                &[],
            ));
        let client = create_iam_client(
            ClientOptions::new(ORIGIN)
                .fetch(fetcher.fetch())
                .retry_rate_limited(RetryRateLimited {
                    max_wait_ms: Some(2_000.0),
                }),
        )
        .unwrap();
        let started = tokio::time::Instant::now();
        let session: Value = client.request("auth/getSession", &json!({})).await.unwrap();
        assert_eq!(session, json!({ "identity": { "id": "usr_1" } }));
        assert!(started.elapsed() >= Duration::from_millis(1_500));
        assert_eq!(fetcher.count(), 2);
        // A wait beyond the cap surfaces the error unchanged; a second refusal after the retry does too.
        let error = client_error(client.auth().get_session().await.unwrap_err());
        assert_eq!(
            (error.code.as_str(), error.retry_after_ms),
            ("RATE_LIMITED", Some(60_000.0))
        );
        assert_eq!(fetcher.count(), 3);
        let error = client_error(client.auth().get_session().await.unwrap_err());
        assert_eq!(error.code, "RATE_LIMITED");
        assert_eq!(fetcher.count(), 5);
        // Off by default.
        let plain_fetcher = Mock::new();
        plain_fetcher.always(failure(
            "RATE_LIMITED",
            429,
            json!({ "retryAfterMs": 10 }),
            &[],
        ));
        let plain =
            create_iam_client(ClientOptions::new(ORIGIN).fetch(plain_fetcher.fetch())).unwrap();
        assert_eq!(
            client_error(plain.auth().get_session().await.unwrap_err()).code,
            "RATE_LIMITED"
        );
        assert_eq!(plain_fetcher.count(), 1);
        // The wait can also come from the Retry-After header (seconds).
        let header_fetcher = Mock::new();
        header_fetcher.once(failure(
            "RATE_LIMITED",
            429,
            json!({}),
            &[("retry-after", "2")],
        ));
        header_fetcher.once(failure(
            "RATE_LIMITED",
            429,
            json!({}),
            &[("retry-after", "soon")],
        ));
        let headed =
            create_iam_client(ClientOptions::new(ORIGIN).fetch(header_fetcher.fetch())).unwrap();
        assert_eq!(
            client_error(headed.auth().get_session().await.unwrap_err()).retry_after_ms,
            Some(2_000.0)
        );
        assert_eq!(
            client_error(headed.auth().get_session().await.unwrap_err()).retry_after_ms,
            None
        );
    });
}

#[test]
fn stops_waiting_to_retry_the_moment_the_call_is_aborted() {
    run_paused(|| async {
        let limited = || failure("RATE_LIMITED", 429, json!({ "retryAfterMs": 4_000 }), &[]);
        // The stub ignores the signal, as if the abort landed after the response arrived.
        let fetcher = Mock::new();
        fetcher.always(limited());
        let client = create_iam_client(
            ClientOptions::new(ORIGIN)
                .fetch(fetcher.fetch())
                .retry_rate_limited(RetryRateLimited::default()),
        )
        .unwrap();
        // Aborted during the wait: the call rejects at once with the signal's reason and sends nothing more.
        let reason: better_iam_client::AbortReason =
            Arc::new(better_iam_client::FetchError("search cancelled".into()));
        let controller = AbortController::new();
        let cancelled = tokio::spawn(
            client
                .auth()
                .get_session()
                .signal(controller.signal())
                .send(),
        );
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(!cancelled.is_finished());
        controller.abort_with(reason.clone());
        let error = cancelled.await.unwrap().unwrap_err();
        assert!(Arc::ptr_eq(error.abort_reason().unwrap(), &reason));
        assert_eq!(fetcher.count(), 1);
        // Without a reason, the rejection is the standard AbortError.
        let bare = AbortController::new();
        let plain = tokio::spawn(client.auth().get_session().signal(bare.signal()).send());
        tokio::time::advance(Duration::from_millis(100)).await;
        bare.abort();
        let error = plain.await.unwrap().unwrap_err();
        let abort = error
            .abort_reason()
            .unwrap()
            .downcast_ref::<AbortError>()
            .unwrap();
        assert_eq!(abort.name(), "AbortError");
        assert_eq!(fetcher.count(), 2);
        // A signal already aborted when the refusal arrives never starts the wait.
        let early = AbortController::new();
        early.abort_with(reason.clone());
        let started = tokio::time::Instant::now();
        let error = client
            .auth()
            .get_session()
            .signal(early.signal())
            .await
            .unwrap_err();
        assert!(Arc::ptr_eq(error.abort_reason().unwrap(), &reason));
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(fetcher.count(), 3);
        // A signal that is never aborted leaves the retry unchanged.
        fetcher
            .once(limited())
            .once(data(json!({ "identity": { "id": "usr_1" } })));
        let kept = AbortController::new();
        let retried: Value = client
            .request("auth/getSession", &json!({}))
            .signal(kept.signal())
            .await
            .unwrap();
        assert_eq!(retried, json!({ "identity": { "id": "usr_1" } }));
        assert_eq!(fetcher.count(), 5);
    });
}

#[test]
fn tags_requests_with_x_request_id_and_carries_it_on_errors() {
    run(|| async {
        let fetcher = Mock::new();
        fetcher
            .once(data(json!({ "identity": { "id": "usr_1" } })))
            .once(failure("ACCESS_DENIED", 403, json!({}), &[]));
        let ids = Arc::new(Mutex::new(vec!["req-one".to_owned(), "req-two".to_owned()]));
        let supply = ids.clone();
        let client = create_iam_client(
            ClientOptions::new(ORIGIN)
                .fetch(fetcher.fetch())
                .request_id(RequestId::Custom(Arc::new(move || {
                    supply.lock().unwrap().remove(0)
                }))),
        )
        .unwrap();
        let _: Value = client.request("auth/getSession", &json!({})).await.unwrap();
        assert_eq!(
            header(&fetcher.call(0), "x-request-id").as_deref(),
            Some("req-one")
        );
        let error = client_error(client.auth().get_session().await.unwrap_err());
        assert_eq!(error.request_id.as_deref(), Some("req-two"));
        // Generated identifiers are plain tokens the server accepts.
        let generated = Mock::new();
        generated.always(data(json!({ "identity": { "id": "usr_1" } })));
        let _: Value = create_iam_client(
            ClientOptions::new(ORIGIN)
                .fetch(generated.fetch())
                .request_id(RequestId::Generate),
        )
        .unwrap()
        .request("auth/getSession", &json!({}))
        .await
        .unwrap();
        let id = header(&generated.call(0), "x-request-id").unwrap();
        assert!(!id.is_empty() && id.len() <= 128);
        assert!(
            id.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        );
        // An invalid custom identifier is refused before anything is sent.
        let error = create_iam_client(
            ClientOptions::new(ORIGIN)
                .fetch(generated.fetch())
                .request_id(RequestId::Custom(Arc::new(|| "not valid!".to_owned()))),
        )
        .unwrap()
        .auth()
        .get_session()
        .await
        .unwrap_err();
        assert_eq!(client_error(error).code, "INVALID_CONFIG");
        assert_eq!(generated.count(), 1);
    });
}

#[test]
fn rate_limit_refusals_tell_callers_when_to_retry_over_http_and_through_the_typed_client() {
    run(|| async {
        let database: Arc<dyn IamStore> =
            sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
        let mut options = BetterIamOptions::new(
            database,
            "retry-after-test-secret-with-at-least-32-chars",
            "http://localhost:3000",
        );
        options.authentication = Some(ServerAuthOptions {
            rate_limits: Some(RateLimitOptions {
                attempts: Some(2.0),
                window_ms: Some(90_000.0),
                ..RateLimitOptions::default()
            }),
            ..ServerAuthOptions::default()
        });
        let iam = better_iam_server::better_iam(options).expect("valid options");
        iam.initialize().await.expect("initialize");
        let root = iam
            .bootstrap(&json!({ "email": "root@example.test", "name": "Root", "password": "a strong root test password" }))
            .await
            .expect("bootstrap");
        let tenant_id = root["tenant"]["id"].as_str().unwrap().to_owned();
        let client = create_iam_client(
            ClientOptions::new("http://localhost:3000").fetch(server_fetch(iam.http.clone())),
        )
        .unwrap();
        let attempt = || {
            client
                .auth()
                .sign_in(better_iam_types::api::auth::SignInInput {
                    tenant_id: tenant_id.clone(),
                    email: "root@example.test".into(),
                    password: "no".into(),
                    ..Default::default()
                })
        };
        assert_eq!(
            client_error(attempt().await.unwrap_err()).code,
            "INVALID_CREDENTIALS"
        );
        assert_eq!(
            client_error(attempt().await.unwrap_err()).code,
            "INVALID_CREDENTIALS"
        );
        let limited = client_error(attempt().await.unwrap_err());
        assert_eq!(
            (
                limited.code.as_str(),
                limited.status,
                limited.retry_after_ms
            ),
            ("RATE_LIMITED", 429, Some(90_000.0))
        );
        let response = iam
            .http
            .handler(
                http::Request::builder()
                    .method("POST")
                    .uri("http://localhost:3000/api/iam/auth/signIn")
                    .header("content-type", "application/json")
                    .header("x-better-iam", "1")
                    .body(bytes::Bytes::from(
                        json!({ "tenantId": tenant_id, "email": "root@example.test", "password": "no" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), 429);
        assert_eq!(response.headers().get("retry-after").unwrap(), "90");
        assert_eq!(
            serde_json::from_slice::<Value>(response.body()).unwrap(),
            json!({ "error": { "code": "RATE_LIMITED", "message": "Too many attempts; try again later", "retryAfterMs": 90_000 } })
        );
        let limited = client_error(attempt().await.unwrap_err());
        assert_eq!(
            (
                limited.code.as_str(),
                limited.status,
                limited.retry_after_ms
            ),
            ("RATE_LIMITED", 429, Some(90_000.0))
        );
    });
}
