//! The typed client transport (tests/client.test.ts).

mod support;

use better_iam_client::{
    AbortController, CallOptions, ClientOptions, ConfirmMfaInput, Error, IamClientError,
    MfaChallenge, create_iam_client,
};
use better_iam_types::api::{auth, operations, tenants};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use support::{Mock, body, data, header, run, text};

const ORIGIN: &str = "https://app.example.com";

fn client_error(error: Error) -> IamClientError {
    error.client().cloned().expect("an IamClientError")
}

#[test]
fn sends_the_server_json_contract_with_mandatory_csrf_headers_and_cookies() {
    run(|| async {
        let fetcher = Mock::new();
        fetcher.always(data(json!({ "token": "new-token" })));
        let client =
            create_iam_client(ClientOptions::new(ORIGIN).fetch(fetcher.fetch()).headers([
                ("x-trace-id", "trace-1"),
                ("x-better-iam", "wrong"),
                ("content-type", "text/plain"),
            ]))
            .unwrap();
        let input = json!({ "tenantId": "tenant-1", "email": "a@example.com", "password": "a-long-password" });
        let result: Value = client.request("auth/signIn", &input).await.unwrap();
        assert_eq!(result, json!({ "token": "new-token" }));
        let request = fetcher.call(0);
        assert_eq!(request.url, "https://app.example.com/api/iam/auth/signIn");
        assert_eq!(request.method, http::Method::POST);
        assert_eq!(request.credentials, "include");
        assert_eq!(request.redirect, "error");
        assert_eq!(request.cache, "no-store");
        assert_eq!(body(&request), input);
        assert_eq!(
            header(&request, "content-type").as_deref(),
            Some("application/json")
        );
        assert_eq!(header(&request, "x-better-iam").as_deref(), Some("1"));
        assert_eq!(header(&request, "x-trace-id").as_deref(), Some("trace-1"));
        assert!(header(&request, "authorization").is_none());

        // The generated method sends the typed input as the same JSON.
        let typed = auth::SignInInput {
            tenant_id: "tenant-1".into(),
            email: "a@example.com".into(),
            password: "a-long-password".into(),
            ..Default::default()
        };
        let _ = client.auth().sign_in(typed).await;
        assert_eq!(
            fetcher.last().url,
            "https://app.example.com/api/iam/auth/signIn"
        );
        assert_eq!(body(&fetcher.last()), input);
    });
}

#[test]
fn reads_the_current_bearer_token_at_each_request_and_supports_per_call_cancellation() {
    run(|| async {
        let token = Arc::new(Mutex::new("first-token-abcdefghijklmnop".to_owned()));
        let fetcher = Mock::new();
        fetcher.always(data(json!({ "identity": { "id": "user-1" } })));
        let current = token.clone();
        let client = create_iam_client(
            ClientOptions::new(ORIGIN)
                .base_path("/custom/iam")
                .fetch(fetcher.fetch())
                .token_fn(move || {
                    let token = current.lock().unwrap().clone();
                    async move { Ok(Some(token)) }
                }),
        )
        .unwrap();
        let controller = AbortController::new();
        let _ = client
            .auth()
            .get_session()
            .signal(controller.signal())
            .header("x-trace-id", "trace-2")
            .await;
        *token.lock().unwrap() = "second-token-abcdefghijklmnop".to_owned();
        let _ = client.auth().get_session().await;
        let first = fetcher.call(0);
        assert_eq!(
            first.url,
            "https://app.example.com/custom/iam/auth/getSession"
        );
        assert!(first.signal.as_ref().unwrap().same(&controller.signal()));
        assert_eq!(body(&first), json!({}));
        assert_eq!(header(&first, "x-trace-id").as_deref(), Some("trace-2"));
        assert!(
            header(&first, "authorization")
                .unwrap()
                .contains("first-token")
        );
        assert!(
            header(&fetcher.call(1), "authorization")
                .unwrap()
                .contains("second-token")
        );
    });
}

#[test]
fn sends_prefixed_tokens_and_session_jwts_as_bearers_and_refuses_other_shapes_before_any_fetch() {
    run(|| async {
        let token: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let fetcher = Mock::new();
        fetcher.always(data(json!({ "identity": { "id": "user-1" } })));
        let current = token.clone();
        let client = create_iam_client(ClientOptions::new(ORIGIN).fetch(fetcher.fetch()).token_fn(
            move || {
                let token = current.lock().unwrap().clone();
                async move { Ok(token) }
            },
        ))
        .unwrap();
        let segment = |length: usize| "aB3_-".repeat(length.div_ceil(5))[..length].to_owned();
        let prefixed = format!("biam_sts_{}AbC12_", segment(43));
        assert_eq!(prefixed.len(), 58);
        let jwt = format!("{}.{}.{}", segment(40), segment(300), segment(86));
        // The largest JWT the server issues (4096 characters) still passes.
        let largest = format!(
            "{}.{}.{}",
            segment(1024),
            segment(4096 - 2048 - 2),
            segment(1024)
        );
        assert_eq!(largest.len(), 4096);
        let mut sent = Vec::new();
        for value in [&prefixed, &jwt, &largest] {
            *token.lock().unwrap() = Some(value.clone());
            let _ = client.auth().get_session().await;
            sent.push(header(&fetcher.last(), "authorization").unwrap());
        }
        assert_eq!(
            sent,
            vec![
                format!("Bearer {prefixed}"),
                format!("Bearer {jwt}"),
                format!("Bearer {largest}")
            ]
        );
        *token.lock().unwrap() = Some(jwt.clone());
        let _ = client.sts().get_caller_identity().await;
        assert_eq!(
            fetcher.last().url,
            "https://app.example.com/api/iam/sts/getCallerIdentity"
        );
        assert_eq!(body(&fetcher.last()), json!({}));

        let calls = fetcher.count();
        for value in [
            "short".to_owned(),
            format!("{} ", segment(16)),
            "Bearer abcdefghijklmnopqrstuvwxyz".to_owned(),
            format!("{}.{}", segment(10), segment(10)),
            format!(
                "{}.{}.{}.{}",
                segment(10),
                segment(10),
                segment(10),
                segment(10)
            ),
            format!("{}..{}", segment(10), segment(10)),
            format!("{}.{}.", segment(10), segment(10)),
            format!("{}.{}.{}", segment(10), segment(1), segment(10)),
            format!("{}.{}.{}=", segment(10), segment(10), segment(10)),
            format!("{}.{}.{}", segment(1025), segment(10), segment(10)),
            format!("{}.{}.{}", segment(1024), segment(2049), segment(1024)),
            segment(513),
        ] {
            *token.lock().unwrap() = Some(value);
            let refused = client_error(client.auth().get_session().await.unwrap_err());
            assert_eq!(refused.name(), "IamClientError");
            assert_eq!(
                (refused.code.as_str(), refused.status),
                ("INVALID_TOKEN", 0)
            );
        }
        assert_eq!(fetcher.count(), calls);
    });
}

#[test]
fn reads_the_only_argument_of_credential_only_methods_outside_auth_as_call_options() {
    run(|| async {
        let fetcher = Mock::new();
        fetcher.always(data(json!([])));
        let client = create_iam_client(ClientOptions::new(ORIGIN).fetch(fetcher.fetch())).unwrap();
        let controller = AbortController::new();
        let options = |trace: &str| {
            CallOptions::default()
                .signal(controller.signal())
                .header("x-trace", trace)
        };
        let _ = client
            .sts()
            .get_caller_identity()
            .options(options("1"))
            .await;
        let _ = client.links().list().options(options("2")).await;
        let _ = client.clearances().templates().options(options("3")).await;
        for (index, path) in [
            "sts/getCallerIdentity",
            "links/list",
            "clearances/templates",
        ]
        .iter()
        .enumerate()
        {
            let request = fetcher.call(index);
            assert_eq!(
                request.url,
                format!("https://app.example.com/api/iam/{path}")
            );
            assert_eq!(body(&request), json!({}));
            assert!(request.signal.as_ref().unwrap().same(&controller.signal()));
            assert_eq!(header(&request, "x-trace"), Some((index + 1).to_string()));
        }
        // The generic form also sends `{}` for them, whatever the input holds.
        let mut ignored = serde_json::Map::new();
        ignored.insert("tenantId".into(), json!("org"));
        let _ = client
            .call(better_iam_types::api::links::List, ignored)
            .await;
        assert_eq!(body(&fetcher.last()), json!({}));
    });
}

#[test]
fn omits_authenticated_credentials_from_the_client_api_while_retaining_public_invitation_tokens() {
    run(|| async {
        let fetcher = Mock::new();
        fetcher.always(data(json!({})));
        let client = create_iam_client(ClientOptions::new(ORIGIN).fetch(fetcher.fetch())).unwrap();
        let _ = client
            .tenants()
            .create(tenants::CreateInput {
                parent_id: "root".into(),
                name: "Organization".into(),
                ..Default::default()
            })
            .await;
        let _ = client
            .tenants()
            .accept_invitation(tenants::AcceptInvitationInput {
                tenant_id: "org".into(),
                token: "invitation-token".into(),
                name: "Owner".into(),
                password: "long-password".into(),
                ..Default::default()
            })
            .await;
        let _ = client.auth().begin_mfa(None).await;
        let _ = client
            .auth()
            .begin_mfa(Some(MfaChallenge {
                tenant_id: "org".into(),
                challenge: "restricted-challenge".into(),
            }))
            .await;
        let _ = client
            .auth()
            .confirm_mfa(ConfirmMfaInput {
                code: "123456".into(),
                ..Default::default()
            })
            .await;
        let _ = client
            .auth()
            .confirm_mfa(ConfirmMfaInput {
                credential: Some(MfaChallenge {
                    tenant_id: "root".into(),
                    challenge: "restricted-challenge".into(),
                }),
                code: "123456".into(),
                remember_device: None,
            })
            .await;
        // The body is the input alone: no credential members travel in it.
        let created = body(&fetcher.call(0));
        assert_eq!(created["parentId"], json!("root"));
        assert_eq!(created["name"], json!("Organization"));
        assert!(created.get("token").is_none() && created.get("headers").is_none());
        assert_eq!(body(&fetcher.call(1))["token"], json!("invitation-token"));
        assert_eq!(body(&fetcher.call(2)), json!({}));
        assert_eq!(
            body(&fetcher.call(3))["challenge"],
            json!("restricted-challenge")
        );
        assert_eq!(body(&fetcher.call(4)), json!({ "code": "123456" }));
        assert_eq!(
            body(&fetcher.call(5)),
            json!({ "credential": { "tenantId": "root", "challenge": "restricted-challenge" }, "code": "123456" })
        );
    });
}

#[test]
fn retains_structured_api_errors_and_rejects_malformed_responses_without_echoing_their_content() {
    run(|| async {
        let fetcher = Mock::new();
        fetcher
            .once(support::failure(
                "MFA_REQUIRED",
                403,
                json!({ "message": "Use MFA" }),
                &[],
            ))
            .once(text(502, "<html>private upstream details</html>"))
            .once(better_iam_client::FetchResponse::json(
                200,
                &json!({ "wrong": "shape" }),
            ))
            .once(better_iam_client::FetchResponse::json(
                503,
                &json!({ "data": null }),
            ))
            .once(better_iam_client::FetchResponse::json(200, &json!([1, 2])))
            .once(better_iam_client::FetchResponse::json(
                400,
                &json!({ "error": { "code": 5 } }),
            ));
        let client = create_iam_client(ClientOptions::new(ORIGIN).fetch(fetcher.fetch())).unwrap();
        let error = client_error(client.auth().get_session().await.unwrap_err());
        assert_eq!(
            (error.code.as_str(), error.message.as_str(), error.status),
            ("MFA_REQUIRED", "Use MFA", 403)
        );
        let error = client_error(client.auth().get_session().await.unwrap_err());
        assert_eq!(
            (error.code.as_str(), error.status),
            ("INVALID_RESPONSE", 502)
        );
        assert!(!error.message.contains("private"));
        let error = client_error(client.auth().get_session().await.unwrap_err());
        assert_eq!(error.code, "INVALID_RESPONSE");
        let error = client_error(client.auth().get_session().await.unwrap_err());
        assert_eq!((error.code.as_str(), error.status), ("HTTP_ERROR", 503));
        let error = client_error(client.auth().get_session().await.unwrap_err());
        assert_eq!(error.message, "The IAM server returned an invalid response");
        let error = client_error(client.auth().get_session().await.unwrap_err());
        assert_eq!(
            (error.code.as_str(), error.message.as_str(), error.status),
            (
                "INVALID_RESPONSE",
                "The IAM server returned an invalid error response",
                400
            )
        );
    });
}

#[test]
fn provides_authorize_and_plugin_transports_while_rejecting_url_traversal() {
    run(|| async {
        let fetcher = Mock::new();
        fetcher.always(data(json!({ "allowed": true, "reason": "allowed" })));
        let client = create_iam_client(ClientOptions::new(ORIGIN).fetch(fetcher.fetch())).unwrap();
        let result = client
            .authorize(operations::AuthorizeInput {
                tenant_id: "org".into(),
                action: "documents:read".into(),
                resource: operations::AuthorizeInputResource {
                    r#type: "document".into(),
                    id: "one".into(),
                },
            })
            .await;
        assert!(fetcher.call(0).url.ends_with("/authorize"));
        assert_eq!(
            body(&fetcher.call(0)),
            json!({ "tenantId": "org", "action": "documents:read", "resource": { "type": "document", "id": "one" } })
        );
        if let Ok(decision) = result {
            assert!(decision.allowed);
        }
        let _: Value = client
            .request("plugins/reporting/summary", &json!({ "tenantId": "org" }))
            .await
            .unwrap();
        assert!(fetcher.call(1).url.ends_with("/plugins/reporting/summary"));
        for path in [
            "../secrets",
            "https://attacker.example",
            "",
            "plugins//x",
            "then",
            "a/__proto__",
        ] {
            let error = client_error(client.request::<Value>(path, &json!({})).await.unwrap_err());
            assert_eq!(error.code, "INVALID_PATH");
        }
        assert_eq!(fetcher.count(), 2);
        assert_eq!(format!("{client:?}"), "BetterIamClient");
    });
}

#[test]
fn validates_the_configuration_before_any_request() {
    let code = |options: ClientOptions| match create_iam_client(options) {
        Ok(_) => "ok".to_owned(),
        Err(error) => {
            let error = error.client().cloned().unwrap();
            assert_eq!(error.status, 0);
            format!("{} {}", error.code, error.message)
        }
    };
    let fetch = || Mock::new().fetch();
    assert_eq!(
        code(ClientOptions::default().fetch(fetch())),
        "INVALID_CONFIG baseURL is required outside a browser"
    );
    assert_eq!(
        code(ClientOptions::new("app.example.com").fetch(fetch())),
        "INVALID_CONFIG baseURL must be an absolute HTTP(S) URL"
    );
    for bad in [
        "ftp://app.example.com",
        "https://user:pass@app.example.com",
        "https://app.example.com/?q=1",
        "https://app.example.com/#top",
    ] {
        assert_eq!(
            code(ClientOptions::new(bad).fetch(fetch())),
            "INVALID_CONFIG baseURL must be an HTTP(S) URL without credentials, query, or fragment"
        );
    }
    for bad in ["api/iam", "/api/iam/", "/api.iam", "/"] {
        assert_eq!(
            code(ClientOptions::new(ORIGIN).base_path(bad).fetch(fetch())),
            "INVALID_CONFIG basePath must be an absolute path without a trailing slash"
        );
    }
    assert_eq!(
        code(ClientOptions::new("https://app.example.com/ignored/path?").fetch(fetch())),
        "ok"
    );
}

#[test]
fn resolves_requests_against_the_origin_alone() {
    run(|| async {
        let fetcher = Mock::new();
        fetcher.always(data(json!({})));
        let client = create_iam_client(
            ClientOptions::new("https://APP.example.com:443/some/page").fetch(fetcher.fetch()),
        )
        .unwrap();
        let _: Value = client
            .request("roles/list", &json!({ "tenantId": "t" }))
            .await
            .unwrap();
        assert_eq!(
            fetcher.last().url,
            "https://app.example.com/api/iam/roles/list"
        );
        // A null input is sent as an empty object.
        let _: Value = client.request("roles/list", &Value::Null).await.unwrap();
        assert_eq!(fetcher.last().body, "{}");
    });
}

#[test]
fn reports_wrong_region_refusals_with_their_region_and_address() {
    run(|| async {
        let fetcher = Mock::new();
        fetcher
            .once(support::failure(
                "WRONG_REGION",
                421,
                json!({ "region": "eu-west-1", "location": "http://globex.signin.eu-west-1.localhost:3000/login" }),
                &[],
            ))
            .once(support::failure(
                "WRONG_REGION",
                421,
                json!({ "region": "eu-west-1", "location": "javascript:alert(1)" }),
                &[],
            ));
        let client =
            create_iam_client(ClientOptions::new("http://localhost:3000").fetch(fetcher.fetch()))
                .unwrap();
        let lookup = || {
            client.tenants().lookup(tenants::LookupInput {
                slug: Some("globex".into()),
                ..Default::default()
            })
        };
        let refused = client_error(lookup().await.unwrap_err());
        assert_eq!(refused.code, "WRONG_REGION");
        assert_eq!(refused.region.as_deref(), Some("eu-west-1"));
        assert_eq!(
            refused.location.as_deref(),
            Some("http://globex.signin.eu-west-1.localhost:3000/login")
        );
        // Only HTTP(S) addresses are kept.
        let refused = client_error(lookup().await.unwrap_err());
        assert_eq!(refused.region.as_deref(), Some("eu-west-1"));
        assert_eq!(refused.location, None);
    });
}
