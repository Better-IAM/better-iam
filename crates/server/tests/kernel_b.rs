//! Kernel B: the composed server (`better_iam`), the decision engine, the operation envelope, credential resolution
//! and the HTTP layer. Ported from the TypeScript suites that do not need the unported API groups
//! (tests/cookie-options.test.ts, tests/http-hardening.test.ts, tests/node-transport.test.ts,
//! tests/credential-resolution.test.ts, tests/access.test.ts): grants are written to the store directly where the
//! TypeScript tests create them through `roles.create` and `bindings.create`.

use std::future::Future;
use std::sync::Arc;

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::service::base::CreateIdentityInput;
use better_iam_core::{
    CredentialInput, IamStore, IamStoreExt, PermissionsConfig, ResourceTypeDefinition,
};
use better_iam_server::options::{
    AccessibleResourcesRequest, AuthorizationRequest, BatchAuthorizationRequest, BetterIamOptions,
    HttpOptions, ResolvedResource, ResourceTarget,
};
use better_iam_server::{BetterIam, better_iam};
use bytes::Bytes;
use http::{HeaderMap, Method};
use serde_json::{Value, json};

const ORIGIN: &str = "https://iam.example.com";
const SECRET: &str = "kernel-b-test-secret-with-32-characters!!";
const OWNER_PASSWORD: &str = "a strong tenant owner password";

/// Runs a test body on a runtime with large worker stacks (debug-build futures are big).
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

struct Fixture {
    iam: BetterIam,
    tenant_id: String,
    owner_id: String,
    root_authority: String,
}

fn options(configure: impl FnOnce(&mut BetterIamOptions)) -> BetterIamOptions {
    let store: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    let mut options = BetterIamOptions::new(store, SECRET, ORIGIN);
    let mut resource_types = indexmap::IndexMap::new();
    resource_types.insert(
        "document".to_owned(),
        ResourceTypeDefinition {
            managed: Some(true),
            actions: Some(vec!["documents:read".into(), "documents:write".into()]),
            ..ResourceTypeDefinition::default()
        },
    );
    options.permissions = Some(PermissionsConfig {
        actions: Some(vec!["files:read".into(), "files:write".into()]),
        resource_types: Some(resource_types),
        ..PermissionsConfig::default()
    });
    options.resolve_resource = Some(Arc::new(|reference| {
        Box::pin(async move { Ok(ResolvedResource::of(&reference)) })
    }));
    configure(&mut options);
    options
}

async fn fixture(configure: impl FnOnce(&mut BetterIamOptions)) -> Fixture {
    let iam = better_iam(options(configure)).expect("valid options");
    iam.initialize().await.expect("initialize");
    let root = iam
        .bootstrap(&json!({ "email": "root@example.test", "name": "Root", "password": "a strong root test password" }))
        .await
        .expect("bootstrap");
    let tenant_id = root["tenant"]["id"].as_str().unwrap().to_owned();
    let owner = iam
        .store
        .transaction(|tx| {
            let auth = iam.auth.clone();
            let tenant_id = tenant_id.clone();
            async move {
                auth.create_identity(
                    &tx,
                    CreateIdentityInput {
                        tenant_id,
                        email: "owner@example.test".into(),
                        name: "Owner".into(),
                        password: Some(OWNER_PASSWORD.into()),
                        owner: None,
                        root_admin: None,
                        email_verified: Some(true),
                    },
                )
                .await
            }
        })
        .await
        .expect("identity");
    let root_id = root["identity"]["id"].as_str().unwrap().to_owned();
    let authority = iam
        .store
        .find(
            "grantAuthorities",
            &better_iam_core::Filter::new().eq("identityId", root_id),
            &better_iam_core::FindOptions::default(),
        )
        .await
        .unwrap()
        .into_iter()
        .next()
        .expect("root authority");
    Fixture {
        iam,
        tenant_id,
        owner_id: owner.id,
        root_authority: authority["id"].as_str().unwrap().to_owned(),
    }
}

fn request(
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> http::Request<Bytes> {
    let mut builder = http::Request::builder()
        .method(method)
        .uri(format!("{ORIGIN}{path}"));
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder
        .body(
            body.map(|body| Bytes::from(body.to_string()))
                .unwrap_or_default(),
        )
        .unwrap()
}

async fn post(
    iam: &BetterIam,
    path: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> http::Response<Bytes> {
    let mut all = vec![("content-type", "application/json"), ("x-better-iam", "1")];
    all.extend_from_slice(headers);
    iam.handler(request(
        Method::POST,
        &format!("/api/iam/{path}"),
        &all,
        Some(body),
    ))
    .await
}

fn json_of(response: &http::Response<Bytes>) -> Value {
    serde_json::from_slice(response.body()).unwrap_or(Value::Null)
}

fn header<'a>(response: &'a http::Response<Bytes>, name: &str) -> Option<&'a str> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
}

fn cookies(response: &http::Response<Bytes>) -> Vec<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect()
}

async fn sign_in(f: &Fixture, headers: &[(&str, &str)]) -> http::Response<Bytes> {
    post(
        &f.iam,
        "auth/signIn",
        json!({ "tenantId": f.tenant_id, "email": "owner@example.test", "password": OWNER_PASSWORD }),
        headers,
    )
    .await
}

async fn owner_token(f: &Fixture) -> String {
    let response = sign_in(f, &[]).await;
    assert_eq!(
        response.status(),
        200,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    json_of(&response)["data"]["token"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// `store.transaction(tx => tx.insert(collection, record))`.
async fn insert(iam: &BetterIam, collection: &str, record: &Value) {
    let collection = collection.to_owned();
    let record = record.as_object().unwrap().clone();
    iam.store
        .transaction(|tx| async move { tx.insert(&collection, &record).await })
        .await
        .unwrap();
}

/// `store.transaction(tx => tx.put(collection, record))`.
async fn put(iam: &BetterIam, collection: &str, record: &serde_json::Map<String, Value>) {
    let collection = collection.to_owned();
    let record = record.clone();
    iam.store
        .transaction(|tx| async move { tx.put(&collection, &record).await })
        .await
        .unwrap();
}

fn bearer(token: &str) -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some(token.to_owned()),
    }
}

/// A role with an inline document, bound to the owner under the root authority.
async fn grant(f: &Fixture, statements: Value, binding_extra: Value) -> String {
    let role_id = better_iam_server::utils::id();
    let mut role = json!({
        "id": role_id,
        "tenantId": f.tenant_id,
        "name": format!("Role {role_id}"),
        "policyIds": [],
        "document": { "version": 1, "statements": statements },
        "protected": false,
        "authorityId": f.root_authority,
    });
    let _ = &mut role;
    insert(&f.iam, "roles", &role).await;
    let mut binding = json!({
        "id": better_iam_server::utils::id(),
        "tenantId": f.tenant_id,
        "subjectType": "identity",
        "subjectId": f.owner_id,
        "roleId": role_id,
        "authorityId": f.root_authority,
    });
    for (key, value) in binding_extra.as_object().unwrap() {
        binding[key] = value.clone();
    }
    insert(&f.iam, "bindings", &binding).await;
    role_id
}

fn check(f: &Fixture, token: &str, action: &str, kind: &str, id: &str) -> AuthorizationRequest {
    AuthorizationRequest {
        credential: bearer(token),
        tenant_id: f.tenant_id.clone(),
        action: action.into(),
        resource: ResourceTarget {
            kind: kind.into(),
            id: id.into(),
        },
    }
}

#[test]
fn composes_and_bootstraps_once() {
    run(|| async {
        let f = fixture(|_| {}).await;
        let again = f
            .iam
            .bootstrap(&json!({ "email": "x@example.test", "name": "X", "password": "a strong root test password" }))
            .await
            .unwrap_err();
        assert_eq!(
            (again.code.as_str(), again.status),
            ("ALREADY_INITIALIZED", 409)
        );
        let audit = f
            .iam
            .store
            .find(
                "audit",
                &better_iam_core::Filter::new().eq("action", "root:bootstrap"),
                &better_iam_core::FindOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0]["actorId"], json!("deployment-operator"));
        // Bad options fail construction with the validator's code.
        let error = better_iam(options(|options| options.base_url = "not a url".into()))
            .err()
            .expect("refused");
        // TypeScript throws a TypeError for an invalid baseURL, which the server reports as INTERNAL_ERROR.
        assert_eq!(error.code, "INTERNAL_ERROR");
        let error = better_iam(options(|options| {
            options.http = Some(HttpOptions {
                cookie_same_site: Some("none".into()),
                ..HttpOptions::default()
            })
        }))
        .err()
        .expect("refused");
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "INVALID_CONFIG",
                "http.cookieSameSite must be lax or strict"
            )
        );
    });
}

#[test]
fn decisions_follow_bindings_denies_boundaries_and_authorities() {
    run(|| async {
        let f = fixture(|_| {}).await;
        let token = owner_token(&f).await;
        // No grant yet: refused (and recorded as a deny).
        let refused = f
            .iam
            .authorize(&check(&f, &token, "files:read", "file", "a"))
            .await
            .unwrap();
        assert!(!refused.allowed);
        assert_eq!(refused.reason, "ACCESS_DENIED");
        assert!(refused.matched.is_empty());
        grant(
            &f,
            json!([
                { "effect": "allow", "actions": ["files:read"], "resources": ["file/*"] },
                { "effect": "deny", "actions": ["files:read"], "resources": ["file/secret"] }
            ]),
            json!({}),
        )
        .await;
        let allowed = f
            .iam
            .authorize(&check(&f, &token, "files:read", "file", "a"))
            .await
            .unwrap();
        assert!(allowed.allowed, "{allowed:?}");
        let secret = f
            .iam
            .authorize(&check(&f, &token, "files:read", "file", "secret"))
            .await
            .unwrap();
        assert!(!secret.allowed);
        let other = f
            .iam
            .authorize(&check(&f, &token, "files:write", "file", "a"))
            .await
            .unwrap();
        assert!(!other.allowed);
        // An action the catalog does not know is refused before the resource is resolved.
        let unknown = f
            .iam
            .authorize(&check(&f, &token, "files:delete", "file", "a"))
            .await
            .unwrap();
        assert!(!unknown.allowed);
        // A batch answers each check.
        let batch = f
            .iam
            .authorize_many(&BatchAuthorizationRequest {
                credential: bearer(&token),
                tenant_id: f.tenant_id.clone(),
                checks: vec![
                    better_iam_server::options::AuthorizationCheck {
                        action: "files:read".into(),
                        resource: ResourceTarget {
                            kind: "file".into(),
                            id: "a".into(),
                        },
                    },
                    better_iam_server::options::AuthorizationCheck {
                        action: "files:read".into(),
                        resource: ResourceTarget {
                            kind: "file".into(),
                            id: "secret".into(),
                        },
                    },
                ],
            })
            .await
            .unwrap();
        assert_eq!(
            batch
                .iter()
                .map(|result| result.allowed)
                .collect::<Vec<_>>(),
            vec![true, false]
        );
        // Denials are audited in the tenant with the denied resource.
        let denies = f
            .iam
            .store
            .find(
                "audit",
                &better_iam_core::Filter::new()
                    .eq("outcome", "deny")
                    .eq("action", "files:read"),
                &better_iam_core::FindOptions::default(),
            )
            .await
            .unwrap();
        assert!(
            denies
                .iter()
                .any(|event| event["resourceId"] == json!("secret"))
        );
        // A tenant boundary bounds every grant.
        let mut tenant = f
            .iam
            .store
            .get("tenants", &f.tenant_id)
            .await
            .unwrap()
            .unwrap();
        tenant.insert(
            "boundary".into(),
            json!({ "version": 1, "statements": [{ "effect": "allow", "actions": ["files:write"], "resources": ["*"] }] }),
        );
        put(&f.iam, "tenants", &tenant).await;
        assert!(
            !f.iam
                .authorize(&check(&f, &token, "files:read", "file", "a"))
                .await
                .unwrap()
                .allowed
        );
        tenant.shift_remove("boundary");
        put(&f.iam, "tenants", &tenant).await;
        assert!(
            f.iam
                .authorize(&check(&f, &token, "files:read", "file", "a"))
                .await
                .unwrap()
                .allowed
        );
        // A revoked authority takes away what it granted.
        let mut authority = f
            .iam
            .store
            .get("grantAuthorities", &f.root_authority)
            .await
            .unwrap()
            .unwrap();
        authority.insert("revoked".into(), json!(true));
        put(&f.iam, "grantAuthorities", &authority).await;
        assert!(
            !f.iam
                .authorize(&check(&f, &token, "files:read", "file", "a"))
                .await
                .unwrap()
                .allowed
        );
    });
}

#[test]
fn bindings_that_ended_or_have_not_started_grant_nothing() {
    run(|| async {
        let f = fixture(|_| {}).await;
        let token = owner_token(&f).await;
        let now = better_iam_server::utils::date_now();
        grant(
            &f,
            json!([{ "effect": "allow", "actions": ["files:read"], "resources": ["file/*"] }]),
            json!({ "expiresAt": now - 1000.0 }),
        )
        .await;
        grant(
            &f,
            json!([{ "effect": "allow", "actions": ["files:write"], "resources": ["file/*"] }]),
            json!({ "startsAt": now + 3_600_000.0 }),
        )
        .await;
        assert!(
            !f.iam
                .authorize(&check(&f, &token, "files:read", "file", "a"))
                .await
                .unwrap()
                .allowed
        );
        assert!(
            !f.iam
                .authorize(&check(&f, &token, "files:write", "file", "a"))
                .await
                .unwrap()
                .allowed
        );
        // A group binding grants to its live members.
        let group_id = better_iam_server::utils::id();
        insert(&f.iam, "groupMembers", &json!({ "id": better_iam_server::utils::id(), "tenantId": f.tenant_id, "groupId": group_id, "identityId": f.owner_id })).await;
        grant(
            &f,
            json!([{ "effect": "allow", "actions": ["files:read"], "resources": ["file/*"] }]),
            json!({ "subjectType": "group", "subjectId": group_id }),
        )
        .await;
        assert!(
            f.iam
                .authorize(&check(&f, &token, "files:read", "file", "a"))
                .await
                .unwrap()
                .allowed
        );
    });
}

#[test]
fn list_accessible_filters_registered_resources() {
    run(|| async {
        let f = fixture(|_| {}).await;
        let token = owner_token(&f).await;
        for (resource_id, level) in [("a", "public"), ("b", "secret"), ("c", "public")] {
            insert(
                &f.iam,
                "resources",
                &json!({
                    "id": better_iam_server::utils::id(),
                    "tenantId": f.tenant_id,
                    "uniqueKey": format!("document/{resource_id}"),
                    "type": "document",
                    "resourceId": resource_id,
                    "attributes": { "level": level },
                    "createdAt": 1, "updatedAt": 1,
                }),
            )
            .await;
        }
        grant(
            &f,
            json!([{
                "effect": "allow", "actions": ["documents:read"], "resources": ["document/*"],
                "conditions": { "StringEquals": { "resource.level": "public" } }
            }]),
            json!({}),
        )
        .await;
        let listed = f
            .iam
            .list_accessible(&AccessibleResourcesRequest {
                credential: bearer(&token),
                tenant_id: f.tenant_id.clone(),
                action: "documents:read".into(),
                kind: "document".into(),
                limit: Some(1.0),
                offset: None,
            })
            .await
            .unwrap();
        assert_eq!(listed.total, 2.0);
        assert_eq!(listed.resources.len(), 1);
        assert_eq!(listed.resources[0]["resourceId"], json!("a"));
        let error = f
            .iam
            .list_accessible(&AccessibleResourcesRequest {
                credential: bearer(&token),
                tenant_id: f.tenant_id.clone(),
                action: "documents:read".into(),
                kind: "document".into(),
                limit: Some(0.0),
                offset: None,
            })
            .await
            .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            ("INVALID_INPUT", "Invalid limit")
        );
        // Over HTTP, the plan of the same grant is conditional on the level.
        let plan = post(
            &f.iam,
            "filters/plan",
            json!({ "tenantId": f.tenant_id, "action": "documents:read", "type": "document" }),
            &[("authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(
            plan.status(),
            200,
            "{}",
            String::from_utf8_lossy(plan.body())
        );
        assert_eq!(json_of(&plan)["data"]["kind"], json!("conditional"));
    });
}

#[test]
fn credentials_resolve_and_revocations_apply_at_once() {
    run(|| async {
        let f = fixture(|_| {}).await;
        let token = owner_token(&f).await;
        let principal = f.iam.authenticate(&bearer(&token)).await.unwrap();
        assert_eq!(principal.identity.id, f.owner_id);
        let header = CredentialInput {
            headers: Some(vec![("authorization".into(), format!("Bearer {token}"))]),
            token: None,
        };
        assert_eq!(
            f.iam.authenticate(&header).await.unwrap().session.id,
            principal.session.id
        );
        let unknown = f
            .iam
            .authenticate(&bearer(&"x".repeat(43)))
            .await
            .unwrap_err();
        assert_eq!(unknown.status, 401);
        let garbage = f
            .iam
            .authenticate(&bearer("biam_key_garbage"))
            .await
            .unwrap_err();
        assert_eq!(
            (garbage.code.as_str(), garbage.message.as_str()),
            ("UNAUTHENTICATED", "Invalid credentials")
        );
        // A disabled identity's session stops working at once.
        let mut identity = f
            .iam
            .store
            .get("identities", &f.owner_id)
            .await
            .unwrap()
            .unwrap();
        identity.insert("status".into(), json!("disabled"));
        put(&f.iam, "identities", &identity).await;
        assert_eq!(
            f.iam
                .authenticate(&bearer(&token))
                .await
                .unwrap_err()
                .status,
            401
        );
    });
}

#[test]
fn operations_authorize_record_and_audit() {
    run(|| async {
        let f = fixture(|_| {}).await;
        let token = owner_token(&f).await;
        let auth = format!("Bearer {token}");
        let listed = post(
            &f.iam,
            "actions/list",
            json!({ "tenantId": f.tenant_id }),
            &[("authorization", &auth)],
        )
        .await;
        assert_eq!(listed.status(), 403);
        assert_eq!(json_of(&listed)["error"]["code"], json!("ACCESS_DENIED"));
        grant(
            &f,
            json!([{ "effect": "allow", "actions": ["iam:actions:read", "iam:resource-types:read", "iam:audit:read"], "resources": ["iam/*"] }]),
            json!({}),
        )
        .await;
        let listed = post(
            &f.iam,
            "actions/list",
            json!({ "tenantId": f.tenant_id }),
            &[("authorization", &auth)],
        )
        .await;
        assert_eq!(
            listed.status(),
            200,
            "{}",
            String::from_utf8_lossy(listed.body())
        );
        let names: Vec<String> = json_of(&listed)["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|action| action["name"].as_str().unwrap().to_owned())
            .collect();
        assert!(names.contains(&"files:read".to_owned()));
        let types = post(
            &f.iam,
            "resourceTypes/get",
            json!({ "tenantId": f.tenant_id, "name": "document" }),
            &[("authorization", &auth)],
        )
        .await;
        assert_eq!(json_of(&types)["data"]["managed"], json!(true));
        let verified = post(
            &f.iam,
            "audit/verify",
            json!({ "tenantId": f.tenant_id }),
            &[("authorization", &auth)],
        )
        .await;
        assert_eq!(
            json_of(&verified)["data"]["valid"],
            json!(true),
            "{}",
            String::from_utf8_lossy(verified.body())
        );
        let events = post(
            &f.iam,
            "audit/list",
            json!({ "tenantId": f.tenant_id, "action": "iam:actions:*" }),
            &[("authorization", &auth)],
        )
        .await;
        let outcomes: Vec<Value> = json_of(&events)["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["outcome"].clone())
            .collect();
        // Newest first: the allowed listing, then the refusal.
        assert_eq!(outcomes, vec![json!("allow"), json!("deny")]);
        // Validation runs inside the envelope, after authorization, as in TypeScript.
        let invalid = post(
            &f.iam,
            "audit/list",
            json!({ "tenantId": f.tenant_id, "limit": 0 }),
            &[("authorization", &auth)],
        )
        .await;
        assert_eq!(
            json_of(&invalid)["error"]["message"],
            json!("Invalid limit")
        );
    });
}

#[test]
fn cookie_options() {
    run(|| async {
        let f = fixture(|_| {}).await;
        let session_cookie = |response: &http::Response<Bytes>| {
            cookies(response)
                .into_iter()
                .find(|line| line.starts_with("__Host-better-iam.session="))
                .expect("session cookie")
        };
        let persistent = session_cookie(&sign_in(&f, &[]).await);
        assert!(persistent.contains("; Max-Age="), "{persistent}");
        assert!(persistent.contains("HttpOnly; Secure; SameSite=Lax; Path=/"));
        let transient = session_cookie(&sign_in(&f, &[("x-better-iam-persistent", "0")]).await);
        assert!(!transient.contains("Max-Age"));
        assert!(
            session_cookie(&sign_in(&f, &[("x-better-iam-persistent", "maybe")]).await)
                .contains("Max-Age=")
        );
        let preflight = f
            .iam
            .handler(request(
                Method::OPTIONS,
                "/api/iam/auth/signIn",
                &[("origin", ORIGIN)],
                None,
            ))
            .await;
        assert_eq!(preflight.status(), 204);
        let allowed = header(&preflight, "access-control-allow-headers").unwrap();
        assert!(allowed.contains("x-better-iam-persistent") && allowed.contains("x-request-id"));

        let strict = fixture(|options| {
            options.http = Some(HttpOptions {
                cookie_same_site: Some("strict".into()),
                persistent_cookies: Some(false),
                ..HttpOptions::default()
            })
        })
        .await;
        let cookie = session_cookie(&sign_in(&strict, &[]).await);
        assert!(
            cookie.contains("SameSite=Strict") && !cookie.contains("Max-Age"),
            "{cookie}"
        );
        assert!(
            session_cookie(&sign_in(&strict, &[("x-better-iam-persistent", "1")]).await)
                .contains("Max-Age=")
        );
    });
}

#[test]
fn cors_request_ids_csrf_and_errors() {
    run(|| async {
        let f = fixture(|options| {
            options.trusted_origins = Some(vec!["https://app.example.com".into()])
        })
        .await;
        let app = [
            ("origin", "https://app.example.com"),
            ("x-request-id", "req-1"),
        ];
        let expect_cors = |response: &http::Response<Bytes>| {
            assert_eq!(
                header(response, "access-control-allow-origin"),
                Some("https://app.example.com")
            );
            assert_eq!(
                header(response, "access-control-allow-credentials"),
                Some("true")
            );
            assert_eq!(header(response, "vary"), Some("Origin"));
            assert_eq!(
                header(response, "access-control-expose-headers"),
                Some("retry-after, x-request-id")
            );
            assert_eq!(header(response, "x-request-id"), Some("req-1"));
        };
        let wrong = post(
            &f.iam,
            "auth/signIn",
            json!({ "tenantId": f.tenant_id, "email": "owner@example.test", "password": "not the password" }),
            &app,
        )
        .await;
        assert_eq!(wrong.status(), 401);
        expect_cors(&wrong);
        assert_eq!(header(&wrong, "cache-control"), Some("no-store"));
        assert_eq!(header(&wrong, "x-content-type-options"), Some("nosniff"));
        assert_eq!(header(&wrong, "referrer-policy"), Some("no-referrer"));
        let anonymous = post(&f.iam, "auth/getSession", json!({}), &app).await;
        assert_eq!(anonymous.status(), 401);
        expect_cors(&anonymous);
        // Refused before dispatch: no JSON content type and no X-Better-IAM header.
        let csrf = f
            .iam
            .handler(request(
                Method::POST,
                "/api/iam/auth/getSession",
                &app,
                Some(json!({})),
            ))
            .await;
        assert_eq!(csrf.status(), 403);
        assert_eq!(
            json_of(&csrf)["error"]["message"],
            json!("JSON and X-Better-IAM header required")
        );
        expect_cors(&csrf);
        let cookie_without_origin =
            post(&f.iam, "auth/getSession", json!({}), &[("cookie", "a=b")]).await;
        assert_eq!(
            json_of(&cookie_without_origin)["error"]["message"],
            json!("Cookie requests require Origin")
        );
        let health = f
            .iam
            .handler(request(Method::GET, "/api/iam/health", &app, None))
            .await;
        assert_eq!(health.status(), 200);
        assert_eq!(json_of(&health)["status"], json!("ok"));
        expect_cors(&health);
        let preflight = f
            .iam
            .handler(request(Method::OPTIONS, "/api/iam/auth/signIn", &app, None))
            .await;
        assert_eq!(preflight.status(), 204);
        expect_cors(&preflight);
        let outside = f
            .iam
            .handler(request(
                Method::GET,
                "/elsewhere",
                &[("x-request-id", "req-3")],
                None,
            ))
            .await;
        assert_eq!(outside.status(), 404);
        assert_eq!(
            json_of(&outside),
            json!({ "error": { "code": "NOT_FOUND", "message": "Not found" } })
        );
        assert_eq!(header(&outside, "x-request-id"), Some("req-3"));
        let untrusted = post(
            &f.iam,
            "auth/getSession",
            json!({}),
            &[
                ("origin", "https://evil.example.com"),
                ("x-request-id", "req-2"),
            ],
        )
        .await;
        assert_eq!(untrusted.status(), 403);
        assert_eq!(
            json_of(&untrusted)["error"]["code"],
            json!("UNTRUSTED_ORIGIN")
        );
        assert!(header(&untrusted, "access-control-allow-origin").is_none());
        assert_eq!(header(&untrusted, "x-request-id"), Some("req-2"));
        // Methods, unknown routes, bodies.
        let put = f
            .iam
            .handler(request(Method::PUT, "/api/iam/auth/signIn", &[], None))
            .await;
        assert_eq!(
            (
                put.status().as_u16(),
                json_of(&put)["error"]["message"].clone()
            ),
            (405, json!("Use POST"))
        );
        let missing = post(&f.iam, "tenants/nope", json!({}), &[]).await;
        assert_eq!(
            (
                missing.status().as_u16(),
                json_of(&missing)["error"]["message"].clone()
            ),
            (404, json!("Endpoint not found"))
        );
        let deep = post(&f.iam, "tenants/create/extra", json!({}), &[]).await;
        assert_eq!(deep.status(), 404);
        let not_json = f
            .iam
            .handler(request(
                Method::POST,
                "/api/iam/auth/getSession",
                &[("content-type", "application/json"), ("x-better-iam", "1")],
                None,
            ))
            .await;
        assert_eq!(
            json_of(&not_json)["error"]["message"],
            json!("Invalid JSON")
        );
        let array = post(&f.iam, "auth/getSession", json!([1]), &[]).await;
        assert_eq!(json_of(&array)["error"]["message"], json!("Invalid JSON"));
        let large = post(
            &f.iam,
            "auth/getSession",
            json!({ "padding": "x".repeat(70_000) }),
            &[],
        )
        .await;
        assert_eq!(
            (
                large.status().as_u16(),
                json_of(&large)["error"]["code"].clone()
            ),
            (413, json!("PAYLOAD_TOO_LARGE"))
        );
    });
}

#[test]
fn sign_out_clears_the_cookie_and_bearer_requests_never_touch_it() {
    run(|| async {
        let f = fixture(|_| {}).await;
        let browser = [("origin", ORIGIN)];
        let signed_in = sign_in(&f, &browser).await;
        let cookie_line = cookies(&signed_in).into_iter().next().unwrap();
        let cookie = cookie_line.split(';').next().unwrap().to_owned();
        let with_cookie = [("origin", ORIGIN), ("cookie", cookie.as_str())];
        assert_eq!(
            post(&f.iam, "auth/getSession", json!({}), &with_cookie)
                .await
                .status(),
            200
        );
        let other = owner_token(&f).await;
        let bearer_out = post(
            &f.iam,
            "auth/signOut",
            json!({}),
            &[("authorization", &format!("Bearer {other}"))],
        )
        .await;
        assert_eq!(bearer_out.status(), 200);
        assert!(cookies(&bearer_out).is_empty());
        let signed_out = post(&f.iam, "auth/signOut", json!({}), &with_cookie).await;
        assert_eq!(signed_out.status(), 200);
        assert!(cookies(&signed_out)[0].contains("Max-Age=0"));
        let again = post(&f.iam, "auth/signOut", json!({}), &with_cookie).await;
        assert_eq!(again.status(), 401);
        assert!(cookies(&again)[0].contains("Max-Age=0"));
        // Session projections never carry the token hash.
        let session = json_of(&sign_in(&f, &[]).await);
        assert!(session["data"]["session"].get("tokenHash").is_none());
    });
}

#[test]
fn node_transport_refuses_trace_and_bad_targets() {
    run(|| async {
        let f = fixture(|_| {}).await;
        let trace = f
            .iam
            .http
            .node_handler(Method::TRACE, "/", HeaderMap::new(), Bytes::new())
            .await;
        assert_eq!(trace.status(), 405);
        assert_eq!(
            serde_json::from_slice::<Value>(trace.body()).unwrap(),
            json!({ "error": { "code": "METHOD_NOT_ALLOWED", "message": "Method is not supported" } })
        );
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("x-better-iam", "1".parse().unwrap());
        let ok = f
            .iam
            .http
            .node_handler(
                Method::POST,
                "/api/iam/auth/getSession",
                headers,
                Bytes::from_static(b"{}"),
            )
            .await;
        assert_eq!(ok.status(), 401);
        let url = f
            .iam
            .http
            .node_url("/api/iam/x", &HeaderMap::new())
            .unwrap();
        assert_eq!(f.iam.http.body_limit(&url), 65536);
        let elsewhere = f.iam.http.node_url("/saml/acs", &HeaderMap::new()).unwrap();
        assert_eq!(f.iam.http.body_limit(&elsewhere), 2_097_152);
    });
}

#[test]
fn inherited_roles_attached_policies_and_context_conditions() {
    run(|| async {
        let f = fixture(|_| {}).await;
        let token = owner_token(&f).await;
        let policy_id = better_iam_server::utils::id();
        insert(
            &f.iam,
            "policies",
            &json!({
                "id": policy_id, "tenantId": f.tenant_id, "name": "Writers", "version": 1,
                "document": { "version": 1, "statements": [{ "effect": "allow", "actions": ["files:write"], "resources": ["file/plain*"] }] },
                "authorityId": f.root_authority,
            }),
        )
        .await;
        let base_id = better_iam_server::utils::id();
        insert(
            &f.iam,
            "roles",
            &json!({
                "id": base_id, "tenantId": f.tenant_id, "name": "Base", "policyIds": [], "protected": false,
                "document": { "version": 1, "statements": [
                    { "effect": "allow", "actions": ["files:read"], "resources": ["file/*"],
                      "conditions": { "StringEquals": { "principal.kind": "user" } } },
                    { "effect": "allow", "actions": ["files:write"], "resources": ["file/mfa*"],
                      "conditions": { "Bool": { "principal.mfa": true } } }
                ] },
                "authorityId": f.root_authority,
            }),
        )
        .await;
        let role_id = better_iam_server::utils::id();
        insert(
            &f.iam,
            "roles",
            &json!({
                "id": role_id, "tenantId": f.tenant_id, "name": "Editor", "policyIds": [policy_id],
                "inherits": [base_id], "protected": false, "authorityId": f.root_authority,
            }),
        )
        .await;
        insert(
            &f.iam,
            "bindings",
            &json!({
                "id": better_iam_server::utils::id(), "tenantId": f.tenant_id, "subjectType": "identity",
                "subjectId": f.owner_id, "roleId": role_id, "authorityId": f.root_authority,
            }),
        )
        .await;
        // Inherited from Base, with a condition on the principal's kind.
        assert!(
            f.iam
                .authorize(&check(&f, &token, "files:read", "file", "a"))
                .await
                .unwrap()
                .allowed
        );
        // From the attached policy.
        assert!(
            f.iam
                .authorize(&check(&f, &token, "files:write", "file", "plain-1"))
                .await
                .unwrap()
                .allowed
        );
        // The session has no second factor.
        assert!(
            !f.iam
                .authorize(&check(&f, &token, "files:write", "file", "mfa-1"))
                .await
                .unwrap()
                .allowed
        );
        // A policy whose authority lapsed grants nothing; the inherited role keeps its own authority.
        let mut policy = f
            .iam
            .store
            .get("policies", &policy_id)
            .await
            .unwrap()
            .unwrap();
        policy.insert("authorityId".into(), json!("missing-authority"));
        put(&f.iam, "policies", &policy).await;
        assert!(
            !f.iam
                .authorize(&check(&f, &token, "files:write", "file", "plain-1"))
                .await
                .unwrap()
                .allowed
        );
        assert!(
            f.iam
                .authorize(&check(&f, &token, "files:read", "file", "a"))
                .await
                .unwrap()
                .allowed
        );
        // Root-only operations refuse everyone else, whatever their grants.
        grant(
            &f,
            json!([{ "effect": "allow", "actions": ["iam:identities:read"], "resources": ["iam/*"] }]),
            json!({}),
        )
        .await;
        let auth = format!("Bearer {token}");
        let refused = post(
            &f.iam,
            "root/listAdministrators",
            json!({ "tenantId": f.tenant_id }),
            &[("authorization", &auth)],
        )
        .await;
        assert_eq!(refused.status(), 403);
        assert_eq!(json_of(&refused)["error"]["code"], json!("ACCESS_DENIED"));
    });
}
