//! Port of `tests/web-identity.test.ts`: AssumeRoleWithWebIdentity end to end: the public exchange
//! (`sts.assumeRoleWithWebIdentity`, in process and over `iam.handler`), the uniform refusal, replay protection, rate
//! and session limits, audits, kill switches and revocation, network allowlists, key rotation, the JWT format, the
//! feature switch, and the administrators' dry run (`trust.evaluateWebIdentity`, which runs `evaluateWebIdentity` of
//! web-identity-exchange.ts). External identity providers are played with `tests/jwt_keys`; keys are served as static
//! `jwks` or through `sts.webIdentity.fetchJson`.
//!
//! The `web-identity trusts` validation tests (`trust.create` and `trust.update` of a web-identity trust) and the
//! `trust management fixes` block exercise `api/trust.ts`, which the trust unit ports.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use better_iam_core::{CredentialInput, IamError, IamResult, Record, SessionClientInfo};
use better_iam_server::api::index::Api;
use better_iam_server::better_iam;
use better_iam_server::options::{BetterIamOptions, FetchJsonFn, HttpResponse};
use better_iam_server::utils::id;
use futures::future::BoxFuture;
use serde_json::{Map, Value, json};

use crate::jwt_keys::{
    Signer, TestKey, decode_test_jwt, generate_test_key, sign_test_jwt, tamper_payload,
};
use crate::support::*;

const ISSUER_IDP: &str = "https://token.actions.example.test";
const AUDIENCE: &str = "https://acme.example";
const SUBJECT: &str = "repo:acme/app:ref:refs/heads/main";

fn rejected_body() -> Value {
    json!({ "error": { "code": "WEB_IDENTITY_REJECTED", "message": "The web identity token was not accepted" } })
}

/// Reads everything; writes only when the session carries the expected web identity, name, tag and source identity.
fn deployer() -> Value {
    json!({
        "version": 1,
        "statements": [
            { "effect": "allow", "actions": ["documents:read"], "resources": ["*"] },
            {
                "effect": "allow",
                "actions": ["documents:write"],
                "resources": ["*"],
                "conditions": {
                    "StringEquals": {
                        "principal.webIdentitySubject": SUBJECT,
                        "principal.sessionName": "ci-run",
                        "principal.sessionTags.repo": "acme/app",
                        "principal.sourceIdentity": "octocat",
                    },
                },
            },
        ],
    })
}

/// What the setup's options add: `webIdentity` members, other `sts` members, and an optional `fetchJson`.
#[derive(Default)]
struct SetupOptions {
    web_identity: Option<Value>,
    sts: Option<Value>,
    fetch_json: Option<FetchJsonFn>,
}

struct Setup {
    f: Fixture,
    rsa: TestKey,
    provider: Value,
    account: Value,
    role: Value,
    trust: Value,
}

fn merge(target: &mut Value, extra: Option<Value>) {
    if let (Value::Object(target), Some(Value::Object(extra))) = (target, extra) {
        for (name, value) in extra {
            target.insert(name, value);
        }
    }
}

fn sts_value(options: &SetupOptions) -> Value {
    let mut web = json!({ "enabled": true });
    merge(&mut web, options.web_identity.clone());
    let mut value = json!({});
    merge(&mut value, options.sts.clone());
    value["webIdentity"] = web;
    value
}

fn configure(options: SetupOptions) -> impl FnOnce(&mut BetterIamOptions) {
    move |target: &mut BetterIamOptions| {
        let mut parsed = sts(sts_value(&options));
        if let Some(fetch_json) = options.fetch_json {
            parsed
                .web_identity
                .get_or_insert_with(Default::default)
                .fetch_json = Some(fetch_json);
        }
        target.sts = Some(parsed);
    }
}

async fn setup(options: SetupOptions) -> IamResult<Setup> {
    let f = organization_fixture(configure(options)).await?;
    let rsa = generate_test_key("RS256", "rsa-1");
    let provider = api!(
        f.iam.api.oidc_providers,
        create,
        &f.owner_credential,
        json!({
            "tenantId": f.tenant_id,
            "name": "GitHub Actions",
            "issuer": ISSUER_IDP,
            "audiences": [AUDIENCE],
            "jwks": { "keys": [rsa.public_jwk] },
        })
    )?;
    let account = api!(
        f.iam.api.service_accounts,
        create,
        &f.owner_credential,
        json!({ "tenantId": f.tenant_id, "name": "ci" })
    )?;
    let role = api!(
        f.iam.api.roles,
        create,
        &f.owner_credential,
        json!({ "tenantId": f.tenant_id, "name": "Deployer", "document": deployer() })
    )?;
    let trust = api!(
        f.iam.api.trust,
        create,
        &f.owner_credential,
        json!({
            "tenantId": f.tenant_id,
            "kind": "web-identity",
            "providerId": provider["id"],
            "serviceAccountId": account["id"],
            "roleId": role["id"],
            "conditions": { "StringEquals": { "token.sub": SUBJECT, "token.repository_owner": "acme" } },
            "tagClaims": { "repo": "token.repository" },
            "sourceIdentityClaim": "token.actor",
        })
    )?;
    Ok(Setup {
        f,
        rsa,
        provider,
        account,
        role,
        trust,
    })
}

/// How a test token is signed: the setup's RSA key, another key, HS256 with a shared secret, or `alg: none`.
enum Key<'a> {
    Default,
    Other(&'a TestKey),
    Hs256(&'static [u8]),
    None,
}

impl Setup {
    /// A fresh token from the test IdP (current iat, five-minute lifetime, unique jti); a `null` claim removes it.
    fn token_with(&self, claims: Value, header: Value, key: Key<'_>) -> String {
        let iat = (self.f.now() / 1000.0).floor();
        let mut payload: Map<String, Value> = map_of(json!({
            "iss": ISSUER_IDP,
            "aud": AUDIENCE,
            "sub": SUBJECT,
            "iat": iat,
            "exp": iat + 300.0,
            "jti": id(),
            "repository": "acme/app",
            "repository_owner": "acme",
            "actor": "octocat",
        }));
        for (name, value) in map_of(claims) {
            if value.is_null() {
                payload.shift_remove(&name);
            } else {
                payload.insert(name, value);
            }
        }
        let signer = match key {
            Key::Default => Signer::Key(&self.rsa),
            Key::Other(key) => Signer::Key(key),
            Key::Hs256(secret) => Signer::Hs256(secret),
            Key::None => Signer::None,
        };
        sign_test_jwt(signer, &Value::Object(payload), header)
    }

    fn token(&self) -> String {
        self.token_with(json!({}), json!({}), Key::Default)
    }

    fn claims(&self, claims: Value) -> String {
        self.token_with(claims, json!({}), Key::Default)
    }

    fn request(&self, web_identity_token: &str, extra: Value) -> Value {
        let mut input = json!({
            "tenantId": self.f.tenant_id,
            "trustId": self.trust["id"],
            "webIdentityToken": web_identity_token,
            "sessionName": "ci-run",
        });
        merge(&mut input, Some(extra));
        input
    }

    async fn exchange(&self, web_identity_token: &str, extra: Value) -> IamResult<Value> {
        json(
            self.f
                .iam
                .api
                .sts
                .assume_role_with_web_identity(body(self.request(web_identity_token, extra)))
                .await,
        )
    }

    /// The public route over the handler, as a workload would call it.
    async fn http(&self, input: Value) -> HttpResponse {
        let endpoint = &self.f.iam.endpoint;
        let url = format!(
            "{}{}/sts/assumeRoleWithWebIdentity",
            endpoint.origin, endpoint.base_path
        );
        self.f
            .iam
            .handler(request(
                http::Method::POST,
                &url,
                &[("content-type", "application/json"), ("x-better-iam", "1")],
                Some(input),
            ))
            .await
    }

    async fn works(&self, credential: &str) -> bool {
        self.f.iam.authenticate(&bearer(credential)).await.is_ok()
    }

    async fn allowed(&self, credential: &str, action: &str) -> IamResult<bool> {
        self.f.allowed(credential, action, "release-notes").await
    }

    /// The tenant's events for `action` in the order they were recorded.
    async fn audits(&self, action: &str) -> Vec<Value> {
        self.f
            .audit(&self.f.tenant_id)
            .await
            .iter()
            .filter(|event| event.get("action").and_then(Value::as_str) == Some(action))
            .map(value)
            .collect()
    }

    async fn exchange_audits(&self) -> Vec<Value> {
        self.audits("role:assumed-with-web-identity").await
    }
}

fn denials(events: &[Value]) -> Vec<Value> {
    events
        .iter()
        .filter(|event| event["outcome"] == "deny")
        .cloned()
        .collect()
}

fn reasons(events: &[Value]) -> Vec<Value> {
    denials(events)
        .iter()
        .map(|event| event["metadata"]["reason"].clone())
        .collect()
}

fn web_identity(s: &Setup) -> Value {
    json!({ "providerId": s.provider["id"], "issuer": ISSUER_IDP, "subject": SUBJECT })
}

fn client(ip: &str, user_agent: &str) -> Option<SessionClientInfo> {
    Some(SessionClientInfo {
        ip: Some(ip.to_owned()),
        user_agent: Some(user_agent.to_owned()),
        ..SessionClientInfo::default()
    })
}

fn fetch_failure(url: &url::Url) -> IamError {
    IamError::new("FETCH_FAILED", format!("unexpected fetch {}", url.as_str()))
}

#[test]
fn issues_a_role_session_for_rsa_tokens_from_static_keys_visible_to_policies() {
    run(|| async {
        let s = ok!(setup(SetupOptions::default()).await);
        let f = &s.f;
        let credential = ok!(s.exchange(&s.token(), json!({})).await);
        let token = str_of(&credential, "token").to_owned();
        assert!(typed_token(&token, "biam_rol_"), "{token}");
        let session_id = str_of(&credential["session"], "id").to_owned();
        same(
            &credential,
            &json!({
                "token": token,
                "tokenType": "Bearer",
                "format": "opaque",
                "expiresAt": f.now() + 900_000.0,
                "expiresIn": 900,
                "session": {
                    "id": session_id,
                    "tenantId": f.tenant_id,
                    "kind": "role",
                    "identityId": s.account["id"],
                    "expiresAt": f.now() + 900_000.0,
                    "mfa": false,
                    "roleId": s.role["id"],
                    "trustId": s.trust["id"],
                    "sessionName": "ci-run",
                    "sourceIdentity": "octocat",
                },
                "webIdentity": web_identity(&s),
            }),
        );
        let row = f.get("sessions", &session_id).await.expect("session row");
        matches(
            &value(&row),
            &json!({
                "kind": "role",
                "identityId": s.account["id"],
                "originalIdentityId": s.account["id"],
                "credentialAuthorityId": s.trust["authorityId"],
                "authenticatedAt": f.now(),
                "sessionTags": { "repo": "acme/app" },
                "webIdentity": web_identity(&s),
            }),
        );
        for absent in ["sourceSessionId", "sourceTenantId", "mfaAuthenticatedAt"] {
            assert!(!row.contains_key(absent), "{absent}");
        }

        assert!(ok!(s.allowed(&token, "documents:read").await));
        assert!(ok!(s.allowed(&token, "documents:write").await));
        matches(
            &ok!(f.get_caller_identity(&bearer(&token)).await),
            &json!({
                "identityId": s.account["id"],
                "sessionKind": "role",
                "sessionName": "ci-run",
                "sourceIdentity": "octocat",
                "sessionTags": { "repo": "acme/app" },
                "webIdentity": web_identity(&s),
            }),
        );
        // Another session name no longer satisfies the write condition; a scope-down policy bounds the session.
        let renamed = ok!(s
            .exchange(&s.token(), json!({ "sessionName": "nightly" }))
            .await);
        assert!(ok!(s
            .allowed(str_of(&renamed, "token"), "documents:read")
            .await));
        assert!(!ok!(s
            .allowed(str_of(&renamed, "token"), "documents:write")
            .await));
        let scoped = ok!(s
            .exchange(
                &s.token(),
                json!({ "durationSeconds": 3600, "policy": allow(&["documents:write"]) }),
            )
            .await);
        assert_eq!(scoped["expiresIn"], 3600);
        assert!(!ok!(s
            .allowed(str_of(&scoped, "token"), "documents:read")
            .await));
        assert!(ok!(s
            .allowed(str_of(&scoped, "token"), "documents:write")
            .await));
    });
}

#[test]
fn verifies_ec_tokens_with_keys_discovered_and_fetched_through_fetch_json() {
    run(|| async {
        let ec = generate_test_key("ES256", "ec-1");
        let gitlab = "https://gitlab.example.test";
        let fetched: Arc<Mutex<Vec<String>>> = Arc::default();
        let fetch_json: FetchJsonFn = {
            let (fetched, ec_public) = (fetched.clone(), ec.public_jwk.clone());
            Arc::new(move |url| {
                let (fetched, ec_public) = (fetched.clone(), ec_public.clone());
                Box::pin(async move {
                    fetched.lock().unwrap().push(url.as_str().to_owned());
                    if url.as_str() == format!("{gitlab}/.well-known/openid-configuration") {
                        return Ok(
                            json!({ "issuer": gitlab, "jwks_uri": format!("{gitlab}/oauth/discovery/keys") }),
                        );
                    }
                    if url.as_str() == format!("{gitlab}/oauth/discovery/keys") {
                        return Ok(json!({ "keys": [ec_public] }));
                    }
                    Err(fetch_failure(&url))
                })
            })
        };
        let s = ok!(setup(SetupOptions {
            fetch_json: Some(fetch_json),
            ..SetupOptions::default()
        })
        .await);
        let f = &s.f;
        let provider = ok!(api!(
            f.iam.api.oidc_providers,
            create,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "name": "GitLab", "issuer": gitlab, "audiences": [AUDIENCE] })
        ));
        // Nothing is fetched when a provider is created.
        assert!(fetched.lock().unwrap().is_empty());
        let trust = ok!(api!(
            f.iam.api.trust,
            create,
            &f.owner_credential,
            json!({
                "tenantId": f.tenant_id,
                "kind": "web-identity",
                "providerId": provider["id"],
                "serviceAccountId": s.account["id"],
                "roleId": s.role["id"],
                "conditions": { "StringLike": { "token.sub": "project_path:acme/*" } },
            })
        ));
        let iat = (f.now() / 1000.0).floor();
        let token = |session_name: &str| {
            json!({
                "tenantId": f.tenant_id,
                "trustId": trust["id"],
                "webIdentityToken": sign_test_jwt(
                    Signer::Key(&ec),
                    &json!({
                        "iss": gitlab,
                        "aud": AUDIENCE,
                        "sub": "project_path:acme/app:ref:main",
                        "iat": iat,
                        "exp": iat + 300.0,
                        "jti": id(),
                    }),
                    json!({}),
                ),
                "sessionName": session_name,
            })
        };
        let credential = ok!(json(
            f.iam
                .api
                .sts
                .assume_role_with_web_identity(body(token("pipeline-42")))
                .await
        ));
        same(
            &credential["webIdentity"],
            &json!({ "providerId": provider["id"], "issuer": gitlab, "subject": "project_path:acme/app:ref:main" }),
        );
        assert!(s.works(str_of(&credential, "token")).await);
        assert_eq!(
            *fetched.lock().unwrap(),
            [
                format!("{gitlab}/.well-known/openid-configuration"),
                format!("{gitlab}/oauth/discovery/keys")
            ]
        );
        // Cached: the next token fetches nothing.
        ok!(json(
            f.iam
                .api
                .sts
                .assume_role_with_web_identity(body(token("pipeline-43")))
                .await
        ));
        assert_eq!(fetched.lock().unwrap().len(), 2);
    });
}

/// A second provider (another issuer and key) with a trust on the same role.
async fn second_provider(s: &Setup, key: &TestKey, issuer: &str) -> IamResult<(Value, Value)> {
    let f = &s.f;
    let provider = api!(
        f.iam.api.oidc_providers,
        create,
        &f.owner_credential,
        json!({
            "tenantId": f.tenant_id,
            "name": "GitLab",
            "issuer": issuer,
            "audiences": [AUDIENCE],
            "jwks": { "keys": [key.public_jwk] },
        })
    )?;
    let trust = api!(
        f.iam.api.trust,
        create,
        &f.owner_credential,
        json!({
            "tenantId": f.tenant_id,
            "kind": "web-identity",
            "providerId": provider["id"],
            "serviceAccountId": s.account["id"],
            "roleId": s.role["id"],
            "conditions": { "StringEquals": { "token.sub": SUBJECT } },
        })
    )?;
    Ok((provider, trust))
}

#[test]
fn answers_every_refusal_with_the_same_body_over_http_and_never_sets_a_cookie() {
    run(|| async {
        let s = ok!(setup(SetupOptions::default()).await);
        let f = &s.f;
        let gitlab_key = generate_test_key("RS256", "gitlab-1");
        let (disabled_provider, disabled_trust) =
            ok!(second_provider(&s, &gitlab_key, "https://gitlab.example.test").await);
        ok!(api!(
            f.iam.api.oidc_providers,
            update,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "providerId": disabled_provider["id"], "enabled": false })
        ));
        let revoked = ok!(api!(
            f.iam.api.trust,
            create,
            &f.owner_credential,
            json!({
                "tenantId": f.tenant_id,
                "kind": "web-identity",
                "providerId": s.provider["id"],
                "serviceAccountId": s.account["id"],
                "roleId": s.role["id"],
                "conditions": { "StringEquals": { "token.sub": SUBJECT } },
            })
        ));
        ok!(api!(
            f.iam.api.trust,
            revoke,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "trustId": revoked["id"] })
        ));

        let now = (f.now() / 1000.0).floor();
        let good = s.token();
        let accepted = s.http(s.request(&good, json!({}))).await;
        reached!(accepted);
        assert_eq!(accepted.status(), 200);
        assert!(header(&accepted, "set-cookie").is_none());
        let accepted_body = response_json(&accepted)["data"].clone();
        assert!(str_of(&accepted_body, "token").starts_with("biam_rol_"));
        same(&accepted_body["webIdentity"], &web_identity(&s));
        assert!(s.works(str_of(&accepted_body, "token")).await);

        let foreign = generate_test_key("RS256", "rsa-1");
        let failures: Vec<(&str, Value)> = vec![
            (
                "audience",
                s.request(
                    &s.claims(json!({ "aud": "https://other.example" })),
                    json!({}),
                ),
            ),
            (
                "issuer",
                s.request(
                    &s.claims(json!({ "iss": "https://evil.example.test" })),
                    json!({}),
                ),
            ),
            (
                "expired",
                s.request(
                    &s.claims(json!({ "iat": now - 1000.0, "exp": now - 100.0 })),
                    json!({}),
                ),
            ),
            (
                "lifetime",
                s.request(&s.claims(json!({ "exp": now + 7200.0 })), json!({})),
            ),
            (
                "age",
                s.request(
                    &s.claims(json!({ "iat": now - 4000.0, "exp": now + 60.0 })),
                    json!({}),
                ),
            ),
            (
                "hs256",
                s.request(
                    &s.token_with(json!({}), json!({}), Key::Hs256(b"shared-secret")),
                    json!({}),
                ),
            ),
            (
                "none",
                s.request(&s.token_with(json!({}), json!({}), Key::None), json!({})),
            ),
            (
                "unknownKid",
                s.request(
                    &s.token_with(json!({}), json!({ "kid": "rotated-away" }), Key::Default),
                    json!({}),
                ),
            ),
            (
                "foreignKey",
                s.request(
                    &s.token_with(json!({}), json!({}), Key::Other(&foreign)),
                    json!({}),
                ),
            ),
            (
                "typ",
                s.request(
                    &s.token_with(json!({}), json!({ "typ": "at+jwt" }), Key::Default),
                    json!({}),
                ),
            ),
            (
                "ownSessionTyp",
                s.request(
                    &s.token_with(
                        json!({}),
                        json!({ "typ": "biam-session+jwt" }),
                        Key::Default,
                    ),
                    json!({}),
                ),
            ),
            (
                "missingSub",
                s.request(&s.claims(json!({ "sub": null })), json!({})),
            ),
            (
                "forged",
                s.request(
                    &tamper_payload(
                        &s.token(),
                        json!({ "sub": "repo:acme/app:ref:refs/heads/evil" }),
                    ),
                    json!({}),
                ),
            ),
            (
                "conditions",
                s.request(
                    &s.claims(json!({ "sub": "repo:acme/other:ref:refs/heads/main" })),
                    json!({}),
                ),
            ),
            (
                "sourceIdentity",
                s.request(&s.claims(json!({ "actor": "not valid!" })), json!({})),
            ),
            ("replay", s.request(&good, json!({}))),
            (
                "unknownTrust",
                s.request(&s.token(), json!({ "trustId": id() })),
            ),
            (
                "otherTenant",
                s.request(&s.token(), json!({ "tenantId": f.root_tenant })),
            ),
            (
                "revokedTrust",
                s.request(&s.token(), json!({ "trustId": revoked["id"] })),
            ),
            (
                "disabledProvider",
                s.request(
                    &s.token_with(
                        json!({ "iss": "https://gitlab.example.test" }),
                        json!({}),
                        Key::Other(&gitlab_key),
                    ),
                    json!({ "trustId": disabled_trust["id"] }),
                ),
            ),
        ];
        for (name, input) in &failures {
            let response = s.http(input.clone()).await;
            same(
                &json!({ "name": name, "status": response.status().as_u16(), "body": response_json(&response) }),
                &json!({ "name": name, "status": 403, "body": rejected_body() }),
            );
            assert!(header(&response, "set-cookie").is_none(), "{name}");
        }
        // Shape errors are the only specific answers before the rate limit and lookup.
        let malformed = s.http(s.request("not-a-jwt", json!({}))).await;
        assert_eq!(malformed.status(), 400);
        assert_eq!(response_json(&malformed)["error"]["code"], "INVALID_INPUT");
        let unnamed = s
            .http(s.request(&s.token(), json!({ "sessionName": "x" })))
            .await;
        assert_eq!(response_json(&unnamed)["error"]["code"], "INVALID_INPUT");

        // Denials are audited with their reason once the trust resolved; claims only when the signature verified.
        let audits = s.exchange_audits().await;
        let denied = denials(&audits);
        let reasons = reasons(&audits);
        for reason in [
            "audience",
            "issuer",
            "expired",
            "lifetime",
            "too-old",
            "algorithm",
            "unknown-key",
            "signature",
            "type",
            "claims",
            "conditions",
            "source-identity",
            "replay",
        ] {
            assert!(reasons.contains(&json!(reason)), "{reason}");
        }
        for event in &denied {
            assert_eq!(event["resourceId"], s.role["id"]);
            assert_eq!(event["actorId"], s.account["id"]);
            matches(
                &event["metadata"],
                &json!({ "trustId": s.trust["id"], "providerId": s.provider["id"] }),
            );
            let verified = ["conditions", "source-identity", "replay"]
                .contains(&str_of(&event["metadata"], "reason"));
            assert_eq!(event["metadata"].get("subject").is_some(), verified);
        }
        let replay = denied
            .iter()
            .find(|event| event["metadata"]["reason"] == "replay")
            .expect("replay denial");
        matches(
            &replay["metadata"],
            &json!({ "issuer": ISSUER_IDP, "subject": SUBJECT }),
        );
        // Unknown, foreign, revoked and disabled-provider trusts leave no audit trail.
        let trust_ids: Vec<&Value> = denied
            .iter()
            .map(|event| &event["metadata"]["trustId"])
            .collect();
        assert!(!trust_ids.contains(&&revoked["id"]));
        assert!(!trust_ids.contains(&&disabled_trust["id"]));
        assert_eq!(denied.len(), failures.len() - 4);
    });
}

#[test]
fn audits_issuance_and_never_stores_the_raw_token_anywhere() {
    run(|| async {
        let s = ok!(setup(SetupOptions::default()).await);
        let f = &s.f;
        let external = s.token();
        let credential = ok!(s.exchange(&external, json!({})).await);
        refused(
            &fails!(s.exchange(&external, json!({})).await),
            "WEB_IDENTITY_REJECTED",
            None,
            None,
        );
        let allow_event = s
            .exchange_audits()
            .await
            .into_iter()
            .find(|event| event["outcome"] == "allow")
            .expect("allow event");
        matches(
            &allow_event,
            &json!({
                "tenantId": f.tenant_id,
                "actorId": s.account["id"],
                "resourceId": s.role["id"],
                "metadata": {
                    "trustId": s.trust["id"],
                    "providerId": s.provider["id"],
                    "issuer": ISSUER_IDP,
                    "subject": SUBJECT,
                    "durationSeconds": 900,
                    "format": "opaque",
                    "tagKeys": ["repo"],
                },
                "sessionContext": {
                    "sessionId": credential["session"]["id"],
                    "kind": "role",
                    "roleId": s.role["id"],
                    "trustId": s.trust["id"],
                    "sessionName": "ci-run",
                    "sourceIdentity": "octocat",
                    "webIdentityProviderId": s.provider["id"],
                    "webIdentitySubject": SUBJECT,
                },
            }),
        );
        let collections = f.iam.store.collections().await.unwrap();
        assert!(collections.iter().any(|name| name == "webIdentityReplays"));
        let signature = external.split('.').nth(2).unwrap().to_owned();
        for collection in &collections {
            let records: Vec<Value> = f
                .find(collection, json!({}))
                .await
                .iter()
                .map(value)
                .collect();
            let dump = better_iam_core::js::stringify(&Value::Array(records));
            assert!(!dump.contains(&external), "{collection}");
            assert!(!dump.contains(&signature), "{collection}");
            assert!(!dump.contains(str_of(&credential, "token")), "{collection}");
        }
    });
}

fn base64url_lenient() -> GeneralPurpose {
    GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    )
}

#[test]
fn redeems_a_token_once_unless_the_provider_turns_replay_protection_off() {
    run(|| async {
        let s = ok!(setup(SetupOptions::default()).await);
        let f = &s.f;
        let external = s.token();
        // A refusal after verification rolls back, so the token is not burned.
        refused(
            &fails!(
                s.exchange(&external, json!({ "durationSeconds": 7200 }))
                    .await
            ),
            "INVALID_INPUT",
            None,
            None,
        );
        refused(
            &fails!(s.exchange(&external, json!({ "format": "jwt" })).await),
            "FEATURE_DISABLED",
            None,
            None,
        );
        assert!(f.find("webIdentityReplays", json!({})).await.is_empty());
        ok!(s.exchange(&external, json!({})).await);
        refused(
            &fails!(s.exchange(&external, json!({})).await),
            "WEB_IDENTITY_REJECTED",
            None,
            None,
        );
        let (_, payload) = decode_test_jwt(&external);
        let replays = f.find("webIdentityReplays", json!({})).await;
        let replay = value(&replays[0]);
        let replay_id = str_of(&replay, "id").to_owned();
        assert!(
            replay_id.len() == 64
                && replay_id
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );
        // The token's exp plus the largest clock tolerance a provider may have (120 s), so it outlives the acceptance
        // window even if the provider's tolerance is raised later.
        same(
            &replay,
            &json!({
                "id": replay_id,
                "tenantId": f.tenant_id,
                "providerId": s.provider["id"],
                "expiresAt": payload["exp"].as_f64().unwrap() * 1000.0 + 120_000.0,
            }),
        );
        // Tokens without a jti are keyed by their signed content (header.payload).
        let anonymous = s.claims(json!({ "jti": null }));
        ok!(s.exchange(&anonymous, json!({})).await);
        refused(
            &fails!(s.exchange(&anonymous, json!({})).await),
            "WEB_IDENTITY_REJECTED",
            None,
            None,
        );
        // A different spelling of the same signature (unused trailing base64url bits) is still the same token.
        // (A distinct claim: without a jti, identical claims at the same clock are the same signed content.)
        let fresh = s.claims(json!({ "jti": null, "run_id": "second" }));
        let cut = fresh.rfind('.').unwrap() + 1;
        let signature = &fresh[cut..];
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let last = alphabet.find(&signature[signature.len() - 1..]).unwrap();
        let respelled = format!(
            "{}{}",
            &signature[..signature.len() - 1],
            &alphabet[(last ^ 1)..(last ^ 1) + 1]
        );
        let engine = base64url_lenient();
        assert_eq!(
            engine.decode(&respelled).unwrap(),
            engine.decode(signature).unwrap()
        );
        let variant = format!("{}{}", &fresh[..cut], respelled);
        assert_ne!(variant, fresh);
        ok!(s.exchange(&variant, json!({})).await);
        refused(
            &fails!(s.exchange(&fresh, json!({})).await),
            "WEB_IDENTITY_REJECTED",
            None,
            None,
        );
        let replay_denials = f
            .find("audit", json!({}))
            .await
            .iter()
            .filter(|event| {
                event
                    .get("metadata")
                    .and_then(|metadata| metadata.get("reason"))
                    == Some(&json!("replay"))
            })
            .count();
        assert!(replay_denials >= 2);

        ok!(api!(
            f.iam.api.oidc_providers,
            update,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "providerId": s.provider["id"], "replayProtection": "off" })
        ));
        let reusable = s.token();
        let first = ok!(s.exchange(&reusable, json!({})).await);
        let second = ok!(s.exchange(&reusable, json!({})).await);
        assert_ne!(first["session"]["id"], second["session"]["id"]);
        // One record each for `external`, `anonymous` and the re-spelled `fresh`; none while protection is off.
        assert_eq!(f.find("webIdentityReplays", json!({})).await.len(), 3);
    });
}

#[test]
fn counts_exchanges_per_client_address_so_junk_from_one_source_cannot_lock_a_trust() {
    run(|| async {
        let s = ok!(setup(SetupOptions {
            web_identity: Some(json!({ "maxExchangesPerWindow": 3 })),
            ..SetupOptions::default()
        })
        .await);
        let auth = &s.f.iam.auth;
        // An attacker who knows the (public) trust id posts junk until its own budget is gone.
        for _ in 0..3 {
            let junk = s.claims(json!({ "aud": "wrong" }));
            refused(
                &fails!(
                    auth.with_client(client("198.51.100.66", "ci"), s.exchange(&junk, json!({})))
                        .await
                ),
                "WEB_IDENTITY_REJECTED",
                None,
                None,
            );
        }
        let token = s.token();
        refused(
            &fails!(
                auth.with_client(client("198.51.100.66", "ci"), s.exchange(&token, json!({})))
                    .await
            ),
            "RATE_LIMITED",
            None,
            None,
        );
        // The real workload, from its own address, still exchanges.
        let token = s.token();
        let credential = ok!(auth
            .with_client(client("203.0.113.9", "ci"), s.exchange(&token, json!({})))
            .await);
        assert_eq!(credential["session"]["kind"], "role");
    });
}

#[test]
fn counts_exchanges_per_trust_before_any_lookup() {
    run(|| async {
        let s = ok!(setup(SetupOptions {
            web_identity: Some(json!({ "maxExchangesPerWindow": 3 })),
            ..SetupOptions::default()
        })
        .await);
        ok!(s.exchange(&s.token(), json!({})).await);
        refused(
            &fails!(
                s.exchange(&s.claims(json!({ "aud": "wrong" })), json!({}))
                    .await
            ),
            "WEB_IDENTITY_REJECTED",
            None,
            None,
        );
        ok!(s.exchange(&s.token(), json!({})).await);
        refused(
            &fails!(s.exchange(&s.token(), json!({})).await),
            "RATE_LIMITED",
            Some(429),
            None,
        );
        // Unknown trusts are counted the same way, so the limit reveals nothing either.
        let unknown = id();
        for _ in 0..3 {
            refused(
                &fails!(s.exchange(&s.token(), json!({ "trustId": unknown })).await),
                "WEB_IDENTITY_REJECTED",
                None,
                None,
            );
        }
        refused(
            &fails!(s.exchange(&s.token(), json!({ "trustId": unknown })).await),
            "RATE_LIMITED",
            None,
            None,
        );
    });
}

#[test]
fn caps_live_sessions_per_trust_without_burning_the_token() {
    run(|| async {
        let s = ok!(setup(SetupOptions {
            web_identity: Some(json!({ "maxSessionsPerTrust": 2 })),
            ..SetupOptions::default()
        })
        .await);
        let f = &s.f;
        ok!(s.exchange(&s.token(), json!({})).await);
        ok!(s.exchange(&s.token(), json!({})).await);
        let third = s.token();
        refused(
            &fails!(s.exchange(&third, json!({})).await),
            "LIMIT_EXCEEDED",
            Some(409),
            None,
        );
        let denial = s
            .exchange_audits()
            .await
            .into_iter()
            .find(|event| event["outcome"] == "deny")
            .expect("denial");
        matches(
            &denial["metadata"],
            &json!({ "reason": "LIMIT_EXCEEDED", "subject": SUBJECT }),
        );
        // Revoked sessions do not count, and the refused token was not redeemed.
        ok!(api!(
            f.iam.api.trust,
            revoke_sessions,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "trustId": s.trust["id"] })
        ));
        f.advance(1.0);
        assert_eq!(
            ok!(s.exchange(&third, json!({})).await)["session"]["trustId"],
            s.trust["id"]
        );
    });
}

#[test]
fn enforces_the_tenants_network_allowlist_on_issuance_and_on_every_use() {
    run(|| async {
        let s = ok!(setup(SetupOptions::default()).await);
        let f = &s.f;
        ok!(api!(
            f.iam.api.tenants,
            set_auth_policy,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "authPolicy": { "allowedIpRanges": ["203.0.113.0/24"] } })
        ));
        let auth = &f.iam.auth;
        let external = s.token();
        refused(
            &fails!(
                auth.with_client(
                    client("198.51.100.8", "ci"),
                    s.exchange(&external, json!({}))
                )
                .await
            ),
            "IP_NOT_ALLOWED",
            None,
            None,
        );
        let credential = ok!(auth
            .with_client(
                client("203.0.113.5", "ci"),
                s.exchange(&external, json!({}))
            )
            .await);
        let session_id = str_of(&credential["session"], "id").to_owned();
        same(
            &f.get("sessions", &session_id).await.unwrap()["client"],
            &json!({ "ip": "203.0.113.5", "userAgent": "ci" }),
        );
        let token = bearer(str_of(&credential, "token"));
        refused(
            &fails!(
                auth.with_client(client("198.51.100.8", "ci"), f.authenticate(&token))
                    .await
            ),
            "IP_NOT_ALLOWED",
            None,
            None,
        );
        let session = ok!(auth
            .with_client(client("203.0.113.9", "ci"), f.authenticate(&token))
            .await);
        assert_eq!(session["id"], json!(session_id));
    });
}

#[test]
fn refetches_keys_for_an_unknown_kid_at_most_once_per_cooldown() {
    run(|| async {
        let first = generate_test_key("RS256", "k1");
        let second = generate_test_key("RS256", "k2");
        let jwks_uri = "https://keys.example.test/jwks";
        let served: Arc<Mutex<Vec<Value>>> =
            Arc::new(Mutex::new(vec![Value::Object(first.public_jwk.clone())]));
        let fetches = Arc::new(AtomicUsize::new(0));
        let fetch_json: FetchJsonFn = {
            let (served, fetches) = (served.clone(), fetches.clone());
            Arc::new(move |url| {
                let (served, fetches) = (served.clone(), fetches.clone());
                Box::pin(async move {
                    if url.as_str() != jwks_uri {
                        return Err(fetch_failure(&url));
                    }
                    fetches.fetch_add(1, Ordering::SeqCst);
                    let keys = served.lock().unwrap().clone();
                    Ok(json!({ "keys": keys }))
                })
            })
        };
        let s = ok!(setup(SetupOptions {
            fetch_json: Some(fetch_json),
            ..SetupOptions::default()
        })
        .await);
        let f = &s.f;
        ok!(api!(
            f.iam.api.oidc_providers,
            update,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "providerId": s.provider["id"], "jwks": null, "jwksUri": jwks_uri })
        ));
        ok!(s
            .exchange(
                &s.token_with(json!({}), json!({}), Key::Other(&first)),
                json!({})
            )
            .await);
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        // The IdP rotates; a token with the new kid within the cooldown is refused without another fetch.
        *served.lock().unwrap() = vec![
            Value::Object(first.public_jwk.clone()),
            Value::Object(second.public_jwk.clone()),
        ];
        refused(
            &fails!(
                s.exchange(
                    &s.token_with(json!({}), json!({}), Key::Other(&second)),
                    json!({})
                )
                .await
            ),
            "WEB_IDENTITY_REJECTED",
            None,
            None,
        );
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        same(
            &Value::Array(reasons(&s.exchange_audits().await)),
            &json!(["unknown-key"]),
        );
        f.advance(31_000.0);
        ok!(s
            .exchange(
                &s.token_with(json!({}), json!({}), Key::Other(&second)),
                json!({})
            )
            .await);
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        // The old key keeps working from the refreshed set.
        ok!(s
            .exchange(
                &s.token_with(json!({}), json!({}), Key::Other(&first)),
                json!({})
            )
            .await);
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    });
}

/// An administrator's change that lands while the exchange is fetching the provider's keys.
type During = Arc<Mutex<Option<BoxFuture<'static, IamResult<Value>>>>>;

#[test]
fn issues_against_the_trust_and_provider_as_they_stand_at_issuance_not_at_verification() {
    run(|| async {
        let jwks_uri = "https://keys.example.test/jwks";
        let legacy_audience = "https://legacy.acme.example";
        let during: During = Arc::default();
        // The key the fetch serves; the setup's RSA key, known once the setup ran.
        let served: Arc<Mutex<Option<Value>>> = Arc::default();
        let clock_slot: Arc<Mutex<Option<Clock>>> = Arc::default();
        let fetch_json: FetchJsonFn = {
            let (during, served, clock_slot) = (during.clone(), served.clone(), clock_slot.clone());
            Arc::new(move |url| {
                let (during, served, clock_slot) =
                    (during.clone(), served.clone(), clock_slot.clone());
                Box::pin(async move {
                    if url.as_str() != jwks_uri {
                        return Err(fetch_failure(&url));
                    }
                    let change = during.lock().unwrap().take();
                    if let Some(change) = change {
                        if let Some(clock) = clock_slot.lock().unwrap().clone() {
                            clock.advance(1.0);
                        }
                        change.await?;
                    }
                    let key = served.lock().unwrap().clone();
                    Ok(json!({ "keys": [key] }))
                })
            })
        };
        let s = ok!(setup(SetupOptions {
            fetch_json: Some(fetch_json),
            ..SetupOptions::default()
        })
        .await);
        let f = &s.f;
        *served.lock().unwrap() = Some(Value::Object(s.rsa.public_jwk.clone()));
        *clock_slot.lock().unwrap() = Some(f.clock.clone());
        let target = json!({ "tenantId": f.tenant_id, "providerId": s.provider["id"] });
        let with = |extra: Value| {
            let mut input = target.clone();
            merge(&mut input, Some(extra));
            input
        };
        f.advance(1.0);
        ok!(api!(
            f.iam.api.oidc_providers,
            update,
            &f.owner_credential,
            with(
                json!({ "jwks": null, "jwksUri": jwks_uri, "audiences": [AUDIENCE, legacy_audience] })
            )
        ));
        let sessions = || async {
            f.find("sessions", json!({ "roleId": s.role["id"] }))
                .await
                .into_iter()
                .filter(|session| session.get("trustId") == Some(&s.trust["id"]))
                .collect::<Vec<Record>>()
        };
        let api: Arc<Api> = f.iam.api.clone();
        let owner: CredentialInput = f.owner_credential.clone();
        let provider_update = |input: Value| -> BoxFuture<'static, IamResult<Value>> {
            let (api, owner) = (api.clone(), owner.clone());
            Box::pin(async move { json(api.oidc_providers.update(&owner, body(input)).await) })
        };

        // A change that does not touch what the token was checked against issues as usual.
        *during.lock().unwrap() = Some(provider_update(with(json!({ "name": "CI" }))));
        let issued = ok!(s
            .exchange(&s.claims(json!({ "aud": legacy_audience })), json!({}))
            .await);
        assert!(during.lock().unwrap().is_none());
        same(
            &f.get("sessions", str_of(&issued["session"], "id"))
                .await
                .unwrap()["sessionTags"],
            &json!({ "repo": "acme/app" }),
        );

        // The provider drops the token's audience while its keys are being fetched.
        *during.lock().unwrap() = Some(provider_update(with(json!({ "audiences": [AUDIENCE] }))));
        refused(
            &fails!(
                s.exchange(&s.claims(json!({ "aud": legacy_audience })), json!({}))
                    .await
            ),
            "WEB_IDENTITY_REJECTED",
            None,
            None,
        );
        assert!(during.lock().unwrap().is_none());
        // The audience change also ended the session issued under the old audiences.
        assert!(sessions().await.is_empty());
        assert_eq!(
            f.get("oidcProviders", str_of(&s.provider, "id"))
                .await
                .unwrap()["sessionsRevokedBefore"],
            better_iam_server::js::number(f.now() + 1.0)
        );

        // The trust's conditions tighten while the keys are being fetched.
        let trust_update = {
            let (api, owner) = (api.clone(), owner.clone());
            let input = json!({
                "tenantId": f.tenant_id,
                "trustId": s.trust["id"],
                "conditions": { "StringEquals": { "token.sub": SUBJECT, "token.repository_owner": "other" } },
            });
            Box::pin(async move { json(api.trust.update(&owner, body(input)).await) })
                as BoxFuture<'static, IamResult<Value>>
        };
        *during.lock().unwrap() = Some(trust_update);
        refused(
            &fails!(s.exchange(&s.token(), json!({})).await),
            "WEB_IDENTITY_REJECTED",
            None,
            None,
        );
        assert!(during.lock().unwrap().is_none());

        assert!(sessions().await.is_empty());
        assert_eq!(f.find("webIdentityReplays", json!({})).await.len(), 1);
        same(
            &Value::Array(reasons(&s.exchange_audits().await)),
            &json!(["provider", "conditions"]),
        );
    });
}

#[test]
fn holds_the_allowed_issuers_pin_for_providers_registered_before_it_narrowed() {
    run(|| async {
        let s = ok!(setup(SetupOptions::default()).await);
        let f = &s.f;
        // The same database, restarted with a pin that no longer lists the provider's issuer.
        let mut options = base_options(f.database.clone(), &f.clock, None);
        options.sts = Some(sts(json!({
            "webIdentity": { "enabled": true, "allowedIssuers": ["https://gitlab.example.test"] },
        })));
        let narrowed = better_iam(options).expect("valid options");
        let target = json!({ "tenantId": f.tenant_id, "trustId": s.trust["id"] });
        let mut exchange = target.clone();
        merge(
            &mut exchange,
            Some(json!({ "webIdentityToken": s.token(), "sessionName": "ci-run" })),
        );
        refused(
            &fails!(json(
                narrowed
                    .api
                    .sts
                    .assume_role_with_web_identity(body(exchange))
                    .await
            )),
            "WEB_IDENTITY_REJECTED",
            None,
            None,
        );
        let mut evaluate = target.clone();
        merge(
            &mut evaluate,
            Some(json!({ "webIdentityToken": s.token() })),
        );
        same(
            &ok!(api!(
                narrowed.api.trust,
                evaluate_web_identity,
                &f.owner_credential,
                evaluate
            )),
            &json!({ "verified": false, "reason": "issuer" }),
        );
        let outcomes: Vec<Value> = s
            .exchange_audits()
            .await
            .iter()
            .map(|event| json!([event["outcome"], event["metadata"]["reason"]]))
            .collect();
        same(&Value::Array(outcomes), &json!([["deny", "issuer"]]));
        assert!(
            f.find("sessions", json!({ "trustId": s.trust["id"] }))
                .await
                .is_empty()
        );
        // The deployment that still admits the issuer keeps accepting its tokens.
        ok!(s.exchange(&s.token(), json!({})).await);
    });
}

#[test]
fn issues_session_jwts_that_carry_the_web_identity() {
    run(|| async {
        let signing = generate_test_key("EdDSA", "iam-1");
        let s = ok!(setup(SetupOptions {
            sts: Some(json!({ "jwt": { "signingKeys": [signing.private_jwk] } })),
            ..SetupOptions::default()
        })
        .await);
        let credential = ok!(s
            .exchange(
                &s.token(),
                json!({ "format": "jwt", "durationSeconds": 600 })
            )
            .await);
        assert_eq!(credential["format"], "jwt");
        let token = str_of(&credential, "token").to_owned();
        let (header, payload) = decode_test_jwt(&token);
        matches(
            &header,
            &json!({ "alg": "EdDSA", "kid": "iam-1", "typ": "biam-session+jwt" }),
        );
        matches(
            &payload,
            &json!({
                "sub": s.account["id"],
                "tid": s.f.tenant_id,
                "kind": "role",
                "mfa": false,
                "role": s.role["id"],
                "trust": s.trust["id"],
                "session_name": "ci-run",
                "source_identity": "octocat",
                "idp": s.provider["id"],
                "idp_sub": SUBJECT,
            }),
        );
        assert_eq!(
            payload["exp"].as_f64().unwrap(),
            payload["iat"].as_f64().unwrap() + 600.0
        );
        // Attribution only: no tags, policies, authority ids or hashes.
        let mut claims: Vec<&String> = payload.as_object().unwrap().keys().collect();
        claims.sort();
        assert_eq!(
            claims,
            [
                "aud",
                "auth_time",
                "exp",
                "iat",
                "idp",
                "idp_sub",
                "iss",
                "jti",
                "kind",
                "mfa",
                "nbf",
                "role",
                "session_name",
                "sid",
                "source_identity",
                "sub",
                "tid",
                "trust",
            ]
        );
        assert!(s.works(&token).await);
        assert!(ok!(s.allowed(&token, "documents:write").await));
        ok!(api!(
            s.f.iam.api.trust,
            revoke_sessions,
            &s.f.owner_credential,
            json!({ "tenantId": s.f.tenant_id, "trustId": s.trust["id"] })
        ));
        assert!(!s.works(&token).await);
    });
}

#[test]
fn need_sts_web_identity_enabled_to_be_created_evaluated_or_updated_but_not_revoked() {
    run(|| async {
        let f = ok!(organization_fixture(|_| {}).await);
        let conditions = json!({ "StringEquals": { "token.sub": SUBJECT } });
        let input = json!({
            "tenantId": f.tenant_id,
            "kind": "web-identity",
            "providerId": id(),
            "serviceAccountId": id(),
            "roleId": id(),
            "conditions": conditions,
        });
        refused(
            &fails!(api!(f.iam.api.trust, create, &f.owner_credential, input)),
            "FEATURE_DISABLED",
            Some(403),
            None,
        );
        refused(
            &fails!(json(
                f.iam
                    .api
                    .sts
                    .assume_role_with_web_identity(body(json!({
                        "tenantId": f.tenant_id,
                        "trustId": id(),
                        "webIdentityToken": "a.b.c",
                        "sessionName": "ci-run",
                    })))
                    .await
            )),
            "FEATURE_DISABLED",
            None,
            None,
        );
        // A web trust stored while the feature was on.
        let now = f.now();
        let seeded = json!({
            "id": id(),
            "tenantId": f.tenant_id,
            "kind": "web-identity",
            "sourceTenantId": f.tenant_id,
            "sourceIdentityId": id(),
            "roleId": id(),
            "requireMfa": false,
            "revoked": false,
            "providerId": id(),
            "conditions": conditions,
            "createdAt": now,
            "updatedAt": now,
        });
        f.insert("trusts", seeded.clone()).await;
        let target = json!({ "tenantId": f.tenant_id, "trustId": seeded["id"] });
        let mut evaluate = target.clone();
        evaluate["webIdentityToken"] = json!("a.b.c");
        refused(
            &fails!(api!(
                f.iam.api.trust,
                evaluate_web_identity,
                &f.owner_credential,
                evaluate
            )),
            "FEATURE_DISABLED",
            None,
            None,
        );
        let mut update = target.clone();
        update["description"] = json!("x");
        refused(
            &fails!(api!(f.iam.api.trust, update, &f.root_credential, update)),
            "FEATURE_DISABLED",
            None,
            None,
        );
        // Revoking only removes access, so it works with the feature off and deletes the trust's sessions: switching
        // the feature back on cannot revive them.
        let token_hash = format!("hash-{}", id());
        let session = json!({
            "id": id(),
            "tenantId": f.tenant_id,
            "identityId": seeded["sourceIdentityId"],
            "originalIdentityId": seeded["sourceIdentityId"],
            "roleId": seeded["roleId"],
            "trustId": seeded["id"],
            "kind": "role",
            "tokenHash": token_hash,
            "createdAt": now,
            "lastSeenAt": now,
            "authenticatedAt": now,
            "expiresAt": now + 900_000.0,
            "mfa": false,
            "webIdentity": { "providerId": seeded["providerId"], "issuer": ISSUER_IDP, "subject": SUBJECT },
            "uniqueKey": token_hash,
        });
        f.insert("sessions", session.clone()).await;
        matches(
            &ok!(api!(
                f.iam.api.trust,
                revoke,
                &f.root_credential,
                target.clone()
            )),
            &json!({ "id": seeded["id"], "revoked": true }),
        );
        assert_eq!(
            f.get("trusts", str_of(&seeded, "id")).await.unwrap()["revoked"],
            true
        );
        assert!(f.get("sessions", str_of(&session, "id")).await.is_none());
    });
}

#[test]
fn kill_switches_and_revocation_end_live_sessions() {
    run(|| async {
        let s = ok!(setup(SetupOptions::default()).await);
        let f = &s.f;
        let target = json!({ "tenantId": f.tenant_id, "providerId": s.provider["id"] });
        let with = |extra: Value| {
            let mut input = target.clone();
            merge(&mut input, Some(extra));
            input
        };

        // Disabling the provider ends its sessions for good: re-enabling it does not bring them back.
        let killed = ok!(s.exchange(&s.token(), json!({})).await);
        let disabled = ok!(api!(
            f.iam.api.oidc_providers,
            update,
            &f.owner_credential,
            with(json!({ "enabled": false }))
        ));
        assert_eq!(
            disabled["sessionsRevokedBefore"],
            better_iam_server::js::number(f.now() + 1.0)
        );
        assert!(
            f.get("sessions", str_of(&killed["session"], "id"))
                .await
                .is_none()
        );
        assert!(!s.works(str_of(&killed, "token")).await);
        refused(
            &fails!(s.exchange(&s.token(), json!({})).await),
            "WEB_IDENTITY_REJECTED",
            None,
            None,
        );
        ok!(api!(
            f.iam.api.oidc_providers,
            update,
            &f.owner_credential,
            with(json!({ "enabled": true }))
        ));
        assert!(!s.works(str_of(&killed, "token")).await);

        // oidcProviders.revokeSessions: watermark plus eager deletion.
        f.advance(1.0);
        let first = ok!(s.exchange(&s.token(), json!({})).await);
        assert!(s.works(str_of(&first, "token")).await);
        let revoked_by_provider = ok!(api!(
            f.iam.api.oidc_providers,
            revoke_sessions,
            &f.owner_credential,
            target.clone()
        ));
        same(
            &revoked_by_provider,
            &json!({ "providerId": s.provider["id"], "sessionsRevokedBefore": f.now() + 1.0, "revoked": 1 }),
        );
        assert!(
            f.get("sessions", str_of(&first["session"], "id"))
                .await
                .is_none()
        );
        assert!(!s.works(str_of(&first, "token")).await);
        let revocations = s.audits("role:sessions-revoked").await;
        assert_eq!(revocations.len(), 1);
        matches(
            &revocations[0],
            &json!({
                "resourceId": s.provider["id"],
                "metadata": { "sessionsRevokedBefore": f.now() + 1.0, "revoked": 1 },
            }),
        );

        // trust.revokeSessions.
        f.advance(1.0);
        let second = ok!(s.exchange(&s.token(), json!({})).await);
        assert!(s.works(str_of(&second, "token")).await);
        let revoked = ok!(api!(
            f.iam.api.trust,
            revoke_sessions,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "trustId": s.trust["id"] })
        ));
        assert_eq!(revoked["revoked"], 1);
        assert!(!s.works(str_of(&second, "token")).await);

        // Disabling the service account ends its sessions.
        f.advance(1.0);
        let third = ok!(s.exchange(&s.token(), json!({})).await);
        let account = json!({ "tenantId": f.tenant_id, "identityId": s.account["id"] });
        let status = |value: &str| {
            let mut input = account.clone();
            input["status"] = json!(value);
            input
        };
        ok!(api!(
            f.iam.api.service_accounts,
            set_status,
            &f.owner_credential,
            status("disabled")
        ));
        assert!(!s.works(str_of(&third, "token")).await);
        refused(
            &fails!(s.exchange(&s.token(), json!({})).await),
            "WEB_IDENTITY_REJECTED",
            None,
            None,
        );
        ok!(api!(
            f.iam.api.service_accounts,
            set_status,
            &f.owner_credential,
            status("active")
        ));

        // Revoking the trust deletes its sessions and refuses further exchanges.
        let fourth = ok!(s.exchange(&s.token(), json!({})).await);
        ok!(api!(
            f.iam.api.trust,
            revoke,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "trustId": s.trust["id"] })
        ));
        assert!(
            f.get("sessions", str_of(&fourth["session"], "id"))
                .await
                .is_none()
        );
        assert!(!s.works(str_of(&fourth, "token")).await);
        refused(
            &fails!(s.exchange(&s.token(), json!({})).await),
            "WEB_IDENTITY_REJECTED",
            None,
            None,
        );
    });
}

#[test]
fn refuses_the_service_accounts_own_api_key_on_the_classic_assume_role_path() {
    run(|| async {
        let s = ok!(setup(SetupOptions::default()).await);
        let f = &s.f;
        let assumer = ok!(api!(
            f.iam.api.roles,
            create,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "name": "Assumer", "permissions": ["iam:roles:assume"] })
        ));
        ok!(api!(
            f.iam.api.bindings,
            create,
            &f.owner_credential,
            json!({
                "tenantId": f.tenant_id,
                "roleId": assumer["id"],
                "subjectType": "identity",
                "subjectId": s.account["id"],
            })
        ));
        let key = ok!(api!(
            f.iam.api.credentials,
            create,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "identityId": s.account["id"] })
        ));
        let error = fails!(api!(
            f.iam.api.roles,
            assume,
            &bearer(str_of(&key, "token")),
            json!({ "tenantId": f.tenant_id, "trustId": s.trust["id"] })
        ));
        refused(
            &error,
            "ACCESS_DENIED",
            None,
            Some("Role trust does not permit assumption"),
        );
    });
}

#[test]
fn dry_runs_verification_conditions_and_mappings_without_redeeming_the_token() {
    run(|| async {
        let s = ok!(setup(SetupOptions::default()).await);
        let f = &s.f;
        let external = s.token();
        let (_, payload) = decode_test_jwt(&external);
        let evaluate = |credential: CredentialInput, trust_id: Value, token: String| {
            let f = &s.f;
            async move {
                api!(
                    f.iam.api.trust,
                    evaluate_web_identity,
                    &credential,
                    json!({ "tenantId": f.tenant_id, "trustId": trust_id, "webIdentityToken": token })
                )
            }
        };
        let owner = || f.owner_credential.clone();
        same(
            &ok!(evaluate(owner(), s.trust["id"].clone(), external.clone()).await),
            &json!({
                "verified": true,
                "claims": {
                    "iss": ISSUER_IDP,
                    "sub": SUBJECT,
                    "aud": AUDIENCE,
                    "iat": payload["iat"],
                    "exp": payload["exp"],
                    "jti": payload["jti"],
                },
                "conditions": { "matched": true, "failed": [] },
                "sessionTags": { "repo": "acme/app" },
                "sourceIdentity": "octocat",
            }),
        );
        // Not redeemed: the exchange still accepts it.
        assert!(f.find("webIdentityReplays", json!({})).await.is_empty());
        ok!(s.exchange(&external, json!({})).await);

        let trust_id = s.trust["id"].clone();
        matches(
            &ok!(evaluate(
                owner(),
                trust_id.clone(),
                s.claims(
                    json!({ "sub": "repo:acme/other:ref:refs/heads/main", "repository_owner": "x" })
                ),
            )
            .await),
            &json!({
                "verified": true,
                "reason": "conditions",
                "conditions": {
                    "matched": false,
                    "failed": ["StringEquals:token.sub", "StringEquals:token.repository_owner"],
                },
            }),
        );
        matches(
            &ok!(evaluate(
                owner(),
                trust_id.clone(),
                s.claims(json!({ "actor": null }))
            )
            .await),
            &json!({ "verified": true, "reason": "source-identity", "conditions": { "matched": true, "failed": [] } }),
        );
        same(
            &ok!(evaluate(
                owner(),
                trust_id.clone(),
                tamper_payload(&s.token(), json!({ "sub": "x" }))
            )
            .await),
            &json!({ "verified": false, "reason": "signature" }),
        );
        same(
            &ok!(evaluate(owner(), trust_id.clone(), "garbage".into()).await),
            &json!({ "verified": false, "reason": "malformed" }),
        );

        // Web trusts only; authorized before the trust is read.
        let identity_trust = ok!(api!(
            f.iam.api.trust,
            create,
            &f.root_credential,
            json!({
                "tenantId": f.tenant_id,
                "sourceTenantId": f.tenant_id,
                "sourceIdentityId": f.owner_id,
                "roleId": s.role["id"],
                "requireMfa": false,
            })
        ));
        refused(
            &fails!(evaluate(owner(), identity_trust["id"].clone(), external.clone()).await),
            "INVALID_INPUT",
            None,
            None,
        );
        ok!(f.member("alice").await);
        let alice = ok!(f.sign_in_credential("alice").await);
        for trust_id in [trust_id.clone(), json!(id())] {
            refused(
                &fails!(evaluate(alice.clone(), trust_id, external.clone()).await),
                "ACCESS_DENIED",
                None,
                None,
            );
        }
        refused(
            &fails!(evaluate(owner(), json!(id()), external.clone()).await),
            "NOT_FOUND",
            None,
            None,
        );
    });
}

#[test]
fn names_the_stored_state_that_would_refuse_the_exchange_which_the_exchange_never_reveals() {
    run(|| async {
        let s = ok!(setup(SetupOptions::default()).await);
        let f = &s.f;
        let target = json!({ "tenantId": f.tenant_id, "trustId": s.trust["id"] });
        let evaluate = |claims: Value| {
            let (s, target) = (&s, &target);
            async move {
                let mut input = target.clone();
                input["webIdentityToken"] = json!(s.claims(claims));
                api!(
                    s.f.iam.api.trust,
                    evaluate_web_identity,
                    &s.f.owner_credential,
                    input
                )
            }
        };
        // The evaluation's reason, and the public exchange's answer to a fresh token.
        let judged = || {
            let s = &s;
            async move {
                let evaluation = evaluate(json!({})).await?;
                assert_eq!(evaluation["verified"], true);
                let exchanged = match s.exchange(&s.token(), json!({})).await {
                    Ok(credential) => credential["session"]["trustId"].clone(),
                    Err(error) if error.code == "NOT_IMPLEMENTED" => return Err(error),
                    Err(error) => json!(error.code),
                };
                Ok::<Value, IamError>(json!([
                    evaluation.get("reason").cloned().unwrap_or(Value::Null),
                    exchanged
                ]))
            }
        };
        assert!(ok!(evaluate(json!({})).await).get("reason").is_none());

        // A disabled provider.
        let provider = json!({ "tenantId": f.tenant_id, "providerId": s.provider["id"] });
        let enabled = |value: bool| {
            let mut input = provider.clone();
            input["enabled"] = json!(value);
            input
        };
        ok!(api!(
            f.iam.api.oidc_providers,
            update,
            &f.owner_credential,
            enabled(false)
        ));
        same(
            &ok!(judged().await),
            &json!(["provider", "WEB_IDENTITY_REJECTED"]),
        );
        ok!(api!(
            f.iam.api.oidc_providers,
            update,
            &f.owner_credential,
            enabled(true)
        ));

        // An inactive, then an expired, service account; a token problem comes first, as in the exchange.
        let account = json!({ "tenantId": f.tenant_id, "identityId": s.account["id"] });
        let status = |value: &str| {
            let mut input = account.clone();
            input["status"] = json!(value);
            input
        };
        ok!(api!(
            f.iam.api.service_accounts,
            set_status,
            &f.owner_credential,
            status("disabled")
        ));
        same(
            &ok!(judged().await),
            &json!(["service-account", "WEB_IDENTITY_REJECTED"]),
        );
        assert_eq!(
            ok!(evaluate(json!({ "repository_owner": "other" })).await)["reason"],
            "conditions"
        );
        ok!(api!(
            f.iam.api.service_accounts,
            set_status,
            &f.owner_credential,
            status("active")
        ));
        let account_id = str_of(&s.account, "id").to_owned();
        f.patch(
            "identities",
            &account_id,
            vec![("expiresAt", Some(json!(f.now() - 1.0)))],
        )
        .await;
        same(
            &ok!(judged().await),
            &json!(["service-account", "WEB_IDENTITY_REJECTED"]),
        );
        f.patch("identities", &account_id, vec![("expiresAt", None)])
            .await;

        // A missing role.
        let role = f.get("roles", str_of(&s.role, "id")).await.unwrap();
        f.delete("roles", str_of(&s.role, "id")).await;
        same(
            &ok!(judged().await),
            &json!(["role", "WEB_IDENTITY_REJECTED"]),
        );
        f.insert("roles", value(&role)).await;

        // A revoked authority behind the trust, then behind the provider.
        let trust = f.get("trusts", str_of(&s.trust, "id")).await.unwrap();
        let trust_id = str_of(&s.trust, "id").to_owned();
        let provider_id = str_of(&s.provider, "id").to_owned();
        f.patch(
            "trusts",
            &trust_id,
            vec![("authorityId", Some(json!(id())))],
        )
        .await;
        same(
            &ok!(judged().await),
            &json!(["authority", "WEB_IDENTITY_REJECTED"]),
        );
        f.patch(
            "trusts",
            &trust_id,
            vec![("authorityId", trust.get("authorityId").cloned())],
        )
        .await;
        f.patch(
            "oidcProviders",
            &provider_id,
            vec![("authorityId", Some(json!(id())))],
        )
        .await;
        same(
            &ok!(judged().await),
            &json!(["authority", "WEB_IDENTITY_REJECTED"]),
        );
        f.patch(
            "oidcProviders",
            &provider_id,
            vec![("authorityId", s.provider.get("authorityId").cloned())],
        )
        .await;

        // Everything restored, the exchange works again; a revoked trust comes before any token problem.
        same(&ok!(judged().await), &json!([null, s.trust["id"]]));
        ok!(api!(
            f.iam.api.trust,
            revoke,
            &f.owner_credential,
            target.clone()
        ));
        same(
            &ok!(judged().await),
            &json!(["trust", "WEB_IDENTITY_REJECTED"]),
        );
        assert_eq!(
            ok!(evaluate(json!({ "repository_owner": "other" })).await)["reason"],
            "trust"
        );
        // The verified claims are still reported alongside the reason.
        matches(
            &ok!(evaluate(json!({})).await),
            &json!({ "verified": true, "claims": { "sub": SUBJECT } }),
        );
    });
}
