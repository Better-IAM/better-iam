//! The Shared Signals receiver (signal-receiver.ts) and the `signals` API group (api/signals.ts): ported from
//! tests/signals-receiver.test.ts.
//!
//! People come from the organization fixture (written as `identities.create` writes them): `identities.create` itself
//! ends in api/package-automation.ts `afterIdentityChange`, another unit's stub. The first case plays Acme's
//! transmitter with signed SETs instead of `createSharedSignalsTransmitter` (@better-iam/oauth, not ported); its
//! echo check belongs to the transmitter and is left out. The threat-detection case needs threat-engine.ts
//! `detectThreats` and the `threats` group, which are still stubs: it is ported and ignored until they land. The
//! deployment-option case checks the `pushPath` values; values of the wrong JSON type cannot be expressed through the
//! typed Rust options.

mod jwt_keys;
mod organization_fixture;

use std::sync::{Arc, Mutex};

use better_iam_auth::service::base::CreateIdentityInput;
use better_iam_core::{CredentialInput, Filter, IamStoreExt, Record};
use better_iam_server::options::{BetterIamOptions, DomainOptions, HttpResponse, SignalsOptions};
use bytes::Bytes;
use http::Method;
use jwt_keys::{Signer, TestKey, generate_test_key, sign_test_jwt, tamper_payload};
use organization_fixture::{ORIGIN, Org, assert_matches, body, fails, ok, organization, run};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CAEP: &str = "https://schemas.openid.net/secevent/caep/event-type/";
const RISC: &str = "https://schemas.openid.net/secevent/risc/event-type/";
const SSF: &str = "https://schemas.openid.net/secevent/ssf/event-type/";
const ISSUER: &str = "https://idp.example.test";
const AUDIENCE: &str = "https://rp.example.test/signals";
const FIXTURE_SECRET: &str = "organization-fixture-secret-with-32-characters";

fn uuid() -> String {
    better_iam_server::utils::id()
}

fn seconds(f: &Org) -> f64 {
    (f.now() / 1000.0).floor()
}

/// `{ ...base, ...patch }` where a `null` member of `patch` stands for `undefined` (left out).
fn merged(base: Value, patch: Value) -> Value {
    let mut out = base.as_object().cloned().unwrap_or_default();
    if let Value::Object(patch) = patch {
        for (key, value) in patch {
            if value.is_null() {
                out.shift_remove(&key);
            } else {
                out.insert(key, value);
            }
        }
    }
    Value::Object(out)
}

/// The `events` claim (one event) and, when given, the RFC 9493 `sub_id`.
fn event(kind: &str, claims: Value, subject: Option<Value>) -> Value {
    let mut out = Map::new();
    let mut events = Map::new();
    events.insert(kind.to_owned(), claims);
    out.insert("events".into(), Value::Object(events));
    if let Some(subject) = subject {
        out.insert("sub_id".into(), subject);
    }
    Value::Object(out)
}

/// A compact SET for ISSUER and AUDIENCE, issued now with a fresh jti unless `claims` says otherwise.
fn security_event(f: &Org, signer: Signer<'_>, claims: Value, header: Value) -> String {
    let payload = merged(
        json!({ "iss": ISSUER, "aud": AUDIENCE, "iat": seconds(f), "jti": uuid() }),
        claims,
    );
    // `null` header entries remove the member (sign_test_jwt reads them so).
    let mut merged_header = Map::new();
    merged_header.insert("typ".into(), json!("secevent+jwt"));
    if let Value::Object(header) = header {
        for (key, value) in header {
            merged_header.insert(key, value);
        }
    }
    sign_test_jwt(signer, &payload, Value::Object(merged_header))
}

async fn send(
    f: &Org,
    url: &str,
    method: Method,
    content_type: &str,
    token: Option<&str>,
    body: &str,
) -> HttpResponse {
    let mut request = http::Request::builder()
        .method(method.clone())
        .uri(url)
        .header("content-type", content_type)
        .header("accept", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let request = request
        .body(if method == Method::GET {
            Bytes::new()
        } else {
            Bytes::from(body.to_owned())
        })
        .unwrap();
    f.iam.handler(request).await
}

async fn post(f: &Org, url: &str, body: &str) -> HttpResponse {
    send(f, url, Method::POST, "application/secevent+jwt", None, body).await
}

fn json_of(response: &HttpResponse) -> Value {
    serde_json::from_slice(response.body()).unwrap_or(Value::Null)
}

fn header(response: &HttpResponse, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .map(|value| value.to_str().unwrap().to_owned())
}

/// A push source of Acme for ISSUER with static keys.
struct PushSource {
    key: TestKey,
    created: Value,
    source_id: String,
    push_url: String,
    push_token: Option<String>,
}

impl PushSource {
    fn sign(&self, f: &Org, claims: Value) -> String {
        security_event(f, Signer::Key(&self.key), claims, json!({}))
    }

    fn sign_with(&self, f: &Org, claims: Value, header: Value, signer: Signer<'_>) -> String {
        security_event(f, signer, claims, header)
    }

    async fn push(&self, f: &Org, body: &str) -> HttpResponse {
        send(
            f,
            &self.push_url,
            Method::POST,
            "application/secevent+jwt",
            self.push_token.as_deref(),
            body,
        )
        .await
    }
}

async fn owner_sign_in(f: &Org) -> CredentialInput {
    f.sign_in(&f.owner_id.clone()).await
}

async fn push_source(f: &Org, overrides: Value) -> PushSource {
    let key = generate_test_key("RS256", "idp-1");
    let input = merged(
        json!({
            "tenantId": f.tenant_id,
            "name": "Upstream IdP",
            "issuer": ISSUER,
            "audiences": [AUDIENCE],
            "jwks": { "keys": [key.public_jwk] },
            "delivery": "push",
        }),
        overrides,
    );
    let created = ok(f
        .iam
        .api
        .signals
        .create_source(&owner_sign_in(f).await, body(input))
        .await);
    PushSource {
        key,
        source_id: created["source"]["id"].as_str().unwrap().to_owned(),
        push_url: created["pushUrl"].as_str().unwrap_or_default().to_owned(),
        push_token: created["pushToken"].as_str().map(str::to_owned),
        created,
    }
}

/// A federation link as federation.ts writes it on sign-in: natural key `[connectionId, issuer, subject]`.
async fn link(
    f: &Org,
    tenant_id: &str,
    connection_id: &str,
    issuer: &str,
    subject: &str,
    identity_id: &str,
) {
    f.insert(
        "externalIdentities",
        json!({
            "id": uuid(),
            "tenantId": tenant_id,
            "uniqueKey": better_iam_core::js::stringify(&json!([connection_id, issuer, subject])),
            "identityId": identity_id,
            "providerId": connection_id,
            "issuer": issuer,
            "subject": subject,
        }),
    )
    .await;
}

/// A user provisioned through a SCIM connection, the IdP's user id as `externalId`.
async fn link_scim(f: &Org, connection_id: &str, identity_id: &str, external_id: &str) {
    f.insert(
        "scimUsers",
        json!({
            "id": uuid(),
            "tenantId": f.tenant_id,
            "connectionId": connection_id,
            "identityId": identity_id,
            "userName": format!("{external_id}@idp.example.test"),
            "externalId": external_id,
            "displayName": external_id,
            "active": true,
            "version": 1,
            "createdAt": f.now(),
            "updatedAt": f.now(),
        }),
    )
    .await;
}

/// A person with a given address (as `identities.create` writes one).
async fn person(f: &Org, tenant_id: &str, email: &str, name: &str) -> String {
    let auth = f.iam.auth.clone();
    let (tenant_id, email, name) = (tenant_id.to_owned(), email.to_owned(), name.to_owned());
    f.iam
        .store
        .transaction(|tx| async move {
            auth.create_identity(
                &tx,
                CreateIdentityInput {
                    tenant_id,
                    email,
                    name,
                    password: None,
                    owner: None,
                    root_admin: None,
                    email_verified: Some(true),
                },
            )
            .await
        })
        .await
        .expect("person")
        .id
}

/// A second organization ("Beta") with an active owner.
async fn second_organization(f: &Org) -> (String, String, CredentialInput) {
    f.activate(
        &f.root_tenant.clone(),
        "Beta",
        "organization",
        "owner@beta.test",
    )
    .await
}

async fn audit(f: &Org, tenant_id: &str, action: &str) -> Vec<Record> {
    let mut entries: Vec<Record> = f
        .find("audit", Filter::new().eq("tenantId", tenant_id.to_owned()))
        .await
        .into_iter()
        .filter(|entry| entry.get("action").and_then(Value::as_str) == Some(action))
        .collect();
    entries.sort_by(|a, b| {
        let sequence =
            |entry: &Record| entry.get("sequence").and_then(Value::as_f64).unwrap_or(0.0);
        sequence(a).partial_cmp(&sequence(b)).unwrap()
    });
    entries
}

fn metadata(entries: &[Record]) -> Vec<Value> {
    entries
        .iter()
        .map(|entry| entry.get("metadata").cloned().unwrap_or(Value::Null))
        .collect()
}

async fn list_events(f: &Org, filter: Value) -> Value {
    ok(f.iam
        .api
        .signals
        .list_events(
            &f.owner_credential,
            body(merged(json!({ "tenantId": f.tenant_id }), filter)),
        )
        .await)
}

async fn get_source(
    f: &Org,
    credential: &CredentialInput,
    tenant_id: &str,
    source_id: &str,
) -> Value {
    ok(f.iam
        .api
        .signals
        .get_source(
            credential,
            body(json!({ "tenantId": tenant_id, "sourceId": source_id })),
        )
        .await)
}

async fn get_event(f: &Org, event_id: &str) -> Value {
    ok(f.iam
        .api
        .signals
        .get_event(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "eventId": event_id })),
        )
        .await)
}

async fn session_ended(f: &Org, credential: &CredentialInput) -> bool {
    matches!(f.iam.auth.get_session(credential).await, Err(error) if error.status == 401)
}

fn number(value: &Value) -> f64 {
    value.as_f64().unwrap_or(f64::NAN)
}

/// One request a test HTTP server received.
#[derive(Debug, Clone)]
struct Received {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Received {
    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    }
}

type Handler = Arc<dyn Fn(&Received) -> (u16, Value) + Send + Sync>;

/// An HTTP server on 127.0.0.1 playing an upstream identity provider or an RFC 8936 poll endpoint.
async fn listen(handler: Handler) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let handler = handler.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16384];
                let mut read: Vec<u8> = Vec::new();
                let head_end = loop {
                    if let Some(index) = read.windows(4).position(|window| window == b"\r\n\r\n") {
                        break index + 4;
                    }
                    let Ok(count) = socket.read(&mut buffer).await else {
                        return;
                    };
                    if count == 0 {
                        return;
                    }
                    read.extend_from_slice(&buffer[..count]);
                };
                let head = String::from_utf8_lossy(&read[..head_end]).into_owned();
                let mut lines = head.split("\r\n");
                let request_line = lines.next().unwrap_or_default();
                let mut parts = request_line.split(' ');
                let method = parts.next().unwrap_or_default().to_owned();
                let path = parts.next().unwrap_or_default().to_owned();
                let headers: Vec<(String, String)> = lines
                    .filter_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        Some((name.trim().to_lowercase(), value.trim().to_owned()))
                    })
                    .collect();
                let length: usize = headers
                    .iter()
                    .find(|(name, _)| name == "content-length")
                    .and_then(|(_, value)| value.parse().ok())
                    .unwrap_or(0);
                while read.len() < head_end + length {
                    let Ok(count) = socket.read(&mut buffer).await else {
                        return;
                    };
                    if count == 0 {
                        break;
                    }
                    read.extend_from_slice(&buffer[..count]);
                }
                let end = (head_end + length).min(read.len());
                let received = Received {
                    method,
                    path,
                    headers,
                    body: String::from_utf8_lossy(&read[head_end..end]).into_owned(),
                };
                let (status, reply) = handler(&received);
                let text = better_iam_core::js::stringify(&reply);
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
                    text.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn insecure_localhost(options: &mut BetterIamOptions) {
    options.signals = Some(SignalsOptions {
        allow_insecure_localhost: Some(true),
        ..SignalsOptions::default()
    });
}

#[test]
fn receives_what_another_organizations_transmitter_sends_and_ends_the_matched_sessions() {
    run(|| async {
        let f = organization(insecure_localhost).await;
        let (beta_tenant, _, beta_owner) = second_organization(&f).await;
        const TRANSMITTER: &str = "https://id.acme.example.test/oidc";
        const BETA_AUDIENCE: &str = "https://beta.example.test/signals";
        let signing = generate_test_key("ES256", "acme-ssf");

        // Beta registers Acme's transmitter, mapping subjects through its Acme sign-in connection.
        let created = ok(f
            .iam
            .api
            .signals
            .create_source(
                &beta_owner,
                body(json!({
                    "tenantId": beta_tenant,
                    "name": "Acme identity provider",
                    "issuer": TRANSMITTER,
                    "audiences": [BETA_AUDIENCE],
                    "jwks": { "keys": [signing.public_jwk] },
                    "delivery": "push",
                    "subjects": { "connectionIds": ["acme-oidc"] },
                    "actions": { "session-revoked": "revoke-sessions" },
                })),
            )
            .await);
        let source_id = created["source"]["id"].as_str().unwrap().to_owned();
        let push_url = created["pushUrl"].as_str().unwrap().to_owned();
        assert_eq!(
            push_url,
            format!("http://localhost:3000/api/iam/signals/push/{source_id}")
        );
        let push_token = created["pushToken"].as_str().unwrap().to_owned();
        assert_eq!(push_token.len(), 43);
        assert!(
            push_token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        );
        // What Acme's transmitter pushes for Beta's stream.
        let transmit = |claims: Value| {
            let payload = merged(
                json!({ "iss": TRANSMITTER, "aud": BETA_AUDIENCE, "iat": seconds(&f), "jti": uuid() }),
                claims,
            );
            sign_test_jwt(
                Signer::Key(&signing),
                &payload,
                json!({ "typ": "secevent+jwt" }),
            )
        };

        // The stream's verification event is accepted and noted on the source.
        let verification = transmit(event(
            &format!("{SSF}verification"),
            json!({ "state": "hello" }),
            Some(json!({ "format": "opaque", "id": "stream-1" })),
        ));
        let answer = send(
            &f,
            &push_url,
            Method::POST,
            "application/secevent+jwt",
            Some(&push_token),
            &verification,
        )
        .await;
        assert_eq!(answer.status(), 202);
        assert_eq!(
            number(&get_source(&f, &beta_owner, &beta_tenant, &source_id).await["lastVerifiedAt"]),
            f.now()
        );
        f.advance(1000.0);

        // Alice works in both organizations; Beta's account is linked to Acme's through Beta's Acme connection.
        let alice_at_acme = f.member("alice").await;
        let alice_at_beta = person(&f, &beta_tenant, "alice@beta.test", "Alice").await;
        link(
            &f,
            &beta_tenant,
            "acme-oidc",
            TRANSMITTER,
            &alice_at_acme,
            &alice_at_beta,
        )
        .await;
        let beta_session = f.sign_in(&alice_at_beta).await;

        // An Acme administrator ends Alice's sessions: session-revoked reaches Beta.
        let revocation = transmit(merged(
            event(
                &format!("{CAEP}session-revoked"),
                json!({ "event_timestamp": seconds(&f), "initiating_entity": "admin" }),
                Some(json!({ "format": "iss_sub", "iss": TRANSMITTER, "sub": alice_at_acme })),
            ),
            json!({ "txn": uuid() }),
        ));
        let answer = send(
            &f,
            &push_url,
            Method::POST,
            "application/secevent+jwt",
            Some(&push_token),
            &revocation,
        )
        .await;
        assert_eq!(answer.status(), 202);
        assert!(session_ended(&f, &beta_session).await);

        let page = ok(f
            .iam
            .api
            .signals
            .list_events(&beta_owner, body(json!({ "tenantId": beta_tenant })))
            .await);
        assert_eq!(page["total"], json!(2));
        let kinds: Vec<(String, String)> = page["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                (
                    entry["eventType"].as_str().unwrap().to_owned(),
                    entry["status"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("session-revoked".to_owned(), "applied".to_owned()),
                ("verification".to_owned(), "recorded".to_owned()),
            ]
        );
        let revoked = page["events"][0].clone();
        assert_matches(
            &revoked,
            json!({
                "sourceId": source_id,
                "identityId": alice_at_beta,
                "subject": { "format": "iss_sub", "iss": TRANSMITTER, "sub": alice_at_acme },
                "claims": { "initiating_entity": "admin" },
            }),
        );
        assert!(revoked["txn"].is_string());
        let received: Vec<Record> = audit(&f, &beta_tenant, "signal:received")
            .await
            .into_iter()
            .filter(|entry| entry["metadata"]["eventType"] == json!("session-revoked"))
            .collect();
        assert_matches(
            &Value::Object(received[0].clone()),
            json!({
                "actorId": format!("signal:{source_id}"),
                "resourceId": alice_at_beta,
                "outcome": "allow",
                "metadata": {
                    "sourceId": source_id,
                    "eventType": "session-revoked",
                    "jti": revoked["jti"],
                    "status": "applied",
                    "identityId": alice_at_beta,
                },
            }),
        );
        assert_eq!(
            metadata(&audit(&f, &beta_tenant, "signal:revoke-sessions").await),
            vec![json!({
                "sourceId": source_id,
                "eventType": "session-revoked",
                "jti": revoked["jti"],
                "revoked": 1,
            })]
        );
        assert!(
            audit(&f, &beta_tenant, "identity:revoke-sessions")
                .await
                .is_empty()
        );
    });
}

#[test]
fn refuses_security_event_tokens_that_fail_verification_with_rfc_8935_answers() {
    run(|| async {
        let f = organization(|_| {}).await;
        let source = push_source(&f, json!({})).await;
        let disabled = event(
            &format!("{RISC}account-disabled"),
            json!({}),
            Some(json!({ "format": "opaque", "id": "someone" })),
        );
        let now = seconds(&f);
        async fn refused(answer: HttpResponse, status: u16, err: &str) {
            assert_eq!(answer.status(), status, "{:?}", json_of(&answer));
            assert_eq!(
                header(&answer, "cache-control").as_deref(),
                Some("no-store")
            );
            let json = json_of(&answer);
            assert_eq!(json["err"], json!(err), "{json}");
            assert!(json["description"].is_string());
            assert_eq!(json.as_object().unwrap().len(), 2);
        }
        let sign = |claims: Value| source.sign(&f, claims);
        // `{ ...disabled, ...claims }`, keeping `null` (undefined) members for `security_event` to leave out.
        let with = |claims: Value| {
            let mut out = disabled.as_object().cloned().unwrap_or_default();
            for (key, value) in claims.as_object().cloned().unwrap_or_default() {
                out.insert(key, value);
            }
            Value::Object(out)
        };

        // Addressed elsewhere, or from someone else.
        refused(
            source
                .push(
                    &f,
                    &sign(with(json!({ "aud": "https://another.example.test" }))),
                )
                .await,
            400,
            "invalid_audience",
        )
        .await;
        refused(
            source.push(&f, &sign(with(json!({ "aud": null })))).await,
            400,
            "invalid_audience",
        )
        .await;
        refused(
            source
                .push(
                    &f,
                    &sign(with(json!({ "iss": "https://evil.example.test" }))),
                )
                .await,
            400,
            "invalid_issuer",
        )
        .await;
        // Keys and algorithms: only the source's keys, only its algorithms, never keys named by the token.
        for signer in [
            generate_test_key("ES384", "idp-1"),
            generate_test_key("RS256", "idp-1"),
            generate_test_key("RS256", "idp-2"),
        ] {
            refused(
                source
                    .push(
                        &f,
                        &source.sign_with(&f, disabled.clone(), json!({}), Signer::Key(&signer)),
                    )
                    .await,
                400,
                "invalid_key",
            )
            .await;
        }
        refused(
            source
                .push(
                    &f,
                    &source.sign_with(
                        &f,
                        disabled.clone(),
                        json!({}),
                        Signer::Hs256(b"shared-secret"),
                    ),
                )
                .await,
            400,
            "invalid_key",
        )
        .await;
        refused(
            source
                .push(
                    &f,
                    &tamper_payload(&sign(disabled.clone()), json!({ "jti": "forged" })),
                )
                .await,
            400,
            "invalid_key",
        )
        .await;
        refused(
            source
                .push(
                    &f,
                    &source.sign_with(&f, disabled.clone(), json!({}), Signer::None),
                )
                .await,
            400,
            "invalid_request",
        )
        .await;
        for extra in [
            json!({ "jwk": source.key.public_jwk }),
            json!({ "jku": "https://idp.example.test/keys" }),
            json!({ "x5u": "https://idp.example.test/cert.pem" }),
            json!({ "x5c": ["MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"] }),
            json!({ "crit": ["exp"], "exp": now + 60.0 }),
            // The token type.
            json!({ "typ": "JWT" }),
            json!({ "typ": null }),
        ] {
            refused(
                source
                    .push(
                        &f,
                        &source.sign_with(&f, disabled.clone(), extra, Signer::Key(&source.key)),
                    )
                    .await,
                400,
                "invalid_request",
            )
            .await;
        }
        // Claims: no nonce (ID tokens), exactly one event, a readable subject, a sane age.
        for claims in [
            json!({ "nonce": "n-0S6_WzA2Mj" }),
            json!({ "events": {
                format!("{RISC}account-disabled"): {},
                format!("{RISC}account-purged"): {},
            } }),
            json!({ "events": {} }),
            json!({ "events": null }),
            json!({ "sub_id": { "format": "email", "email": "not-an-address" } }),
            json!({ "sub": "someone-else", "sub_id": { "format": "iss_sub", "iss": ISSUER, "sub": "someone" } }),
            json!({ "iat": now - 8.0 * 86_400.0 }),
            json!({ "iat": now + 600.0 }),
            json!({ "exp": now - 600.0 }),
            json!({ "nbf": now + 600.0 }),
        ] {
            refused(
                source.push(&f, &sign(with(claims))).await,
                400,
                "invalid_request",
            )
            .await;
        }
        refused(
            source
                .push(&f, &format!("{}.b.c", "a".repeat(17_000)))
                .await,
            400,
            "invalid_request",
        )
        .await;
        refused(source.push(&f, "not a token").await, 400, "invalid_request").await;

        // The transport: bearer token, media type, size, method, stream.
        let token = sign(disabled.clone());
        refused(
            send(
                &f,
                &source.push_url,
                Method::POST,
                "application/secevent+jwt",
                Some("not-the-token"),
                &token,
            )
            .await,
            401,
            "authentication_failed",
        )
        .await;
        let anonymous = send(
            &f,
            &source.push_url,
            Method::POST,
            "application/secevent+jwt",
            None,
            &token,
        )
        .await;
        assert_eq!(anonymous.status(), 401);
        assert_eq!(
            header(&anonymous, "www-authenticate").as_deref(),
            Some("Bearer")
        );
        for media in ["application/json", "application/jwt"] {
            refused(
                send(
                    &f,
                    &source.push_url,
                    Method::POST,
                    media,
                    source.push_token.as_deref(),
                    &token,
                )
                .await,
                415,
                "invalid_request",
            )
            .await;
        }
        refused(
            source.push(&f, &"x".repeat(70_000)).await,
            413,
            "invalid_request",
        )
        .await;
        refused(
            send(
                &f,
                &format!("http://localhost:3000/api/iam/signals/push/{}", uuid()),
                Method::POST,
                "application/secevent+jwt",
                source.push_token.as_deref(),
                &token,
            )
            .await,
            404,
            "invalid_request",
        )
        .await;
        let get = send(
            &f,
            &source.push_url,
            Method::GET,
            "application/secevent+jwt",
            source.push_token.as_deref(),
            "",
        )
        .await;
        assert_eq!(get.status(), 405);
        assert_eq!(header(&get, "allow").as_deref(), Some("POST"));

        // Nothing refused was recorded; the latest refusal is noted on the source.
        assert_eq!(list_events(&f, json!({})).await["total"], json!(0));
        let last_error = get_source(&f, &f.owner_credential, &f.tenant_id, &source.source_id).await
            ["lastError"]
            .clone();
        assert_eq!(number(&last_error["at"]), f.now());
        assert!(
            last_error["message"]
                .as_str()
                .unwrap()
                .starts_with("Refused an event: ")
        );
        assert_eq!(last_error.as_object().unwrap().len(), 2);

        // Accepted: an audience list naming this receiver, the issuer with a trailing slash, the media type spelling
        // of typ, a token days old (a transmitter's queue) or a little ahead of this clock.
        for set in [
            sign(with(
                json!({ "aud": ["https://another.example.test", AUDIENCE] }),
            )),
            sign(with(json!({ "iss": format!("{ISSUER}/") }))),
            source.sign_with(
                &f,
                disabled.clone(),
                json!({ "typ": "application/secevent+jwt" }),
                Signer::Key(&source.key),
            ),
            sign(with(json!({ "iat": now - 6.0 * 86_400.0 }))),
            sign(with(json!({ "iat": now + 120.0 }))),
        ] {
            let answer = source.push(&f, &set).await;
            assert_eq!(answer.status(), 202, "{:?}", json_of(&answer));
            assert_eq!(
                header(&answer, "cache-control").as_deref(),
                Some("no-store")
            );
            assert!(answer.body().is_empty());
        }
        // An event type the receiver does not know is kept, and ignored.
        let custom = sign(event(
            "https://example.test/event-type/custom",
            json!({ "detail": 1 }),
            None,
        ));
        assert_eq!(source.push(&f, &custom).await.status(), 202);
        let page = list_events(&f, json!({})).await;
        assert_eq!(page["total"], json!(6));
        let events = page["events"].as_array().unwrap();
        let unknown: Vec<&Value> = events
            .iter()
            .filter(|entry| entry["eventType"] == json!("unknown"))
            .collect();
        assert_eq!(unknown.len(), 1);
        assert_matches(
            unknown[0],
            json!({
                "status": "ignored",
                "reason": "unsupported-event",
                "eventUri": "https://example.test/event-type/custom",
                "claims": { "detail": 1 },
            }),
        );
        assert_eq!(unknown[0]["claims"], json!({ "detail": 1 }));
        assert!(
            events
                .iter()
                .filter(|entry| entry["eventType"] == json!("account-disabled"))
                .all(|entry| entry["status"] == json!("unmatched")
                    && entry["reason"] == json!("no-match"))
        );
    });
}

#[test]
fn tries_each_key_of_a_source_that_could_have_signed_a_token_without_a_kid() {
    run(|| async {
        let f = organization(|_| {}).await;
        let retired = generate_test_key("RS256", "retired");
        let current = generate_test_key("RS256", "current");
        let without_kid = |key: &TestKey| {
            let mut jwk = key.public_jwk.clone();
            jwk.shift_remove("kid");
            Value::Object(jwk)
        };
        let source = push_source(
            &f,
            json!({ "jwks": { "keys": [without_kid(&retired), without_kid(&current)] } }),
        )
        .await;
        let verification = event(
            &format!("{SSF}verification"),
            json!({ "state": "no-kid" }),
            None,
        );
        let no_kid = json!({ "kid": null });
        for signer in [&current, &retired] {
            let set = source.sign_with(
                &f,
                verification.clone(),
                no_kid.clone(),
                Signer::Key(signer),
            );
            assert_eq!(source.push(&f, &set).await.status(), 202);
        }
        let stranger = generate_test_key("RS256", "stranger");
        let answer = source
            .push(
                &f,
                &source.sign_with(
                    &f,
                    verification.clone(),
                    no_kid.clone(),
                    Signer::Key(&stranger),
                ),
            )
            .await;
        assert_eq!(answer.status(), 400);
        assert_eq!(json_of(&answer)["err"], json!("invalid_key"));
        assert_eq!(list_events(&f, json!({})).await["total"], json!(2));
    });
}

#[test]
fn ends_sessions_only_for_configured_event_types_once_per_event_never_for_a_protected_identity() {
    run(|| async {
        let f = organization(|_| {}).await;
        let source = push_source(
            &f,
            json!({
                "subjects": { "scimConnectionIds": ["okta-scim"] },
                "actions": { "session-revoked": "revoke-sessions", "credential-compromise": "record" },
            }),
        )
        .await;
        let source_id = source.source_id.clone();
        let alice = f.member("alice").await;
        link_scim(&f, "okta-scim", &alice, "00u-alice").await;
        let first = f.sign_in(&alice).await;
        let second = f.sign_in(&alice).await;
        let alice_subject = json!({ "format": "iss_sub", "iss": ISSUER, "sub": "00u-alice" });

        // Recorded only: the sessions stay.
        let compromise = source.sign(
            &f,
            event(
                &format!("{RISC}credential-compromise"),
                json!({ "credential_type": "password" }),
                Some(alice_subject.clone()),
            ),
        );
        assert_eq!(source.push(&f, &compromise).await.status(), 202);
        assert_eq!(
            f.iam.auth.get_session(&first).await.unwrap().identity.id,
            alice
        );

        let revocation = source.sign(
            &f,
            event(
                &format!("{CAEP}session-revoked"),
                json!({ "event_timestamp": seconds(&f), "initiating_entity": "policy" }),
                Some(alice_subject.clone()),
            ),
        );
        assert_eq!(source.push(&f, &revocation).await.status(), 202);
        for credential in [&first, &second] {
            assert!(session_ended(&f, credential).await);
        }
        let revoked = metadata(&audit(&f, &f.tenant_id, "signal:revoke-sessions").await);
        assert_eq!(revoked.len(), 1);
        assert_matches(
            &revoked[0],
            json!({ "sourceId": source_id, "eventType": "session-revoked", "revoked": 2 }),
        );
        assert!(revoked[0]["jti"].is_string());

        // The same event again (a transmitter retrying): accepted, nothing happens twice.
        let again = f.sign_in(&alice).await;
        assert_eq!(source.push(&f, &revocation).await.status(), 202);
        assert_eq!(
            f.iam.auth.get_session(&again).await.unwrap().identity.id,
            alice
        );
        assert_matches(
            &f.iam
                .signals
                .receive(&source_id, &revocation)
                .await
                .unwrap(),
            json!({ "duplicate": true, "status": "applied", "identityId": alice }),
        );
        assert_eq!(
            audit(&f, &f.tenant_id, "signal:revoke-sessions")
                .await
                .len(),
            1
        );
        assert_eq!(audit(&f, &f.tenant_id, "signal:received").await.len(), 2);
        let page = list_events(&f, json!({})).await;
        let mut statuses: Vec<String> = page["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["status"].as_str().unwrap().to_owned())
            .collect();
        statuses.sort();
        assert_eq!(statuses, vec!["applied", "recorded"]);
        let applied = page["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["status"] == json!("applied"))
            .unwrap()
            .clone();
        assert_matches(
            &applied,
            json!({
                "eventType": "session-revoked",
                "identityId": alice,
                "eventTimestamp": seconds(&f) * 1000.0,
                "claims": { "initiating_entity": "policy" },
            }),
        );

        // A root administrator is never signed out by an organization's source.
        let bob = f.member("bob").await;
        link_scim(&f, "okta-scim", &bob, "00u-bob").await;
        f.sign_in(&bob).await;
        let mut record = f.iam.store.get("identities", &bob).await.unwrap().unwrap();
        record.insert("rootAdmin".into(), Value::Bool(true));
        f.put("identities", record).await;
        let protected = f
            .iam
            .signals
            .receive(
                &source_id,
                &source.sign(
                    &f,
                    event(
                        &format!("{CAEP}session-revoked"),
                        json!({}),
                        Some(json!({ "format": "opaque", "id": "00u-bob" })),
                    ),
                ),
            )
            .await
            .unwrap();
        assert_matches(
            &protected,
            json!({ "status": "ignored", "identityId": bob, "duplicate": false }),
        );
        assert_matches(
            &get_event(&f, protected["eventId"].as_str().unwrap()).await,
            json!({ "status": "ignored", "reason": "protected" }),
        );
        assert_eq!(
            f.find("sessions", Filter::new().eq("identityId", bob.clone()))
                .await
                .len(),
            1
        );

        // An event about someone not mapped yet can be reprocessed once the mapping exists; the action runs then.
        let dan = f.member("dan").await;
        let dan_session = f.sign_in(&dan).await;
        let early = f
            .iam
            .signals
            .receive(
                &source_id,
                &source.sign(
                    &f,
                    event(
                        &format!("{CAEP}session-revoked"),
                        json!({}),
                        Some(json!({ "format": "opaque", "id": "00u-dan" })),
                    ),
                ),
            )
            .await
            .unwrap();
        assert_matches(&early, json!({ "status": "unmatched" }));
        link_scim(&f, "okta-scim", &dan, "00u-dan").await;
        let owner = owner_sign_in(&f).await;
        let reprocess = json!({ "tenantId": f.tenant_id, "eventId": early["eventId"] });
        assert_matches(
            &ok(f
                .iam
                .api
                .signals
                .reprocess(&owner, body(reprocess.clone()))
                .await),
            json!({ "status": "applied", "identityId": dan, "reprocessedBy": f.owner_id }),
        );
        assert!(session_ended(&f, &dan_session).await);
        let reprocessed = metadata(&audit(&f, &f.tenant_id, "signal:reprocess").await);
        assert_eq!(reprocessed.len(), 1);
        assert_matches(
            &reprocessed[0],
            json!({
                "sourceId": source_id,
                "eventType": "session-revoked",
                "previousStatus": "unmatched",
                "status": "applied",
                "identityId": dan,
            }),
        );
        assert_eq!(reprocessed[0].as_object().unwrap().len(), 6);
        // Threat detection sees it with the identity now.
        assert_eq!(
            audit(&f, &f.tenant_id, "signal:received")
                .await
                .iter()
                .filter(|entry| entry["metadata"]["identityId"] == json!(dan))
                .count(),
            1
        );
        let error = fails(f.iam.api.signals.reprocess(&owner, body(reprocess)).await);
        assert_eq!(error.code, "INVALID_TRANSITION");
    });
}

#[test]
fn accepts_legacy_risc_events_from_a_source_that_does_not_require_the_set_type() {
    run(|| async {
        let f = organization(|_| {}).await;
        let google = generate_test_key("RS256", "google-2026");
        const GOOGLE: &str = "https://accounts.google.com/";
        const CLIENT: &str = "1234-web.apps.googleusercontent.com";
        const PERSON: &str = "110169484474386276334";
        let owner = owner_sign_in(&f).await;
        let created = ok(f
            .iam
            .api
            .signals
            .create_source(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Google",
                    "issuer": GOOGLE,
                    "audiences": [CLIENT],
                    "jwks": { "keys": [google.public_jwk] },
                    "delivery": "push",
                    "pushToken": false,
                    "subjects": { "connectionIds": ["google"] },
                    "actions": { "sessions-revoked": "revoke-sessions" },
                })),
            )
            .await);
        assert_matches(
            &created["source"],
            json!({ "issuer": "https://accounts.google.com", "requireTyp": true, "hasPushToken": false }),
        );
        assert!(created.get("pushToken").is_none());
        let source_id = created["source"]["id"].as_str().unwrap().to_owned();
        let push_url = created["pushUrl"].as_str().unwrap().to_owned();
        let paula = f.member("paula").await;
        // Google ID tokens name the issuer without the trailing slash its RISC events use.
        link(
            &f,
            &f.tenant_id,
            "google",
            "https://accounts.google.com",
            PERSON,
            &paula,
        )
        .await;
        let session = f.sign_in(&paula).await;

        // Google's shape: no typ, OAuth client ids as audiences, the subject inside the event (`subject_type`).
        let risc = |kind: &str, claims: Value, header: Value| {
            sign_test_jwt(
                Signer::Key(&google),
                &json!({
                    "iss": GOOGLE,
                    "aud": [CLIENT, "5678-android.apps.googleusercontent.com"],
                    "iat": seconds(&f),
                    "jti": uuid(),
                    "events": { format!("{RISC}{kind}"): claims },
                }),
                header,
            )
        };
        let no_typ = json!({ "typ": null });
        let revoked = risc(
            "sessions-revoked",
            json!({ "subject": { "subject_type": "iss-sub", "iss": GOOGLE, "sub": PERSON } }),
            no_typ.clone(),
        );
        let strict = post(&f, &push_url, &revoked).await;
        assert_eq!(strict.status(), 400);
        assert_eq!(json_of(&strict)["err"], json!("invalid_request"));

        ok(f.iam
            .api
            .signals
            .update_source(
                &owner,
                body(
                    json!({ "tenantId": f.tenant_id, "sourceId": source_id, "requireTyp": false }),
                ),
            )
            .await);
        assert_eq!(post(&f, &push_url, &revoked).await.status(), 202);
        assert!(session_ended(&f, &session).await);
        let page = list_events(&f, json!({ "eventType": "sessions-revoked" })).await;
        let record = page["events"][0].clone();
        assert_matches(
            &record,
            json!({
                "status": "applied",
                "identityId": paula,
                "subject": { "format": "iss_sub", "iss": GOOGLE, "sub": PERSON },
            }),
        );
        assert_eq!(record["claims"], json!({}));

        // Google's verification event lives under the RISC namespace.
        let verification = risc(
            "verification",
            json!({ "state": "check-1" }),
            no_typ.clone(),
        );
        assert_eq!(post(&f, &push_url, &verification).await.status(), 202);
        assert_eq!(
            number(&get_source(&f, &owner, &f.tenant_id, &source_id).await["lastVerifiedAt"]),
            f.now()
        );
        // A plain JWT typ passes; other token types (an access token) never do.
        let plain = risc(
            "account-credential-change-required",
            json!({}),
            json!({ "typ": "JWT" }),
        );
        assert_eq!(post(&f, &push_url, &plain).await.status(), 202);
        let access = risc(
            "account-credential-change-required",
            json!({}),
            json!({ "typ": "at+jwt" }),
        );
        assert_eq!(post(&f, &push_url, &access).await.status(), 400);
    });
}

#[test]
fn maps_subjects_to_people_of_the_source_organization_only() {
    run(|| async {
        let txt: Arc<Mutex<std::collections::HashMap<String, Vec<Vec<String>>>>> = Arc::default();
        let zone = txt.clone();
        let f = organization(move |options| {
            options.domains = Some(DomainOptions {
                resolve_txt: Some(Arc::new(move |name| {
                    let records = zone.lock().unwrap().get(&name).cloned().unwrap_or_default();
                    Box::pin(async move { Ok(records) })
                })),
                ..DomainOptions::default()
            });
        })
        .await;
        let (beta_tenant, _, _) = second_organization(&f).await;
        let source = push_source(
            &f,
            json!({
                "issuer": format!("{ISSUER}/"),
                "subjects": {
                    "matchEmail": true,
                    "connectionIds": ["okta-oidc"],
                    "scimConnectionIds": ["okta-scim"],
                },
            }),
        )
        .await;
        let source_id = source.source_id.clone();
        let receive = |subject: Option<Value>| {
            let set = source.sign(
                &f,
                event(&format!("{RISC}account-disabled"), json!({}), subject),
            );
            let iam = &f.iam;
            let source_id = source_id.clone();
            async move { iam.signals.receive(&source_id, &set).await.unwrap() }
        };
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        let carol = f.member("carol").await;
        let dave = person(&f, &f.tenant_id, "dave@other.test", "Dave").await;

        // Email: only at a domain the organization proved it controls.
        assert_matches(
            &receive(Some(
                json!({ "format": "email", "email": "alice@acme.test" }),
            ))
            .await,
            json!({ "status": "unmatched" }),
        );
        let claim = ok(f
            .iam
            .api
            .domains
            .add(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "domain": "acme.test" })),
            )
            .await);
        txt.lock().unwrap().insert(
            claim["dnsRecord"]["name"].as_str().unwrap().to_owned(),
            vec![vec![
                claim["dnsRecord"]["value"].as_str().unwrap().to_owned(),
            ]],
        );
        assert_matches(
            &ok(f
                .iam
                .api
                .domains
                .verify(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "domainId": claim["id"] })),
                )
                .await),
            json!({ "verified": true }),
        );
        assert_matches(
            &receive(Some(
                json!({ "format": "email", "email": "Alice@ACME.test" }),
            ))
            .await,
            json!({ "status": "recorded", "identityId": alice }),
        );
        assert_matches(
            &receive(Some(
                json!({ "format": "account", "uri": "acct:alice@acme.test" }),
            ))
            .await,
            json!({ "identityId": alice }),
        );
        assert_matches(
            &receive(Some(
                json!({ "format": "email", "email": "dave@other.test" }),
            ))
            .await,
            json!({ "status": "unmatched" }),
        );
        // Someone of another organization with an address at the domain is never matched.
        person(&f, &beta_tenant, "erin@acme.test", "Erin").await;
        assert_matches(
            &receive(Some(
                json!({ "format": "email", "email": "erin@acme.test" }),
            ))
            .await,
            json!({ "status": "unmatched" }),
        );

        // iss_sub: a federation link of a configured connection, for the source's issuer in either spelling.
        link(&f, &f.tenant_id, "okta-oidc", ISSUER, "00u-bob", &bob).await;
        for iss in [ISSUER.to_owned(), format!("{ISSUER}/")] {
            assert_matches(
                &receive(Some(
                    json!({ "format": "iss_sub", "iss": iss, "sub": "00u-bob" }),
                ))
                .await,
                json!({ "status": "recorded", "identityId": bob }),
            );
        }
        // Not another issuer's subject, not a link of a connection the source does not name, not another
        // organization's link.
        link(
            &f,
            &f.tenant_id,
            "okta-oidc",
            "https://other-idp.example.test",
            "00u-bob",
            &bob,
        )
        .await;
        assert_matches(
            &receive(Some(json!({
                "format": "iss_sub", "iss": "https://other-idp.example.test", "sub": "00u-bob",
            })))
            .await,
            json!({ "status": "unmatched" }),
        );
        link(&f, &f.tenant_id, "saml-partner", ISSUER, "00u-dave", &dave).await;
        assert_matches(
            &receive(Some(
                json!({ "format": "iss_sub", "iss": ISSUER, "sub": "00u-dave" }),
            ))
            .await,
            json!({ "status": "unmatched" }),
        );
        let frank = person(&f, &beta_tenant, "frank@beta.test", "Frank").await;
        link(&f, &beta_tenant, "okta-oidc", ISSUER, "00u-frank", &frank).await;
        assert_matches(
            &receive(Some(
                json!({ "format": "iss_sub", "iss": ISSUER, "sub": "00u-frank" }),
            ))
            .await,
            json!({ "status": "unmatched" }),
        );

        // SCIM externalId: as iss_sub, opaque, a complex subject's user, or one alias among others.
        link_scim(&f, "okta-scim", &carol, "00u-carol").await;
        for subject in [
            json!({ "format": "iss_sub", "iss": ISSUER, "sub": "00u-carol" }),
            json!({ "format": "opaque", "id": "00u-carol" }),
            json!({
                "format": "complex",
                "user": { "format": "opaque", "id": "00u-carol" },
                "session": { "format": "opaque", "id": "sid-1" },
            }),
            json!({
                "format": "aliases",
                "identifiers": [
                    { "format": "phone_number", "phone_number": "+15555550100" },
                    { "format": "opaque", "id": "00u-carol" },
                ],
            }),
        ] {
            assert_matches(
                &receive(Some(subject)).await,
                json!({ "status": "recorded", "identityId": carol }),
            );
        }
        link_scim(&f, "other-scim", &dave, "00u-dave-2").await;
        assert_matches(
            &receive(Some(json!({ "format": "opaque", "id": "00u-dave-2" }))).await,
            json!({ "status": "unmatched" }),
        );
        // Subjects that name no person, and no subject at all.
        assert_matches(
            &receive(Some(
                json!({ "format": "complex", "session": { "format": "opaque", "id": "sid-1" } }),
            ))
            .await,
            json!({ "status": "unmatched" }),
        );
        let anonymous = receive(None).await;
        assert_matches(
            &get_event(&f, anonymous["eventId"].as_str().unwrap()).await,
            json!({ "status": "unmatched", "reason": "no-subject" }),
        );

        // Turning email matching off stops email matches; the rest of the mapping stays.
        ok(f.iam
            .api
            .signals
            .update_source(
                &owner_sign_in(&f).await,
                body(json!({
                    "tenantId": f.tenant_id,
                    "sourceId": source_id,
                    "subjects": { "matchEmail": false },
                })),
            )
            .await);
        assert_matches(
            &receive(Some(
                json!({ "format": "email", "email": "alice@acme.test" }),
            ))
            .await,
            json!({ "status": "unmatched" }),
        );
        assert_matches(
            &receive(Some(json!({ "format": "opaque", "id": "00u-carol" }))).await,
            json!({ "identityId": carol }),
        );
        assert_eq!(
            list_events(&f, json!({ "identityId": carol })).await["total"],
            json!(5)
        );
    });
}

#[test]
fn audits_every_received_event_as_signal_received_with_what_threat_detection_needs() {
    run(|| async {
        let f = organization(|_| {}).await;
        let source = push_source(
            &f,
            json!({ "subjects": { "scimConnectionIds": ["okta-scim"] } }),
        )
        .await;
        let source_id = source.source_id.clone();
        let alice = f.member("alice").await;
        link_scim(&f, "okta-scim", &alice, "00u-alice").await;
        let subject = json!({ "format": "opaque", "id": "00u-alice" });
        let receive = |kind: String, claims: Value, about: Value| {
            let set = source.sign(&f, event(&kind, claims, Some(about)));
            let iam = &f.iam;
            let source_id = source_id.clone();
            async move { iam.signals.receive(&source_id, &set).await.unwrap() }
        };
        let compromise = receive(
            format!("{RISC}credential-compromise"),
            json!({
                "credential_type": "password",
                "reason_admin": { "de": "In einem Datenleck gefunden", "en": "Found in a breach corpus" },
                "reason_user": { "en": "Your password appeared in a breach" },
            }),
            subject.clone(),
        )
        .await;
        receive(
            format!("{CAEP}risk-level-change"),
            json!({
                "current_level": "high",
                "previous_level": "low",
                "risk_reason": "PASSWORD_FOUND_IN_DATA_BREACH",
                "principal": "USER",
            }),
            subject.clone(),
        )
        .await;
        receive(
            format!("{RISC}account-disabled"),
            json!({ "reason": "hijacking", "reason_admin": "x".repeat(300) }),
            json!({ "format": "opaque", "id": "nobody" }),
        )
        .await;
        let trail = audit(&f, &f.tenant_id, "signal:received").await;
        assert_eq!(trail.len(), 3);
        let about = |kind: &str| {
            Value::Object(
                trail
                    .iter()
                    .find(|entry| entry["metadata"]["eventType"] == json!(kind))
                    .unwrap()
                    .clone(),
            )
        };
        let jti = get_event(&f, compromise["eventId"].as_str().unwrap()).await["jti"].clone();
        assert_matches(
            &about("credential-compromise"),
            json!({ "actorId": format!("signal:{source_id}"), "resourceId": alice, "outcome": "allow" }),
        );
        assert_eq!(
            about("credential-compromise")["metadata"],
            json!({
                "sourceId": source_id,
                "eventType": "credential-compromise",
                "jti": jti,
                "status": "recorded",
                "identityId": alice,
                "reasonAdmin": "Found in a breach corpus",
                "credentialType": "password",
            })
        );
        let risk = about("risk-level-change")["metadata"].clone();
        assert!(risk["jti"].is_string());
        assert_eq!(
            risk,
            json!({
                "sourceId": source_id,
                "eventType": "risk-level-change",
                "jti": risk["jti"],
                "status": "recorded",
                "identityId": alice,
                "currentLevel": "HIGH",
            })
        );
        let unmatched = about("account-disabled");
        assert_eq!(
            unmatched["resourceId"],
            json!(format!("signals/sources/{source_id}"))
        );
        assert_eq!(
            unmatched["metadata"],
            json!({
                "sourceId": source_id,
                "eventType": "account-disabled",
                "jti": unmatched["metadata"]["jti"],
                "status": "unmatched",
                "reasonAdmin": "x".repeat(256),
            })
        );
    });
}

#[test]
fn discovers_a_sources_keys_and_answers_503_while_they_cannot_be_fetched() {
    run(|| async {
        let f = organization(insecure_localhost).await;
        let key = generate_test_key("EdDSA", "edge-1");
        let idp = Arc::new(Mutex::new((500u16, 0u32)));
        let base_slot: Arc<Mutex<String>> = Arc::default();
        let (state, slot, public) = (idp.clone(), base_slot.clone(), key.public_jwk.clone());
        let base = listen(Arc::new(move |request: &Received| {
            let base = slot.lock().unwrap().clone();
            match request.path.as_str() {
                "/.well-known/ssf-configuration/tenant" => {
                    state.lock().unwrap().1 += 1;
                    (
                        200,
                        json!({
                            "spec_version": "1_0",
                            "issuer": format!("{base}/tenant"),
                            "jwks_uri": format!("{base}/keys"),
                            "delivery_methods_supported": ["urn:ietf:rfc:8935"],
                        }),
                    )
                }
                "/.well-known/ssf-configuration/impostor" => (
                    200,
                    json!({ "issuer": "https://someone-else.example.test", "jwks_uri": format!("{base}/keys") }),
                ),
                "/keys" => {
                    let status = state.lock().unwrap().0;
                    if status == 200 {
                        (200, json!({ "keys": [public] }))
                    } else {
                        (status, json!({ "error": "unavailable" }))
                    }
                }
                _ => (404, json!({})),
            }
        }))
        .await;
        *base_slot.lock().unwrap() = base.clone();
        let owner = owner_sign_in(&f).await;
        let create = |path: &str| {
            let input = json!({
                "tenantId": f.tenant_id,
                "name": path,
                "issuer": format!("{base}/{path}"),
                "audiences": ["rp"],
                "delivery": "push",
                "pushToken": false,
            });
            let (iam, owner) = (&f.iam, owner.clone());
            async move { ok(iam.api.signals.create_source(&owner, body(input)).await) }
        };
        let verification = |issuer: String, signer: &TestKey| {
            sign_test_jwt(
                Signer::Key(signer),
                &merged(
                    json!({ "iss": issuer, "aud": "rp", "iat": seconds(&f), "jti": uuid() }),
                    event(&format!("{SSF}verification"), json!({}), None),
                ),
                json!({ "typ": "secevent+jwt" }),
            )
        };
        let tenant = create("tenant").await;
        let tenant_url = tenant["pushUrl"].as_str().unwrap().to_owned();

        // The key set answers 500: a temporary refusal, so the transmitter delivers again.
        let unavailable = post(
            &f,
            &tenant_url,
            &verification(format!("{base}/tenant"), &key),
        )
        .await;
        assert_eq!(unavailable.status(), 503);
        assert_eq!(header(&unavailable, "retry-after").as_deref(), Some("30"));
        assert_eq!(json_of(&unavailable)["err"], json!("invalid_key"));
        // Once it answers: accepted; the discovery document was read once.
        idp.lock().unwrap().0 = 200;
        for _ in 0..2 {
            let answer = post(
                &f,
                &tenant_url,
                &verification(format!("{base}/tenant"), &key),
            )
            .await;
            assert_eq!(answer.status(), 202, "{:?}", json_of(&answer));
        }
        assert_eq!(idp.lock().unwrap().1, 1);
        // A key the fetched set does not have yet (a transmitter that just rotated) is retried later too.
        let rotated_key = generate_test_key("EdDSA", "edge-2");
        let rotated = post(
            &f,
            &tenant_url,
            &verification(format!("{base}/tenant"), &rotated_key),
        )
        .await;
        assert_eq!(rotated.status(), 503);
        assert_eq!(json_of(&rotated)["err"], json!("invalid_key"));

        // A discovery document naming another issuer is not trusted.
        let impostor = create("impostor").await;
        let answer = post(
            &f,
            impostor["pushUrl"].as_str().unwrap(),
            &verification(format!("{base}/impostor"), &key),
        )
        .await;
        assert_eq!(answer.status(), 503);
        let source = get_source(
            &f,
            &owner,
            &f.tenant_id,
            impostor["source"]["id"].as_str().unwrap(),
        )
        .await;
        assert!(
            source["lastError"]["message"]
                .as_str()
                .unwrap()
                .contains("could not be obtained")
        );

        // Key URLs on private addresses are refused at registration (only loopback is allowed here).
        for jwks_uri in [
            "https://10.0.0.8/keys",
            "https://169.254.169.254/latest/keys",
        ] {
            let error = fails(
                f.iam
                    .api
                    .signals
                    .create_source(
                        &owner,
                        body(json!({
                            "tenantId": f.tenant_id,
                            "name": "Internal",
                            "issuer": "https://internal.example.test",
                            "audiences": ["rp"],
                            "jwksUri": jwks_uri,
                            "delivery": "push",
                        })),
                    )
                    .await,
            );
            assert_eq!(error.code, "INVALID_INPUT");
        }
        let missing = f.iam.signals.receive(&uuid(), "x.y.z").await.unwrap_err();
        assert_eq!(missing.code, "NOT_FOUND");
    });
}

#[test]
fn polls_an_rfc_8936_transmitter_acknowledging_committed_events_with_the_next_request() {
    run(|| async {
        let f = organization(insecure_localhost).await;
        let key = generate_test_key("ES256", "poll-1");
        let requests: Arc<Mutex<Vec<Received>>> = Arc::default();
        let replies: Arc<Mutex<std::collections::VecDeque<(u16, Value)>>> = Arc::default();
        let (seen, queue) = (requests.clone(), replies.clone());
        let base = listen(Arc::new(move |request: &Received| {
            if request.path != "/poll" || request.method != "POST" {
                return (404, json!({}));
            }
            seen.lock().unwrap().push(request.clone());
            queue
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or((200, json!({ "sets": {}, "moreAvailable": false })))
        }))
        .await;
        let polled = |jti: &str| {
            security_event(
                &f,
                Signer::Key(&key),
                merged(
                    json!({ "jti": jti }),
                    event(
                        &format!("{RISC}account-disabled"),
                        json!({}),
                        Some(json!({ "format": "opaque", "id": "nobody" })),
                    ),
                ),
                json!({}),
            )
        };
        let body_of = |index: usize| -> Value {
            serde_json::from_str(&requests.lock().unwrap()[index].body).unwrap()
        };
        let owner = owner_sign_in(&f).await;
        let created = ok(f
            .iam
            .api
            .signals
            .create_source(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Poller",
                    "issuer": ISSUER,
                    "audiences": [AUDIENCE],
                    "jwks": { "keys": [key.public_jwk] },
                    "delivery": "poll",
                    "poll": { "endpoint": format!("{base}/poll"), "token": "poll-secret-token", "maxEvents": 10 },
                })),
            )
            .await);
        let source_id = created["source"]["id"].as_str().unwrap().to_owned();
        assert!(created.get("pushUrl").is_none());
        assert!(created.get("pushToken").is_none());
        assert_eq!(
            created["source"]["poll"],
            json!({ "endpoint": format!("{base}/poll"), "maxEvents": 10, "pendingAcks": 0 })
        );
        // The poll token is stored sealed and never shown.
        assert!(!created.to_string().contains("poll-secret-token"));
        let stored = f
            .iam
            .store
            .get("signalSources", &source_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !Value::Object(stored)
                .to_string()
                .contains("poll-secret-token")
        );
        // A poll source takes no pushes.
        let pushed = post(
            &f,
            &format!("http://localhost:3000/api/iam/signals/push/{source_id}"),
            &polled("pushed"),
        )
        .await;
        assert_eq!(pushed.status(), 404);
        let poll_result = |sources: u32, received: u32, acknowledged: u32, errors: u32| json!({ "sources": sources, "received": received, "acknowledged": acknowledged, "errors": errors });
        let run_poll = |input: Option<Value>| {
            let signals = &f.iam.signals;
            async move { signals.poll(input.as_ref()).await.unwrap().to_value() }
        };

        // One run: two requests (moreAvailable), the second acknowledging what the first returned.
        replies.lock().unwrap().extend([
            (
                200,
                json!({ "sets": { "a": polled("a"), "b": polled("b") }, "moreAvailable": true }),
            ),
            (
                200,
                json!({ "sets": { "c": polled("c"), "bad": "x.y.z", "mismatched": polled("other") } }),
            ),
        ]);
        assert_eq!(run_poll(None).await, poll_result(1, 3, 2, 0));
        {
            let first = requests.lock().unwrap()[0].clone();
            assert_eq!(
                first.header("authorization").as_deref(),
                Some("Bearer poll-secret-token")
            );
            assert_eq!(
                first.header("content-type").as_deref(),
                Some("application/json")
            );
        }
        assert_eq!(
            body_of(0),
            json!({ "maxEvents": 10, "returnImmediately": true, "ack": [] })
        );
        assert_eq!(
            body_of(1),
            json!({ "maxEvents": 10, "returnImmediately": true, "ack": ["a", "b"] })
        );
        let source = get_source(&f, &f.owner_credential, &f.tenant_id, &source_id).await;
        assert_matches(
            &source["poll"],
            json!({ "pendingAcks": 1, "lastPolledAt": f.now() }),
        );

        // The transmitter fails: acknowledgements and errors wait for the next run.
        let check_set_errs = |body: &Value| {
            let errors = body["setErrs"].as_object().unwrap();
            assert_eq!(errors.len(), 2);
            for name in ["bad", "mismatched"] {
                assert_eq!(errors[name]["err"], json!("invalid_request"));
                assert!(errors[name]["description"].is_string());
            }
        };
        replies.lock().unwrap().push_back((500, json!({})));
        let polled_now = ok(f
            .iam
            .api
            .signals
            .poll(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "sourceId": source_id })),
            )
            .await);
        assert_eq!(polled_now, poll_result(1, 0, 0, 1));
        let third = body_of(2);
        assert_matches(
            &third,
            json!({ "maxEvents": 10, "returnImmediately": true, "ack": ["c"] }),
        );
        check_set_errs(&third);
        assert_matches(
            &get_source(&f, &f.owner_credential, &f.tenant_id, &source_id).await,
            json!({
                "lastError": { "message": "The poll endpoint answered 500" },
                "poll": { "pendingAcks": 1 },
            }),
        );

        // A redelivered event is acknowledged again but recorded once.
        replies.lock().unwrap().push_back((
            200,
            json!({ "sets": { "a": polled("a") }, "moreAvailable": false }),
        ));
        assert_eq!(
            run_poll(Some(json!({ "sourceId": source_id }))).await,
            poll_result(1, 0, 1, 0)
        );
        let fourth = body_of(3);
        assert_eq!(third, fourth);

        // More than a run's worth: at most five requests per source per run.
        for index in 0..8 {
            let jti = format!("e{index}");
            replies.lock().unwrap().push_back((
                200,
                json!({ "sets": { jti.clone(): polled(&jti) }, "moreAvailable": true }),
            ));
        }
        let before = requests.lock().unwrap().len();
        assert_eq!(run_poll(None).await, poll_result(1, 5, 5, 0));
        let after = requests.lock().unwrap().len();
        assert_eq!(after - before, 5);
        assert_eq!(body_of(before)["ack"], json!(["a"]));
        assert_eq!(body_of(after - 1)["ack"], json!(["e3"]));
        assert_eq!(
            list_events(&f, json!({ "sourceId": source_id })).await["total"],
            json!(8)
        );
        replies.lock().unwrap().clear();

        // Disabled sources are not polled; push sources cannot be.
        ok(f.iam
            .api
            .signals
            .update_source(
                &owner,
                body(
                    json!({ "tenantId": f.tenant_id, "sourceId": source_id, "status": "disabled" }),
                ),
            )
            .await);
        assert_eq!(run_poll(None).await, poll_result(0, 0, 0, 0));
        let error = fails(
            f.iam
                .api
                .signals
                .poll(
                    &owner,
                    body(json!({ "tenantId": f.tenant_id, "sourceId": source_id })),
                )
                .await,
        );
        assert_eq!(error.code, "INVALID_TRANSITION");
        let push = ok(f
            .iam
            .api
            .signals
            .create_source(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Pusher",
                    "issuer": "https://push.example.test",
                    "audiences": [AUDIENCE],
                    "jwks": { "keys": [key.public_jwk] },
                    "delivery": "push",
                })),
            )
            .await);
        let error = fails(
            f.iam
                .api
                .signals
                .poll(
                    &owner,
                    body(json!({ "tenantId": f.tenant_id, "sourceId": push["source"]["id"] })),
                )
                .await,
        );
        assert_eq!(error.code, "INVALID_INPUT");
        // A new poll endpoint needs its token again.
        let error = fails(
            f.iam
                .api
                .signals
                .update_source(
                    &owner,
                    body(json!({
                        "tenantId": f.tenant_id,
                        "sourceId": source_id,
                        "poll": { "endpoint": format!("{base}/poll/v2") },
                    })),
                )
                .await,
        );
        assert_eq!(error.code, "INVALID_INPUT");
        assert_matches(
            &ok(f
                .iam
                .api
                .signals
                .update_source(
                    &owner,
                    body(json!({
                        "tenantId": f.tenant_id,
                        "sourceId": source_id,
                        "poll": { "endpoint": format!("{base}/poll/v2"), "token": "another-token" },
                    })),
                )
                .await),
            json!({ "poll": { "endpoint": format!("{base}/poll/v2"), "pendingAcks": 0 } }),
        );
    });
}

#[test]
fn leaves_polled_events_unacknowledged_while_the_sources_keys_cannot_be_fetched() {
    run(|| async {
        let f = organization(insecure_localhost).await;
        let key = generate_test_key("PS256", "poll-2");
        let idp = Arc::new(Mutex::new(503u16));
        let acks: Arc<Mutex<Vec<Value>>> = Arc::default();
        let set = security_event(
            &f,
            Signer::Key(&key),
            merged(
                json!({ "jti": "k1" }),
                event(&format!("{RISC}account-enabled"), json!({}), None),
            ),
            json!({}),
        );
        let (state, log, public, polled_set) = (
            idp.clone(),
            acks.clone(),
            key.public_jwk.clone(),
            set.clone(),
        );
        let base = listen(Arc::new(move |request: &Received| {
            if request.path == "/keys" {
                let status = *state.lock().unwrap();
                return if status == 200 {
                    (200, json!({ "keys": [public] }))
                } else {
                    (status, json!({}))
                };
            }
            let body: Value = serde_json::from_str(&request.body).unwrap();
            log.lock()
                .unwrap()
                .push(json!({ "ack": body["ack"], "setErrs": body.get("setErrs") }));
            // Unacknowledged events come back until acknowledged.
            let acknowledged = body["ack"]
                .as_array()
                .unwrap()
                .iter()
                .any(|jti| jti == "k1");
            (
                200,
                if acknowledged {
                    json!({ "sets": {} })
                } else {
                    json!({ "sets": { "k1": polled_set } })
                },
            )
        }))
        .await;
        let created = ok(f
            .iam
            .api
            .signals
            .create_source(
                &owner_sign_in(&f).await,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Poller",
                    "issuer": ISSUER,
                    "audiences": [AUDIENCE],
                    "jwksUri": format!("{base}/keys"),
                    "algorithms": ["PS256"],
                    "delivery": "poll",
                    "poll": { "endpoint": format!("{base}/poll"), "token": "poll-token" },
                })),
            )
            .await);
        let poll = || async { f.iam.signals.poll(None).await.unwrap().to_value() };
        assert_eq!(
            poll().await,
            json!({ "sources": 1, "received": 0, "acknowledged": 0, "errors": 1 })
        );
        *idp.lock().unwrap() = 200;
        assert_eq!(
            poll().await,
            json!({ "sources": 1, "received": 1, "acknowledged": 0, "errors": 0 })
        );
        assert_matches(&poll().await, json!({ "received": 0, "acknowledged": 1 }));
        // Neither acknowledged nor reported as an error while the keys were missing.
        assert_eq!(
            acks.lock().unwrap().clone(),
            vec![
                json!({ "ack": [], "setErrs": null }),
                json!({ "ack": [], "setErrs": null }),
                json!({ "ack": ["k1"], "setErrs": null }),
            ]
        );
        let page = list_events(&f, json!({ "sourceId": created["source"]["id"] })).await;
        let events = page["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_matches(
            &events[0],
            json!({ "jti": "k1", "eventType": "account-enabled", "status": "unmatched" }),
        );
    });
}

#[test]
fn reseals_the_poll_token_when_the_deployment_secret_rotates() {
    run(|| async {
        let f = organization(insecure_localhost).await;
        let key = generate_test_key("ES256", "poll-3");
        let authorizations: Arc<Mutex<Vec<Option<String>>>> = Arc::default();
        let seen = authorizations.clone();
        let base = listen(Arc::new(move |request: &Received| {
            let authorization = request.header("authorization");
            seen.lock().unwrap().push(authorization.clone());
            if authorization.as_deref() != Some("Bearer rotating-poll-token") {
                return (401, json!({}));
            }
            (200, json!({ "sets": {}, "moreAvailable": false }))
        }))
        .await;
        let created = ok(f
            .iam
            .api
            .signals
            .create_source(
                &owner_sign_in(&f).await,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Poller",
                    "issuer": ISSUER,
                    "audiences": [AUDIENCE],
                    "jwks": { "keys": [key.public_jwk] },
                    "delivery": "poll",
                    "poll": { "endpoint": format!("{base}/poll"), "token": "rotating-poll-token" },
                })),
            )
            .await);
        const NEW_SECRET: &str = "a-new-deployment-secret-with-32-characters!!";
        let deployment = |secret: &str, previous: Option<Vec<String>>| {
            let mut options = BetterIamOptions::new(f.store(), secret, ORIGIN);
            options.previous_secrets = previous;
            insecure_localhost(&mut options);
            better_iam_server::better_iam(options).expect("deployment")
        };
        // During the rotation the token still opens with the previous secret, and is re-sealed.
        let during = deployment(NEW_SECRET, Some(vec![FIXTURE_SECRET.to_owned()]));
        assert_matches(
            &during.signals.poll(None).await.unwrap().to_value(),
            json!({ "sources": 1, "errors": 0 }),
        );
        let rotation = during
            .rotate_secrets(&better_iam_server::secrets::SecretRotationOptions::default())
            .await
            .unwrap();
        assert_eq!(rotation.resealed.get("signalSources"), Some(&1.0));
        // The old deployment can no longer open it; the new secret alone can.
        assert_matches(
            &f.iam.signals.poll(None).await.unwrap().to_value(),
            json!({ "sources": 1, "errors": 1 }),
        );
        let source = get_source(
            &f,
            &f.owner_credential,
            &f.tenant_id,
            created["source"]["id"].as_str().unwrap(),
        )
        .await;
        assert!(
            source["lastError"]["message"]
                .as_str()
                .unwrap()
                .contains("sealed with a secret that is gone")
        );
        assert_matches(
            &deployment(NEW_SECRET, None)
                .signals
                .poll(None)
                .await
                .unwrap()
                .to_value(),
            json!({ "sources": 1, "errors": 0 }),
        );
        assert_eq!(
            authorizations.lock().unwrap().clone(),
            vec![
                Some("Bearer rotating-poll-token".to_owned()),
                Some("Bearer rotating-poll-token".to_owned()),
            ]
        );
    });
}

#[test]
fn guards_and_validates_the_signals_api() {
    run(|| async {
        let f = organization(insecure_localhost).await;
        let (beta_tenant, _, beta_owner) = second_organization(&f).await;
        let key = generate_test_key("RS256", "api-1");
        let owner = owner_sign_in(&f).await;
        let base = json!({
            "tenantId": f.tenant_id,
            "name": "IdP",
            "issuer": ISSUER,
            "audiences": [AUDIENCE],
            "jwks": { "keys": [key.public_jwk] },
            "delivery": "push",
        });
        let signals = &f.iam.api.signals;
        let created = ok(signals.create_source(&owner, body(base.clone())).await);
        let source_id = created["source"]["id"].as_str().unwrap().to_owned();
        let created_token = created["pushToken"].as_str().unwrap().to_owned();
        let push_url = created["pushUrl"].as_str().unwrap().to_owned();

        // The push token is shown once; views never carry it, its hash or a sealed token.
        let view = get_source(&f, &f.owner_credential, &f.tenant_id, &source_id).await;
        assert_matches(
            &view,
            json!({
                "hasPushToken": true,
                "requireTyp": true,
                "status": "active",
                "algorithms": ["RS256", "ES256", "PS256", "EdDSA"],
                "subjects": { "connectionIds": [], "matchEmail": false, "scimConnectionIds": [] },
                "actions": {},
                "pushUrl": push_url,
                "createdBy": f.owner_id,
            }),
        );
        assert!(view.get("pushTokenHash").is_none());
        assert!(!view.to_string().contains(&created_token));
        assert_eq!(
            ok(signals
                .list_sources(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id }))
                )
                .await),
            json!([view])
        );

        // People without the permission, and other organizations, are refused.
        let eve_id = f.member("eve").await;
        let eve = f.sign_in(&eve_id).await;
        assert_eq!(
            fails(
                signals
                    .list_sources(&eve, body(json!({ "tenantId": f.tenant_id })))
                    .await
            )
            .code,
            "ACCESS_DENIED"
        );
        assert_eq!(
            fails(
                signals
                    .list_events(&eve, body(json!({ "tenantId": f.tenant_id })))
                    .await
            )
            .code,
            "ACCESS_DENIED"
        );
        assert_eq!(
            fails(
                signals
                    .create_source(
                        &eve,
                        body(merged(
                            base.clone(),
                            json!({ "issuer": "https://eve.example.test" })
                        ))
                    )
                    .await
            )
            .code,
            "ACCESS_DENIED"
        );
        assert_eq!(
            fails(
                signals
                    .get_source(
                        &beta_owner,
                        body(json!({ "tenantId": f.tenant_id, "sourceId": source_id }))
                    )
                    .await
            )
            .code,
            "ACCESS_DENIED"
        );
        assert_eq!(
            fails(
                signals
                    .get_source(
                        &beta_owner,
                        body(json!({ "tenantId": beta_tenant, "sourceId": source_id }))
                    )
                    .await
            )
            .code,
            "NOT_FOUND"
        );
        assert_eq!(
            fails(
                signals
                    .delete_source(
                        &beta_owner,
                        body(json!({ "tenantId": beta_tenant, "sourceId": source_id }))
                    )
                    .await
            )
            .code,
            "NOT_FOUND"
        );

        // Input validation.
        let poll = json!({ "endpoint": "https://idp.example.test/poll", "token": "poll-token" });
        let with_poll = |patch: Value| merged(poll.clone(), patch);
        let aliases: Vec<String> = (0..6)
            .map(|index| format!("https://alias{index}.example.test"))
            .collect();
        let audiences: Vec<String> = (0..11).map(|index| format!("aud-{index}")).collect();
        for input in [
            json!({ "issuer": "http://idp.example.test" }),
            json!({ "issuer": "https://idp.example.test/?tenant=1" }),
            json!({ "issuer": "not a url" }),
            json!({ "name": "" }),
            json!({ "audiences": [] }),
            json!({ "audiences": audiences }),
            json!({ "algorithms": ["HS256"] }),
            json!({ "algorithms": ["none"] }),
            json!({ "algorithms": [] }),
            json!({ "jwks": { "keys": [key.private_jwk] } }),
            json!({ "jwks": { "keys": [] } }),
            json!({ "jwksUri": "https://idp.example.test/keys" }),
            json!({ "jwks": null, "jwksUri": "https://10.1.2.3/keys" }),
            json!({ "jwks": null, "jwksUri": "http://keys.example.test/jwks" }),
            json!({ "delivery": "email" }),
            json!({ "delivery": "poll" }),
            json!({ "delivery": "poll", "poll": with_poll(json!({ "token": "has a space" })) }),
            json!({ "delivery": "poll", "poll": with_poll(json!({ "maxEvents": 0 })) }),
            json!({ "delivery": "poll", "poll": with_poll(json!({ "endpoint": "https://192.168.1.10/poll" })) }),
            json!({ "delivery": "poll", "poll": with_poll(json!({ "extra": true })) }),
            json!({ "delivery": "poll", "poll": poll, "pushToken": true }),
            json!({ "poll": poll }),
            json!({ "subjects": { "emails": true } }),
            json!({ "subjects": { "matchEmail": "yes" } }),
            json!({ "subjects": { "connectionIds": "okta" } }),
            json!({ "actions": { "verification": "revoke-sessions" } }),
            json!({ "actions": { "session-revoked": "disable" } }),
            json!({ "actions": { "made-up": "record" } }),
            json!({ "requireTyp": "no" }),
            json!({ "issuerAliases": ["http://alias.example.test"] }),
            json!({ "issuerAliases": aliases }),
        ] {
            let input = merged(
                merged(
                    base.clone(),
                    json!({ "issuer": "https://new.example.test" }),
                ),
                input.clone(),
            );
            let error = fails(signals.create_source(&owner, body(input.clone())).await);
            assert_eq!(error.code, "INVALID_INPUT", "{input}");
        }

        // One source per issuer (trailing slashes aside), twenty per organization; another organization has its own.
        assert_eq!(
            fails(
                signals
                    .create_source(
                        &owner,
                        body(merged(
                            base.clone(),
                            json!({ "issuer": format!("{ISSUER}/") })
                        ))
                    )
                    .await
            )
            .code,
            "CONFLICT"
        );
        for index in 1..20 {
            ok(signals
                .create_source(
                    &owner,
                    body(merged(
                        base.clone(),
                        json!({ "issuer": format!("https://idp{index}.example.test"), "pushToken": false }),
                    )),
                )
                .await);
        }
        assert_eq!(
            fails(
                signals
                    .create_source(
                        &owner,
                        body(merged(
                            base.clone(),
                            json!({ "issuer": "https://idp20.example.test" })
                        ))
                    )
                    .await
            )
            .code,
            "LIMIT_EXCEEDED"
        );
        ok(signals
            .create_source(
                &beta_owner,
                body(merged(base.clone(), json!({ "tenantId": beta_tenant }))),
            )
            .await);

        // Updates: the issuer, delivery and push token cannot change here; an update must change something.
        let update_input = |input: Value| {
            merged(
                json!({ "tenantId": f.tenant_id, "sourceId": source_id }),
                input,
            )
        };
        for input in [
            json!({ "issuer": "https://other.example.test" }),
            json!({ "delivery": "poll" }),
            json!({ "pushToken": true }),
            json!({}),
            json!({ "name": "IdP" }),
            json!({ "poll": { "maxEvents": 5 } }),
            json!({ "status": "paused" }),
            json!({ "jwksUri": "https://idp.example.test/keys" }),
        ] {
            let error = fails(
                signals
                    .update_source(&owner, body(update_input(input.clone())))
                    .await,
            );
            assert_eq!(error.code, "INVALID_INPUT", "{input}");
        }

        // A session past its recent sign-in may read but not change.
        f.advance(6.0 * 60_000.0);
        assert_eq!(
            fails(
                signals
                    .update_source(&owner, body(update_input(json!({ "name": "Renamed" }))))
                    .await
            )
            .code,
            "RECENT_AUTH_REQUIRED"
        );
        assert_eq!(
            fails(
                signals
                    .rotate_push_token(
                        &owner,
                        body(json!({ "tenantId": f.tenant_id, "sourceId": source_id }))
                    )
                    .await
            )
            .code,
            "RECENT_AUTH_REQUIRED"
        );
        assert_eq!(
            ok(signals
                .list_sources(&owner, body(json!({ "tenantId": f.tenant_id })))
                .await)
            .as_array()
            .unwrap()
            .len(),
            20
        );
        let fresh = owner_sign_in(&f).await;

        // Rotating the push token: the old one stops working at once.
        let push = |secret: Option<String>| {
            let set = security_event(
                &f,
                Signer::Key(&key),
                event(&format!("{SSF}verification"), json!({ "state": "x" }), None),
                json!({}),
            );
            let (f, url) = (&f, push_url.clone());
            async move {
                send(
                    f,
                    &url,
                    Method::POST,
                    "application/secevent+jwt",
                    secret.as_deref(),
                    &set,
                )
                .await
                .status()
            }
        };
        assert_eq!(push(Some(created_token.clone())).await, 202);
        let rotated = ok(signals
            .rotate_push_token(
                &fresh,
                body(json!({ "tenantId": f.tenant_id, "sourceId": source_id })),
            )
            .await);
        let push_token = rotated["pushToken"].as_str().unwrap().to_owned();
        assert_ne!(push_token, created_token);
        assert_eq!(push(Some(created_token.clone())).await, 401);
        assert_eq!(push(Some(push_token.clone())).await, 202);

        // Disabled, a source's pushes answer 404 until it is enabled again.
        assert_matches(
            &ok(signals
                .update_source(&fresh, body(update_input(json!({ "status": "disabled" }))))
                .await),
            json!({ "status": "disabled" }),
        );
        assert_eq!(push(Some(push_token.clone())).await, 404);
        assert_matches(
            &ok(signals
                .update_source(
                    &fresh,
                    body(update_input(json!({
                        "status": "active",
                        "name": "Renamed IdP",
                        "audiences": [AUDIENCE, "https://rp2.example.test"],
                        "subjects": { "matchEmail": true },
                        "actions": { "credential-compromise": "revoke-sessions" },
                    }))),
                )
                .await),
            json!({
                "status": "active",
                "name": "Renamed IdP",
                "subjects": { "matchEmail": true, "connectionIds": [] },
                "actions": { "credential-compromise": "revoke-sessions" },
                "updatedBy": f.owner_id,
            }),
        );
        assert_eq!(push(Some(push_token.clone())).await, 202);
        assert_eq!(
            audit(&f, &f.tenant_id, "signal:source-update")
                .await
                .last()
                .unwrap()["metadata"],
            json!({ "changed": ["name", "audiences", "subjects", "actions", "status"] })
        );

        // Received events: paged, filtered, one at a time, not across organizations.
        let page = ok(signals
            .list_events(
                &fresh,
                body(json!({
                    "tenantId": f.tenant_id,
                    "sourceId": source_id,
                    "eventType": "verification",
                    "limit": 2,
                })),
            )
            .await);
        assert_eq!(page["total"], json!(3));
        assert_eq!(page["events"].as_array().unwrap().len(), 2);
        let event_id = page["events"][0]["id"].as_str().unwrap().to_owned();
        assert_eq!(
            ok(signals
                .get_event(
                    &fresh,
                    body(json!({ "tenantId": f.tenant_id, "eventId": event_id }))
                )
                .await),
            page["events"][0]
        );
        assert_eq!(
            fails(
                signals
                    .get_event(
                        &beta_owner,
                        body(json!({ "tenantId": beta_tenant, "eventId": event_id }))
                    )
                    .await
            )
            .code,
            "NOT_FOUND"
        );
        for input in [
            json!({ "status": "odd" }),
            json!({ "eventType": "made-up" }),
            json!({ "limit": 0 }),
            json!({ "offset": -1 }),
        ] {
            let error = fails(
                signals
                    .list_events(
                        &fresh,
                        body(merged(json!({ "tenantId": f.tenant_id }), input)),
                    )
                    .await,
            );
            assert_eq!(error.code, "INVALID_INPUT");
        }
        // Only unmatched and failed events can be reprocessed.
        assert_eq!(
            fails(
                signals
                    .reprocess(
                        &fresh,
                        body(json!({ "tenantId": f.tenant_id, "eventId": event_id }))
                    )
                    .await
            )
            .code,
            "INVALID_TRANSITION"
        );

        // Over HTTP as well.
        let (status, answer) = f
            .post(
                "signals/listSources",
                fresh.token.as_deref().unwrap(),
                json!({ "tenantId": f.tenant_id }),
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(answer["data"].as_array().unwrap().len(), 20);
        assert!(!answer["data"].to_string().contains(&push_token));

        // Deleted: pushes answer 404; its events stay until the retention sweep.
        assert_eq!(
            ok(signals
                .delete_source(
                    &fresh,
                    body(json!({ "tenantId": f.tenant_id, "sourceId": source_id }))
                )
                .await),
            json!({ "deleted": true })
        );
        assert_eq!(push(Some(push_token.clone())).await, 404);
        assert_eq!(
            list_events(&f, json!({ "sourceId": source_id })).await["total"],
            json!(3)
        );
        let actions: Vec<String> = f
            .find("audit", Filter::new().eq("tenantId", f.tenant_id.clone()))
            .await
            .iter()
            .filter_map(|entry| entry["action"].as_str().map(str::to_owned))
            .collect();
        for action in [
            "signal:source-create",
            "signal:source-update",
            "signal:source-rotate",
            "signal:source-delete",
        ] {
            assert!(actions.iter().any(|entry| entry == action), "{action}");
        }
    });
}

#[test]
fn validates_the_signals_deployment_option_and_serves_a_custom_push_path() {
    run(|| async {
        for push_path in [
            "signals/push",
            "/signals/push/",
            "/signals//push",
            "/signals push",
        ] {
            let store = better_iam_adapter_sqlite::sqlite_adapter(
                better_iam_adapter_sqlite::SqliteAdapterOptions::new(":memory:"),
            )
            .unwrap();
            let mut options = BetterIamOptions::new(store, FIXTURE_SECRET, ORIGIN);
            options.signals = Some(SignalsOptions {
                push_path: Some(push_path.to_owned()),
                ..SignalsOptions::default()
            });
            let Err(error) = better_iam_server::better_iam(options) else {
                panic!("{push_path} accepted");
            };
            assert_eq!(error.code, "INVALID_CONFIG");
            assert!(error.message.starts_with("signals"), "{}", error.message);
        }

        let f = organization(|options| {
            options.signals = Some(SignalsOptions {
                push_path: Some("/ssf/push".into()),
                ..SignalsOptions::default()
            });
        })
        .await;
        let source = push_source(&f, json!({})).await;
        assert_eq!(
            source.created["pushUrl"],
            json!(format!(
                "http://localhost:3000/ssf/push/{}",
                source.source_id
            ))
        );
        let verification = event(&format!("{SSF}verification"), json!({}), None);
        assert_eq!(
            source
                .push(&f, &source.sign(&f, verification.clone()))
                .await
                .status(),
            202
        );
        let moved = send(
            &f,
            &format!(
                "http://localhost:3000/api/iam/signals/push/{}",
                source.source_id
            ),
            Method::POST,
            "application/secevent+jwt",
            source.push_token.as_deref(),
            &source.sign(&f, verification),
        )
        .await;
        assert_ne!(moved.status(), 202);
        assert_eq!(list_events(&f, json!({})).await["total"], json!(1));
    });
}

#[test]
#[ignore = "needs threat-engine.ts detectThreats and the threats API group (other units, still stubs)"]
fn turns_upstream_compromise_and_risk_reports_into_threat_detections_for_the_matched_person() {
    run(|| async {
        let f = organization(|_| {}).await;
        let source = push_source(
            &f,
            json!({ "subjects": { "scimConnectionIds": ["okta-scim"] } }),
        )
        .await;
        let alice = f.member("alice").await;
        link_scim(&f, "okta-scim", &alice, "00u-alice").await;
        let alice_subject = json!({ "format": "iss_sub", "iss": ISSUER, "sub": "00u-alice" });
        let scope = json!({ "tenantId": f.tenant_id });
        f.iam.detect_threats(Some(&scope)).await.unwrap();
        for signal in [
            event(
                &format!("{RISC}credential-compromise"),
                json!({ "credential_type": "password" }),
                Some(alice_subject.clone()),
            ),
            event(
                &format!("{CAEP}risk-level-change"),
                json!({ "current_level": "LOW" }),
                Some(alice_subject.clone()),
            ),
            event(
                &format!("{CAEP}session-revoked"),
                json!({ "event_timestamp": seconds(&f) }),
                Some(alice_subject.clone()),
            ),
            event(
                &format!("{CAEP}risk-level-change"),
                json!({ "current_level": "MEDIUM" }),
                Some(alice_subject.clone()),
            ),
        ] {
            assert_eq!(
                source.push(&f, &source.sign(&f, signal)).await.status(),
                202
            );
        }
        f.iam.detect_threats(Some(&scope)).await.unwrap();
        let detections = ok(f
            .iam
            .api
            .threats
            .list_detections(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "ruleId": "upstream-signal" })),
            )
            .await);
        // Low risk and session revocations raise nothing.
        let mut found: Vec<Value> = detections["detections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                json!([
                    entry["severity"],
                    entry["identityId"],
                    entry["metadata"]["eventType"]
                ])
            })
            .collect();
        found.sort_by_key(|entry| entry.to_string());
        assert_eq!(
            found,
            vec![
                json!(["high", alice, "credential-compromise"]),
                json!(["medium", alice, "risk-level-change"]),
            ]
        );
        let risk = ok(f
            .iam
            .api
            .threats
            .get_risk(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "identityId": alice })),
            )
            .await);
        assert_eq!(risk["level"], json!("high"));
    });
}

#[test]
fn binds_a_source_to_one_organization_of_a_shared_issuer_through_the_tenant_id_claim() {
    run(|| async {
        let f = organization(|_| {}).await;
        // A Better IAM transmitter signs every organization's events with one issuer and key.
        let source = push_source(&f, json!({ "tenantClaim": "org-acme" })).await;
        let verification = |claims: Value| {
            source.sign(
                &f,
                merged(
                    event(&format!("{SSF}verification"), json!({}), None),
                    claims,
                ),
            )
        };
        assert_eq!(
            source
                .push(&f, &verification(json!({ "tenant_id": "org-acme" })))
                .await
                .status(),
            202
        );
        for claims in [
            json!({ "tenant_id": "org-other" }),
            json!({}),
            json!({ "tenant_id": 42 }),
        ] {
            let refused = source.push(&f, &verification(claims)).await;
            assert_eq!(refused.status(), 400);
            assert_eq!(json_of(&refused)["err"], json!("invalid_audience"));
        }
        assert_eq!(list_events(&f, json!({})).await["total"], json!(1));
        let owner = owner_sign_in(&f).await;
        let view = get_source(&f, &owner, &f.tenant_id, &source.source_id).await;
        assert_eq!(view["tenantClaim"], json!("org-acme"));
        // Clearing the binding accepts SETs without the claim again.
        let cleared = ok(f
            .iam
            .api
            .signals
            .update_source(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "sourceId": source.source_id, "tenantClaim": null })),
            )
            .await);
        assert!(cleared.get("tenantClaim").is_none());
        assert_eq!(
            source.push(&f, &verification(json!({}))).await.status(),
            202
        );
    });
}

/// The API half of tests/console-signals.test.ts ("sends bodies the signals API accepts, and only what changed"): the
/// bodies the console helpers (apps/console, TypeScript only) produce, sent as they are.
#[test]
fn accepts_the_bodies_the_console_sends_and_only_what_changed() {
    run(|| async {
        let f = organization(|_| {}).await;
        let signals = &f.iam.api.signals;
        let owner = owner_sign_in(&f).await;
        let key = generate_test_key("ES256", "idp-key");
        let created = ok(signals
            .create_source(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Okta",
                    "issuer": "https://idp.example.test/",
                    "audiences": ["https://rp.example.test"],
                    "jwks": { "keys": [key.public_jwk] },
                    "algorithms": ["ES256"],
                    "delivery": "push",
                    "pushToken": true,
                    "requireTyp": true,
                    "subjects": { "connectionIds": ["okta"], "scimConnectionIds": [], "matchEmail": true },
                    "actions": { "credential-compromise": "revoke-sessions" },
                })),
            )
            .await);
        assert!(created["pushToken"].is_string());
        let source = created["source"].clone();
        let source_id = source["id"].as_str().unwrap().to_owned();
        assert_matches(
            &source,
            json!({ "issuer": "https://idp.example.test", "hasPushToken": true }),
        );
        let update = |input: Value| {
            body(merged(
                json!({ "tenantId": f.tenant_id, "sourceId": source_id }),
                input,
            ))
        };

        // Switching to discovery clears the static keys (`null` is sent as JSON null here).
        let mut discover = Map::new();
        discover.insert(
            "issuerAliases".into(),
            json!(["https://idp.example.test/oauth2/default"]),
        );
        discover.insert("jwks".into(), Value::Null);
        let mut input = Map::new();
        input.insert("tenantId".into(), json!(f.tenant_id));
        input.insert("sourceId".into(), json!(source_id));
        input.extend(discover);
        let discovered = ok(signals
            .update_source(&owner, body(Value::Object(input)))
            .await);
        assert!(discovered.get("jwks").is_none());
        assert_eq!(
            discovered["issuerAliases"],
            json!(["https://idp.example.test/oauth2/default"])
        );
        let fetched = ok(signals
            .update_source(
                &owner,
                update(json!({
                    "jwksUri": "https://idp.example.test/keys",
                    "algorithms": ["ES256", "RS256"],
                    "requireTyp": false,
                })),
            )
            .await);
        assert_matches(
            &fetched,
            json!({ "jwksUri": "https://idp.example.test/keys", "requireTyp": false }),
        );
        let mapped = ok(signals
            .update_source(
                &owner,
                update(json!({
                    "subjects": { "connectionIds": ["okta"], "scimConnectionIds": [], "matchEmail": false },
                    "actions": {},
                })),
            )
            .await);
        assert_eq!(mapped["subjects"]["matchEmail"], json!(false));
        assert_eq!(mapped["actions"], json!({}));

        // Poll sources: the token is sent only when typed; a new endpoint needs it again.
        let poll = ok(signals
            .create_source(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Partner",
                    "issuer": "https://partner.example.test",
                    "audiences": ["acme"],
                    "algorithms": ["RS256", "ES256", "PS256", "EdDSA"],
                    "delivery": "poll",
                    "poll": {
                        "endpoint": "https://partner.example.test/ssf/poll",
                        "token": "poll-token",
                        "maxEvents": 10,
                    },
                    "requireTyp": true,
                    "subjects": { "connectionIds": [], "scimConnectionIds": [], "matchEmail": false },
                    "actions": {},
                })),
            )
            .await);
        assert!(poll.get("pushToken").is_none());
        assert_matches(
            &poll["source"]["poll"],
            json!({ "maxEvents": 10, "pendingAcks": 0 }),
        );
        let error = fails(
            signals
                .update_source(
                    &owner,
                    body(json!({
                        "tenantId": f.tenant_id,
                        "sourceId": poll["source"]["id"],
                        "poll": { "endpoint": "https://partner.example.test/v2/poll" },
                    })),
                )
                .await,
        );
        assert_eq!(error.code, "INVALID_INPUT");
    });
}
