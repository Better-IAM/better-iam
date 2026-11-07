//! The issuance core of temporary credentials (temporary-credentials.ts): input validators, duration bounds,
//! `mintCredential` for opaque tokens and session JWTs, the allowlist projections, and eager revocation of role
//! sessions. The TypeScript suites exercise these through `roles.assume`, `sts.getSessionToken`,
//! `sts.getCallerIdentity` and `roles.listSessions` (tests/caller-identity.test.ts, tests/jwt-session-tokens.test.ts,
//! tests/role-session-attributes.test.ts, tests/sts-hardening.test.ts); here the module is called directly, with a
//! recording signer standing in for `sts.jwt`.

use std::future::Future;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::service::base::CreateIdentityInput;
use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, IamStore, IamStoreExt, Identity, Session,
};
use better_iam_server::contracts::SessionTokenSigner;
use better_iam_server::options::BetterIamOptions;
use better_iam_server::session_tokens::{PublicSessionJwk, SessionTokenClaims};
use better_iam_server::temporary_credentials::{
    audit_session_context, caller_identity, credential_format, delete_temporary_sessions,
    duration_within, mint_credential, role_duration_bounds, role_session_summary,
    session_token_duration_bounds, temporary_credential,
};
use better_iam_server::utils::{hash, id};
use better_iam_server::{BetterIam, better_iam};
use serde_json::{Value, json};

const ORIGIN: &str = "https://iam.example.com";
const SECRET: &str = "temporary-credentials-test-secret-32chars!";
const NOW: f64 = 1_800_000_000_000.0;

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

/// A signer that records the claims it signs and returns `jwt.{claims}` padded to `pad` characters.
struct RecordingSigner {
    audiences: Vec<String>,
    max_lifetime: f64,
    pad: usize,
    signed: Mutex<Vec<SessionTokenClaims>>,
}

#[async_trait]
impl SessionTokenSigner for RecordingSigner {
    fn issuer(&self) -> &str {
        &self.audiences[0]
    }
    fn audiences(&self) -> &[String] {
        &self.audiences
    }
    fn max_lifetime_seconds(&self) -> f64 {
        self.max_lifetime
    }
    async fn sign(&self, claims: &SessionTokenClaims) -> IamResult<String> {
        self.signed.lock().unwrap().push(claims.clone());
        let mut token = format!("jwt.{}", claims.jti);
        while token.len() < self.pad {
            token.push('x');
        }
        Ok(token)
    }
    async fn verify(&self, _token: &str, _audience: Option<&str>) -> IamResult<SessionTokenClaims> {
        Err(IamError::with_status(
            "UNAUTHENTICATED",
            "Invalid or expired credentials",
            401,
        ))
    }
    fn public_jwks(&self) -> Vec<PublicSessionJwk> {
        Vec::new()
    }
}

struct Fixture {
    iam: BetterIam,
    tenant_id: String,
    identity: Identity,
}

async fn fixture() -> Fixture {
    let store: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    let mut options = BetterIamOptions::new(store, SECRET, ORIGIN);
    options.authentication = Some(better_iam_server::options::ServerAuthOptions {
        now: Some(Arc::new(|| NOW)),
        ..Default::default()
    });
    let iam = better_iam(options).expect("valid options");
    iam.initialize().await.expect("initialize");
    let root = iam
        .bootstrap(&json!({ "email": "root@example.test", "name": "Root", "password": "a strong root test password" }))
        .await
        .expect("bootstrap");
    let tenant_id = root["tenant"]["id"].as_str().unwrap().to_owned();
    let auth = iam.auth.clone();
    let tenant = tenant_id.clone();
    let identity = iam
        .store
        .transaction(|tx| async move {
            auth.create_identity(
                &tx,
                CreateIdentityInput {
                    tenant_id: tenant,
                    email: "dev@example.test".into(),
                    name: "Dev".into(),
                    password: Some("a strong developer password".into()),
                    owner: None,
                    root_admin: None,
                    email_verified: Some(true),
                },
            )
            .await
        })
        .await
        .expect("identity");
    Fixture {
        iam,
        tenant_id,
        identity,
    }
}

fn signer(max_lifetime: f64, pad: usize) -> Arc<RecordingSigner> {
    Arc::new(RecordingSigner {
        audiences: vec![
            "https://iam.example.com/api/iam".into(),
            "https://api.example".into(),
        ],
        max_lifetime,
        pad,
        signed: Mutex::new(Vec::new()),
    })
}

/// A draft session row as the flows build it (`tokenHash: ''`, no unique key).
fn draft(f: &Fixture, kind: &str, extra: Value) -> Value {
    let mut draft = json!({
        "id": id(),
        "tenantId": f.tenant_id,
        "identityId": f.identity.id,
        "kind": kind,
        "sourceSessionId": "source-session",
        "tokenHash": "",
        "createdAt": NOW,
        "lastSeenAt": NOW,
        "authenticatedAt": NOW - 5_000.0,
        "expiresAt": NOW + 900_000.0,
        "mfa": false,
    });
    for (key, value) in extra.as_object().unwrap() {
        draft[key] = value.clone();
    }
    draft
}

async fn mint(f: &Fixture, input: Value) -> Result<Value, IamError> {
    let ctx = f.iam.ctx.clone();
    f.iam
        .store
        .transaction(|tx| async move { mint_credential(&ctx, &tx, &input).await })
        .await
}

fn identity_value(f: &Fixture) -> Value {
    serde_json::to_value(&f.identity).unwrap()
}

fn error(result: Result<Value, IamError>) -> (String, u16, String) {
    match result {
        Ok(value) => panic!("expected an error, got {value}"),
        Err(error) => (error.code, error.status, error.message),
    }
}

fn session(value: Value) -> Session {
    serde_json::from_value(value).expect("session")
}

#[test]
fn opaque_tokens_are_typed_hashed_and_stored() {
    run(|| async {
        let f = fixture().await;
        let row = draft(
            &f,
            "role",
            json!({ "roleId": "role-1", "trustId": "trust-1", "format": "jwt", "audience": ["x"] }),
        );
        let minted = mint(
            &f,
            json!({ "identity": identity_value(&f), "draft": row, "format": "opaque" }),
        )
        .await
        .unwrap();
        let token = minted["token"].as_str().unwrap();
        assert!(token.starts_with("biam_rol_"), "{token}");
        assert_eq!(token.len(), 58);
        assert_eq!(minted["session"]["tokenHash"], json!(hash(token)));
        assert_eq!(minted["session"]["uniqueKey"], json!(hash(token)));
        // The draft's own format and audience never reach the row of an opaque token.
        assert!(minted["session"].get("format").is_none());
        assert!(minted["session"].get("audience").is_none());
        let stored = f
            .iam
            .store
            .get("sessions", row["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Value::Object(stored), minted["session"]);
        // Session tokens are `biam_sts_…`; a null audience counts as none.
        let minted = mint(
            &f,
            json!({ "identity": identity_value(&f), "draft": draft(&f, "session-token", json!({})), "format": "opaque", "audience": null }),
        )
        .await
        .unwrap();
        assert!(minted["token"].as_str().unwrap().starts_with("biam_sts_"));
        assert_eq!(
            error(mint(&f, json!({ "identity": identity_value(&f), "draft": draft(&f, "role", json!({})), "format": "opaque", "audience": ["a"] })).await),
            ("INVALID_INPUT".into(), 400, "audience requires format 'jwt'".into())
        );
        assert_eq!(
            error(mint(&f, json!({ "identity": identity_value(&f), "draft": draft(&f, "role", json!({})), "format": "pem" })).await),
            ("INVALID_INPUT".into(), 400, "format must be 'opaque' or 'jwt'".into())
        );
        // Only role sessions and session tokens are minted here (a programming error, answered as a 500).
        assert_eq!(
            error(mint(&f, json!({ "identity": identity_value(&f), "draft": draft(&f, "user", json!({})), "format": "opaque" })).await),
            ("INTERNAL_ERROR".into(), 500, "Internal server error".into())
        );
        // Session JWTs need sts.jwt.
        assert_eq!(
            error(mint(&f, json!({ "identity": identity_value(&f), "draft": draft(&f, "role", json!({})), "format": "jwt" })).await),
            (
                "FEATURE_DISABLED".into(),
                403,
                "Session JWTs are not enabled on this deployment (sts.jwt)".into()
            )
        );
    });
}

#[test]
fn session_jwts_check_audiences_lifetime_and_size() {
    run(|| async {
        let f = fixture().await;
        let signing = signer(3600.0, 0);
        f.iam.ctx.attach_session_tokens(signing.clone());
        let issuer = "https://iam.example.com/api/iam";
        let row = draft(
            &f,
            "role",
            json!({
                "roleId": "role-1", "trustId": "trust-1", "sourceTenantId": f.tenant_id,
                "sessionName": "deploy-42", "sourceIdentity": "alice@corp", "mfa": true,
                "webIdentity": { "providerId": "gh", "issuer": "https://token.actions.githubusercontent.com", "subject": "repo:acme/app" },
            }),
        );
        let minted = mint(
            &f,
            json!({ "identity": identity_value(&f), "draft": row, "format": "jwt" }),
        )
        .await
        .unwrap();
        let token = minted["token"].as_str().unwrap();
        assert_eq!(token, format!("jwt.{}", row["id"].as_str().unwrap()));
        let stored = &minted["session"];
        assert_eq!(stored["tokenHash"], json!(hash(token)));
        assert_eq!(stored["uniqueKey"], json!(hash(token)));
        assert_eq!(stored["format"], json!("jwt"));
        assert_eq!(stored["audience"], json!([issuer]));
        // `format` and `audience` are the last members of the row.
        let keys: Vec<&String> = stored.as_object().unwrap().keys().collect();
        assert_eq!(
            keys[keys.len() - 2..],
            [&"format".to_owned(), &"audience".to_owned()]
        );
        let claims = signing.signed.lock().unwrap()[0].clone();
        assert_eq!(claims.iss, issuer);
        assert_eq!(claims.aud, json!(issuer));
        assert_eq!(claims.sub, f.identity.id);
        assert_eq!(claims.tid, f.tenant_id);
        assert_eq!(claims.sid, row["id"].as_str().unwrap());
        assert_eq!(claims.jti, claims.sid);
        assert_eq!(claims.iat, (NOW / 1000.0).floor());
        assert_eq!(claims.nbf, claims.iat);
        assert_eq!(claims.exp, ((NOW + 900_000.0) / 1000.0).floor());
        assert_eq!(claims.auth_time, ((NOW - 5_000.0) / 1000.0).floor());
        assert_eq!(claims.kind, "role");
        assert!(claims.mfa);
        assert_eq!(claims.role.as_deref(), Some("role-1"));
        assert_eq!(claims.trust.as_deref(), Some("trust-1"));
        assert_eq!(claims.src_tid.as_deref(), Some(f.tenant_id.as_str()));
        assert_eq!(claims.session_name.as_deref(), Some("deploy-42"));
        assert_eq!(claims.source_identity.as_deref(), Some("alice@corp"));
        assert_eq!(claims.idp.as_deref(), Some("gh"));
        assert_eq!(claims.idp_sub.as_deref(), Some("repo:acme/app"));
        // The issuer response carries the audience after the session.
        let credential = temporary_credential(token, &session(stored.clone()), NOW).unwrap();
        let value = serde_json::to_value(&credential).unwrap();
        let keys: Vec<&String> = value.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "token",
                "tokenType",
                "format",
                "expiresAt",
                "expiresIn",
                "session",
                "audience"
            ]
            .iter()
            .map(|key| key.to_string())
            .collect::<Vec<_>>()
            .iter()
            .collect::<Vec<_>>()
        );
        assert_eq!(credential.format, json!("jwt"));
        assert_eq!(credential.expires_in, 900.0);
        assert_eq!(credential.audience, Some(vec![issuer.to_owned()]));
        assert_eq!(
            credential.session,
            json!({
                "id": row["id"], "tenantId": f.tenant_id, "kind": "role", "identityId": f.identity.id,
                "expiresAt": 1_800_000_900_000_i64, "mfa": true, "roleId": "role-1", "trustId": "trust-1",
                "sessionName": "deploy-42", "sourceIdentity": "alice@corp",
            })
        );
        // Audiences: on the allowlist, at most five.
        assert_eq!(
            error(mint(&f, json!({ "identity": identity_value(&f), "draft": draft(&f, "role", json!({})), "format": "jwt", "audience": ["https://other.example"] })).await),
            (
                "INVALID_INPUT".into(),
                400,
                "audience https://other.example is not an allowed session token audience".into()
            )
        );
        assert_eq!(
            error(mint(&f, json!({ "identity": identity_value(&f), "draft": draft(&f, "role", json!({})), "format": "jwt", "audience": [] })).await),
            ("INVALID_INPUT".into(), 400, "audience must list 1 to 5 audiences".into())
        );
        // A lifetime longer than sts.jwt allows.
        assert_eq!(
            error(mint(&f, json!({ "identity": identity_value(&f), "draft": draft(&f, "session-token", json!({ "expiresAt": NOW + 3_601_000.0 })), "format": "jwt" })).await),
            (
                "INVALID_INPUT".into(),
                400,
                "durationSeconds exceeds the session JWT lifetime of 3600".into()
            )
        );
        // A non-issuer audience needs iam:assertions:create on iam/{aud} for the drafted session.
        let downstream = draft(&f, "session-token", json!({}));
        assert_eq!(
            error(mint(&f, json!({ "identity": identity_value(&f), "draft": downstream, "format": "jwt", "audience": [issuer, "https://api.example"] })).await),
            (
                "ACCESS_DENIED".into(),
                403,
                "This credential may not obtain tokens for audience https://api.example".into()
            )
        );
        grant_assertions(&f).await;
        let minted = mint(
            &f,
            json!({ "identity": identity_value(&f), "draft": draft(&f, "session-token", json!({})), "format": "jwt", "audience": [issuer, "https://api.example"] }),
        )
        .await
        .unwrap();
        assert_eq!(
            minted["session"]["audience"],
            json!([issuer, "https://api.example"])
        );
        let claims = signing.signed.lock().unwrap().last().unwrap().clone();
        assert_eq!(claims.aud, json!([issuer, "https://api.example"]));
        assert_eq!(claims.kind, "session-token");
        assert_eq!(claims.role, None);
    });
}

#[test]
fn oversized_session_jwts_are_refused() {
    run(|| async {
        let f = fixture().await;
        f.iam.ctx.attach_session_tokens(signer(3600.0, 4097));
        assert_eq!(
            error(mint(&f, json!({ "identity": identity_value(&f), "draft": draft(&f, "role", json!({})), "format": "jwt" })).await),
            (
                "INVALID_INPUT".into(),
                400,
                "The session token would exceed 4096 characters".into()
            )
        );
        assert!(
            f.iam
                .store
                .find(
                    "sessions",
                    &Filter::new().eq("kind", "role"),
                    &FindOptions::default()
                )
                .await
                .unwrap()
                .is_empty()
        );
    });
}

/// A role granting `iam:assertions:create` on every resource, bound to the fixture's identity under root's authority.
async fn grant_assertions(f: &Fixture) {
    let authority = f
        .iam
        .store
        .find(
            "grantAuthorities",
            &Filter::new().eq("tenantId", f.tenant_id.clone()),
            &FindOptions::default(),
        )
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap()["id"]
        .clone();
    let role_id = id();
    let role = json!({
        "id": role_id, "tenantId": f.tenant_id, "name": "Token broker", "policyIds": [],
        "document": { "version": 1, "statements": [{ "effect": "allow", "actions": ["iam:assertions:create"], "resources": ["*"] }] },
        "protected": false, "authorityId": authority,
    });
    let binding = json!({
        "id": id(), "tenantId": f.tenant_id, "subjectType": "identity", "subjectId": f.identity.id,
        "roleId": role_id, "authorityId": authority,
    });
    f.iam
        .store
        .transaction(|tx| async move {
            tx.insert("roles", role.as_object().unwrap()).await?;
            tx.insert("bindings", binding.as_object().unwrap()).await
        })
        .await
        .unwrap();
}

#[test]
fn duration_bounds_take_the_least_usable_limit() {
    run(|| async {
        let f = fixture().await;
        let ctx = f.iam.ctx.clone();
        let opaque = credential_format(None).unwrap();
        let jwt = credential_format(Some(&json!("jwt"))).unwrap();
        // The deployment default ceiling (3600) and the trust's own maximum.
        assert_eq!(
            role_duration_bounds(&ctx, &json!({}), &opaque).unwrap(),
            json!({ "min": 60, "max": 3600, "fallback": 900 })
        );
        assert_eq!(
            role_duration_bounds(&ctx, &json!({ "maxSessionSeconds": 1800 }), &opaque).unwrap(),
            json!({ "min": 60, "max": 1800, "fallback": 900 })
        );
        assert_eq!(
            role_duration_bounds(&ctx, &json!({ "maxSessionSeconds": 300 }), &opaque).unwrap(),
            json!({ "min": 60, "max": 300, "fallback": 300 })
        );
        // A malformed stored maximum fails closed to the default instead of disabling the range check.
        for malformed in [json!("1800"), json!(-5), json!(12.5), json!(null), json!(0)] {
            assert_eq!(
                role_duration_bounds(&ctx, &json!({ "maxSessionSeconds": malformed }), &opaque)
                    .unwrap(),
                json!({ "min": 60, "max": 3600, "fallback": 900 })
            );
        }
        assert_eq!(
            session_token_duration_bounds(&ctx, &opaque).unwrap(),
            json!({ "min": 60, "max": 43200, "fallback": 3600 })
        );
        // Without sts.jwt the JWT format has no cap of its own (issuance refuses it anyway).
        assert_eq!(
            session_token_duration_bounds(&ctx, &jwt).unwrap(),
            json!({ "min": 60, "max": 43200, "fallback": 3600 })
        );
        ctx.attach_session_tokens(signer(600.0, 0));
        assert_eq!(
            role_duration_bounds(&ctx, &json!({}), &jwt).unwrap(),
            json!({ "min": 60, "max": 600, "fallback": 600 })
        );
        assert_eq!(
            session_token_duration_bounds(&ctx, &jwt).unwrap(),
            json!({ "min": 60, "max": 600, "fallback": 600 })
        );
        assert_eq!(
            role_duration_bounds(&ctx, &json!({}), &opaque).unwrap(),
            json!({ "min": 60, "max": 3600, "fallback": 900 })
        );
        let bounds =
            role_duration_bounds(&ctx, &json!({ "maxSessionSeconds": 1800 }), &opaque).unwrap();
        assert_eq!(duration_within(None, &bounds).unwrap(), 900.0);
        assert_eq!(duration_within(Some(&json!(null)), &bounds).unwrap(), 900.0);
        assert_eq!(
            duration_within(Some(&json!(1800)), &bounds).unwrap(),
            1800.0
        );
        assert_eq!(
            duration_within(Some(&json!(1801)), &bounds)
                .unwrap_err()
                .message,
            "durationSeconds must be an integer from 60 to 1800"
        );
    });
}

#[test]
fn projections_are_allowlists() {
    let base = json!({
        "id": "s1", "tenantId": "t1", "identityId": "i1", "tokenHash": "secret-hash", "uniqueKey": "secret-hash",
        "createdAt": 1000.0, "lastSeenAt": 1000.0, "authenticatedAt": 500.0, "expiresAt": 61_500.0, "mfa": true,
        "kind": "role", "roleId": "r1", "trustId": "tr1", "sourceTenantId": "t0", "sessionName": "deploy",
        "sourceIdentity": "alice", "sessionTags": { "team": "blue" }, "policy": { "version": 1, "statements": [] },
        "sourceSessionId": "src", "sourceAuthorityIds": ["a1"], "method": "password",
        "webIdentity": { "providerId": "gh", "issuer": "https://issuer.example", "subject": "repo:x" },
        "client": { "ip": "203.0.113.9" },
    });
    let row = session(base.clone());
    // temporaryCredential: expiresIn in whole seconds, never negative.
    let credential = temporary_credential("tok", &row, 1000.0).unwrap();
    assert_eq!(credential.token_type, "Bearer");
    assert_eq!(credential.format, json!("opaque"));
    assert_eq!(credential.expires_in, 60.0);
    assert_eq!(credential.audience, None);
    assert_eq!(
        temporary_credential("tok", &row, 100_000.0)
            .unwrap()
            .expires_in,
        0.0
    );
    // callerIdentity.
    let principal = better_iam_core::AuthenticatedPrincipal {
        identity: serde_json::from_value(json!({
            "id": "i1", "tenantId": "t0", "kind": "user", "name": "Alice", "status": "active",
            "emailVerified": true, "rootAdmin": false, "owner": false, "createdAt": 0,
        }))
        .unwrap(),
        session: row.clone(),
        device_proof: None,
    };
    let caller = serde_json::to_value(caller_identity(&principal).unwrap()).unwrap();
    assert_eq!(
        caller,
        json!({
            "identityId": "i1", "identityTenantId": "t0", "identityKind": "user", "tenantId": "t1",
            "sessionId": "s1", "sessionKind": "role", "format": "opaque", "mfa": true, "authenticatedAt": 500.0,
            "issuedAt": 1000.0, "expiresAt": 61_500.0, "method": "password", "roleId": "r1", "trustId": "tr1",
            "sourceTenantId": "t0", "sessionName": "deploy", "sourceIdentity": "alice",
            "sessionTags": { "team": "blue" },
            "webIdentity": { "providerId": "gh", "issuer": "https://issuer.example", "subject": "repo:x" },
        })
    );
    // An empty tag set is left out.
    let mut untagged = row.clone();
    untagged.session_tags = Some(serde_json::Map::new());
    let principal = better_iam_core::AuthenticatedPrincipal {
        session: untagged,
        ..principal
    };
    assert!(caller_identity(&principal).unwrap().session_tags.is_none());
    // roleSessionSummary: a cross-tenant session hides the caller's address.
    let summary = serde_json::to_value(role_session_summary(&row).unwrap()).unwrap();
    assert_eq!(
        summary,
        json!({
            "id": "s1", "roleId": "r1", "trustId": "tr1", "identityId": "i1", "mfa": true, "format": "opaque",
            "createdAt": 1000.0, "expiresAt": 61_500.0, "sourceTenantId": "t0", "sessionName": "deploy",
            "sourceIdentity": "alice", "webIdentity": { "providerId": "gh", "subject": "repo:x" },
        })
    );
    let mut same_tenant = base.clone();
    same_tenant["sourceTenantId"] = json!("t1");
    let summary = role_session_summary(&session(same_tenant)).unwrap();
    assert_eq!(summary.client_ip.as_deref(), Some("203.0.113.9"));
    // auditSessionContext.
    let context = audit_session_context(Some(&row)).unwrap();
    assert_eq!(
        serde_json::to_value(context).unwrap(),
        json!({
            "sessionId": "s1", "kind": "role", "roleId": "r1", "trustId": "tr1", "sourceTenantId": "t0",
            "sessionName": "deploy", "sourceIdentity": "alice", "webIdentityProviderId": "gh",
            "webIdentitySubject": "repo:x",
        })
    );
    let mut simulated = row.clone();
    simulated.id = "simulation".into();
    assert!(audit_session_context(Some(&simulated)).is_none());
    assert!(audit_session_context(None).is_none());
}

#[test]
fn eager_revocation_deletes_matching_role_sessions_only() {
    run(|| async {
        let f = fixture().await;
        let row = |id: &str, extra: Value| {
            let mut row = json!({
                "id": id, "tenantId": "t1", "identityId": "i1", "tokenHash": id, "uniqueKey": id,
                "createdAt": 1000, "lastSeenAt": 1000, "authenticatedAt": 1000, "expiresAt": 999_999, "mfa": false,
                "kind": "role", "roleId": "r1", "trustId": "tr1",
            });
            for (key, value) in extra.as_object().unwrap() {
                row[key] = value.clone();
            }
            row
        };
        let rows = vec![
            row("a", json!({})),
            row("b", json!({ "trustId": "tr2" })),
            row("c", json!({ "createdAt": 5000 })),
            row("d", json!({ "tenantId": "t2" })),
            row("e", json!({ "kind": "session-token" })),
            row("f", json!({ "roleId": "r2" })),
            row(
                "g",
                json!({ "webIdentity": { "providerId": "gh", "issuer": "https://i", "subject": "s" } }),
            ),
        ];
        f.iam
            .store
            .transaction(|tx| async move {
                for row in rows {
                    tx.insert("sessions", row.as_object().unwrap()).await?;
                }
                Ok(())
            })
            .await
            .unwrap();
        let delete = |filter: Value| {
            let store = f.iam.store.clone();
            async move {
                store
                    .transaction(|tx| async move { delete_temporary_sessions(&tx, &filter).await })
                    .await
                    .unwrap()
            }
        };
        let remaining = || async {
            let mut ids: Vec<String> = f
                .iam
                .store
                .find(
                    "sessions",
                    &Filter::new().eq("tenantId", "t1"),
                    &FindOptions::default(),
                )
                .await
                .unwrap()
                .into_iter()
                .chain(
                    f.iam
                        .store
                        .find(
                            "sessions",
                            &Filter::new().eq("tenantId", "t2"),
                            &FindOptions::default(),
                        )
                        .await
                        .unwrap(),
                )
                .map(|row| row["id"].as_str().unwrap().to_owned())
                .collect();
            ids.sort();
            ids
        };
        // One provider only.
        assert_eq!(
            delete(json!({ "tenantId": "t1", "roleId": "r1", "providerId": "gh", "createdBefore": 2000 })).await,
            1.0
        );
        assert_eq!(remaining().await, ["a", "b", "c", "d", "e", "f"]);
        // One trust only, created strictly before the watermark.
        assert_eq!(
            delete(
                json!({ "tenantId": "t1", "roleId": "r1", "trustId": "tr1", "createdBefore": 1000 })
            )
            .await,
            0.0
        );
        assert_eq!(
            delete(
                json!({ "tenantId": "t1", "roleId": "r1", "trustId": "tr1", "createdBefore": 1001 })
            )
            .await,
            1.0
        );
        assert_eq!(remaining().await, ["b", "c", "d", "e", "f"]);
        // Every trust of the role in the tenant.
        assert_eq!(
            delete(json!({ "tenantId": "t1", "roleId": "r1", "createdBefore": 10_000 })).await,
            2.0
        );
        assert_eq!(remaining().await, ["d", "e", "f"]);
    });
}
