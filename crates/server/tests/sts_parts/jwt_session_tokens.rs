//! Port of `tests/jwt-session-tokens.test.ts`: IAM-signed session JWTs end to end: configuration, issuance by
//! `roles.assume` and `sts.getSessionToken`, acceptance by IAM (bound to their stored row), offline verification
//! downstream, audiences, lifetime caps and key rotation.
//!
//! `iam.sessionTokens.verify` answers an `IamError` in Rust (the `reason` of the TypeScript `SessionTokenError` is
//! not carried), so its refusals are checked by code; the downstream verifier's reasons are checked through
//! `verify_detailed`.

use better_iam_core::IamResult;
use better_iam_server::options::BetterIamOptions;
use better_iam_server::session_tokens::{SessionTokenVerifier, create_session_token_verifier_with};
use better_iam_server::utils::hash;
use better_iam_server::{BetterIam, better_iam};
use serde_json::{Map, Value, json};

use crate::jwt_keys::{Signer, TestKey, decode_test_jwt, generate_test_key, sign_test_jwt};
use crate::support::*;

const TYP: &str = "biam-session+jwt";
const CLAIM_NAMES: [&str; 19] = [
    "iss",
    "aud",
    "sub",
    "tid",
    "sid",
    "jti",
    "iat",
    "nbf",
    "exp",
    "auth_time",
    "kind",
    "mfa",
    "role",
    "trust",
    "src_tid",
    "session_name",
    "source_identity",
    "idp",
    "idp_sub",
];

fn seconds(ms: &Value) -> Value {
    json!((ms.as_f64().unwrap_or(0.0) / 1000.0).floor())
}

fn read_only() -> Value {
    allow(&["documents:read"])
}

fn jwt_options(key: &TestKey, extra: Value) -> impl FnOnce(&mut BetterIamOptions) {
    let mut jwt = json!({ "signingKeys": [key.private_jwk] });
    for (name, value) in extra.as_object().cloned().unwrap_or_default() {
        jwt[name] = value;
    }
    move |options: &mut BetterIamOptions| options.sts = Some(sts(json!({ "jwt": jwt })))
}

/// A same-tenant read-only trust from the owner that admits a `team` tag and an optional source identity.
async fn open_trust(f: &Fixture) -> IamResult<(Value, Value)> {
    let role = api!(
        f.iam.api.roles,
        create,
        &f.owner_credential,
        json!({ "tenantId": f.tenant_id, "name": "JWT reader", "permissions": ["documents:read"] })
    )?;
    let trust = api!(
        f.iam.api.trust,
        create,
        &f.root_credential,
        json!({
            "tenantId": f.tenant_id,
            "sourceTenantId": f.tenant_id,
            "sourceIdentityId": f.owner_id,
            "roleId": role["id"],
            "requireMfa": false,
        })
    )?;
    f.patch(
        "trusts",
        str_of(&trust, "id"),
        vec![
            ("allowedTagKeys", Some(json!(["team"]))),
            ("sourceIdentityMode", Some(json!("optional"))),
        ],
    )
    .await;
    Ok((role, trust))
}

/// Another IAM instance on the fixture's database and clock, with its own `sts.jwt`.
fn instance(f: &Fixture, jwt: Option<Value>) -> BetterIam {
    let mut options = base_options(f.database.clone(), &f.clock, None);
    if let Some(jwt) = jwt {
        options.sts = Some(sts(json!({ "jwt": jwt })));
    }
    better_iam(options).expect("valid options")
}

fn verifier(f: &Fixture, audience: &str, jwks: Value) -> SessionTokenVerifier {
    create_session_token_verifier_with(
        &json!({ "issuer": ISSUER, "audience": audience, "jwks": jwks }),
        Some(f.clock.now_fn()),
    )
    .expect("verifier")
}

fn claims_json(claims: &better_iam_server::session_tokens::SessionTokenClaims) -> Value {
    Value::Object(claims.to_json())
}

#[test]
fn refuses_invalid_sts_jwt_settings_when_the_deployment_is_built() {
    run(|| async {
        let eddsa = generate_test_key("EdDSA", "k1");
        let rsa = generate_test_key("RS256", "r1");
        for jwt in [
            json!({ "signingKeys": [] }),
            json!({ "signingKeys": [eddsa.public_jwk] }),
            json!({ "signingKeys": [rsa.private_jwk] }),
            json!({ "signingKeys": [eddsa.private_jwk], "activeKeyId": "missing" }),
            json!({ "signingKeys": [eddsa.private_jwk], "maxLifetimeSeconds": 100 }),
            json!({
                "signingKeys": [eddsa.private_jwk],
                "verificationKeys": [generate_test_key("ES256", "e1").private_jwk],
            }),
            json!({ "signingKeys": [eddsa.private_jwk, eddsa.private_jwk] }),
        ] {
            let built =
                organization_fixture(|options| options.sts = Some(sts(json!({ "jwt": jwt }))))
                    .await;
            let error = fails!(built);
            refused(&error, "INVALID_CONFIG", None, None);
        }
    });
}

#[test]
fn issues_role_sessions_and_session_tokens_as_signed_jwts_bound_to_their_rows() {
    run(|| async {
        let key = generate_test_key("EdDSA", "k1");
        let f = ok!(organization_fixture(jwt_options(&key, json!({}))).await);
        let (role, trust) = ok!(open_trust(&f).await);
        let assumed = ok!(api!(
            f.iam.api.roles,
            assume,
            &ok!(f.owner_sign_in().await),
            json!({
                "tenantId": f.tenant_id,
                "trustId": trust["id"],
                "format": "jwt",
                "sessionName": "deploy-7",
                "sourceIdentity": "ops@corp",
                "tags": { "team": "red" },
                "policy": read_only(),
            })
        ));
        matches(
            &assumed,
            &json!({ "tokenType": "Bearer", "format": "jwt", "audience": [ISSUER], "expiresIn": 900 }),
        );
        let assumed_token = str_of(&assumed, "token").to_owned();
        assert!(assumed_token.len() <= 4096);
        let (header, payload) = decode_test_jwt(&assumed_token);
        same(&header, &json!({ "alg": "EdDSA", "kid": "k1", "typ": TYP }));
        let row = f.row_of(&assumed_token).await;
        matches(
            &value(&row),
            &json!({
                "format": "jwt",
                "audience": [ISSUER],
                "tokenHash": hash(&assumed_token),
                "uniqueKey": hash(&assumed_token),
            }),
        );
        same(
            &payload,
            &json!({
                "iss": ISSUER,
                "aud": ISSUER,
                "sub": f.owner_id,
                "tid": f.tenant_id,
                "sid": row["id"],
                "jti": row["id"],
                "iat": seconds(&row["createdAt"]),
                "nbf": seconds(&row["createdAt"]),
                "exp": seconds(&row["expiresAt"]),
                "auth_time": seconds(&row["authenticatedAt"]),
                "kind": "role",
                "mfa": row["mfa"],
                "role": role["id"],
                "trust": trust["id"],
                "src_tid": f.tenant_id,
                "session_name": "deploy-7",
                "source_identity": "ops@corp",
            }),
        );
        // Tags and policies stay on the row: the token never carries them.
        let body = better_iam_core::js::stringify(&payload);
        for secret in ["team", "red", "statements", "documents:read"] {
            assert!(!body.contains(secret), "{secret}");
        }

        let token = ok!(f
            .get_session_token(
                &f.owner_credential,
                json!({ "format": "jwt", "sessionName": "cli" })
            )
            .await);
        let token_value = str_of(&token, "token").to_owned();
        let (_, token_payload) = decode_test_jwt(&token_value);
        assert!(
            token_payload
                .as_object()
                .unwrap()
                .keys()
                .all(|claim| CLAIM_NAMES.contains(&claim.as_str()))
        );
        matches(
            &token_payload,
            &json!({
                "kind": "session-token",
                "sub": f.owner_id,
                "tid": f.tenant_id,
                "sid": token["session"]["id"],
                "session_name": "cli",
                "mfa": false,
            }),
        );
        assert_eq!(
            token_payload["exp"].as_f64().unwrap() - token_payload["iat"].as_f64().unwrap(),
            3600.0
        );
        for claim in ["role", "trust", "src_tid", "source_identity"] {
            assert!(token_payload.get(claim).is_none(), "{claim}");
        }
        matches(
            &value(&f.row_of(&token_value).await),
            &json!({ "kind": "session-token", "format": "jwt" }),
        );

        // IAM accepts both, with their own boundaries.
        assert!(ok!(f
            .allowed(&assumed_token, "documents:read", "jwt-document")
            .await));
        assert!(!ok!(f
            .allowed(&assumed_token, "documents:write", "jwt-document")
            .await));
        assert!(ok!(f
            .allowed(&token_value, "documents:write", "jwt-document")
            .await));
        let authorization = format!("Bearer {token_value}");
        let principal = ok!(f
            .authenticate(&headers(&[("authorization", &authorization)]))
            .await);
        same(&principal["id"], &token["session"]["id"]);
    });
}

#[test]
fn verifies_offline_with_the_published_keys_and_iam_refuses_a_revoked_token_at_once() {
    run(|| async {
        let key = generate_test_key("ES256", "k1");
        let f = ok!(organization_fixture(jwt_options(&key, json!({}))).await);
        let session_tokens = f.iam.session_tokens.as_ref().unwrap();
        let offline = verifier(&f, ISSUER, session_tokens.jwks());
        let person = ok!(f.owner_sign_in().await);
        let issued = ok!(f
            .get_session_token(&person, json!({ "format": "jwt" }))
            .await);
        let token = str_of(&issued, "token").to_owned();
        let sid = issued["session"]["id"].clone();
        same(
            &decode_test_jwt(&token).0,
            &json!({ "alg": "ES256", "kid": "k1", "typ": TYP }),
        );
        matches(
            &claims_json(&offline.verify_detailed(&token).await.unwrap()),
            &json!({ "sid": sid, "kind": "session-token" }),
        );
        let request = json!({ "headers": { "authorization": format!("bearer {token}") } });
        matches(
            &claims_json(&offline.verify_request_detailed(&request).await.unwrap()),
            &json!({ "sid": sid }),
        );
        matches(
            &claims_json(&ok!(session_tokens.verify(&token, None).await)),
            &json!({ "sid": sid }),
        );

        // Signing out the source ends the token inside IAM; an offline verifier still accepts it until exp.
        ok!(f.auth("signOut", &person, json!({})).await);
        refused(
            &fails!(f.authenticate(&bearer(&token)).await),
            "UNAUTHENTICATED",
            None,
            Some("Session token revoked"),
        );
        refused(
            &fails!(f.get_caller_identity(&bearer(&token)).await),
            "UNAUTHENTICATED",
            None,
            None,
        );
        same(
            &json!(offline.verify_detailed(&token).await.unwrap().sid),
            &sid,
        );
        refused(
            &fails!(session_tokens.verify(&token, None).await),
            "INVALID_SESSION_TOKEN",
            None,
            None,
        );
        // At exp the offline verifier refuses it too.
        f.advance(3_600_000.0 + 10_000.0);
        let error = offline.verify_detailed(&token).await.expect_err("expired");
        assert_eq!(error.reason, "expired");
    });
}

#[test]
fn allows_only_listed_audiences_the_credential_may_obtain_tokens_for() {
    run(|| async {
        let key = generate_test_key("EdDSA", "k1");
        let f = ok!(organization_fixture(jwt_options(
            &key,
            json!({ "audiences": ["https://api.example", "https://reports.example"] }),
        ))
        .await);
        let session_tokens = f.iam.session_tokens.as_ref().unwrap();
        let get = |credential: better_iam_core::CredentialInput,
                   audience: Option<Value>,
                   policy: Option<Value>| {
            let f = &f;
            async move {
                let mut input = json!({ "format": "jwt" });
                if let Some(audience) = audience {
                    input["audience"] = audience;
                }
                if let Some(policy) = policy {
                    input["policy"] = policy;
                }
                f.get_session_token(&credential, input).await
            }
        };
        for audience in [
            json!(["https://other.example"]),
            json!([]),
            json!([" bad"]),
            json!(["a1", "a2", "a3", "a4", "a5", "a6"]),
        ] {
            refused(
                &fails!(get(f.owner_credential.clone(), Some(audience), None).await),
                "INVALID_INPUT",
                None,
                None,
            );
        }

        // A downstream-only token: verified downstream and online for its audience, never accepted by IAM itself.
        let downstream = ok!(get(
            f.owner_credential.clone(),
            Some(json!(["https://api.example"])),
            None
        )
        .await);
        let downstream_token = str_of(&downstream, "token").to_owned();
        same(&downstream["audience"], &json!(["https://api.example"]));
        assert_eq!(
            decode_test_jwt(&downstream_token).1["aud"],
            "https://api.example"
        );
        refused(
            &fails!(f.authenticate(&bearer(&downstream_token)).await),
            "UNAUTHENTICATED",
            None,
            Some("Invalid credentials"),
        );
        let api_verifier = verifier(&f, "https://api.example", session_tokens.jwks());
        same(
            &json!(
                api_verifier
                    .verify_detailed(&downstream_token)
                    .await
                    .unwrap()
                    .sid
            ),
            &downstream["session"]["id"],
        );
        same(
            &json!(
                ok!(session_tokens
                    .verify(&downstream_token, Some("https://api.example"))
                    .await)
                .sid
            ),
            &downstream["session"]["id"],
        );
        refused(
            &fails!(session_tokens.verify(&downstream_token, None).await),
            "INVALID_SESSION_TOKEN",
            None,
            None,
        );
        // Naming the issuer as well makes it usable in IAM.
        let both = ok!(get(
            f.owner_credential.clone(),
            Some(json!([ISSUER, "https://api.example"])),
            None
        )
        .await);
        let both_token = str_of(&both, "token").to_owned();
        same(
            &decode_test_jwt(&both_token).1["aud"],
            &json!([ISSUER, "https://api.example"]),
        );
        same(
            &ok!(f.authenticate(&bearer(&both_token)).await)["id"],
            &both["session"]["id"],
        );

        // Other audiences need iam:assertions:create on iam/{aud}, under the token's own boundaries.
        let alice = ok!(f.member("alice").await);
        let role = ok!(api!(
            f.iam.api.roles,
            create,
            &f.owner_credential,
            json!({ "tenantId": f.tenant_id, "name": "Minter", "permissions": ["iam:session-tokens:create"] })
        ));
        ok!(api!(
            f.iam.api.bindings,
            create,
            &f.owner_credential,
            json!({
                "tenantId": f.tenant_id,
                "roleId": role["id"],
                "subjectType": "identity",
                "subjectId": alice["id"],
            })
        ));
        let login = ok!(f.sign_in_credential("alice").await);
        same(
            &ok!(get(login.clone(), None, None).await)["audience"],
            &json!([ISSUER]),
        );
        refused(
            &fails!(get(login.clone(), Some(json!(["https://api.example"])), None).await),
            "ACCESS_DENIED",
            None,
            Some("This credential may not obtain tokens for audience https://api.example"),
        );
        ok!(api!(
            f.iam.api.roles,
            update,
            &f.owner_credential,
            json!({
                "tenantId": f.tenant_id,
                "roleId": role["id"],
                "permissions": ["iam:session-tokens:create", "iam:assertions:create"],
            })
        ));
        same(
            &ok!(get(login.clone(), Some(json!(["https://api.example"])), None).await)["audience"],
            &json!(["https://api.example"]),
        );
        refused(
            &fails!(
                get(
                    f.owner_credential.clone(),
                    Some(json!(["https://reports.example"])),
                    Some(read_only())
                )
                .await
            ),
            "ACCESS_DENIED",
            None,
            None,
        );
    });
}

#[test]
fn caps_the_lifetime_and_needs_sts_jwt() {
    run(|| async {
        let key = generate_test_key("EdDSA", "k1");
        let f = ok!(
            organization_fixture(jwt_options(&key, json!({ "maxLifetimeSeconds": 600 }))).await
        );
        let (_, trust) = ok!(open_trust(&f).await);
        assert_eq!(
            ok!(f
                .get_session_token(&f.owner_credential, json!({ "format": "jwt" }))
                .await)["expiresIn"],
            600
        );
        refused(
            &fails!(
                f.get_session_token(
                    &f.owner_credential,
                    json!({ "format": "jwt", "durationSeconds": 900 })
                )
                .await
            ),
            "INVALID_INPUT",
            None,
            None,
        );
        assert_eq!(
            ok!(f.get_session_token(&f.owner_credential, json!({})).await)["expiresIn"],
            3600
        );
        let assume = |duration: Option<f64>| {
            let (f, trust) = (&f, &trust);
            async move {
                let mut input =
                    json!({ "tenantId": f.tenant_id, "trustId": trust["id"], "format": "jwt" });
                if let Some(duration) = duration {
                    input["durationSeconds"] = json!(duration);
                }
                api!(f.iam.api.roles, assume, &f.owner_sign_in().await?, input)
            }
        };
        assert_eq!(ok!(assume(None).await)["expiresIn"], 600);
        refused(
            &fails!(assume(Some(900.0)).await),
            "INVALID_INPUT",
            None,
            None,
        );

        let plain = ok!(organization_fixture(|_| {}).await);
        assert!(plain.iam.session_tokens.is_none());
        refused(
            &fails!(
                plain
                    .get_session_token(&plain.owner_credential, json!({ "format": "jwt" }))
                    .await
            ),
            "FEATURE_DISABLED",
            Some(403),
            None,
        );
        let (_, plain_trust) = ok!(open_trust(&plain).await);
        let error = fails!(api!(
            plain.iam.api.roles,
            assume,
            &ok!(plain.owner_sign_in().await),
            json!({ "tenantId": plain.tenant_id, "trustId": plain_trust["id"], "format": "jwt" })
        ));
        refused(&error, "FEATURE_DISABLED", None, None);
    });
}

#[test]
fn refuses_a_validly_signed_jwt_whose_kind_subject_or_tenant_disagrees_with_its_row() {
    run(|| async {
        let key = generate_test_key("EdDSA", "k1");
        let f = ok!(organization_fixture(jwt_options(&key, json!({}))).await);
        let session_tokens = f.iam.session_tokens.as_ref().unwrap();
        let alice = ok!(f.member("alice").await);
        let issued = ok!(f
            .get_session_token(&f.owner_credential, json!({ "format": "jwt" }))
            .await);
        let issued_token = str_of(&issued, "token").to_owned();
        let row = f.row_of(&issued_token).await;
        let check_refused = |token: String| {
            let f = &f;
            async move {
                let error = f.authenticate(&bearer(&token)).await.expect_err("refused");
                refused(
                    &error,
                    "UNAUTHENTICATED",
                    Some(401),
                    Some("Credential expired or revoked"),
                );
                let error = session_tokens
                    .verify(&token, None)
                    .await
                    .expect_err("revoked");
                assert_eq!(error.code, "INVALID_SESSION_TOKEN");
            }
        };
        let changed = |changes: Vec<(&str, Option<Value>)>| {
            let mut record = row.clone();
            for (key, value) in changes {
                match value {
                    Some(value) => {
                        record.insert(key.to_owned(), value);
                    }
                    None => {
                        record.shift_remove(key);
                    }
                }
            }
            record
        };

        // Signed by the deployment, then the row changes under it: the hash still matches, the binding does not.
        for change in [
            vec![("kind", Some(json!("role")))],
            vec![("identityId", Some(alice["id"].clone()))],
            vec![("tenantId", Some(json!(f.root_tenant)))],
            vec![("format", None)],
        ] {
            f.replace("sessions", changed(change)).await;
            check_refused(issued_token.clone()).await;
        }
        f.replace("sessions", row.clone()).await;
        same(
            &ok!(f.authenticate(&bearer(&issued_token)).await)["id"],
            &row["id"],
        );

        // Signed with the deployment's key but naming another kind, subject or tenant for the same row. Each forged
        // token gets its hash written onto the row, so the hash comparison passes and only the one claim comparison
        // can fail.
        let (_, payload) = decode_test_jwt(&issued_token);
        let resign = |change: Value| {
            let mut claims: Map<String, Value> = payload.as_object().cloned().unwrap();
            for (name, value) in change.as_object().cloned().unwrap_or_default() {
                claims.insert(name, value);
            }
            sign_test_jwt(
                Signer::Key(&key),
                &Value::Object(claims),
                json!({ "typ": TYP }),
            )
        };
        let rebound = |token: &str| {
            changed(vec![
                ("tokenHash", Some(json!(hash(token)))),
                ("uniqueKey", Some(json!(hash(token)))),
            ])
        };
        for change in [
            json!({ "kind": "role" }),
            json!({ "sub": alice["id"] }),
            json!({ "tid": f.root_tenant }),
        ] {
            let forged = resign(change);
            f.replace("sessions", rebound(&forged)).await;
            check_refused(forged).await;
        }
        // The control: a re-signed token that changes only an unbound claim is accepted once the row holds its hash,
        // so the refusals above come from the claim comparisons alone.
        let control = resign(json!({ "session_name": "control" }));
        check_refused(control.clone()).await;
        f.replace("sessions", rebound(&control)).await;
        same(
            &ok!(f.authenticate(&bearer(&control)).await)["id"],
            &row["id"],
        );
        // The same claims re-signed are a different token: the row holds the hash of the issued one only.
        f.replace("sessions", row.clone()).await;
        check_refused(control).await;
        check_refused(resign(json!({ "mfa": true }))).await;
        same(
            &ok!(f.authenticate(&bearer(&issued_token)).await)["id"],
            &row["id"],
        );
    });
}

fn kids(iam: &BetterIam) -> Vec<String> {
    iam.session_tokens.as_ref().unwrap().jwks()["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| str_of(key, "kid").to_owned())
        .collect()
}

async fn session_id(iam: &BetterIam, token: &str) -> IamResult<Value> {
    Ok(
        serde_json::to_value(&iam.authenticate(&bearer(token)).await?.session).unwrap()["id"]
            .clone(),
    )
}

#[test]
fn rotates_with_a_retired_key_kept_in_verification_keys_then_drops_it() {
    run(|| async {
        let k1 = generate_test_key("EdDSA", "k1");
        let k2 = generate_test_key("ES256", "k2");
        let f = ok!(organization_fixture(jwt_options(&k1, json!({}))).await);
        let first = ok!(f
            .get_session_token(&f.owner_credential, json!({ "format": "jwt" }))
            .await);
        let first_token = str_of(&first, "token").to_owned();

        // Step 1: publish the new key alongside the active one, then make it active.
        let staged = instance(
            &f,
            Some(json!({ "signingKeys": [k1.private_jwk, k2.private_jwk], "activeKeyId": "k2" })),
        );
        assert_eq!(kids(&staged), ["k1", "k2"]);
        same(
            &ok!(session_id(&staged, &first_token).await),
            &first["session"]["id"],
        );
        // activeKeyId takes effect at once: the staged deployment already signs with k2, and accepts what it signs.
        let staging = ok!(json(
            staged
                .api
                .sts
                .get_session_token(&f.owner_credential, body(json!({ "format": "jwt" })))
                .await
        ));
        let staging_token = str_of(&staging, "token").to_owned();
        same(
            &decode_test_jwt(&staging_token).0,
            &json!({ "alg": "ES256", "kid": "k2", "typ": TYP }),
        );
        same(
            &ok!(session_id(&staged, &staging_token).await),
            &staging["session"]["id"],
        );

        // Step 2: the old key moves to verificationKeys; it verifies but no longer signs.
        let second = instance(
            &f,
            Some(json!({ "signingKeys": [k2.private_jwk], "verificationKeys": [k1.public_jwk] })),
        );
        assert_eq!(kids(&second), ["k2", "k1"]);
        same(
            &ok!(session_id(&second, &first_token).await),
            &first["session"]["id"],
        );
        let next = ok!(json(
            second
                .api
                .sts
                .get_session_token(&f.owner_credential, body(json!({ "format": "jwt" })))
                .await
        ));
        let next_token = str_of(&next, "token").to_owned();
        same(
            &decode_test_jwt(&next_token).0,
            &json!({ "alg": "ES256", "kid": "k2", "typ": TYP }),
        );
        let downstream = verifier(&f, ISSUER, second.session_tokens.as_ref().unwrap().jwks());
        same(
            &json!(downstream.verify_detailed(&first_token).await.unwrap().sid),
            &first["session"]["id"],
        );
        same(
            &json!(downstream.verify_detailed(&next_token).await.unwrap().sid),
            &next["session"]["id"],
        );

        // Step 3: the retired key is removed; its tokens stop working in IAM at once.
        let third = instance(&f, Some(json!({ "signingKeys": [k2.private_jwk] })));
        assert_eq!(kids(&third), ["k2"]);
        refused(
            &fails!(third.authenticate(&bearer(&first_token)).await),
            "UNAUTHENTICATED",
            None,
            Some("Invalid credentials"),
        );
        let third_tokens = third.session_tokens.as_ref().unwrap();
        refused(
            &fails!(third_tokens.verify(&first_token, None).await),
            "INVALID_SESSION_TOKEN",
            None,
            None,
        );
        same(
            &ok!(session_id(&third, &next_token).await),
            &next["session"]["id"],
        );
        matches(
            &Value::Object(ok!(third_tokens.verify(&next_token, None).await).to_json()),
            &json!({ "sid": next["session"]["id"] }),
        );
    });
}
