//! Port of `tests/sts-end-to-end.test.ts`: temporary credentials end to end, over `iam.handler` only. An owner
//! registers an OIDC provider and a web-identity trust, a CI job exchanges its external token for a session JWT on the
//! public route, uses it as a Bearer inside IAM and has it verified offline from the JWKS route; revoking the role's
//! sessions refuses the JWT inside IAM at once while offline verification keeps passing until `exp`. A person then
//! enrolls TOTP, steps up through `sts/getSessionToken` with an `mfaCode`, and assumes an MFA-gated trust from that
//! session token. `sts/getCallerIdentity` is checked at every hop, and no `sts/*` or `oidcProviders/*` answer ever
//! sets a cookie.

use std::sync::Mutex;

use better_iam_core::{IamError, IamResult};
use better_iam_server::http::encode_uri_component;
use better_iam_server::session_tokens::create_session_token_verifier_with;
use better_iam_server::utils::id;
use serde_json::{Value, json};

use crate::jwt_keys::{Signer, generate_test_key, sign_test_jwt};
use crate::support::*;

const IDP_ISSUER: &str = "https://token.actions.example.test";
const IDP_AUDIENCE: &str = "https://acme.example";
const SUBJECT: &str = "repo:acme/app:ref:refs/heads/main";

/// An answer of the HTTP client: the status, `data` and `error` of the envelope.
struct Answer {
    status: u16,
    data: Value,
    error: Option<Value>,
}

/// An HTTP client over the fixture's handler that records whether each route set a cookie.
struct Client<'a> {
    f: &'a Fixture,
    cookies: Mutex<Vec<(String, Option<String>)>>,
}

impl<'a> Client<'a> {
    fn new(f: &'a Fixture) -> Self {
        Client {
            f,
            cookies: Mutex::new(Vec::new()),
        }
    }

    /// Posts to a route; an answer naming another unit's stub is `NOT_IMPLEMENTED`, which the tests skip on.
    async fn post(
        &self,
        path: &str,
        body: Value,
        headers: &[(String, String)],
    ) -> IamResult<Answer> {
        let pairs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let response = self.f.post(path, body, &pairs).await;
        unported(&response)?;
        self.cookies.lock().unwrap().push((
            path.to_owned(),
            header(&response, "set-cookie").map(str::to_owned),
        ));
        let json = response_json(&response);
        Ok(Answer {
            status: response.status().as_u16(),
            data: json.get("data").cloned().unwrap_or(Value::Null),
            error: json.get("error").cloned(),
        })
    }

    fn bearer(token: &str) -> Vec<(String, String)> {
        vec![("authorization".into(), format!("Bearer {token}"))]
    }

    /// A browser request: the credential in the session cookie, with a trusted Origin.
    fn browser(token: &str) -> Vec<(String, String)> {
        vec![
            (
                "cookie".into(),
                format!("better-iam.session={}", encode_uri_component(token)),
            ),
            ("origin".into(), ORIGIN.into()),
        ]
    }

    async fn whoami(&self, token: &str) -> IamResult<Value> {
        let answer = self
            .post("sts/getCallerIdentity", json!({}), &Self::bearer(token))
            .await?;
        if answer.status != 200 {
            return Err(IamError::new(
                "TEST_FAILURE",
                format!("whoami answered {}", answer.status),
            ));
        }
        Ok(answer.data)
    }

    async fn allowed(&self, token: &str, action: &str) -> IamResult<Answer> {
        self.post(
            "authorize",
            json!({ "tenantId": self.f.tenant_id, "action": action, "resource": { "type": "document", "id": "release" } }),
            &Self::bearer(token),
        )
        .await
    }

    fn assert_no_cookies(&self, prefixes: &[&str]) -> usize {
        let cookies = self.cookies.lock().unwrap();
        let mut count = 0;
        for (path, set_cookie) in cookies.iter() {
            if prefixes.iter().any(|prefix| path.starts_with(prefix)) {
                count += 1;
                assert!(set_cookie.is_none(), "{path} set a cookie");
            }
        }
        count
    }
}

#[test]
fn federates_a_ci_job_to_a_session_jwt_verifies_it_offline_and_revokes_it_inside_iam_at_once() {
    run(|| async {
        let iam_key = generate_test_key("EdDSA", "iam-1");
        let idp_key = generate_test_key("RS256", "idp-1");
        let f = ok!(organization_fixture(|options| {
            options.sts = Some(sts(json!({
                "jwt": { "signingKeys": [iam_key.private_jwk] },
                "webIdentity": { "enabled": true },
            })))
        })
        .await);
        let http = Client::new(&f);
        let owner = Client::bearer(token_of(&f.owner_credential));

        // Hop 0: the owner, in their own right.
        matches(
            &ok!(http.whoami(token_of(&f.owner_credential)).await),
            &json!({ "identityId": f.owner_id, "tenantId": f.tenant_id, "sessionKind": "user", "format": "opaque" }),
        );

        // The owner registers the identity provider and a web-identity trust, all over HTTP.
        let provider = ok!(http
            .post(
                "oidcProviders/create",
                json!({
                    "tenantId": f.tenant_id,
                    "name": "GitHub Actions",
                    "issuer": IDP_ISSUER,
                    "audiences": [IDP_AUDIENCE],
                    "jwks": { "keys": [idp_key.public_jwk] },
                }),
                &owner,
            )
            .await);
        assert_eq!(provider.status, 200);
        matches(
            &provider.data,
            &json!({ "issuer": IDP_ISSUER, "enabled": true }),
        );
        let account = ok!(http
            .post(
                "serviceAccounts/create",
                json!({ "tenantId": f.tenant_id, "name": "ci" }),
                &owner
            )
            .await);
        assert_eq!(account.status, 200);
        let role = ok!(
            http.post(
                "roles/create",
                json!({ "tenantId": f.tenant_id, "name": "Deployer", "permissions": ["documents:read"] }),
                &owner,
            )
            .await
        );
        assert_eq!(role.status, 200);
        let trust = ok!(http
            .post(
                "trust/create",
                json!({
                    "tenantId": f.tenant_id,
                    "kind": "web-identity",
                    "providerId": provider.data["id"],
                    "serviceAccountId": account.data["id"],
                    "roleId": role.data["id"],
                    "conditions": { "StringEquals": { "token.sub": SUBJECT } },
                }),
                &owner,
            )
            .await);
        assert_eq!(trust.status, 200);
        assert_eq!(trust.data["kind"], "web-identity");
        // Provider reads work over a browser session too, and never touch its cookie.
        let listed = ok!(http
            .post(
                "oidcProviders/list",
                json!({ "tenantId": f.tenant_id }),
                &Client::browser(token_of(&f.owner_credential)),
            )
            .await);
        assert_eq!(listed.status, 200);
        let ids: Vec<&Value> = listed
            .data
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| &entry["id"])
            .collect();
        assert_eq!(ids, [&provider.data["id"]]);

        // The CI job: an external token from its identity provider, exchanged on the public route with the
        // X-Better-IAM header and no cookie or credential of its own.
        let external = || {
            let iat = (f.now() / 1000.0).floor();
            sign_test_jwt(
                Signer::Key(&idp_key),
                &json!({ "iss": IDP_ISSUER, "aud": IDP_AUDIENCE, "sub": SUBJECT, "iat": iat, "exp": iat + 300.0, "jti": id() }),
                json!({}),
            )
        };
        let exchange = |headers: Vec<(String, String)>| {
            let (http, f, trust, external) = (&http, &f, &trust, &external);
            async move {
                http.post(
                    "sts/assumeRoleWithWebIdentity",
                    json!({
                        "tenantId": f.tenant_id,
                        "trustId": trust.data["id"],
                        "webIdentityToken": external(),
                        "sessionName": "ci-run-1",
                        "format": "jwt",
                    }),
                    &headers,
                )
                .await
            }
        };
        let issued = ok!(exchange(Vec::new()).await);
        assert_eq!(issued.status, 200);
        let jwt = str_of(&issued.data, "token").to_owned();
        assert_eq!(jwt.split('.').count(), 3);
        let web_identity =
            json!({ "providerId": provider.data["id"], "issuer": IDP_ISSUER, "subject": SUBJECT });
        matches(
            &issued.data,
            &json!({
                "tokenType": "Bearer",
                "format": "jwt",
                "audience": [ISSUER],
                "session": {
                    "kind": "role",
                    "identityId": account.data["id"],
                    "roleId": role.data["id"],
                    "trustId": trust.data["id"],
                    "sessionName": "ci-run-1",
                },
                "webIdentity": web_identity,
            }),
        );

        // Hop 1: the JWT as a Bearer inside IAM.
        matches(
            &ok!(http.whoami(&jwt).await),
            &json!({
                "identityId": account.data["id"],
                "tenantId": f.tenant_id,
                "identityKind": "service",
                "sessionId": issued.data["session"]["id"],
                "sessionKind": "role",
                "format": "jwt",
                "roleId": role.data["id"],
                "trustId": trust.data["id"],
                "sessionName": "ci-run-1",
                "audience": [ISSUER],
                "webIdentity": web_identity,
            }),
        );
        assert_eq!(
            ok!(http.allowed(&jwt, "documents:read").await).data["allowed"],
            true
        );
        assert_eq!(
            ok!(http.allowed(&jwt, "documents:write").await).data["allowed"],
            false
        );

        // Offline: a downstream service verifies the JWT with the published keys only.
        let jwks_response = get_url(&f.iam, &format!("{ISSUER}/.well-known/jwks.json"), &[]).await;
        assert_eq!(jwks_response.status(), 200);
        assert!(header(&jwks_response, "set-cookie").is_none());
        let jwks = response_json(&jwks_response);
        assert_eq!(jwks["keys"].as_array().map(Vec::len), Some(1));
        assert!(jwks["keys"][0].get("d").is_none());
        let verifier = create_session_token_verifier_with(
            &json!({ "issuer": ISSUER, "audience": ISSUER, "jwks": jwks }),
            Some(f.clock.now_fn()),
        )
        .expect("verifier");
        let expected = json!({
            "iss": ISSUER,
            "sub": account.data["id"],
            "tid": f.tenant_id,
            "sid": issued.data["session"]["id"],
            "kind": "role",
            "role": role.data["id"],
            "trust": trust.data["id"],
            "session_name": "ci-run-1",
            "idp": provider.data["id"],
            "idp_sub": SUBJECT,
        });
        matches(
            &Value::Object(verifier.verify_detailed(&jwt).await.unwrap().to_json()),
            &expected,
        );
        let request = json!({ "headers": { "authorization": format!("bearer {jwt}") } });
        matches(
            &Value::Object(
                verifier
                    .verify_request_detailed(&request)
                    .await
                    .unwrap()
                    .to_json(),
            ),
            &expected,
        );

        // The owner revokes the role's sessions: the very next IAM call is refused, offline verification still passes
        // until exp (the documented lag), and the in-process online check reports the revocation.
        let fresh_owner = ok!(f.owner_sign_in().await);
        let revoked = ok!(http
            .post(
                "roles/revokeSessions",
                json!({ "tenantId": f.tenant_id, "roleId": role.data["id"] }),
                &Client::bearer(token_of(&fresh_owner)),
            )
            .await);
        assert_eq!(revoked.status, 200);
        assert_eq!(revoked.data["revoked"], 1);
        let refused_answer = ok!(http.allowed(&jwt, "documents:read").await);
        assert_eq!(refused_answer.status, 401);
        assert_eq!(refused_answer.error.unwrap()["code"], "UNAUTHENTICATED");
        let whoami_refused = ok!(http
            .post("sts/getCallerIdentity", json!({}), &Client::bearer(&jwt))
            .await);
        assert_eq!(whoami_refused.status, 401);
        matches(
            &Value::Object(verifier.verify_detailed(&jwt).await.unwrap().to_json()),
            &expected,
        );
        refused(
            &fails!(
                f.iam
                    .session_tokens
                    .as_ref()
                    .unwrap()
                    .verify(&jwt, None)
                    .await
            ),
            "INVALID_SESSION_TOKEN",
            None,
            None,
        );

        // Revocation covers sessions issued so far only: the next run federates again, even with a stray browser
        // cookie and Origin on the request (the public route ignores both and sets no cookie).
        f.advance(1000.0);
        let again = ok!(exchange(Client::browser(token_of(&f.owner_credential))).await);
        assert_eq!(again.status, 200);
        assert_ne!(again.data["session"]["id"], issued.data["session"]["id"]);
        assert_eq!(
            ok!(http.whoami(str_of(&again.data, "token")).await)["sessionKind"],
            "role"
        );

        http.assert_no_cookies(&["sts/", "oidcProviders/"]);
    });
}

#[test]
fn steps_up_with_totp_for_a_session_token_then_assumes_an_mfa_gated_trust_from_it() {
    run(|| async {
        let f = ok!(organization_fixture(|_| {}).await);
        let http = Client::new(&f);
        let owner = Client::bearer(token_of(&f.owner_credential));
        let alice = ok!(http
            .post(
                "identities/create",
                json!({
                    "tenantId": f.tenant_id,
                    "email": "alice@acme.test",
                    "name": "alice",
                    "password": "a strong alice password",
                }),
                &owner,
            )
            .await);
        assert_eq!(alice.status, 200);
        let alice_id = alice.data["id"].clone();
        let grants = ok!(http
            .post(
                "roles/create",
                json!({
                    "tenantId": f.tenant_id,
                    "name": "Temporary credentials",
                    "permissions": ["iam:session-tokens:create", "iam:roles:assume"],
                }),
                &owner,
            )
            .await);
        let bound = ok!(http
            .post(
                "bindings/create",
                json!({
                    "tenantId": f.tenant_id,
                    "roleId": grants.data["id"],
                    "subjectType": "identity",
                    "subjectId": alice_id,
                }),
                &owner,
            )
            .await);
        assert_eq!(bound.status, 200);
        let writer = ok!(
            http.post(
                "roles/create",
                json!({ "tenantId": f.tenant_id, "name": "Writer", "permissions": ["documents:write"] }),
                &owner,
            )
            .await
        );
        // Identity trusts stay platform-controlled: the root administrator creates the MFA-gated one.
        let trust = ok!(http
            .post(
                "trust/create",
                json!({
                    "tenantId": f.tenant_id,
                    "sourceTenantId": f.tenant_id,
                    "sourceIdentityId": alice_id,
                    "roleId": writer.data["id"],
                    "requireMfa": true,
                }),
                &Client::bearer(token_of(&f.root_credential)),
            )
            .await);
        assert_eq!(trust.status, 200);
        assert_eq!(trust.data["requireMfa"], true);

        // Alice signs in and enrolls an authenticator over HTTP.
        let login = ok!(f.sign_in("alice").await);
        let login_token = str_of(&login, "token").to_owned();
        matches(
            &ok!(http.whoami(&login_token).await),
            &json!({ "identityId": alice_id, "sessionKind": "user", "mfa": false }),
        );
        // Control: a session token minted from the password-only sign-in carries no MFA, and the gated trust refuses
        // it.
        let unverified = ok!(http
            .post(
                "sts/getSessionToken",
                json!({ "sessionName": "alice-password-only" }),
                &Client::bearer(&login_token),
            )
            .await);
        assert_eq!(unverified.status, 200);
        matches(
            &unverified.data["session"],
            &json!({ "kind": "session-token", "mfa": false }),
        );
        let unverified_token = str_of(&unverified.data, "token").to_owned();
        assert_eq!(ok!(http.whoami(&unverified_token).await)["mfa"], false);
        let refused_assume = ok!(
            http.post(
                "roles/assume",
                json!({ "tenantId": f.tenant_id, "trustId": trust.data["id"], "sessionName": "alice-no-mfa" }),
                &Client::bearer(&unverified_token),
            )
            .await
        );
        assert_eq!(refused_assume.status, 403);
        assert_eq!(refused_assume.error.unwrap()["code"], "ACCESS_DENIED");
        let enrollment = ok!(http
            .post("auth/beginMfa", json!({}), &Client::bearer(&login_token))
            .await);
        assert_eq!(enrollment.status, 200);
        let secret = str_of(&enrollment.data, "secret").to_owned();
        let enrollment_code = totp(&secret, f.now());
        let confirmed = ok!(http
            .post(
                "auth/confirmMfa",
                json!({ "code": enrollment_code }),
                &Client::bearer(&login_token)
            )
            .await);
        assert_eq!(confirmed.status, 200);
        let person = str_of(&confirmed.data, "token").to_owned();
        matches(
            &ok!(http.whoami(&person).await),
            &json!({ "identityId": alice_id, "sessionKind": "user", "mfa": true }),
        );
        // Enrolling ended the earlier sessions, and the session token minted from one of them.
        assert_eq!(
            ok!(http
                .post(
                    "sts/getCallerIdentity",
                    json!({}),
                    &Client::bearer(&unverified_token)
                )
                .await)
            .status,
            401
        );

        // The route verifies the code: a wrong code and the spent enrollment code (same time step) are refused.
        let step_up = |code: String| {
            let (http, person) = (&http, &person);
            async move {
                http.post(
                    "sts/getSessionToken",
                    json!({ "mfaCode": code, "sessionName": "alice-laptop" }),
                    &Client::bearer(person),
                )
                .await
            }
        };
        for code in [totp(&secret, f.now() + 600_000.0), enrollment_code.clone()] {
            let refused_code = ok!(step_up(code).await);
            assert_eq!(refused_code.status, 401);
            assert_eq!(refused_code.error.unwrap()["code"], "INVALID_MFA");
        }

        // Step up: a first-hand code from the next time step (the enrollment code's step is spent).
        f.advance(30_000.0);
        let step_up_code = totp(&secret, f.now());
        let stepped = ok!(step_up(step_up_code.clone()).await);
        assert_eq!(stepped.status, 200);
        let session_token = str_of(&stepped.data, "token").to_owned();
        assert!(typed_token(&session_token, "biam_sts_"), "{session_token}");
        matches(
            &stepped.data["session"],
            &json!({ "kind": "session-token", "mfa": true }),
        );
        // The source session is already MFA, so the flag alone proves nothing: the step-up itself is on record, and
        // the same code cannot be used twice.
        let replayed = ok!(step_up(step_up_code).await);
        assert_eq!(replayed.status, 401);
        assert_eq!(replayed.error.unwrap()["code"], "INVALID_MFA");
        let issued_events = || {
            let (http, f, owner) = (&http, &f, &owner);
            async move {
                let listed = http
                    .post(
                        "audit/list",
                        json!({ "tenantId": f.tenant_id, "action": "session-token:issued" }),
                        owner,
                    )
                    .await?;
                assert_eq!(listed.status, 200);
                Ok::<Value, IamError>(listed.data)
            }
        };
        let issued_for = |events: &Value, session_id: &Value| {
            events
                .as_array()
                .unwrap()
                .iter()
                .find(|event| &event["metadata"]["sessionId"] == session_id)
                .map(|event| event["metadata"].clone())
                .expect("issued event")
        };
        matches(
            &issued_for(&ok!(issued_events().await), &stepped.data["session"]["id"]),
            &json!({ "mfaStepUp": true }),
        );
        let step_ups = ok!(http
            .post(
                "audit/list",
                json!({ "tenantId": f.tenant_id, "action": "auth:mfa:step-up" }),
                &owner,
            )
            .await);
        assert_eq!(step_ups.status, 200);
        let actors: Vec<&Value> = step_ups
            .data
            .as_array()
            .unwrap()
            .iter()
            .map(|event| &event["actorId"])
            .collect();
        assert_eq!(actors, [&alice_id]);
        matches(
            &ok!(http.whoami(&session_token).await),
            &json!({
                "identityId": alice_id,
                "sessionKind": "session-token",
                "sessionId": stepped.data["session"]["id"],
                "sessionName": "alice-laptop",
                "mfa": true,
                "format": "opaque",
            }),
        );
        // The session token itself cannot write, and cannot mint another session token.
        assert_eq!(
            ok!(http.allowed(&session_token, "documents:write").await).data["allowed"],
            false
        );
        let chained = ok!(http
            .post(
                "sts/getSessionToken",
                json!({}),
                &Client::bearer(&session_token)
            )
            .await);
        assert_eq!(chained.status, 400);
        assert_eq!(
            chained.error.unwrap()["code"],
            "CREDENTIAL_CHAINING_DISABLED"
        );

        // AssumeRole from the stepped-up session token satisfies the MFA-gated trust.
        let assumed = ok!(
            http.post(
                "roles/assume",
                json!({ "tenantId": f.tenant_id, "trustId": trust.data["id"], "sessionName": "alice-write" }),
                &Client::bearer(&session_token),
            )
            .await
        );
        assert_eq!(assumed.status, 200);
        let assumed_token = str_of(&assumed.data, "token").to_owned();
        assert!(assumed_token.starts_with("biam_rol_"));
        matches(
            &assumed.data["session"],
            &json!({ "kind": "role", "mfa": true, "roleId": writer.data["id"], "trustId": trust.data["id"] }),
        );
        matches(
            &ok!(http.whoami(&assumed_token).await),
            &json!({
                "identityId": alice_id,
                "sessionKind": "role",
                "roleId": writer.data["id"],
                "trustId": trust.data["id"],
                "sessionName": "alice-write",
                "mfa": true,
            }),
        );
        assert_eq!(
            ok!(http.allowed(&assumed_token, "documents:write").await).data["allowed"],
            true
        );

        // Browser requests (cookie plus a trusted Origin) reach the sts routes without any cookie coming back.
        let browser_whoami = ok!(http
            .post(
                "sts/getCallerIdentity",
                json!({}),
                &Client::browser(&person)
            )
            .await);
        assert_eq!(browser_whoami.status, 200);
        assert_eq!(browser_whoami.data["sessionKind"], "user");
        let browser_token = ok!(http
            .post("sts/getSessionToken", json!({}), &Client::browser(&person))
            .await);
        assert_eq!(browser_token.status, 200);
        assert!(str_of(&browser_token.data, "token").starts_with("biam_sts_"));
        // Without a code the token copies the source's MFA state, and the audit says no step-up happened.
        assert_eq!(browser_token.data["session"]["mfa"], true);
        matches(
            &issued_for(
                &ok!(issued_events().await),
                &browser_token.data["session"]["id"],
            ),
            &json!({ "mfaStepUp": false }),
        );

        // Revoking the session token ends the role session derived from it, on the next use.
        let revoke = ok!(http
            .post(
                "auth/revokeSession",
                json!({ "sessionId": stepped.data["session"]["id"] }),
                &Client::bearer(&person),
            )
            .await);
        assert_eq!(revoke.status, 200);
        for token in [&session_token, &assumed_token] {
            let answer = ok!(http
                .post("sts/getCallerIdentity", json!({}), &Client::bearer(token))
                .await);
            assert_eq!(answer.status, 401);
        }

        assert!(http.assert_no_cookies(&["sts/"]) >= 8);
    });
}
