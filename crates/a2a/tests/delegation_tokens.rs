//! Delegation tokens on the service and agent sides: the `verifyDelegationToken` and `createDelegationTokenCache`
//! assertions of tests/delegation-tokens.test.ts. Issuing, the live checks and the refusals of
//! `delegations.issueToken` are ported in crates/server/tests/delegation_tokens.rs.

mod support;

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_iam_a2a::{
    CardJwks, DelegationTokenCacheOptions, DelegationTokenErrorReason, IssuedDelegationToken,
    TrustedKeys, VerifyDelegationTokenOptions, create_delegation_token_cache, fetch_fn, transport,
    verify_delegation_token,
};
use better_iam_server::options::A2aOptions;
use futures::FutureExt;
use indexmap::IndexMap;
use serde_json::{Value, json};
use support::{
    Org, agent_with_key, bearer, body, card_key, clock, id_of, jwks, jwks_response, ok,
    organization, run,
};

const CALENDAR: &str = "https://calendar.example.com";
const FILES: &str = "https://files.docs.example.com";

struct Setup {
    f: Arc<Org>,
    alice: String,
    assistant: (String, String),
    researcher: (String, String),
}

/// Acme with alice (read and write on every document) and two agents with keys: an assistant that may present
/// delegations to the calendar and any docs service, and a researcher only to docs services.
async fn setup() -> Setup {
    let f = organization(|options| {
        options.a2a = Some(A2aOptions {
            signing_keys: vec![card_key("card-1")],
            jwks_url: Some("https://iam.acme.test/jwks".into()),
            ..A2aOptions::default()
        })
    })
    .await;
    let alice = f.member("alice").await;
    let assistant = agent_with_key(
        &f,
        json!({ "name": "Assistant", "tokenAudiences": [CALENDAR, "https://*.docs.example.com"] }),
    )
    .await;
    let researcher = agent_with_key(
        &f,
        json!({ "name": "Researcher", "tokenAudiences": ["https://*.docs.example.com"] }),
    )
    .await;
    f.grant(
        &alice,
        json!([{ "effect": "allow", "actions": ["documents:read", "documents:write"], "resources": ["document/*"] }]),
    )
    .await;
    Setup {
        f: Arc::new(f),
        alice,
        assistant,
        researcher,
    }
}

impl Setup {
    /// A delegation from alice to an agent, and the agent's session acting on it.
    async fn act_for(&self, agent: &(String, String), grant: Value) -> (Value, String) {
        let f = &self.f;
        let alice_session = f.sign_in(&self.alice).await;
        let mut input = grant.as_object().cloned().unwrap_or_default();
        input.insert("tenantId".into(), json!(f.tenant_id));
        input.insert("agentId".into(), json!(agent.0));
        let delegation = ok(f
            .iam
            .api
            .delegations
            .grant(&alice_session, body(Value::Object(input)))
            .await);
        let acting = ok(f
            .iam
            .api
            .delegations
            .assume(
                &bearer(&agent.1),
                body(json!({ "tenantId": f.tenant_id, "delegationId": id_of(&delegation) })),
            )
            .await);
        (delegation, acting["token"].as_str().unwrap().to_owned())
    }

    async fn issue(&self, session: &str, audience: &str) -> Value {
        ok(self
            .f
            .iam
            .api
            .delegations
            .issue_token(
                &bearer(session),
                body(json!({ "tenantId": self.f.tenant_id, "audience": audience })),
            )
            .await)
    }
}

fn trusted(f: &Arc<Org>, issuer: &str, audience: &str) -> VerifyDelegationTokenOptions {
    VerifyDelegationTokenOptions {
        audience: audience.to_owned(),
        trusted_issuers: IndexMap::from([(issuer.to_owned(), TrustedKeys::Jwks(jwks(f)))]),
        now: Some(clock(f)),
        ..VerifyDelegationTokenOptions::default()
    }
}

async fn reason(token: &str, options: &VerifyDelegationTokenOptions) -> DelegationTokenErrorReason {
    match verify_delegation_token(token, options).await {
        Ok(_) => panic!("expected a refusal"),
        Err(error) => {
            error
                .delegation_token()
                .expect("a DelegationTokenError")
                .reason
        }
    }
}

fn claims_of(token: &str) -> Value {
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

#[test]
fn lets_a_service_verify_offline_that_an_agent_acts_for_a_person() {
    run(|| async {
        let s = setup().await;
        let f = s.f.clone();
        let (delegation, session) = s
            .act_for(
                &s.assistant,
                json!({ "scopes": ["documents:read", "documents:write"] }),
            )
            .await;
        let issued = s.issue(&session, CALENDAR).await;
        let token = issued["token"].as_str().unwrap().to_owned();
        let issuer = issued["issuer"].as_str().unwrap().to_owned();

        // The service verifies it offline with the deployment's published keys.
        let verified = verify_delegation_token(&token, &trusted(&f, &issuer, CALENDAR))
            .await
            .expect("verified");
        assert_eq!(verified.person_id, s.alice);
        assert_eq!(verified.agent_id, s.assistant.0);
        assert_eq!(verified.chain, vec![s.assistant.0.clone()]);
        assert_eq!(verified.tenant_id, f.tenant_id);
        assert_eq!(verified.delegation_id, id_of(&delegation));
        assert_eq!(verified.scopes, vec!["documents:read", "documents:write"]);
        assert_eq!(verified.token_id, issued["tokenId"].as_str().unwrap());

        let base = trusted(&f, &issuer, CALENDAR);
        assert_eq!(
            reason(
                &token,
                &VerifyDelegationTokenOptions {
                    audience: FILES.into(),
                    ..base.clone()
                }
            )
            .await,
            DelegationTokenErrorReason::Audience
        );
        assert_eq!(
            reason(
                &token,
                &VerifyDelegationTokenOptions {
                    tenant_id: Some("another-tenant".into()),
                    ..base.clone()
                }
            )
            .await,
            DelegationTokenErrorReason::Tenant
        );
        assert_eq!(
            reason(
                &token,
                &VerifyDelegationTokenOptions {
                    trusted_issuers: IndexMap::from([(
                        issuer.clone(),
                        TrustedKeys::Jwks(CardJwks::default())
                    )]),
                    ..base.clone()
                }
            )
            .await,
            DelegationTokenErrorReason::UntrustedKey
        );
        assert_eq!(
            reason(
                &token,
                &VerifyDelegationTokenOptions {
                    trusted_issuers: IndexMap::from([(
                        "https://other.example".to_owned(),
                        TrustedKeys::Jwks(CardJwks::default())
                    )]),
                    ..base.clone()
                }
            )
            .await,
            DelegationTokenErrorReason::Issuer
        );
        let later = f.clone();
        assert_eq!(
            reason(
                &token,
                &VerifyDelegationTokenOptions {
                    now: Some(Arc::new(move || later.now() + 10.0 * 60_000.0)),
                    ..base.clone()
                }
            )
            .await,
            DelegationTokenErrorReason::Expired
        );
        let parts: Vec<&str> = token.split('.').collect();
        let mut claims = claims_of(&token);
        claims["sub"] = json!("someone-else");
        let forged = URL_SAFE_NO_PAD.encode(claims.to_string());
        assert_eq!(
            reason(&format!("{}.{forged}.{}", parts[0], parts[2]), &base).await,
            DelegationTokenErrorReason::Signature
        );
        let seen = Arc::new(Mutex::new(HashSet::<String>::new()));
        let once = VerifyDelegationTokenOptions {
            replay: Some({
                let seen = seen.clone();
                Arc::new(move |id: String, _expires_at: f64| {
                    let fresh = seen.lock().unwrap().insert(id);
                    async move { Ok(fresh) }.boxed()
                })
            }),
            ..base.clone()
        };
        verify_delegation_token(&token, &once)
            .await
            .expect("first use");
        assert_eq!(
            reason(&token, &once).await,
            DelegationTokenErrorReason::Replay
        );

        // Keys fetched from the issuer's JWKS URL verify too, fetched once and cached.
        let fetches = Arc::new(AtomicUsize::new(0));
        let fetcher = {
            let (f, fetches) = (f.clone(), fetches.clone());
            fetch_fn(move |request: http::Request<transport::Body>| {
                assert_eq!(request.uri().to_string(), "https://iam.acme.test/jwks");
                fetches.fetch_add(1, Ordering::SeqCst);
                let response = jwks_response(&f);
                async move { Ok(response) }
            })
        };
        let by_url = VerifyDelegationTokenOptions {
            trusted_issuers: IndexMap::from([(
                issuer.clone(),
                TrustedKeys::Url("https://iam.acme.test/jwks".into()),
            )]),
            fetch: Some(fetcher),
            ..base.clone()
        };
        verify_delegation_token(&token, &by_url)
            .await
            .expect("verified");
        verify_delegation_token(&token, &by_url)
            .await
            .expect("verified");
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        // Tokens that are not compact JWTs of the delegation type are refused before any key is looked at.
        assert_eq!(
            reason("a.b", &base).await,
            DelegationTokenErrorReason::Malformed
        );
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","kid":"card-1","typ":"JWT"}"#);
        assert_eq!(
            reason(&format!("{header}.{}.{}", parts[1], parts[2]), &base).await,
            DelegationTokenErrorReason::Type
        );
        let missing = verify_delegation_token(
            &token,
            &VerifyDelegationTokenOptions {
                audience: String::new(),
                ..base
            },
        )
        .await
        .unwrap_err();
        assert_eq!(
            missing.to_string(),
            "verifyDelegationToken needs audience and trustedIssuers"
        );
    });
}

#[test]
fn names_every_agent_a_hand_off_passed_through() {
    run(|| async {
        let s = setup().await;
        let f = s.f.clone();
        let (_, session) = s
            .act_for(
                &s.assistant,
                json!({
                    "scopes": ["documents:read", "documents:write"],
                    "handoff": { "agents": [s.researcher.0] },
                }),
            )
            .await;
        let handoff = ok(f
            .iam
            .api
            .delegations
            .handoff(
                &bearer(&session),
                body(json!({ "tenantId": f.tenant_id, "agentId": s.researcher.0, "scopes": ["documents:read"] })),
            )
            .await);
        let researching = ok(f
            .iam
            .api
            .delegations
            .assume(
                &bearer(&s.researcher.1),
                body(json!({ "tenantId": f.tenant_id, "delegationId": id_of(&handoff) })),
            )
            .await);
        let issued = s.issue(researching["token"].as_str().unwrap(), FILES).await;
        let verified = verify_delegation_token(
            issued["token"].as_str().unwrap(),
            &trusted(&f, issued["issuer"].as_str().unwrap(), FILES),
        )
        .await
        .expect("verified");
        assert_eq!(verified.agent_id, s.researcher.0);
        assert_eq!(
            verified.chain,
            vec![s.assistant.0.clone(), s.researcher.0.clone()]
        );
        assert_eq!(verified.person_id, s.alice);
    });
}

#[test]
fn caches_tokens_on_the_agent_side() {
    run(|| async {
        let now = Arc::new(Mutex::new(1_000_000.0_f64));
        let issued = Arc::new(AtomicUsize::new(0));
        let token_for = create_delegation_token_cache(DelegationTokenCacheOptions {
            now: Some({
                let now = now.clone();
                Arc::new(move || *now.lock().unwrap())
            }),
            refresh_share: None,
            issue: {
                let (now, issued) = (now.clone(), issued.clone());
                Arc::new(move |audience: String, scopes: Option<Vec<String>>| {
                    let count = issued.fetch_add(1, Ordering::SeqCst) + 1;
                    let at = *now.lock().unwrap();
                    async move {
                        tokio::task::yield_now().await;
                        Ok(IssuedDelegationToken {
                            token: format!(
                                "{audience}|{}|{count}",
                                scopes.map(|scopes| scopes.join(",")).unwrap_or_default()
                            ),
                            expires_at: at + 300_000.0,
                        })
                    }
                    .boxed()
                })
            },
        });
        let (first, second) = futures::join!(
            token_for.token(CALENDAR, None),
            token_for.token(CALENDAR, None)
        );
        assert_eq!(first.unwrap(), second.unwrap());
        let ba = ["b".to_owned(), "a".to_owned()];
        let ab = ["a".to_owned(), "b".to_owned()];
        assert_eq!(
            token_for.token(CALENDAR, Some(&ba)).await.unwrap(),
            format!("{CALENDAR}|b,a|2")
        );
        assert_eq!(
            token_for.token(CALENDAR, Some(&ab)).await.unwrap(),
            format!("{CALENDAR}|b,a|2")
        );
        *now.lock().unwrap() += 250_000.0;
        assert_eq!(
            token_for.token(CALENDAR, None).await.unwrap(),
            format!("{CALENDAR}||3")
        );
        assert_eq!(issued.load(Ordering::SeqCst), 3);
    });
}

#[test]
fn verifies_es256_signatures() {
    use p256::ecdsa::signature::Signer;
    run(|| async {
        let secret = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let point = secret.verifying_key().to_encoded_point(false);
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
            "kid": "ec-1",
            "alg": "ES256",
        });
        let now = 1_700_000_000_000.0_f64;
        let header =
            URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","kid":"ec-1","typ":"biam-delegation+jwt"}"#);
        let claims = json!({
            "iss": "https://iam.example",
            "sub": "person-1",
            "aud": CALENDAR,
            "jti": "token-1",
            "tenant_id": "tenant-1",
            "delegation_id": "delegation-1",
            "act": { "sub": "agent-1" },
            "scope": "documents:read",
            "iat": now / 1000.0,
            "nbf": now / 1000.0,
            "exp": now / 1000.0 + 300.0,
        });
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        let signature: p256::ecdsa::Signature =
            secret.sign(format!("{header}.{payload}").as_bytes());
        let token = format!(
            "{header}.{payload}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        let options = VerifyDelegationTokenOptions {
            audience: CALENDAR.into(),
            trusted_issuers: IndexMap::from([(
                "https://iam.example".to_owned(),
                TrustedKeys::Jwks(CardJwks { keys: vec![jwk] }),
            )]),
            now: Some(Arc::new(move || now)),
            ..VerifyDelegationTokenOptions::default()
        };
        let verified = verify_delegation_token(&token, &options)
            .await
            .expect("verified");
        assert_eq!(verified.person_id, "person-1");
        assert_eq!(verified.agent_id, "agent-1");
        // A null entry in a key set fails the key lookup.
        let broken = VerifyDelegationTokenOptions {
            trusted_issuers: IndexMap::from([(
                "https://iam.example".to_owned(),
                TrustedKeys::Jwks(CardJwks {
                    keys: vec![Value::Null],
                }),
            )]),
            ..options
        };
        assert_eq!(
            reason(&token, &broken).await,
            DelegationTokenErrorReason::Fetch
        );
    });
}
