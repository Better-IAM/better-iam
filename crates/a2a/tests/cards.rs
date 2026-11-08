//! IAM-attested A2A agent cards: the package side of tests/a2a.test.ts (`verifyAgentCard`, `discoverAgent`,
//! `createCardAttestor` and the gate's card). The server side (`agents.signCard`, `agents.directory`, `iam.a2a`)
//! is ported in crates/server/tests/a2a.rs; the JSON canonicalization case is covered by the core vectors.

mod support;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use better_iam_a2a::{A2aError, AgentCard};
use better_iam_a2a::{
    A2aGateOptions, A2aRule, AgentCardErrorReason, CardAttestorOptions, CardJwks, CardKeys,
    CardSource, DiscoverAgentOptions, SignedCard, TrustedKeys, VerifyAgentCardOptions,
    create_a2a_gate, create_card_attestor, discover_agent, fetch_fn, transport, verify_agent_card,
};
use better_iam_server::options::A2aOptions;
use futures::FutureExt;
use indexmap::IndexMap;
use serde_json::{Map, Value, json};
use support::{
    Org, OrgIam, assert_matches, base_card, bearer, body, card_key, clock, jwks, jwks_response, ok,
    organization, run,
};

const JWKS_URL: &str = "https://iam.acme.test/a2a/jwks.json";

struct Setup {
    f: Arc<Org>,
    agent_id: String,
    token: String,
}

async fn setup() -> Setup {
    let f = organization(|options| {
        options.a2a = Some(A2aOptions {
            signing_keys: vec![card_key("card-1")],
            jwks_url: Some(JWKS_URL.into()),
            ..A2aOptions::default()
        })
    })
    .await;
    let (agent_id, token) = support::agent_with_key(
        &f,
        json!({
            "name": "Triage agent",
            "url": "https://agents.acme.test/triage",
            "model": "claude-sonnet-5",
            "provider": "Anthropic",
            "protocols": ["a2a"],
        }),
    )
    .await;
    Setup {
        f: Arc::new(f),
        agent_id,
        token,
    }
}

/// `sign(card)`: `agents.signCard` with the agent's own key.
async fn sign(
    f: &Org,
    agent_id: &str,
    token: &str,
    card: &AgentCard,
) -> Result<SignedCard, A2aError> {
    let signed = f
        .iam
        .api
        .agents
        .sign_card(
            &bearer(token),
            body(json!({ "tenantId": f.tenant_id, "agentId": agent_id, "card": card })),
        )
        .await?
        .into_value()?;
    Ok(SignedCard {
        card: signed["card"].as_object().cloned().unwrap_or_default(),
        expires_at: signed["expiresAt"].as_f64().unwrap_or(f64::NAN),
    })
}

fn keys_options(f: &Arc<Org>, keys: CardJwks) -> VerifyAgentCardOptions {
    VerifyAgentCardOptions {
        keys: Some(CardKeys::Jwks(keys)),
        now: Some(clock(f)),
        ..VerifyAgentCardOptions::default()
    }
}

async fn reason(card: &Value, options: &VerifyAgentCardOptions) -> AgentCardErrorReason {
    match verify_agent_card(card, options).await {
        Ok(_) => panic!("expected a refusal"),
        Err(error) => error.card().expect("an AgentCardError").reason,
    }
}

#[test]
fn verifies_an_attested_card_against_the_deployment_keys() {
    run(|| async {
        let Setup { f, agent_id, token } = setup().await;
        let signed = sign(
            &f,
            &agent_id,
            &token,
            &base_card("https://agents.acme.test/a2a"),
        )
        .await
        .expect("signed");
        let card = Value::Object(signed.card.clone());
        let keys = jwks(&f);
        let verified = verify_agent_card(
            &card,
            &VerifyAgentCardOptions {
                tenant_id: Some(f.tenant_id.clone()),
                issuers: Some(vec!["http://localhost:3000/api/iam".into()]),
                ..keys_options(&f, keys.clone())
            },
        )
        .await
        .expect("verified");
        assert_eq!(verified.kid, "card-1");
        assert_eq!(verified.attestation.agent_id, agent_id);
        assert_eq!(verified.attestation.issuer, "http://localhost:3000/api/iam");
        assert!(verified.attestation.delegable());
        assert_eq!(verified.attestation.model(), Some("claude-sonnet-5"));

        // Any change breaks the signature; an expired attestation, another tenant or unknown keys are refused.
        let mut tampered = signed.card.clone();
        let mut skills = tampered["skills"].as_array().cloned().unwrap();
        skills.push(json!({ "id": "x" }));
        tampered.insert("skills".into(), Value::Array(skills));
        assert_eq!(
            reason(&Value::Object(tampered), &keys_options(&f, keys.clone())).await,
            AgentCardErrorReason::Signature
        );
        let later = f.clone();
        assert_eq!(
            reason(
                &card,
                &VerifyAgentCardOptions {
                    now: Some(Arc::new(move || later.now() + 3.0 * 3_600_000.0)),
                    ..keys_options(&f, keys.clone())
                }
            )
            .await,
            AgentCardErrorReason::Expired
        );
        assert_eq!(
            reason(
                &card,
                &VerifyAgentCardOptions {
                    tenant_id: Some("other".into()),
                    ..keys_options(&f, keys.clone())
                }
            )
            .await,
            AgentCardErrorReason::Tenant
        );
        let mut stranger = card_key("card-1");
        stranger.remove("d");
        let strangers = CardJwks {
            keys: vec![Value::Object(stranger)],
        };
        assert_eq!(
            reason(&card, &keys_options(&f, strangers)).await,
            AgentCardErrorReason::Signature
        );
        let mut unsigned = signed.card.clone();
        unsigned.insert("signatures".into(), json!([]));
        assert_eq!(
            reason(&Value::Object(unsigned), &keys_options(&f, keys.clone())).await,
            AgentCardErrorReason::Unsigned
        );

        // Keys fetched from a trusted JWKS URL (the signature's jku) verify too; other URLs are never fetched.
        let fetched = Arc::new(Mutex::new(Vec::<String>::new()));
        let fetcher = {
            let (f, fetched) = (f.clone(), fetched.clone());
            fetch_fn(move |request: http::Request<transport::Body>| {
                fetched.lock().unwrap().push(request.uri().to_string());
                let response = jwks_response(&f);
                async move { Ok(response) }
            })
        };
        let by_url = |urls: &[&str]| VerifyAgentCardOptions {
            trusted_jwks_urls: Some(urls.iter().map(|url| url.to_string()).collect()),
            fetch: Some(fetcher.clone()),
            now: Some(clock(&f)),
            ..VerifyAgentCardOptions::default()
        };
        let verified = verify_agent_card(&card, &by_url(&[JWKS_URL]))
            .await
            .expect("verified with fetched keys");
        assert_eq!(verified.kid, "card-1");
        assert_eq!(
            reason(&card, &by_url(&["https://iam.other.test/jwks.json"])).await,
            AgentCardErrorReason::UntrustedKey
        );
        assert_eq!(*fetched.lock().unwrap(), vec![JWKS_URL.to_owned()]);

        // Options naming no keys are a programming error.
        let error = verify_agent_card(&card, &VerifyAgentCardOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(error, A2aError::Type(_)), "{error:?}");
        assert_eq!(
            error.to_string(),
            "verifyAgentCard needs trustedIssuers, keys or trustedJwksUrls"
        );
    });
}

#[test]
fn verifies_the_signed_cards_of_the_directory() {
    run(|| async {
        let Setup { f, agent_id, token } = setup().await;
        sign(
            &f,
            &agent_id,
            &token,
            &base_card("https://agents.acme.test/a2a"),
        )
        .await
        .expect("signed");
        let alice = f.member("alice").await;
        let alice = f.sign_in(&alice).await;
        let entries = ok(f
            .iam
            .api
            .agents
            .directory(&alice, body(json!({ "tenantId": f.tenant_id })))
            .await);
        let entry = entries.as_array().unwrap().first().cloned().unwrap();
        // Entries are the signed cards themselves, ready to verify.
        let verified = verify_agent_card(&entry["card"], &keys_options(&f, jwks(&f)))
            .await
            .expect("verified");
        assert_eq!(verified.attestation.agent_id, agent_id);
    });
}

#[test]
fn keeps_a_served_card_attested_and_lets_callers_discover_and_verify_it() {
    run(|| async {
        let Setup { f, agent_id, token } = setup().await;
        let signings = Arc::new(AtomicUsize::new(0));
        let signer = {
            let (f, agent_id, token, signings) =
                (f.clone(), agent_id.clone(), token.clone(), signings.clone());
            Arc::new(move |card: AgentCard| {
                signings.fetch_add(1, Ordering::SeqCst);
                let (f, agent_id, token) = (f.clone(), agent_id.clone(), token.clone());
                async move { sign(&f, &agent_id, &token, &card).await }.boxed()
            })
        };
        let attested = create_card_attestor(CardAttestorOptions {
            card: CardSource::Card(base_card("https://agents.acme.test/a2a")),
            sign: signer.clone(),
            refresh_share: None,
            now: Some(clock(&f)),
        });
        let gate = create_a2a_gate(A2aGateOptions {
            card: Some(attested.clone().into()),
            ..A2aGateOptions::new(
                Arc::new(OrgIam(f.clone())),
                f.tenant_id.as_str(),
                A2aRule::public(),
            )
        });
        let fetcher = fetch_fn(move |request: http::Request<transport::Body>| {
            let gate = gate.clone();
            async move {
                gate.handle(request, |_, _| async {
                    Ok(http::Response::builder()
                        .status(500)
                        .body(transport::full("unexpected"))
                        .unwrap())
                })
                .await
            }
        });
        let discover = |url: &'static str, tenant: bool| {
            let options = DiscoverAgentOptions::from(VerifyAgentCardOptions {
                tenant_id: tenant.then(|| f.tenant_id.clone()),
                fetch: Some(fetcher.clone()),
                ..keys_options(&f, jwks(&f))
            });
            async move { discover_agent(url, &options).await }
        };
        let discovered = discover("https://agents.acme.test", true)
            .await
            .expect("discovered");
        assert_eq!(discovered.attestation.agent_id, agent_id);
        attested.card().await.expect("card");
        assert_eq!(signings.load(Ordering::SeqCst), 1);
        // Re-signed once less than a fifth of the hour is left.
        f.advance(50.0 * 60_000.0);
        attested.card().await.expect("card");
        assert_eq!(signings.load(Ordering::SeqCst), 2);
        let impostor = discover("https://impostor.test", false).await.unwrap_err();
        assert_eq!(
            impostor.card().unwrap().reason,
            AgentCardErrorReason::Endpoint
        );

        // trusted_issuers binds keys to the issuer a card names: the right keys under another issuer's name do not
        // count.
        let issuer = discovered.attestation.issuer.clone();
        let card = Value::Object(discovered.card.clone());
        let trusting = |name: &str| VerifyAgentCardOptions {
            trusted_issuers: Some(IndexMap::from([(
                name.to_owned(),
                TrustedKeys::Jwks(jwks(&f)),
            )])),
            now: Some(clock(&f)),
            ..VerifyAgentCardOptions::default()
        };
        let verified = verify_agent_card(&card, &trusting(&issuer))
            .await
            .expect("verified");
        assert_eq!(verified.attestation.issuer, issuer);
        assert_eq!(
            reason(&card, &trusting("https://iam.other.test/api/iam")).await,
            AgentCardErrorReason::Issuer
        );

        // An attestor whose card builder fails recovers once the builder works.
        let broken = Arc::new(AtomicBool::new(true));
        let flaky = create_card_attestor(CardAttestorOptions {
            card: {
                let broken = broken.clone();
                CardSource::build(move || {
                    let broken = broken.load(Ordering::SeqCst);
                    async move {
                        if broken {
                            Err(A2aError::message("not ready"))
                        } else {
                            Ok(base_card("https://agents.acme.test/a2a"))
                        }
                    }
                })
            },
            sign: signer,
            refresh_share: None,
            now: Some(clock(&f)),
        });
        assert_eq!(flaky.card().await.unwrap_err().to_string(), "not ready");
        broken.store(false, Ordering::SeqCst);
        let card = flaky.card().await.expect("card");
        assert_eq!(card["name"], "Triage");
    });
}

#[test]
fn an_attestor_shares_one_signing_and_keeps_a_valid_card_when_resigning_fails() {
    run(|| async {
        let now = Arc::new(Mutex::new(1_000_000.0_f64));
        let calls = Arc::new(AtomicUsize::new(0));
        let failing = Arc::new(AtomicBool::new(false));
        let attestor = create_card_attestor(CardAttestorOptions {
            card: CardSource::Card(Map::from_iter([("name".to_owned(), json!("A"))])),
            sign: {
                let (now, calls, failing) = (now.clone(), calls.clone(), failing.clone());
                Arc::new(move |card: AgentCard| {
                    let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
                    let at = *now.lock().unwrap();
                    let failing = failing.load(Ordering::SeqCst);
                    async move {
                        tokio::task::yield_now().await;
                        if failing {
                            return Err(A2aError::message("signing failed"));
                        }
                        let mut card = card;
                        card.insert("signed".into(), json!(call));
                        Ok(SignedCard {
                            card,
                            expires_at: at + 100_000.0,
                        })
                    }
                    .boxed()
                })
            },
            refresh_share: None,
            now: Some({
                let now = now.clone();
                Arc::new(move || *now.lock().unwrap())
            }),
        });
        let (first, second) = futures::join!(attestor.card(), attestor.card());
        assert_eq!(first.unwrap()["signed"], 1);
        assert_eq!(second.unwrap()["signed"], 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Within the last fifth of its lifetime the card is signed again; a failure keeps the still-valid card.
        *now.lock().unwrap() += 85_000.0;
        failing.store(true, Ordering::SeqCst);
        assert_eq!(attestor.card().await.unwrap()["signed"], 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        *now.lock().unwrap() += 20_000.0;
        assert_eq!(
            attestor.card().await.unwrap_err().to_string(),
            "signing failed"
        );
        failing.store(false, Ordering::SeqCst);
        assert_eq!(attestor.card().await.unwrap()["signed"], 4);
    });
}

#[test]
fn refuses_malformed_cards_and_signatures() {
    run(|| async {
        let Setup { f, agent_id, token } = setup().await;
        let signed = sign(
            &f,
            &agent_id,
            &token,
            &base_card("https://agents.acme.test/a2a"),
        )
        .await
        .expect("signed");
        let options = keys_options(&f, jwks(&f));
        assert_eq!(
            reason(&json!(["not", "a", "card"]), &options).await,
            AgentCardErrorReason::Malformed
        );
        assert_eq!(
            reason(&json!({ "name": "x" }), &options).await,
            AgentCardErrorReason::Malformed
        );
        // A signature of another type (a JWT signed with the same keys) is not a card signature.
        let mut retyped = signed.card.clone();
        let signature = retyped["signatures"][0].clone();
        let header = r#"{"alg":"EdDSA","kid":"card-1","typ":"JWT"}"#;
        let mut forged = signature.as_object().unwrap().clone();
        forged.insert("protected".into(), json!(base64_url(header.as_bytes())));
        retyped.insert("signatures".into(), json!([forged]));
        assert_eq!(
            reason(&Value::Object(retyped), &options).await,
            AgentCardErrorReason::UntrustedKey
        );
        // The origin of the card's url must be the one asked for.
        let error = verify_agent_card(
            &Value::Object(signed.card.clone()),
            &VerifyAgentCardOptions {
                origin: Some("https://elsewhere.test/".into()),
                ..options.clone()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.card().unwrap().reason, AgentCardErrorReason::Endpoint);
        let verified = verify_agent_card(
            &Value::Object(signed.card.clone()),
            &VerifyAgentCardOptions {
                origin: Some("https://agents.acme.test/somewhere".into()),
                ..options.clone()
            },
        )
        .await
        .expect("same origin");
        assert_matches(
            &verified.attestation.to_value(),
            json!({ "agentId": agent_id, "sponsored": true }),
        );
        let tolerance = verify_agent_card(
            &Value::Object(signed.card),
            &VerifyAgentCardOptions {
                clock_tolerance_seconds: Some(f64::NAN),
                ..options
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(tolerance, A2aError::Type(_)));
    });
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
