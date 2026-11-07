//! IAM-attested A2A agent cards: ported from tests/a2a.test.ts (the server side: `agents.signCard`,
//! `agents.directory`, `iam.a2a` and the `a2a` option). The JSON canonicalization case belongs to the core vectors and
//! the attestor, discovery and gate cases to the `@better-iam/a2a` package; signatures are checked here directly
//! against the published keys, as `verifyAgentCard` does.

mod organization_fixture;

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_core::{CredentialInput, IamError, IamStore, canonicalize_json};
use better_iam_server::a2a::AGENT_ATTESTATION_URI;
use better_iam_server::options::{A2aOptions, BetterIamOptions, Jwk};
use organization_fixture::{
    ORIGIN, Org, assert_matches, bearer, body, code, fails, ok, organization, run,
};
use serde_json::{Value, json};

/// `cardKey(kid)`: a fresh Ed25519 private JWK as `KeyObject#export({ format: 'jwk' })` gives it, with kid, alg
/// and use.
fn card_key(kid: &str) -> Jwk {
    let secret: [u8; 32] = rand::random();
    let key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let jwk = json!({
        "crv": "Ed25519",
        "d": URL_SAFE_NO_PAD.encode(secret),
        "x": URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
        "kty": "OKP",
        "kid": kid,
        "alg": "EdDSA",
        "use": "sig",
    });
    jwk.as_object().unwrap().clone()
}

fn base_card(url: &str) -> Value {
    json!({
        "protocolVersion": "0.3.0",
        "name": "Triage",
        "description": "Sorts incoming requests",
        "url": url,
        "version": "1.2.0",
        "capabilities": { "streaming": true },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [
            { "id": "summarize", "name": "Summarize", "description": "Summarizes a document", "tags": ["docs"] },
            { "id": "purge", "name": "Purge", "description": "Deletes archived documents", "tags": ["docs"] },
        ],
    })
}

fn card() -> Value {
    base_card("https://agents.acme.test/a2a")
}

fn merged(base: Value, extra: Value) -> Value {
    let mut out = base.as_object().cloned().unwrap_or_default();
    for (key, value) in extra.as_object().cloned().unwrap_or_default() {
        out.insert(key, value);
    }
    Value::Object(out)
}

struct Setup {
    f: Org,
    agent: Value,
    agent_id: String,
    token: String,
}

fn a2a_options(lifetime: Option<f64>) -> A2aOptions {
    A2aOptions {
        signing_keys: vec![card_key("card-1")],
        jwks_url: Some("https://iam.acme.test/a2a/jwks.json".into()),
        card_lifetime_seconds: lifetime,
        ..A2aOptions::default()
    }
}

async fn setup() -> Setup {
    let f = organization(|options| options.a2a = Some(a2a_options(None))).await;
    let agent = ok(f
        .iam
        .api
        .agents
        .create(
            &f.owner_credential,
            body(json!({
                "tenantId": f.tenant_id,
                "name": "Triage agent",
                "url": "https://agents.acme.test/triage",
                "model": "claude-sonnet-5",
                "provider": "Anthropic",
                "protocols": ["a2a"],
            })),
        )
        .await);
    let agent_id = agent["id"].as_str().unwrap().to_owned();
    let key = ok(f
        .iam
        .api
        .credentials
        .create(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "identityId": agent_id })),
        )
        .await);
    let token = key["token"].as_str().unwrap().to_owned();
    Setup {
        f,
        agent,
        agent_id,
        token,
    }
}

impl Setup {
    async fn sign_with(
        &self,
        card: Value,
        credential: &CredentialInput,
    ) -> Result<Value, IamError> {
        self.f
            .iam
            .api
            .agents
            .sign_card(
                credential,
                body(
                    json!({ "tenantId": self.f.tenant_id, "agentId": self.agent_id, "card": card }),
                ),
            )
            .await
            .map(|reply| reply.into_value().unwrap())
    }

    async fn sign(&self, card: Value) -> Result<Value, IamError> {
        self.sign_with(card, &bearer(&self.token)).await
    }
}

fn iso(ms: f64) -> String {
    better_iam_core::js::iso_string(ms).unwrap()
}

/// Checks a signed card against a key set as `verifyAgentCard` checks the signature: the detached JWS over the
/// canonical card without `signatures`, with the key the header names. Returns the kid on success.
fn verify_card(card: &Value, keys: &Value) -> Result<String, &'static str> {
    let signatures = card["signatures"].as_array().cloned().unwrap_or_default();
    let Some(signature) = signatures.first() else {
        return Err("unsigned");
    };
    let protected = signature["protected"].as_str().unwrap();
    let header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).unwrap()).unwrap();
    let kid = header["kid"].as_str().unwrap();
    let Some(jwk) = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["kid"] == kid)
    else {
        return Err("untrusted-key");
    };
    let mut payload = card.as_object().unwrap().clone();
    payload.shift_remove("signatures");
    let canonical = canonicalize_json(&Value::Object(payload));
    let input = format!(
        "{protected}.{}",
        URL_SAFE_NO_PAD.encode(canonical.as_bytes())
    );
    let x: [u8; 32] = URL_SAFE_NO_PAD
        .decode(jwk["x"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let key = ed25519_dalek::VerifyingKey::from_bytes(&x).map_err(|_| "signature")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(signature["signature"].as_str().unwrap())
        .map_err(|_| "signature")?;
    let signature = ed25519_dalek::Signature::from_slice(&bytes).map_err(|_| "signature")?;
    key.verify_strict(input.as_bytes(), &signature)
        .map_err(|_| "signature")?;
    Ok(kid.to_owned())
}

#[test]
fn signs_an_agent_s_card_with_an_attestation_that_verifies_against_the_deployment_keys() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        let signed = s
            .sign(merged(
                card(),
                json!({
                    "provider": { "organization": "Somebody else", "url": "https://acme.test" },
                    "capabilities": {
                        "streaming": true,
                        "extensions": [
                            { "uri": AGENT_ATTESTATION_URI, "params": { "agentId": "forged" } },
                            { "uri": "https://example.test/ext/traceability", "required": false },
                        ],
                    },
                    "signatures": [{ "protected": "forged", "signature": "forged" }],
                }),
            ))
            .await
            .unwrap();
        // The provider is the organization at the agent's registered origin, whatever the card claimed.
        assert_eq!(
            signed["card"]["provider"],
            json!({ "organization": "Acme", "url": "https://agents.acme.test" })
        );
        assert_eq!(signed["card"]["signatures"].as_array().unwrap().len(), 1);
        let uris: Vec<Value> = signed["card"]["capabilities"]["extensions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["uri"].clone())
            .collect();
        assert_eq!(
            uris,
            vec![
                json!("https://example.test/ext/traceability"),
                json!(AGENT_ATTESTATION_URI)
            ]
        );
        assert_eq!(
            signed["attestation"],
            json!({
                "issuer": "http://localhost:3000/api/iam",
                "tenantId": f.tenant_id,
                "organization": "Acme",
                "agentId": s.agent_id,
                "agentName": "Triage agent",
                "sponsored": true,
                "delegable": true,
                "model": "claude-sonnet-5",
                "provider": "anthropic",
                "protocols": ["a2a"],
                "issuedAt": iso(f.now()),
                "expiresAt": iso(f.now() + 3_600_000.0),
            })
        );
        let protected = signed["card"]["signatures"][0]["protected"]
            .as_str()
            .unwrap();
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).unwrap()).unwrap();
        assert_eq!(
            header,
            json!({
                "alg": "EdDSA",
                "kid": "card-1",
                "typ": "JOSE",
                "jku": "https://iam.acme.test/a2a/jwks.json",
            })
        );

        let keys = f.iam.a2a.jwks();
        let listed = keys["keys"].as_array().unwrap();
        assert_eq!(listed.len(), 1);
        assert_matches(
            &listed[0],
            json!({ "kid": "card-1", "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig" }),
        );
        assert!(listed[0].get("d").is_none());
        assert_eq!(verify_card(&signed["card"], &keys), Ok("card-1".to_owned()));
        let attestation = signed["card"]["capabilities"]["extensions"][1]["params"].clone();
        assert_eq!(attestation["agentId"], json!(s.agent_id));

        // Any change breaks the signature; unknown keys and unsigned cards are refused.
        let mut tampered = signed["card"].as_object().unwrap().clone();
        let mut skills = tampered["skills"].as_array().unwrap().clone();
        skills.push(json!({ "id": "x" }));
        tampered.insert("skills".into(), Value::Array(skills));
        assert_eq!(
            verify_card(&Value::Object(tampered), &keys),
            Err("signature")
        );
        let mut stranger = card_key("card-1");
        stranger.shift_remove("d");
        assert_eq!(
            verify_card(&signed["card"], &json!({ "keys": [stranger] })),
            Err("signature")
        );
        let mut unsigned = signed["card"].as_object().unwrap().clone();
        unsigned.insert("signatures".into(), json!([]));
        assert_eq!(
            verify_card(&Value::Object(unsigned), &keys),
            Err("unsigned")
        );

        // The JWKS response publishes the same keys, cacheable, to anyone.
        let response = f.iam.a2a.jwks_response();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers()["content-type"],
            "application/jwk-set+json"
        );
        assert_eq!(response.headers()["cache-control"], "public, max-age=300");
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        let published: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(published, keys);

        let audit = ok(f
            .iam
            .api
            .audit
            .list(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "action": "agent:card-sign" })),
            )
            .await);
        assert_matches(
            &audit[0],
            json!({ "actorId": s.agent_id, "resourceId": s.agent_id }),
        );
        // The stored directory entry is the signed card.
        let entry = f
            .find(
                "agentCards",
                better_iam_core::Filter::new().eq("id", s.agent_id.clone()),
            )
            .await
            .remove(0);
        assert_eq!(entry["card"], signed["card"]);
        assert_eq!(entry["agentId"], json!(s.agent_id));
        assert!(s.agent["agent"]["url"].is_string());
    });
}

#[test]
fn only_attests_registered_endpoints_of_agents_in_good_standing_for_the_agent_its_sponsor_or_administrators()
 {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        let off_origin = s
            .sign(base_card("https://elsewhere.test/a2a"))
            .await
            .unwrap_err();
        assert_eq!(code(&off_origin), "INVALID_INPUT");
        let side_door = s
            .sign(merged(
                card(),
                json!({ "additionalInterfaces": [{ "url": "https://elsewhere.test/grpc", "transport": "GRPC" }] }),
            ))
            .await
            .unwrap_err();
        assert!(side_door.message.contains("additionalInterfaces[0].url"));
        let newer = s
            .sign(merged(
                card(),
                json!({ "supportedInterfaces": [{ "url": "https://elsewhere.test/a2a" }] }),
            ))
            .await
            .unwrap_err();
        assert!(newer.message.contains("supportedInterfaces[0].url"));

        // A key whose scopes limit it cannot attest the agent, even its own.
        let scoped = ok(f
            .iam
            .api
            .credentials
            .create(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "identityId": s.agent_id,
                    "scopes": ["documents:read"],
                })),
            )
            .await);
        let error = s
            .sign_with(card(), &bearer(scoped["token"].as_str().unwrap()))
            .await
            .unwrap_err();
        assert_eq!(code(&error), "ACCESS_DENIED");

        // The owner (an administrator) may sign; another agent's key may not.
        let signed = s.sign_with(card(), &f.owner_credential).await.unwrap();
        assert_matches(&signed, json!({ "attestation": { "agentId": s.agent_id } }));
        let other = ok(f
            .iam
            .api
            .agents
            .create(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Other",
                    "url": "https://agents.acme.test/other",
                })),
            )
            .await);
        let other_key = ok(f
            .iam
            .api
            .credentials
            .create(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "identityId": other["id"] })),
            )
            .await);
        let error = s
            .sign_with(card(), &bearer(other_key["token"].as_str().unwrap()))
            .await
            .unwrap_err();
        assert_eq!(code(&error), "ACCESS_DENIED");

        // A sponsor signs their own agent's card; an agent without a registered url cannot be attested.
        let sam = f.member("sam").await;
        let sam_session = f.sign_in(&sam).await;
        let unregistered = ok(f
            .iam
            .api
            .agents
            .create(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "name": "Unregistered", "sponsorId": sam })),
            )
            .await);
        let error = fails(
            f.iam
                .api
                .agents
                .sign_card(
                    &sam_session,
                    body(json!({
                        "tenantId": f.tenant_id,
                        "agentId": unregistered["id"],
                        "card": card(),
                    })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");

        // A card carrying token claims at its top level is refused.
        let error = s
            .sign(merged(card(), json!({ "iss": "x", "aud": "y" })))
            .await
            .unwrap_err();
        assert_eq!(code(&error), "INVALID_INPUT");
        assert_eq!(
            error.message,
            "An agent card may not carry the token claims iss, aud"
        );
    });
}

#[test]
#[ignore = "agents.suspend needs threats.ts endContainment and delegations.ts deleteDelegatedSessions (other units)"]
fn refuses_to_attest_a_suspended_agent() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        // A suspended agent is neither attested nor able to ask.
        ok(f.iam
            .api
            .agents
            .suspend(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "agentId": s.agent_id })),
            )
            .await);
        let error = s.sign_with(card(), &f.owner_credential).await.unwrap_err();
        assert_eq!(code(&error), "INVALID_IDENTITY");
        let error = s.sign(card()).await.unwrap_err();
        assert_eq!(error.status, 401);
    });
}

async fn helper_agent(s: &Setup) -> (String, String) {
    let f = &s.f;
    s.sign(card()).await.unwrap();
    let helper = ok(f
        .iam
        .api
        .agents
        .create(
            &f.owner_credential,
            body(json!({
                "tenantId": f.tenant_id,
                "name": "Helper",
                "url": "https://helper.acme.test",
                "protocols": ["mcp"],
            })),
        )
        .await);
    let helper_id = helper["id"].as_str().unwrap().to_owned();
    let helper_key = ok(f
        .iam
        .api
        .credentials
        .create(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "identityId": helper_id })),
        )
        .await);
    let helper_token = helper_key["token"].as_str().unwrap().to_owned();
    ok(f.iam
        .api
        .agents
        .sign_card(
            &bearer(&helper_token),
            body(json!({
                "tenantId": f.tenant_id,
                "agentId": helper_id,
                "card": {
                    "name": "Helper",
                    "url": "https://helper.acme.test/a2a",
                    "skills": [{ "id": "translate", "name": "Translate", "tags": ["language"] }],
                },
            })),
        )
        .await);
    (helper_id, helper_token)
}

async fn directory(f: &Org, credential: &CredentialInput, filter: Value) -> Vec<Value> {
    ok(f.iam
        .api
        .agents
        .directory(
            credential,
            body(merged(json!({ "tenantId": f.tenant_id }), filter)),
        )
        .await)
    .as_array()
    .cloned()
    .unwrap()
}

async fn names(f: &Org, credential: &CredentialInput, filter: Value) -> Vec<String> {
    directory(f, credential, filter)
        .await
        .iter()
        .map(|entry| entry["name"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn keeps_a_directory_of_the_tenant_s_attested_agents_by_skill_and_protocol() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        let (_, helper_token) = helper_agent(&s).await;
        let alice_id = f.member("alice").await;
        let alice = f.sign_in(&alice_id).await;
        assert_eq!(
            names(f, &alice, json!({})).await,
            ["Helper", "Triage agent"]
        );
        // Entries are the signed cards themselves, ready to verify.
        let entries = directory(f, &alice, json!({})).await;
        let triage = &entries[1];
        assert_eq!(
            verify_card(&triage["card"], &f.iam.a2a.jwks()),
            Ok("card-1".into())
        );
        assert_eq!(triage["attestation"]["agentId"], json!(s.agent_id));
        assert_eq!(
            names(f, &alice, json!({ "skill": "summarize" })).await,
            ["Triage agent"]
        );
        assert_eq!(
            names(f, &alice, json!({ "skill": "language" })).await,
            ["Helper"]
        );
        assert_eq!(
            names(f, &alice, json!({ "protocol": "a2a" })).await,
            ["Triage agent"]
        );
        // Agents find each other too.
        assert_eq!(
            names(f, &bearer(&helper_token), json!({})).await,
            ["Helper", "Triage agent"]
        );
        // Attestations that expire leave the directory.
        f.advance(2.0 * 3_600_000.0);
        let later = f.sign_in(&alice_id).await;
        assert!(names(f, &later, json!({})).await.is_empty());
    });
}

#[test]
#[ignore = "agents.suspend and agents.delete need threats.ts endContainment and delegations.ts (other units)"]
fn drops_suspended_and_deleted_agents_from_the_directory() {
    run(|| async {
        let s = setup().await;
        let f = &s.f;
        let (helper_id, _) = helper_agent(&s).await;
        let alice_id = f.member("alice").await;
        let alice = f.sign_in(&alice_id).await;
        // Suspended agents leave the directory, as do attestations that expire; deleted agents' entries go.
        ok(f.iam
            .api
            .agents
            .suspend(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "agentId": helper_id })),
            )
            .await);
        assert_eq!(names(f, &alice, json!({})).await, ["Triage agent"]);
        let owner = f.sign_in(&f.owner_id).await;
        ok(f.iam
            .api
            .agents
            .resume(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "agentId": helper_id })),
            )
            .await);
        assert_eq!(
            names(f, &alice, json!({})).await,
            ["Helper", "Triage agent"]
        );
        let owner = f.sign_in(&f.owner_id).await;
        ok(f.iam
            .api
            .agents
            .delete(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "agentId": helper_id })),
            )
            .await);
        assert_eq!(names(f, &alice, json!({})).await, ["Triage agent"]);
        f.advance(2.0 * 3_600_000.0);
        let later = f.sign_in(&alice_id).await;
        assert!(names(f, &later, json!({})).await.is_empty());
    });
}

/// `organizationFixture({ a2a })` up to construction: the options the fixture builds, with `a2a`.
fn construct(a2a: A2aOptions) -> Result<(), IamError> {
    let store: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    let mut options = BetterIamOptions::new(
        store,
        "organization-fixture-secret-with-32-characters",
        ORIGIN,
    );
    options.a2a = Some(a2a);
    better_iam_server::better_iam(options).map(|_| ())
}

#[test]
fn is_off_without_the_a2a_option_and_refuses_invalid_keys_at_construction() {
    run(|| async {
        let f = organization(|_| {}).await;
        assert!(!f.iam.a2a.enabled());
        assert_eq!(f.iam.a2a.jwks(), json!({ "keys": [] }));
        let agent = ok(f
            .iam
            .api
            .agents
            .create(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Plain",
                    "url": "https://agents.acme.test",
                })),
            )
            .await);
        let error = fails(
            f.iam
                .api
                .agents
                .sign_card(
                    &f.owner_credential,
                    body(
                        json!({ "tenantId": f.tenant_id, "agentId": agent["id"], "card": card() }),
                    ),
                )
                .await,
        );
        assert_eq!(code(&error), "FEATURE_DISABLED");
        let mut public_only = card_key("public");
        public_only.shift_remove("d");
        let error = construct(A2aOptions {
            signing_keys: vec![public_only],
            ..A2aOptions::default()
        })
        .unwrap_err();
        assert_eq!(error.message, "a2a.signingKeys must contain private keys");
        let error = construct(A2aOptions {
            signing_keys: vec![card_key("k")],
            card_lifetime_seconds: Some(10.0),
            ..A2aOptions::default()
        })
        .unwrap_err();
        assert!(error.message.contains("cardLifetimeSeconds"));
        // Keys are checked one by one: a public key that does not match its private half, duplicate kids.
        let mut mismatched = card_key("m");
        mismatched.insert("x".into(), card_key("other")["x"].clone());
        let error = construct(A2aOptions {
            signing_keys: vec![mismatched],
            ..A2aOptions::default()
        })
        .unwrap_err();
        assert_eq!(
            error.message,
            "a2a.signingKeys key m is not a valid EdDSA key"
        );
        let error = construct(A2aOptions {
            signing_keys: vec![card_key("same"), card_key("same")],
            ..A2aOptions::default()
        })
        .unwrap_err();
        assert_eq!(error.message, "a2a.kid same is used more than once");
        assert!(construct(a2a_options(Some(600.0))).is_ok());
    });
}
