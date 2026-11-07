//! Delegation tokens (`delegations.issueToken`, delegation-tokens.ts): the port of tests/delegation-tokens.test.ts,
//! plus checks of what tokens stand on (`scopeRefusal`, `tokenStillStands`) that run on their own.
//!
//! Issuing needs agents with token audiences (`agents.create`, `tokenAudience`, `audienceMatches`,
//! `assertAgentUsable`: agents unit) and the deployment's card signer (`cardSigner`: a2a unit); live verification is
//! `iam.a2a.verifyDelegationToken` (a2a unit). Those suites are `#[ignore]`d with that reason until the units land.
//! The offline verifier and the token cache of the `@better-iam/a2a` package (`verifyDelegationToken`,
//! `createDelegationTokenCache`) have no Rust crate in this repository, so their assertions are not part of this
//! port; the in-deployment verifier covers the same refusals.

mod delegation_support;
mod governance;
mod jwt_keys;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_iam_core::{
    CredentialInput, DelegationTokenExpectations, DelegationTokenRead, DelegationTokenRejection,
    IamStoreExt, Identity, Tenant, delegation_actor, read_delegation_token_claims,
};
use better_iam_server::delegation_tokens::{
    DelegationTokenRecord, ScopeRefusal, TokenBasis, scope_refusal, token_still_stands,
};
use better_iam_server::delegations::Delegation;
use better_iam_server::options::A2aOptions;
use better_iam_server::port::decode;
use delegation_support::{
    Fixture, TestAgent, actions, assert_matches, doc, organization, refusal, token_of,
};
use governance::{DAY, body, err, ok, run};
use serde_json::{Map, Value, json};

const CALENDAR: &str = "https://calendar.example.com";
const FILES: &str = "https://files.docs.example.com";

fn claims_of(token: &str) -> Value {
    let part = token.split('.').nth(1).expect("a payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("JSON claims")
}

fn header_of(token: &str) -> Value {
    let part = token.split('.').next().expect("a header");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("JSON header")
}

fn signing_key(kid: &str) -> Map<String, Value> {
    let mut jwk = jwt_keys::generate_test_key("EdDSA", kid).private_jwk;
    jwk.insert("use".into(), json!("sig"));
    jwk
}

// --- what tokens stand on ----------------------------------------------------------------------------------------

/// Alice (documents:read and documents:write on every document), an agent record and a delegation to it, written to
/// the store as the TypeScript server writes them.
async fn stored_chain(f: &Fixture, confirm: Value) -> (String, String, String) {
    let alice = f.member("alice").await;
    f.grant(
        "Editor",
        doc(&["documents:read", "documents:write"], &["document/*"]),
        &alice,
    )
    .await;
    let agent = better_iam_server::utils::id();
    f.insert(
        "identities",
        json!({
            "id": agent,
            "tenantId": f.tenant_id,
            "kind": "agent",
            "agent": { "sponsorId": f.owner_id, "tokenAudiences": [CALENDAR] },
            "name": "Assistant",
            "status": "active",
            "emailVerified": false,
            "rootAdmin": false,
            "owner": false,
            "createdAt": f.now(),
        }),
    )
    .await;
    let mut delegation = json!({
        "id": "dlg-1",
        "tenantId": f.tenant_id,
        "agentId": agent,
        "subjectId": alice,
        "status": "active",
        "policy": { "version": 1, "statements": [{ "sid": "DelegationScopes", "effect": "allow", "actions": ["documents:read", "documents:write"], "resources": ["*"] }] },
        "scopes": ["documents:read", "documents:write"],
        "requestedBy": "subject",
        "createdAt": f.now(),
        "decidedAt": f.now(),
        "expiresAt": f.now() + DAY,
    });
    if !confirm.is_null() {
        delegation["confirm"] = confirm;
    }
    f.insert("delegations", delegation).await;
    (alice, agent, "dlg-1".to_owned())
}

async fn basis(f: &Fixture, alice: &str, agent: &str, delegation: &str) -> TokenBasis {
    let tenant: Tenant = decode(f.get("tenants", &f.tenant_id).await.unwrap()).unwrap();
    let delegation: Delegation = decode(f.get("delegations", delegation).await.unwrap()).unwrap();
    let agent: Identity = decode(f.get("identities", agent).await.unwrap()).unwrap();
    TokenBasis {
        tenant,
        person_id: alice.to_owned(),
        delegation,
        ancestors: Vec::new(),
        agents: vec![agent],
        session_policies: Vec::new(),
        authority_ids: Vec::new(),
    }
}

async fn refusal_of(f: &Fixture, basis: &TokenBasis, scopes: &[&str]) -> Option<ScopeRefusal> {
    let ctx = f.iam.ctx.clone();
    let basis = basis.clone();
    let scopes: Vec<String> = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    f.iam
        .store
        .transaction(move |tx| async move { scope_refusal(&ctx, &tx, &basis, &scopes).await })
        .await
        .unwrap()
}

#[test]
fn scopes_must_be_allowed_outright_and_never_confirmed_or_touched_by_a_deny() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (alice, agent, delegation) = stored_chain(&f, json!(["documents:wri?e"])).await;
        let chain = basis(&f, &alice, &agent, &delegation).await;
        assert_eq!(refusal_of(&f, &chain, &[]).await, None);
        assert_eq!(refusal_of(&f, &chain, &["documents:read"]).await, None);
        assert_eq!(
            refusal_of(&f, &chain, &["documents:read", "documents:write"]).await,
            Some(ScopeRefusal::Scope {
                scope: "documents:write".into(),
                why: "confirm"
            })
        );
        // A pattern broader than the delegation's scopes is not allowed outright.
        assert_eq!(
            refusal_of(&f, &chain, &["documents:*"]).await,
            Some(ScopeRefusal::Scope {
                scope: "documents:*".into(),
                why: "limit"
            })
        );
        // The session's own limits bound the token too.
        let mut limited = chain.clone();
        limited.session_policies = vec![
            better_iam_core::PolicyDocument::from_value(&doc(&["documents:write"], &["*"]))
                .unwrap(),
        ];
        assert_eq!(
            refusal_of(&f, &limited, &["documents:read"]).await,
            Some(ScopeRefusal::Scope {
                scope: "documents:read".into(),
                why: "limit"
            })
        );
        // A deny among alice's own grants refuses any scope it could touch, whatever its conditions.
        f.grant(
            "No agent writes",
            json!({
                "version": 1,
                "statements": [{
                    "effect": "deny",
                    "actions": ["documents:read"],
                    "resources": ["document/*"],
                    "conditions": { "Bool": { "principal.delegated": true } },
                }],
            }),
            &alice,
        )
        .await;
        assert_eq!(
            refusal_of(&f, &chain, &["documents:read"]).await,
            Some(ScopeRefusal::Scope {
                scope: "documents:read".into(),
                why: "deny"
            })
        );
        // A revoked issuer authority makes the chain inactive.
        let mut revoked = chain.clone();
        revoked.authority_ids = vec!["no-such-authority".into()];
        assert_eq!(
            refusal_of(&f, &revoked, &["documents:read"]).await,
            Some(ScopeRefusal::Inactive)
        );
    });
}

#[test]
fn a_token_stops_standing_once_its_delegation_person_or_key_goes() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (alice, agent, delegation) = stored_chain(&f, Value::Null).await;
        let record = DelegationTokenRecord {
            id: "token-1".into(),
            delegation_id: delegation.clone(),
            person_id: alice.clone(),
            agent_id: agent.clone(),
            key_id: "missing-key".into(),
            audience: CALENDAR.into(),
            scopes: vec!["documents:read".into()],
            session_policies: Vec::new(),
            authority_id: None,
            created_at: f.now(),
            expires_at: f.now() + 300_000.0,
            tenant_id: f.tenant_id.clone(),
            unique_key: None,
            extra: Map::new(),
        };
        let stands = |record: DelegationTokenRecord| {
            let ctx = f.iam.ctx.clone();
            let now = f.now();
            let store = f.iam.store.clone();
            async move {
                store
                    .transaction(move |tx| async move {
                        token_still_stands(&ctx, &tx, &record, now).await
                    })
                    .await
                    .unwrap()
            }
        };
        // The acting key is gone.
        assert!(!stands(record.clone()).await);
        // Another person, another delegation.
        let mut other = record.clone();
        other.person_id = f.owner_id.clone();
        assert!(!stands(other).await);
        let mut unknown = record.clone();
        unknown.delegation_id = "missing".into();
        assert!(!stands(unknown).await);
    });
}

#[test]
fn reads_claims_strictly() {
    let now = 1_700_000_000_000.0;
    let iat = now / 1000.0;
    let claims = json!({
        "iss": "https://iam.example",
        "sub": "person-1",
        "aud": CALENDAR,
        "iat": iat,
        "nbf": iat,
        "exp": iat + 300.0,
        "jti": "token-1",
        "tenant_id": "tenant-1",
        "delegation_id": "delegation-1",
        "act": delegation_actor(&["agent-a".into(), "agent-b".into()]).unwrap(),
    });
    let expected = DelegationTokenExpectations {
        issuer: vec!["https://iam.example".into()],
        audience: CALENDAR.into(),
        now,
        ..DelegationTokenExpectations::default()
    };
    match read_delegation_token_claims(&claims, &expected).unwrap() {
        DelegationTokenRead::Token(token) => {
            assert_eq!(token.agent_id, "agent-b");
            assert_eq!(token.chain, ["agent-a", "agent-b"]);
            assert!(token.scopes.is_empty());
        }
        other => panic!("expected a token, got {other:?}"),
    }
    let rejected = |changes: Value| {
        let mut changed = claims.clone();
        for (key, value) in changes.as_object().unwrap() {
            if value.get("$undefined").is_some() {
                changed.as_object_mut().unwrap().remove(key);
            } else {
                changed[key] = value.clone();
            }
        }
        match read_delegation_token_claims(&changed, &expected).unwrap() {
            DelegationTokenRead::Rejected { rejected, .. } => Some(rejected),
            DelegationTokenRead::Token(_) => None,
        }
    };
    use DelegationTokenRejection::*;
    assert_eq!(rejected(json!({ "exp": iat + 3601.0 })), Some(Lifetime));
    assert_eq!(
        rejected(json!({ "act": { "sub": "agent-a", "act": { "sub": "agent-a" } } })),
        Some(Malformed)
    );
    assert_eq!(
        rejected(json!({ "act": { "sub": "person-1" } })),
        Some(Malformed)
    );
    assert_eq!(
        rejected(json!({ "act": { "$undefined": true } })),
        Some(Malformed)
    );
    let five: Vec<String> = ["a", "b", "c", "d", "e"]
        .iter()
        .map(|id| (*id).to_owned())
        .collect();
    assert_eq!(
        rejected(json!({ "act": delegation_actor(&five).unwrap() })),
        Some(Malformed)
    );
    assert_eq!(
        rejected(json!({ "scope": "documents:read bad?scope" })),
        Some(Malformed)
    );
    assert_eq!(
        rejected(json!({ "nbf": iat + 120.0, "exp": iat + 300.0 })),
        Some(NotYetValid)
    );
    assert_eq!(rejected(json!({ "aud": [CALENDAR] })), Some(Malformed));
}

// --- tests/delegation-tokens.test.ts ---------------------------------------------------------------------------

struct Setup {
    f: Fixture,
    alice: String,
    assistant: TestAgent,
    researcher: TestAgent,
    alice_session: CredentialInput,
}

/// Acme with alice (read and write on every document) and agents with keys: an assistant that may present
/// delegations to the calendar and any docs service, and a researcher only to docs services.
async fn setup(a2a: bool) -> Setup {
    let f = organization(|options| {
        if a2a {
            options.a2a = Some(A2aOptions {
                signing_keys: vec![signing_key("card-1")],
                jwks_url: Some("https://iam.acme.test/jwks".into()),
                ..A2aOptions::default()
            });
        }
    })
    .await;
    let alice = f.member("alice").await;
    let assistant = f
        .agent(
            "Assistant",
            json!({ "tokenAudiences": [CALENDAR, "https://*.docs.example.com"] }),
            json!({}),
        )
        .await;
    let researcher = f
        .agent(
            "Researcher",
            json!({ "tokenAudiences": ["https://*.docs.example.com"] }),
            json!({}),
        )
        .await;
    f.grant(
        "Editor",
        doc(&["documents:read", "documents:write"], &["document/*"]),
        &alice,
    )
    .await;
    let alice_session = f.sign_in("alice").await;
    Setup {
        f,
        alice,
        assistant,
        researcher,
        alice_session,
    }
}

/// `actFor(who, grant)`: alice delegates to an agent, which opens a delegated session.
async fn act_for(
    f: &Fixture,
    alice_session: &CredentialInput,
    who: &TestAgent,
    grant: Value,
) -> (Value, CredentialInput) {
    let mut input = json!({ "tenantId": f.tenant_id, "agentId": who.id });
    let grant = if grant.is_null() {
        json!({ "scopes": ["documents:read", "documents:write"] })
    } else {
        grant
    };
    for (key, value) in grant.as_object().unwrap() {
        input[key] = value.clone();
    }
    let delegation = ok(f
        .iam
        .api
        .delegations
        .grant(alice_session, body(input))
        .await);
    let acting = ok(f
        .iam
        .api
        .delegations
        .assume(
            &who.key,
            body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
        )
        .await);
    (delegation, token_of(&acting))
}

async fn issue(
    f: &Fixture,
    credential: &CredentialInput,
    input: Value,
) -> Result<Value, better_iam_core::IamError> {
    let mut body_value = json!({ "tenantId": f.tenant_id, "audience": CALENDAR });
    for (key, value) in input.as_object().unwrap() {
        body_value[key] = value.clone();
    }
    governance::value(
        f.iam
            .api
            .delegations
            .issue_token(credential, body(body_value))
            .await,
    )
}

async fn live(
    f: &Fixture,
    token: &str,
    audience: &str,
) -> Result<better_iam_core::DelegationTokenSummary, better_iam_core::IamError> {
    f.iam
        .a2a
        .verify_delegation_token(token, &json!({ "audience": audience, "live": true }))
        .await
}

#[test]
#[ignore = "needs agents.create, tokenAudience, audienceMatches, assertAgentUsable (agents unit) and cardSigner, A2aRuntime.verifyDelegationToken (a2a unit)"]
fn lets_an_agent_show_another_service_with_a_signed_token_that_it_acts_for_a_person() {
    run(|| async {
        let Setup {
            f,
            alice,
            assistant,
            alice_session,
            ..
        } = setup(true).await;
        let (delegation, session) = act_for(&f, &alice_session, &assistant, Value::Null).await;
        let issued = issue(&f, &session, json!({})).await.unwrap();
        assert_matches(
            &issued,
            json!({
                "tokenType": "biam-delegation+jwt",
                "audience": CALENDAR,
                "scopes": ["documents:read", "documents:write"],
                "chain": [assistant.id],
                "expiresIn": 300,
            }),
        );
        let token = issued["token"].as_str().unwrap().to_owned();
        assert_eq!(
            header_of(&token),
            json!({ "alg": "EdDSA", "kid": "card-1", "typ": "biam-delegation+jwt", "jku": "https://iam.acme.test/jwks" })
        );
        assert_matches(
            &claims_of(&token),
            json!({
                "iss": issued["issuer"],
                "sub": alice,
                "aud": CALENDAR,
                "tenant_id": f.tenant_id,
                "delegation_id": delegation["id"],
                "act": { "sub": assistant.id },
                "scope": "documents:read documents:write",
            }),
        );
        // Inside the deployment, a live check also sees revocation before the token expires.
        assert_eq!(live(&f, &token, CALENDAR).await.unwrap().person_id, alice);
        let verified = f
            .iam
            .a2a
            .verify_delegation_token(&token, &json!({ "audience": CALENDAR }))
            .await
            .unwrap();
        assert_eq!(verified.agent_id, assistant.id);
        assert_eq!(verified.chain, std::slice::from_ref(&assistant.id));
        assert_eq!(verified.token_id, issued["tokenId"].as_str().unwrap());
        let refused = |options: Value| {
            let token = token.clone();
            let a2a = &f.iam.a2a;
            async move { refusal(a2a.verify_delegation_token(&token, &options).await).code }
        };
        assert_eq!(
            refused(json!({ "audience": FILES })).await,
            "DELEGATION_TOKEN_INVALID"
        );
        assert_eq!(
            refused(json!({ "audience": CALENDAR, "tenantId": "another-tenant" })).await,
            "DELEGATION_TOKEN_INVALID"
        );
        ok(f.iam
            .api
            .delegations
            .revoke(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await);
        assert_eq!(
            refusal(live(&f, &token, CALENDAR).await).code,
            "DELEGATION_TOKEN_INVALID"
        );
        assert_eq!(
            f.iam
                .a2a
                .verify_delegation_token(&token, &json!({ "audience": CALENDAR }))
                .await
                .unwrap()
                .agent_id,
            assistant.id
        );
        let activity = actions(&ok(f
            .iam
            .api
            .delegations
            .activity(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await));
        assert!(
            activity
                .iter()
                .any(|action| action == "delegation:token-issue")
        );
    });
}

#[test]
#[ignore = "needs agents.create, tokenAudience, audienceMatches, assertAgentUsable (agents unit) and cardSigner (a2a unit)"]
fn refuses_audiences_scopes_and_callers_outside_every_limit_on_the_session() {
    run(|| async {
        let Setup {
            f,
            assistant,
            alice_session,
            ..
        } = setup(true).await;
        let (_, session) = act_for(&f, &alice_session, &assistant, Value::Null).await;
        let code = |result: Result<Value, better_iam_core::IamError>| refusal(result).code;
        assert_eq!(
            code(
                issue(
                    &f,
                    &session,
                    json!({ "audience": "https://evil.example.com" })
                )
                .await
            ),
            "DELEGATION_NOT_ALLOWED"
        );
        assert_eq!(
            code(
                issue(
                    &f,
                    &session,
                    json!({ "audience": "https://*.docs.example.com" })
                )
                .await
            ),
            "INVALID_INPUT"
        );
        assert_eq!(
            code(issue(&f, &session, json!({ "audience": "not a uri" })).await),
            "INVALID_INPUT"
        );
        assert_eq!(
            code(issue(&f, &session, json!({ "scopes": ["billing:read"] })).await),
            "DELEGATION_NOT_ALLOWED"
        );
        // A pattern broader than the delegation's scopes, or one with ?, is refused.
        assert_eq!(
            code(issue(&f, &session, json!({ "scopes": ["documents:*"] })).await),
            "DELEGATION_NOT_ALLOWED"
        );
        assert_eq!(
            code(issue(&f, &session, json!({ "scopes": ["documents:rea?"] })).await),
            "INVALID_INPUT"
        );
        assert_eq!(
            code(issue(&f, &session, json!({ "lifetimeSeconds": 10 })).await),
            "INVALID_INPUT"
        );
        let narrow = issue(
            &f,
            &session,
            json!({ "audience": FILES, "scopes": ["documents:read"], "lifetimeSeconds": 60 }),
        )
        .await
        .unwrap();
        assert_matches(
            &narrow,
            json!({ "scopes": ["documents:read"], "expiresIn": 60 }),
        );
        // The agent's own key is not a delegation.
        assert_eq!(
            code(issue(&f, &assistant.key, json!({})).await),
            "ACCESS_DENIED"
        );
        // A key limited to reading cannot carry the delegation's write scope.
        let scoped = f
            .agent(
                "Scoped",
                json!({ "tokenAudiences": [CALENDAR] }),
                json!({ "scopes": ["documents:read"] }),
            )
            .await;
        let (_, limited) = act_for(&f, &alice_session, &scoped, Value::Null).await;
        assert_eq!(
            code(issue(&f, &limited, json!({})).await),
            "DELEGATION_NOT_ALLOWED"
        );
        assert_matches(
            &issue(&f, &limited, json!({ "scopes": ["documents:read"] }))
                .await
                .unwrap(),
            json!({ "scopes": ["documents:read"] }),
        );
        // A delegation given as a resource-limited policy carries no scopes, and cannot claim any.
        let helper = f
            .agent(
                "Team helper",
                json!({ "tokenAudiences": [CALENDAR] }),
                json!({}),
            )
            .await;
        let (_, team) = act_for(
            &f,
            &alice_session,
            &helper,
            json!({ "policy": doc(&["documents:read"], &["document/team-*"]) }),
        )
        .await;
        assert_matches(
            &issue(&f, &team, json!({})).await.unwrap(),
            json!({ "scopes": [] }),
        );
        assert_eq!(
            code(issue(&f, &team, json!({ "scopes": ["documents:read"] })).await),
            "DELEGATION_NOT_ALLOWED"
        );
        // Without token audiences an agent gets no tokens at all.
        let quiet = f.agent("Quiet", json!({}), json!({})).await;
        let (_, quiet_session) = act_for(&f, &alice_session, &quiet, Value::Null).await;
        assert_eq!(
            code(issue(&f, &quiet_session, json!({})).await),
            "DELEGATION_NOT_ALLOWED"
        );
        assert_eq!(
            err(f
                .iam
                .api
                .agents
                .update(
                    &f.owner,
                    body(json!({
                        "tenantId": f.tenant_id,
                        "agentId": quiet.id,
                        "tokenAudiences": ["https://ok.example", "with space"],
                    })),
                )
                .await)
            .code,
            "INVALID_INPUT"
        );
    });
}

#[test]
#[ignore = "needs agents.create, agents.update, tokenAudience, audienceMatches, assertAgentUsable (agents unit) and cardSigner, A2aRuntime.verifyDelegationToken (a2a unit)"]
fn names_every_agent_a_hand_off_passed_through_in_nested_act_claims() {
    run(|| async {
        let Setup {
            f,
            alice,
            assistant,
            researcher,
            alice_session,
        } = setup(true).await;
        let (delegation, session) = act_for(
            &f,
            &alice_session,
            &assistant,
            json!({ "scopes": ["documents:read", "documents:write"], "handoff": { "agents": [researcher.id] } }),
        )
        .await;
        let handoff = ok(f
            .iam
            .api
            .delegations
            .handoff(
                &session,
                body(json!({ "tenantId": f.tenant_id, "agentId": researcher.id, "scopes": ["documents:read"] })),
            )
            .await);
        let acting = token_of(&ok(f
            .iam
            .api
            .delegations
            .assume(
                &researcher.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": handoff["id"] })),
            )
            .await));
        let issued = issue(&f, &acting, json!({ "audience": FILES }))
            .await
            .unwrap();
        assert_matches(
            &issued,
            json!({ "chain": [assistant.id, researcher.id], "scopes": ["documents:read"] }),
        );
        let token = issued["token"].as_str().unwrap().to_owned();
        assert_matches(
            &claims_of(&token),
            json!({
                "sub": alice,
                "delegation_id": handoff["id"],
                "act": { "sub": researcher.id, "act": { "sub": assistant.id } },
            }),
        );
        let verified = f
            .iam
            .a2a
            .verify_delegation_token(&token, &json!({ "audience": FILES }))
            .await
            .unwrap();
        assert_eq!(verified.agent_id, researcher.id);
        assert_eq!(
            verified.chain,
            [assistant.id.clone(), researcher.id.clone()]
        );
        // The researcher may not claim more than it was handed, nor reach a service the assistant may not.
        assert_eq!(
            refusal(
                issue(
                    &f,
                    &acting,
                    json!({ "audience": FILES, "scopes": ["documents:write"] })
                )
                .await
            )
            .code,
            "DELEGATION_NOT_ALLOWED"
        );
        for (agent, audiences) in [
            (&researcher, json!([CALENDAR, "https://*.docs.example.com"])),
            (&assistant, json!(["https://*.docs.example.com"])),
        ] {
            ok(f
                .iam
                .api
                .agents
                .update(
                    &f.owner,
                    body(json!({ "tenantId": f.tenant_id, "agentId": agent.id, "tokenAudiences": audiences })),
                )
                .await);
        }
        assert_eq!(
            refusal(issue(&f, &acting, json!({})).await).code,
            "DELEGATION_NOT_ALLOWED"
        );
        // Revoking the person's own delegation ends the hand-off below it, and live checks see it.
        ok(f.iam
            .api
            .delegations
            .revoke(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await);
        assert_eq!(
            refusal(live(&f, &token, FILES).await).code,
            "DELEGATION_TOKEN_INVALID"
        );
    });
}

#[test]
#[ignore = "needs agents.create, tokenAudience (agents unit) and cardSigner (a2a unit)"]
fn needs_the_a2a_signing_keys() {
    run(|| async {
        let Setup {
            f,
            assistant,
            alice_session,
            ..
        } = setup(false).await;
        let (_, session) = act_for(&f, &alice_session, &assistant, Value::Null).await;
        assert_eq!(
            refusal(issue(&f, &session, json!({})).await).code,
            "FEATURE_DISABLED"
        );
    });
}

#[test]
#[ignore = "needs agents.create, tokenAudience, audienceMatches, assertAgentUsable (agents unit) and cardSigner (a2a unit)"]
fn never_carries_what_the_person_confirms_call_by_call_or_what_their_own_denies_may_touch() {
    run(|| async {
        let Setup {
            f,
            alice,
            assistant,
            researcher,
            alice_session,
        } = setup(true).await;
        let (_, confirmed) = act_for(
            &f,
            &alice_session,
            &assistant,
            json!({ "scopes": ["documents:read", "documents:write"], "confirm": ["documents:wri?e"] }),
        )
        .await;
        let error = refusal(issue(&f, &confirmed, json!({ "audience": FILES })).await);
        assert_eq!(error.code, "DELEGATION_NOT_ALLOWED");
        assert!(error.message.contains("confirms documents:write"));
        assert_matches(
            &issue(
                &f,
                &confirmed,
                json!({ "audience": FILES, "scopes": ["documents:read"] }),
            )
            .await
            .unwrap(),
            json!({ "scopes": ["documents:read"] }),
        );
        // A deny among alice's own grants refuses any scope it could touch, whatever its resources or conditions.
        f.grant(
            "No agent writes",
            json!({
                "version": 1,
                "statements": [{
                    "effect": "deny",
                    "actions": ["documents:write"],
                    "resources": ["document/*"],
                    "conditions": { "Bool": { "principal.delegated": true } },
                }],
            }),
            &alice,
        )
        .await;
        let (_, plain) = act_for(&f, &alice_session, &researcher, Value::Null).await;
        let error = refusal(issue(&f, &plain, json!({ "audience": FILES })).await);
        assert_eq!(error.code, "DELEGATION_NOT_ALLOWED");
        assert!(error.message.contains("deny"));
        assert_matches(
            &issue(
                &f,
                &plain,
                json!({ "audience": FILES, "scopes": ["documents:read"] }),
            )
            .await
            .unwrap(),
            json!({ "scopes": ["documents:read"] }),
        );
    });
}

#[test]
#[ignore = "needs agents.create, tokenAudience, audienceMatches, assertAgentUsable (agents unit) and cardSigner (a2a unit)"]
fn keeps_honouring_a_deny_whose_authors_authority_was_revoked() {
    run(|| async {
        let Setup {
            f,
            alice,
            researcher,
            alice_session,
            ..
        } = setup(true).await;
        let api = &f.iam.api;
        let security = f.member("security").await;
        let writer = ok(api
            .roles
            .create(
                &f.owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Security policy writer",
                    "permissions": ["iam:policies:create", "iam:policies:read"],
                })),
            )
            .await);
        ok(api
            .bindings
            .create(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "roleId": writer["id"], "subjectType": "identity", "subjectId": security })),
            )
            .await);
        let authority = ok(api
            .authorities
            .create(
                &f.owner_sign_in().await,
                body(json!({
                    "tenantId": f.tenant_id,
                    "identityId": security,
                    "ceiling": { "version": 1, "statements": [{ "effect": "allow", "actions": ["documents:*"], "resources": ["*"] }] },
                })),
            )
            .await);
        let guard = ok(api
            .policies
            .create(
                &f.sign_in("security").await,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "No agent writes",
                    "document": { "version": 1, "statements": [{ "effect": "deny", "actions": ["documents:write"], "resources": ["document/*"] }] },
                })),
            )
            .await);
        let staff = ok(api
            .roles
            .create(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "name": "Staff", "permissions": ["documents:read"] })),
            )
            .await);
        ok(api
            .roles
            .update(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "roleId": staff["id"], "policyIds": [guard["id"]] })),
            )
            .await);
        ok(api
            .bindings
            .create(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "roleId": staff["id"], "subjectType": "identity", "subjectId": alice })),
            )
            .await);
        // The security engineer leaves: their authority is revoked, but the deny they wrote still applies, so a token
        // for alice must not carry documents:write either.
        ok(api
            .authorities
            .revoke(
                &f.owner_sign_in().await,
                body(json!({ "tenantId": f.tenant_id, "authorityId": authority["id"] })),
            )
            .await);
        let (_, acting) = act_for(&f, &alice_session, &researcher, Value::Null).await;
        let error = refusal(issue(&f, &acting, json!({ "audience": FILES })).await);
        assert_eq!(error.code, "DELEGATION_NOT_ALLOWED");
        assert!(error.message.contains("deny"));
    });
}

#[test]
#[ignore = "needs agents.create, agents.update, tokenAudience, audienceMatches, assertAgentUsable (agents unit) and cardSigner, A2aRuntime.verifyDelegationToken (a2a unit)"]
fn matches_audiences_by_url_structure_quickly_and_re_checks_everything_live() {
    run(|| async {
        let Setup {
            f,
            assistant,
            alice_session,
            ..
        } = setup(true).await;
        let wide = f
            .agent(
                "Wide",
                json!({
                    "tokenAudiences": [
                        "https://*.example.com",
                        format!("urn:{}x", "*:".repeat(12)),
                        "https://api.example.org/v1/*",
                    ],
                }),
                json!({}),
            )
            .await;
        let (_, session) = act_for(&f, &alice_session, &wide, Value::Null).await;
        let to = |audience: String| json!({ "audience": audience });
        assert_matches(
            &issue(&f, &session, to("https://files.example.com".into()))
                .await
                .unwrap(),
            json!({ "audience": "https://files.example.com" }),
        );
        issue(&f, &session, to("https://api.example.org/v1/events".into()))
            .await
            .unwrap();
        for outside in [
            "https://evil.com/.example.com",
            "https://example.com",
            "https://api.example.org/v2",
        ] {
            assert_eq!(
                refusal(issue(&f, &session, to(outside.into())).await).code,
                "DELEGATION_NOT_ALLOWED"
            );
        }
        for malformed in [
            "https://evil.com#.example.com",
            "https://user@files.example.com",
            "https://files.example.com?x=1",
            "https://*.example.com",
        ] {
            assert_eq!(
                refusal(issue(&f, &session, to(malformed.into())).await).code,
                "INVALID_INPUT"
            );
        }
        // Many wildcards against a long audience finish at once (no backtracking blow-up).
        let started = std::time::Instant::now();
        assert_eq!(
            refusal(issue(&f, &session, to(format!("urn:{}y", "a:".repeat(240)))).await).code,
            "DELEGATION_NOT_ALLOWED"
        );
        assert!(started.elapsed().as_millis() < 2000);

        // Live verification re-checks the agent's key, its delegation switch, its audiences and its ceiling.
        let (_, fresh) = act_for(&f, &alice_session, &assistant, Value::Null).await;
        let first = issue(&f, &fresh, json!({})).await.unwrap()["token"]
            .as_str()
            .unwrap()
            .to_owned();
        let update = |changes: Value| {
            let mut input = json!({ "tenantId": f.tenant_id, "agentId": assistant.id });
            for (key, value) in changes.as_object().unwrap() {
                input[key] = value.clone();
            }
            let agents = f.iam.api.agents.clone();
            let owner = f.owner.clone();
            async move { ok(agents.update(&owner, body(input)).await) }
        };
        assert_eq!(
            live(&f, &first, CALENDAR).await.unwrap().agent_id,
            assistant.id
        );
        update(json!({ "tokenAudiences": ["https://*.docs.example.com"] })).await;
        assert_eq!(
            refusal(live(&f, &first, CALENDAR).await).code,
            "DELEGATION_TOKEN_INVALID"
        );
        update(json!({ "tokenAudiences": [CALENDAR] })).await;
        live(&f, &first, CALENDAR).await.unwrap();
        update(json!({ "boundary": { "version": 1, "statements": [{ "effect": "allow", "actions": ["documents:read"], "resources": ["*"] }] } })).await;
        assert_eq!(
            refusal(live(&f, &first, CALENDAR).await).code,
            "DELEGATION_TOKEN_INVALID"
        );
        update(json!({ "boundary": null })).await;
        update(json!({ "delegable": false })).await;
        assert_eq!(
            refusal(live(&f, &first, CALENDAR).await).code,
            "DELEGATION_TOKEN_INVALID"
        );
        update(json!({ "delegable": true })).await;
        live(&f, &first, CALENDAR).await.unwrap();
        let keys = ok(f
            .iam
            .api
            .credentials
            .list(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "identityId": assistant.id })),
            )
            .await);
        for key in keys.as_array().unwrap() {
            ok(f.iam
                .api
                .credentials
                .revoke(
                    &f.owner,
                    body(json!({ "tenantId": f.tenant_id, "credentialId": key["id"] })),
                )
                .await);
        }
        assert_eq!(
            refusal(live(&f, &first, CALENDAR).await).code,
            "DELEGATION_TOKEN_INVALID"
        );
        // Offline verification cannot see any of this before the token expires.
        f.iam
            .a2a
            .verify_delegation_token(&first, &json!({ "audience": CALENDAR }))
            .await
            .unwrap();
    });
}
