//! AI agents as accounts: ported from tests/agents.test.ts. Tenants, members and grants come from the organization
//! fixture (written as `tenants.create`, `identities.create`, `roles.create` and `bindings.create` write them).

mod organization_fixture;

use better_iam_core::{CredentialInput, IamResult};
use better_iam_server::options::{AuthorizationRequest, ResourceTarget};
use organization_fixture::{Org, assert_matches, bearer, body, code, fails, ok, organization, run};
use serde_json::{Value, json};

/// `doc(actions, resources = ['document/*'])`.
fn doc(actions: &[&str], resources: &[&str]) -> Value {
    json!({
        "version": 1,
        "statements": [{ "effect": "allow", "actions": actions, "resources": resources }],
    })
}

/// Grants `actions` on documents to an identity through a fresh role.
async fn grant(f: &Org, subject_id: &str, actions: &[&str]) {
    f.grant(
        subject_id,
        json!([{ "effect": "allow", "actions": actions, "resources": ["document/*"] }]),
    )
    .await;
}

fn merged(base: Value, extra: Value) -> Value {
    let mut out = base.as_object().cloned().unwrap_or_default();
    for (key, value) in extra.as_object().cloned().unwrap_or_default() {
        out.insert(key, value);
    }
    Value::Object(out)
}

async fn create_agent(f: &Org, input: Value) -> Value {
    ok(f.iam
        .api
        .agents
        .create(
            &f.owner_credential,
            body(merged(json!({ "tenantId": f.tenant_id }), input)),
        )
        .await)
}

async fn key_for(f: &Org, agent_id: &str) -> String {
    let key = ok(f
        .iam
        .api
        .credentials
        .create(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "identityId": agent_id, "name": "runtime" })),
        )
        .await);
    key["token"].as_str().unwrap().to_owned()
}

async fn agent_with_key(f: &Org, input: Value) -> (Value, String) {
    let agent = create_agent(
        f,
        merged(
            json!({
                "name": "Research assistant",
                "model": "claude-opus-5-5",
                "provider": "Anthropic",
                "purpose": "Summarizes documents",
            }),
            input,
        ),
    )
    .await;
    let token = key_for(f, agent["id"].as_str().unwrap()).await;
    (agent, token)
}

fn id_of(value: &Value) -> String {
    value["id"].as_str().unwrap().to_owned()
}

async fn authorize(f: &Org, token: &str, id: &str, action: &str) -> IamResult<bool> {
    f.iam
        .authorize(&AuthorizationRequest {
            credential: bearer(token),
            tenant_id: f.tenant_id.clone(),
            action: action.into(),
            resource: ResourceTarget {
                kind: "document".into(),
                id: id.into(),
            },
        })
        .await
        .map(|decision| decision.allowed)
}

async fn read(f: &Org, token: &str, id: &str) -> bool {
    authorize(f, token, id, "documents:read").await.unwrap()
}

async fn audit(f: &Org, filter: Value) -> Vec<Value> {
    ok(f.iam
        .api
        .audit
        .list(
            &f.owner_credential,
            body(merged(json!({ "tenantId": f.tenant_id }), filter)),
        )
        .await)
    .as_array()
    .cloned()
    .unwrap()
}

async fn agent_get(f: &Org, agent_id: &str) -> Value {
    ok(f.iam
        .api
        .agents
        .get(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "agentId": agent_id })),
        )
        .await)
}

async fn list_mine(f: &Org, credential: &CredentialInput) -> Vec<Value> {
    ok(f.iam
        .api
        .agents
        .list_mine(credential, body(json!({ "tenantId": f.tenant_id })))
        .await)
    .as_array()
    .cloned()
    .unwrap()
}

#[test]
fn registers_an_agent_with_a_sponsor_and_a_profile() {
    run(|| async {
        let f = organization(|_| {}).await;
        let agent = create_agent(
            &f,
            json!({
                "name": "Triage bot",
                "model": "claude-sonnet-5",
                "provider": "Anthropic",
                "protocols": ["MCP", "a2a", "mcp"],
                "url": "https://agents.acme.test/triage",
            }),
        )
        .await;
        assert_matches(
            &agent,
            json!({
                "name": "Triage bot",
                "status": "active",
                "standing": "ok",
                "agent": {
                    "sponsorId": f.owner_id,
                    "model": "claude-sonnet-5",
                    "provider": "anthropic",
                    "protocols": ["a2a", "mcp"],
                },
                "sponsor": { "id": f.owner_id, "email": "owner@acme.test" },
            }),
        );
        let listed = ok(f
            .iam
            .api
            .agents
            .list(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id })),
            )
            .await);
        let ids: Vec<String> = listed.as_array().unwrap().iter().map(id_of).collect();
        assert_eq!(ids, vec![id_of(&agent)]);
        let identities = ok(f
            .iam
            .api
            .identities
            .list(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id })),
            )
            .await);
        let identity = identities
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["id"] == agent["id"])
            .cloned()
            .unwrap();
        assert_eq!(identity["kind"], "agent");

        let error = fails(
            f.iam
                .api
                .agents
                .create(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "name": "Bad", "model": "has spaces" })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let error = fails(
            f.iam
                .api
                .agents
                .create(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "name": "Orphan", "sponsorId": agent["id"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_SPONSOR");
    });
}

#[test]
fn acts_through_its_own_keys_bounded_by_its_ceiling_and_exposes_agent_context_keys() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (agent, token) = agent_with_key(
            &f,
            json!({ "boundary": doc(&["documents:read"], &["document/*"]) }),
        )
        .await;
        let agent_id = id_of(&agent);
        grant(&f, &agent_id, &["documents:read", "documents:write"]).await;
        assert!(read(&f, &token, "a").await);
        // The boundary keeps the agent from writing even though its role allows it.
        assert!(!authorize(&f, &token, "a", "documents:write").await.unwrap());

        // Policies can single out agents and their model.
        let statements = json!([{
            "effect": "allow",
            "actions": ["documents:read"],
            "resources": ["document/secret"],
            "conditions": {
                "StringEquals": {
                    "principal.kind": "agent",
                    "principal.agentModel": "claude-opus-5-5",
                    "principal.agentSponsorId": f.owner_id,
                },
                "Bool": { "principal.delegated": false },
            },
        }]);
        let (other, other_token) =
            agent_with_key(&f, json!({ "name": "Other", "model": "small-model" })).await;
        for subject in [agent_id.clone(), id_of(&other)] {
            f.grant(&subject, statements.clone()).await;
        }
        assert!(read(&f, &token, "secret").await);
        assert!(!read(&f, &other_token, "secret").await);

        let caller = ok(f
            .iam
            .api
            .sts
            .get_caller_identity(&bearer(&token), body(json!({})))
            .await);
        assert_matches(
            &caller,
            json!({ "identityKind": "agent", "sessionKind": "api-key" }),
        );

        // Tightening the boundary applies at once.
        ok(f.iam
            .api
            .agents
            .update(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "agentId": agent_id,
                    "boundary": doc(&["documents:write"], &["document/none"]),
                })),
            )
            .await);
        assert!(!read(&f, &token, "a").await);
        ok(f.iam
            .api
            .agents
            .update(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent_id, "boundary": null })),
            )
            .await);
        assert!(authorize(&f, &token, "a", "documents:write").await.unwrap());
    });
}

#[test]
#[ignore = "identities.setStatus needs threats.ts endContainment (threats unit)"]
fn stops_working_while_its_sponsor_is_not_an_active_person() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let agent = create_agent(
            &f,
            json!({ "name": "Alice\u{2019}s agent", "sponsorId": alice }),
        )
        .await;
        let agent_id = id_of(&agent);
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
        grant(&f, &agent_id, &["documents:read"]).await;
        assert!(read(&f, &token, "a").await);

        ok(f.iam
            .api
            .identities
            .set_status(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "identityId": alice, "status": "disabled" })),
            )
            .await);
        let error = authorize(&f, &token, "a", "documents:read")
            .await
            .unwrap_err();
        assert_eq!(code(&error), "UNAUTHENTICATED");
        assert_eq!(
            agent_get(&f, &agent_id).await["standing"],
            "sponsor-inactive"
        );
        // Keys cannot be issued meanwhile either.
        let error = fails(
            f.iam
                .api
                .credentials
                .create(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "identityId": agent_id })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_IDENTITY");

        // Handing the agent to another sponsor brings it back.
        ok(f.iam
            .api
            .agents
            .update(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent_id, "sponsorId": f.owner_id })),
            )
            .await);
        assert!(read(&f, &token, "a").await);
    });
}

/// The same standing rules with the sponsor disabled directly in storage (no identities.setStatus), so they are
/// covered while the threats unit is not ported.
#[test]
fn refuses_the_agent_while_its_sponsor_record_is_disabled() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let agent = create_agent(&f, json!({ "name": "Alice’s agent", "sponsorId": alice })).await;
        let agent_id = id_of(&agent);
        let token = key_for(&f, &agent_id).await;
        grant(&f, &agent_id, &["documents:read"]).await;
        assert!(read(&f, &token, "a").await);
        let mut record = f
            .find(
                "identities",
                better_iam_core::Filter::new().eq("id", alice.clone()),
            )
            .await
            .remove(0);
        record.insert("status".into(), json!("disabled"));
        f.put("identities", record).await;
        let error = authorize(&f, &token, "a", "documents:read")
            .await
            .unwrap_err();
        assert_eq!(code(&error), "UNAUTHENTICATED");
        assert_eq!(error.message, "The agent’s sponsor is no longer active");
        assert_eq!(
            agent_get(&f, &agent_id).await["standing"],
            "sponsor-inactive"
        );
        let error = fails(
            f.iam
                .api
                .credentials
                .create(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "identityId": agent_id })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_IDENTITY");
        ok(f.iam
            .api
            .agents
            .update(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent_id, "sponsorId": f.owner_id })),
            )
            .await);
        assert!(read(&f, &token, "a").await);
        let changes = audit(&f, json!({ "action": "agent:sponsor-change" })).await;
        assert_matches(
            &changes[0]["metadata"],
            json!({ "from": alice, "to": f.owner_id }),
        );
    });
}

#[test]
#[ignore = "needs threats.ts endContainment and delegations.ts deleteDelegatedSessions (other units)"]
fn stops_every_agent_of_the_organization_at_once_in_an_emergency() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (first, first_token) = agent_with_key(&f, json!({ "name": "One" })).await;
        let (second, second_token) = agent_with_key(&f, json!({ "name": "Two" })).await;
        let (other, other_token) = agent_with_key(
            &f,
            json!({ "name": "Three", "provider": "openai", "model": "gpt-x" }),
        )
        .await;
        let alice_id = f.member("alice").await;
        let alice = f.sign_in(&alice_id).await;
        let error = fails(
            f.iam
                .api
                .agents
                .suspend_all(
                    &alice,
                    body(json!({ "tenantId": f.tenant_id, "reason": "Incident 42" })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");

        let result = ok(f
            .iam
            .api
            .agents
            .suspend_all(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "reason": "Incident 42",
                    "provider": "Anthropic",
                })),
            )
            .await);
        assert_eq!(result["suspended"], 2);
        let mut ids: Vec<String> = result["agentIds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_owned())
            .collect();
        ids.sort();
        let mut expected = vec![id_of(&first), id_of(&second)];
        expected.sort();
        assert_eq!(ids, expected);
        for token in [&first_token, &second_token] {
            let error = f.iam.authenticate(&bearer(token)).await.unwrap_err();
            assert_eq!(error.status, 401);
        }
        assert!(f.iam.authenticate(&bearer(&other_token)).await.is_ok());
        let events = audit(&f, json!({ "action": "agent:suspend-all" })).await;
        assert_matches(
            &events[0]["metadata"],
            json!({ "reason": "Incident 42", "suspended": 2 }),
        );
        // Already suspended agents are left as they are; the rest stop now.
        let rest = ok(f
            .iam
            .api
            .agents
            .suspend_all(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "reason": "Incident 42, all of them" })),
            )
            .await);
        assert_eq!(rest["agentIds"], json!([id_of(&other)]));
    });
}

#[test]
#[ignore = "needs threats.ts endContainment and delegations.ts deleteDelegatedSessions (other units)"]
fn gives_the_sponsor_a_kill_switch() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        let agent = create_agent(
            &f,
            json!({ "name": "Alice\u{2019}s agent", "sponsorId": alice }),
        )
        .await;
        let agent_id = id_of(&agent);
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
        grant(&f, &agent_id, &["documents:read"]).await;
        let alice_session = f.sign_in(&alice).await;
        let bob_session = f.sign_in(&bob).await;

        let mine: Vec<String> = list_mine(&f, &alice_session)
            .await
            .iter()
            .map(id_of)
            .collect();
        assert_eq!(mine, vec![agent_id.clone()]);
        assert!(list_mine(&f, &bob_session).await.is_empty());

        // Bob is neither the sponsor nor an administrator.
        let error = fails(
            f.iam
                .api
                .agents
                .suspend(
                    &bob_session,
                    body(json!({ "tenantId": f.tenant_id, "agentId": agent_id })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");

        let suspended = ok(f
            .iam
            .api
            .agents
            .suspend(
                &alice_session,
                body(json!({
                    "tenantId": f.tenant_id,
                    "agentId": agent_id,
                    "reason": "Looping on the wiki",
                })),
            )
            .await);
        assert_matches(
            &suspended,
            json!({ "status": "disabled", "standing": "suspended" }),
        );
        assert_matches(
            &suspended["agent"]["suspended"],
            json!({ "by": alice, "reason": "Looping on the wiki" }),
        );
        let error = authorize(&f, &token, "a", "documents:read")
            .await
            .unwrap_err();
        assert_eq!(code(&error), "UNAUTHENTICATED");

        let resumed = ok(f
            .iam
            .api
            .agents
            .resume(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent_id })),
            )
            .await);
        assert_eq!(resumed["standing"], "ok");
        assert!(resumed["agent"].get("suspended").is_none());
        // The key was kept.
        assert!(read(&f, &token, "a").await);

        // An administrator's suspension is theirs to lift.
        ok(f.iam
            .api
            .agents
            .suspend(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent_id })),
            )
            .await);
        let error = fails(
            f.iam
                .api
                .agents
                .resume(
                    &alice_session,
                    body(json!({ "tenantId": f.tenant_id, "agentId": agent_id })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        ok(f.iam
            .api
            .agents
            .resume(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent_id })),
            )
            .await);
        assert!(read(&f, &token, "a").await);

        let actions: Vec<String> = audit(&f, json!({}))
            .await
            .iter()
            .map(|event| event["action"].as_str().unwrap().to_owned())
            .collect();
        for wanted in ["agent:create", "agent:suspend", "agent:resume"] {
            assert!(actions.iter().any(|action| action == wanted), "{wanted}");
        }
    });
}

#[test]
#[ignore = "needs delegations.ts (grant, revokeDelegationsOf) from the delegations unit"]
fn hands_a_leaver_s_agents_to_their_successor_and_ends_their_delegations() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        let agent = create_agent(
            &f,
            json!({ "name": "Alice\u{2019}s agent", "sponsorId": alice }),
        )
        .await;
        let agent_id = id_of(&agent);
        let other = create_agent(&f, json!({ "name": "Shared agent" })).await;
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
        grant(&f, &agent_id, &["documents:read"]).await;
        let alice_session = f.sign_in(&alice).await;
        let delegation = ok(f
            .iam
            .api
            .delegations
            .grant(
                &alice_session,
                body(json!({
                    "tenantId": f.tenant_id,
                    "agentId": other["id"],
                    "scopes": ["documents:read"],
                })),
            )
            .await);

        let result = ok(f
            .iam
            .api
            .identities
            .offboard(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "identityId": alice,
                    "reason": "Left the company",
                    "successorId": bob,
                })),
            )
            .await);
        assert_matches(
            &result,
            json!({ "agentsReassigned": 1, "delegationsRevoked": 1 }),
        );
        let moved = agent_get(&f, &agent_id).await;
        assert_matches(
            &moved,
            json!({ "standing": "ok", "agent": { "sponsorId": bob } }),
        );
        assert!(read(&f, &token, "a").await);
        let fetched = ok(f
            .iam
            .api
            .delegations
            .get(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await);
        assert_eq!(fetched["status"], "revoked");

        // Without a successor the agent keeps a disabled sponsor and is refused until reassigned.
        let bob_session = f.sign_in(&bob).await;
        assert_eq!(list_mine(&f, &bob_session).await.len(), 1);
        let again = ok(f
            .iam
            .api
            .identities
            .offboard(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "identityId": bob, "reason": "Left too" })),
            )
            .await);
        assert_matches(&again, json!({ "agentsUnsponsored": 1 }));
        let error = authorize(&f, &token, "a", "documents:read")
            .await
            .unwrap_err();
        assert_eq!(code(&error), "UNAUTHENTICATED");
    });
}

fn finding_ids(findings: &[Value], kind: &str) -> Vec<String> {
    findings
        .iter()
        .filter(|finding| finding["kind"] == kind)
        .map(|finding| finding["subject"]["id"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
#[ignore = "needs delegations.ts (grant) and the analysis unit"]
fn reports_risky_agents_and_delegations_in_access_analysis() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        let orphan = create_agent(&f, json!({ "name": "Orphaned", "sponsorId": bob })).await;
        let admin = create_agent(
            &f,
            json!({ "name": "Overpowered", "boundary": doc(&["documents:read"], &["document/*"]) }),
        )
        .await;
        let open = create_agent(&f, json!({ "name": "Open" })).await;
        f.grant(
            &id_of(&admin),
            json!([{ "effect": "allow", "actions": ["*"], "resources": ["*"] }]),
        )
        .await;
        let alice_session = f.sign_in(&alice).await;
        let delegation = ok(f
            .iam
            .api
            .delegations
            .grant(
                &alice_session,
                body(json!({
                    "tenantId": f.tenant_id,
                    "agentId": open["id"],
                    "scopes": ["*"],
                    "expiresInSeconds": 365 * 86_400,
                })),
            )
            .await);
        ok(f.iam
            .api
            .identities
            .set_status(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "identityId": bob, "status": "disabled" })),
            )
            .await);
        f.advance(91.0 * 86_400_000.0);
        let owner = f.sign_in(&f.owner_id).await;
        let result = ok(f
            .iam
            .api
            .analysis
            .findings(&owner, body(json!({ "tenantId": f.tenant_id })))
            .await);
        let findings = result["findings"].as_array().cloned().unwrap();
        assert_eq!(
            finding_ids(&findings, "agent-without-sponsor"),
            vec![id_of(&orphan)]
        );
        assert_eq!(finding_ids(&findings, "agent-admin"), vec![id_of(&admin)]);
        assert_eq!(
            finding_ids(&findings, "unbounded-agent"),
            vec![id_of(&open)]
        );
        assert_eq!(
            finding_ids(&findings, "broad-delegation"),
            vec![id_of(&delegation)]
        );
        assert_eq!(
            finding_ids(&findings, "unused-delegation"),
            vec![id_of(&delegation)]
        );
        let broad = findings
            .iter()
            .find(|finding| finding["kind"] == "broad-delegation")
            .unwrap();
        assert_eq!(broad["subject"]["name"], "alice@acme.test \u{2192} Open");
        assert!(!alice.is_empty());
    });
}

#[test]
#[ignore = "needs delegations.ts (grant) and the analysis unit"]
fn reports_agents_refused_over_and_over_and_delegations_handed_on_to_any_agent() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let (looping, looping_token) = agent_with_key(&f, json!({ "name": "Looping" })).await;
        for index in 0..20 {
            authorize(&f, &looping_token, &format!("d{index}"), "documents:read")
                .await
                .unwrap();
        }
        let (handy, _) = agent_with_key(&f, json!({ "name": "Handy" })).await;
        let alice_session = f.sign_in(&alice).await;
        let delegation = ok(f
            .iam
            .api
            .delegations
            .grant(
                &alice_session,
                body(json!({
                    "tenantId": f.tenant_id,
                    "agentId": handy["id"],
                    "scopes": ["documents:read"],
                    "handoff": { "depth": 2 },
                })),
            )
            .await);
        let owner = f.sign_in(&f.owner_id).await;
        let result = ok(f
            .iam
            .api
            .analysis
            .findings(&owner, body(json!({ "tenantId": f.tenant_id })))
            .await);
        let findings = result["findings"].as_array().cloned().unwrap();
        let denials: Vec<&Value> = findings
            .iter()
            .filter(|finding| finding["kind"] == "agent-denials")
            .collect();
        assert_eq!(
            denials
                .iter()
                .map(|finding| finding["subject"]["id"].clone())
                .collect::<Vec<_>>(),
            vec![looping["id"].clone()]
        );
        assert!(
            denials[0]["title"]
                .as_str()
                .unwrap()
                .contains("refused 20 times")
        );
        let open: Vec<Value> = findings
            .iter()
            .filter(|finding| finding["kind"] == "open-handoff")
            .map(|finding| json!([finding["subject"]["id"], finding["severity"]]))
            .collect();
        assert_eq!(open, vec![json!([delegation["id"], "medium"])]);
    });
}

#[test]
fn enforces_the_tenant_agent_limit() {
    run(|| async {
        let f = organization(|_| {}).await;
        ok(f.iam
            .api
            .tenants
            .set_limits(
                &f.root_credential,
                body(json!({ "tenantId": f.tenant_id, "limits": { "agents": 1 } })),
            )
            .await);
        create_agent(&f, json!({ "name": "One" })).await;
        let error = fails(
            f.iam
                .api
                .agents
                .create(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "name": "Two" })),
                )
                .await,
        );
        assert_eq!(code(&error), "LIMIT_EXCEEDED");
    });
}

/// The audience rules `delegations.issueToken` relies on (agents.ts `audienceMatches`, `tokenAudienceList`,
/// `tokenAudience`).
#[test]
fn matches_token_audiences_by_url_structure() {
    use better_iam_server::agents::{audience_matches, token_audience, token_audience_list};
    assert!(audience_matches(
        "https://api.example.com",
        "https://api.example.com"
    ));
    assert!(audience_matches(
        "https://api.example.com",
        "HTTPS://API.example.com/"
    ));
    assert!(audience_matches(
        "https://*.example.com",
        "https://a.b.example.com"
    ));
    assert!(!audience_matches(
        "https://*.example.com",
        "https://example.com"
    ));
    assert!(audience_matches(
        "https://*.example.com/v1/*",
        "https://a.example.com/v1/x/y"
    ));
    assert!(!audience_matches(
        "https://*.example.com/v1/*",
        "https://a.example.com/v2/x"
    ));
    assert!(!audience_matches(
        "https://api.example.com:8443",
        "https://api.example.com"
    ));
    assert!(!audience_matches(
        "https://api.example.com",
        "http://api.example.com"
    ));
    assert!(!audience_matches(
        "https://*.example.com",
        "https://*.example.com"
    ));
    assert!(!audience_matches(
        "https://api.example.com/*",
        "https://api.example.com.evil.test/"
    ));
    assert!(audience_matches("urn:example:*", "urn:example:api"));
    assert!(!audience_matches("urn:example:*", "https://example.com"));
    assert!(!audience_matches(
        "urn:*",
        &format!("urn:{}", "a".repeat(600))
    ));
    assert_eq!(
        token_audience_list(
            Some(&json!([
                "urn:b:api",
                "https://*.example.com/v1/*",
                "urn:b:api"
            ])),
            None
        )
        .unwrap(),
        vec!["https://*.example.com/v1/*", "urn:b:api"]
    );
    let error = token_audience_list(Some(&json!(["https://user@example.com"])), None).unwrap_err();
    assert_eq!(
        error.message,
        "tokenAudiences must list at most 16 absolute URIs (such as https://api.example.com, https://*.example.com or urn:example:api)"
    );
    assert_eq!(
        token_audience(Some(&json!("https://api.example.com/x"))).unwrap(),
        "https://api.example.com/x"
    );
    assert_eq!(
        code(&token_audience(Some(&json!("https://*.example.com"))).unwrap_err()),
        "INVALID_INPUT"
    );
}
