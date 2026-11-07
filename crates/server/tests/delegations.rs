//! Delegations to AI agents: the port of tests/delegations.test.ts, tests/delegation-handoffs.test.ts and
//! tests/delegation-spend.test.ts, plus checks of the module's helpers (delegations.ts) that run on their own.
//!
//! The end-to-end suites create agents with `agents.create` and rely on `agentStanding` / `assertAgentUsable`
//! (agents unit) for every grant, assume and delegated decision, and the spending suite on the inference gateway
//! (inference unit); until those land they are `#[ignore]`d with that reason. Everything that works without them
//! runs.

mod delegation_support;
mod governance;

use better_iam_auth::templates::{
    DelegationLink, RenderInput, TemplateOptions, render_delivery_message,
};
use better_iam_core::{IamStoreExt, PolicyDocument};
use better_iam_server::delegations::{
    Delegation, actions_may_overlap, confirm_patterns, delegation_seconds, handoff_setting,
    policy_allows_scope, revoke_delegations_of, spend_setting,
};
use better_iam_server::options::Toggle;
use delegation_support::{
    Fixture, TestAgent, actions, assert_matches, doc, id_of, ids, organization, refusal, token_of,
};
use governance::{DAY, body, err, ok, run};
use serde_json::{Value, json};

const AGENTS: &str = "needs agents.create, agentStanding and assertAgentUsable (agents unit)";
const AGENTS_AND_INFERENCE: &str = "needs agents.create, agentStanding and assertAgentUsable (agents unit) and the inference gateway (inference unit)";

fn policy(value: Value) -> PolicyDocument {
    PolicyDocument::from_value(&value).expect("a valid policy")
}

// --- delegations.ts helpers ----------------------------------------------------------------------------------------

#[test]
fn spend_settings_need_a_known_period_and_a_limit() {
    let valid = spend_setting(Some(
        &json!({ "period": "day", "maxRequests": 3, "maxCostUsd": 1 }),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(valid.period, "day");
    assert_eq!(valid.max_requests, Some(3.0));
    assert_eq!(valid.max_cost_micros, Some(1_000_000.0));
    assert_eq!(spend_setting(None).unwrap(), None);
    assert_eq!(spend_setting(Some(&Value::Null)).unwrap(), None);
    // The validation cases of 'is set, changed or removed by the person, and validated'.
    for spend in [
        json!({ "period": "week", "maxRequests": 1 }),
        json!({ "period": "day" }),
        json!({ "period": "day", "maxCostUsd": 0 }),
        json!({ "period": "day", "maxCostUsd": 0.0000001 }),
        json!({ "period": "day", "maxTokens": 1.5 }),
        json!("day"),
    ] {
        let error = spend_setting(Some(&spend)).unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT", "{spend}");
    }
    assert_eq!(
        spend_setting(Some(&json!({ "period": "day" })))
            .unwrap_err()
            .message,
        "spend needs maxTokens, maxCostUsd or maxRequests"
    );
    assert_eq!(
        spend_setting(Some(&json!({ "period": "week" })))
            .unwrap_err()
            .message,
        "spend.period must be 'minute', 'hour', 'day' or 'month'"
    );
}

#[test]
fn confirm_lists_are_action_patterns() {
    assert_eq!(confirm_patterns(None).unwrap(), None);
    assert_eq!(confirm_patterns(Some(&json!([]))).unwrap(), None);
    assert_eq!(
        confirm_patterns(Some(&json!([
            "documents:write",
            "billing:*",
            "documents:write"
        ])))
        .unwrap(),
        Some(vec!["documents:write".to_owned(), "billing:*".to_owned()])
    );
    assert_eq!(
        confirm_patterns(Some(&json!(["bad pattern"])))
            .unwrap_err()
            .message,
        "Invalid action pattern bad pattern"
    );
    let many: Vec<String> = (0..51).map(|index| format!("a:{index}")).collect();
    assert_eq!(
        confirm_patterns(Some(&json!(many))).unwrap_err().message,
        "confirm may list at most 50 actions"
    );
    assert_eq!(
        confirm_patterns(Some(&json!("documents:write")))
            .unwrap_err()
            .message,
        "Invalid confirm"
    );
}

#[test]
fn lifetimes_stay_within_bounds() {
    assert_eq!(delegation_seconds(None).unwrap(), 30.0 * 86_400.0);
    assert_eq!(delegation_seconds(Some(&json!(86_400))).unwrap(), 86_400.0);
    for value in [json!(299), json!(365 * 86_400 + 1), json!("1"), Value::Null] {
        assert_eq!(
            delegation_seconds(Some(&value)).unwrap_err().message,
            "Invalid expiresInSeconds"
        );
    }
}

#[test]
fn scopes_are_judged_conservatively() {
    // The person's confirm patterns and deny statements touch any scope they might match.
    assert!(actions_may_overlap("documents:wri?e", "documents:write"));
    assert!(actions_may_overlap("documents:write", "documents:*"));
    assert!(actions_may_overlap("documents:*", "documents:read"));
    assert!(actions_may_overlap("${principal.x}", "documents:read"));
    assert!(!actions_may_overlap("billing:*", "documents:*"));
    assert!(!actions_may_overlap("documents:write", "documents:read"));
    assert!(!actions_may_overlap("*:write", "documents:*read"));

    let scopes = policy(json!({
        "version": 1,
        "statements": [{ "effect": "allow", "actions": ["documents:read", "documents:write"], "resources": ["*"] }],
    }));
    assert!(policy_allows_scope(&scopes, "documents:read"));
    // A pattern broader than the delegation's scopes is not allowed outright.
    assert!(!policy_allows_scope(&scopes, "documents:*"));
    assert!(!policy_allows_scope(&scopes, "billing:read"));
    let wildcard = policy(json!({
        "version": 1,
        "statements": [{ "effect": "allow", "actions": ["documents:*"], "resources": ["*"] }],
    }));
    assert!(policy_allows_scope(&wildcard, "documents:*"));
    let question = policy(json!({
        "version": 1,
        "statements": [{ "effect": "allow", "actions": ["documents:rea?"], "resources": ["*"] }],
    }));
    assert!(policy_allows_scope(&question, "documents:read"));
    assert!(!policy_allows_scope(&question, "documents:*"));
    // Resource-limited, conditional or denied scopes do not count.
    assert!(!policy_allows_scope(
        &policy(doc(&["documents:read"], &["document/team-*"])),
        "documents:read"
    ));
    let conditional = policy(json!({
        "version": 1,
        "statements": [{
            "effect": "allow",
            "actions": ["documents:read"],
            "resources": ["*"],
            "conditions": { "Bool": { "principal.delegated": true } },
        }],
    }));
    assert!(!policy_allows_scope(&conditional, "documents:read"));
    let denied = policy(json!({
        "version": 1,
        "statements": [
            { "effect": "allow", "actions": ["*"], "resources": ["*"] },
            { "effect": "deny", "actions": ["documents:write"], "resources": ["document/secret"] },
        ],
    }));
    assert!(policy_allows_scope(&denied, "documents:read"));
    assert!(!policy_allows_scope(&denied, "documents:write"));
    assert!(!policy_allows_scope(&denied, "documents:*"));
}

#[test]
fn hand_off_settings_name_agents_of_the_tenant() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let agent_id = better_iam_server::utils::id();
        f.insert(
            "identities",
            json!({
                "id": agent_id,
                "tenantId": f.tenant_id,
                "kind": "agent",
                "agent": { "sponsorId": f.owner_id },
                "name": "Assistant",
                "status": "active",
                "emailVerified": false,
                "rootAdmin": false,
                "owner": false,
                "createdAt": f.now(),
            }),
        )
        .await;
        let tx = f.iam.store.clone();
        let tenant = f.tenant_id.clone();
        assert_eq!(handoff_setting(&tx, &tenant, None).await.unwrap(), None);
        assert_eq!(
            handoff_setting(&tx, &tenant, Some(&Value::Null))
                .await
                .unwrap(),
            None
        );
        let plain = handoff_setting(&tx, &tenant, Some(&json!({})))
            .await
            .unwrap()
            .unwrap();
        assert_eq!((plain.depth, plain.agents), (1.0, None));
        let named = handoff_setting(
            &tx,
            &tenant,
            Some(&json!({ "agents": [agent_id, agent_id], "depth": 2 })),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(named.agents, Some(vec![agent_id.clone()]));
        assert_eq!(named.depth, 2.0);
        for (setting, message) in [
            (
                json!({ "agents": ["not-an-agent"] }),
                "handoff.agents: not-an-agent is not an agent of this tenant".to_owned(),
            ),
            (
                json!({ "agents": [alice] }),
                format!("handoff.agents: {alice} is not an agent of this tenant"),
            ),
            (json!({ "depth": 4 }), "Invalid handoff.depth".to_owned()),
            (
                json!({ "agents": [] }),
                "handoff.agents must name 1 to 20 agents".to_owned(),
            ),
        ] {
            let error = handoff_setting(&tx, &tenant, Some(&setting))
                .await
                .unwrap_err();
            assert_eq!(
                (error.code.as_str(), error.message),
                ("INVALID_INPUT", message)
            );
        }
    });
}

#[test]
fn ending_an_identity_revokes_its_delegations_hand_offs_and_sessions() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let now = f.now();
        let delegation = |id: &str, status: &str, parent: Option<&str>| {
            let mut record = json!({
                "id": id,
                "tenantId": f.tenant_id,
                "agentId": format!("agent-{id}"),
                "subjectId": alice,
                "status": status,
                "policy": doc(&["documents:read"], &["*"]),
                "requestedBy": "subject",
                "createdAt": now,
                "expiresAt": now + DAY,
            });
            if let Some(parent) = parent {
                record["parentId"] = json!(parent);
                record["requestedBy"] = json!("handoff");
            }
            record
        };
        f.insert("delegations", delegation("direct", "active", None))
            .await;
        f.insert(
            "delegations",
            delegation("handed", "active", Some("direct")),
        )
        .await;
        f.insert(
            "delegations",
            delegation("deeper", "active", Some("handed")),
        )
        .await;
        f.insert("delegations", delegation("refused", "denied", None))
            .await;
        for (session, delegation_id) in [("s1", "direct"), ("s2", "deeper")] {
            f.insert(
                "sessions",
                json!({
                    "id": session,
                    "tenantId": f.tenant_id,
                    "identityId": alice,
                    "kind": "delegated",
                    "agentId": format!("agent-{delegation_id}"),
                    "delegationId": delegation_id,
                    "tokenHash": format!("hash-{session}"),
                    "createdAt": now,
                    "lastSeenAt": now,
                    "authenticatedAt": now,
                    "expiresAt": now + 900_000.0,
                    "mfa": false,
                }),
            )
            .await;
        }
        let ctx = f.iam.ctx.clone();
        let identity = json!({ "id": alice, "tenantId": f.tenant_id });
        let ended = f
            .iam
            .store
            .transaction(move |tx| async move {
                revoke_delegations_of(&ctx, &tx, &identity, "administrator").await
            })
            .await
            .unwrap();
        assert_eq!(ended, 3.0);
        for id in ["direct", "handed", "deeper"] {
            let record = f.get("delegations", id).await.unwrap();
            assert_eq!(record["status"], json!("revoked"), "{id}");
            assert_eq!(record["revokedBy"], json!("administrator"));
            assert_eq!(record["revokedAt"], governance::num(now));
            assert_eq!(record["sessionsRevokedBefore"], governance::num(now + 1.0));
            // The typed view still reads the record.
            let _: Delegation = better_iam_server::port::decode(record).unwrap();
        }
        assert_eq!(
            f.get("delegations", "refused").await.unwrap()["status"],
            json!("denied")
        );
        assert!(f.get("sessions", "s1").await.is_none());
        assert!(f.get("sessions", "s2").await.is_none());
    });
}

// --- the delegations API without agents -------------------------------------------------------------------------

#[test]
fn validates_input_and_refuses_people_and_machines_that_are_not_agents() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let alice_session = f.sign_in("alice").await;
        let api = &f.iam.api.delegations;
        let missing = err(api
            .grant(
                &alice_session,
                body(json!({ "agentId": alice, "scopes": ["documents:read"] })),
            )
            .await);
        assert_eq!(
            (missing.code.as_str(), missing.message.as_str()),
            ("INVALID_INPUT", "Invalid tenantId")
        );
        // A service account as `serviceAccounts.create` stores it (that call reaches the package automation of
        // another unit).
        let service = better_iam_server::utils::id();
        f.insert(
            "identities",
            json!({
                "id": service,
                "tenantId": f.tenant_id,
                "kind": "service",
                "name": "ci",
                "status": "active",
                "emailVerified": false,
                "rootAdmin": false,
                "owner": false,
                "createdAt": f.now(),
            }),
        )
        .await;
        for agent_id in [service, alice.clone()] {
            let refused = err(api
                .grant(
                    &alice_session,
                    body(json!({ "tenantId": f.tenant_id, "agentId": agent_id, "scopes": ["documents:read"] })),
                )
                .await);
            assert_eq!((refused.code.as_str(), refused.status), ("NOT_FOUND", 404));
            assert_eq!(refused.message, "Agent not found");
        }
        // A request needs exactly one way to name the person.
        let both = err(api
            .request(
                &alice_session,
                body(json!({
                    "tenantId": f.tenant_id,
                    "subjectId": alice,
                    "subjectEmail": "alice@acme.test",
                    "reason": "x",
                    "scopes": ["documents:read"],
                })),
            )
            .await);
        assert_eq!(both.message, "Provide either subjectId or subjectEmail");
        // Only an agent's own key asks.
        let person = err(api
            .request(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "subjectId": alice, "reason": "x", "scopes": ["documents:read"] })),
            )
            .await);
        assert_eq!(
            (person.code.as_str(), person.status),
            ("ACCESS_DENIED", 403)
        );
        // A person's own lists start empty.
        assert_eq!(
            ok(api
                .list_mine(&alice_session, body(json!({ "tenantId": f.tenant_id })))
                .await),
            json!([])
        );
        assert_eq!(
            ok(api
                .list_confirmations(&alice_session, body(json!({ "tenantId": f.tenant_id })))
                .await),
            json!([])
        );
        assert_eq!(
            ok(api
                .list(&f.owner, body(json!({ "tenantId": f.tenant_id })))
                .await),
            json!([])
        );
        // Unknown delegations are not found, for administrators too.
        let unknown = err(api
            .get(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "delegationId": "missing" })),
            )
            .await);
        assert_eq!(unknown.code, "NOT_FOUND");
        let unknown = err(api
            .get_confirmation(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "confirmationId": "missing" })),
            )
            .await);
        assert_eq!(unknown.message, "Confirmation request not found");
        let not_boolean = err(api
            .decide_confirmation(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "confirmationId": "missing", "approve": "yes" })),
            )
            .await);
        assert_eq!(not_boolean.message, "approve must be a boolean");
        // Hand-offs and confirmation requests come from delegated sessions only.
        let handoff = err(api
            .handoff(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "agentId": alice, "scopes": ["documents:read"] })),
            )
            .await);
        assert_eq!(
            (handoff.code.as_str(), handoff.status),
            ("ACCESS_DENIED", 403)
        );
        let confirm = err(api
            .request_confirmation(
                &alice_session,
                body(json!({
                    "tenantId": f.tenant_id,
                    "action": "documents:write",
                    "resource": { "type": "document", "id": "report" },
                    "reason": "x",
                })),
            )
            .await);
        assert_eq!(
            confirm.message,
            "Only an agent acting for a person can ask them to confirm an action"
        );
        // Impersonation never manages delegations, and a person's session is no agent key.
        let assume = err(api
            .assume(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": "missing" })),
            )
            .await);
        assert_eq!(
            assume.message,
            "Only an agent using its own API key can do this"
        );
    });
}

#[test]
fn administrators_list_and_revoke_delegations_stored_by_any_server() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let now = f.now();
        // A delegation as the TypeScript server writes it (the agent is gone; summaries fall back to its ID).
        f.insert(
            "delegations",
            json!({
                "id": "dlg-1",
                "tenantId": f.tenant_id,
                "agentId": "agent-1",
                "subjectId": alice,
                "status": "active",
                "policy": { "version": 1, "statements": [{ "sid": "DelegationScopes", "effect": "allow", "actions": ["documents:read"], "resources": ["*"] }] },
                "scopes": ["documents:read"],
                "requestedBy": "subject",
                "createdAt": now,
                "decidedAt": now,
                "expiresAt": now + DAY,
                "confirm": ["documents:write"],
                "handoff": { "agents": ["agent-2"], "depth": 2 },
            }),
        )
        .await;
        let api = &f.iam.api.delegations;
        let listed = ok(api
            .list(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "agentId": "agent-1" })),
            )
            .await);
        assert_eq!(
            listed,
            json!([{
                "id": "dlg-1",
                "tenantId": f.tenant_id,
                "status": "active",
                "expired": false,
                "agent": { "id": "agent-1", "name": "agent-1" },
                "subject": { "id": alice, "name": "alice", "email": "alice@acme.test" },
                "policy": { "version": 1, "statements": [{ "sid": "DelegationScopes", "effect": "allow", "actions": ["documents:read"], "resources": ["*"] }] },
                "requestedBy": "subject",
                "createdAt": governance::num(now),
                "expiresAt": governance::num(now + DAY),
                "scopes": ["documents:read"],
                "decidedAt": governance::num(now),
                "confirm": ["documents:write"],
                "handoff": { "depth": 2, "agents": ["agent-2"] },
            }])
        );
        // Alice sees it; another member does not.
        let alice_session = f.sign_in("alice").await;
        assert_eq!(
            ids(&ok(api
                .list_mine(&alice_session, body(json!({ "tenantId": f.tenant_id })))
                .await)),
            vec!["dlg-1".to_owned()]
        );
        f.member("mallory").await;
        let mallory = f.sign_in("mallory").await;
        let refused = err(api
            .get(
                &mallory,
                body(json!({ "tenantId": f.tenant_id, "delegationId": "dlg-1" })),
            )
            .await);
        assert_eq!(refused.code, "ACCESS_DENIED");
        // The person revokes; revoking twice is refused.
        let revoked = ok(api
            .revoke(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": "dlg-1", "reason": "done" })),
            )
            .await);
        assert_matches(
            &revoked,
            json!({ "status": "revoked", "revokedBy": alice, "revokedAt": governance::num(now) }),
        );
        let again = err(api
            .revoke(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "delegationId": "dlg-1" })),
            )
            .await);
        assert_eq!(
            (again.code.as_str(), again.message.as_str()),
            ("INVALID_TRANSITION", "The delegation is already revoked")
        );
        let audit = ok(f
            .iam
            .api
            .audit
            .list(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "action": "delegation:revoke" })),
            )
            .await);
        assert_matches(
            &audit[0],
            json!({
                "actorId": alice,
                "resourceId": "dlg-1",
                "outcome": "allow",
                "metadata": { "agentId": "agent-1", "subjectId": alice, "sessionsEnded": 0, "reason": "done" },
            }),
        );
        assert!(audit[0]["metadata"].get("handoffsRevoked").is_none());
    });
}

// --- tests/delegations.test.ts ---------------------------------------------------------------------------------

struct Setup {
    f: Fixture,
    alice: String,
    agent: TestAgent,
    alice_session: better_iam_core::CredentialInput,
}

/// Acme with alice (documents:read and documents:write on every document) and an agent sponsored by the owner with
/// its own key but no grants of its own.
async fn setup(agent_input: Value) -> Setup {
    let f = organization(|_| {}).await;
    let alice = f.member("alice").await;
    f.grant(
        "Editor",
        doc(&["documents:read", "documents:write"], &["document/*"]),
        &alice,
    )
    .await;
    let mut profile = json!({ "model": "claude-sonnet-5" });
    for (key, value) in agent_input.as_object().cloned().unwrap_or_default() {
        profile[key] = value;
    }
    let agent = f.agent("Inbox agent", profile, json!({})).await;
    let alice_session = f.sign_in("alice").await;
    Setup {
        f,
        alice,
        agent,
        alice_session,
    }
}

#[test]
#[ignore = "needs agents.create, agentStanding and assertAgentUsable (agents unit)"]
fn lets_a_person_delegate_part_of_their_access_to_an_agent() {
    let _ = AGENTS;
    run(|| async {
        let Setup {
            f,
            alice,
            agent,
            alice_session,
        } = setup(json!({})).await;
        let api = &f.iam.api.delegations;
        // Without a delegation the agent has nothing.
        assert!(!f.allowed(&agent.key, "documents:read", "a").await.unwrap());
        let delegation = ok(api
            .grant(
                &alice_session,
                body(json!({
                    "tenantId": f.tenant_id,
                    "agentId": agent.id,
                    "scopes": ["documents:read"],
                    "expiresInSeconds": 86_400,
                })),
            )
            .await);
        assert_matches(
            &delegation,
            json!({
                "status": "active",
                "requestedBy": "subject",
                "scopes": ["documents:read"],
                "agent": { "id": agent.id, "name": "Inbox agent", "model": "claude-sonnet-5" },
                "subject": { "id": alice, "email": "alice@acme.test" },
            }),
        );
        let credential = ok(api
            .assume(
                &agent.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"], "sessionName": "triage-run" })),
            )
            .await);
        assert_eq!(
            better_iam_auth::crypto::parse_credential_token(credential["token"].as_str().unwrap())
                .map(|kind| kind.as_str()),
            Some("dlg")
        );
        assert_matches(
            &credential["session"],
            json!({
                "kind": "delegated",
                "identityId": alice,
                "agentId": agent.id,
                "delegationId": delegation["id"],
                "sessionName": "triage-run",
            }),
        );
        assert_eq!(credential["expiresIn"], json!(900));
        let token = token_of(&credential);
        // Alice's access, narrowed to the scope.
        assert!(f.allowed(&token, "documents:read", "a").await.unwrap());
        assert!(!f.allowed(&token, "documents:write", "a").await.unwrap());
        let caller = ok(f
            .iam
            .api
            .sts
            .get_caller_identity(&token, body(json!({})))
            .await);
        assert_matches(
            &caller,
            json!({
                "identityId": alice,
                "sessionKind": "delegated",
                "agentId": agent.id,
                "delegationId": delegation["id"],
            }),
        );
        // The audit trail names the person, the agent and the delegation.
        let _ = f.allowed(&token, "documents:write", "b").await;
        let denials = ok(f
            .iam
            .api
            .audit
            .list(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "action": "documents:write" })),
            )
            .await);
        assert_matches(
            &denials[0],
            json!({
                "actorId": alice,
                "outcome": "deny",
                "sessionContext": { "kind": "delegated", "agentId": agent.id, "delegationId": delegation["id"] },
            }),
        );
        assert_eq!(
            ids(&ok(api
                .list_mine(&alice_session, body(json!({ "tenantId": f.tenant_id })))
                .await)),
            vec![id_of(&delegation)]
        );
        let mine = ok(api
            .list_mine(&agent.key, body(json!({ "tenantId": f.tenant_id })))
            .await);
        assert_eq!(mine[0]["id"], delegation["id"]);
        assert!(mine[0]["lastUsedAt"].is_number());
    });
}

#[test]
#[ignore = "needs agents.create, agentStanding and assertAgentUsable (agents unit)"]
fn shows_the_person_and_the_sponsor_what_the_agent_did() {
    run(|| async {
        let Setup {
            f,
            alice,
            agent,
            alice_session,
        } = setup(json!({})).await;
        let api = &f.iam.api.delegations;
        let delegation = ok(api
            .grant(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent.id, "scopes": ["documents:read"] })),
            )
            .await);
        let token = token_of(&ok(api
            .assume(
                &agent.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await));
        // One denied action for alice, one denied action with the agent's own key.
        assert!(
            !f.allowed(&token, "documents:write", "secret")
                .await
                .unwrap()
        );
        assert!(
            !f.allowed(&agent.key, "documents:read", "own")
                .await
                .unwrap()
        );
        let for_alice = ok(api
            .activity(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await);
        // Newest first; events in the same millisecond may come in either order.
        let mut seen = actions(&for_alice);
        seen.sort();
        assert_eq!(
            seen,
            ["delegation:assume", "delegation:grant", "documents:write"]
        );
        let write = for_alice
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["action"] == json!("documents:write"))
            .unwrap();
        assert_matches(
            write,
            json!({ "actorId": alice, "resourceId": "secret", "outcome": "deny" }),
        );
        // The owner sponsors the agent: they see both, through their own session.
        let by_sponsor = ok(f
            .iam
            .api
            .agents
            .activity(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent.id })),
            )
            .await);
        let pairs: Vec<(Value, Value)> = by_sponsor
            .as_array()
            .unwrap()
            .iter()
            .map(|event| (event["action"].clone(), event["resourceId"].clone()))
            .collect();
        for expected in [
            (json!("documents:read"), json!("own")),
            (json!("documents:write"), json!("secret")),
            (json!("delegation:assume"), delegation["id"].clone()),
        ] {
            assert!(pairs.contains(&expected), "{expected:?}");
        }
        assert!(by_sponsor.as_array().unwrap().iter().all(|event| {
            event["actorId"] == json!(agent.id)
                || event["sessionContext"]["agentId"] == json!(agent.id)
        }));
        // Another member sees neither.
        f.member("mallory").await;
        let mallory = f.sign_in("mallory").await;
        assert_eq!(
            err(api
                .activity(
                    &mallory,
                    body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] }))
                )
                .await)
            .code,
            "ACCESS_DENIED"
        );
        assert_eq!(
            err(f
                .iam
                .api
                .agents
                .activity(
                    &mallory,
                    body(json!({ "tenantId": f.tenant_id, "agentId": agent.id }))
                )
                .await)
            .code,
            "ACCESS_DENIED"
        );
    });
}

#[test]
#[ignore = "needs agents.create, agentStanding and assertAgentUsable (agents unit)"]
fn holds_back_sensitive_actions_until_the_person_confirms_each_one() {
    run(|| async {
        let Setup {
            f,
            alice,
            agent,
            alice_session,
        } = setup(json!({})).await;
        let api = &f.iam.api.delegations;
        let delegation = ok(api
            .grant(
                &alice_session,
                body(json!({
                    "tenantId": f.tenant_id,
                    "agentId": agent.id,
                    "scopes": ["documents:*"],
                    "confirm": ["documents:write"],
                })),
            )
            .await);
        assert_eq!(delegation["confirm"], json!(["documents:write"]));
        let acting = token_of(&ok(api
            .assume(
                &agent.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await));
        assert!(
            f.allowed(&acting, "documents:read", "report")
                .await
                .unwrap()
        );
        assert!(
            !f.allowed(&acting, "documents:write", "report")
                .await
                .unwrap()
        );
        let ask = |credential: better_iam_core::CredentialInput,
                   action: &str,
                   reason: &str,
                   extra: Value| {
            let mut input = json!({
                "tenantId": f.tenant_id,
                "action": action,
                "resource": { "type": "document", "id": "report" },
                "reason": reason,
            });
            for (key, value) in extra.as_object().cloned().unwrap_or_default() {
                input[key] = value;
            }
            let api = f.iam.api.delegations.clone();
            async move { api.request_confirmation(&credential, body(input)).await }
        };
        // Reading needs no confirmation, so asking for it is refused.
        assert_eq!(
            err(ask(acting.clone(), "documents:read", "x", json!({})).await).code,
            "INVALID_INPUT"
        );
        // Only the delegated session may ask.
        assert_eq!(
            err(ask(agent.key.clone(), "documents:write", "x", json!({})).await).code,
            "ACCESS_DENIED"
        );
        let request = ok(ask(
            acting.clone(),
            "documents:write",
            "Fix the typo in the summary you asked about",
            json!({ "validSeconds": 120 }),
        )
        .await);
        assert_matches(
            &request,
            json!({
                "status": "pending",
                "action": "documents:write",
                "resource": { "type": "document", "id": "report" },
                "agent": { "id": agent.id, "name": "Inbox agent" },
                "subjectId": alice,
            }),
        );
        // Asking again returns the same pending request.
        assert_eq!(
            ok(ask(acting.clone(), "documents:write", "again", json!({})).await)["id"],
            request["id"]
        );
        let inbox = f.inbox().await;
        let email = inbox
            .iter()
            .find(|message| message.template == "delegation-confirmation")
            .expect("the confirmation email");
        assert_eq!(email.to, "alice@acme.test");
        assert_matches(
            &Value::Object(email.payload.clone()),
            json!({ "confirmationId": request["id"], "action": "documents:write", "resource": "document/report" }),
        );
        assert_eq!(
            render_delivery_message(&RenderInput::from(email), &TemplateOptions::default())
                .unwrap()
                .subject,
            "Inbox agent asks you to confirm an action"
        );
        // Alice sees it; the agent polls it; the owner (not involved) cannot decide it.
        assert_eq!(
            ids(&ok(api
                .list_confirmations(&alice_session, body(json!({ "tenantId": f.tenant_id })))
                .await)),
            vec![id_of(&request)]
        );
        assert_eq!(
            ok(api
                .get_confirmation(
                    &acting,
                    body(json!({ "tenantId": f.tenant_id, "confirmationId": request["id"] }))
                )
                .await)["status"],
            json!("pending")
        );
        assert_eq!(
            err(api
                .decide_confirmation(
                    &f.owner,
                    body(json!({ "tenantId": f.tenant_id, "confirmationId": request["id"], "approve": true })),
                )
                .await)
            .code,
            "NOT_FOUND"
        );
        let approved = ok(api
            .decide_confirmation(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "confirmationId": request["id"], "approve": true })),
            )
            .await);
        assert_matches(
            &approved,
            json!({ "status": "approved", "expiresAt": governance::num(f.now() + 120_000.0) }),
        );
        // Exactly that action on exactly that resource, for a while.
        assert!(
            f.allowed(&acting, "documents:write", "report")
                .await
                .unwrap()
        );
        assert!(
            !f.allowed(&acting, "documents:write", "other")
                .await
                .unwrap()
        );
        f.advance(121_000.0);
        assert!(
            !f.allowed(&acting, "documents:write", "report")
                .await
                .unwrap()
        );
        // A rejection opens nothing, and the trail shows every step.
        let second = ok(ask(
            acting.clone(),
            "documents:write",
            "One more edit",
            json!({}),
        )
        .await);
        let rejected = ok(api
            .decide_confirmation(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "confirmationId": second["id"], "approve": false })),
            )
            .await);
        assert_eq!(rejected["status"], json!("rejected"));
        assert!(
            !f.allowed(&acting, "documents:write", "report")
                .await
                .unwrap()
        );
        let trail = actions(&ok(api
            .activity(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await));
        for action in [
            "delegation:confirmation-request",
            "delegation:confirm",
            "delegation:reject",
        ] {
            assert!(trail.iter().any(|item| item == action), "{action}");
        }
    });
}

#[test]
#[ignore = "needs agents.create, agentStanding and assertAgentUsable (agents unit)"]
fn keeps_the_agent_keys_own_scopes_on_the_sessions_it_opens() {
    run(|| async {
        let Setup {
            f,
            agent,
            alice_session,
            ..
        } = setup(json!({})).await;
        // An administrator issued this key for reading only.
        let read_only = token_of(&ok(f
            .iam
            .api
            .credentials
            .create(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "identityId": agent.id, "scopes": ["documents:read", "iam:*"] })),
            )
            .await));
        let api = &f.iam.api.delegations;
        let delegation = ok(api
            .grant(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent.id, "scopes": ["documents:*"] })),
            )
            .await);
        let token = token_of(&ok(api
            .assume(
                &read_only,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await));
        assert!(f.allowed(&token, "documents:read", "a").await.unwrap());
        // Alice may write and delegated writing, but the key never could.
        assert!(!f.allowed(&token, "documents:write", "a").await.unwrap());
    });
}

#[test]
#[ignore = "needs agents.create, agents.update, agentStanding and assertAgentUsable (agents unit)"]
fn never_gives_the_agent_more_than_the_person_has() {
    run(|| async {
        let Setup {
            f,
            agent,
            alice_session,
            ..
        } = setup(json!({})).await;
        let api = &f.iam.api.delegations;
        let delegation = ok(api
            .grant(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent.id, "scopes": ["*"] })),
            )
            .await);
        let token = token_of(&ok(api
            .assume(
                &agent.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await));
        assert!(f.allowed(&token, "documents:write", "a").await.unwrap());
        // Alice cannot read the audit log, so neither can her agent.
        assert_eq!(
            err(f
                .iam
                .api
                .audit
                .list(&token, body(json!({ "tenantId": f.tenant_id })))
                .await)
            .code,
            "ACCESS_DENIED"
        );
        // A delegated session is no substitute for a fresh sign-in or the person's own session.
        assert_eq!(
            err(api
                .grant(
                    &token,
                    body(json!({ "tenantId": f.tenant_id, "agentId": agent.id, "scopes": ["documents:read"] })),
                )
                .await)
            .code,
            "ACCESS_DENIED"
        );
        assert_eq!(
            err(f
                .iam
                .api
                .sts
                .get_session_token(&token, body(json!({})))
                .await)
            .code,
            "CREDENTIAL_CHAINING_DISABLED"
        );
        // A delegated token cannot open further delegated sessions.
        assert_eq!(
            err(api
                .assume(
                    &token,
                    body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] }))
                )
                .await)
            .code,
            "ACCESS_DENIED"
        );
        // The agent's own ceiling bounds delegated sessions as well, live.
        ok(f.iam
            .api
            .agents
            .update(
                &f.owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "agentId": agent.id,
                    "boundary": doc(&["documents:read"], &["document/*"]),
                })),
            )
            .await);
        assert!(!f.allowed(&token, "documents:write", "a").await.unwrap());
        assert!(f.allowed(&token, "documents:read", "a").await.unwrap());
        // A scope-down at assume time narrows one session further.
        let narrow = token_of(&ok(api
            .assume(
                &agent.key,
                body(json!({
                    "tenantId": f.tenant_id,
                    "delegationId": delegation["id"],
                    "policy": doc(&["documents:read"], &["document/only-this"]),
                })),
            )
            .await));
        assert!(
            f.allowed(&narrow, "documents:read", "only-this")
                .await
                .unwrap()
        );
        assert!(!f.allowed(&narrow, "documents:read", "other").await.unwrap());
    });
}

#[test]
#[ignore = "needs agents.create, agentStanding and assertAgentUsable (agents unit)"]
fn runs_the_request_and_approval_flow() {
    run(|| async {
        let Setup {
            f,
            alice,
            agent,
            alice_session,
        } = setup(json!({})).await;
        let api = &f.iam.api.delegations;
        let request = ok(api
            .request(
                &agent.key,
                body(json!({
                    "tenantId": f.tenant_id,
                    "subjectEmail": "Alice@acme.test",
                    "scopes": ["documents:read", "documents:write"],
                    "reason": "Draft replies to your inbox",
                    "expiresInSeconds": 7 * 86_400,
                })),
            )
            .await);
        assert_matches(
            &request,
            json!({
                "status": "pending",
                "requestedBy": "agent",
                "reason": "Draft replies to your inbox",
                "requestedSeconds": 7 * 86_400,
                "subject": { "id": alice },
            }),
        );
        let inbox = f.inbox().await;
        let email = inbox
            .iter()
            .find(|message| message.template == "delegation-request")
            .expect("the request email");
        assert_eq!(email.to, "alice@acme.test");
        assert_matches(
            &Value::Object(email.payload.clone()),
            json!({ "delegationId": request["id"], "agentName": "Inbox agent", "days": "7" }),
        );
        let mut options = TemplateOptions::default();
        options.links.delegation = Some(Box::new(|link: DelegationLink| {
            format!("https://console.test/delegations/{}", link.delegation_id)
        }));
        let rendered = render_delivery_message(&RenderInput::from(email), &options).unwrap();
        assert_eq!(rendered.subject, "Inbox agent asks to act on your behalf");
        assert!(rendered.text.contains("(claude-sonnet-5)"));
        assert!(rendered.text.contains("for 7 days"));
        assert!(rendered.text.contains("Draft replies to your inbox"));
        assert!(rendered.html.contains(&format!(
            "https://console.test/delegations/{}",
            id_of(&request)
        )));
        // Not usable until approved; a second request is refused.
        assert_eq!(
            err(api
                .assume(
                    &agent.key,
                    body(json!({ "tenantId": f.tenant_id, "delegationId": request["id"] }))
                )
                .await)
            .code,
            "DELEGATION_PENDING"
        );
        assert_eq!(
            err(api
                .request(
                    &agent.key,
                    body(json!({ "tenantId": f.tenant_id, "subjectId": alice, "scopes": ["documents:read"], "reason": "again" })),
                )
                .await)
            .code,
            "DELEGATION_EXISTS"
        );
        // Only alice decides: not the owner, not the agent.
        assert_eq!(
            err(api
                .approve(
                    &f.owner,
                    body(json!({ "tenantId": f.tenant_id, "delegationId": request["id"] }))
                )
                .await)
            .code,
            "NOT_FOUND"
        );
        // The agent polls while it waits.
        assert_eq!(
            ok(api
                .get(
                    &agent.key,
                    body(json!({ "tenantId": f.tenant_id, "delegationId": request["id"] }))
                )
                .await)["status"],
            json!("pending")
        );
        // Alice approves read only.
        let approved = ok(api
            .approve(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": request["id"], "scopes": ["documents:read"] })),
            )
            .await);
        assert_matches(
            &approved,
            json!({ "status": "active", "scopes": ["documents:read"] }),
        );
        assert_eq!(approved["expiresAt"], governance::num(f.now() + 7.0 * DAY));
        let token = token_of(&ok(api
            .assume(
                &agent.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": request["id"] })),
            )
            .await));
        assert!(f.allowed(&token, "documents:read", "a").await.unwrap());
        assert!(!f.allowed(&token, "documents:write", "a").await.unwrap());
    });
}

#[test]
#[ignore = "needs agents.create and agentStanding (agents unit)"]
fn lets_people_deny_requests_and_requests_lapse() {
    run(|| async {
        let Setup {
            f,
            alice,
            agent,
            alice_session,
        } = setup(json!({})).await;
        let api = &f.iam.api.delegations;
        let first = ok(api
            .request(
                &agent.key,
                body(json!({ "tenantId": f.tenant_id, "subjectId": alice, "scopes": ["documents:read"], "reason": "Please" })),
            )
            .await);
        let denied = ok(api
            .deny(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": first["id"] })),
            )
            .await);
        assert_eq!(denied["status"], json!("denied"));
        let second = ok(api
            .request(
                &agent.key,
                body(json!({ "tenantId": f.tenant_id, "subjectId": alice, "scopes": ["documents:read"], "reason": "Please, again" })),
            )
            .await);
        f.advance(8.0 * DAY);
        let fresh = f.sign_in("alice").await;
        assert_eq!(
            err(api
                .approve(
                    &fresh,
                    body(json!({ "tenantId": f.tenant_id, "delegationId": second["id"] }))
                )
                .await)
            .code,
            "INVALID_TRANSITION"
        );
        assert_eq!(
            ok(api
                .get(
                    &fresh,
                    body(json!({ "tenantId": f.tenant_id, "delegationId": second["id"] }))
                )
                .await)["expired"],
            json!(true)
        );
    });
}

#[test]
#[ignore = "needs agents.create, agents.suspend/resume/update, agentStanding and assertAgentUsable (agents unit)"]
fn ends_delegated_sessions_the_moment_anything_in_the_chain_goes_away() {
    run(|| async {
        let Setup {
            f,
            alice,
            agent,
            alice_session,
        } = setup(json!({})).await;
        let api = &f.iam.api.delegations;
        let grant_and_assume = || async {
            let fresh = f.sign_in("alice").await;
            let delegation = ok(api
                .grant(
                    &fresh,
                    body(json!({ "tenantId": f.tenant_id, "agentId": agent.id, "scopes": ["documents:read"] })),
                )
                .await);
            let token = token_of(&ok(api
                .assume(
                    &agent.key,
                    body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
                )
                .await));
            assert!(f.allowed(&token, "documents:read", "a").await.unwrap());
            (delegation, token)
        };
        let unauthenticated =
            |error: better_iam_core::IamError| assert_eq!(error.code, "UNAUTHENTICATED");

        // 1. The person revokes.
        let (delegation, token) = grant_and_assume().await;
        ok(api
            .revoke(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await);
        unauthenticated(refusal(f.allowed(&token, "documents:read", "a").await));

        // 2. The sponsor suspends the agent.
        let (delegation, token) = grant_and_assume().await;
        ok(f.iam
            .api
            .agents
            .suspend(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent.id })),
            )
            .await);
        unauthenticated(refusal(f.allowed(&token, "documents:read", "a").await));
        ok(f.iam
            .api
            .agents
            .resume(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent.id })),
            )
            .await);
        ok(api
            .revoke(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await);

        // 3. The agent stops accepting delegation.
        let (delegation, token) = grant_and_assume().await;
        ok(f.iam
            .api
            .agents
            .update(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent.id, "delegable": false })),
            )
            .await);
        unauthenticated(refusal(f.allowed(&token, "documents:read", "a").await));
        assert_eq!(
            err(api
                .assume(
                    &agent.key,
                    body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] }))
                )
                .await)
            .code,
            "DELEGATION_NOT_ALLOWED"
        );
        ok(f.iam
            .api
            .agents
            .update(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent.id, "delegable": true })),
            )
            .await);
        assert!(f.allowed(&token, "documents:read", "a").await.unwrap());

        // 4. The agent's key is revoked.
        let keys = ok(f
            .iam
            .api
            .credentials
            .list(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "identityId": agent.id })),
            )
            .await);
        ok(f.iam
            .api
            .credentials
            .revoke(
                &f.owner_sign_in().await,
                body(json!({ "tenantId": f.tenant_id, "credentialId": keys[0]["id"] })),
            )
            .await);
        unauthenticated(refusal(f.allowed(&token, "documents:read", "a").await));

        // 5. The person is disabled.
        let second = token_of(&ok(f
            .iam
            .api
            .credentials
            .create(
                &f.owner_sign_in().await,
                body(json!({ "tenantId": f.tenant_id, "identityId": agent.id })),
            )
            .await));
        let again = token_of(&ok(api
            .assume(
                &second,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await));
        assert!(f.allowed(&again, "documents:read", "a").await.unwrap());
        ok(f.iam
            .api
            .identities
            .set_status(
                &f.owner_sign_in().await,
                body(json!({ "tenantId": f.tenant_id, "identityId": alice, "status": "disabled" })),
            )
            .await);
        unauthenticated(refusal(f.allowed(&again, "documents:read", "a").await));
    });
}

#[test]
#[ignore = "needs agents.create and agentStanding (agents unit)"]
fn refuses_delegation_to_agents_that_do_not_accept_it_and_to_non_agents() {
    run(|| async {
        let Setup {
            f,
            alice,
            alice_session,
            ..
        } = setup(json!({})).await;
        let api = &f.iam.api.delegations;
        let closed = ok(f
            .iam
            .api
            .agents
            .create(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "name": "Closed", "delegable": false })),
            )
            .await);
        let grant = |agent_id: Value, scopes: Value| {
            let api = f.iam.api.delegations.clone();
            let session = alice_session.clone();
            let input = json!({ "tenantId": f.tenant_id, "agentId": agent_id, "scopes": scopes });
            async move { api.grant(&session, body(input)).await }
        };
        assert_eq!(
            err(grant(closed["id"].clone(), json!(["documents:read"])).await).code,
            "DELEGATION_NOT_ALLOWED"
        );
        let service = ok(f
            .iam
            .api
            .service_accounts
            .create(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "name": "ci" })),
            )
            .await);
        assert_eq!(
            err(grant(service["id"].clone(), json!(["documents:read"])).await).code,
            "NOT_FOUND"
        );
        assert_eq!(
            err(grant(json!(alice), json!(["documents:read"])).await).code,
            "NOT_FOUND"
        );
        assert_eq!(
            err(grant(closed["id"].clone(), json!(["no:such-action"])).await).code,
            "DELEGATION_NOT_ALLOWED"
        );
        // A stale sign-in cannot consent.
        f.advance(3_600_000.0);
        let open = ok(f
            .iam
            .api
            .agents
            .create(
                &f.owner_sign_in().await,
                body(json!({ "tenantId": f.tenant_id, "name": "Open" })),
            )
            .await);
        assert_eq!(
            err(grant(open["id"].clone(), json!(["documents:read"])).await).code,
            "RECENT_AUTH_REQUIRED"
        );
        let _ = api;
    });
}

#[test]
#[ignore = "needs agents.create, agents.get, agents.delete, agentStanding and assertAgentUsable (agents unit)"]
fn lets_administrators_list_and_revoke_delegations_and_deleting_an_agent_revokes_them() {
    run(|| async {
        let Setup {
            f,
            agent,
            alice_session,
            ..
        } = setup(json!({})).await;
        let api = &f.iam.api.delegations;
        let delegation = ok(api
            .grant(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent.id, "scopes": ["documents:read"] })),
            )
            .await);
        let token = token_of(&ok(api
            .assume(
                &agent.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await));
        let listed = ok(api
            .list(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent.id })),
            )
            .await);
        assert_eq!(ids(&listed), vec![id_of(&delegation)]);
        let detail = ok(f
            .iam
            .api
            .agents
            .get(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent.id })),
            )
            .await);
        assert_matches(
            &detail,
            json!({ "delegations": { "active": 1, "pending": 0 }, "liveDelegatedSessions": 1 }),
        );
        assert!(detail["keys"][0]["id"].is_string());
        ok(f.iam
            .api
            .agents
            .delete(
                &f.owner_sign_in().await,
                body(json!({ "tenantId": f.tenant_id, "agentId": agent.id })),
            )
            .await);
        assert_eq!(
            refusal(f.allowed(&token, "documents:read", "a").await).code,
            "UNAUTHENTICATED"
        );
        assert_eq!(
            ok(api
                .get(
                    &f.owner,
                    body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] }))
                )
                .await)["status"],
            json!("revoked")
        );
    });
}

// --- tests/delegation-handoffs.test.ts -------------------------------------------------------------------------

struct HandoffSetup {
    f: Fixture,
    alice: String,
    assistant: TestAgent,
    researcher: TestAgent,
    writer: TestAgent,
    alice_session: better_iam_core::CredentialInput,
}

/// Acme with alice (read and write on every document, but never document/secret for the research agent) and three
/// agents with keys and no grants of their own: an assistant alice delegates to, and a researcher and a writer the
/// assistant may hand work on to.
async fn handoff_setup(assistant_scopes: Option<Value>) -> HandoffSetup {
    let f = organization(|_| {}).await;
    let alice = f.member("alice").await;
    let assistant = f
        .agent(
            "Assistant",
            json!({}),
            match &assistant_scopes {
                Some(scopes) => json!({ "scopes": scopes }),
                None => json!({}),
            },
        )
        .await;
    let researcher = f.agent("Researcher", json!({}), json!({})).await;
    let writer = f.agent("Writer", json!({}), json!({})).await;
    f.grant(
        "Editor",
        json!({
            "version": 1,
            "statements": [
                { "effect": "allow", "actions": ["documents:read", "documents:write"], "resources": ["document/*"] },
                {
                    "effect": "deny",
                    "actions": ["documents:read"],
                    "resources": ["document/secret"],
                    "conditions": { "ArrayContains": { "principal.delegationChain": [researcher.id] } },
                },
            ],
        }),
        &alice,
    )
    .await;
    let alice_session = f.sign_in("alice").await;
    HandoffSetup {
        f,
        alice,
        assistant,
        researcher,
        writer,
        alice_session,
    }
}

#[test]
#[ignore = "needs agents.create, agentStanding and assertAgentUsable (agents unit)"]
fn lets_an_agent_acting_for_a_person_hand_part_of_the_work_on_to_another_agent() {
    run(|| async {
        let HandoffSetup {
            f,
            alice,
            assistant,
            researcher,
            alice_session,
            ..
        } = handoff_setup(None).await;
        let api = &f.iam.api.delegations;
        let delegation = ok(api
            .grant(
                &alice_session,
                body(json!({
                    "tenantId": f.tenant_id,
                    "agentId": assistant.id,
                    "scopes": ["documents:*"],
                    "handoff": { "agents": [researcher.id] },
                })),
            )
            .await);
        assert_eq!(
            delegation["handoff"],
            json!({ "depth": 1, "agents": [researcher.id] })
        );
        let acting = token_of(&ok(api
            .assume(
                &assistant.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await));
        let handoff = ok(api
            .handoff(
                &acting,
                body(json!({
                    "tenantId": f.tenant_id,
                    "agentId": researcher.id,
                    "scopes": ["documents:read"],
                    "reason": "Find the sources for the report",
                })),
            )
            .await);
        assert_matches(
            &handoff,
            json!({
                "status": "active",
                "requestedBy": "handoff",
                "parentId": delegation["id"],
                "chain": [{ "id": assistant.id, "name": "Assistant" }],
                "agent": { "id": researcher.id },
                "subject": { "id": alice },
                "scopes": ["documents:read"],
            }),
        );
        assert!(handoff.get("handoff").is_none());
        assert_eq!(handoff["expiresAt"], governance::num(f.now() + 3_600_000.0));
        // The researcher opens its own sessions for alice with its own key, within the hand-off.
        let research = ok(api
            .assume(
                &researcher.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": handoff["id"] })),
            )
            .await);
        assert_matches(
            &research["session"],
            json!({ "identityId": alice, "agentId": researcher.id }),
        );
        let research = token_of(&research);
        assert!(f.allowed(&research, "documents:read", "a").await.unwrap());
        assert!(!f.allowed(&research, "documents:write", "a").await.unwrap());
        // Policies see the whole chain: alice keeps document/secret away from anything the researcher does.
        assert!(
            !f.allowed(&research, "documents:read", "secret")
                .await
                .unwrap()
        );
        assert!(
            f.allowed(&acting, "documents:read", "secret")
                .await
                .unwrap()
        );
        // Alice sees the hand-off; the delegation's activity includes the researcher's work.
        let mut mine = ids(&ok(api
            .list_mine(&alice_session, body(json!({ "tenantId": f.tenant_id })))
            .await));
        mine.sort();
        let mut expected = vec![id_of(&delegation), id_of(&handoff)];
        expected.sort();
        assert_eq!(mine, expected);
        let activity = ok(api
            .activity(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await);
        let seen = actions(&activity);
        assert!(seen.iter().any(|action| action == "delegation:handoff"));
        assert!(seen.iter().any(|action| action == "documents:read"));
        assert!(
            activity
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["sessionContext"]["agentId"] == json!(researcher.id))
        );
        // The researcher's own direct delegations are unaffected by the hand-off.
        assert_eq!(
            ok(api
                .grant(
                    &alice_session,
                    body(json!({ "tenantId": f.tenant_id, "agentId": researcher.id, "scopes": ["documents:read"] })),
                )
                .await)["status"],
            json!("active")
        );
        // Revoking alice's delegation ends the hand-off and its sessions with it.
        let revoked = ok(api
            .revoke(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await);
        assert_eq!(revoked["status"], json!("revoked"));
        assert_eq!(
            ok(api
                .get(
                    &alice_session,
                    body(json!({ "tenantId": f.tenant_id, "delegationId": handoff["id"] }))
                )
                .await)["status"],
            json!("revoked")
        );
        assert_eq!(refusal(f.iam.authenticate(&research).await).status, 401);
        let audit = ok(f
            .iam
            .api
            .audit
            .list(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "action": "delegation:revoke" })),
            )
            .await);
        assert_matches(&audit[0]["metadata"], json!({ "handoffsRevoked": 1 }));
    });
}

#[test]
#[ignore = "needs agents.create, agents.suspend/resume, agentStanding and assertAgentUsable (agents unit)"]
fn only_hands_on_what_the_person_allowed_to_whom_they_allowed_as_deep_as_they_allowed() {
    run(|| async {
        let HandoffSetup {
            f,
            assistant,
            researcher,
            writer,
            alice_session,
            ..
        } = handoff_setup(None).await;
        let api = &f.iam.api.delegations;
        let hand_on = |credential: better_iam_core::CredentialInput,
                       agent_id: String,
                       scopes: Value| {
            let api = f.iam.api.delegations.clone();
            let input = json!({ "tenantId": f.tenant_id, "agentId": agent_id, "scopes": scopes });
            async move { api.handoff(&credential, body(input)).await }
        };
        let plain = ok(api
            .grant(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "agentId": assistant.id, "scopes": ["documents:*"] })),
            )
            .await);
        let acting = token_of(&ok(api
            .assume(
                &assistant.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": plain["id"] })),
            )
            .await));
        let read = json!(["documents:read"]);
        assert_eq!(
            err(hand_on(acting.clone(), researcher.id.clone(), read.clone()).await).code,
            "DELEGATION_NOT_ALLOWED"
        );
        // Only delegated sessions hand work on.
        assert_eq!(
            err(hand_on(assistant.key.clone(), researcher.id.clone(), read.clone()).await).code,
            "ACCESS_DENIED"
        );
        assert_eq!(
            err(hand_on(alice_session.clone(), researcher.id.clone(), read.clone()).await).code,
            "ACCESS_DENIED"
        );
        ok(api
            .revoke(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": plain["id"] })),
            )
            .await);
        let fresh = f.sign_in("alice").await;
        let deep = ok(api
            .grant(
                &fresh,
                body(json!({
                    "tenantId": f.tenant_id,
                    "agentId": assistant.id,
                    "scopes": ["documents:*"],
                    "confirm": ["documents:write"],
                    "handoff": { "agents": [researcher.id, writer.id], "depth": 2 },
                })),
            )
            .await);
        let assistant_session = token_of(&ok(api
            .assume(
                &assistant.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": deep["id"] })),
            )
            .await));
        let first = ok(hand_on(
            assistant_session.clone(),
            writer.id.clone(),
            json!(["documents:*"]),
        )
        .await);
        // Depth and the person's confirm list travel down the chain.
        assert_matches(
            &first,
            json!({ "handoff": { "agents": [researcher.id, writer.id], "depth": 1 }, "confirm": ["documents:write"] }),
        );
        let writer_session = token_of(&ok(api
            .assume(
                &writer.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": first["id"] })),
            )
            .await));
        assert!(
            !f.allowed(&writer_session, "documents:write", "draft")
                .await
                .unwrap()
        );
        assert!(
            f.allowed(&writer_session, "documents:read", "a")
                .await
                .unwrap()
        );
        // The writer asks alice to confirm, as her own delegate would have to.
        let confirmation = ok(api
            .request_confirmation(
                &writer_session,
                body(json!({
                    "tenantId": f.tenant_id,
                    "action": "documents:write",
                    "resource": { "type": "document", "id": "draft" },
                    "reason": "Save the draft",
                })),
            )
            .await);
        ok(api
            .decide_confirmation(
                &fresh,
                body(json!({ "tenantId": f.tenant_id, "confirmationId": confirmation["id"], "approve": true })),
            )
            .await);
        assert!(
            f.allowed(&writer_session, "documents:write", "draft")
                .await
                .unwrap()
        );
        // No agent appears twice in a chain.
        assert_eq!(
            err(hand_on(writer_session.clone(), assistant.id.clone(), read.clone()).await).code,
            "DELEGATION_NOT_ALLOWED"
        );
        let second = ok(hand_on(writer_session.clone(), researcher.id.clone(), read.clone()).await);
        assert_eq!(
            second["chain"]
                .as_array()
                .unwrap()
                .iter()
                .map(id_of)
                .collect::<Vec<_>>(),
            vec![assistant.id.clone(), writer.id.clone()]
        );
        assert!(second.get("handoff").is_none());
        let research_session = token_of(&ok(api
            .assume(
                &researcher.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": second["id"] })),
            )
            .await));
        assert!(
            f.allowed(&research_session, "documents:read", "a")
                .await
                .unwrap()
        );
        // The end of the line: no further hand-offs.
        assert_eq!(
            err(hand_on(research_session.clone(), writer.id.clone(), read.clone()).await).code,
            "DELEGATION_NOT_ALLOWED"
        );
        // Suspending an agent in the middle of the chain stops everything below it.
        ok(f.iam
            .api
            .agents
            .suspend(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "agentId": writer.id })),
            )
            .await);
        assert_eq!(
            refusal(f.iam.authenticate(&research_session).await).status,
            401
        );
        ok(f.iam
            .api
            .agents
            .resume(
                &f.owner_sign_in().await,
                body(json!({ "tenantId": f.tenant_id, "agentId": writer.id })),
            )
            .await);
        assert!(
            f.allowed(&research_session, "documents:read", "a")
                .await
                .unwrap()
        );
    });
}

#[test]
#[ignore = "needs agents.create, agentStanding and assertAgentUsable (agents unit)"]
fn ends_a_hand_off_with_the_key_that_made_it_and_credits_agents_with_what_they_revoke() {
    run(|| async {
        let HandoffSetup {
            f,
            alice,
            assistant,
            researcher,
            alice_session,
            ..
        } = handoff_setup(None).await;
        let api = &f.iam.api.delegations;
        let delegation = ok(api
            .grant(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "agentId": assistant.id, "scopes": ["documents:*"], "handoff": {} })),
            )
            .await);
        let acting = token_of(&ok(api
            .assume(
                &assistant.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await));
        let hand_on = || {
            let api = f.iam.api.delegations.clone();
            let acting = acting.clone();
            let input = json!({
                "tenantId": f.tenant_id,
                "agentId": researcher.id,
                "scopes": ["documents:read"],
                "expiresInSeconds": 300 * 86_400,
            });
            async move { api.handoff(&acting, body(input)).await }
        };
        let first = ok(hand_on().await);
        // Never past the key the assistant acted with (a key lasts 90 days by default).
        let keys = ok(f
            .iam
            .api
            .credentials
            .list(&f.owner, body(json!({ "tenantId": f.tenant_id })))
            .await);
        let assistant_key = keys
            .as_array()
            .unwrap()
            .iter()
            .find(|key| key["identityId"] == json!(assistant.id))
            .unwrap()
            .clone();
        assert!(
            first["expiresAt"].as_f64().unwrap() <= assistant_key["expiresAt"].as_f64().unwrap()
        );
        let research = token_of(&ok(api
            .assume(
                &researcher.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": first["id"] })),
            )
            .await));
        assert!(f.allowed(&research, "documents:read", "a").await.unwrap());
        // The assistant revokes its own hand-off from its delegated session: the record names the assistant.
        let second = ok(hand_on().await);
        let revoked = ok(api
            .revoke(
                &acting,
                body(json!({ "tenantId": f.tenant_id, "delegationId": second["id"] })),
            )
            .await);
        assert_eq!(revoked["revokedBy"], json!(assistant.id));
        assert_ne!(revoked["revokedBy"], json!(alice));
        // Revoking the assistant's key (a compromised agent) stops what it handed on at once.
        ok(f.iam
            .api
            .credentials
            .revoke(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "credentialId": assistant_key["id"] })),
            )
            .await);
        assert_eq!(refusal(f.iam.authenticate(&research).await).status, 401);
        assert_eq!(
            err(api
                .assume(
                    &researcher.key,
                    body(json!({ "tenantId": f.tenant_id, "delegationId": first["id"] }))
                )
                .await)
            .code,
            "DELEGATION_INACTIVE"
        );
    });
}

#[test]
#[ignore = "needs agents.create, agentStanding and assertAgentUsable (agents unit)"]
fn never_hands_on_more_than_the_handing_session_could_do() {
    run(|| async {
        // The assistant's key may only read, even though alice's delegation covers writing.
        let HandoffSetup {
            f,
            assistant,
            writer,
            alice_session,
            ..
        } = handoff_setup(Some(json!(["documents:read"]))).await;
        let api = &f.iam.api.delegations;
        let delegation = ok(api
            .grant(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "agentId": assistant.id, "scopes": ["documents:*"], "handoff": {} })),
            )
            .await);
        assert_eq!(delegation["handoff"], json!({ "depth": 1 }));
        let acting = token_of(&ok(api
            .assume(
                &assistant.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await));
        assert!(!f.allowed(&acting, "documents:write", "a").await.unwrap());
        let handoff = ok(api
            .handoff(
                &acting,
                body(json!({ "tenantId": f.tenant_id, "agentId": writer.id, "scopes": ["documents:*"] })),
            )
            .await);
        let writing = token_of(&ok(api
            .assume(
                &writer.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": handoff["id"] })),
            )
            .await));
        assert!(f.allowed(&writing, "documents:read", "a").await.unwrap());
        assert!(!f.allowed(&writing, "documents:write", "a").await.unwrap());
        // The approval path: an agent's request may ask for hand-offs, but they count only when the person states them.
        let request = ok(api
            .request(
                &writer.key,
                body(json!({
                    "tenantId": f.tenant_id,
                    "subjectEmail": "alice@acme.test",
                    "scopes": ["documents:read"],
                    "reason": "Draft the weekly summary",
                    "handoff": { "depth": 2 },
                })),
            )
            .await);
        assert_eq!(request["handoff"], json!({ "depth": 2 }));
        let approved = ok(api
            .approve(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": request["id"] })),
            )
            .await);
        assert!(approved.get("handoff").is_none());
        let other = ok(f
            .iam
            .api
            .agents
            .create(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "name": "Other" })),
            )
            .await);
        for handoff in [
            json!({ "agents": ["not-an-agent"] }),
            json!({ "depth": 4 }),
            json!({ "agents": [] }),
        ] {
            assert_eq!(
                err(api
                    .grant(
                        &alice_session,
                        body(json!({
                            "tenantId": f.tenant_id,
                            "agentId": other["id"],
                            "scopes": ["documents:read"],
                            "handoff": handoff,
                        })),
                    )
                    .await)
                .code,
                "INVALID_INPUT"
            );
        }
    });
}

// --- tests/delegation-spend.test.ts ----------------------------------------------------------------------------

struct SpendSetup {
    f: Fixture,
    assistant: TestAgent,
    helper: TestAgent,
    alice_session: better_iam_core::CredentialInput,
}

/// Acme with inference on, one small model alice may use, and two agents with keys.
async fn spend_setup() -> SpendSetup {
    let f = organization(|options| options.inference = Some(Toggle::Flag(true))).await;
    let provider = ok(f
        .iam
        .api
        .inference
        .create_provider(
            &f.owner,
            body(json!({
                "tenantId": f.tenant_id,
                "name": "Anthropic",
                "kind": "anthropic",
                "apiKey": "sk-ant-secret-provider-key-0042",
            })),
        )
        .await);
    ok(f.iam
        .api
        .inference
        .create_model(
            &f.owner,
            body(json!({
                "tenantId": f.tenant_id,
                "name": "haiku",
                "providerId": provider["id"],
                "upstreamModel": "claude-haiku-4-5",
                "inputPricePerMTok": 1,
                "outputPricePerMTok": 5,
            })),
        )
        .await);
    let alice = f.member("alice").await;
    f.grant(
        "Models",
        json!({ "version": 1, "statements": [{ "effect": "allow", "actions": ["inference:invoke"], "resources": ["model/*"] }] }),
        &alice,
    )
    .await;
    let assistant = f.agent("Assistant", json!({}), json!({})).await;
    let helper = f.agent("Helper", json!({}), json!({})).await;
    let alice_session = f.sign_in("alice").await;
    SpendSetup {
        f,
        assistant,
        helper,
        alice_session,
    }
}

/// `call(f, token)`: one model call of 1000 input and 1000 output tokens through the in-process gateway, metered;
/// `"ok"`, or the refusal (`{ reason, ... }`) when the gateway denies it.
async fn call(f: &Fixture, credential: &better_iam_core::CredentialInput) -> Value {
    match f
        .iam
        .inference
        .authorize(credential, &json!({ "model": "haiku" }))
        .await
    {
        Ok(permit) => {
            f.iam
                .inference
                .record(
                    &permit,
                    &json!({ "model": "haiku", "inputTokens": 1000, "outputTokens": 1000 }),
                )
                .await
                .expect("metered");
            json!("ok")
        }
        Err(error) => json!({ "reason": error.code, "message": error.message }),
    }
}

#[test]
#[ignore = "needs agents.create, agentStanding and assertAgentUsable (agents unit) and the inference gateway (inference unit)"]
fn caps_what_an_agent_spends_on_models_on_a_persons_behalf_across_hand_offs() {
    let _ = AGENTS_AND_INFERENCE;
    run(|| async {
        let SpendSetup {
            f,
            assistant,
            helper,
            alice_session,
        } = spend_setup().await;
        let api = &f.iam.api.delegations;
        let delegation = ok(api
            .grant(
                &alice_session,
                body(json!({
                    "tenantId": f.tenant_id,
                    "agentId": assistant.id,
                    "scopes": ["inference:invoke"],
                    "spend": { "period": "day", "maxRequests": 3, "maxCostUsd": 1 },
                    "handoff": {},
                })),
            )
            .await);
        assert_matches(
            &delegation["spend"],
            json!({ "period": "day", "maxRequests": 3, "maxCostUsd": 1, "usedRequests": 0, "usedCostUsd": 0 }),
        );
        let acting = token_of(&ok(api
            .assume(
                &assistant.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await));
        assert_eq!(call(&f, &acting).await, json!("ok"));
        assert_eq!(call(&f, &acting).await, json!("ok"));
        // Work handed on counts against the same cap.
        let handoff = ok(api
            .handoff(
                &acting,
                body(json!({ "tenantId": f.tenant_id, "agentId": helper.id, "scopes": ["inference:invoke"] })),
            )
            .await);
        let helping = token_of(&ok(api
            .assume(
                &helper.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": handoff["id"] })),
            )
            .await));
        assert_eq!(call(&f, &helping).await, json!("ok"));
        assert_matches(
            &call(&f, &helping).await,
            json!({ "reason": "BUDGET_EXCEEDED" }),
        );
        assert_matches(
            &call(&f, &acting).await,
            json!({ "reason": "BUDGET_EXCEEDED" }),
        );
        // Alice sees what her delegation used: 3 calls of 1000 input and 1000 output tokens each ($0.006 each).
        let seen = ok(api
            .get(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await);
        assert_matches(
            &seen["spend"],
            json!({ "usedRequests": 3, "usedTokens": 6000, "usedCostUsd": 0.018 }),
        );
        let exceeded = ok(f
            .iam
            .api
            .audit
            .list(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "action": "inference:budget-exceeded" })),
            )
            .await);
        assert_matches(
            &exceeded[0],
            json!({ "resourceId": format!("delegation:{}", id_of(&delegation)) }),
        );
        // A new day, a new allowance (in a new session: the old one has ended); alice's own calls were never capped.
        f.advance(DAY);
        let tomorrow = token_of(&ok(api
            .assume(
                &assistant.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await));
        assert_eq!(call(&f, &tomorrow).await, json!("ok"));
        assert_eq!(call(&f, &alice_session).await, json!("ok"));
    });
}

#[test]
#[ignore = "needs agents.create, agentStanding and assertAgentUsable (agents unit) and the inference gateway (inference unit)"]
fn meters_gateway_tickets_after_the_session_ends_and_counts_hand_offs_against_the_handing_agents_budget()
 {
    run(|| async {
        let SpendSetup {
            f,
            assistant,
            helper,
            alice_session,
        } = spend_setup().await;
        let api = &f.iam.api.delegations;
        let delegation = ok(api
            .grant(
                &alice_session,
                body(json!({
                    "tenantId": f.tenant_id,
                    "agentId": assistant.id,
                    "scopes": ["inference:invoke"],
                    "spend": { "period": "day", "maxRequests": 1 },
                    "handoff": {},
                })),
            )
            .await);
        let acting = token_of(&ok(api
            .assume(
                &assistant.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"], "durationSeconds": 60 })),
            )
            .await));
        let check = ok(f
            .iam
            .api
            .inference
            .check(
                &acting,
                body(json!({ "tenantId": f.tenant_id, "model": "haiku" })),
            )
            .await);
        assert!(check["ticket"].is_string());
        // The session ends before the external gateway reports the call; it is metered against the cap all the same.
        f.advance(120_000.0);
        let gateway = ok(f
            .iam
            .api
            .agents
            .create(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "name": "Gateway" })),
            )
            .await);
        let recorder = ok(f
            .iam
            .api
            .roles
            .create(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "name": "Recorder", "permissions": ["iam:inference:record"] })),
            )
            .await);
        ok(f
            .iam
            .api
            .bindings
            .create(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "roleId": recorder["id"], "subjectType": "identity", "subjectId": gateway["id"] })),
            )
            .await);
        let gateway_key = token_of(&ok(f
            .iam
            .api
            .credentials
            .create(
                &f.owner,
                body(json!({ "tenantId": f.tenant_id, "identityId": gateway["id"] })),
            )
            .await));
        ok(f
            .iam
            .api
            .inference
            .record(
                &gateway_key,
                body(json!({ "tenantId": f.tenant_id, "ticket": check["ticket"], "inputTokens": 10, "outputTokens": 10 })),
            )
            .await);
        let seen = ok(api
            .get(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await);
        assert_matches(&seen["spend"], json!({ "usedRequests": 1 }));
        // An identity budget on the assistant counts what it hands on to the helper, too.
        ok(f.iam
            .api
            .inference
            .set_budget(
                &f.owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Assistant",
                    "subjectType": "identity",
                    "subjectId": assistant.id,
                    "period": "day",
                    "maxRequests": 1,
                })),
            )
            .await);
        ok(api
            .revoke(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await);
        let fresh = ok(api
            .grant(
                &f.sign_in("alice").await,
                body(json!({ "tenantId": f.tenant_id, "agentId": assistant.id, "scopes": ["inference:invoke"], "handoff": {} })),
            )
            .await);
        let again = token_of(&ok(api
            .assume(
                &assistant.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": fresh["id"] })),
            )
            .await));
        let handoff = ok(api
            .handoff(
                &again,
                body(json!({ "tenantId": f.tenant_id, "agentId": helper.id, "scopes": ["inference:invoke"] })),
            )
            .await);
        let helping = token_of(&ok(api
            .assume(
                &helper.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": handoff["id"] })),
            )
            .await));
        assert_eq!(call(&f, &helping).await, json!("ok"));
        assert_matches(
            &call(&f, &helping).await,
            json!({ "reason": "BUDGET_EXCEEDED" }),
        );
    });
}

#[test]
#[ignore = "needs agents.create, agentStanding and assertAgentUsable (agents unit) and the inference gateway (inference unit)"]
fn is_set_changed_or_removed_by_the_person_and_validated() {
    run(|| async {
        let SpendSetup {
            f,
            assistant,
            helper,
            alice_session,
        } = spend_setup().await;
        let api = &f.iam.api.delegations;
        let request = ok(api
            .request(
                &assistant.key,
                body(json!({
                    "tenantId": f.tenant_id,
                    "subjectEmail": "alice@acme.test",
                    "scopes": ["inference:invoke"],
                    "reason": "Summarize your inbox",
                    "spend": { "period": "month", "maxCostUsd": 50 },
                })),
            )
            .await);
        assert_matches(
            &request["spend"],
            json!({ "period": "month", "maxCostUsd": 50 }),
        );
        let approved = ok(api
            .approve(
                &alice_session,
                body(json!({
                    "tenantId": f.tenant_id,
                    "delegationId": request["id"],
                    "spend": { "period": "minute", "maxRequests": 1 },
                })),
            )
            .await);
        assert_matches(
            &approved["spend"],
            json!({ "period": "minute", "maxRequests": 1 }),
        );
        assert!(approved["spend"].get("maxCostUsd").is_none());
        let acting = token_of(&ok(api
            .assume(
                &assistant.key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": request["id"] })),
            )
            .await));
        assert_eq!(call(&f, &acting).await, json!("ok"));
        assert_matches(
            &call(&f, &acting).await,
            json!({ "reason": "BUDGET_EXCEEDED" }),
        );
        f.advance(60_000.0);
        assert_eq!(call(&f, &acting).await, json!("ok"));
        for spend in [
            json!({ "period": "week", "maxRequests": 1 }),
            json!({ "period": "day" }),
            json!({ "period": "day", "maxCostUsd": 0 }),
            json!({ "period": "day", "maxCostUsd": 0.0000001 }),
            json!({ "period": "day", "maxTokens": 1.5 }),
        ] {
            assert_eq!(
                err(api
                    .grant(
                        &alice_session,
                        body(json!({
                            "tenantId": f.tenant_id,
                            "agentId": helper.id,
                            "scopes": ["inference:invoke"],
                            "spend": spend,
                        })),
                    )
                    .await)
                .code,
                "INVALID_INPUT"
            );
        }
    });
}
