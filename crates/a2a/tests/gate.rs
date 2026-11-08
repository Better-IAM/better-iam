//! The A2A gate: the port of the gate cases of tests/a2a.test.ts and the skill-name case of
//! tests/security-integrations.test.ts.

mod support;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_iam_a2a::MemoryTaskOwnersOptions;
use better_iam_a2a::{
    A2A_ACCESS_DENIED, A2A_CONFIRMATION_REQUESTED, A2aAuthorization, A2aCaller, A2aCheck, A2aError,
    A2aGate, A2aGateOptions, A2aIam, A2aIamCaller, A2aPrincipal, A2aResourceRef, A2aRule,
    A2aTaskOwners, Body, CardSource, HANDOFF_METADATA_KEY, Passthrough, create_a2a_authorizer,
    create_a2a_gate, handoff_of, memory_task_owners, task_owner_of, transport, with_handoff,
};
use better_iam_core::CredentialInput;
use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use indexmap::IndexMap;
use serde_json::{Map, Value, json};
use support::{
    Org, OrgIam, agent_with_key, assert_matches, base_card, bearer, body, id_of, json_response, ok,
    organization, read, read_json, request_json, run,
};

/// A stand-in A2A server: creates tasks for messages (JSON or an event stream) and answers task reads.
#[derive(Default)]
struct A2aServer {
    calls: Mutex<Vec<(String, A2aCaller)>>,
    count: Mutex<u32>,
}

impl A2aServer {
    async fn handle(
        self: Arc<Self>,
        request: http::Request<Body>,
        caller: A2aCaller,
    ) -> Result<http::Response<Body>, A2aError> {
        let message = request_json(request).await;
        let method = message["method"].as_str().unwrap().to_owned();
        self.calls.lock().unwrap().push((method.clone(), caller));
        let sent_context = message["params"]["message"]["contextId"]
            .as_str()
            .map(str::to_owned);
        let task = |id: &str, state: &str| {
            json!({
                "kind": "task",
                "id": id,
                "contextId": sent_context.clone().unwrap_or_else(|| format!("ctx-{id}")),
                "status": { "state": state },
            })
        };
        let next_id = || {
            let mut count = self.count.lock().unwrap();
            *count += 1;
            format!("task-{count}")
        };
        let id = message["id"].clone();
        Ok(match method.as_str() {
            "message/send" => json_response(
                &json!({ "jsonrpc": "2.0", "id": id, "result": task(&next_id(), "submitted") }),
            ),
            "message/stream" => {
                let task_id = next_id();
                let events = [
                    json!({ "jsonrpc": "2.0", "id": id, "result": task(&task_id, "submitted") }),
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": { "kind": "status-update", "taskId": task_id, "status": { "state": "working" }, "final": true },
                    }),
                ];
                let text: String = events
                    .iter()
                    .map(|event| format!("data: {event}\n\n"))
                    .collect();
                let chunks: Vec<Result<http_body::Frame<Bytes>, transport::BodyError>> = text
                    .as_bytes()
                    .chunks(17)
                    .map(|chunk| Ok(http_body::Frame::data(Bytes::copy_from_slice(chunk))))
                    .collect();
                http::Response::builder()
                    .header("content-type", "text/event-stream")
                    .body(StreamBody::new(futures::stream::iter(chunks)).boxed_unsync())
                    .unwrap()
            }
            "tasks/get" | "tasks/cancel" => {
                let task_id = better_iam_auth::util::js_string(&message["params"]["id"]);
                json_response(
                    &json!({ "jsonrpc": "2.0", "id": id, "result": task(&task_id, "working") }),
                )
            }
            _ => json_response(&json!({ "jsonrpc": "2.0", "id": id, "result": {} })),
        })
    }

    fn methods(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(method, _)| method.clone())
            .collect()
    }
}

fn grant_documents(actions: &[&str]) -> Value {
    json!([{ "effect": "allow", "actions": actions, "resources": ["document/*"] }])
}

fn document(id: &str) -> Option<A2aResourceRef> {
    Some(A2aResourceRef::new("document", id))
}

struct GateSetup {
    f: Arc<Org>,
    gate: A2aGate,
    server: Arc<A2aServer>,
}

async fn gate_setup() -> GateSetup {
    let f = Arc::new(organization(|_| {}).await);
    let card = base_card("https://agents.acme.test/a2a");
    let gate = create_a2a_gate(A2aGateOptions {
        card: Some(CardSource::Card(card.clone())),
        extended_card: Some(CardSource::Card(card)),
        skills: Some(IndexMap::from([
            (
                "summarize".to_owned(),
                A2aRule::action("documents:read", document("inbox")),
            ),
            (
                "purge".to_owned(),
                A2aRule::action("documents:write", document("archive")),
            ),
        ])),
        task_admin_action: Some("documents:write".into()),
        ..A2aGateOptions::new(
            Arc::new(OrgIam(f.clone())),
            f.tenant_id.as_str(),
            A2aRule::action("documents:read", document("inbox")),
        )
    });
    GateSetup {
        f,
        gate,
        server: Arc::new(A2aServer::default()),
    }
}

fn rpc_request(token: Option<&str>, payload: &Value) -> http::Request<Body> {
    let mut builder = http::Request::builder()
        .method("POST")
        .uri("https://agents.acme.test/a2a")
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder.body(transport::full(payload.to_string())).unwrap()
}

impl GateSetup {
    async fn rpc(
        &self,
        token: Option<&str>,
        method: &str,
        params: Option<Value>,
    ) -> http::Response<Body> {
        let mut payload = json!({ "jsonrpc": "2.0", "id": 3, "method": method });
        if let Some(params) = params {
            payload["params"] = params;
        }
        let server = self.server.clone();
        self.gate
            .handle(rpc_request(token, &payload), move |request, caller| {
                server.handle(request, caller)
            })
            .await
            .expect("an answer")
    }

    async fn rpc_json(
        &self,
        token: Option<&str>,
        method: &str,
        params: Option<Value>,
    ) -> (u16, Value) {
        read_json(self.rpc(token, method, params).await).await
    }

    async fn agent_with(&self, name: &str, actions: &[&str]) -> String {
        let (id, token) = agent_with_key(&self.f, json!({ "name": name })).await;
        if !actions.is_empty() {
            self.f.grant(&id, grant_documents(actions)).await;
        }
        token
    }
}

fn message(text: &str, extra: Value) -> Value {
    let mut sent = json!({
        "kind": "message",
        "role": "user",
        "messageId": format!("m-{text}"),
        "parts": [{ "kind": "text", "text": text }],
    });
    for (key, value) in extra.as_object().cloned().unwrap_or_default() {
        sent[key] = value;
    }
    json!({ "message": sent })
}

#[test]
fn authorizes_messages_by_skill_and_keeps_each_task_private_to_its_caller() {
    run(|| async {
        let s = gate_setup().await;
        let f = s.f.clone();
        let server = s.server.clone();
        let card = s
            .gate
            .handle(
                http::Request::builder()
                    .uri("https://agents.acme.test/.well-known/agent-card.json")
                    .body(transport::empty())
                    .unwrap(),
                move |request, caller| server.handle(request, caller),
            )
            .await
            .unwrap();
        let (status, card) = read_json(card).await;
        assert_eq!(status, 200);
        assert_eq!(card["name"], "Triage");
        assert_eq!(
            s.rpc(None, "message/send", Some(message("hi", json!({}))))
                .await
                .status(),
            401
        );

        let reader = s.agent_with("Reader", &["documents:read"]).await;
        let neighbour = s.agent_with("Neighbour", &["documents:read"]).await;
        let (_, sent) = s
            .rpc_json(
                Some(&reader),
                "message/send",
                Some(message("hi", json!({}))),
            )
            .await;
        assert_eq!(sent["result"]["id"], "task-1");
        {
            let calls = s.server.calls.lock().unwrap();
            let A2aCaller::Iam(caller) = &calls.last().unwrap().1 else {
                panic!("an IAM caller");
            };
            assert_eq!(caller.identity_kind, "agent");
        }

        let (_, got) = s
            .rpc_json(Some(&reader), "tasks/get", Some(json!({ "id": "task-1" })))
            .await;
        assert_matches(&got, json!({ "result": { "id": "task-1" } }));
        // Another caller cannot read, cancel or continue the task: it does not exist for them.
        for (method, params) in [
            ("tasks/get", json!({ "id": "task-1" })),
            ("tasks/cancel", json!({ "id": "task-1" })),
            (
                "tasks/pushNotificationConfig/set",
                json!({ "taskId": "task-1", "pushNotificationConfig": {} }),
            ),
            (
                "message/send",
                message("more", json!({ "taskId": "task-1" })),
            ),
        ] {
            let (_, answer) = s.rpc_json(Some(&neighbour), method, Some(params)).await;
            assert_matches(
                &answer,
                json!({ "error": { "code": -32001, "message": "Task not found" } }),
            );
        }
        // An operator with the task admin action may.
        let owner_token = f.owner_credential.token.clone().unwrap();
        let (_, cancelled) = s
            .rpc_json(
                Some(&owner_token),
                "tasks/cancel",
                Some(json!({ "id": "task-1" })),
            )
            .await;
        assert_matches(&cancelled, json!({ "result": { "id": "task-1" } }));

        // Tasks started over an event stream are recorded as the events pass by.
        let streamed = s
            .rpc(
                Some(&reader),
                "message/stream",
                Some(message("stream", json!({}))),
            )
            .await;
        let (_, text) = read(streamed).await;
        assert!(text.contains("status-update"));
        let (_, got) = s
            .rpc_json(Some(&reader), "tasks/get", Some(json!({ "id": "task-2" })))
            .await;
        assert_matches(&got, json!({ "result": { "id": "task-2" } }));

        // Conversations (contexts) are private the same way: only the caller who started one may add to it.
        let (_, joined) = s
            .rpc_json(
                Some(&neighbour),
                "message/send",
                Some(message("join", json!({ "contextId": "ctx-task-1" }))),
            )
            .await;
        assert_matches(&joined, json!({ "error": { "code": -32602 } }));
        let (_, again) = s
            .rpc_json(
                Some(&reader),
                "message/send",
                Some(message("again", json!({ "contextId": "ctx-task-1" }))),
            )
            .await;
        assert_matches(
            &again,
            json!({ "result": { "id": "task-3", "contextId": "ctx-task-1" } }),
        );
        // Conversations the server never started belong to no one; referenced tasks must be the caller's own.
        let (_, made_up) = s
            .rpc_json(
                Some(&reader),
                "message/send",
                Some(message("new", json!({ "contextId": "ctx-made-up" }))),
            )
            .await;
        assert_matches(&made_up, json!({ "error": { "code": -32602 } }));
        let (_, peek) = s
            .rpc_json(
                Some(&neighbour),
                "message/send",
                Some(message("peek", json!({ "referenceTaskIds": ["task-1"] }))),
            )
            .await;
        assert_matches(&peek, json!({ "error": { "code": -32001 } }));
        // A request naming two different skills is refused, so the gate and the server cannot disagree on it.
        let mut both = message("both", json!({ "metadata": { "skillId": "summarize" } }));
        both["metadata"] = json!({ "skillId": "purge" });
        let (_, both) = s.rpc_json(Some(&reader), "message/send", Some(both)).await;
        assert_matches(
            &both,
            json!({ "error": { "code": A2A_ACCESS_DENIED, "data": { "reason": "AMBIGUOUS_SKILL" } } }),
        );
        // Only JSON-RPC over POST reaches the server.
        let server = s.server.clone();
        let get = s
            .gate
            .handle(
                http::Request::builder()
                    .uri("https://agents.acme.test/v1/tasks/task-1")
                    .header("authorization", format!("Bearer {neighbour}"))
                    .body(transport::empty())
                    .unwrap(),
                move |request, caller| server.handle(request, caller),
            )
            .await
            .unwrap();
        assert_eq!(get.status(), 405);

        // Skills: the one the caller may use passes; a denied or unknown one never reaches the server.
        let skill = |id: &str| message(id, json!({ "metadata": { "skillId": id } }));
        assert_eq!(
            s.rpc(Some(&reader), "message/send", Some(skill("summarize")))
                .await
                .status(),
            200
        );
        let (status, denied) = s
            .rpc_json(Some(&reader), "message/send", Some(skill("purge")))
            .await;
        assert_eq!(status, 403);
        assert_matches(
            &denied,
            json!({ "error": { "code": A2A_ACCESS_DENIED, "data": { "reason": "ACCESS_DENIED" } } }),
        );
        let (_, mystery) = s
            .rpc_json(Some(&reader), "message/send", Some(skill("mystery")))
            .await;
        assert_matches(
            &mystery,
            json!({ "error": { "code": A2A_ACCESS_DENIED, "message": "Unknown skill", "data": { "reason": "UNKNOWN_SKILL" } } }),
        );
        let outsider = s.agent_with("Outsider", &[]).await;
        assert_eq!(
            s.rpc(
                Some(&outsider),
                "message/send",
                Some(message("hi", json!({})))
            )
            .await
            .status(),
            403
        );

        // The extended card lists only usable skills; unknown methods and batches are refused.
        let (_, extended) = s
            .rpc_json(Some(&reader), "agent/getAuthenticatedExtendedCard", None)
            .await;
        assert_matches(
            &extended,
            json!({ "result": { "skills": [{ "id": "summarize" }] } }),
        );
        let (_, dump) = s.rpc_json(Some(&reader), "admin/dump", None).await;
        assert_matches(&dump, json!({ "error": { "code": -32601 } }));
        let server = s.server.clone();
        let batch = s
            .gate
            .handle(
                rpc_request(
                    Some(&reader),
                    &json!([{ "jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": { "id": "task-1" } }]),
                ),
                move |request, caller| server.handle(request, caller),
            )
            .await
            .unwrap();
        let (_, batch) = read_json(batch).await;
        assert_matches(&batch, json!({ "error": { "code": -32600 } }));
        assert_eq!(
            s.server.methods(),
            [
                "message/send",
                "tasks/get",
                "tasks/cancel",
                "message/stream",
                "tasks/get",
                "message/send",
                "message/send",
            ]
        );

        // A gate that belongs to another tenant decides there, not in the caller's own tenant.
        let foreign = create_a2a_gate(A2aGateOptions::new(
            Arc::new(OrgIam(f.clone())),
            f.root_tenant.as_str(),
            A2aRule::action("documents:read", document("inbox")),
        ));
        let server = s.server.clone();
        let elsewhere = foreign
            .handle(
                rpc_request(
                    Some(&reader),
                    &json!({ "jsonrpc": "2.0", "id": 1, "method": "message/send", "params": message("x", json!({})) }),
                ),
                move |request, caller| server.handle(request, caller),
            )
            .await
            .unwrap();
        assert_eq!(elsewhere.status(), 403);
    });
}

#[test]
fn carries_a_hand_off_from_one_agent_to_the_next() {
    run(|| async {
        let f = Arc::new(organization(|_| {}).await);
        let alice = f.member("alice").await;
        f.grant(&alice, grant_documents(&["documents:read"])).await;
        let (assistant, assistant_token) = agent_with_key(&f, json!({ "name": "Assistant" })).await;
        let (researcher, researcher_token) =
            agent_with_key(&f, json!({ "name": "Researcher" })).await;
        let alice_session = f.sign_in(&alice).await;
        let delegation = ok(f
            .iam
            .api
            .delegations
            .grant(
                &alice_session,
                body(json!({
                    "tenantId": f.tenant_id,
                    "agentId": assistant,
                    "scopes": ["documents:read"],
                    "handoff": { "agents": [researcher] },
                })),
            )
            .await);
        let acting = ok(f
            .iam
            .api
            .delegations
            .assume(
                &bearer(&assistant_token),
                body(json!({ "tenantId": f.tenant_id, "delegationId": id_of(&delegation) })),
            )
            .await);
        let acting_token = acting["token"].as_str().unwrap().to_owned();

        // The researcher's A2A server: behind the gate, it takes up the hand-off with its own key and acts for alice.
        let acted_as: Arc<Mutex<Option<Value>>> = Arc::default();
        let gate = create_a2a_gate(A2aGateOptions::new(
            Arc::new(OrgIam(f.clone())),
            f.tenant_id.as_str(),
            A2aRule::public(),
        ));
        let researcher_server = {
            let (f, acted_as, researcher_token) =
                (f.clone(), acted_as.clone(), researcher_token.clone());
            move |request: http::Request<Body>, _caller: A2aCaller| async move {
                let payload = request_json(request).await;
                let params = payload["params"].as_object().cloned().unwrap_or_default();
                let Some(delegation_id) = handoff_of(&params) else {
                    return Ok(json_response(
                        &json!({ "jsonrpc": "2.0", "id": payload["id"], "error": { "code": -1 } }),
                    ));
                };
                let session = ok(f
                    .iam
                    .api
                    .delegations
                    .assume(
                        &bearer(&researcher_token),
                        body(json!({ "tenantId": f.tenant_id, "delegationId": delegation_id })),
                    )
                    .await);
                let session_token = session["token"].as_str().unwrap().to_owned();
                let decision = A2aIam::authorize(
                    &f.iam,
                    &bearer(&session_token),
                    &f.tenant_id,
                    "documents:read",
                    &A2aResourceRef::new("document", "q3"),
                )
                .await?;
                let summary = ok(f
                    .iam
                    .api
                    .delegations
                    .get(
                        &bearer(&session_token),
                        body(json!({ "tenantId": f.tenant_id, "delegationId": delegation_id })),
                    )
                    .await);
                let mut chain: Vec<Value> = summary["chain"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .map(|item| item["id"].clone())
                    .collect();
                chain.push(session["session"]["agentId"].clone());
                *acted_as.lock().unwrap() = Some(json!({
                    "identityId": session["session"]["identityId"],
                    "chain": chain,
                }));
                Ok(json_response(&json!({
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "result": {
                        "kind": "task",
                        "id": "research-1",
                        "contextId": "c1",
                        "status": { "state": if decision.allowed { "completed" } else { "failed" } },
                    },
                })))
            }
        };

        // The assistant hands the work on and says so in the message it sends.
        let handoff = ok(f
            .iam
            .api
            .delegations
            .handoff(
                &bearer(&acting_token),
                body(json!({ "tenantId": f.tenant_id, "agentId": researcher, "scopes": ["documents:read"] })),
            )
            .await);
        let sent = json!({
            "kind": "message",
            "role": "user",
            "messageId": "m1",
            "parts": [{ "kind": "text", "text": "Find the Q3 numbers" }],
        });
        assert_eq!(HANDOFF_METADATA_KEY, "better-iam/handoff");
        let sent = with_handoff(sent.as_object().unwrap(), &id_of(&handoff));
        assert_eq!(
            sent["metadata"],
            json!({ "better-iam/handoff": id_of(&handoff) })
        );
        let response = gate
            .handle(
                http::Request::builder()
                    .method("POST")
                    .uri("https://researcher.acme.test/a2a")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {acting_token}"))
                    .body(transport::full(
                        json!({ "jsonrpc": "2.0", "id": 1, "method": "message/send", "params": { "message": sent } })
                            .to_string(),
                    ))
                    .unwrap(),
                researcher_server,
            )
            .await
            .unwrap();
        let (_, answer) = read_json(response).await;
        assert_matches(
            &answer,
            json!({ "result": { "status": { "state": "completed" } } }),
        );
        assert_eq!(
            acted_as.lock().unwrap().clone().unwrap(),
            json!({ "identityId": alice, "chain": [assistant, researcher] })
        );
    });
}

#[test]
fn asks_the_person_an_agent_acts_for_to_confirm_a_held_back_skill() {
    run(|| async {
        let s = gate_setup().await;
        let f = s.f.clone();
        let alice = f.member("alice").await;
        f.grant(
            &alice,
            grant_documents(&["documents:read", "documents:write"]),
        )
        .await;
        let agent_key = s.agent_with("Assistant", &[]).await;
        let agent_id = f
            .iam
            .authenticate(&bearer(&agent_key))
            .await
            .unwrap()
            .identity
            .id;
        let alice_session = f.sign_in(&alice).await;
        let delegation = ok(f
            .iam
            .api
            .delegations
            .grant(
                &alice_session,
                body(json!({
                    "tenantId": f.tenant_id,
                    "agentId": agent_id,
                    "scopes": ["documents:*"],
                    "confirm": ["documents:write"],
                })),
            )
            .await);
        let acting = ok(f
            .iam
            .api
            .delegations
            .assume(
                &bearer(&agent_key),
                body(json!({ "tenantId": f.tenant_id, "delegationId": id_of(&delegation) })),
            )
            .await);
        let acting_token = acting["token"].as_str().unwrap().to_owned();
        let purge = message("purge", json!({ "metadata": { "skillId": "purge" } }));
        let (status, first) = s
            .rpc_json(Some(&acting_token), "message/send", Some(purge.clone()))
            .await;
        assert_eq!(status, 403);
        assert_eq!(first["error"]["code"], A2A_CONFIRMATION_REQUESTED);
        assert_eq!(first["error"]["data"]["reason"], "CONFIRMATION_REQUESTED");
        assert!(first["error"]["data"]["expiresAt"].is_number());
        let confirmation_id = first["error"]["data"]["confirmationId"]
            .as_str()
            .unwrap()
            .to_owned();
        ok(f
            .iam
            .api
            .delegations
            .decide_confirmation(
                &alice_session,
                body(json!({ "tenantId": f.tenant_id, "confirmationId": confirmation_id, "approve": true })),
            )
            .await);
        assert_eq!(
            s.rpc(Some(&acting_token), "message/send", Some(purge))
                .await
                .status(),
            200
        );
    });
}

/// An IAM that must not be called (`{} as never`).
struct NoIam;

#[async_trait]
impl A2aIam for NoIam {
    async fn authenticate(&self, _: &CredentialInput) -> Result<A2aPrincipal, A2aError> {
        panic!("not called")
    }

    async fn authorize(
        &self,
        _: &CredentialInput,
        _: &str,
        _: &str,
        _: &A2aResourceRef,
    ) -> Result<A2aAuthorization, A2aError> {
        panic!("not called")
    }

    async fn authorize_many(
        &self,
        _: &CredentialInput,
        _: &str,
        _: &[A2aCheck],
    ) -> Result<Vec<A2aAuthorization>, A2aError> {
        panic!("not called")
    }
}

fn iam_caller() -> A2aCaller {
    A2aCaller::Iam(A2aIamCaller {
        credential: CredentialInput::default(),
        tenant_id: "tenant".into(),
        identity_id: "someone".into(),
        identity_kind: "user".into(),
        session_kind: "user".into(),
        agent_id: None,
        delegation_id: None,
    })
}

#[test]
fn refuses_a_skill_id_that_is_not_a_string_instead_of_treating_it_as_no_skill() {
    run(|| async {
        let authorizer = create_a2a_authorizer(A2aGateOptions {
            skills: Some(IndexMap::from([(
                "purge".to_owned(),
                A2aRule::action("documents:delete", None),
            )])),
            ..A2aGateOptions::new(Arc::new(NoIam), "tenant", A2aRule::public())
        });
        let params = json!({ "message": { "metadata": { "skillId": ["purge"] } } });
        let decision = authorizer
            .can_send(&iam_caller(), params.as_object().unwrap())
            .await
            .unwrap();
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AMBIGUOUS_SKILL");
        // The same skill named twice is not ambiguous.
        let params = json!({
            "message": { "metadata": { "skillId": "other" } },
            "metadata": { "skillId": "other" },
        });
        let decision = authorizer
            .can_send(&iam_caller(), params.as_object().unwrap())
            .await
            .unwrap();
        assert_eq!(decision.reason, "UNKNOWN_SKILL");
    });
}

#[test]
fn hand_offs_and_owner_keys() {
    let message = json!({ "kind": "message", "metadata": { "trace": "t1" } });
    let handed = with_handoff(message.as_object().unwrap(), "del-1");
    assert_eq!(
        Value::Object(handed.clone()),
        json!({ "kind": "message", "metadata": { "trace": "t1", "better-iam/handoff": "del-1" } })
    );
    let params: Map<String, Value> = json!({ "message": handed }).as_object().unwrap().clone();
    assert_eq!(handoff_of(&params).as_deref(), Some("del-1"));
    // The message's hand-off comes first; a null one falls back to the request's; an empty one is none.
    let params = json!({
        "message": { "metadata": { "better-iam/handoff": null } },
        "metadata": { "better-iam/handoff": "del-2" },
    });
    assert_eq!(
        handoff_of(params.as_object().unwrap()).as_deref(),
        Some("del-2")
    );
    let params = json!({ "metadata": { "better-iam/handoff": "" } });
    assert_eq!(handoff_of(params.as_object().unwrap()), None);
    assert_eq!(task_owner_of(&iam_caller()), "iam:tenant:someone:");
    assert_eq!(
        task_owner_of(&A2aCaller::OAuth(better_iam_a2a::A2aOAuthCaller {
            subject: None,
            client_id: "client".into(),
            tenant_id: None,
            scopes: vec![],
        })),
        "oauth:client:"
    );
}

#[test]
fn memory_task_owners_expire_and_stay_bounded() {
    run(|| async {
        let now = Arc::new(Mutex::new(0.0_f64));
        let owners = memory_task_owners(MemoryTaskOwnersOptions {
            max_tasks: Some(2),
            ttl_ms: Some(1000.0),
            now: Some({
                let now = now.clone();
                Arc::new(move || *now.lock().unwrap())
            }),
        });
        owners.set("task:a", "one").await.unwrap();
        owners.set("task:b", "two").await.unwrap();
        owners.set("task:c", "three").await.unwrap();
        assert_eq!(owners.get("task:a").await.unwrap(), None);
        assert_eq!(owners.get("task:b").await.unwrap().as_deref(), Some("two"));
        *now.lock().unwrap() = 1000.0;
        assert_eq!(owners.get("task:c").await.unwrap(), None);
    });
}

#[test]
fn passes_other_methods_on_when_allowed_and_challenges_without_a_credential() {
    run(|| async {
        let f = Arc::new(organization(|_| {}).await);
        let gate = create_a2a_gate(A2aGateOptions {
            other_methods: Passthrough::Allow,
            other_http_methods: Passthrough::Allow,
            ..A2aGateOptions::new(
                Arc::new(OrgIam(f.clone())),
                f.tenant_id.as_str(),
                A2aRule::public(),
            )
        });
        let owner_token = f.owner_credential.token.clone().unwrap();
        let echo = |request: http::Request<Body>, _caller: A2aCaller| async move {
            let method = request.method().to_string();
            let content_length = request.headers().contains_key("content-length");
            let bytes = request.into_body().collect().await.unwrap().to_bytes();
            Ok(json_response(&json!({
                "method": method,
                "contentLength": content_length,
                "body": String::from_utf8_lossy(&bytes),
            })))
        };
        let response = gate
            .handle(
                http::Request::builder()
                    .method("POST")
                    .uri("https://agents.acme.test/a2a")
                    .header("x-api-key", &owner_token)
                    .header("content-length", "62")
                    .body(transport::full(
                        r#"{"jsonrpc":"2.0","id":1.0,"method":"custom/thing","x":[1e2]}"#,
                    ))
                    .unwrap(),
                echo,
            )
            .await
            .unwrap();
        let (_, answer) = read_json(response).await;
        // The server receives the request as the gate read it, written again.
        assert_eq!(
            answer,
            json!({
                "method": "POST",
                "contentLength": false,
                "body": r#"{"jsonrpc":"2.0","id":1,"method":"custom/thing","x":[100]}"#,
            })
        );
        let response = gate
            .handle(
                http::Request::builder()
                    .method("DELETE")
                    .uri("https://agents.acme.test/a2a/things/1")
                    .header("authorization", format!("bearer {owner_token}"))
                    .body(transport::empty())
                    .unwrap(),
                echo,
            )
            .await
            .unwrap();
        let (_, answer) = read_json(response).await;
        assert_eq!(answer["method"], "DELETE");

        // No credential: a challenge; a credential that does not authenticate: invalid_token.
        let response = gate
            .handle(
                http::Request::builder()
                    .method("POST")
                    .uri("https://agents.acme.test/a2a")
                    .body(transport::empty())
                    .unwrap(),
                echo,
            )
            .await
            .unwrap();
        assert_eq!(response.headers()["www-authenticate"], "Bearer");
        let (status, answer) = read_json(response).await;
        assert_eq!(status, 401);
        assert_eq!(answer["error"], "unauthorized");
        let response = gate
            .handle(
                http::Request::builder()
                    .method("POST")
                    .uri("https://agents.acme.test/a2a")
                    .header("authorization", "Bearer nope")
                    .body(transport::empty())
                    .unwrap(),
                echo,
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers()["www-authenticate"],
            "Bearer error=\"invalid_token\""
        );
        // Bodies over the limit are refused before they are read.
        let small = create_a2a_gate(A2aGateOptions {
            max_body_bytes: Some(10),
            ..A2aGateOptions::new(
                Arc::new(OrgIam(f.clone())),
                f.tenant_id.as_str(),
                A2aRule::public(),
            )
        });
        let response = small
            .handle(
                rpc_request(
                    Some(&owner_token),
                    &json!({ "jsonrpc": "2.0", "method": "tasks/get" }),
                ),
                echo,
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 413);
        // Unparseable bodies are JSON-RPC parse errors.
        let response = gate
            .handle(
                http::Request::builder()
                    .method("POST")
                    .uri("https://agents.acme.test/a2a")
                    .header("authorization", format!("Bearer {owner_token}"))
                    .body(transport::full("{"))
                    .unwrap(),
                echo,
            )
            .await
            .unwrap();
        let (_, answer) = read_json(response).await;
        assert_eq!(
            answer,
            json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error" } })
        );
    });
}

/// The gate's futures can run on a multi-threaded runtime.
#[allow(dead_code)]
fn the_gate_is_send(gate: A2aGate, request: http::Request<Body>) {
    fn send<T: Send>(_: T) {}
    send(gate.handle(request, |_, _| async {
        Ok(http::Response::new(transport::empty()))
    }));
    let owners: Arc<dyn A2aTaskOwners> =
        Arc::new(memory_task_owners(MemoryTaskOwnersOptions::default()));
    send(owners);
}
