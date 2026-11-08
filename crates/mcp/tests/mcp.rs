//! The port of tests/mcp.test.ts: the MCP gate in front of a stand-in MCP server.

#[path = "../../server/tests/organization_fixture/mod.rs"]
mod organization_fixture;

use std::borrow::Borrow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_iam_core::{CredentialInput, IamError, IamResult};
use better_iam_mcp::{
    GateBody, McpAuthorizerOptions, McpCaller, McpGate, McpGateOptions, McpOAuthRequest,
    McpOAuthToken, McpOAuthVerifier, McpResource, McpResourceMetadata, McpResourceRef,
    McpScopeRequirement, McpTenant, McpToolRule,
};
use better_iam_server::BetterIam;
use bytes::Bytes;
use http::{Request, Response};
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody};
use organization_fixture::{Org, assert_matches, body, ok, organization, run};
use serde_json::{Value, json};

impl Borrow<BetterIam> for Org {
    fn borrow(&self) -> &BetterIam {
        &self.iam
    }
}

fn tools() -> Value {
    json!([
        { "name": "search_docs", "description": "Search", "inputSchema": { "type": "object" } },
        { "name": "delete_doc", "description": "Delete", "inputSchema": { "type": "object" } },
        { "name": "ping", "description": "Ping", "inputSchema": { "type": "object" } },
        { "name": "secret_tool", "description": "Not in the rules", "inputSchema": { "type": "object" } },
    ])
}

type Calls = Arc<Mutex<Vec<(String, McpCaller, Value)>>>;

fn boxed_full(bytes: impl Into<Bytes>) -> GateBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn json_response(value: &Value) -> Response<GateBody> {
    let mut response = Response::new(boxed_full(value.to_string()));
    response.headers_mut().insert(
        "content-type",
        http::HeaderValue::from_static("application/json"),
    );
    response
}

/// A stand-in MCP server: answers tools/list (JSON, or SSE when asked) and echoes tools/call with the caller.
async fn mcp_server(
    calls: Calls,
    request: Request<GateBody>,
    caller: McpCaller,
) -> Response<GateBody> {
    let sse = request.headers().contains_key("x-test-sse");
    let bytes = request.into_body().collect().await.unwrap().to_bytes();
    let message: Value = serde_json::from_slice(&bytes).unwrap();
    let method = message["method"].as_str().unwrap_or_default().to_owned();
    calls.lock().unwrap().push((
        method.clone(),
        caller,
        message.get("params").cloned().unwrap_or(Value::Null),
    ));
    if method == "tools/list" {
        let response =
            json!({ "jsonrpc": "2.0", "id": message["id"], "result": { "tools": tools() } });
        if sse {
            let text = format!(
                "event: message\ndata: {}\n\nevent: message\ndata: {}\n\n",
                json!({ "jsonrpc": "2.0", "method": "notifications/progress" }),
                response
            );
            let chunks: Vec<Result<Frame<Bytes>, better_iam_mcp::BoxError>> = text
                .as_bytes()
                .chunks(23)
                .map(|chunk| Ok(Frame::data(Bytes::copy_from_slice(chunk))))
                .collect();
            let mut answer =
                Response::new(StreamBody::new(futures::stream::iter(chunks)).boxed_unsync());
            answer.headers_mut().insert(
                "content-type",
                http::HeaderValue::from_static("text/event-stream"),
            );
            return answer;
        }
        return json_response(&response);
    }
    json_response(&json!({
        "jsonrpc": "2.0",
        "id": message["id"],
        "result": { "content": [{ "type": "text", "text": format!("ran {}", message["params"]["name"].as_str().unwrap_or("undefined")) }] },
    }))
}

struct OAuth;

#[async_trait]
impl McpOAuthVerifier for OAuth {
    async fn verify_request(
        &self,
        request: &McpOAuthRequest,
        _requirement: Option<&McpScopeRequirement>,
    ) -> IamResult<McpOAuthToken> {
        if request.authorization.as_deref() != Some("Bearer oauth-access-token") {
            return Err(IamError::new("INVALID_TOKEN", "invalid token"));
        }
        Ok(McpOAuthToken {
            subject: Some("user-1".into()),
            client_id: "claude-desktop".into(),
            tenant_id: None,
            scopes: vec!["docs.search".into()],
        })
    }
}

struct Setup {
    org: Arc<Org>,
    calls: Calls,
    gate: McpGate,
}

fn rules() -> HashMap<String, McpToolRule> {
    let mut tools = HashMap::new();
    tools.insert(
        "search_docs".to_owned(),
        McpToolRule {
            action: Some("documents:read".into()),
            resource: Some(McpResource::Fixed(McpResourceRef::new("document", "index"))),
            scopes: Some(vec!["docs.search".into()]),
            ..McpToolRule::default()
        },
    );
    tools.insert(
        "delete_doc".to_owned(),
        McpToolRule {
            action: Some("documents:write".into()),
            resource: Some(McpResource::derived(|args| {
                let id = match args.get("id") {
                    Some(Value::String(id)) => id.clone(),
                    Some(Value::Number(id)) => {
                        better_iam_core::js::number_to_string(id.as_f64().unwrap_or(f64::NAN))
                    }
                    Some(other) => other.to_string(),
                    None => "undefined".into(),
                };
                Ok(McpResourceRef::new("document", id))
            })),
            list_as: Some(McpResourceRef::new("document", "any")),
            scopes: Some(vec!["docs.delete".into()]),
            ..McpToolRule::default()
        },
    );
    tools.insert(
        "ping".to_owned(),
        McpToolRule {
            public: true,
            ..McpToolRule::default()
        },
    );
    tools
}

async fn setup() -> Setup {
    let org = Arc::new(organization(|_| {}).await);
    let mut authorizer = McpAuthorizerOptions::new(
        org.clone(),
        McpTenant::Fixed(org.tenant_id.clone()),
        rules(),
    );
    authorizer.oauth = Some(Arc::new(OAuth));
    let gate = McpGate::new(McpGateOptions {
        authorizer,
        metadata: Some(McpResourceMetadata {
            resource: "https://mcp.acme.test/mcp".into(),
            authorization_servers: vec!["https://iam.acme.test/oauth".into()],
            scopes: Some(vec!["docs.search".into(), "docs.delete".into()]),
            resource_name: None,
            documentation: None,
        }),
        max_body_bytes: None,
    })
    .unwrap();
    Setup {
        org,
        calls: Arc::new(Mutex::new(Vec::new())),
        gate,
    }
}

struct Answer {
    status: u16,
    headers: http::HeaderMap,
    text: String,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }

    fn names(&self) -> Vec<String> {
        self.json()["result"]["tools"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_owned())
            .collect()
    }
}

async fn read(response: Response<GateBody>) -> Answer {
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    Answer {
        status: parts.status.as_u16(),
        headers: parts.headers,
        text: String::from_utf8(bytes.to_vec()).unwrap(),
    }
}

async fn send(gate: &McpGate, calls: &Calls, request: Request<GateBody>) -> Answer {
    let calls = calls.clone();
    let response = gate
        .handle(request, move |request, caller| {
            mcp_server(calls, request, caller)
        })
        .await
        .unwrap();
    read(response).await
}

impl Setup {
    async fn rpc(
        &self,
        token: Option<&str>,
        method: &str,
        params: Option<Value>,
        headers: &[(&str, &str)],
    ) -> Answer {
        let mut message = json!({ "jsonrpc": "2.0", "id": 7, "method": method });
        if let Some(params) = params {
            message["params"] = params;
        }
        let mut request = Request::builder()
            .method("POST")
            .uri("https://mcp.acme.test/mcp")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let request = request.body(boxed_full(message.to_string())).unwrap();
        send(&self.gate, &self.calls, request).await
    }

    fn methods(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(method, _, _)| method.clone())
            .collect()
    }

    fn last_caller(&self) -> Value {
        serde_json::to_value(&self.calls.lock().unwrap().last().unwrap().1).unwrap()
    }
}

async fn grant_documents(org: &Org, subject_id: &str, actions: &[&str]) {
    let role = ok(org
        .iam
        .api
        .roles
        .create(
            &org.owner_credential,
            body(json!({
                "tenantId": org.tenant_id,
                "name": format!("Docs {subject_id}"),
                "document": { "version": 1, "statements": [{ "effect": "allow", "actions": actions, "resources": ["document/*"] }] },
            })),
        )
        .await);
    ok(org
        .iam
        .api
        .bindings
        .create(
            &org.owner_credential,
            body(json!({
                "tenantId": org.tenant_id,
                "roleId": role["id"],
                "subjectType": "identity",
                "subjectId": subject_id,
            })),
        )
        .await);
}

async fn agent_with_key(org: &Org, name: &str) -> (String, String) {
    let agent = ok(org
        .iam
        .api
        .agents
        .create(
            &org.owner_credential,
            body(json!({ "tenantId": org.tenant_id, "name": name })),
        )
        .await);
    let agent_id = agent["id"].as_str().unwrap().to_owned();
    let key = ok(org
        .iam
        .api
        .credentials
        .create(
            &org.owner_credential,
            body(json!({ "tenantId": org.tenant_id, "identityId": agent_id })),
        )
        .await);
    (agent_id, key["token"].as_str().unwrap().to_owned())
}

fn token_of(credential: &CredentialInput) -> CredentialInput {
    CredentialInput {
        headers: None,
        token: credential.token.clone(),
    }
}

fn bearer(token: &str) -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some(token.to_owned()),
    }
}

#[test]
fn challenges_unauthenticated_callers_and_serves_protected_resource_metadata() {
    run(|| async {
        let setup = setup().await;
        let anonymous = setup.rpc(None, "tools/list", None, &[]).await;
        assert_eq!(anonymous.status, 401);
        assert_eq!(
            anonymous.headers.get("www-authenticate").unwrap(),
            "Bearer resource_metadata=\"https://mcp.acme.test/.well-known/oauth-protected-resource/mcp\""
        );
        let invalid = setup
            .rpc(
                Some("biam_key_not-a-real-key-at-all-0000000000000000000000000"),
                "tools/list",
                None,
                &[],
            )
            .await;
        assert_eq!(invalid.status, 401);
        assert!(
            invalid
                .headers
                .get("www-authenticate")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("error=\"invalid_token\"")
        );
        let request = Request::builder()
            .uri("https://mcp.acme.test/.well-known/oauth-protected-resource/mcp")
            .body(boxed_full(""))
            .unwrap();
        let metadata = send(&setup.gate, &setup.calls, request).await;
        assert_eq!(
            metadata.json(),
            json!({
                "resource": "https://mcp.acme.test/mcp",
                "authorization_servers": ["https://iam.acme.test/oauth"],
                "scopes_supported": ["docs.search", "docs.delete"],
                "bearer_methods_supported": ["header"],
            })
        );
        // The metadata path also answers relative request targets (as servers receive them).
        let relative = Request::builder()
            .method("OPTIONS")
            .uri("/.well-known/oauth-protected-resource/mcp")
            .body(boxed_full(""))
            .unwrap();
        let preflight = send(&setup.gate, &setup.calls, relative).await;
        assert_eq!(preflight.status, 204);
        assert!(setup.calls.lock().unwrap().is_empty());
    });
}

#[test]
fn decides_an_agents_tool_calls_with_its_own_grants_and_filters_the_tool_list() {
    run(|| async {
        let setup = setup().await;
        let org = &setup.org;
        let (agent_id, token) = agent_with_key(org, "Docs agent").await;
        grant_documents(org, &agent_id, &["documents:read"]).await;

        assert_eq!(
            setup
                .rpc(Some(&token), "tools/list", None, &[])
                .await
                .names(),
            vec!["search_docs", "ping"]
        );
        let allowed = setup
            .rpc(
                Some(&token),
                "tools/call",
                Some(json!({ "name": "search_docs", "arguments": { "q": "x" } })),
                &[],
            )
            .await;
        assert_matches(
            &allowed.json(),
            json!({ "result": { "content": [{ "type": "text", "text": "ran search_docs" }] } }),
        );
        assert_matches(
            &setup.last_caller(),
            json!({ "kind": "iam", "identityKind": "agent", "agentId": agent_id, "tenantId": org.tenant_id }),
        );

        let refused = setup
            .rpc(
                Some(&token),
                "tools/call",
                Some(json!({ "name": "delete_doc", "arguments": { "id": "q3" } })),
                &[],
            )
            .await;
        assert_eq!(
            refused.json(),
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "result": {
                    "content": [{ "type": "text", "text": "Access denied: you may not call delete_doc" }],
                    "isError": true,
                },
            })
        );
        let unknown = setup
            .rpc(
                Some(&token),
                "tools/call",
                Some(json!({ "name": "secret_tool" })),
                &[],
            )
            .await;
        assert_matches(
            &unknown.json(),
            json!({ "result": { "isError": true, "content": [{ "type": "text", "text": "Unknown tool: secret_tool" }] } }),
        );
        // Refused calls never reach the server, and the server audits the denial with the agent attached.
        assert_eq!(setup.methods(), vec!["tools/list", "tools/call"]);
        let denials = ok(org
            .iam
            .api
            .audit
            .list(
                &org.owner_credential,
                body(json!({ "tenantId": org.tenant_id, "action": "documents:write", "outcome": "deny" })),
            )
            .await);
        assert_matches(
            &denials[0],
            json!({ "actorId": agent_id, "resourceId": "q3" }),
        );

        // The same list arrives filtered inside an event stream.
        let streamed = setup
            .rpc(Some(&token), "tools/list", None, &[("x-test-sse", "1")])
            .await;
        assert!(streamed.text.contains("notifications/progress"));
        let data: Vec<Value> = streamed
            .text
            .split('\n')
            .filter(|line| line.starts_with("data: ") && line.contains("\"tools\""))
            .map(|line| serde_json::from_str(&line[6..]).unwrap())
            .collect();
        let names: Vec<&str> = data[0]["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["search_docs", "ping"]);
    });
}

#[test]
fn lets_a_delegated_agent_act_as_the_person_within_the_delegation() {
    run(|| async {
        let setup = setup().await;
        let org = &setup.org;
        let alice = org.member("alice").await;
        grant_documents(org, &alice, &["documents:read", "documents:write"]).await;
        let (agent_id, key) = agent_with_key(org, "Assistant").await;
        let alice_session = token_of(&org.sign_in(&alice).await);
        let delegation = ok(org
            .iam
            .api
            .delegations
            .grant(
                &alice_session,
                body(json!({ "tenantId": org.tenant_id, "agentId": agent_id, "scopes": ["documents:*"] })),
            )
            .await);
        let acting = ok(org
            .iam
            .api
            .delegations
            .assume(
                &bearer(&key),
                body(json!({ "tenantId": org.tenant_id, "delegationId": delegation["id"] })),
            )
            .await);
        let acting = acting["token"].as_str().unwrap().to_owned();
        assert_eq!(
            setup
                .rpc(Some(&acting), "tools/list", None, &[])
                .await
                .names(),
            vec!["search_docs", "delete_doc", "ping"]
        );
        let deleted = setup
            .rpc(
                Some(&acting),
                "tools/call",
                Some(json!({ "name": "delete_doc", "arguments": { "id": "draft" } })),
                &[],
            )
            .await;
        assert_matches(
            &deleted.json(),
            json!({ "result": { "content": [{ "type": "text", "text": "ran delete_doc" }] } }),
        );

        // Narrow the delegation to reading and the destructive tool disappears.
        ok(org
            .iam
            .api
            .delegations
            .revoke(
                &alice_session,
                body(json!({ "tenantId": org.tenant_id, "delegationId": delegation["id"] })),
            )
            .await);
        assert_eq!(
            setup
                .rpc(Some(&acting), "tools/list", None, &[])
                .await
                .status,
            401
        );
        let fresh = token_of(&org.sign_in(&alice).await);
        let read_only = ok(org
            .iam
            .api
            .delegations
            .grant(
                &fresh,
                body(json!({ "tenantId": org.tenant_id, "agentId": agent_id, "scopes": ["documents:read"] })),
            )
            .await);
        let reader = ok(org
            .iam
            .api
            .delegations
            .assume(
                &bearer(&key),
                body(json!({ "tenantId": org.tenant_id, "delegationId": read_only["id"] })),
            )
            .await);
        let reader = reader["token"].as_str().unwrap().to_owned();
        assert_eq!(
            setup
                .rpc(Some(&reader), "tools/list", None, &[])
                .await
                .names(),
            vec!["search_docs", "ping"]
        );
    });
}

#[test]
fn asks_the_person_to_confirm_a_held_back_tool_call_then_lets_the_retry_through() {
    run(|| async {
        let setup = setup().await;
        let org = &setup.org;
        let alice = org.member("alice").await;
        grant_documents(org, &alice, &["documents:read", "documents:write"]).await;
        let (agent_id, key) = agent_with_key(org, "Careful agent").await;
        let alice_session = token_of(&org.sign_in(&alice).await);
        let delegation = ok(org
            .iam
            .api
            .delegations
            .grant(
                &alice_session,
                body(json!({
                    "tenantId": org.tenant_id,
                    "agentId": agent_id,
                    "scopes": ["documents:*"],
                    "confirm": ["documents:write"],
                })),
            )
            .await);
        let acting = ok(org
            .iam
            .api
            .delegations
            .assume(
                &bearer(&key),
                body(json!({ "tenantId": org.tenant_id, "delegationId": delegation["id"] })),
            )
            .await);
        let acting = acting["token"].as_str().unwrap().to_owned();
        let first = setup
            .rpc(
                Some(&acting),
                "tools/call",
                Some(json!({ "name": "delete_doc", "arguments": { "id": "draft" } })),
                &[],
            )
            .await
            .json();
        assert_eq!(first["result"]["isError"], true);
        assert!(
            first["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("must confirm this call first")
        );
        let confirmation_id = first["result"]["_meta"]["better-iam/confirmationId"]
            .as_str()
            .expect("confirmation id")
            .to_owned();
        let pending = ok(org
            .iam
            .api
            .delegations
            .list_confirmations(
                &alice_session,
                body(json!({ "tenantId": org.tenant_id, "status": "pending" })),
            )
            .await);
        let pending = pending.as_array().unwrap();
        assert_eq!(pending.len(), 1);
        assert_matches(
            &pending[0],
            json!({
                "id": confirmation_id,
                "action": "documents:write",
                "resource": { "type": "document", "id": "draft" },
            }),
        );
        assert!(
            pending[0]["reason"]
                .as_str()
                .unwrap()
                .contains("delete_doc")
        );
        // Reading is not held back.
        assert_matches(
            &setup
                .rpc(
                    Some(&acting),
                    "tools/call",
                    Some(json!({ "name": "search_docs" })),
                    &[],
                )
                .await
                .json(),
            json!({ "result": { "content": [{ "type": "text", "text": "ran search_docs" }] } }),
        );

        ok(org
            .iam
            .api
            .delegations
            .decide_confirmation(
                &alice_session,
                body(json!({ "tenantId": org.tenant_id, "confirmationId": confirmation_id, "approve": true })),
            )
            .await);
        let retry = setup
            .rpc(
                Some(&acting),
                "tools/call",
                Some(json!({ "name": "delete_doc", "arguments": { "id": "draft" } })),
                &[],
            )
            .await;
        assert_matches(
            &retry.json(),
            json!({ "result": { "content": [{ "type": "text", "text": "ran delete_doc" }] } }),
        );
        assert_eq!(
            setup
                .methods()
                .iter()
                .filter(|method| *method == "tools/call")
                .count(),
            2
        );
    });
}

#[test]
fn decides_oauth_callers_by_scope() {
    run(|| async {
        let setup = setup().await;
        assert_eq!(
            setup
                .rpc(Some("oauth-access-token"), "tools/list", None, &[])
                .await
                .names(),
            vec!["search_docs", "ping"]
        );
        let refused = setup
            .rpc(
                Some("oauth-access-token"),
                "tools/call",
                Some(json!({ "name": "delete_doc", "arguments": { "id": 1 } })),
                &[],
            )
            .await;
        assert_matches(&refused.json(), json!({ "result": { "isError": true } }));
        setup
            .rpc(
                Some("oauth-access-token"),
                "tools/call",
                Some(json!({ "name": "search_docs" })),
                &[],
            )
            .await;
        assert_eq!(
            setup.last_caller(),
            json!({ "kind": "oauth", "clientId": "claude-desktop", "subject": "user-1", "scopes": ["docs.search"] })
        );
        // Other methods pass straight through.
        let initialize = setup
            .rpc(
                Some("oauth-access-token"),
                "initialize",
                Some(json!({ "protocolVersion": "2025-11-25" })),
                &[],
            )
            .await;
        assert_eq!(initialize.status, 200);
    });
}

#[test]
fn decides_in_the_servers_own_tenant_never_the_callers_and_bounds_request_bodies() {
    run(|| async {
        let setup = setup().await;
        let org = &setup.org;
        let (agent_id, token) = agent_with_key(org, "Elsewhere").await;
        grant_documents(org, &agent_id, &["documents:read"]).await;
        // A gate that belongs to another tenant (the platform root) does not honour grants the caller holds in Acme.
        let mut tools = HashMap::new();
        tools.insert(
            "search_docs".to_owned(),
            McpToolRule {
                action: Some("documents:read".into()),
                resource: Some(McpResource::Fixed(McpResourceRef::new("document", "x"))),
                ..McpToolRule::default()
            },
        );
        let foreign = McpGate::new(McpGateOptions {
            authorizer: McpAuthorizerOptions::new(
                setup.org.clone(),
                McpTenant::Fixed(org.root_tenant.clone()),
                tools,
            ),
            metadata: None,
            max_body_bytes: None,
        })
        .unwrap();
        let request = |body: GateBody| {
            Request::builder()
                .method("POST")
                .uri("https://mcp.acme.test/mcp")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(body)
                .unwrap()
        };
        let refused = send(
            &foreign,
            &setup.calls,
            request(boxed_full(
                json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "search_docs" } })
                    .to_string(),
            )),
        )
        .await;
        assert_matches(&refused.json(), json!({ "result": { "isError": true } }));
        // A body without a declared length is still cut off at the limit.
        let small = McpGate::new(McpGateOptions {
            authorizer: McpAuthorizerOptions::new(
                setup.org.clone(),
                McpTenant::Fixed(org.tenant_id.clone()),
                HashMap::new(),
            ),
            metadata: None,
            max_body_bytes: Some(1024),
        })
        .unwrap();
        let chunks: Vec<Result<Frame<Bytes>, better_iam_mcp::BoxError>> = (0..5)
            .map(|_| Ok(Frame::data(Bytes::from("x".repeat(600)))))
            .collect();
        let stream = StreamBody::new(futures::stream::iter(chunks)).boxed_unsync();
        assert_eq!(
            send(&small, &setup.calls, request(stream)).await.status,
            413
        );
        assert!(setup.calls.lock().unwrap().is_empty());
    });
}

#[test]
fn refuses_batched_tool_traffic_and_tool_names_that_are_not_strings() {
    run(|| async {
        let setup = setup().await;
        let (agent_id, token) = agent_with_key(&setup.org, "Batcher").await;
        grant_documents(&setup.org, &agent_id, &["documents:read"]).await;
        let post = |body: &str| {
            Request::builder()
                .method("POST")
                .uri("https://mcp.acme.test/mcp")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(boxed_full(body.to_owned()))
                .unwrap()
        };
        let batch = send(
            &setup.gate,
            &setup.calls,
            post(r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]"#),
        )
        .await;
        assert_eq!(batch.status, 400);
        assert_eq!(batch.json()["error"]["code"], -32600);
        let name = send(
            &setup.gate,
            &setup.calls,
            post(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":["search_docs"]}}"#),
        )
        .await;
        assert_eq!(name.status, 400);
        assert_eq!(
            name.json(),
            json!({ "jsonrpc": "2.0", "id": 3, "error": { "code": -32602, "message": "The tool name must be a string" } })
        );
        let parse = send(&setup.gate, &setup.calls, post("{not json")).await;
        assert_eq!(parse.status, 400);
        assert_eq!(parse.json()["error"]["code"], -32700);
        assert!(setup.calls.lock().unwrap().is_empty());
    });
}
