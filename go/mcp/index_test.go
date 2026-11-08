package mcp_test

// Port of tests/mcp.test.ts.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/internal/orgfixture"
	"github.com/Better-IAM/better-iam/go/mcp"
	"github.com/Better-IAM/better-iam/go/server"
)

var tools = []any{
	map[string]any{"name": "search_docs", "description": "Search", "inputSchema": map[string]any{"type": "object"}},
	map[string]any{"name": "delete_doc", "description": "Delete", "inputSchema": map[string]any{"type": "object"}},
	map[string]any{"name": "ping", "description": "Ping", "inputSchema": map[string]any{"type": "object"}},
	map[string]any{"name": "secret_tool", "description": "Not in the rules", "inputSchema": map[string]any{"type": "object"}},
}

type call struct {
	method string
	caller *mcp.Caller
}

// mcpServer is a stand-in MCP server: it answers tools/list (JSON, or SSE when asked) and echoes tools/call.
type mcpServer struct {
	mu    sync.Mutex
	calls []call
}

func (s *mcpServer) recorded() []call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]call{}, s.calls...)
}

func (s *mcpServer) handle(r *http.Request, caller *mcp.Caller) (*http.Response, error) {
	var message struct {
		ID     any            `json:"id"`
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.calls = append(s.calls, call{method: message.Method, caller: caller})
	s.mu.Unlock()
	if message.Method == "tools/list" {
		response, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": message.ID, "result": map[string]any{"tools": tools}})
		if r.Header.Get("x-test-sse") != "" {
			progress, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/progress"})
			text := "event: message\ndata: " + string(progress) + "\n\nevent: message\ndata: " + string(response) + "\n\n"
			reader, writer := io.Pipe()
			go func() {
				data := []byte(text)
				for index := 0; index < len(data); index += 23 {
					_, _ = writer.Write(data[index:min(index+23, len(data))])
				}
				_ = writer.Close()
			}()
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: reader}, nil
		}
		return jsonAnswer(response), nil
	}
	response, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": message.ID,
		"result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "ran " + toString(message.Params["name"])}}},
	})
	return jsonAnswer(response), nil
}

func toString(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return "undefined"
}

func jsonAnswer(body []byte) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}
}

// oauth accepts one access token.
type oauth struct{}

func (oauth) VerifyRequest(_ context.Context, request mcp.OAuthRequest, _ *mcp.OAuthRequirement) (*mcp.OAuthToken, error) {
	if request.Authorization != "Bearer oauth-access-token" {
		return nil, errors.New("invalid token")
	}
	return &mcp.OAuthToken{Subject: "user-1", ClientID: "claude-desktop", Scopes: []string{"docs.search"}}, nil
}

type harness struct {
	f      *orgfixture.Fixture
	server *mcpServer
	gate   *mcp.Gate
}

func setup(t *testing.T) *harness {
	t.Helper()
	f := orgfixture.New(t, nil)
	gate, err := mcp.NewGate(mcp.GateOptions{
		AuthorizerOptions: mcp.AuthorizerOptions{
			IAM: f.IAM, TenantID: f.TenantID,
			Tools: map[string]mcp.ToolRule{
				"search_docs": {Action: "documents:read", Resource: &mcp.ResourceRef{Type: "document", ID: "index"}, Scopes: []string{"docs.search"}},
				"delete_doc": {
					Action: "documents:write",
					DeriveResource: func(args *core.Object) (mcp.ResourceRef, error) {
						return mcp.ResourceRef{Type: "document", ID: jsString(args.Get("id"))}, nil
					},
					ListAs: &mcp.ResourceRef{Type: "document", ID: "any"}, Scopes: []string{"docs.delete"},
				},
				"ping": {Public: true},
			},
			OAuth: oauth{},
		},
		Metadata: &mcp.ResourceMetadata{
			Resource: "https://mcp.acme.test/mcp", AuthorizationServers: []string{"https://iam.acme.test/oauth"},
			Scopes: []string{"docs.search", "docs.delete"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{f: f, server: &mcpServer{}, gate: gate}
}

func jsString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case float64:
		return core.NumberString(v)
	}
	return core.MustStringify(value)
}

func (h *harness) rpc(t *testing.T, token, method string, params any, header map[string]string) *http.Response {
	t.Helper()
	message := map[string]any{"jsonrpc": "2.0", "id": 7, "method": method}
	if params != nil {
		message["params"] = params
	}
	body, _ := json.Marshal(message)
	request := httptest.NewRequest("POST", "https://mcp.acme.test/mcp", bytes.NewReader(body))
	request.Header.Set("content-type", "application/json")
	request.Header.Set("accept", "application/json, text/event-stream")
	if token != "" {
		request.Header.Set("authorization", "Bearer "+token)
	}
	for name, value := range header {
		request.Header.Set(name, value)
	}
	response, err := h.gate.Handle(request, h.server.handle)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func decode(t *testing.T, response *http.Response) map[string]any {
	t.Helper()
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("not JSON: %s", data)
	}
	return value
}

func names(t *testing.T, response *http.Response) []string {
	t.Helper()
	result, _ := decode(t, response)["result"].(map[string]any)
	list, _ := result["tools"].([]any)
	out := make([]string, len(list))
	for index, tool := range list {
		out[index], _ = tool.(map[string]any)["name"].(string)
	}
	return out
}

func text(t *testing.T, value map[string]any) string {
	t.Helper()
	result, _ := value["result"].(map[string]any)
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content: %v", value)
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	return text
}

func expectNames(t *testing.T, got []string, want ...string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected tools %v, got %v", want, got)
	}
}

func grantDocuments(t *testing.T, f *orgfixture.Fixture, subjectID string, actions ...string) {
	t.Helper()
	list := make([]any, len(actions))
	for index, action := range actions {
		list[index] = action
	}
	role := f.Object(f.IAM.API.Roles.Create(f.Ctx, f.Owner, server.Input[apitypes.RolesCreateInput](core.NewObject(
		"tenantId", f.TenantID, "name", "Docs "+subjectID,
		"document", core.NewObject("version", float64(1), "statements", []any{core.NewObject("effect", "allow", "actions", list, "resources", []any{"document/*"})}),
	))))
	f.Object(f.IAM.API.Bindings.Create(f.Ctx, f.Owner, server.Input[apitypes.BindingsCreateInput](core.NewObject(
		"tenantId", f.TenantID, "roleId", role.Get("id"), "subjectType", "identity", "subjectId", subjectID,
	))))
}

func createAgent(t *testing.T, f *orgfixture.Fixture, name string) (id, token string) {
	t.Helper()
	agent := f.Object(f.IAM.API.Agents.Create(f.Ctx, f.Owner, server.Input[apitypes.AgentsCreateInput](core.NewObject("tenantId", f.TenantID, "name", name))))
	id, _ = agent.Get("id").(string)
	key := f.Object(f.IAM.API.Credentials.Create(f.Ctx, f.Owner, server.Input[apitypes.CredentialsCreateInput](core.NewObject("tenantId", f.TenantID, "identityId", id))))
	token, _ = key.Get("token").(string)
	return id, token
}

func TestMcpGateChallengesUnauthenticatedCallersAndServesProtectedResourceMetadata(t *testing.T) {
	h := setup(t)
	anonymous := h.rpc(t, "", "tools/list", nil, nil)
	if anonymous.StatusCode != 401 {
		t.Fatalf("status %d", anonymous.StatusCode)
	}
	if got := anonymous.Header.Get("www-authenticate"); got != `Bearer resource_metadata="https://mcp.acme.test/.well-known/oauth-protected-resource/mcp"` {
		t.Fatalf("challenge %q", got)
	}
	invalid := h.rpc(t, "biam_key_not-a-real-key-at-all-0000000000000000000000000", "tools/list", nil, nil)
	if invalid.StatusCode != 401 || !strings.Contains(invalid.Header.Get("www-authenticate"), `error="invalid_token"`) {
		t.Fatalf("invalid token: %d %q", invalid.StatusCode, invalid.Header.Get("www-authenticate"))
	}
	metadata, err := h.gate.Handle(httptest.NewRequest("GET", "https://mcp.acme.test/.well-known/oauth-protected-resource/mcp", nil), h.server.handle)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(decode(t, metadata))
	want := `{"authorization_servers":["https://iam.acme.test/oauth"],"bearer_methods_supported":["header"],"resource":"https://mcp.acme.test/mcp","scopes_supported":["docs.search","docs.delete"]}`
	if string(got) != want {
		t.Fatalf("metadata %s", got)
	}
	if len(h.server.recorded()) != 0 {
		t.Fatal("the server must not be reached")
	}
}

func TestMcpGateDecidesAnAgentsToolCallsWithItsOwnGrantsAndFiltersTheToolList(t *testing.T) {
	h := setup(t)
	f := h.f
	agentID, token := createAgent(t, f, "Docs agent")
	grantDocuments(t, f, agentID, "documents:read")

	expectNames(t, names(t, h.rpc(t, token, "tools/list", nil, nil)), "search_docs", "ping")
	allowed := h.rpc(t, token, "tools/call", map[string]any{"name": "search_docs", "arguments": map[string]any{"q": "x"}}, nil)
	if got := text(t, decode(t, allowed)); got != "ran search_docs" {
		t.Fatalf("allowed: %q", got)
	}
	calls := h.server.recorded()
	last := calls[len(calls)-1].caller
	if last.Kind != mcp.CallerIAM || last.IdentityKind != "agent" || last.AgentID != agentID || last.TenantID != f.TenantID {
		t.Fatalf("caller %+v", last)
	}

	refused := decode(t, h.rpc(t, token, "tools/call", map[string]any{"name": "delete_doc", "arguments": map[string]any{"id": "q3"}}, nil))
	got, _ := json.Marshal(refused)
	if string(got) != `{"id":7,"jsonrpc":"2.0","result":{"content":[{"text":"Access denied: you may not call delete_doc","type":"text"}],"isError":true}}` {
		t.Fatalf("refused %s", got)
	}
	unknown := decode(t, h.rpc(t, token, "tools/call", map[string]any{"name": "secret_tool"}, nil))
	if text(t, unknown) != "Unknown tool: secret_tool" || unknown["result"].(map[string]any)["isError"] != true {
		t.Fatalf("unknown %v", unknown)
	}
	// Refused calls never reach the server, and the server audits the denial with the agent attached.
	var methods []string
	for _, call := range h.server.recorded() {
		methods = append(methods, call.method)
	}
	expectNames(t, methods, "tools/list", "tools/call")
	denials := f.Items(f.IAM.API.Audit.List(f.Ctx, f.Owner, server.Input[apitypes.AuditListInput](core.NewObject(
		"tenantId", f.TenantID, "action", "documents:write", "outcome", "deny",
	))))
	// The tools/list filter (resource "any") and the refused call (resource "q3") both audit a
	// deny, often in the same millisecond, and audit ties are ordered by random id, so the q3
	// denial is looked up rather than assumed to be first.
	var refusedDenial *core.Object
	for _, denial := range denials {
		if denial.Get("resourceId") == "q3" {
			refusedDenial = denial
			break
		}
	}
	if refusedDenial == nil || refusedDenial.Get("actorId") != agentID {
		t.Fatalf("denials %v", denials)
	}

	// The same list arrives filtered inside an event stream.
	streamed := h.rpc(t, token, "tools/list", nil, map[string]string{"x-test-sse": "1"})
	data, err := io.ReadAll(streamed.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "notifications/progress") {
		t.Fatalf("stream %s", data)
	}
	var lists []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, `"tools"`) {
			lists = append(lists, line[6:])
		}
	}
	if len(lists) == 0 {
		t.Fatalf("no tool list in %s", data)
	}
	var message struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lists[0]), &message); err != nil {
		t.Fatal(err)
	}
	var streamedNames []string
	for _, tool := range message.Result.Tools {
		streamedNames = append(streamedNames, tool.Name)
	}
	expectNames(t, streamedNames, "search_docs", "ping")
}

func TestMcpGateLetsADelegatedAgentActAsThePersonWithinTheDelegation(t *testing.T) {
	h := setup(t)
	f := h.f
	alice := f.Member("alice")
	aliceID, _ := alice.Get("id").(string)
	grantDocuments(t, f, aliceID, "documents:read", "documents:write")
	agentID, key := createAgent(t, f, "Assistant")
	aliceSession := core.CredentialInput{Token: f.SignIn("alice")}
	delegation := f.Object(f.IAM.API.Delegations.Grant(f.Ctx, aliceSession, server.Input[apitypes.DelegationsGrantInput](core.NewObject(
		"tenantId", f.TenantID, "agentId", agentID, "scopes", []any{"documents:*"},
	))))
	acting := f.Object(f.IAM.API.Delegations.Assume(f.Ctx, core.CredentialInput{Token: key}, server.Input[apitypes.DelegationsAssumeInput](core.NewObject(
		"tenantId", f.TenantID, "delegationId", delegation.Get("id"),
	))))
	actingToken, _ := acting.Get("token").(string)
	expectNames(t, names(t, h.rpc(t, actingToken, "tools/list", nil, nil)), "search_docs", "delete_doc", "ping")
	deleted := decode(t, h.rpc(t, actingToken, "tools/call", map[string]any{"name": "delete_doc", "arguments": map[string]any{"id": "draft"}}, nil))
	if text(t, deleted) != "ran delete_doc" {
		t.Fatalf("deleted %v", deleted)
	}

	// Narrow the delegation to reading and the destructive tool disappears.
	f.Value(f.IAM.API.Delegations.Revoke(f.Ctx, aliceSession, server.Input[apitypes.DelegationsRevokeInput](core.NewObject(
		"tenantId", f.TenantID, "delegationId", delegation.Get("id"),
	))))
	if status := h.rpc(t, actingToken, "tools/list", nil, nil).StatusCode; status != 401 {
		t.Fatalf("revoked delegation: %d", status)
	}
	fresh := core.CredentialInput{Token: f.SignIn("alice")}
	readOnly := f.Object(f.IAM.API.Delegations.Grant(f.Ctx, fresh, server.Input[apitypes.DelegationsGrantInput](core.NewObject(
		"tenantId", f.TenantID, "agentId", agentID, "scopes", []any{"documents:read"},
	))))
	reader := f.Object(f.IAM.API.Delegations.Assume(f.Ctx, core.CredentialInput{Token: key}, server.Input[apitypes.DelegationsAssumeInput](core.NewObject(
		"tenantId", f.TenantID, "delegationId", readOnly.Get("id"),
	))))
	readerToken, _ := reader.Get("token").(string)
	expectNames(t, names(t, h.rpc(t, readerToken, "tools/list", nil, nil)), "search_docs", "ping")
}

func TestMcpGateAsksThePersonToConfirmAHeldBackToolCallThenLetsTheRetryThrough(t *testing.T) {
	h := setup(t)
	f := h.f
	alice := f.Member("alice")
	aliceID, _ := alice.Get("id").(string)
	grantDocuments(t, f, aliceID, "documents:read", "documents:write")
	agentID, key := createAgent(t, f, "Careful agent")
	aliceSession := core.CredentialInput{Token: f.SignIn("alice")}
	delegation := f.Object(f.IAM.API.Delegations.Grant(f.Ctx, aliceSession, server.Input[apitypes.DelegationsGrantInput](core.NewObject(
		"tenantId", f.TenantID, "agentId", agentID, "scopes", []any{"documents:*"}, "confirm", []any{"documents:write"},
	))))
	acting := f.Object(f.IAM.API.Delegations.Assume(f.Ctx, core.CredentialInput{Token: key}, server.Input[apitypes.DelegationsAssumeInput](core.NewObject(
		"tenantId", f.TenantID, "delegationId", delegation.Get("id"),
	))))
	actingToken, _ := acting.Get("token").(string)
	first := decode(t, h.rpc(t, actingToken, "tools/call", map[string]any{"name": "delete_doc", "arguments": map[string]any{"id": "draft"}}, nil))
	result, _ := first["result"].(map[string]any)
	if result["isError"] != true || !strings.Contains(text(t, first), "must confirm this call first") {
		t.Fatalf("first %v", first)
	}
	meta, _ := result["_meta"].(map[string]any)
	confirmationID, _ := meta["better-iam/confirmationId"].(string)
	if confirmationID == "" {
		t.Fatalf("no confirmation id: %v", first)
	}
	if _, ok := meta["better-iam/confirmationExpiresAt"].(float64); !ok {
		t.Fatalf("no confirmation expiry: %v", first)
	}
	pending := f.Items(f.IAM.API.Delegations.ListConfirmations(f.Ctx, aliceSession, server.Input[apitypes.DelegationsListConfirmationsInput](core.NewObject(
		"tenantId", f.TenantID, "status", "pending",
	))))
	if len(pending) != 1 || pending[0].Get("id") != confirmationID || pending[0].Get("action") != "documents:write" ||
		core.MustStringify(pending[0].Get("resource")) != `{"type":"document","id":"draft"}` ||
		!strings.Contains(jsString(pending[0].Get("reason")), "delete_doc") {
		t.Fatalf("pending %v", pending)
	}
	// Reading is not held back.
	if got := text(t, decode(t, h.rpc(t, actingToken, "tools/call", map[string]any{"name": "search_docs"}, nil))); got != "ran search_docs" {
		t.Fatalf("search: %q", got)
	}
	f.Value(f.IAM.API.Delegations.DecideConfirmation(f.Ctx, aliceSession, server.Input[apitypes.DelegationsDecideConfirmationInput](core.NewObject(
		"tenantId", f.TenantID, "confirmationId", confirmationID, "approve", true,
	))))
	retry := decode(t, h.rpc(t, actingToken, "tools/call", map[string]any{"name": "delete_doc", "arguments": map[string]any{"id": "draft"}}, nil))
	if text(t, retry) != "ran delete_doc" {
		t.Fatalf("retry %v", retry)
	}
	count := 0
	for _, call := range h.server.recorded() {
		if call.method == "tools/call" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("tools/call reached the server %d times", count)
	}
}

func TestMcpGateDecidesOAuthCallersByScope(t *testing.T) {
	h := setup(t)
	expectNames(t, names(t, h.rpc(t, "oauth-access-token", "tools/list", nil, nil)), "search_docs", "ping")
	refused := decode(t, h.rpc(t, "oauth-access-token", "tools/call", map[string]any{"name": "delete_doc", "arguments": map[string]any{"id": 1}}, nil))
	if refused["result"].(map[string]any)["isError"] != true {
		t.Fatalf("refused %v", refused)
	}
	h.rpc(t, "oauth-access-token", "tools/call", map[string]any{"name": "search_docs"}, nil)
	calls := h.server.recorded()
	last := calls[len(calls)-1].caller
	if !reflect.DeepEqual(*last, mcp.Caller{Kind: mcp.CallerOAuth, ClientID: "claude-desktop", Subject: "user-1", Scopes: []string{"docs.search"}}) {
		t.Fatalf("caller %+v", last)
	}
	// Other methods pass straight through.
	if status := h.rpc(t, "oauth-access-token", "initialize", map[string]any{"protocolVersion": "2025-11-25"}, nil).StatusCode; status != 200 {
		t.Fatalf("initialize: %d", status)
	}
}

// chunked is a request body without a declared length.
type chunked struct{ remaining int }

func (c *chunked) Read(p []byte) (int, error) {
	if c.remaining == 0 {
		return 0, io.EOF
	}
	count := min(len(p), c.remaining, 600)
	for index := range count {
		p[index] = 'x'
	}
	c.remaining -= count
	return count, nil
}

func TestMcpGateDecidesInTheServersOwnTenantNeverTheCallersAndBoundsRequestBodies(t *testing.T) {
	h := setup(t)
	f := h.f
	agentID, token := createAgent(t, f, "Elsewhere")
	grantDocuments(t, f, agentID, "documents:read")
	// A gate that belongs to another tenant (the platform root) does not honour grants the caller holds in Acme.
	foreign, err := mcp.NewGate(mcp.GateOptions{AuthorizerOptions: mcp.AuthorizerOptions{
		IAM: f.IAM, TenantID: f.RootID,
		Tools: map[string]mcp.ToolRule{"search_docs": {Action: "documents:read", Resource: &mcp.ResourceRef{Type: "document", ID: "x"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	send := func(gate *mcp.Gate, body io.Reader) *http.Response {
		request := httptest.NewRequest("POST", "https://mcp.acme.test/mcp", body)
		request.Header.Set("content-type", "application/json")
		request.Header.Set("authorization", "Bearer "+token)
		request.ContentLength = -1
		response, err := gate.Handle(request, h.server.handle)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	refused := decode(t, send(foreign, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_docs"}}`)))
	if refused["result"].(map[string]any)["isError"] != true {
		t.Fatalf("refused %v", refused)
	}
	// A body without a declared length is still cut off at the limit.
	small, err := mcp.NewGate(mcp.GateOptions{AuthorizerOptions: mcp.AuthorizerOptions{IAM: f.IAM, TenantID: f.TenantID, Tools: map[string]mcp.ToolRule{}}, MaxBodyBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if status := send(small, &chunked{remaining: 3000}).StatusCode; status != 413 {
		t.Fatalf("status %d", status)
	}
	if len(h.server.recorded()) != 0 {
		t.Fatal("the server must not be reached")
	}
}

func TestMcpGateRefusesMalformedAndBatchedToolRequests(t *testing.T) {
	h := setup(t)
	agentID, token := createAgent(t, h.f, "Strict")
	grantDocuments(t, h.f, agentID, "documents:read")
	send := func(body string) map[string]any {
		request := httptest.NewRequest("POST", "https://mcp.acme.test/mcp", strings.NewReader(body))
		request.Header.Set("authorization", "Bearer "+token)
		response, err := h.gate.Handle(request, h.server.handle)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 400 {
			t.Fatalf("status %d for %s", response.StatusCode, body)
		}
		return decode(t, response)
	}
	code := func(value map[string]any) float64 { return value["error"].(map[string]any)["code"].(float64) }
	if got := send("{not json"); code(got) != -32700 {
		t.Fatalf("parse error %v", got)
	}
	if got := send(`[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`); code(got) != -32600 {
		t.Fatalf("batch %v", got)
	}
	if got := send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":["search_docs"]}}`); code(got) != -32602 || got["id"] != float64(3) {
		t.Fatalf("non-string name %v", got)
	}
	if len(h.server.recorded()) != 0 {
		t.Fatal("the server must not be reached")
	}
}

func TestMcpGateHandlerStreamsThroughNetHTTP(t *testing.T) {
	h := setup(t)
	agentID, token := createAgent(t, h.f, "Streaming agent")
	grantDocuments(t, h.f, agentID, "documents:read")
	handler := h.gate.Handler(func(w http.ResponseWriter, r *http.Request, caller *mcp.Caller) {
		if mcp.CallerFrom(r) != caller {
			http.Error(w, "caller missing", 500)
			return
		}
		response, err := h.server.handle(r, caller)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		for key, values := range response.Header {
			w.Header()[key] = values
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	})
	httpServer := httptest.NewServer(handler)
	t.Cleanup(httpServer.Close)
	send := func(sse bool) *http.Response {
		request, _ := http.NewRequest("POST", httpServer.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`))
		request.Header.Set("authorization", "Bearer "+token)
		if sse {
			request.Header.Set("x-test-sse", "1")
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	expectNames(t, names(t, send(false)), "search_docs", "ping")
	streamed := send(true)
	defer func() { _ = streamed.Body.Close() }()
	data, _ := io.ReadAll(streamed.Body)
	if !strings.Contains(string(data), `"name":"search_docs"`) || strings.Contains(string(data), "delete_doc") || !strings.Contains(string(data), "notifications/progress") {
		t.Fatalf("stream %s", data)
	}
	anonymous, err := http.Post(httpServer.URL+"/mcp", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = anonymous.Body.Close()
	if anonymous.StatusCode != 401 {
		t.Fatalf("anonymous %d", anonymous.StatusCode)
	}
}
