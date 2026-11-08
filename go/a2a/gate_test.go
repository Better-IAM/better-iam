package a2a

// Port of the A2A gate parts of tests/a2a.test.ts and the A2A skill name case of tests/security-integrations.test.ts,
// plus the http.Handler middleware.

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

type serverCall struct {
	method string
	caller *Caller
}

// stubServer is a stand-in A2A server: it creates tasks for messages (JSON or an event stream) and answers task
// reads.
type stubServer struct {
	mu    sync.Mutex
	calls []serverCall
	count int
}

// chunked hands out a body at most 17 bytes at a time.
type chunked struct{ data []byte }

func (c *chunked) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p[:min(len(p), 17)], c.data)
	c.data = c.data[n:]
	return n, nil
}

func jsonAnswer(value any) *http.Response {
	header := http.Header{}
	header.Set("content-type", "application/json")
	return newResponse(200, header, []byte(core.MustStringify(value)))
}

func (s *stubServer) handle(request *http.Request, caller *Caller) (*http.Response, error) {
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	message := must(core.ParseJSON(raw)).(*core.Object)
	method := message.Get("method").(string)
	s.mu.Lock()
	s.calls = append(s.calls, serverCall{method: method, caller: caller})
	s.mu.Unlock()
	params, _ := message.Get("params").(*core.Object)
	sent, _ := params.Get("message").(*core.Object)
	task := func(id, state string) *core.Object {
		contextID := sent.Get("contextId")
		if core.IsUndefined(contextID) {
			contextID = "ctx-" + id
		}
		return core.NewObject("kind", "task", "id", id, "contextId", contextID, "status", core.NewObject("state", state))
	}
	next := func() string {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.count++
		return "task-" + strconv.Itoa(s.count)
	}
	switch method {
	case "message/send":
		return jsonAnswer(core.NewObject("jsonrpc", "2.0", "id", message.Get("id"), "result", task(next(), "submitted"))), nil
	case "message/stream":
		id := next()
		events := []*core.Object{
			core.NewObject("jsonrpc", "2.0", "id", message.Get("id"), "result", task(id, "submitted")),
			core.NewObject("jsonrpc", "2.0", "id", message.Get("id"), "result", core.NewObject("kind", "status-update", "taskId", id,
				"status", core.NewObject("state", "working"), "final", true)),
		}
		var stream strings.Builder
		for _, event := range events {
			stream.WriteString("data: " + core.MustStringify(event) + "\n\n")
		}
		header := http.Header{}
		header.Set("content-type", "text/event-stream")
		return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(&chunked{data: []byte(stream.String())}), ContentLength: -1}, nil
	case "tasks/get", "tasks/cancel":
		return jsonAnswer(core.NewObject("jsonrpc", "2.0", "id", message.Get("id"), "result", task(jsString(params.Get("id")), "working"))), nil
	}
	return jsonAnswer(core.NewObject("jsonrpc", "2.0", "id", message.Get("id"), "result", core.NewObject())), nil
}

func (s *stubServer) methods() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var methods []string
	for _, call := range s.calls {
		methods = append(methods, call.method)
	}
	return strings.Join(methods, ",")
}

type gateFixture struct {
	*orgFixture
	gate   *Gate
	server *stubServer
}

func newGateFixture(t *testing.T) *gateFixture {
	t.Helper()
	f := newOrgFixture(t, nil)
	card := baseCard("")
	stub := &stubServer{}
	gate := CreateGate(GateOptions{
		Iam: Server(f.iam), TenantID: f.tenantID, Card: card, ExtendedCard: card,
		Message: Rule{Action: "documents:read", Resource: &ResourceRef{Type: "document", ID: "inbox"}},
		Skills: map[string]Rule{
			"summarize": {Action: "documents:read", Resource: &ResourceRef{Type: "document", ID: "inbox"}},
			"purge":     {Action: "documents:write", Resource: &ResourceRef{Type: "document", ID: "archive"}},
		},
		TaskAdminAction: "documents:write",
	})
	return &gateFixture{orgFixture: f, gate: gate, server: stub}
}

func rpcRequest(t *testing.T, url, token string, payload any) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, url, strings.NewReader(core.MustStringify(payload)))
	request.Header.Set("content-type", "application/json")
	if token != "" {
		request.Header.Set("authorization", "Bearer "+token)
	}
	return request
}

// rpc sends one JSON-RPC request through the gate.
func (f *gateFixture) rpc(token, method string, params *core.Object) *http.Response {
	f.t.Helper()
	payload := core.NewObject("jsonrpc", "2.0", "id", 3.0, "method", method)
	if params != nil {
		payload.Set("params", params)
	}
	return must(f.gate.Serve(rpcRequest(f.t, "https://agents.acme.test/a2a", token, payload), f.server.handle))
}

// agentWith is an agent allowed actions on every document: its key.
func (f *gateFixture) agentWith(name string, actions ...string) string {
	f.t.Helper()
	id, token := f.agentKey("name", name)
	if len(actions) > 0 {
		f.grantDocuments(id, actions...)
	}
	return token
}

func message(text string, extra ...any) *core.Object {
	sent := core.NewObject("kind", "message", "role", "user", "messageId", "m-"+text, "parts", []any{core.NewObject("kind", "text", "text", text)})
	sent.Assign(core.NewObject(extra...))
	return core.NewObject("message", sent)
}

func readJSON(t *testing.T, response *http.Response) *core.Object {
	t.Helper()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return parseObject(t, string(raw))
}

func expectError(t *testing.T, response *http.Response, code float64, reason string) *core.Object {
	t.Helper()
	answer := readJSON(t, response)
	if member(answer, "error", "code") != code || (reason != "" && member(answer, "error", "data", "reason") != reason) {
		t.Fatalf("answer = %s, want error %v %s", core.MustStringify(answer), code, reason)
	}
	return answer
}

func expectResult(t *testing.T, response *http.Response, id string) *core.Object {
	t.Helper()
	answer := readJSON(t, response)
	if member(answer, "result", "id") != id {
		t.Fatalf("answer = %s, want task %s", core.MustStringify(answer), id)
	}
	return answer
}

func TestGateAuthorizesMessagesBySkillAndKeepsTasksPrivate(t *testing.T) {
	f := newGateFixture(t)
	cardResponse := must(f.gate.Serve(httptest.NewRequest(http.MethodGet, "https://agents.acme.test/.well-known/agent-card.json", nil), f.server.handle))
	if cardResponse.StatusCode != 200 || readJSON(t, cardResponse).Get("name") != "Triage" || cardResponse.Header.Get("cache-control") != "public, max-age=300" {
		t.Fatalf("card = %d", cardResponse.StatusCode)
	}
	options := must(f.gate.Serve(httptest.NewRequest(http.MethodOptions, "https://agents.acme.test/.well-known/agent.json", nil), f.server.handle))
	if options.StatusCode != 204 || options.Header.Get("access-control-allow-methods") != "GET, OPTIONS" {
		t.Fatalf("options = %d", options.StatusCode)
	}
	unauthenticated := f.rpc("", "message/send", message("hi"))
	if unauthenticated.StatusCode != 401 || unauthenticated.Header.Get("www-authenticate") != "Bearer" {
		t.Fatalf("unauthenticated = %d %v", unauthenticated.StatusCode, unauthenticated.Header)
	}
	invalid := f.rpc("not-a-token", "message/send", message("hi"))
	if invalid.StatusCode != 401 || invalid.Header.Get("www-authenticate") != `Bearer error="invalid_token"` ||
		readJSON(t, invalid).Get("error") != "invalid_token" {
		t.Fatalf("invalid = %d %v", invalid.StatusCode, invalid.Header)
	}

	reader := f.agentWith("Reader", "documents:read")
	neighbour := f.agentWith("Neighbour", "documents:read")
	expectResult(t, f.rpc(reader, "message/send", message("hi")), "task-1")
	if last := f.server.calls[len(f.server.calls)-1].caller; last.Kind != "iam" || last.IdentityKind != "agent" || last.AgentID != last.IdentityID {
		t.Fatalf("caller = %+v", last)
	}
	expectResult(t, f.rpc(reader, "tasks/get", core.NewObject("id", "task-1")), "task-1")
	// Another caller cannot read, cancel or continue the task: it does not exist for them.
	for _, attempt := range []struct {
		method string
		params *core.Object
	}{
		{"tasks/get", core.NewObject("id", "task-1")},
		{"tasks/cancel", core.NewObject("id", "task-1")},
		{"tasks/pushNotificationConfig/set", core.NewObject("taskId", "task-1", "pushNotificationConfig", core.NewObject())},
		{"message/send", message("more", "taskId", "task-1")},
	} {
		answer := expectError(t, f.rpc(neighbour, attempt.method, attempt.params), -32001, "")
		if member(answer, "error", "message") != "Task not found" || answer.Get("id") != 3.0 {
			t.Fatalf("answer = %s", core.MustStringify(answer))
		}
	}
	// An operator with the task admin action may.
	expectResult(t, f.rpc(f.owner.Token, "tasks/cancel", core.NewObject("id", "task-1")), "task-1")

	// Tasks started over an event stream are recorded as the events pass by.
	streamed := f.rpc(reader, "message/stream", message("stream"))
	text := string(must(io.ReadAll(streamed.Body)))
	if !strings.Contains(text, "status-update") || streamed.Header.Get("content-type") != "text/event-stream" {
		t.Fatalf("stream = %s", text)
	}
	expectResult(t, f.rpc(reader, "tasks/get", core.NewObject("id", "task-2")), "task-2")

	// Conversations (contexts) are private the same way: only the caller who started one may add to it.
	expectError(t, f.rpc(neighbour, "message/send", message("join", "contextId", "ctx-task-1")), -32602, "")
	again := expectResult(t, f.rpc(reader, "message/send", message("again", "contextId", "ctx-task-1")), "task-3")
	if member(again, "result", "contextId") != "ctx-task-1" {
		t.Fatalf("again = %s", core.MustStringify(again))
	}
	// Conversations the server never started belong to no one; referenced tasks must be the caller's own.
	expectError(t, f.rpc(reader, "message/send", message("new", "contextId", "ctx-made-up")), -32602, "")
	expectError(t, f.rpc(neighbour, "message/send", message("peek", "referenceTaskIds", []any{"task-1"})), -32001, "")
	expectError(t, f.rpc(reader, "message/send", message("peek", "referenceTaskIds", "task-1")), -32602, "")
	// A request naming two different skills is refused, so the gate and the server cannot disagree on it.
	both := message("both", "metadata", core.NewObject("skillId", "summarize"))
	both.Set("metadata", core.NewObject("skillId", "purge"))
	expectError(t, f.rpc(reader, "message/send", both), A2AAccessDenied, "AMBIGUOUS_SKILL")
	// Only JSON-RPC over POST reaches the server.
	get := httptest.NewRequest(http.MethodGet, "https://agents.acme.test/v1/tasks/task-1", nil)
	get.Header.Set("authorization", "Bearer "+neighbour)
	if response := must(f.gate.Serve(get, f.server.handle)); response.StatusCode != 405 || response.Header.Get("allow") != "POST" {
		t.Fatalf("GET = %d", response.StatusCode)
	}

	// Skills: the one the caller may use passes; a denied or unknown one never reaches the server.
	skill := func(id string) *core.Object { return message(id, "metadata", core.NewObject("skillId", id)) }
	if response := f.rpc(reader, "message/send", skill("summarize")); response.StatusCode != 200 {
		t.Fatalf("summarize = %d", response.StatusCode)
	}
	denied := f.rpc(reader, "message/send", skill("purge"))
	if denied.StatusCode != 403 {
		t.Fatalf("purge = %d", denied.StatusCode)
	}
	if answer := expectError(t, denied, A2AAccessDenied, "ACCESS_DENIED"); member(answer, "error", "message") != "Access denied" {
		t.Fatalf("answer = %s", core.MustStringify(answer))
	}
	if answer := expectError(t, f.rpc(reader, "message/send", skill("mystery")), A2AAccessDenied, "UNKNOWN_SKILL"); member(answer, "error", "message") != "Unknown skill" {
		t.Fatalf("answer = %s", core.MustStringify(answer))
	}
	outsider := f.agentWith("Outsider")
	if response := f.rpc(outsider, "message/send", message("hi")); response.StatusCode != 403 {
		t.Fatalf("outsider = %d", response.StatusCode)
	}

	// The extended card lists only usable skills; unknown methods and batches are refused.
	extended := readJSON(t, f.rpc(reader, "agent/getAuthenticatedExtendedCard", nil))
	if got := core.MustStringify(member(extended, "result", "skills")); !strings.HasPrefix(got, `[{"id":"summarize"`) || strings.Contains(got, "purge") {
		t.Fatalf("extended = %s", core.MustStringify(extended))
	}
	expectError(t, f.rpc(reader, "admin/dump", nil), -32601, "")
	batch := must(f.gate.Serve(rpcRequest(t, "https://agents.acme.test/a2a", reader,
		[]any{core.NewObject("jsonrpc", "2.0", "id", 1.0, "method", "tasks/get", "params", core.NewObject("id", "task-1"))}), f.server.handle))
	expectError(t, batch, -32600, "")
	parse := httptest.NewRequest(http.MethodPost, "https://agents.acme.test/a2a", strings.NewReader("{"))
	parse.Header.Set("authorization", "Bearer "+reader)
	expectError(t, must(f.gate.Serve(parse, f.server.handle)), -32700, "")
	if got := f.server.methods(); got != "message/send,tasks/get,tasks/cancel,message/stream,tasks/get,message/send,message/send" {
		t.Fatalf("server calls = %s", got)
	}

	// A gate that belongs to another tenant decides there, not in the caller's own tenant.
	foreign := CreateGate(GateOptions{Iam: Server(f.iam), TenantID: f.rootID,
		Message: Rule{Action: "documents:read", Resource: &ResourceRef{Type: "document", ID: "inbox"}}})
	elsewhere := must(foreign.Serve(rpcRequest(t, "https://agents.acme.test/a2a", reader,
		core.NewObject("jsonrpc", "2.0", "id", 1.0, "method", "message/send", "params", message("x"))), f.server.handle))
	if elsewhere.StatusCode != 403 {
		t.Fatalf("foreign = %d", elsewhere.StatusCode)
	}
	// An oversized body is refused before it is read.
	small := CreateGate(GateOptions{Iam: Server(f.iam), TenantID: f.tenantID, Message: Rule{Public: true}, MaxBodyBytes: 10})
	tooLarge := must(small.Serve(rpcRequest(t, "https://agents.acme.test/a2a", reader, core.NewObject("jsonrpc", "2.0", "method", "message/send")), f.server.handle))
	if tooLarge.StatusCode != 413 {
		t.Fatalf("too large = %d", tooLarge.StatusCode)
	}
}

func TestGateCarriesAHandOffFromOneAgentToTheNext(t *testing.T) {
	f := newOrgFixture(t, nil)
	alice := f.memberIdentity("alice")
	aliceID := alice.Get("id").(string)
	f.grantDocuments(aliceID, "documents:read")
	assistantID, assistantToken := f.agentKey("name", "Assistant")
	researcherID, researcherToken := f.agentKey("name", "Researcher")
	aliceSession := f.signIn("alice")
	delegation := call(f, f.iam.API.Delegations.Grant, aliceSession, "agentId", assistantID, "scopes", []any{"documents:read"},
		"handoff", core.NewObject("agents", []any{researcherID}))
	acting := call(f, f.iam.API.Delegations.Assume, core.CredentialInput{Token: assistantToken}, "delegationId", delegation.Get("id"))

	// The researcher's A2A server: behind the gate, it takes up the hand-off with its own key and acts for alice.
	var actedAs string
	gate := CreateGate(GateOptions{Iam: Server(f.iam), TenantID: f.tenantID, Message: Rule{Public: true}})
	researcherServer := func(request *http.Request, _ *Caller) (*http.Response, error) {
		payload := must(core.ParseJSON(must(io.ReadAll(request.Body)))).(*core.Object)
		params := payload.Get("params").(*core.Object)
		delegationID := HandoffOf(params)
		if delegationID == "" {
			return jsonAnswer(core.NewObject("jsonrpc", "2.0", "id", payload.Get("id"), "error", core.NewObject("code", -1.0))), nil
		}
		session := call(f, f.iam.API.Delegations.Assume, core.CredentialInput{Token: researcherToken}, "delegationId", delegationID)
		token := session.Get("token").(string)
		decision := must(f.iam.Authorize(f.ctx, server.AuthorizationRequest{Credential: core.CredentialInput{Token: token}, TenantID: f.tenantID,
			Action: "documents:read", Resource: server.ResourceTarget{Type: "document", ID: "q3"}}))
		summary := call(f, f.iam.API.Delegations.Get, core.CredentialInput{Token: token}, "delegationId", delegationID)
		var chain []string
		if list, ok := summary.Get("chain").([]any); ok {
			for _, item := range list {
				chain = append(chain, member(item, "id").(string))
			}
		}
		chain = append(chain, member(session, "session", "agentId").(string))
		actedAs = member(session, "session", "identityId").(string) + " " + strings.Join(chain, ",")
		state := "failed"
		if decision.Allowed {
			state = "completed"
		}
		return jsonAnswer(core.NewObject("jsonrpc", "2.0", "id", payload.Get("id"), "result", core.NewObject("kind", "task", "id", "research-1",
			"contextId", "c1", "status", core.NewObject("state", state)))), nil
	}

	// The assistant hands the work on and says so in the message it sends.
	handoff := call(f, f.iam.API.Delegations.Handoff, core.CredentialInput{Token: acting.Get("token").(string)}, "agentId", researcherID,
		"scopes", []any{"documents:read"})
	sent := WithHandoff(core.NewObject("kind", "message", "role", "user", "messageId", "m1",
		"parts", []any{core.NewObject("kind", "text", "text", "Find the Q3 numbers")}), handoff.Get("id").(string))
	if core.MustStringify(sent.Get("metadata")) != core.MustStringify(core.NewObject(HandoffMetadataKey, handoff.Get("id"))) {
		t.Fatalf("metadata = %s", core.MustStringify(sent.Get("metadata")))
	}
	response := must(gate.Serve(rpcRequest(t, "https://researcher.acme.test/a2a", acting.Get("token").(string),
		core.NewObject("jsonrpc", "2.0", "id", 1.0, "method", "message/send", "params", core.NewObject("message", sent))), researcherServer))
	if answer := readJSON(t, response); member(answer, "result", "status", "state") != "completed" {
		t.Fatalf("answer = %s", core.MustStringify(answer))
	}
	if actedAs != aliceID+" "+assistantID+","+researcherID {
		t.Fatalf("acted as %s", actedAs)
	}
	// The hand-off in the request's metadata counts too; the message's comes first.
	if HandoffOf(core.NewObject("metadata", core.NewObject(HandoffMetadataKey, "d-2"))) != "d-2" ||
		HandoffOf(core.NewObject("message", core.NewObject("metadata", core.NewObject(HandoffMetadataKey, "d-1")),
			"metadata", core.NewObject(HandoffMetadataKey, "d-2"))) != "d-1" || HandoffOf(core.NewObject()) != "" {
		t.Fatal("handoffOf")
	}
}

func TestGateAsksThePersonToConfirmAHeldBackSkill(t *testing.T) {
	f := newGateFixture(t)
	alice := f.memberIdentity("alice")
	f.grantDocuments(alice.Get("id").(string), "documents:read", "documents:write")
	agentKey := f.agentWith("Assistant")
	principal := must(f.iam.Authenticate(f.ctx, core.CredentialInput{Token: agentKey}))
	aliceSession := f.signIn("alice")
	delegation := call(f.orgFixture, f.iam.API.Delegations.Grant, aliceSession, "agentId", principal.Identity.Get("id"),
		"scopes", []any{"documents:*"}, "confirm", []any{"documents:write"})
	acting := call(f.orgFixture, f.iam.API.Delegations.Assume, core.CredentialInput{Token: agentKey}, "delegationId", delegation.Get("id"))
	purge := message("purge", "metadata", core.NewObject("skillId", "purge"))
	first := f.rpc(acting.Get("token").(string), "message/send", purge)
	if first.StatusCode != 403 {
		t.Fatalf("first = %d", first.StatusCode)
	}
	answer := expectError(t, first, A2AConfirmationRequested, "CONFIRMATION_REQUESTED")
	confirmationID, _ := member(answer, "error", "data", "confirmationId").(string)
	if _, isNumber := member(answer, "error", "data", "expiresAt").(float64); confirmationID == "" || !isNumber {
		t.Fatalf("answer = %s", core.MustStringify(answer))
	}
	call(f.orgFixture, f.iam.API.Delegations.DecideConfirmation, aliceSession, "confirmationId", confirmationID, "approve", true)
	if response := f.rpc(acting.Get("token").(string), "message/send", purge); response.StatusCode != 200 {
		t.Fatalf("after approval = %d %s", response.StatusCode, core.MustStringify(readJSON(t, response)))
	}
}

func TestAuthorizerRefusesASkillIDThatIsNotAString(t *testing.T) {
	authorizer := CreateAuthorizer(GateOptions{TenantID: "tenant", Message: Rule{Public: true},
		Skills: map[string]Rule{"purge": {Action: "documents:delete"}}})
	caller := &Caller{Kind: "iam", TenantID: "tenant", IdentityID: "someone"}
	decision, err := authorizer.CanSend(context.Background(), caller, core.NewObject("message", core.NewObject("metadata", core.NewObject("skillId", []any{"purge"}))))
	if err != nil || decision.Allowed || decision.Reason != "AMBIGUOUS_SKILL" {
		t.Fatalf("decision = %+v %v", decision, err)
	}
}

// fakeIam answers fixed decisions.
type fakeIam struct {
	allowed map[string]bool
}

func (i *fakeIam) Authenticate(context.Context, core.CredentialInput) (*Principal, error) {
	return nil, core.NewIamError("UNAUTHENTICATED", "Authentication required", 401)
}

func (i *fakeIam) Authorize(_ context.Context, request AuthorizeRequest) (Decision, error) {
	return Decision{Allowed: i.allowed[request.Action+" "+request.Resource.Type+"/"+request.Resource.ID]}, nil
}

func (i *fakeIam) AuthorizeMany(_ context.Context, request AuthorizeManyRequest) ([]Decision, error) {
	var out []Decision
	for _, check := range request.Checks {
		out = append(out, Decision{Allowed: i.allowed[check.Action+" "+check.Resource.Type+"/"+check.Resource.ID]})
	}
	return out, nil
}

func TestAuthorizerDecidesOAuthCallersByScopeAndListsVisibleSkills(t *testing.T) {
	iam := &fakeIam{allowed: map[string]bool{"skills:use a2a-skill/translate": true}}
	authorizer := CreateAuthorizer(GateOptions{Iam: iam, TenantID: "tenant",
		Message: Rule{Scopes: []string{"agent:message"}},
		Skills: map[string]Rule{
			"translate": {Action: "skills:use", Scopes: []string{"agent:translate"}},
			"summarize": {Action: "skills:use"},
			"weather":   {Public: true},
			"dynamic": {Action: "skills:use", ResourceFunc: func(params *core.Object) (ResourceRef, error) {
				return ResourceRef{Type: "doc", ID: jsString(params.Get("doc"))}, nil
			}},
		}, UnlistedSkills: "message"})
	oauth := &Caller{Kind: "oauth", ClientID: "client", Scopes: []string{"agent:message"}}
	cases := []struct {
		params *core.Object
		reason string
	}{
		{core.NewObject(), "ALLOWED"},
		{core.NewObject("metadata", core.NewObject("skillId", "translate")), "INSUFFICIENT_SCOPE"},
		{core.NewObject("metadata", core.NewObject("skillId", "summarize")), "NO_RULE_FOR_CALLER"},
		{core.NewObject("metadata", core.NewObject("skillId", "weather")), "PUBLIC"},
		{core.NewObject("metadata", core.NewObject("skillId", "unlisted")), "ALLOWED"},
	}
	for _, c := range cases {
		decision, err := authorizer.CanSend(context.Background(), oauth, c.params)
		if err != nil || decision.Reason != c.reason {
			t.Fatalf("%s: decision = %+v %v", core.MustStringify(c.params), decision, err)
		}
	}
	skills := []any{core.NewObject("id", "translate"), core.NewObject("id", "summarize"), core.NewObject("id", "weather"),
		core.NewObject("id", "dynamic"), core.NewObject("id", "unlisted")}
	ids := func(list []any) string {
		var out []string
		for _, item := range list {
			out = append(out, member(item, "id").(string))
		}
		return strings.Join(out, ",")
	}
	visible := must(authorizer.VisibleSkills(context.Background(), oauth, skills))
	if got := ids(visible); got != "weather,unlisted" {
		t.Fatalf("oauth visible = %s", got)
	}
	person := &Caller{Kind: "iam", TenantID: "tenant", IdentityID: "p"}
	visible = must(authorizer.VisibleSkills(context.Background(), person, skills))
	if got := ids(visible); got != "translate,weather,dynamic" {
		t.Fatalf("iam visible = %s", got)
	}
	// The owner key of each kind of caller.
	if TaskOwnerOf(person) != "iam:tenant:p:" || TaskOwnerOf(oauth) != "oauth:client:" {
		t.Fatalf("owners = %s %s", TaskOwnerOf(person), TaskOwnerOf(oauth))
	}
}

func TestGateAcceptsOAuthTokensForItsTenant(t *testing.T) {
	verifier := OAuthVerifierFunc(func(_ context.Context, request OAuthRequest) (*OAuthToken, error) {
		switch request.Authorization {
		case "DPoP good":
			if request.DPoP != "proof" || request.Method != "POST" || request.URL != "https://agents.acme.test/a2a" {
				t.Errorf("request = %+v", request)
			}
			return &OAuthToken{ClientID: "client", Subject: "sub", TenantID: "tenant", Scopes: []string{"agent:message"}}, nil
		case "Bearer foreign":
			return &OAuthToken{ClientID: "client", TenantID: "other", Scopes: []string{"agent:message"}}, nil
		}
		return nil, core.NewIamError("UNAUTHENTICATED", "invalid token", 401)
	})
	var seen *Caller
	gate := CreateGate(GateOptions{Iam: &fakeIam{}, TenantID: "tenant", OAuth: verifier, Message: Rule{Scopes: []string{"agent:message"}}})
	send := func(authorization string) *http.Response {
		request := rpcRequest(t, "https://agents.acme.test/a2a", "", core.NewObject("jsonrpc", "2.0", "id", 1.0, "method", "message/send", "params", message("hi")))
		request.Header.Set("authorization", authorization)
		request.Header.Set("dpop", "proof")
		return must(gate.Serve(request, func(_ *http.Request, caller *Caller) (*http.Response, error) {
			seen = caller
			return jsonAnswer(core.NewObject("jsonrpc", "2.0", "id", 1.0, "result", core.NewObject("kind", "task", "id", "t1"))), nil
		}))
	}
	if response := send("DPoP good"); response.StatusCode != 200 || seen == nil || seen.Kind != "oauth" || seen.Subject != "sub" || seen.TenantID != "tenant" {
		t.Fatalf("good = %d %+v", response.StatusCode, seen)
	}
	if response := send("Bearer foreign"); response.StatusCode != 401 {
		t.Fatalf("foreign = %d", response.StatusCode)
	}
	if response := send("Basic abc"); response.StatusCode != 401 || response.Header.Get("www-authenticate") != "Bearer" {
		t.Fatalf("basic = %d", response.StatusCode)
	}
}

func TestMemoryTaskOwnersExpireAndEvict(t *testing.T) {
	now := 0.0
	owners := MemoryTaskOwners(MemoryTaskOwnersOptions{MaxTasks: 2, TTLMs: 1000, Now: func() float64 { return now }})
	ctx := context.Background()
	for _, key := range []string{"a", "b", "a", "c"} {
		if err := owners.Set(ctx, key, "owner-"+key); err != nil {
			t.Fatal(err)
		}
	}
	// Setting a again moved it behind b, so b went first.
	if _, ok, _ := owners.Get(ctx, "b"); ok {
		t.Fatal("b should be evicted")
	}
	if owner, ok, _ := owners.Get(ctx, "a"); !ok || owner != "owner-a" {
		t.Fatal("a should be kept")
	}
	now = 1000
	if _, ok, _ := owners.Get(ctx, "c"); ok {
		t.Fatal("c should have expired")
	}
}

func TestMiddlewareGatesAnHTTPHandlerAndStreams(t *testing.T) {
	f := newGateFixture(t)
	gate := CreateGate(GateOptions{Iam: Server(f.iam), TenantID: f.tenantID, Message: Rule{Action: "documents:read",
		Resource: &ResourceRef{Type: "document", ID: "inbox"}}})
	handler := gate.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, ok := CallerOf(r.Context())
		payload := must(core.ParseJSON(must(io.ReadAll(r.Body)))).(*core.Object)
		if !ok || caller.Kind != "iam" {
			http.Error(w, "no caller", 500)
			return
		}
		switch payload.Get("method") {
		case "message/stream":
			w.Header().Set("content-type", "text/event-stream")
			w.WriteHeader(200)
			_, _ = io.WriteString(w, "data: "+core.MustStringify(core.NewObject("jsonrpc", "2.0", "id", 1.0, "result",
				core.NewObject("kind", "task", "id", "s-1", "contextId", "c-1")))+"\r\n\r\n")
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"result\":{\"kind\":\"status-update\",\"taskId\":\"s-1\"}}")
		default:
			w.Header().Set("content-type", "application/json")
			_, _ = io.WriteString(w, core.MustStringify(core.NewObject("jsonrpc", "2.0", "id", payload.Get("id"), "result",
				core.NewObject("kind", "task", "id", jsString(member(payload, "params", "id")), "status", core.NewObject("state", "working")))))
		}
	}))
	reader := f.agentWith("Reader", "documents:read")
	neighbour := f.agentWith("Neighbour", "documents:read")
	serve := func(token, method string, params *core.Object) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, rpcRequest(t, "https://agents.acme.test/a2a", token,
			core.NewObject("jsonrpc", "2.0", "id", 1.0, "method", method, "params", params)))
		return recorder
	}
	stream := serve(reader, "message/stream", message("go"))
	if stream.Code != 200 || !bytes.Contains(stream.Body.Bytes(), []byte("status-update")) {
		t.Fatalf("stream = %d %s", stream.Code, stream.Body.String())
	}
	if got := serve(reader, "tasks/get", core.NewObject("id", "s-1")); got.Code != 200 || !strings.Contains(got.Body.String(), `"id":"s-1"`) {
		t.Fatalf("owner read = %d %s", got.Code, got.Body.String())
	}
	if got := serve(neighbour, "tasks/get", core.NewObject("id", "s-1")); !strings.Contains(got.Body.String(), "Task not found") {
		t.Fatalf("neighbour read = %d %s", got.Code, got.Body.String())
	}
	if got := serve(reader, "message/send", message("join", "contextId", "c-1")); got.Code != 200 {
		t.Fatalf("join = %d %s", got.Code, got.Body.String())
	}
}
