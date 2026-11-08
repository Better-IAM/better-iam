package server

// Agents tests, after tests/agents.test.ts: agents as accounts with a sponsor and a profile, their own keys bounded by
// their ceiling and exposing agent context keys, sponsorship standing, the emergency stop, the sponsor's kill switch,
// the catalog, activity and standing reads, and the tenant agent limit. The fixture works in the root tenant with the
// root administrator as the owner; people are seeded through the auth service. Steps that reach another unit's stub
// (threats.ts endContainment, delegations.ts, ...) skip until that unit is ported.

import (
	"context"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Better-IAM/better-iam/go/auth"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

type agentsFixture struct {
	*bindingsFixture
	t       *testing.T
	ownerID string
}

func newAgentsFixture(t *testing.T, mutate func(options *BetterIamOptions)) *agentsFixture {
	t.Helper()
	bindings := newBindingsFixtureWith(t, func(options *BetterIamOptions) {
		// Documents, as the organization fixture of the TypeScript tests declares them.
		options.Permissions.ResourceTypes = append(options.Permissions.ResourceTypes, core.NamedResourceType{
			Name: "document", Definition: core.ResourceTypeDefinition{Actions: []string{"documents:read", "documents:write", "documents:share"}},
		})
		if mutate != nil {
			mutate(options)
		}
	})
	return &agentsFixture{bindingsFixture: bindings, t: t, ownerID: bindings.rootID}
}

// newBindingsFixtureWith is newBindingsFixture with extra options (such as a2a).
func newBindingsFixtureWith(t *testing.T, mutate func(options *BetterIamOptions)) *bindingsFixture {
	t.Helper()
	clock := &atomic.Int64{}
	clock.Store(1_767_225_600_000)
	f := &bindingsFixture{clock: clock}
	f.decisionFixture = newDecisionFixture(t, func(options *BetterIamOptions) {
		options.WallClock = func() int64 { return clock.Load() }
		options.Authentication = &auth.Options{Now: func() int64 { return clock.Load() }, SendEmail: func(_ context.Context, message auth.DeliveryMessage) error {
			f.inboxMu.Lock()
			defer f.inboxMu.Unlock()
			f.inbox = append(f.inbox, message)
			return nil
		}}
		mutate(options)
	})
	f.rootID = jsString(member(f.root.Get("identity"), "id"))
	root, err := f.iam.Store.Get(context.Background(), "identities", f.rootID)
	if err != nil || root == nil {
		t.Fatalf("root identity: %v", err)
	}
	f.owner = core.CredentialInput{Token: f.signIn(root, true)}
	ownerPrincipal := f.principal(f.owner.Token)
	authority, err := core.Transact(context.Background(), f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Context.GrantingAuthority(ctx, tx, ownerPrincipal, f.tenantID, "")
	})
	if err != nil {
		t.Fatalf("root authority: %v", err)
	}
	f.authority = jsString(authority.Get("id"))
	return f
}

// agentsCall invokes an API method with a body for the fixture's tenant and skips the test when it reaches another
// unit's stub.
func agentsCall[I, O any](f *agentsFixture, method func(context.Context, core.CredentialInput, In[I]) (Out[O], error), credential core.CredentialInput, members ...any) (any, error) {
	f.t.Helper()
	out, err := method(context.Background(), credential, Input[I](f.body(members...)))
	if err != nil {
		skipUnported(f.t, err)
		return nil, err
	}
	return out.Value, nil
}

func mustAgents[I, O any](f *agentsFixture, method func(context.Context, core.CredentialInput, In[I]) (Out[O], error), credential core.CredentialInput, members ...any) *core.Object {
	f.t.Helper()
	value, err := agentsCall(f, method, credential, members...)
	if err != nil {
		f.t.Fatalf("unexpected error: %v", err)
	}
	object, ok := value.(*core.Object)
	if !ok {
		f.t.Fatalf("expected an object, got %T", value)
	}
	return object
}

func mustAgentList[I, O any](f *agentsFixture, method func(context.Context, core.CredentialInput, In[I]) (Out[O], error), credential core.CredentialInput, members ...any) []any {
	f.t.Helper()
	value, err := agentsCall(f, method, credential, members...)
	if err != nil {
		f.t.Fatalf("unexpected error: %v", err)
	}
	list, ok := value.([]any)
	if !ok {
		f.t.Fatalf("expected a list, got %T", value)
	}
	return list
}

func agentsExpectCode(t *testing.T, err error, code string) *core.IamError {
	t.Helper()
	skipUnported(t, err)
	if err == nil {
		t.Fatalf("expected %s, got success", code)
	}
	known := iamError(t, err)
	if known.Code != code {
		t.Fatalf("expected %s, got %s: %s", code, known.Code, known.Message)
	}
	return known
}

// createAgent registers an agent as the owner.
func (f *agentsFixture) createAgent(members ...any) *core.Object {
	f.t.Helper()
	return mustAgents(f, f.iam.API.Agents.Create, f.owner, members...)
}

// key issues an API key for an identity as the owner and returns its token.
func (f *agentsFixture) key(identityID string, members ...any) string {
	f.t.Helper()
	created := mustAgents(f, f.iam.API.Credentials.Create, f.owner, append([]any{"identityId", identityID}, members...)...)
	return jsString(created.Get("token"))
}

// readDoc authorizes action on document/id with a token (the decision, or the error).
func (f *agentsFixture) readDoc(token, id, action string) (bool, error) {
	f.t.Helper()
	decision, err := f.iam.Authorize(context.Background(), AuthorizationRequest{
		Credential: core.CredentialInput{Token: token}, TenantID: f.tenantID, Action: action, Resource: ResourceTarget{Type: "document", ID: id},
	})
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

func (f *agentsFixture) mustRead(token, id, action string) bool {
	f.t.Helper()
	allowed, err := f.readDoc(token, id, action)
	if err != nil {
		f.t.Fatalf("authorize %s %s: %v", action, id, err)
	}
	return allowed
}

func docAllow(actions []string, resources ...string) *core.Object {
	if len(resources) == 0 {
		resources = []string{"document/*"}
	}
	return core.NewObject("version", 1.0, "statements", []any{core.NewObject("effect", "allow", "actions", stringsOf(actions), "resources", stringsOf(resources))})
}

func TestAgentsRegisterWithSponsorAndProfile(t *testing.T) {
	f := newAgentsFixture(t, nil)
	agent := f.createAgent("name", "Triage bot", "model", "claude-sonnet-5", "provider", "Anthropic",
		"protocols", []any{"MCP", "a2a", "mcp"}, "url", "https://agents.acme.test/triage")
	if agent.Get("name") != "Triage bot" || agent.Get("status") != "active" || agent.Get("standing") != "ok" {
		t.Fatalf("agent = %s", stringify(agent))
	}
	expectJSON(t, "profile", agent.Get("agent"), `{"sponsorId":"`+f.ownerID+`","model":"claude-sonnet-5","provider":"anthropic","url":"https://agents.acme.test/triage","protocols":["a2a","mcp"]}`)
	if member(agent.Get("sponsor"), "id") != f.ownerID || member(agent.Get("sponsor"), "email") != "root@example.test" {
		t.Fatalf("sponsor = %s", stringify(agent.Get("sponsor")))
	}
	listed := mustAgentList(f, f.iam.API.Agents.List, f.owner)
	if len(listed) != 1 || member(listed[0], "id") != agent.Get("id") {
		t.Fatalf("list = %s", stringify(listed))
	}
	stored, err := f.iam.Store.Get(context.Background(), "identities", jsString(agent.Get("id")))
	if err != nil || stored.Get("kind") != "agent" {
		t.Fatalf("stored = %v %v", stored, err)
	}
	created := f.audits("agent:create")
	if len(created) != 1 || stringify(created[0].Get("metadata")) != `{"sponsorId":"`+f.ownerID+`","model":"claude-sonnet-5","provider":"anthropic"}` {
		t.Fatalf("agent:create = %s", stringify(created))
	}

	_, err = agentsCall(f, f.iam.API.Agents.Create, f.owner, "name", "Bad", "model", "has spaces")
	expectError(t, err, "INVALID_INPUT", "model must be 1-128 letters, digits or ._:/@+- characters")
	_, err = agentsCall(f, f.iam.API.Agents.Create, f.owner, "name", "Orphan", "sponsorId", agent.Get("id"))
	expectError(t, err, "INVALID_SPONSOR", "An agent sponsor must be an active person of the same tenant")
	_, err = agentsCall(f, f.iam.API.Agents.Create, f.owner, "name", "Bad url", "url", "ftp://agents.acme.test")
	expectError(t, err, "INVALID_INPUT", "url must be an http(s) URL")
	_, err = agentsCall(f, f.iam.API.Agents.Create, f.owner, "name", "Bad audience", "tokenAudiences", []any{"https://*"})
	agentsExpectCode(t, err, "INVALID_INPUT")
}

func TestAgentsCreateNeedsASponsor(t *testing.T) {
	f := newAgentsFixture(t, nil)
	aliceID, alice := f.member("alice@example.test", "Alice")
	// A person without iam:agents:create cannot register agents.
	_, err := agentsCall(f, f.iam.API.Agents.Create, alice, "name", "Mine")
	agentsExpectCode(t, err, "ACCESS_DENIED")
	// Naming another person needs iam:identities:update on them; the owner holds it.
	agent := f.createAgent("name", "Alice's agent", "sponsorId", aliceID)
	if member(agent.Get("agent"), "sponsorId") != aliceID || member(agent.Get("sponsor"), "name") != "Alice" {
		t.Fatalf("agent = %s", stringify(agent))
	}
	// An agent's own key has no person to default to.
	token := f.key(jsString(agent.Get("id")))
	f.grant("agent-creator", "identity", jsString(agent.Get("id")), document(allowStatement("iam:agents:create", "*")))
	_, err = agentsCall(f, f.iam.API.Agents.Create, core.CredentialInput{Token: token}, "name", "Child")
	expectError(t, err, "INVALID_SPONSOR", "Name the person accountable for the agent (sponsorId)")
}

func TestAgentsOwnKeysBoundedByCeiling(t *testing.T) {
	f := newAgentsFixture(t, nil)
	agent := f.createAgent("name", "Research assistant", "model", "claude-opus-5-5", "provider", "Anthropic",
		"purpose", "Summarizes documents", "boundary", docAllow([]string{"documents:read"}))
	agentID := jsString(agent.Get("id"))
	token := f.key(agentID, "name", "runtime")
	f.grant("writer", "identity", agentID, docAllow([]string{"documents:read", "documents:write"}))
	if !f.mustRead(token, "a", "documents:read") {
		t.Fatal("the agent should read")
	}
	// The boundary keeps the agent from writing even though its role allows it.
	if f.mustRead(token, "a", "documents:write") {
		t.Fatal("the boundary should keep the agent from writing")
	}

	// Policies can single out agents and their model.
	guarded := core.NewObject("version", 1.0, "statements", []any{core.NewObject(
		"effect", "allow", "actions", []any{"documents:read"}, "resources", []any{"document/secret"},
		"conditions", core.NewObject(
			"StringEquals", core.NewObject("principal.kind", "agent", "principal.agentModel", "claude-opus-5-5", "principal.agentSponsorId", f.ownerID),
			"Bool", core.NewObject("principal.delegated", false),
		),
	)})
	other := f.createAgent("name", "Other", "model", "small-model")
	otherToken := f.key(jsString(other.Get("id")))
	f.grant("guarded-1", "identity", agentID, guarded)
	f.grant("guarded-2", "identity", jsString(other.Get("id")), guarded)
	if !f.mustRead(token, "secret", "documents:read") {
		t.Fatal("the opus agent should read the secret")
	}
	if f.mustRead(otherToken, "secret", "documents:read") {
		t.Fatal("the small-model agent should not read the secret")
	}

	// Tightening the boundary applies at once.
	mustAgents(f, f.iam.API.Agents.Update, f.owner, "agentId", agentID, "boundary", docAllow([]string{"documents:write"}, "document/none"))
	if f.mustRead(token, "a", "documents:read") {
		t.Fatal("the tightened boundary should apply at once")
	}
	cleared := mustAgents(f, f.iam.API.Agents.Update, f.owner, "agentId", agentID, "boundary", nil)
	if !isUndefined(member(cleared.Get("agent"), "boundary")) {
		t.Fatalf("boundary not cleared: %s", stringify(cleared))
	}
	if !f.mustRead(token, "a", "documents:write") {
		t.Fatal("without a boundary the role applies")
	}

	// Detail: the live key with its label, no delegations.
	detail := mustAgents(f, f.iam.API.Agents.Get, f.owner, "agentId", agentID)
	keys, _ := detail.Get("keys").([]any)
	if len(keys) != 1 || member(keys[0], "name") != "runtime" || !isUndefined(member(keys[0], "lastUsedAt")) && jsNumber(member(keys[0], "lastUsedAt")) <= jsNumber(member(keys[0], "createdAt")) {
		t.Fatalf("keys = %s", stringify(keys))
	}
	expectJSON(t, "delegations", detail.Get("delegations"), `{"active":0,"pending":0}`)
	if detail.Get("liveDelegatedSessions") != 0.0 {
		t.Fatalf("liveDelegatedSessions = %v", detail.Get("liveDelegatedSessions"))
	}
}

func TestAgentsStopWhileSponsorInactive(t *testing.T) {
	f := newAgentsFixture(t, nil)
	aliceID, _ := f.member("alice@example.test", "Alice")
	agent := f.createAgent("name", "Alice’s agent", "sponsorId", aliceID)
	agentID := jsString(agent.Get("id"))
	token := f.key(agentID)
	f.grant("reader", "identity", agentID, docAllow([]string{"documents:read"}))
	if !f.mustRead(token, "a", "documents:read") {
		t.Fatal("the agent should read")
	}

	if _, err := agentsCall(f, f.iam.API.Identities.SetStatus, f.owner, "identityId", aliceID, "status", "disabled"); err != nil {
		t.Fatal(err)
	}
	_, err := f.readDoc(token, "a", "documents:read")
	agentsExpectCode(t, err, "UNAUTHENTICATED")
	standing := mustAgents(f, f.iam.API.Agents.Get, f.owner, "agentId", agentID)
	if standing.Get("standing") != "sponsor-inactive" {
		t.Fatalf("standing = %v", standing.Get("standing"))
	}
	answer := mustAgents(f, f.iam.API.Agents.Standing, f.owner, "agentId", agentID)
	expectJSON(t, "standing", answer, `{"agentId":"`+agentID+`","standing":"sponsor-inactive"}`)
	// Keys cannot be issued meanwhile either.
	_, err = agentsCall(f, f.iam.API.Credentials.Create, f.owner, "identityId", agentID)
	agentsExpectCode(t, err, "INVALID_IDENTITY")

	// Handing the agent to another sponsor brings it back.
	mustAgents(f, f.iam.API.Agents.Update, f.owner, "agentId", agentID, "sponsorId", f.ownerID)
	if !f.mustRead(token, "a", "documents:read") {
		t.Fatal("the agent should read again")
	}
	changes := f.audits("agent:sponsor-change")
	if len(changes) != 1 || stringify(changes[0].Get("metadata")) != `{"from":"`+aliceID+`","to":"`+f.ownerID+`"}` {
		t.Fatalf("agent:sponsor-change = %s", stringify(changes))
	}
}

func TestAgentsEmergencyStop(t *testing.T) {
	f := newAgentsFixture(t, nil)
	first := f.createAgent("name", "One", "model", "claude-opus-5-5", "provider", "Anthropic")
	second := f.createAgent("name", "Two", "model", "claude-opus-5-5", "provider", "Anthropic")
	other := f.createAgent("name", "Three", "provider", "openai", "model", "gpt-x")
	firstToken, secondToken := f.key(jsString(first.Get("id"))), f.key(jsString(second.Get("id")))
	otherToken := f.key(jsString(other.Get("id")))
	_, alice := f.member("alice@example.test", "Alice")
	_, err := agentsCall(f, f.iam.API.Agents.SuspendAll, alice, "reason", "Incident 42")
	agentsExpectCode(t, err, "ACCESS_DENIED")

	result := mustAgents(f, f.iam.API.Agents.SuspendAll, f.owner, "reason", "Incident 42", "provider", "Anthropic")
	if result.Get("suspended") != 2.0 {
		t.Fatalf("result = %s", stringify(result))
	}
	ids := []string{}
	for _, id := range result.Get("agentIds").([]any) {
		ids = append(ids, jsString(id))
	}
	sort.Strings(ids)
	want := []string{jsString(first.Get("id")), jsString(second.Get("id"))}
	sort.Strings(want)
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("agentIds = %v, want %v", ids, want)
	}
	for _, token := range []string{firstToken, secondToken} {
		_, err := f.iam.Authenticate(context.Background(), core.CredentialInput{Token: token})
		if known := agentsExpectCode(t, err, "UNAUTHENTICATED"); known.Status != 401 {
			t.Fatalf("status = %d", known.Status)
		}
	}
	if _, err := f.iam.Authenticate(context.Background(), core.CredentialInput{Token: otherToken}); err != nil {
		t.Fatalf("the other agent should still authenticate: %v", err)
	}
	stops := f.audits("agent:suspend-all")
	if len(stops) != 1 || stringify(stops[0].Get("metadata")) != `{"reason":"Incident 42","suspended":2,"provider":"anthropic"}` {
		t.Fatalf("agent:suspend-all = %s", stringify(stops))
	}
	// Already suspended agents are left as they are; the rest stop now.
	rest := mustAgents(f, f.iam.API.Agents.SuspendAll, f.owner, "reason", "Incident 42, all of them")
	expectJSON(t, "agentIds", rest.Get("agentIds"), `["`+jsString(other.Get("id"))+`"]`)
}

func TestAgentsSponsorKillSwitch(t *testing.T) {
	f := newAgentsFixture(t, nil)
	aliceID, alice := f.member("alice@example.test", "Alice")
	_, bob := f.member("bob@example.test", "Bob")
	agent := f.createAgent("name", "Alice’s agent", "sponsorId", aliceID)
	agentID := jsString(agent.Get("id"))
	token := f.key(agentID)
	f.grant("reader", "identity", agentID, docAllow([]string{"documents:read"}))

	mine := mustAgentList(f, f.iam.API.Agents.ListMine, alice)
	if len(mine) != 1 || member(mine[0], "id") != agentID {
		t.Fatalf("listMine = %s", stringify(mine))
	}
	if list := mustAgentList(f, f.iam.API.Agents.ListMine, bob); len(list) != 0 {
		t.Fatalf("bob's listMine = %s", stringify(list))
	}
	// The sponsor reads the agent's standing and activity without a permission; Bob cannot.
	if standing := mustAgents(f, f.iam.API.Agents.Standing, alice, "agentId", agentID); standing.Get("standing") != "ok" {
		t.Fatalf("standing = %s", stringify(standing))
	}
	_, err := agentsCall(f, f.iam.API.Agents.Standing, bob, "agentId", agentID)
	agentsExpectCode(t, err, "ACCESS_DENIED")

	// Bob is neither the sponsor nor an administrator.
	_, err = agentsCall(f, f.iam.API.Agents.Suspend, bob, "agentId", agentID)
	agentsExpectCode(t, err, "ACCESS_DENIED")

	suspended := mustAgents(f, f.iam.API.Agents.Suspend, alice, "agentId", agentID, "reason", "Looping on the wiki")
	if suspended.Get("status") != "disabled" || suspended.Get("standing") != "suspended" {
		t.Fatalf("suspended = %s", stringify(suspended))
	}
	mark := member(suspended.Get("agent"), "suspended")
	if member(mark, "by") != aliceID || member(mark, "reason") != "Looping on the wiki" {
		t.Fatalf("suspended mark = %s", stringify(mark))
	}
	_, err = f.readDoc(token, "a", "documents:read")
	agentsExpectCode(t, err, "UNAUTHENTICATED")
	_, err = agentsCall(f, f.iam.API.Agents.Suspend, alice, "agentId", agentID)
	expectError(t, err, "CONFLICT", "The agent is already suspended")

	resumed := mustAgents(f, f.iam.API.Agents.Resume, alice, "agentId", agentID)
	if resumed.Get("standing") != "ok" || !isUndefined(member(resumed.Get("agent"), "suspended")) {
		t.Fatalf("resumed = %s", stringify(resumed))
	}
	// The key was kept.
	if !f.mustRead(token, "a", "documents:read") {
		t.Fatal("the kept key should work again")
	}

	// An administrator's suspension is theirs to lift.
	mustAgents(f, f.iam.API.Agents.Suspend, f.owner, "agentId", agentID)
	_, err = agentsCall(f, f.iam.API.Agents.Resume, alice, "agentId", agentID)
	expectError(t, err, "ACCESS_DENIED", "Only an administrator can resume an agent someone else suspended")
	mustAgents(f, f.iam.API.Agents.Resume, f.owner, "agentId", agentID)
	if !f.mustRead(token, "a", "documents:read") {
		t.Fatal("the key should work after the administrator resumed the agent")
	}

	for _, action := range []string{"agent:create", "agent:suspend", "agent:resume"} {
		if len(f.audits(action)) == 0 {
			t.Fatalf("no %s event", action)
		}
	}
	// What the agent did: its own key's decisions, newest first. Allowed checks are not audited (only refusals and
	// root overrides are, as in operations.ts recordedDecision), so the agent makes one refused check.
	if f.mustRead(token, "a", "documents:write") {
		t.Fatal("the agent holds no documents:write grant")
	}
	activity := mustAgentList(f, f.iam.API.Agents.Activity, alice, "agentId", agentID, "limit", 5.0)
	if len(activity) == 0 {
		t.Fatal("expected activity")
	}
	for _, event := range activity {
		if member(event, "actorId") != agentID && member(member(event, "sessionContext"), "agentId") != agentID {
			t.Fatalf("activity event of someone else: %s", stringify(event))
		}
	}
	_, err = agentsCall(f, f.iam.API.Agents.Activity, alice, "agentId", agentID, "limit", 501.0)
	agentsExpectCode(t, err, "INVALID_INPUT")
}

func TestAgentsCatalog(t *testing.T) {
	f := newAgentsFixture(t, nil)
	_, alice := f.member("alice@example.test", "Alice")
	f.createAgent("name", "Zeta", "purpose", "Writes", "tokenAudiences", []any{"https://api.example.com"})
	f.createAgent("name", "Alpha", "model", "m1", "protocols", []any{"a2a"})
	f.createAgent("name", "Private", "delegable", false)
	listings := mustAgentList(f, f.iam.API.Agents.Catalog, alice)
	names := []string{}
	for _, listing := range listings {
		names = append(names, jsString(member(listing, "name")))
	}
	if strings.Join(names, ",") != "Alpha,Zeta" {
		t.Fatalf("catalog = %s", stringify(listings))
	}
	if member(listings[0], "sponsorName") != "Root" || stringify(member(listings[1], "tokenAudiences")) != `["https://api.example.com"]` {
		t.Fatalf("catalog = %s", stringify(listings))
	}
	// An agent's key is not a person's own session.
	agent := f.createAgent("name", "Reader")
	token := f.key(jsString(agent.Get("id")))
	_, err := agentsCall(f, f.iam.API.Agents.Catalog, core.CredentialInput{Token: token})
	expectError(t, err, "ACCESS_DENIED", "The agent catalog is read from a person’s own session of the tenant")
	_, err = agentsCall(f, f.iam.API.Agents.ListMine, core.CredentialInput{Token: token})
	expectError(t, err, "ACCESS_DENIED", "Sponsored agents are listed from a person’s own session of the tenant")
}

func TestAgentsListFilters(t *testing.T) {
	f := newAgentsFixture(t, nil)
	aliceID, _ := f.member("alice@example.test", "Alice")
	first := f.createAgent("name", "First")
	f.advance(1000)
	second := f.createAgent("name", "Second", "sponsorId", aliceID)
	list := mustAgentList(f, f.iam.API.Agents.List, f.owner)
	if len(list) != 2 || member(list[0], "id") != second.Get("id") || member(list[1], "id") != first.Get("id") {
		t.Fatalf("list = %s", stringify(list))
	}
	mine := mustAgentList(f, f.iam.API.Agents.List, f.owner, "sponsorId", aliceID)
	if len(mine) != 1 || member(mine[0], "id") != second.Get("id") {
		t.Fatalf("by sponsor = %s", stringify(mine))
	}
	if inactive := mustAgentList(f, f.iam.API.Agents.List, f.owner, "standing", "sponsor-inactive"); len(inactive) != 0 {
		t.Fatalf("by standing = %s", stringify(inactive))
	}
	_, err := agentsCall(f, f.iam.API.Agents.Get, f.owner, "agentId", aliceID)
	expectError(t, err, "NOT_FOUND", "Agent not found")
}

func TestAgentsTenantLimit(t *testing.T) {
	f := newAgentsFixture(t, nil)
	tenant, err := f.iam.Store.Get(context.Background(), "tenants", f.tenantID)
	if err != nil || tenant == nil {
		t.Fatalf("tenant: %v", err)
	}
	f.seed("tenants", tenant.Spread(core.NewObject("limits", core.NewObject("agents", 1.0))))
	f.createAgent("name", "One")
	_, err = agentsCall(f, f.iam.API.Agents.Create, f.owner, "name", "Two")
	agentsExpectCode(t, err, "LIMIT_EXCEEDED")
}

func TestAgentsDelete(t *testing.T) {
	f := newAgentsFixture(t, nil)
	agent := f.createAgent("name", "Short-lived")
	agentID := jsString(agent.Get("id"))
	deleted := mustAgents(f, f.iam.API.Agents.Delete, f.owner, "agentId", agentID)
	if deleted.Get("status") != "deleted" {
		t.Fatalf("deleted = %s", stringify(deleted))
	}
	events := f.audits("identity:delete")
	if len(events) == 0 || stringify(events[len(events)-1].Get("metadata")) != `{"kind":"agent","delegationsRevoked":0}` {
		t.Fatalf("identity:delete = %s", stringify(events))
	}
	if list := mustAgentList(f, f.iam.API.Agents.List, f.owner); len(list) != 0 {
		t.Fatalf("list = %s", stringify(list))
	}
	if list := mustAgentList(f, f.iam.API.Agents.List, f.owner, "includeDeleted", true); len(list) != 1 {
		t.Fatalf("list with deleted = %s", stringify(list))
	}
	_, err := agentsCall(f, f.iam.API.Agents.Update, f.owner, "agentId", agentID, "name", "Back")
	expectError(t, err, "NOT_FOUND", "Agent has been deleted")
}

func TestAgentAudiences(t *testing.T) {
	cases := []struct {
		pattern, audience string
		want              bool
	}{
		{"https://api.example.com", "https://api.example.com", true},
		{"https://api.example.com", "https://API.example.com/", true},
		{"https://api.example.com", "http://api.example.com", false},
		{"https://*.example.com", "https://a.example.com/x", false},
		{"https://*.example.com/*", "https://a.example.com/x", true},
		{"https://*.example.com", "https://example.com", false},
		{"https://api.example.com:8443/v1/*", "https://api.example.com:8443/v1/items", true},
		{"https://api.example.com:8443/v1/*", "https://api.example.com/v1/items", false},
		{"urn:example:*", "urn:example:api", true},
		{"urn:example:*", "https://urn.example", false},
	}
	for _, item := range cases {
		if got := AudienceMatches(item.pattern, item.audience); got != item.want {
			t.Errorf("AudienceMatches(%q, %q) = %v, want %v", item.pattern, item.audience, got, item.want)
		}
	}
	list, err := TokenAudienceList([]any{"urn:b", "https://a.example", "urn:b"}, "")
	if err != nil || strings.Join(list, ",") != "https://a.example,urn:b" {
		t.Fatalf("TokenAudienceList = %v %v", list, err)
	}
	_, err = TokenAudience("https://*.example.com")
	expectError(t, err, "INVALID_INPUT", "audience must name one service: an http(s) URL without user info, query, fragment or *, or another absolute URI")
}

// Unused-type guard: the generated input types stay referenced by the tests' calls.
var _ = apitypes.AgentsCreateInput{}
